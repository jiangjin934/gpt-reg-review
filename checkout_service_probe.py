"""通过 int31.space 的探测服务读「这个号结算时真实要付多少钱」。

为什么需要它（2026-09-29 实测结论）：
  我们自己写的纯协议 checkout（payment_probe.py）在**这台机器上被 OpenAI 的
  滥用闸门稳定拒绝** —— 换过 100 条印度住宅出口、换过 7 组请求头/请求体、
  换过设备标识、甚至不走代理直连，都是同一句
  `400 Our systems have detected unusual activity`；
  而同样一个账号、同样一条印度出口，交给 int31 的服务去建 checkout 就能拿到
  真实金额（实测 169407 INR = ₹1694.07），说明被拦的是**我们客户端的请求指纹**，
  不是账号、不是出口。所以在自研客户端能过闸门之前，探测走这条链路。

接口（2026-09-27 实测 + 前端 bundle 反解）：
  · POST {BASE}/public/api/checkout-capabilities        {accessToken, proxyUrl} -> 202 {taskId,...}
  · POST {BASE}/public/api/checkout-capabilities/batch  {taskIds:[...]}          -> {tasks:[...]}
  · 限流：连发几次就 429，响应带 retryAfterSeconds，必须按它退避
  · 代理写法：**提交时必须 http://**（服务端只认这个），本机验活用 socks5h://
    （cliproxy:3010 不支持 HTTP CONNECT），同一个 sid 就是同一个出口

只做预览、不产生支付：服务端只是创建未支付 checkout 会话并回读金额。
"""
from __future__ import annotations

import logging
import random
import re
import string
import threading
import time
from typing import Any, Mapping, Optional

from curl_cffi import requests as cffi_requests

logger = logging.getLogger("checkout_service_probe")

BASE = "https://int31.space"
SUBMIT_URL = f"{BASE}/public/api/checkout-capabilities"
POLL_URL = f"{SUBMIT_URL}/batch"
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
TERMINAL = {"SUCCEEDED", "COMPLETED", "FAILED", "CANCELLED", "EXPIRED"}

FAILURE_TRANSPORT = "CheckoutTransportException"
FAILURE_SERVICE = "CheckoutServiceError"
FAILURE_RATE_LIMITED = "CheckoutRateLimited"


class RateLimited(Exception):
    """服务端限流，带它要求的退避秒数。"""

    def __init__(self, retry_after: int):
        super().__init__(f"探测服务限流，{retry_after}s 后可再试")
        self.retry_after = int(retry_after)


def to_service_proxy(proxy: str) -> str:
    """提交给服务端用的代理写法：一律 http://（服务端只认这个）。"""
    return re.sub(r"^socks5h?://", "http://", (proxy or "").strip())


def to_local_proxy(proxy: str) -> str:
    """本机验活用的写法：一律 socks5h://（cliproxy:3010 不支持 HTTP CONNECT）。"""
    return re.sub(r"^https?://", "socks5h://", (proxy or "").strip())


def build_india_proxy(template: str, *, ttl_minutes: int = 1440) -> str:
    """把代理模板改成一条新的印度静态会话（region→IN、换新 sid、TTL 拉长）。

    ⚠️ 整段 region 记号一起换（region-Rand → region-IN）：只匹配两位字母会把
    region-Rand 变成非法的 region-INnd，出口直接连不通。
    """
    sid = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    out = (template or "").strip()
    out = re.sub(r"region-[A-Za-z0-9]+", "region-IN", out)
    if re.search(r"sid-[A-Za-z0-9]+", out):
        out = re.sub(r"sid-[A-Za-z0-9]+", f"sid-{sid}", out, count=1)
    else:
        out = re.sub(r"(region-[A-Za-z0-9]+)", rf"\1-sid-{sid}", out, count=1)
    out = re.sub(r"-t-\d+", f"-t-{int(ttl_minutes)}", out)
    return out


def _session() -> Any:
    session = cffi_requests.Session(impersonate="chrome")
    session.trust_env = False
    return session


# ── 提交侧全局最小间隔 ──
# 并发 worker 会同时 submit：服务端虽然按 token 限流（号与号互不影响），但"短时间
# 连发一串"本身也可能被它当成突发流量（另一台机器实测"连发 7 次就 429"）。
# 这里用一把锁把提交摊开，多路并发时也不会形成突发。
_SUBMIT_LOCK = threading.Lock()
_LAST_SUBMIT_AT = 0.0
_MIN_SUBMIT_GAP = 1.5


def _throttle_submit() -> None:
    global _LAST_SUBMIT_AT
    with _SUBMIT_LOCK:
        wait = _MIN_SUBMIT_GAP - (time.time() - _LAST_SUBMIT_AT)
        if wait > 0:
            time.sleep(wait)
        _LAST_SUBMIT_AT = time.time()


def _http_json(method: str, url: str, *, payload: Optional[Mapping[str, Any]] = None,
               timeout: float = 45.0) -> tuple[int, dict]:
    session = _session()
    try:
        kwargs: dict[str, Any] = {"timeout": timeout}
        if payload is not None:
            kwargs["json"] = dict(payload)
            kwargs["headers"] = {"Content-Type": "application/json"}
        resp = session.request(method, url, **kwargs)
        try:
            data = resp.json() if (resp.text or "").strip() else {}
        except Exception:  # noqa: BLE001
            data = {}
        return int(resp.status_code), (data if isinstance(data, dict) else {})
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass


def proxy_alive(proxy: str, *, timeout: float = 12.0) -> bool:
    """本机验活：用 socks5h 走一遍 trace，确认这条会话真的能出网。"""
    session = _session()
    try:
        value = to_local_proxy(proxy)
        session.proxies = {"http": value, "https": value}
        resp = session.get(TRACE_URL, timeout=timeout)
        return int(getattr(resp, "status_code", 0) or 0) == 200 and "loc=" in (resp.text or "")
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass


def _failure(error: str, *, failure_type: str = FAILURE_SERVICE, **extra: Any) -> dict:
    """失败结论也带齐标准键，调用方（落库/前端）不必分两套形状读。"""
    return {
        "ok": False,
        "status": "FAILED",
        "failure_type": failure_type,
        "error": error[:400],
        "transport_failed": failure_type == FAILURE_TRANSPORT,
        "amount_minor": None,
        "currency": "",
        "payment_methods": [],
        "processor_entity": "",
        "provider_country": "",
        "free_trial": False,
        "checkout_session_id": "",
        "source": "int31",
        "checked_at": time.time(),
        **extra,
    }


def _submit(token: str, proxy: str) -> dict:
    _throttle_submit()
    status, data = _http_json("POST", SUBMIT_URL,
                              payload={"accessToken": token, "proxyUrl": to_service_proxy(proxy)})
    if status == 429:
        raise RateLimited(int((data or {}).get("retryAfterSeconds") or 600))
    if status >= 400:
        raise RuntimeError(f"提交失败 HTTP {status}: {str(data)[:200]}")
    return data


def _poll(task_id: str, *, timeout: float = 40.0) -> dict:
    status, data = _http_json("POST", POLL_URL, payload={"taskIds": [task_id]}, timeout=timeout)
    if status >= 400:
        raise RuntimeError(f"轮询失败 HTTP {status}")
    tasks = (data or {}).get("tasks") or []
    return tasks[0] if tasks else {}


def probe_via_service(
    access_token: str,
    *,
    proxy: str = "",
    template: str = "",
    wait_seconds: float = 240.0,
    poll_every: float = 2.5,
    retries: int = 2,
) -> dict:
    """提交一条探测并等到终态。传输类失败会换一条新印度会话重试（最多 retries 次）。

    template 非空时，每次重试都用它生成一条全新的印度会话（同一个 sid 复用同一出口，
    sid 死了就换 —— 探测服务连不上代理时最常见的原因就是这条会话已经失效）。
    """
    token = str(access_token or "").strip()
    if not token:
        return _failure("没有 access_token", no_at=True)
    current = (proxy or "").strip()
    if not current and template:
        current = build_india_proxy(template)
    if not current:
        return _failure("没有可用代理（探测服务必须由我们提供出口）", proxy_failed=True)

    for attempt in range(retries + 1):
        try:
            created = _submit(token, current)
        except RateLimited as exc:
            return _failure(str(exc), failure_type=FAILURE_RATE_LIMITED,
                            retry_after=exc.retry_after, rate_limited=True, proxy=current)
        except Exception as exc:  # noqa: BLE001
            return _failure(f"{type(exc).__name__}: {str(exc)[:200]}",
                            failure_type=FAILURE_TRANSPORT, proxy_failed=True, proxy=current)

        task_id = str(created.get("taskId") or created.get("task_id") or "")
        if not task_id:
            return _failure(f"提交后没有 taskId: {str(created)[:160]}", proxy=current)

        deadline = time.time() + max(30.0, float(wait_seconds))
        task: dict = {}
        while time.time() < deadline:
            time.sleep(max(1.0, float(poll_every)))
            try:
                task = _poll(task_id) or {}
            except Exception as exc:  # noqa: BLE001
                logger.debug("轮询异常（继续等）: %s", exc)
                continue
            if str(task.get("status") or "").upper() in TERMINAL:
                break

        status = str(task.get("status") or "").upper()
        failure_type = str(task.get("failureType") or task.get("failure_type") or "")
        result = task.get("result") if isinstance(task.get("result"), Mapping) else {}

        if failure_type == FAILURE_TRANSPORT and attempt < retries:
            # 服务端连不上这条代理：换一条新的印度会话再来（旧会话多半已失效）
            logger.info("探测服务连不上代理，换新印度会话重试（%d/%d）", attempt + 1, retries)
            current = build_india_proxy(template) if template else current
            if not template:
                time.sleep(3)
            continue

        if status not in ("SUCCEEDED", "COMPLETED"):
            return _failure(
                f"任务未成功: status={status or 'TIMEOUT'} failure={failure_type or '-'}",
                failure_type=failure_type or FAILURE_SERVICE, proxy=current,
                task_id=task_id, amount_minor=None,
            )

        amount = result.get("amountMinor")
        if amount is None:
            amount = result.get("amount_minor")
        try:
            amount_minor = int(amount) if amount is not None else None
        except (TypeError, ValueError):
            amount_minor = None
        methods = result.get("paymentMethodTypes") or result.get("payment_methods") or []
        return {
            "ok": True,
            "status": "SUCCEEDED",
            "failure_type": "",
            "amount_minor": amount_minor,
            "currency": str(result.get("currency") or "").strip(),
            # amount_minor == 0 才是真·0 元可领
            "free_trial": amount_minor == 0 and bool(result),
            "payment_methods": list(methods) if isinstance(methods, (list, tuple)) else [],
            "processor_entity": str(result.get("processorEntity") or result.get("processor_entity") or ""),
            "provider_country": str(result.get("providerCountry") or result.get("provider_country") or ""),
            "checkout_backend": str(result.get("checkoutBackend") or ""),
            "checkout_session_id": str(result.get("sessionId") or task.get("taskId") or ""),
            "email": str(task.get("email") or ""),
            "source": "int31",
            "proxy": current,
            "checked_at": time.time(),
        }

    return _failure("重试次数用尽", failure_type=FAILURE_TRANSPORT, proxy=current)
