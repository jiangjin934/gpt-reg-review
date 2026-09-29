"""浏览器引擎的 checkout 探测（免费自建版）。

背景：协议直连 /backend-api/payments/checkout 会被风控拦（400 unusual
activity），因为请求里缺 ``cf_clearance`` —— 那是 Cloudflare 挑战通过后才
颁发的 cookie，只有真实浏览器（或反指纹浏览器）能拿到。int31 等收费服务
能干成这件事，靠的就是浏览器会话或高信誉出口。

这里用项目自带的 Camoufox（反指纹 Firefox，注释注明能过 Cloudflare）：
  1. 启动浏览器（任务冻结的指纹 + 出口代理，无头）
  2. 种上账号的注册 Cookie（session-token / oai-did / oai-sc 等）
  3. 打开 chatgpt.com —— 浏览器自动通过 CF 挑战，拿到 cf_clearance
  4. 在**页面上下文里** fetch checkout 端点：请求由真实浏览器发出，
     携带真实 TLS、真实头、真实 Cookie、真实 JS 环境
  5. 解析金额/币种/支付方式，归一化成与 payment_probe 相同的 outcome 结构

返回结构与 payment_probe.probe_checkout 完全一致，另带 source="browser"。
失败分类沿用同一套语义：传输失败绝不写成「该号不可支付」。
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from typing import Any, Optional

from payment_probe import (
    CHECKOUT_URL,
    FAILURE_DEAD_END,
    FAILURE_REQUEST_REJECTED,
    FAILURE_RISK_BLOCKED,
    FAILURE_TOKEN,
    FAILURE_TRANSPORT,
    default_checkout_body,
    _RISK_BLOCK_MARKERS,
    _as_list,
    _first_key,
    _normalize_amount,
    _CURRENCY_KEYS,
    _ENTITY_KEYS,
    _METHOD_KEYS,
    _PROVIDER_COUNTRY_KEYS,
)

logger = logging.getLogger("browser_checkout_probe")

HOMEPAGE = "https://chatgpt.com"


def _failure(
    failure_type: str,
    error: str,
    *,
    transport_failed: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "ok": False,
        "status": "FAILED",
        "failure_type": failure_type,
        "error": error[:400],
        "transport_failed": transport_failed,
        "amount_minor": None,
        "currency": "",
        "payment_methods": [],
        "processor_entity": "",
        "provider_country": "",
        "free_trial": False,
        "checkout_session_id": "",
        "source": "browser",
        "checked_at": time.time(),
        **extra,
    }


def _cookies_to_seed(cookie_header: str) -> list[dict[str, Any]]:
    """把 `k=v; k2=v2` 的 Cookie 头拆成 Playwright 可种的对象列表。

    ⚠️ 必须用 `url` 形式（host-only + https），不能写成 `domain=".chatgpt.com"`：
       注册会话里的 cookie 带 `__Secure-` / `__Host-` 前缀，浏览器对这两种前缀有
       硬性规则（`__Secure-` 必须 Secure、`__Host-` 必须 host-only 且不许带 Domain），
       带前导点的 Domain 写法会被直接丢弃。2026-09-29 实测踩到：种完 cookie 打开
       首页，右上角仍是 "Log in / Sign up for free" —— 浏览器其实是**未登录**状态，
       所以之前"浏览器路径也被拦"的结论不成立，测的是一次游客访问。
    """
    out: list[dict[str, Any]] = []
    for part in (cookie_header or "").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        if name:
            out.append({
                "name": name,
                "value": value.strip(),
                "url": "https://chatgpt.com/",
                "secure": True,
                "sameSite": "Lax",
            })
    return out


def _checkout_via_page(page: Any, headers: dict[str, str], body: dict[str, Any], timeout_ms: int) -> dict[str, Any]:
    """在页面上下文里 fetch checkout 端点，返回 {status, text}。

    页面自身在 chatgpt.com 域下，fetch 相对路径是同源请求，浏览器自动带上
    全部 Cookie（含刚拿到的 cf_clearance）。请求头、TLS、JS 环境都是真实的。
    """
    script = """
    async ([url, headers, body, timeoutMs]) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const resp = await fetch(url, {
          method: "POST",
          headers: headers,
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        return { status: resp.status, text: await resp.text() };
      } catch (err) {
        return { status: 0, text: String(err && err.message ? err.message : err) };
      } finally {
        clearTimeout(timer);
      }
    }
    """
    return page.evaluate(script, [CHECKOUT_URL, headers, body, timeout_ms])


def probe_checkout_browser(
    access_token: str,
    *,
    proxy: str = "",
    fingerprint: Optional[Mapping[str, Any]] = None,
    account_id: str = "",
    device_id: str = "",
    cookie_header: str = "",
    billing_country: str = "IN",
    currency: str = "INR",
    body_override: Optional[Mapping[str, Any]] = None,
    timeout: float = 90.0,
) -> dict[str, Any]:
    """浏览器版 checkout 探测。返回结构与 payment_probe.probe_checkout 一致。"""
    token = str(access_token or "").strip()
    if not token:
        return _failure(FAILURE_DEAD_END, "没有 access_token", no_at=True)

    fp = dict(fingerprint or {})
    # Camoufox 是 Firefox 内核：画像必须是 Firefox 族，否则启动器会拒绝。
    # 取不到或不是 firefox 时，按出口国家现场生成一套 firefox 画像。
    if fp.get("browser_family") != "firefox":
        try:
            from fingerprint import generate_fingerprint

            fp = generate_fingerprint(
                country_code=fp.get("country_code") or "",
                browser_family="firefox",
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("现场生成 firefox 画像失败: %s", exc)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if account_id:
        headers["ChatGPT-Account-ID"] = account_id
    if device_id:
        headers["Oai-Device-Id"] = device_id
    body = dict(body_override) if isinstance(body_override, Mapping) else default_checkout_body(
        country=billing_country, currency=currency
    )

    browser_launcher = None
    browser = None
    context = None
    relay = None
    started = time.time()
    try:
        from browser_launcher import _launch_camoufox, close_browser
        from local_socks_relay import LocalSocksRelay

        proxy_value = (proxy or "").strip()
        # 带认证的 socks5 浏览器不支持（Playwright/Camoufox 均如此）：
        # 起本地中继 —— 浏览器连 127.0.0.1 免认证，中继带凭据连上游。
        if "@" in proxy_value and "://" in proxy_value:
            relay = LocalSocksRelay(proxy_value)
            proxy_value = relay.start()

        browser_launcher, browser, context = _launch_camoufox(
            proxy_value or None,
            headless=True,
            fingerprint=fp,
        )
        page = context.new_page()

        # 种上账号 Cookie：真实浏览器升级页就是带着这些历史 Cookie 发起 checkout 的。
        seeds = _cookies_to_seed(cookie_header)
        if seeds:
            context.add_cookies(seeds)

        # 打开首页过 CF 挑战（cf_clearance 在这一步拿到），并让 Cookie 域归位。
        page.goto(HOMEPAGE, wait_until="domcontentloaded")
        time.sleep(2.0)

        result = _checkout_via_page(page, headers, body, timeout_ms=int(timeout * 1000))
        status = int(result.get("status") or 0)
        text = str(result.get("text") or "")
        payload: Any = None
        if text.strip():
            try:
                payload = json.loads(text)
            except ValueError:
                payload = None

        if status == 0:
            return _failure(
                FAILURE_TRANSPORT,
                f"浏览器内 fetch 失败（未取得金额，结论无效）: {text[:200]}",
                transport_failed=True,
                elapsed_ms=int((time.time() - started) * 1000),
            )
        if status in (401, 403):
            return _failure(
                FAILURE_TOKEN if status == 401 else FAILURE_DEAD_END,
                f"HTTP {status}: {text[:240]}",
                http_status=status,
                elapsed_ms=int((time.time() - started) * 1000),
            )
        if status >= 400:
            body_lower = text.lower()
            if any(marker in body_lower for marker in _RISK_BLOCK_MARKERS):
                return _failure(
                    FAILURE_RISK_BLOCKED,
                    f"HTTP {status}: {text[:240]}",
                    http_status=status,
                    hint="浏览器链路同样被风控拦截；实测与出口无关（多出口结果一致），属账号侧支付风控",
                    elapsed_ms=int((time.time() - started) * 1000),
                )
            failure_type = (
                FAILURE_REQUEST_REJECTED if status in (400, 404, 422) else FAILURE_DEAD_END
            )
            return _failure(
                failure_type,
                f"HTTP {status}: {text[:240]}",
                http_status=status,
                elapsed_ms=int((time.time() - started) * 1000),
            )

        amount_minor, amount_key, amount_raw, amount_basis = _normalize_amount(payload)
        _, currency_value = _first_key(payload, _CURRENCY_KEYS)
        _, methods_value = _first_key(payload, _METHOD_KEYS)
        _, entity_value = _first_key(payload, _ENTITY_KEYS)
        _, country_value = _first_key(payload, _PROVIDER_COUNTRY_KEYS)

        return {
            "ok": True,
            "status": "SUCCEEDED",
            "failure_type": "",
            "amount_minor": amount_minor,
            "currency": str(currency_value or currency or "").strip(),
            "payment_methods": _as_list(methods_value),
            "processor_entity": str(entity_value or "").strip(),
            "provider_country": str(country_value or billing_country or "").strip().upper(),
            "free_trial": amount_minor == 0,
            "checkout_session_id": "",
            "source": "browser",
            "proxy": proxy,
            "checked_at": time.time(),
            "elapsed_ms": int((time.time() - started) * 1000),
            "amount_source": {
                "key": amount_key,
                "raw": amount_raw,
                "basis": amount_basis,
            },
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("[browser_checkout_probe] 探测异常: %s", str(exc)[:200])
        return _failure(
            FAILURE_TRANSPORT,
            f"浏览器探测异常，结论无效: {str(exc)[:200]}",
            transport_failed=True,
            elapsed_ms=int((time.time() - started) * 1000),
        )
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:  # noqa: BLE001
                pass
        if browser_launcher is not None and browser is not None:
            try:
                close_browser(browser_launcher, browser)
            except Exception:  # noqa: BLE001
                pass
        if relay is not None:
            try:
                relay.stop()
            except Exception:  # noqa: BLE001
                pass


__all__ = ["probe_checkout_browser"]
