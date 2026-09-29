"""支付能力探测的 WebUI 侧编排（自建协议链路）。

探测本身在 payment_probe.py（纯协议、零 db 依赖）。这里只负责三件事：
  · 印度出口的选择、验活与自愈；
  · 结论落进注册记录的 plus_check.checkout；
  · 后台队列与节流 —— 逐个探测之间留间隔，避免在同一条出口上密集打
    checkout。

原实现走 int31.space 的异步任务接口（提交 + 轮询 + 429 退避），
2026-09-28 换成协议链路，旧文件保留在 checkout_capability.py.int31.bak 备查。
"""
from __future__ import annotations

import logging
import queue
import random
import re
import string
import threading
import time
from typing import Any, Optional

from curl_cffi import requests as cffi_requests

from . import db

logger = logging.getLogger("webui.checkout_capability")

# ── 自动探测队列 ──
# 注册完一个号就排队，后台单线程按节奏探（默认每个之间 6 秒）。协议链路的
# 瓶颈换成了出口本身：同一条印度出口上连打 checkout 会被风控盯上，所以
# 即便没有 429 也要留间隔。
_QUEUE: "queue.Queue[str]" = queue.Queue()
_QUEUED: set[str] = set()
_WORKERS: list[threading.Thread] = []
_WORKER_LOCK = threading.Lock()
# 每个 worker 正在探的号（worker 名 → email），用于状态展示
_PROCESSING: dict[str, str] = {}
_STATE = {
    "processing": "",
    "done": 0,
    "failed": 0,
    "last_error": "",
    "last_result": {},
    # 最近一次「按 token 限流」告知的可重试时间（仅展示用：限流是按号的，
    # 队列会跳过该号继续跑，不再整体暂停）
    "rate_limited_until": 0.0,
}

# 印度出口的存活检查缓存：同一个代理 60 秒内不重复验活
_INDIA_CHECK = {"proxy": "", "ok": False, "at": 0.0}
_TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"


class CheckoutCapabilityError(RuntimeError):
    """配置或环境类错误。

    探测本身的失败（网络、账号、参数）一律通过返回值表达，不抛异常 ——
    队列 worker 与 API 层都按结构化结果记账，异常只留给真正的调用错误。
    """

    def __init__(self, message: str, *, rate_limited: bool = False, retry_after: int = 0):
        super().__init__(message)
        self.rate_limited = rate_limited
        self.retry_after = int(retry_after or 0)


def config() -> dict:
    def _get(key: str, default: str) -> str:
        try:
            return (db.get_setting(key, default) or default).strip()
        except Exception:  # noqa: BLE001
            return default

    return {
        "enabled": _get("checkout_capability_enabled", "1") in ("1", "true", "yes", "on"),
        # 探测走哪条链路：
        #   int31    = 走探测服务（默认）。2026-09-29 实测：同样账号 + 同样印度出口，
        #              自研协议客户端被 OpenAI 滥用闸门稳定拒绝，交给服务端就能拿到
        #              真实金额（169407 INR）。在自研客户端能过闸门之前，用这条。
        #   protocol = 自研纯协议 checkout（payment_probe.py），失败时可回退浏览器。
        "probe_source": (_get("checkout_probe_source", "int31") or "int31").lower(),
        # 打开 auto 才会在每个命中试用的号上自动探。
        "auto": _get("checkout_capability_auto", "0") in ("1", "true", "yes", "on"),
        # 命中试用时是否在注册流程里同步探测（会阻塞注册）。
        "sync_eligible": _get("checkout_capability_sync_eligible", "0")
        in ("1", "true", "yes", "on"),
        # 协议探测被风控拦（RiskBlocked）时，自动回退到浏览器引擎探测。
        # 浏览器自带 cf_clearance 与真实 JS 环境，是过 checkout 风控的唯一免费路径；
        # 代价是每个号约 30~90 秒 + 一份浏览器内存。
        "browser_fallback": _get("checkout_capability_browser_fallback", "1")
        in ("1", "true", "yes", "on"),
        # 风控冷却（秒）：同一号被风控拦（unusual activity）后，冷却期内
        # 不再重复探测。「try again later」是时间性拦截 —— 反复打同一个号
        # 只会让 flag 越积越重（2026-09-29 实测：一个号被连打 20+ 次后
        # 所有路径全被拦）。冷却默认 6 小时。
        "risk_cooldown_seconds": max(
            0.0, float(_get("checkout_capability_risk_cooldown", "21600") or 21600)
        ),
        # 自备的静态印度出口（完整 URL）。留空则从代理池改写一条。
        "india_proxy": _get("checkout_capability_india_proxy", ""),
        # 队列里每个号之间的间隔（秒）
        # 6 秒是另一台机器实测跑通的节奏：限流是**按 token** 的（同一个号反复探才会
        # 429、要等约 1 小时），而队列里每个号只探一次 —— 6 秒一个既快又不会触发限流
        # （185 个号约 20 分钟跑完）。真遇到 429 也不会整体停滞：见 _worker_loop 的
        # 「跳过该号继续下一个」。
        "interval_seconds": max(3.0, float(_get("checkout_capability_interval", "6") or 6)),
        # 并发 worker 数（1-8）。限流按 token，号与号互不影响，所以并发是安全的；
        # 默认 8 路（2026-09-29 提速：6 秒节奏 + 8 路 ≈ 13 号/分，且不触发限流）。
        "concurrency": max(1, min(8, int(float(_get("checkout_capability_concurrency", "8") or 8)))),
        # 印度粘性会话的最长复用时间（秒）：超过就主动换一条，别等它掉线
        "sid_ttl_seconds": max(120.0, float(_get("checkout_capability_sid_ttl", "1500") or 1500)),
        # 结算地：0 元试用是按市场发的，印度试用必须以印度为结算地
        "billing_country": (_get("checkout_capability_billing_country", "IN") or "IN").upper(),
        "currency": (_get("checkout_capability_currency", "INR") or "INR").upper(),
        "timeout": max(5.0, float(_get("checkout_capability_timeout", "25") or 25)),
    }


def _india_proxy_alive(proxy: str) -> bool:
    """探一探这条印度出口还能不能用（粘性会话会过期/掉线，必须能自愈）。"""
    now = time.time()
    if _INDIA_CHECK["proxy"] == proxy and now - _INDIA_CHECK["at"] < 60:
        return bool(_INDIA_CHECK["ok"])
    alive = False
    session = None
    try:
        session = cffi_requests.Session(impersonate="chrome")
        session.trust_env = False
        session.proxies = {"http": proxy, "https": proxy}
        resp = session.get(_TRACE_URL, timeout=15)
        alive = resp.status_code == 200 and "loc=" in (resp.text or "")
    except Exception:  # noqa: BLE001
        alive = False
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
    _INDIA_CHECK.update(proxy=proxy, ok=alive, at=now)
    return alive


def pick_india_proxy() -> str:
    """取一条**静态**印度出口：固定地区 + 长 TTL，跨多次探测复用同一出口。

    主人要求印度探测用静态出口：探测结算对出口稳定性敏感，每次换 IP 会被
    判成异常。配置了 checkout_capability_india_proxy 时优先用它（自备静态
    代理）；否则从代理池挑一条轮换端点，改写成「region-IN + 固定 sid +
    24 小时 TTL」的粘性会话。

    ⚠️ 不再把 socks5h 改写成 http://。那是 int31 服务的限制，协议链路走
    curl：socks5h 让 DNS 在代理端解析，本地解析既泄露又会造成握手失败。
    """
    configured = (config()["india_proxy"] or "").strip()
    if configured:
        if _india_proxy_alive(configured):
            return configured
        logger.warning("[checkout_capability] 自备印度出口不可用，回落到代理池改写")

    pool_text = ""
    try:
        pool_text = db.get_setting("proxy_pool", "") or ""
    except Exception:  # noqa: BLE001
        return ""
    lines = [line.strip() for line in pool_text.splitlines() if line.strip()]
    if not lines:
        return ""
    template = random.choice(lines)

    def _build(sid_value: str) -> str:
        # 整段 region 记号一起换（region-Rand → region-IN）。只匹配两位字母会
        # 把 region-Rand 变成非法的 region-INnd，出口直接连不通。
        proxy = re.sub(r"region-[A-Za-z0-9]+", "region-IN", template)
        if re.search(r"sid-[A-Za-z0-9]+", proxy):
            proxy = re.sub(r"sid-[A-Za-z0-9]+", f"sid-{sid_value}", proxy, count=1)
        else:
            # 池里的模板故意不带 sid —— 注册链路靠 sessionize_proxy 注入
            # per-task sid（带 sid 的模板会被它跳过，导致所有任务共用同一出口）。
            # 探测需要固定会话，所以这里自己补一段。
            proxy = re.sub(
                r"(region-[A-Za-z0-9]+)", rf"\1-sid-{sid_value}", proxy, count=1
            )
        # 静态会话：TTL 拉长，别中途换 IP
        proxy = re.sub(r"-t-\d+", "-t-1440", proxy)
        return proxy

    def _new_sid() -> str:
        value = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        try:
            db.set_setting("checkout_capability_india_sid", value)
            db.set_setting("checkout_capability_india_sid_at", str(time.time()))
        except Exception:  # noqa: BLE001
            pass
        return value

    def _stored() -> tuple[str, float]:
        try:
            value = (db.get_setting("checkout_capability_india_sid", "") or "").strip()
        except Exception:  # noqa: BLE001
            value = ""
        try:
            created = float(db.get_setting("checkout_capability_india_sid_at", "0") or 0)
        except Exception:  # noqa: BLE001
            created = 0.0
        return value, created

    sid, created_at = _stored()
    ttl = float(config().get("sid_ttl_seconds") or 1500)
    stale = (not sid) or (created_at and time.time() - created_at > ttl)
    if stale:
        sid = _new_sid()
    proxy = _build(sid)
    # 会话死了/过期就换一条：静态不等于死不换，探不通必须能自愈
    if not _india_proxy_alive(proxy):
        logger.warning("[checkout_capability] 印度出口不可用，换新会话重试")
        sid = _new_sid()
        proxy = _build(sid)
    return proxy


def _session_context(email: str) -> dict:
    """组装探测所需的会话上下文：画像、账号 ID、设备 ID、注册会话 Cookie。

    checkout 端点不只看 Bearer token，还会校验同域 Cookie（session-token /
    oai-did 等）与设备身份。缺了这些就是一次「冷请求」，服务端算出来的促销
    与支付资格会与真实浏览器不一致。

    ⚠️ 库里另存着 ``session_token``（就是 ``__Secure-next-auth.session-token``
    的值），但注册流程导出的 ``cookie_header`` 里通常**没有**它 —— 实测某个
    成功注册的号，cookie_header 只有 7 项，恰恰缺了这一个。而它正是 checkout
    最看重的那一项（auth_flow 的注释写明该端点"不仅依赖 session-token，还会
    校验 csrf / oai-sc / CF 相关 cookie"）。有令牌却没用上，等于白拿一次
    400。这里补进 Cookie 头，前面的位置留给它（同名时以库里的令牌为准）。
    """
    record = db.get_registered(email) or {}
    cookie = (record.get("cookie_header") or "").strip()
    session_token = (record.get("session_token") or "").strip()
    if session_token and "__Secure-next-auth.session-token=" not in cookie:
        cookie = (
            f"__Secure-next-auth.session-token={session_token}"
            + (f"; {cookie}" if cookie else "")
        )

    context: dict[str, Any] = {
        "fingerprint": {},
        "account_id": "",
        "device_id": (record.get("device_id") or "").strip(),
        "cookie_header": cookie,
    }
    try:
        context["fingerprint"] = db.latest_fingerprint(email) or {}
    except Exception:  # noqa: BLE001
        context["fingerprint"] = {}

    token = (record.get("access_token") or "").strip()
    if token:
        try:
            from .exporter import _decode_jwt_payload, _get_auth

            claims = _get_auth(_decode_jwt_payload(token))
            context["account_id"] = str(
                claims.get("chatgpt_account_id") or claims.get("account_id") or ""
            ).strip()
        except Exception:  # noqa: BLE001
            context["account_id"] = ""
    return context


def probe(
    access_token: str,
    proxy_url: str = "",
    *,
    wait_seconds: Optional[float] = None,  # 兼容旧签名：协议链路是同步返回的
    session_context: Optional[dict] = None,
) -> dict:
    """探测一个 AT：默认走印度出口。返回 outcome dict。"""
    cfg = config()
    proxy = (proxy_url or "").strip() or pick_india_proxy()
    if not proxy:
        return {
            "ok": False,
            "error": "没有可用代理（代理池为空且未配置印度出口）",
            "rate_limited": False,
        }

    context = dict(session_context or {})

    if cfg["probe_source"] == "protocol":
        return _probe_with_local_protocol(access_token, proxy, cfg, context,
                                          wait_seconds=wait_seconds)

    # ── 默认链路：交给探测服务（我们自己提供印度出口）──
    from checkout_service_probe import probe_via_service

    outcome = probe_via_service(
        access_token,
        proxy=proxy,
        template=proxy if _is_rotatable(proxy) else "",
        wait_seconds=float(wait_seconds or 240.0),
    )
    # 服务端连不上我们给的代理时会换新会话重试；这里再补一步本机验活 + 换一条，
    # 因为最常见的原因就是这条粘性会话已经过期（换 sid 即换出口）。
    if outcome.get("transport_failed") and _is_rotatable(proxy):
        from checkout_service_probe import build_india_proxy

        retry_proxy = build_india_proxy(proxy)
        if _india_proxy_alive(retry_proxy):
            logger.info("[checkout_capability] 传输失败，换一条印度会话重试")
            outcome = probe_via_service(
                access_token, proxy=retry_proxy, template=proxy,
                wait_seconds=float(wait_seconds or 240.0),
            )
    outcome["proxy"] = outcome.get("proxy") or proxy
    outcome.setdefault("rate_limited", False)
    return outcome


def _is_rotatable(proxy: str) -> bool:
    """这条代理是不是「轮换端点模板」（带 region- 记号就能换 sid 换出口）。"""
    return "region-" in (proxy or "")


def _probe_with_local_protocol(
    access_token: str, proxy: str, cfg: dict, context: dict, *, wait_seconds: Optional[float],
) -> dict:
    """自研纯协议链路（payment_probe）+ 被风控拦时的浏览器回退。"""
    from payment_probe import FAILURE_TRANSPORT, FAILURE_RISK_BLOCKED, probe_checkout

    outcome = probe_checkout(
        access_token,
        proxy=proxy,
        fingerprint=context.get("fingerprint") or None,
        account_id=context.get("account_id") or "",
        device_id=context.get("device_id") or "",
        cookie_header=context.get("cookie_header") or "",
        billing_country=cfg["billing_country"],
        currency=cfg["currency"],
        timeout=cfg["timeout"],
    )
    # 协议探测被风控拦（RiskBlocked）时回退浏览器引擎：浏览器自带
    # cf_clearance 与真实 JS 环境。回退失败/再被拦则保留协议结论。
    if cfg["browser_fallback"] and outcome.get("failure_type") == FAILURE_RISK_BLOCKED:
        try:
            from browser_checkout_probe import probe_checkout_browser

            logger.info(
                "[checkout_capability] 协议探测被风控拦，回退浏览器引擎（email=%s）",
                context.get("email", "-"),
            )
            browser_outcome = probe_checkout_browser(
                access_token,
                proxy=proxy,
                fingerprint=context.get("fingerprint") or None,
                account_id=context.get("account_id") or "",
                device_id=context.get("device_id") or "",
                cookie_header=context.get("cookie_header") or "",
                billing_country=cfg["billing_country"],
                currency=cfg["currency"],
                timeout=max(30.0, cfg["timeout"] * 3),
            )
            if browser_outcome.get("ok") or browser_outcome.get("failure_type") != FAILURE_RISK_BLOCKED:
                # 浏览器链路有结论时以它为准，但**资格快照要保留协议侧读到的**：
                # 浏览器探测不读 coupon/accounts，直接覆盖会让结论页丢掉
                # 「账号本来有没有资格」这条关键信息（2026-09-29 实测踩到）。
                eligibility = {
                    key: outcome.get(key)
                    for key in (
                        "coupon_state", "promo_plus_id", "plan_type",
                        "has_active_subscription", "eligible_promo_campaigns",
                        "coupon_http_status", "accounts_http_status",
                    )
                    if outcome.get(key) not in (None, "")
                }
                outcome = {**browser_outcome, **eligibility}
                outcome["protocol_was_blocked"] = True
            else:
                outcome["browser_also_blocked"] = True
                # 2026-09-29 实测更正（两次）：这条 400 既不是出口问题、也不是账号问题 ——
                # 同一个账号、同一条印度住宅出口，交给外部探测服务就能拿到真实金额
                # （169407 INR），而自研协议客户端与自研浏览器客户端都被同一句 400 拦下。
                # 所以被拦的是**我们自己客户端的请求指纹**。别再让主人换出口或换号。
                outcome["error"] = (
                    "风控拦截（400 unusual activity）：账号与出口均已验证无问题"
                    "（同账号+同出口换客户端可出金额），拦的是自研客户端的请求指纹；"
                    "探测请走 int31 链路（checkout_probe_source=int31）"
                )
                outcome["hint"] = "自研客户端指纹被风控；建议使用 int31 探测链路"
        except Exception as exc:  # noqa: BLE001
            logger.warning("[checkout_capability] 浏览器回退失败: %s", str(exc)[:200])

    outcome["proxy"] = proxy
    outcome.setdefault("rate_limited", False)
    outcome.setdefault("transport_failed", outcome.get("failure_type") == FAILURE_TRANSPORT)
    return outcome


def merge_into_check(existing: Optional[dict], outcome: dict) -> dict:
    """把探测结论塞进 plus_check（保留原有字段）。

    ⚠️ 关键不变量：**已探到的金额不能被「这次没探成」覆盖掉**。
    2026-09-29 实测踩到：`86.dare-satrapy` 已经拿到 ₹1694.07，随后一次
    限流（CheckoutRateLimited）把它覆盖成「探测失败」，页面上金额就消失了 ——
    而金额本身并没有变。所以：
      · 成功结论 → 照写（金额、币种、支付方式全部刷新）；
      · **暂时性失败**（限流 / 传输失败 / 冷却跳过）且库里已有金额 → 保留旧金额，
        只把这次失败记到 note 里，并留下 last_attempt_at；
      · 其它失败（账号级：封号、token 失效等）→ 照旧写失败结论。
    """
    from payment_probe import FAILURE_TRANSPORT

    previous = dict((existing or {}).get("plus_check", {}).get("checkout") or {})
    transient = (
        bool(outcome.get("rate_limited"))
        or bool(outcome.get("transport_failed"))
        or bool(outcome.get("risk_cooldown"))
        or outcome.get("failure_type") == FAILURE_TRANSPORT
    )
    previous_amount = previous.get("amount_minor")

    check = dict((existing or {}).get("plus_check") or {})
    check["checkout"] = {
        "ok": bool(outcome.get("ok")),
        "status": outcome.get("status") or "",
        "failure_type": outcome.get("failure_type") or "",
        "result": outcome.get("result"),
        "amount_minor": outcome.get("amount_minor"),
        "currency": outcome.get("currency") or "",
        "free_trial": bool(outcome.get("free_trial")),
        "payment_methods": outcome.get("payment_methods") or [],
        "processor_entity": outcome.get("processor_entity") or "",
        "provider_country": outcome.get("provider_country") or "",
        "task_id": outcome.get("checkout_session_id") or outcome.get("task_id") or "",
        "proxy_used": outcome.get("proxy") or "",
        "checked_at": outcome.get("checked_at") or time.time(),
        "error": outcome.get("error") or "",
        # 来源标记：历史结论来自 int31 外部服务，新结论来自本机协议链路，
        # 列表页据此区分，排查时也能知道该信哪一条。
        "source": outcome.get("source") or "protocol",
        # 资格快照：checkout 被拒时主人要能看出「账号本来就没资格」还是「链路问题」。
        # 缺这段，结论页只有一句风控拦截，看不出所以然（2026-09-29 实测教训）。
        "coupon_state": outcome.get("coupon_state") or "",
        "promo_plus_id": outcome.get("promo_plus_id") or "",
        "plan_type": outcome.get("plan_type") or "",
        "has_active_subscription": bool(outcome.get("has_active_subscription")),
        "eligible_promo_campaigns": list(outcome.get("eligible_promo_campaigns") or []),
        "coupon_http_status": outcome.get("coupon_http_status") or 0,
        "accounts_http_status": outcome.get("accounts_http_status") or 0,
        "hint": outcome.get("hint") or "",
    }

    if outcome.get("transport_failed"):
        # 探测侧连不上代理 ≠ 账号不能付款，别把它写成「不可支付」
        check["checkout"]["note"] = "探测侧网络失败，结论无效"
    elif outcome.get("rate_limited"):
        retry_after = float(outcome.get("retry_after") or 0)
        check["checkout"]["note"] = (
            f"探测服务限流，{int(retry_after)}s 后可再试"
        )
        # 记下这个号的「可重试时间」：队列下次碰到它会直接跳过，等过了这个点再补探，
        # 不再重复撞限流（限流是按 token 的，同一个号短时间内只能探一次）。
        if retry_after > 0:
            check["checkout"]["retry_after_at"] = time.time() + retry_after
    elif outcome.get("risk_cooldown"):
        check["checkout"]["note"] = "风控冷却期内，沿用上次结论"
    elif outcome.get("deferred"):
        check["checkout"]["note"] = "该号仍在探测服务冷却期内，稍后自动补探"

    if transient and not outcome.get("ok") and isinstance(previous_amount, int):
        # 保留上一次的金额，只记录「这次没探成」
        check["checkout"]["amount_minor"] = previous_amount
        check["checkout"]["currency"] = previous.get("currency") or ""
        check["checkout"]["free_trial"] = bool(previous.get("free_trial"))
        check["checkout"]["payment_methods"] = list(previous.get("payment_methods") or [])
        check["checkout"]["processor_entity"] = previous.get("processor_entity") or ""
        check["checkout"]["provider_country"] = previous.get("provider_country") or ""
        check["checkout"]["result"] = previous.get("result")
        check["checkout"]["ok"] = bool(previous.get("ok"))
        check["checkout"]["status"] = previous.get("status") or ""
        check["checkout"]["amount_from"] = previous.get("checked_at")
        check["checkout"]["failure_type"] = previous.get("failure_type") or ""
        check["checkout"]["error"] = previous.get("error") or ""
        check["checkout"]["last_attempt_error"] = outcome.get("error") or ""
        check["checkout"]["last_attempt_at"] = outcome.get("checked_at") or time.time()
    return check


def probe_email(email: str, proxy_url: str = "", *, store: bool = True) -> dict:
    """按邮箱探一次并把结论写进注册记录。

    风控冷却：上次结论是 RiskBlocked 且还在冷却期内时，直接复用该结论、
    不发请求。「unusual activity, try again later」是时间性拦截，反复打
    只会把 flag 越养越重。
    """
    from payment_probe import FAILURE_RISK_BLOCKED

    record = db.get_registered(email)
    if not record:
        return {"ok": False, "email": email, "error": "本地没有这个号的凭证"}
    token = (record.get("access_token") or "").strip()
    if not token:
        return {"ok": False, "email": email, "error": "该号没有 access_token"}

    # 风控冷却只对**自研协议链路**生效：那条链路反复打同一个号会把 flag 养重。
    # int31 链路不能套用 —— 服务端的限流是**按 token** 的、冷却窗口约 40 分钟由它自己给，
    # 套 6 小时冷却会让队列里的号压根不被重探（2026-09-29 实测：185 个待探号全被
    # 旧结论的 RiskBlocked 命中冷却，队列空转成"失败"）。
    cooldown = config()["risk_cooldown_seconds"] if config()["probe_source"] == "protocol" else 0.0
    if cooldown > 0:
        previous = ((record.get("extra") or {}).get("plus_check") or {}).get("checkout") or {}
        if previous.get("failure_type") == FAILURE_RISK_BLOCKED:
            checked_at = float(previous.get("checked_at") or 0)
            if time.time() - checked_at < cooldown:
                logger.info(
                    "[checkout_capability] %s 上次被风控拦，冷却期内跳过（剩 %.0f 分钟）",
                    email, (cooldown - (time.time() - checked_at)) / 60,
                )
                return {
                    "ok": False,
                    "email": email,
                    "status": previous.get("status") or "FAILED",
                    "failure_type": FAILURE_RISK_BLOCKED,
                    "error": previous.get("error") or "风控冷却期内，暂不重试",
                    "risk_cooldown": True,
                    "source": previous.get("source") or "protocol",
                    "checked_at": previous.get("checked_at"),
                }

    outcome = probe(token, proxy_url, session_context=_session_context(email))
    outcome["email"] = email
    if store:
        merged = merge_into_check(record.get("extra"), outcome)
        db.update_plus_check(email, {**merged, "checked_at": merged.get("checked_at", time.time())})
    return outcome


def probe_email_if_due(email: str, proxy_url: str = "") -> dict:
    """队列用：还在「探测服务冷却期」内的号直接跳过，不发请求、不改结论。

    限流是按 token 的（同一个号短时间内只能探一次），所以重复探只会拿到 429 并
    在页面上留下一条没用的失败记录。这里读上次记下的 `retry_after_at`，没到点就
    返回 deferred，交给队列稍后自动补探。
    """
    record = db.get_registered(email) or {}
    checkout = ((record.get("extra") or {}).get("plus_check") or {}).get("checkout") or {}
    due_at = checkout.get("retry_after_at")
    try:
        due_at = float(due_at or 0)
    except (TypeError, ValueError):
        due_at = 0.0
    if due_at > time.time():
        return {
            "ok": False,
            "email": email,
            "deferred": True,
            "retry_after_at": due_at,
            "retry_in": due_at - time.time(),
            "amount_minor": checkout.get("amount_minor"),
            "source": checkout.get("source") or "",
        }
    return probe_email(email, proxy_url)


def queue_status() -> dict:
    """给 WebUI 看：排队多少、正在探谁、上次的错误与结论。"""
    cfg = config()
    return {
        "enabled": cfg["enabled"],
        "auto": cfg["auto"],
        "queued": _QUEUE.qsize(),
        "processing": _STATE["processing"],
        "deferred": len(_DEFERRED),
        "done": _STATE["done"],
        "failed": _STATE["failed"],
        "rate_limited_until": _STATE["rate_limited_until"],
        "last_error": _STATE["last_error"],
        "last_result": _STATE["last_result"],
        "interval_seconds": cfg["interval_seconds"],
        # 实际生效的探测链路（int31 / protocol）——以前这里写死 "protocol"，
        # 排查时看不出队列到底走的哪条链路。
        "source": cfg["probe_source"],
    }


def enqueue(email: str) -> bool:
    """把一个号放进自动探测队列（去重）。返回是否真的入队。"""
    cfg = config()
    if not cfg["enabled"] or not cfg["auto"]:
        return False
    key = (email or "").strip().lower()
    if not key or key in _QUEUED:
        return False
    _QUEUED.add(key)
    _QUEUE.put(key)
    _ensure_worker()
    logger.info("[checkout_capability] 入队待探测: %s (队列 %s)", key, _QUEUE.qsize())
    return True


def _ensure_worker() -> None:
    """按配置并发数把 worker 拉满（缺几个补几个）。

    ⚠️ 为什么能并发：限流是**按 token** 的（同一个号反复探才会 429），号与号之间
    互不影响，所以并行探 N 个号不会额外触发限流。串行时每个号要 submit + 轮询等
    结论约 25 秒，170 个号要一个半小时；4 路并发后 20 分钟左右跑完。
    提交侧仍有全局最小间隔（见 checkout_service_probe._throttle_submit），
    避免多路同时 submit 形成突发。
    """
    global _WORKERS
    with _WORKER_LOCK:
        _WORKERS = [t for t in _WORKERS if t.is_alive()]
        want = config()["concurrency"]
        while len(_WORKERS) < want:
            index = len(_WORKERS)
            thread = threading.Thread(
                target=_worker_loop, daemon=True,
                name=f"checkout-capability-worker-{index}",
            )
            thread.start()
            _WORKERS.append(thread)


# 等冷却的号：email → 可重试时间戳。队列空了以后由 worker 到点自动补探，
# 不需要主人手动再点一次。
_DEFERRED: dict[str, float] = {}


def _defer(email: str, due_at: float) -> None:
    with _WORKER_LOCK:
        _DEFERRED[email] = max(float(due_at or 0), time.time() + 5.0)


def _take_due_deferred(now: float | None = None) -> list[str]:
    """把到点（或已过期）的号取出来重新入队。"""
    now = time.time() if now is None else now
    with _WORKER_LOCK:
        due = [email for email, at in _DEFERRED.items() if at <= now]
        for email in due:
            _DEFERRED.pop(email, None)
    for email in due:
        _QUEUED.discard(email)
        _QUEUE.put(email)
    return due


def _next_deferred_delay(now: float | None = None, *, cap: float = 30.0) -> float | None:
    """还有多久最早的那个号到点（最多等 cap 秒，便于周期性复查）。"""
    now = time.time() if now is None else now
    with _WORKER_LOCK:
        if not _DEFERRED:
            return None
        soonest = min(_DEFERRED.values())
    return max(1.0, min(cap, soonest - now))


def _worker_loop() -> None:
    """后台探测 worker（可并发多个）；每个号之间留间隔。

    可并发的前提：限流是**按 token** 的 —— 号与号互不影响，同一时刻探不同号
    不会触发限流（2026-09-29 实测 + 另一台机器的聊天记录印证）。提交侧由
    checkout_service_probe._throttle_submit 保证全局最小提交间隔，防突发。
    """
    worker_name = threading.current_thread().name
    while True:
        email = _QUEUE.get(timeout=300)
        outcome: dict = {}
        try:
            with _WORKER_LOCK:
                _PROCESSING[worker_name] = email
            _STATE["processing"] = "、".join(sorted(_PROCESSING.values()))
            outcome = probe_email_if_due(email)
            if outcome.get("deferred"):
                # 该号还在探测服务的冷却期内：不探测、不写失败，交给队列到点补探
                _defer(email, float(outcome.get("retry_after_at") or 0))
                logger.info(
                    "[checkout_capability] %s 冷却中（剩 %.0f 分钟），稍后自动补探",
                    email, float(outcome.get("retry_in") or 0) / 60,
                )
            elif outcome.get("ok"):
                with _WORKER_LOCK:
                    _STATE["done"] += 1
                    _STATE["last_result"] = {
                        "email": email,
                        "amount_minor": outcome.get("amount_minor"),
                        "currency": outcome.get("currency"),
                        "free_trial": outcome.get("free_trial"),
                        "checked_at": outcome.get("checked_at"),
                    }
                logger.info(
                    "[checkout_capability] %s -> %s %s%s",
                    email,
                    "0元可领" if outcome.get("free_trial") else "需付款",
                    outcome.get("amount_minor"),
                    outcome.get("currency"),
                )
            else:
                with _WORKER_LOCK:
                    _STATE["failed"] += 1
                    _STATE["last_error"] = (
                        outcome.get("error")
                        or outcome.get("failure_type")
                        or outcome.get("status")
                        or "unknown"
                    )
                logger.warning(
                    "[checkout_capability] %s 探测未通过: %s",
                    email, _STATE["last_error"],
                )
        except Exception as exc:  # noqa: BLE001
            with _WORKER_LOCK:
                _STATE["failed"] += 1
                _STATE["last_error"] = str(exc)[:200]
            logger.warning("[checkout_capability] 队列任务异常: %s", str(exc)[:200])
        finally:
            with _WORKER_LOCK:
                _PROCESSING.pop(worker_name, None)
                _STATE["processing"] = "、".join(sorted(_PROCESSING.values()))
            _QUEUED.discard(email)
            try:
                _QUEUE.task_done()
            except Exception:  # noqa: BLE001
                pass
        # 万一还是撞上限流（例如同一个号被别处探过）：记下可重试时间、跳过该号继续，
        # 并把该号排进补探队列 —— 不再让它以「失败」留在页面上。
        if outcome.get("rate_limited"):
            retry_after = float(outcome.get("retry_after") or 0)
            _STATE["rate_limited_until"] = time.time() + retry_after
            if retry_after > 0:
                _defer(email, time.time() + retry_after)
            logger.warning(
                "[checkout_capability] %s 被服务端限流（%.1f 分钟后自动补探），先继续下一个",
                email, retry_after / 60,
            )
        # 队列空了但还有等冷却的号：等最近的到点补探（而不是收工）。
        if _QUEUE.empty():
            delay = _next_deferred_delay()
            if delay is not None:
                time.sleep(delay)
                requeued = _take_due_deferred()
                if requeued:
                    logger.info(
                        "[checkout_capability] 冷却结束，补探 %d 个号", len(requeued)
                    )
        time.sleep(config()["interval_seconds"])
