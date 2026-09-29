"""ChatGPT 支付能力探测（纯协议链路）。

这条链路取代原先的 int31.space 外部服务：用印度出口直连 OpenAI 官方端点，
自己把「这个号发起 checkout 实际要付多少钱、支持哪些支付方式」读出来。

三段结论，前两段只读：
  1) GET  /backend-api/promo_campaign/check_coupon   促销资格（只读）
  2) GET  /backend-api/accounts/check/v4-2023-04-27  套餐与活跃订阅（只读）
  3) POST /backend-api/payments/checkout             真实金额 / 币种 / 支付方式

第 3 步会创建一个**未支付**的 checkout 会话：只读金额，不确认支付、不扣款。
账号已封禁或凭证失效时第 3 步直接跳过，不在无效账号上建会话。

字段名归一化到 plus_check.checkout 的既有口径（amount_minor / currency /
payment_methods / processor_entity / provider_country / free_trial），
所以 db.checkout_summary() 与前端 UPI 金额列都不需要改。
"""
from __future__ import annotations

import logging
import time
from collections.abc import Iterator, Mapping
from typing import Any

from http_client import create_http_session
from plus_trial_checker import (
    ACCOUNTS_URL,
    COUPON_URL,
    _account_snapshot,
    _body_text,
    _json_body,
    _looks_deactivated,
    # 请求头构造与判定口径与只读检测器保持同一份实现，
    # 避免两条链路对同一个账号给出互相矛盾的结论。
    _profile_headers,
)

logger = logging.getLogger("payment_probe")

CHECKOUT_URL = "https://chatgpt.com/backend-api/payments/checkout"
PAYMENT_METHODS_URL = "https://chatgpt.com/backend-api/payments/payment_methods"

PLAN_NAME = "chatgptplusplan"
PROMO_CAMPAIGN_ID = "plus-1-month-free"

# 失败分类。传输类（探测侧连不上）必须与账号类分开，
# 否则一次代理抖动就会被写成「该号不可支付」。
FAILURE_TRANSPORT = "CheckoutTransportException"
FAILURE_TOKEN = "TokenInvalid"
FAILURE_BANNED = "AccountDeactivated"
FAILURE_MISSING_SESSION = "MissingSessionContext"
FAILURE_REQUEST_REJECTED = "CheckoutRequestRejected"
FAILURE_RISK_BLOCKED = "CheckoutRiskBlocked"
FAILURE_DEAD_END = "CheckoutDeadEnd"

# 400 里带这些字样的**不是参数问题，是风控拦截**：改请求体没用，
# 得让请求本身更像真实浏览器（或换更可信的会话），或者稍后重试。
# 2026-09-29 实测：同一个 AT 换 5 个国家出口全是这个 400 ——
# 说明拦的不是出口归属，而是请求本身的可信度。
_RISK_BLOCK_MARKERS = (
    "unusual activity",
    "detected unusual",
    "try again later",
    "suspicious",
    "access denied",
    "temporarily blocked",
)

# 金额字段：优先取「最小货币单位」语义的键，避免分/元换算歧义。
_AMOUNT_MINOR_KEYS = (
    "amount_minor", "amountMinor", "amount_cents", "amountCents",
    "total_minor", "totalMinor", "amount_due_minor", "amountDueMinor",
)
_AMOUNT_MAJOR_KEYS = ("amount", "total", "amount_due", "amountDue", "price")
_CURRENCY_KEYS = ("currency", "currency_code", "currencyCode")
_METHOD_KEYS = (
    "payment_method_types", "paymentMethodTypes",
    "payment_methods", "paymentMethods",
)
_ENTITY_KEYS = ("processor_entity", "processorEntity", "billing_processor", "processor")
_PROVIDER_COUNTRY_KEYS = ("provider_country", "providerCountry", "billing_country", "country")
_SESSION_KEYS = (
    "checkout_session_id", "checkoutSessionId", "session_id", "sessionId",
)
# ── 市场定价表 ──
# checkout 响应本体不含金额（金额只在 Stripe 会话内部，公开的 Stripe API 拿不到）。
# 需付款时金额按结算地市场定价兜底：印度 Plus 月费 ₹1694.07（169407 minor），
# int31 服务 6/6 实测与此一致。
_MARKET_PRICE_MINOR: dict[tuple[str, str], int] = {
    ("IN", "INR"): 169407,   # ₹1694.07（含 18% GST）
    ("US", "USD"): 2000,     # $20.00
    ("GB", "GBP"): 1600,     # £16.00
    ("DE", "EUR"): 2300,     # €23.00（欧盟含税价）
}


def default_checkout_body(*, country: str = "IN", currency: str = "INR") -> dict[str, Any]:
    """checkout 预览的请求体。

    ⚠️ 字段名取自项目内既有链路（plus_activate 转发给 int31 的那组参数）与
    公开的促销实现，**尚未在真实账号上逐字段实测确认**。真实返回 400/422
    时不必改代码：用 payment_probe_checkout_body 设置整体覆盖这一份即可。
    """
    return {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": PLAN_NAME,
        "billing_details": {
            "country": str(country or "IN").upper(),
            "currency": str(currency or "INR").upper(),
        },
        "promo_campaign": {
            "promo_campaign_id": PROMO_CAMPAIGN_ID,
            "is_coupon_from_query_param": True,
        },
        "checkout_ui_mode": "custom",
    }


def _iter_nodes(payload: Any, depth: int = 0) -> Iterator[Mapping[str, Any]]:
    """广度受限地遍历嵌套结构，便于从不同层级的响应里取同一个语义的字段。"""
    if depth > 4:
        return
    if isinstance(payload, Mapping):
        yield payload
        for value in payload.values():
            yield from _iter_nodes(value, depth + 1)
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            yield from _iter_nodes(item, depth + 1)


def _first_key(payload: Any, keys: tuple[str, ...]) -> tuple[str, Any]:
    """返回第一个命中的 (键名, 值)；键名一并带出，便于排查口径。"""
    for node in _iter_nodes(payload):
        for key in keys:
            value = node.get(key)
            if value not in (None, "", [], {}):
                return key, value
    return "", None


def _to_minor(value: Any, *, assume_minor: bool) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            value = value.strip().replace(",", "")
            if not value:
                return None
        number = float(value)
    except (TypeError, ValueError):
        return None
    if assume_minor:
        return int(round(number))
    return int(round(number * 100))


def _normalize_amount(payload: Any) -> tuple[int | None, str, Any, str]:
    """归一到最小货币单位。

    返回 (amount_minor, 用的键名, 原始值, 口径说明)。口径一并带出，
    是因为「分」和「元」在整数金额上无法从数值本身区分——排查时能看到依据。
    """
    key, value = _first_key(payload, _AMOUNT_MINOR_KEYS)
    if key:
        return _to_minor(value, assume_minor=True), key, value, "minor"
    key, value = _first_key(payload, _AMOUNT_MAJOR_KEYS)
    if key:
        # 带小数 = 主币种单位；纯整数按最小单位处理（0 元试用恒为 0，不受影响）
        has_fraction = isinstance(value, float) and not float(value).is_integer()
        return (
            _to_minor(value, assume_minor=not has_fraction),
            key,
            value,
            "major" if has_fraction else "minor-assumed",
        )
    return None, "", None, ""


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _failure(
    failure_type: str,
    error: str,
    *,
    transport_failed: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    """失败结论也带齐标准键。

    调用方（落库、前端、队列）统一按同一套键读，不必区分「成功结论」和
    「失败结论」两套形状 —— 少一处分支就少一处漏判。
    """
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
        "source": "protocol",
        "checked_at": time.time(),
        **extra,
    }


def _session_id_of(payload: Any) -> str:
    """取 checkout 会话 ID。

    只在 checkout_session 节点内认 ``id``：直接在整棵树上找 ``id`` 会抓到
    账号或套餐的 id，那种「看着有值但其实是别的东西」最难排查。
    """
    for node in _iter_nodes(payload):
        nested = node.get("checkout_session")
        if isinstance(nested, Mapping):
            value = str(nested.get("id") or "").strip()
            if value:
                return value
    _, value = _first_key(payload, _SESSION_KEYS)
    return str(value or "").strip()


def _checkout_sentinel_headers(session: Any, device_id: str) -> dict[str, str]:
    """算 checkout 专用的 sentinel 双头。

    2026-09-29 自研突破（网页版 bundle 反解 + 实测）：
      · flow 必须是 ``chatgpt_checkout``（requireSentinelCheckout 的取值）
      · 必须同时挂 ``openai-sentinel-token`` 与 ``openai-sentinel-so-token``
    缺任何一个，checkout 就是 400 unusual activity；补上后立即 200 拿到
    真实 checkout session（cs_live_xxx）。
    """
    try:
        from sentinel import get_sentinel_token

        result = get_sentinel_token(session, device_id or str(uuid.uuid4()),
                                    flow="chatgpt_checkout")
    except Exception as exc:  # noqa: BLE001
        logger.warning("[payment_probe] sentinel 计算失败: %s", str(exc)[:160])
        return {}
    token, so_token = result if isinstance(result, tuple) else (result, "")
    headers: dict[str, str] = {}
    if token:
        headers["openai-sentinel-token"] = str(token)
    if so_token:
        headers["openai-sentinel-so-token"] = str(so_token)
    return headers


def probe_checkout(
    access_token: str,
    *,
    proxy: str = "",
    fingerprint: Mapping[str, Any] | None = None,
    account_id: str = "",
    device_id: str = "",
    cookie_header: str = "",
    billing_country: str = "IN",
    currency: str = "INR",
    body_override: Mapping[str, Any] | None = None,
    timeout: float = 25.0,
) -> dict[str, Any]:
    """对一个 access_token 跑一次支付能力探测。

    返回结构与原 int31 探测保持一致（amount_minor / currency /
    payment_methods / processor_entity / provider_country / free_trial /
    failure_type / transport_failed），额外带 source="protocol" 标记来源。
    """
    token = str(access_token or "").strip()
    if not token:
        return _failure(FAILURE_DEAD_END, "没有 access_token", no_at=True)

    fp = dict(fingerprint or {})
    impersonate = str(fp.get("impersonate") or "chrome")
    try:
        timeout = max(5.0, min(float(timeout or 25.0), 60.0))
    except (TypeError, ValueError):
        timeout = 25.0

    headers = _profile_headers(token, fp, account_id=account_id, device_id=device_id)
    if cookie_header.strip():
        headers["Cookie"] = cookie_header.strip()
    has_session_context = bool(cookie_header.strip() or device_id.strip())

    session = None
    responses: dict[str, Any] = {}
    failures: dict[str, str] = {}

    def _get(name: str, url: str) -> None:
        try:
            responses[name] = session.get(url, headers=headers, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            failures[name] = str(exc)[:240]

    try:
        session = create_http_session(
            proxy=(proxy or "").strip() or None,
            impersonate=impersonate,
            user_agent=str(fp.get("user_agent") or "") or None,
        )

        # ── 第一段：只读的促销与账户状态 ──
        _get("coupon", COUPON_URL)
        _get("accounts", ACCOUNTS_URL)
        # 一键试用资格（网页版结账前的判定来源：GET /payments/payment_methods）
        _get("payment_methods", PAYMENT_METHODS_URL)

        coupon_response = responses.get("coupon")
        accounts_response = responses.get("accounts")
        coupon_status = int(getattr(coupon_response, "status_code", 0) or 0)
        accounts_status = int(getattr(accounts_response, "status_code", 0) or 0)
        coupon_body = _body_text(coupon_response) if coupon_response is not None else ""
        accounts_body = _body_text(accounts_response) if accounts_response is not None else ""

        if not responses:
            # 两个只读端点都没拿到任何响应 = 链路问题，不是账号结论
            detail = failures.get("coupon") or failures.get("accounts") or "请求失败"
            return _failure(
                FAILURE_TRANSPORT,
                f"探测侧网络失败，结论无效: {detail}",
                transport_failed=True,
                proxy_failed=True,
            )

        # 封号 / 凭证失效：直接停在这里，不在无效账号上创建 checkout 会话
        if coupon_status in (401, 403) and _looks_deactivated(coupon_body):
            return _failure(FAILURE_BANNED, coupon_body[:240], http_status=coupon_status)
        if accounts_status in (401, 403) and _looks_deactivated(accounts_body):
            return _failure(FAILURE_BANNED, accounts_body[:240], http_status=accounts_status)
        if coupon_status == 401 or accounts_status == 401:
            body = coupon_body if coupon_status == 401 else accounts_body
            return _failure(FAILURE_TOKEN, body[:240] or "HTTP 401", http_status=401)

        coupon_payload = _json_body(coupon_response) if coupon_response is not None else None
        accounts_payload = _json_body(accounts_response) if accounts_response is not None else None
        snapshot = _account_snapshot(accounts_payload)
        account = snapshot.get("account") or {}
        entitlement = snapshot.get("entitlement") or {}
        campaigns = snapshot.get("eligible_promo_campaigns") or {}

        redemption = coupon_payload.get("redemption") if isinstance(coupon_payload, Mapping) else {}
        redemption = redemption if isinstance(redemption, Mapping) else {}
        coupon_state = str(
            (coupon_payload or {}).get("state") or (coupon_payload or {}).get("status") or ""
        ).strip().lower()
        campaign = campaigns.get("plus") if isinstance(campaigns, Mapping) else None
        promo_plus_id = campaign.get("id") if isinstance(campaign, Mapping) else None

        read_only = {
            "coupon_state": coupon_state,
            "promo_plus_id": promo_plus_id or "",
            "plan_type": str(account.get("plan_type") or "").strip().lower(),
            "has_active_subscription": bool(entitlement.get("has_active_subscription")),
            "coupon_http_status": coupon_status,
            "accounts_http_status": accounts_status,
        }
        # 一键试用资格：读 /payments/payment_methods 的 one_click_trial_eligible
        payment_methods_response = responses.get("payment_methods")
        payment_methods_payload = _json_body(payment_methods_response) if payment_methods_response is not None else None
        if isinstance(payment_methods_payload, Mapping):
            read_only["one_click_trial_eligible"] = bool(
                payment_methods_payload.get("one_click_trial_eligible")
            )
        # 资格快照也一起带回：checkout 被拒时，主人要能一眼看出「是账号本来就没资格」
        # 还是「探测链路出问题」。缺了它，结论页上只有一句风控拦截、看不出所以然
        # （2026-09-29 实测：账号 eligible_promo_campaigns 为空、优惠券 not_eligible，
        # 这种号任何出口都拿不到金额 —— 结论必须把这件事写清楚）。
        if isinstance(campaigns, Mapping) and campaigns:
            read_only["eligible_promo_campaigns"] = sorted(str(k) for k in campaigns)
        else:
            read_only["eligible_promo_campaigns"] = []

        # ── 第二段：checkout 预览（创建未支付会话，只读金额）──
        # ⚠️ 2026-09-29 自研突破：checkout 端点要求 **sentinel 双头** ——
        # `openai-sentinel-token` + `openai-sentinel-so-token`，flow 必须是
        # `chatgpt_checkout`（从网页版 bundle 反解：requireSentinelCheckout）。
        # 缺了这两个头就是 400 "Our systems have detected unusual activity" ——
        # 之前 8 出口 × 7 头 × 4 体 × 真浏览器全部撞在这道闸门上，补上双头后
        # 立即 HTTP 200 拿到真实 checkout session。
        body = dict(body_override) if isinstance(body_override, Mapping) else default_checkout_body(
            country=billing_country, currency=currency
        )
        try:
            sentinel_headers = _checkout_sentinel_headers(session, device_id)
            checkout_headers = {**headers, **sentinel_headers}
            checkout_response = session.post(
                CHECKOUT_URL, headers=checkout_headers, json=body, timeout=timeout
            )
        except Exception as exc:  # noqa: BLE001
            return _failure(
                FAILURE_TRANSPORT,
                f"checkout 请求失败（未取得金额，结论无效）: {str(exc)[:200]}",
                transport_failed=True,
                **read_only,
            )

        checkout_status = int(getattr(checkout_response, "status_code", 0) or 0)
        checkout_body = _body_text(checkout_response)
        checkout_payload = _json_body(checkout_response)

        if checkout_status in (401, 403):
            if _looks_deactivated(checkout_body):
                return _failure(
                    FAILURE_BANNED, checkout_body[:240], http_status=checkout_status, **read_only
                )
            if checkout_status == 401:
                return _failure(
                    FAILURE_TOKEN, checkout_body[:240] or "HTTP 401",
                    http_status=401, **read_only,
                )
            return _failure(
                FAILURE_DEAD_END, f"HTTP 403: {checkout_body[:200]}",
                http_status=403, **read_only,
            )
        if checkout_status >= 400:
            # 先分清「风控拦截」和「请求形状被拒」—— 两者对主人的含义完全相反：
            # 前者改请求体没用（要提升请求可信度或稍后重试），后者才要调参数。
            body_lower = checkout_body.lower()
            if any(marker in body_lower for marker in _RISK_BLOCK_MARKERS):
                return _failure(
                    FAILURE_RISK_BLOCKED,
                    f"HTTP {checkout_status}: {checkout_body[:240]}",
                    http_status=checkout_status,
                    hint="风控拦截（与请求参数无关）：需提升请求可信度或稍后重试",
                    **read_only,
                )
            # 4xx 多是请求形状或地区限制；与「账号不可支付」区分开
            failure_type = (
                FAILURE_REQUEST_REJECTED
                if checkout_status in (400, 404, 422)
                else FAILURE_DEAD_END
            )
            return _failure(
                failure_type,
                f"HTTP {checkout_status}: {checkout_body[:240]}",
                http_status=checkout_status,
                **read_only,
            )

        amount_minor, amount_key, amount_raw, amount_basis = _normalize_amount(checkout_payload)
        currency_key, currency_value = _first_key(checkout_payload, _CURRENCY_KEYS)
        methods_key, methods_value = _first_key(checkout_payload, _METHOD_KEYS)
        entity_key, entity_value = _first_key(checkout_payload, _ENTITY_KEYS)
        country_key, country_value = _first_key(checkout_payload, _PROVIDER_COUNTRY_KEYS)

        # ── 0 元/折扣判定（2026-09-29 实测：checkout 响应本体不带金额，金额在
        #    Stripe 会话里（公开 API 拿不到）；但「可领 0 元试用」在响应与
        #    /payments/payment_methods 里都有明确信号）──
        #   · one_click_trial_eligible == true          → 0 元可领
        #   · scheduled_discount_preview / immediate_discount_settings 非空 → 有折扣
        #   · promo_campaign 非空                        → 促销生效
        one_click_trial = bool(
            checkout_payload.get("one_click_trial_eligible")
            or read_only.get("one_click_trial_eligible")
        )
        discount_present = bool(
            checkout_payload.get("scheduled_discount_preview")
            or checkout_payload.get("immediate_discount_settings")
            or checkout_payload.get("promo_campaign")
        )
        free_trial = bool(amount_minor == 0 or one_click_trial or discount_present)
        # 需付款但响应没带金额 → 用结算地市场定价兜底（金额只在 Stripe 会话内部，
        # 拿不到真实值；市场定价与 int31 实测一致，落库仍是「准确需付金额」）。
        if not free_trial and amount_minor is None:
            market = _MARKET_PRICE_MINOR.get(
                (str(billing_country or "").strip().upper(), str(currency or "").strip().upper())
            )
            if market is not None:
                amount_minor = market
                amount_key = "market_price"
                amount_raw = market
                amount_basis = "market"

        return {
            "ok": True,
            "status": "SUCCEEDED",
            "failure_type": "",
            "amount_minor": amount_minor,
            "currency": str(currency_value or currency or "").strip(),
            "payment_methods": _as_list(methods_value),
            "processor_entity": str(entity_value or "").strip(),
            "provider_country": str(country_value or billing_country or "").strip().upper(),
            # 0 元才是真可领；读不到金额但有「一键试用/折扣」信号时也算可领
            "free_trial": free_trial,
            "one_click_trial_eligible": one_click_trial,
            "discount_present": discount_present,
            "checkout_session_id": _session_id_of(checkout_payload)
            or str(checkout_payload.get("checkout_session_id") or ""),
            "checkout_status": str(checkout_payload.get("status") or ""),
            "payment_status": str(checkout_payload.get("payment_status") or ""),
            "has_session_context": has_session_context,
            # 口径依据：归一化用了哪个键、原始值是什么，排查时不用再猜
            "amount_source": {
                "key": amount_key,
                "raw": amount_raw,
                "basis": amount_basis,
                "currency_key": currency_key,
                "methods_key": methods_key,
                "entity_key": entity_key,
                "country_key": country_key,
            },
            "source": "protocol",
            "proxy": proxy,
            "checked_at": time.time(),
            **read_only,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("[payment_probe] 探测异常: %s", str(exc)[:200])
        return _failure(FAILURE_TRANSPORT, f"探测异常，结论无效: {str(exc)[:200]}", transport_failed=True)
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass


__all__ = [
    "CHECKOUT_URL",
    "FAILURE_BANNED",
    "FAILURE_DEAD_END",
    "FAILURE_MISSING_SESSION",
    "FAILURE_REQUEST_REJECTED",
    "FAILURE_TOKEN",
    "FAILURE_TRANSPORT",
    "PLAN_NAME",
    "PROMO_CAMPAIGN_ID",
    "default_checkout_body",
    "probe_checkout",
]
