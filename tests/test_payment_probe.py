"""协议支付探测：金额解析、失败分类、会话上下文。

这些用例盯住两个容易出事的地方：
  · 金额归一化 —— 字段名在不同响应里不一样，读错会让「0 元可领」判反；
  · 失败分类 —— 传输失败或参数被拒绝不能写成「该号不可支付」。
"""
from __future__ import annotations

import json

import pytest

import payment_probe


class FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text else ("" if payload is None else json.dumps(payload))

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    """按 URL 分派响应；post 单独记数，用来断言「封号时不建 checkout 会话」。"""

    def __init__(self, coupon=None, accounts=None, checkout=None):
        self.coupon = coupon
        self.accounts = accounts
        self.checkout = checkout
        self.get_calls: list[str] = []
        self.post_calls: int = 0

    def get(self, url, **kwargs):
        self.get_calls.append(url)
        target = self.coupon if "check_coupon" in url else self.accounts
        if isinstance(target, Exception):
            raise target
        if target is None:
            raise RuntimeError("no fixture for " + url)
        return target

    def post(self, url, **kwargs):
        self.post_calls += 1
        if isinstance(self.checkout, Exception):
            raise self.checkout
        if self.checkout is None:
            raise RuntimeError("no fixture for post")
        return self.checkout

    def close(self):
        pass


def _accounts_free(**account):
    return FakeResponse(
        200,
        {
            "accounts": {
                "acc-1": {
                    "account": {"plan_type": "free", **account},
                    "entitlement": {},
                    "eligible_promo_campaigns": {},
                }
            }
        },
    )


def _run(monkeypatch, *, coupon, accounts=None, checkout=None, **kwargs):
    session = FakeSession(coupon=coupon, accounts=accounts or _accounts_free(), checkout=checkout)
    monkeypatch.setattr(payment_probe, "create_http_session", lambda **_: session)
    # sentinel 计算会真跑 node 子进程（测试禁网 → 每个用例空等子进程超时），
    # 这里 mock 掉；sentinel 头的行为由 test_checkout_sentinel_headers 单独覆盖。
    monkeypatch.setattr(payment_probe, "_checkout_sentinel_headers",
                        lambda _s, _d: {"openai-sentinel-token": "fixture"})
    outcome = payment_probe.probe_checkout(
        "access-token",
        proxy="socks5h://user:pass@in.example:1080",
        cookie_header="oai-did=fixture",
        device_id="device-1",
        **kwargs,
    )
    return outcome, session


# ──────────────────────── 金额与支付方式 ────────────────────────


def test_zero_amount_is_free_trial(monkeypatch):
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "eligible"}),
        checkout=FakeResponse(
            200,
            {
                "amount_minor": 0,
                "currency": "inr",
                "payment_method_types": ["card", "upi"],
                "processor_entity": "openai_llc",
                "provider_country": "IN",
            },
        ),
    )

    assert outcome["ok"] is True
    assert outcome["free_trial"] is True
    assert outcome["amount_minor"] == 0
    assert outcome["currency"] == "inr"
    assert outcome["payment_methods"] == ["card", "upi"]
    assert outcome["processor_entity"] == "openai_llc"
    assert outcome["provider_country"] == "IN"
    assert outcome["source"] == "protocol"


def test_paid_amount_is_not_free_trial(monkeypatch):
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "ineligible"}),
        checkout=FakeResponse(200, {"amount_minor": 169407, "currency": "inr"}),
    )

    assert outcome["ok"] is True
    assert outcome["free_trial"] is False
    assert outcome["amount_minor"] == 169407


def test_major_unit_amount_with_fraction_is_converted(monkeypatch):
    """带真实小数的 amount 是主币种单位（卢比），要乘 100 换成最小单位。

    注意 1999.00 这类「整数值的浮点」经 JSON 往返会变成 1999.0，小数信息
    本来就不存在，因此这里用真正带小数的 19.99 来验证换算分支。
    """
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "ineligible"}),
        checkout=FakeResponse(200, {"amount": 19.99, "currency": "inr"}),
    )

    assert outcome["amount_minor"] == 1999
    assert outcome["amount_source"]["basis"] == "major"


def test_amount_key_and_raw_value_are_reported(monkeypatch):
    """归一化依据要落进结论，读错口径时排查不用重跑。"""
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "ineligible"}),
        checkout=FakeResponse(200, {"amountCents": 50000, "currency": "inr"}),
    )

    assert outcome["amount_minor"] == 50000
    assert outcome["amount_source"]["key"] == "amountCents"
    assert outcome["amount_source"]["basis"] == "minor"


def test_amount_read_from_nested_checkout_session(monkeypatch):
    """金额可能嵌在会话对象里，必须能挖出来。"""
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "ineligible"}),
        checkout=FakeResponse(
            200,
            {"checkout_session": {"id": "cs_1", "amount_minor": 0, "currency": "inr"}},
        ),
    )

    assert outcome["amount_minor"] == 0
    assert outcome["free_trial"] is True
    assert outcome["checkout_session_id"] == "cs_1"


def test_missing_amount_never_claims_free_trial(monkeypatch):
    """读不到金额时不能给「0 元可领」这个结论。

    2026-09-29 演进：checkout 响应本体不含金额（金额在 Stripe 会话内部），
    需付款时按结算地市场定价兜底（印度 INR Plus = 169407 minor，int31 6/6 实测一致），
    所以 amount_minor 不再为 None —— 但 free_trial 仍必须是 False。
    """
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "eligible"}),
        checkout=FakeResponse(200, {"status": "ok"}),
    )

    assert outcome["ok"] is True
    assert outcome["free_trial"] is False
    assert outcome["amount_minor"] == 169407          # 市场定价兜底（IN/INR）
    assert outcome["amount_source"]["basis"] == "market"


def test_missing_amount_with_unknown_market_stays_none(monkeypatch):
    """结算地不在定价表里（非 IN/US/GB/DE）时，金额保持 None、不给可领结论。"""
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "eligible"}),
        checkout=FakeResponse(200, {"status": "ok"}),
        billing_country="JP",
        currency="JPY",
    )

    assert outcome["ok"] is True
    assert outcome["amount_minor"] is None
    assert outcome["free_trial"] is False


# ──────────────────────── 失败分类 ────────────────────────


def test_token_invalid_on_401(monkeypatch):
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(401, {"detail": "Could not parse your authentication token."}),
        accounts=FakeResponse(401, {"detail": "Could not parse your authentication token."}),
    )

    assert outcome["ok"] is False
    assert outcome["failure_type"] == payment_probe.FAILURE_TOKEN
    assert outcome["transport_failed"] is False


def test_banned_is_detected_from_body(monkeypatch):
    outcome, session = _run(
        monkeypatch,
        coupon=FakeResponse(
            401, {"detail": "account_deactivated"}, "your account_deactivated"
        ),
        accounts=FakeResponse(401, {"detail": "account_deactivated"}, "account_deactivated"),
    )

    assert outcome["failure_type"] == payment_probe.FAILURE_BANNED
    # 封号号不该再创建 checkout 会话
    assert session.post_calls == 0


def test_transport_failure_is_not_an_account_verdict(monkeypatch):
    outcome, _ = _run(
        monkeypatch,
        coupon=RuntimeError("curl: (97) proxy closed connection"),
        accounts=RuntimeError("curl: (97) proxy closed connection"),
    )

    assert outcome["ok"] is False
    assert outcome["failure_type"] == payment_probe.FAILURE_TRANSPORT
    assert outcome["transport_failed"] is True
    assert "无效" in outcome["error"]


def test_checkout_post_carries_sentinel_headers(monkeypatch):
    """checkout POST 必须带 sentinel 双头（2026-09-29 自研突破：缺了就 400 unusual
    activity，补上立即 200）。"""
    seen: dict[str, str] = {}

    class RecordingSession(FakeSession):
        def post(self, url, **kwargs):
            seen["headers"] = dict(kwargs.get("headers") or {})
            return super().post(url, **kwargs)

    session = RecordingSession(
        coupon=FakeResponse(200, {"state": "eligible"}),
        accounts=_accounts_free(),
        checkout=FakeResponse(200, {"amount_minor": 0, "currency": "inr"}),
    )
    monkeypatch.setattr(payment_probe, "create_http_session", lambda **_: session)
    monkeypatch.setattr(payment_probe, "_checkout_sentinel_headers",
                        lambda _s, _d: {"openai-sentinel-token": "tok-1",
                                        "openai-sentinel-so-token": "so-1"})

    outcome = payment_probe.probe_checkout(
        "access-token", proxy="socks5h://u:p@in.example:1080",
        cookie_header="oai-did=fixture", device_id="device-1",
    )

    assert outcome["ok"] is True
    assert seen["headers"].get("openai-sentinel-token") == "tok-1"
    assert seen["headers"].get("openai-sentinel-so-token") == "so-1"


def test_sentinel_failure_does_not_kill_probe(monkeypatch):
    """sentinel 算不出来（缺 node 等）时仍照常发 checkout —— 结论按响应分类，
    而不是把探测直接判死。"""
    monkeypatch.setattr(payment_probe, "_checkout_sentinel_headers",
                        lambda _s, _d: {})

    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "eligible"}),
        checkout=FakeResponse(200, {"amount_minor": 0, "currency": "inr"}),
    )

    assert outcome["ok"] is True
    assert outcome["free_trial"] is True


def test_checkout_transport_failure_keeps_read_only_readings(monkeypatch):
    """checkout 打不通时，只读那两段的结果仍然要带出来。"""
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "eligible"}),
        accounts=_accounts_free(),
        checkout=TimeoutError("timed out"),
    )

    assert outcome["transport_failed"] is True
    assert outcome["coupon_state"] == "eligible"
    assert outcome["amount_minor"] is None


def test_rejected_request_is_not_account_verdict(monkeypatch):
    """400/422 是请求形状问题，不能当成该号不能支付。"""
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "eligible"}),
        accounts=_accounts_free(),
        checkout=FakeResponse(400, {"detail": "invalid plan_name"}),
    )

    assert outcome["failure_type"] == payment_probe.FAILURE_REQUEST_REJECTED
    assert outcome["transport_failed"] is False
    assert outcome["free_trial"] is False


def test_no_token_is_reported_without_network(monkeypatch):
    called = {"n": 0}

    def _boom(**_):
        called["n"] += 1
        raise AssertionError("没有 token 时不该发请求")

    monkeypatch.setattr(payment_probe, "create_http_session", _boom)
    outcome = payment_probe.probe_checkout("   ")

    assert outcome["ok"] is False
    assert called["n"] == 0


# ──────────────────────── 会话上下文与请求体 ────────────────────────


def test_default_body_targets_india_and_promo():
    body = payment_probe.default_checkout_body(country="in", currency="inr")

    assert body["billing_details"] == {"country": "IN", "currency": "INR"}
    assert body["promo_campaign"]["promo_campaign_id"] == payment_probe.PROMO_CAMPAIGN_ID
    assert body["plan_name"] == payment_probe.PLAN_NAME


def test_missing_session_context_is_flagged(monkeypatch):
    session = FakeSession(
        coupon=FakeResponse(200, {"state": "eligible"}),
        accounts=_accounts_free(),
        checkout=FakeResponse(200, {"amount_minor": 0, "currency": "inr"}),
    )
    monkeypatch.setattr(payment_probe, "create_http_session", lambda **_: session)
    outcome = payment_probe.probe_checkout("token", proxy="socks5h://in")

    assert outcome["has_session_context"] is False


def test_cookie_header_is_sent_when_present(monkeypatch):
    seen = {}

    class RecordingSession(FakeSession):
        def get(self, url, **kwargs):
            seen["cookie"] = (kwargs.get("headers") or {}).get("Cookie")
            return super().get(url, **kwargs)

    session = RecordingSession(
        coupon=FakeResponse(200, {"state": "eligible"}),
        accounts=_accounts_free(),
        checkout=FakeResponse(200, {"amount_minor": 0}),
    )
    monkeypatch.setattr(payment_probe, "create_http_session", lambda **_: session)
    payment_probe.probe_checkout(
        "token", proxy="socks5h://in", cookie_header="oai-did=abc; other=1"
    )

    assert seen["cookie"] == "oai-did=abc; other=1"


def test_socks5h_proxy_is_passed_through_unchanged(monkeypatch):
    """协议链路必须保留 socks5h —— 改写成 http 是旧外部服务的限制。"""
    seen = {}

    def _factory(**kwargs):
        seen.update(kwargs)
        return FakeSession(
            coupon=FakeResponse(200, {"state": "eligible"}),
            accounts=_accounts_free(),
            checkout=FakeResponse(200, {"amount_minor": 0}),
        )

    monkeypatch.setattr(payment_probe, "create_http_session", _factory)
    payment_probe.probe_checkout("token", proxy="socks5h://u:p@in.example:1080")

    assert seen["proxy"] == "socks5h://u:p@in.example:1080"


# ──────────────────────── 风控 vs 参数问题 ────────────────────────


def test_risk_block_is_distinguished_from_bad_request(monkeypatch):
    """400 + "unusual activity" 是风控拦截，不是参数写错。

    这两者给主人的指引完全相反：前者改请求体没用（要提升请求可信度或稍后重试），
    后者才要去调 plan_name / promo_campaign 这类字段。
    2026-09-29 实测：同一 AT 换 5 个国家出口全是这个 400。
    """
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "eligible"}),
        checkout=FakeResponse(
            400,
            {"detail": "Our systems have detected unusual activity. Please try again later."},
        ),
    )

    assert outcome["failure_type"] == payment_probe.FAILURE_RISK_BLOCKED
    assert "风控" in (outcome.get("hint") or "")
    assert outcome["transport_failed"] is False


def test_plain_rejection_stays_request_rejected(monkeypatch):
    """没有风控字样的 400 仍然是请求形状问题，不能被误判成风控。"""
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "eligible"}),
        checkout=FakeResponse(400, {"detail": "invalid plan_name"}),
    )

    assert outcome["failure_type"] == payment_probe.FAILURE_REQUEST_REJECTED


def test_risk_block_failure_carries_eligibility_snapshot(monkeypatch):
    """风控拦截也要把「资格快照」带回来。

    2026-09-29 实测：账号 eligible_promo_campaigns 为空、优惠券 not_eligible 时，
    8 个出口 × 6 组请求头都拿不到金额 —— 那是账号本来就没资格。
    结论里必须能看出这件事，否则主人只会以为探测链路又坏了。
    """
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "not_eligible"}),
        checkout=FakeResponse(
            400,
            {"detail": "Our systems have detected unusual activity. Please try again later."},
        ),
    )

    assert outcome["failure_type"] == payment_probe.FAILURE_RISK_BLOCKED
    assert outcome["coupon_state"] == "not_eligible"
    assert outcome["plan_type"] == "free"
    assert outcome["eligible_promo_campaigns"] == []
    assert outcome["has_active_subscription"] is False


def test_eligible_campaigns_are_reported_when_present(monkeypatch):
    """有资格时要报出促销活动 id，供结论页显示「可领」。"""
    accounts = FakeResponse(200, {
        "accounts": {
            "acc-1": {
                "account": {"plan_type": "free"},
                "entitlement": {"has_active_subscription": False},
                "eligible_promo_campaigns": {"plus": {"id": "plus-1-month-free"}},
            }
        }
    })
    outcome, _ = _run(
        monkeypatch,
        coupon=FakeResponse(200, {"state": "eligible"}),
        accounts=accounts,
        checkout=FakeResponse(200, {"amount_minor": 0, "currency": "inr"}),
    )

    assert outcome["eligible_promo_campaigns"] == ["plus"]
    assert outcome["promo_plus_id"] == "plus-1-month-free"
