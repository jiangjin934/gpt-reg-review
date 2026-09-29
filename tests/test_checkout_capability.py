"""支付能力探测的 WebUI 侧编排：印度出口选择、落库、结果合并。

默认探测链路 = int31 探测服务（checkout_probe_source=int31，2026-09-29 实测：
同账号+同出口，自研协议客户端被 OpenAI 滥用闸门拦，交给服务端就能拿到真实金额）。
本文件主要盯**自研协议链路**（显式把 probe_source 设成 protocol）与出口选择：
   · 出口必须是印度且保留 socks5h（改写成 http 是旧外部服务的限制，协议链路走 curl
     时必须保留远端 DNS）；
   · 传输失败不能写成不可支付。
"""
from __future__ import annotations

import pytest

from webui import checkout_capability, db

POOL_TEMPLATE = (
    "socks5h://user-region-Rand-sid-OLD00001-t-30:pass@sg2.cliproxy.io:443"
)


def _pool(monkeypatch, template: str = POOL_TEMPLATE) -> None:
    db.set_setting("proxy_pool", template)
    db.set_setting("checkout_capability_india_proxy", "")
    db.set_setting("checkout_capability_india_sid", "")
    db.set_setting("checkout_capability_india_sid_at", "0")
    # 本文件的用例盯的是自研协议链路；默认链路是 int31（见 test_checkout_service_probe.py）
    db.set_setting("checkout_probe_source", "protocol")
    monkeypatch.setattr(checkout_capability, "_india_proxy_alive", lambda _p: True)


# ──────────────────────── 印度出口选择 ────────────────────────


def test_pick_india_proxy_keeps_socks5h_scheme(monkeypatch):
    """协议链路必须保留 socks5h：改成 http 是旧外部服务的限制。"""
    _pool(monkeypatch)

    proxy = checkout_capability.pick_india_proxy()

    assert proxy.startswith("socks5h://")
    assert not proxy.startswith("http://")


def test_pick_india_proxy_rewrites_region_and_sid(monkeypatch):
    _pool(monkeypatch)

    proxy = checkout_capability.pick_india_proxy()

    assert "region-IN" in proxy
    # 整段 region 记号都要换掉：只换两位字母会拼出 region-INnd 这种非法地区码
    assert "region-INnd" not in proxy
    assert "sid-OLD00001" not in proxy
    # 静态会话：TTL 拉长，别中途换 IP
    assert "-t-1440" in proxy
    # 主机与凭据保持不变
    assert proxy.endswith("@sg2.cliproxy.io:443")


def test_pick_india_proxy_is_static_across_calls(monkeypatch):
    _pool(monkeypatch)

    first = checkout_capability.pick_india_proxy()
    second = checkout_capability.pick_india_proxy()

    assert first == second
    stored = db.get_setting("checkout_capability_india_sid", "")
    assert stored and f"sid-{stored}" in first


def test_configured_india_proxy_wins(monkeypatch):
    db.set_setting("checkout_capability_india_proxy", "socks5h://fixed:pass@in.example:1080")
    monkeypatch.setattr(checkout_capability, "_india_proxy_alive", lambda _p: True)

    assert (
        checkout_capability.pick_india_proxy()
        == "socks5h://fixed:pass@in.example:1080"
    )


def test_configured_proxy_falls_back_when_dead(monkeypatch):
    """自备静态串也会掉线：探不通必须回落到池子改写，而不是直接把死串发出去。"""
    _pool(monkeypatch)
    db.set_setting("checkout_capability_india_proxy", "socks5h://dead:pass@in.example:1080")
    monkeypatch.setattr(checkout_capability, "_india_proxy_alive", lambda _p: False)

    proxy = checkout_capability.pick_india_proxy()

    assert "region-IN" in proxy
    assert "dead" not in proxy


def test_india_proxy_rotates_when_session_is_dead(monkeypatch):
    """静态会话掉线时必须自动换一条，否则所有探测都会传输失败。"""
    _pool(monkeypatch)
    db.set_setting("checkout_capability_india_sid", "DEADSID1")
    db.set_setting("checkout_capability_india_sid_at", "0")
    monkeypatch.setattr(checkout_capability, "_india_proxy_alive", lambda _p: False)

    proxy = checkout_capability.pick_india_proxy()

    assert "sid-DEADSID1" not in proxy
    assert f"sid-{db.get_setting('checkout_capability_india_sid', '')}" in proxy


def test_pick_india_proxy_without_pool_returns_empty(monkeypatch):
    db.set_setting("proxy_pool", "")
    db.set_setting("checkout_capability_india_proxy", "")
    monkeypatch.setattr(checkout_capability, "_india_proxy_alive", lambda _p: True)

    assert checkout_capability.pick_india_proxy() == ""


# ──────────────────────── probe 编排 ────────────────────────


def _stub_probe(monkeypatch, outcome: dict):
    captured = {}

    def _fake(access_token, **kwargs):
        captured.update(kwargs)
        captured["access_token"] = access_token
        return dict(outcome)

    import payment_probe

    monkeypatch.setattr(payment_probe, "probe_checkout", _fake)
    return captured


def test_probe_defaults_to_india_egress(monkeypatch):
    """不传代理时必须自己挑印度出口，不能直连。"""
    _pool(monkeypatch)
    captured = _stub_probe(monkeypatch, {"ok": True, "amount_minor": 0})

    checkout_capability.probe("tok")

    assert "region-IN" in captured["proxy"]
    assert captured["proxy"].startswith("socks5h://")
    assert captured["billing_country"] == "IN"
    assert captured["currency"] == "INR"


def test_probe_without_any_proxy_reports_clearly(monkeypatch):
    db.set_setting("proxy_pool", "")
    db.set_setting("checkout_capability_india_proxy", "")
    monkeypatch.setattr(checkout_capability, "_india_proxy_alive", lambda _p: True)

    outcome = checkout_capability.probe("tok")

    assert outcome["ok"] is False
    assert "没有可用代理" in outcome["error"]


def test_probe_passes_session_context(monkeypatch):
    _pool(monkeypatch)
    captured = _stub_probe(monkeypatch, {"ok": True})

    checkout_capability.probe(
        "tok",
        session_context={
            "fingerprint": {"impersonate": "chrome146"},
            "account_id": "acc-9",
            "device_id": "dev-9",
            "cookie_header": "oai-did=abc",
        },
    )

    assert captured["account_id"] == "acc-9"
    assert captured["device_id"] == "dev-9"
    assert captured["cookie_header"] == "oai-did=abc"
    assert captured["fingerprint"] == {"impersonate": "chrome146"}


def test_probe_keeps_legacy_rate_limited_key(monkeypatch):
    """旧前端会读 rate_limited；协议链路下恒为 False，键必须还在。"""
    _pool(monkeypatch)
    _stub_probe(monkeypatch, {"ok": True})

    outcome = checkout_capability.probe("tok")

    assert outcome["rate_limited"] is False


# ──────────────────────── 结论合并与落库 ────────────────────────


def test_merge_marks_protocol_source():
    merged = checkout_capability.merge_into_check(
        {},
        {"ok": True, "status": "SUCCEEDED", "amount_minor": 0,
         "currency": "inr", "free_trial": True, "source": "protocol"},
    )

    assert merged["checkout"]["source"] == "protocol"
    assert merged["checkout"]["amount_minor"] == 0
    assert merged["checkout"]["free_trial"] is True


def test_transport_failure_is_marked_invalid_not_capability_denied():
    merged = checkout_capability.merge_into_check(
        {},
        {
            "ok": False,
            "status": "FAILED",
            "failure_type": "CheckoutTransportException",
            "transport_failed": True,
            "error": "探测侧网络失败",
        },
    )

    assert merged["checkout"]["ok"] is False
    assert "网络失败" in merged["checkout"]["note"]
    assert merged["checkout"]["amount_minor"] is None


def test_merge_preserves_other_plus_check_fields():
    merged = checkout_capability.merge_into_check(
        {"plus_check": {"status": "plus_eligible", "label": "可领Plus试用"}},
        {"ok": True, "amount_minor": 0},
    )

    assert merged["status"] == "plus_eligible"
    assert merged["label"] == "可领Plus试用"
    assert merged["checkout"]["amount_minor"] == 0


def test_probe_email_stores_result_into_plus_check(monkeypatch):
    _pool(monkeypatch)
    db.save_registered({"email": "cap@example.com", "access_token": "tok-1", "password": "x"})
    db.update_plus_check("cap@example.com", {
        "status": "plus_eligible", "label": "可领Plus试用",
        "trial_eligible": True, "eligible_country": "IN", "checked_at": 1.0,
    })
    _stub_probe(
        monkeypatch,
        {
            "ok": True, "status": "SUCCEEDED", "amount_minor": 0,
            "currency": "inr", "free_trial": True,
            "payment_methods": ["card", "upi"], "source": "protocol",
            "checked_at": 123.0,
        },
    )

    outcome = checkout_capability.probe_email("cap@example.com")

    assert outcome["ok"] is True
    stored = (db.get_registered("cap@example.com") or {}).get("extra", {}).get("plus_check")
    assert stored["checkout"]["ok"] is True
    assert stored["checkout"]["free_trial"] is True
    assert stored["checkout"]["source"] == "protocol"
    assert stored["status"] == "plus_eligible"


def test_probe_email_without_token_is_rejected(monkeypatch):
    db.save_registered({"email": "notoken@example.com", "password": "x"})

    outcome = checkout_capability.probe_email("notoken@example.com")

    assert outcome["ok"] is False
    assert "access_token" in outcome["error"]


def test_probe_email_for_unknown_account_is_rejected():
    outcome = checkout_capability.probe_email("missing@example.com")

    assert outcome["ok"] is False
    assert "凭证" in outcome["error"]


def test_probe_email_survives_transport_failure(monkeypatch):
    """传输失败要落库成「结论无效」，不能把号标成不可支付。"""
    _pool(monkeypatch)
    db.save_registered({"email": "dead@example.com", "access_token": "tok", "password": "x"})
    _stub_probe(
        monkeypatch,
        {
            "ok": False, "status": "FAILED",
            "failure_type": "CheckoutTransportException",
            "transport_failed": True,
            "error": "探测侧网络失败，结论无效",
            "checked_at": 5.0,
        },
    )

    outcome = checkout_capability.probe_email("dead@example.com")

    assert outcome["ok"] is False
    stored = (db.get_registered("dead@example.com") or {}).get("extra", {}).get("plus_check")
    assert stored["checkout"]["note"] == "探测侧网络失败，结论无效"
    assert stored["checkout"]["free_trial"] is False


# ──────────────────────── 浏览器回退 ────────────────────────


def _risk_blocked_outcome() -> dict:
    return {
        "ok": False, "status": "FAILED", "failure_type": "CheckoutRiskBlocked",
        "transport_failed": False, "error": "HTTP 400: unusual activity",
    }


def test_probe_falls_back_to_browser_when_protocol_risk_blocked(monkeypatch):
    """协议被风控拦 → 回退浏览器；浏览器成功 → 用浏览器的结论。"""
    _pool(monkeypatch)
    db.set_setting("checkout_capability_browser_fallback", "1")
    captured = _stub_probe(monkeypatch, _risk_blocked_outcome())

    import browser_checkout_probe
    monkeypatch.setattr(
        browser_checkout_probe, "probe_checkout_browser",
        lambda *a, **k: {"ok": True, "status": "SUCCEEDED", "amount_minor": 0,
                         "currency": "inr", "source": "browser", "free_trial": True},
    )

    outcome = checkout_capability.probe("tok", session_context={})

    assert outcome["ok"] is True
    assert outcome["source"] == "browser"
    assert outcome["protocol_was_blocked"] is True
    assert captured["access_token"] == "tok"


def test_probe_keeps_protocol_verdict_when_browser_also_blocked(monkeypatch):
    """两条自研链路都被拦 → 保留结论，并说清拦的是**客户端指纹**。

    2026-09-29 两次实测更正：
      · 早先以为"出口 IP 信誉问题" → 8 个不同出口（含首页不被 CF 挑战的干净出口）
        得到的是同一句 400，换出口没用；
      · 再以为是"账号侧风控" → 同一账号 + 同一条印度住宅出口，交给外部探测服务
        就能拿到真实金额（169407 INR）。所以既不是出口、也不是账号，而是**我们
        自己客户端的请求指纹**。结论必须指向"改用能过闸门的链路"。
    """
    _pool(monkeypatch)
    db.set_setting("checkout_capability_browser_fallback", "1")
    _stub_probe(monkeypatch, _risk_blocked_outcome())

    import browser_checkout_probe
    monkeypatch.setattr(
        browser_checkout_probe, "probe_checkout_browser",
        lambda *a, **k: dict(_risk_blocked_outcome(), source="browser"),
    )

    outcome = checkout_capability.probe("tok", session_context={})

    assert outcome["ok"] is False
    assert outcome["failure_type"] == "CheckoutRiskBlocked"
    assert outcome["browser_also_blocked"] is True
    assert "客户端" in outcome["error"]
    assert "int31" in outcome["error"]
    assert outcome["hint"] == "自研客户端指纹被风控；建议使用 int31 探测链路"


def test_probe_skips_browser_fallback_when_disabled(monkeypatch):
    _pool(monkeypatch)
    db.set_setting("checkout_capability_browser_fallback", "0")
    _stub_probe(monkeypatch, _risk_blocked_outcome())

    import browser_checkout_probe
    called = {"n": 0}

    def _boom(*a, **k):
        called["n"] += 1
        raise AssertionError("开关关闭时不该回退浏览器")

    monkeypatch.setattr(browser_checkout_probe, "probe_checkout_browser", _boom)

    outcome = checkout_capability.probe("tok", session_context={})

    assert outcome["failure_type"] == "CheckoutRiskBlocked"
    assert called["n"] == 0


def test_browser_fallback_survives_browser_exception(monkeypatch):
    """浏览器引擎抛异常（未装依赖等）不能把探测本身打崩。"""
    _pool(monkeypatch)
    db.set_setting("checkout_capability_browser_fallback", "1")
    _stub_probe(monkeypatch, _risk_blocked_outcome())

    import browser_checkout_probe
    monkeypatch.setattr(
        browser_checkout_probe, "probe_checkout_browser",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("camoufox 未安装")),
    )

    outcome = checkout_capability.probe("tok", session_context={})

    assert outcome["ok"] is False
    assert outcome["failure_type"] == "CheckoutRiskBlocked"


# ──────────────────────── 风控冷却 ────────────────────────


def _store_risk_blocked(email: str, checked_at: float) -> None:
    db.save_registered({"email": email, "access_token": "tok", "password": "x"})
    db.update_plus_check(email, {"checkout": {
        "ok": False, "status": "FAILED", "failure_type": "CheckoutRiskBlocked",
        "error": "HTTP 400: unusual activity", "checked_at": checked_at,
        "source": "protocol",
    }})


def test_risk_blocked_within_cooldown_is_skipped(monkeypatch):
    """冷却期内直接复用旧结论、不发请求 —— 反复打只会把 flag 养重。"""
    import time

    _pool(monkeypatch)
    _store_risk_blocked("cool@example.com", time.time() - 60)
    called = {"n": 0}
    monkeypatch.setattr(
        checkout_capability, "probe",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {"ok": True},
    )

    outcome = checkout_capability.probe_email("cool@example.com")

    assert outcome["ok"] is False
    assert outcome["risk_cooldown"] is True
    assert outcome["failure_type"] == "CheckoutRiskBlocked"
    assert called["n"] == 0


def test_risk_blocked_beyond_cooldown_reprobes(monkeypatch):
    import time

    _pool(monkeypatch)
    _store_risk_blocked("cool2@example.com", time.time() - 999999)
    monkeypatch.setattr(
        checkout_capability, "probe",
        lambda *a, **k: {"ok": True, "status": "SUCCEEDED", "amount_minor": 0,
                         "currency": "inr", "source": "protocol", "checked_at": time.time()},
    )

    outcome = checkout_capability.probe_email("cool2@example.com")

    assert outcome.get("risk_cooldown") is not True
    assert outcome["ok"] is True


def test_other_failures_do_not_trigger_cooldown(monkeypatch):
    """传输失败等不是风控拦截 —— 下次探测要照常进行。"""
    import time

    _pool(monkeypatch)
    db.save_registered({"email": "net@example.com", "access_token": "tok", "password": "x"})
    db.update_plus_check("net@example.com", {"checkout": {
        "ok": False, "status": "FAILED", "failure_type": "CheckoutTransportException",
        "error": "探测侧网络失败", "checked_at": time.time() - 60,
    }})
    called = {"n": 0}
    monkeypatch.setattr(
        checkout_capability, "probe",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {"ok": True},
    )

    checkout_capability.probe_email("net@example.com")

    assert called["n"] == 1


def test_queue_status_shape(monkeypatch):
    db.set_setting("checkout_capability_enabled", "1")
    db.set_setting("checkout_capability_auto", "1")

    status = checkout_capability.queue_status()

    for key in ("enabled", "auto", "queued", "processing", "done", "failed",
                "rate_limited_until", "interval_seconds", "source"):
        assert key in status
    # source 报的是**实际生效**的链路（默认 int31），不再写死 protocol ——
    # 否则排查时看不出队列到底走的哪条链路（2026-09-29 实测踩到）。
    assert status["source"] == checkout_capability.config()["probe_source"]
    assert status["source"] == "int31"


def test_queue_status_reports_explicit_protocol_source(monkeypatch):
    _pool(monkeypatch)   # _pool 会把 checkout_probe_source 设成 protocol

    assert checkout_capability.queue_status()["source"] == "protocol"


def test_merge_keeps_eligibility_snapshot():
    """落库要保住资格快照：结论页靠它区分「账号本来没资格」和「探测链路坏了」。

    2026-09-29 之前这里只存 ok/failure_type/amount，coupon/促销活动全被丢掉，
    页面上只剩一句风控拦截，看不出到底是哪一环的问题。
    """
    merged = checkout_capability.merge_into_check(
        {},
        {
            "ok": False,
            "status": "FAILED",
            "failure_type": "CheckoutRiskBlocked",
            "http_status": 400,
            "error": "HTTP 400: Our systems have detected unusual activity.",
            "coupon_state": "not_eligible",
            "plan_type": "free",
            "eligible_promo_campaigns": ["plus"],
            "has_active_subscription": False,
            "coupon_http_status": 200,
            "accounts_http_status": 200,
            "hint": "风控拦截（与请求参数无关）：需提升请求可信度或稍后重试",
        },
    )

    checkout = merged["checkout"]
    assert checkout["coupon_state"] == "not_eligible"
    assert checkout["plan_type"] == "free"
    assert checkout["eligible_promo_campaigns"] == ["plus"]
    assert checkout["has_active_subscription"] is False
    assert checkout["coupon_http_status"] == 200
    assert "风控" in checkout["hint"]


def test_merge_defaults_eligibility_snapshot_when_absent():
    """旧记录/传输失败没有资格快照时，键也要在（空值），避免前端两套形状。"""
    merged = checkout_capability.merge_into_check({}, {"ok": True, "status": "SUCCEEDED"})

    checkout = merged["checkout"]
    assert checkout["coupon_state"] == ""
    assert checkout["eligible_promo_campaigns"] == []
    assert checkout["coupon_http_status"] == 0
