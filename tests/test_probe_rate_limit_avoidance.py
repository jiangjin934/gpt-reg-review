"""限流避免相关的用例：
  · 冷却期内的号 → deferred（不发请求、不写失败、不动已有金额）；
  · 到点后能被重新取出补探；
  · 限流结论会记下可重试时间；队列状态能看到还有几个在等冷却。
"""
from __future__ import annotations

import time

from webui import checkout_capability, db


def _store(email: str, checkout: dict) -> None:
    db.save_registered({"email": email, "password": "pw-1"})
    # update_plus_check 自己会写进 extra_json.plus_check，所以这里传的是它的内容
    db.update_plus_check(email, {"checkout": checkout})


def _make_due(email: str, *, future: bool) -> None:
    _store(email, {
        "ok": True, "status": "SUCCEEDED", "amount_minor": 169407, "currency": "inr",
        "payment_methods": ["card", "upi"], "source": "int31",
        "checked_at": time.time(),
        "retry_after_at": time.time() + (600 if future else -600),
    })


def test_account_still_in_cooldown_is_deferred(monkeypatch):
    email = "cooling@example.com"
    _make_due(email, future=True)
    called = []
    monkeypatch.setattr(checkout_capability, "probe_email",
                        lambda *a, **k: called.append(a) or {"ok": True})

    outcome = checkout_capability.probe_email_if_due(email)

    assert outcome["deferred"] is True
    assert outcome["retry_in"] > 0
    assert called == []                                 # 一个请求都没发
    stored = (db.get_registered(email) or {}).get("extra", {}).get("plus_check", {}).get("checkout", {})
    assert stored.get("amount_minor") == 169407          # 已有金额原封不动
    assert not stored.get("failure_type")


def test_account_past_cooldown_is_probed(monkeypatch):
    email = "due@example.com"
    _make_due(email, future=False)
    called = []

    def fake_probe(*_a, **_k):
        called.append(True)
        return {"ok": True, "amount_minor": 169407, "currency": "inr", "source": "int31"}

    monkeypatch.setattr(checkout_capability, "probe_email", fake_probe)

    outcome = checkout_capability.probe_email_if_due(email)

    assert called == [True]
    assert outcome["ok"] is True
    assert not outcome.get("deferred")


def test_rate_limited_records_retry_at_and_counted_as_deferred():
    merged = checkout_capability.merge_into_check(
        {},
        {"ok": False, "status": "FAILED", "failure_type": "CheckoutRateLimited",
         "rate_limited": True, "retry_after": 1200, "error": "限流", "source": "int31"},
    )["checkout"]

    assert merged["retry_after_at"] > time.time() + 1000
    assert "限流" in merged["note"]


def test_deferred_queue_returns_items_when_due():
    checkout_capability._DEFERRED.clear()
    checkout_capability._defer("later@example.com", time.time() + 3600)
    checkout_capability._defer("soon@example.com", time.time() + 10)

    assert checkout_capability._next_deferred_delay() is not None
    assert checkout_capability._take_due_deferred(now=time.time()) == []
    due = checkout_capability._take_due_deferred(now=time.time() + 60)
    assert due == ["soon@example.com"]
    assert checkout_capability._next_deferred_delay() is not None  # later 还在等


def test_queue_status_exposes_deferred_count():
    status = checkout_capability.queue_status()
    assert "deferred" in status
