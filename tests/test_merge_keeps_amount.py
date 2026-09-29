"""锁住两条新不变量：
  1) 限流/传输/冷却这类「这次没探成」不能覆盖已探到的金额；
  2) 真正的新结论（成功，或账号级失败）该覆盖就覆盖。
"""
from __future__ import annotations

from webui import checkout_capability


def _existing_amount(amount=169407, currency="inr"):
    return {
        "plus_check": {
            "checkout": {
                "ok": True,
                "status": "SUCCEEDED",
                "failure_type": "",
                "amount_minor": amount,
                "currency": currency,
                "free_trial": False,
                "payment_methods": ["card", "upi"],
                "processor_entity": "openai_llc",
                "provider_country": "IN",
                "source": "int31",
                "checked_at": 1790658000.0,
                "error": "",
            }
        }
    }


def test_rate_limited_keeps_previous_amount():
    """实测踩到：86.dare-satrapy 已有 ₹1694.07，被一次 429 覆盖成「探测失败」→ 金额消失。"""
    merged = checkout_capability.merge_into_check(
        _existing_amount(),
        {
            "ok": False,
            "status": "FAILED",
            "failure_type": "CheckoutRateLimited",
            "rate_limited": True,
            "retry_after": 1697,
            "error": "探测服务限流，1697s 后可再试",
            "source": "int31",
        },
    )
    checkout = merged["checkout"]

    assert checkout["amount_minor"] == 169407          # 金额保住
    assert checkout["currency"] == "inr"
    assert checkout["payment_methods"] == ["card", "upi"]
    assert checkout["ok"] is True
    assert checkout["failure_type"] == ""              # 这次失败不算在结论上
    assert checkout["last_attempt_error"]              # 但留痕：这次没探成
    assert checkout["amount_from"] == 1790658000.0     # 金额的原始采集时间
    assert "限流" in checkout["note"]


def test_transport_failure_keeps_previous_amount():
    merged = checkout_capability.merge_into_check(
        _existing_amount(),
        {
            "ok": False,
            "status": "FAILED",
            "failure_type": "CheckoutTransportException",
            "transport_failed": True,
            "error": "探测侧网络失败，结论无效",
            "source": "int31",
        },
    )
    checkout = merged["checkout"]

    assert checkout["amount_minor"] == 169407
    assert checkout["last_attempt_error"]
    assert "网络失败" in checkout["note"]


def test_rate_limit_without_previous_amount_writes_failure():
    """没探到过金额时，限流就如实写成失败（不要伪造金额）。"""
    merged = checkout_capability.merge_into_check(
        {},
        {
            "ok": False,
            "status": "FAILED",
            "failure_type": "CheckoutRateLimited",
            "rate_limited": True,
            "retry_after": 600,
            "error": "限流",
            "source": "int31",
        },
    )
    checkout = merged["checkout"]

    assert checkout["amount_minor"] is None
    assert checkout["ok"] is False
    assert checkout["failure_type"] == "CheckoutRateLimited"


def test_success_and_account_failures_still_overwrite():
    """新结论要能覆盖旧金额：成功刷新金额，账号级失败（封号）也要写进去。"""
    newer = checkout_capability.merge_into_check(
        _existing_amount(),
        {
            "ok": True, "status": "SUCCEEDED", "amount_minor": 0, "currency": "inr",
            "free_trial": True, "payment_methods": ["upi"], "source": "int31",
        },
    )["checkout"]
    assert newer["amount_minor"] == 0
    assert newer["free_trial"] is True

    banned = checkout_capability.merge_into_check(
        _existing_amount(),
        {"ok": False, "status": "FAILED", "failure_type": "AccountDeactivated",
         "error": "账号已封", "source": "int31"},
    )["checkout"]
    assert banned["amount_minor"] is None              # 账号级结论要覆盖旧金额
    assert banned["failure_type"] == "AccountDeactivated"
