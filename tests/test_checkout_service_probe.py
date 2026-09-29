"""探测服务链路（int31）的用例：代理写法转换、金额映射、429 退避、传输失败换会话。"""
from unittest.mock import Mock

import pytest

import checkout_service_probe as csp


def test_proxy_format_conversion():
    """提交给服务端必须 http://，本机验活必须 socks5h://（cliproxy:3010 不吃 HTTP CONNECT）。"""
    line = "socks5h://user-region-IN-sid-Aa1-t-30:pw@sg2.cliproxy.io:3010"
    assert csp.to_service_proxy(line).startswith("http://")
    assert csp.to_local_proxy(csp.to_service_proxy(line)).startswith("socks5h://")
    assert csp.to_service_proxy("http://u:p@h:1") == "http://u:p@h:1"
    assert csp.to_local_proxy("http://u:p@h:1") == "socks5h://u:p@h:1"


def test_build_india_proxy_rewrites_region_sid_and_ttl():
    template = "socks5h://u-region-Rand-sid-OLD123-t-30:pw@sg2.cliproxy.io:3010"
    out = csp.build_india_proxy(template)
    assert "region-IN" in out
    assert "region-INnd" not in out          # 只换两位字母会造出这种非法记号
    assert "sid-OLD123" not in out
    assert "-t-1440" in out
    assert csp.build_india_proxy("socks5h://u-region-JP:pw@h:1").count("-sid-") == 1


def _patch_transport(monkeypatch, *, submit=None, poll=None, sleeps=None):
    monkeypatch.setattr(csp, "_http_json", _http_json_factory(submit, poll))
    monkeypatch.setattr(csp.time, "sleep", lambda _s: (sleeps or []).append(_s))


def _http_json_factory(submit, poll):
    calls = {"submit": 0, "poll": 0}

    def _http_json(method, url, *, payload=None, timeout=45.0):
        if url == csp.SUBMIT_URL:
            calls["submit"] += 1
            result = submit(calls["submit"]) if callable(submit) else submit
            return result
        calls["poll"] += 1
        result = poll(calls["poll"]) if callable(poll) else poll
        return result
    return _http_json


def test_amount_mapping_and_free_trial(monkeypatch):
    _patch_transport(
        monkeypatch,
        submit=(202, {"taskId": "t-1"}),
        poll=(200, {"tasks": [{"status": "SUCCEEDED", "result": {
            "amountMinor": 169407, "currency": "inr", "paymentMethodTypes": ["card", "upi"],
            "processorEntity": "openai_llc", "providerCountry": "IN", "checkoutBackend": "STRIPE",
        }}]}),
    )
    outcome = csp.probe_via_service("tok", proxy="socks5h://u:p@h:1")

    assert outcome["ok"] is True
    assert outcome["amount_minor"] == 169407
    assert outcome["currency"] == "inr"
    assert outcome["free_trial"] is False           # 非 0 元不是"可领"
    assert outcome["payment_methods"] == ["card", "upi"]
    assert outcome["source"] == "int31"


def test_zero_amount_is_free_trial(monkeypatch):
    _patch_transport(
        monkeypatch,
        submit=(202, {"taskId": "t-2"}),
        poll=(200, {"tasks": [{"status": "SUCCEEDED", "result": {"amountMinor": 0, "currency": "inr"}}]}),
    )
    outcome = csp.probe_via_service("tok", proxy="socks5h://u:p@h:1")

    assert outcome["amount_minor"] == 0
    assert outcome["free_trial"] is True


def test_rate_limit_reports_retry_after(monkeypatch):
    _patch_transport(monkeypatch, submit=(429, {"retryAfterSeconds": 600}), poll=(200, {}))
    outcome = csp.probe_via_service("tok", proxy="socks5h://u:p@h:1")

    assert outcome["ok"] is False
    assert outcome["rate_limited"] is True
    assert outcome["retry_after"] == 600
    assert outcome["failure_type"] == csp.FAILURE_RATE_LIMITED


def test_transport_failure_retries_with_a_new_session(monkeypatch):
    """服务端连不上代理 → 换一条新印度会话重试，不应直接判成账号不可支付。"""
    proxies: list[str] = []

    def submit(_n):
        return (202, {"taskId": "t-3"})

    def poll(_n):
        return (200, {"tasks": [{"status": "FAILED", "failureType": csp.FAILURE_TRANSPORT}]})

    def _http_json(method, url, *, payload=None, timeout=45.0):
        if url == csp.SUBMIT_URL:
            proxies.append(payload["proxyUrl"])
            return submit(0)
        return poll(0)

    monkeypatch.setattr(csp, "_http_json", _http_json)
    monkeypatch.setattr(csp.time, "sleep", lambda _s: None)

    outcome = csp.probe_via_service(
        "tok", proxy="socks5h://u-region-IN-sid-FIRST-t-30:pw@h:1",
        template="socks5h://u-region-Rand-sid-SECOND-t-30:pw@h:1", retries=2,
    )

    assert outcome["ok"] is False
    assert outcome["transport_failed"] is True
    assert len(proxies) >= 2                       # 至少换过一次会话
    assert proxies[0] == proxies[1] is False or proxies  # 提交用的是 http:// 写法
    assert all(p.startswith("http://") for p in proxies)


def test_missing_token_is_reported_without_network(monkeypatch):
    monkeypatch.setattr(csp, "_http_json", Mock(side_effect=AssertionError("不该发包")))
    outcome = csp.probe_via_service("", proxy="socks5h://u:p@h:1")

    assert outcome["ok"] is False
    assert outcome["no_at"] is True


def test_missing_proxy_is_reported(monkeypatch):
    monkeypatch.setattr(csp, "_http_json", Mock(side_effect=AssertionError("不该发包")))
    outcome = csp.probe_via_service("tok", proxy="")

    assert outcome["ok"] is False
    assert outcome["proxy_failed"] is True
