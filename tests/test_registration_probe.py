"""注册状态判定：页面类型到结论的映射，以及失败不误判。

判定表是这套东西唯一有业务含义的部分 —— 映射错了，用户拿到的名单就是反的。
所以这里把 authorize/continue 的每一种已知返回值都固定住，
并确认「没探成」永远落到 unknown 而不是掉进某一侧。
"""
from __future__ import annotations

import pytest

import registration_probe


class FakeFlow:
    """替身：只复现 probe_registration 依赖的那几个方法。"""

    def __init__(self, *args, **kwargs):
        self.session = _FakeSession()
        self.result = type("R", (), {"email": ""})()
        self._existing_page_type = ""
        self._existing_email_verification_mode = ""
        self._network_preflight_error = ""
        self.signup_called = False
        # 由各用例注入
        self.next_page_type = ""
        self.next_mode = ""
        self.warmup_ok = True
        self.check_proxy_ok = True
        self.sentinel_ok = True

    def check_proxy(self):
        if not self.check_proxy_ok:
            self._network_preflight_error = "出口不通"
        return self.check_proxy_ok

    def warmup(self):
        return self.warmup_ok

    def get_csrf_token(self):
        return "csrf-token"

    def get_auth_url(self, csrf_token, email=""):
        return "https://auth.openai.com/authorize?x=1"

    def auth_oauth_init(self, auth_url):
        return "device-id"

    def get_sentinel_token(self, device_id):
        return "sentinel-token" if self.sentinel_ok else ""

    def signup(self, email, sentinel_token):
        self.signup_called = True
        self._existing_page_type = self.next_page_type
        self._existing_email_verification_mode = self.next_mode
        return self.next_page_type == "create_account_password"


class _FakeSession:
    def close(self):
        pass


@pytest.fixture
def flow(monkeypatch):
    import auth_flow

    monkeypatch.setattr(auth_flow, "AuthFlow", FakeFlow)
    return FakeFlow()


def _probe(monkeypatch, page_type: str, mode: str = "") -> dict:
    import auth_flow

    instance = FakeFlow()
    instance.next_page_type = page_type
    instance.next_mode = mode
    monkeypatch.setattr(auth_flow, "AuthFlow", lambda *a, **k: instance)
    return registration_probe.probe_registration("someone@icloud.com", proxy="socks5h://in")


# ──────────────────────── 判定表 ────────────────────────


def test_register_password_page_means_unregistered(monkeypatch):
    result = _probe(monkeypatch, "create_account_password")

    assert result["status"] == registration_probe.STATUS_UNREGISTERED


def test_passwordless_signup_means_unregistered(monkeypatch):
    """无密码注册仍然是新号 —— 不能因为它没有密码就当成老号。"""
    result = _probe(monkeypatch, "email_otp_verification", "passwordless_signup")

    assert result["status"] == registration_probe.STATUS_UNREGISTERED


def test_passwordless_login_means_registered(monkeypatch):
    result = _probe(monkeypatch, "email_otp_verification", "passwordless_login")

    assert result["status"] == registration_probe.STATUS_REGISTERED


def test_login_password_page_means_registered(monkeypatch):
    """实测 2026-09-28：老号在 signup 阶段直接落到 login_password。"""
    result = _probe(monkeypatch, "login_password")

    assert result["status"] == registration_probe.STATUS_REGISTERED


def test_mfa_challenge_page_means_registered(monkeypatch):
    result = _probe(monkeypatch, "mfa_challenge")

    assert result["status"] == registration_probe.STATUS_REGISTERED


def test_otp_page_without_mode_is_unknown(monkeypatch):
    """没有 mode 就分不清「无密码注册」和「无密码登录」，这两个对用户意义相反。"""
    result = _probe(monkeypatch, "email_otp_verification", "")

    assert result["status"] == registration_probe.STATUS_UNKNOWN


def test_unrecognized_page_is_unknown(monkeypatch):
    result = _probe(monkeypatch, "some_new_page_type")

    assert result["status"] == registration_probe.STATUS_UNKNOWN
    assert "some_new_page_type" in result["reason"]


# ──────────────────────── 失败路径 ────────────────────────


def test_empty_email_short_circuits():
    result = registration_probe.probe_registration("   ")

    assert result["status"] == registration_probe.STATUS_UNKNOWN
    assert "邮箱为空" in result["error"]


def test_proxy_failure_is_unknown_not_registered(monkeypatch):
    import auth_flow

    instance = FakeFlow()
    instance.check_proxy_ok = False
    monkeypatch.setattr(auth_flow, "AuthFlow", lambda *a, **k: instance)

    result = registration_probe.probe_registration("a@icloud.com")

    assert result["status"] == registration_probe.STATUS_UNKNOWN
    assert instance.signup_called is False


def test_warmup_failure_stops_before_signup(monkeypatch):
    import auth_flow

    instance = FakeFlow()
    instance.warmup_ok = False
    monkeypatch.setattr(auth_flow, "AuthFlow", lambda *a, **k: instance)

    result = registration_probe.probe_registration("a@icloud.com")

    assert result["status"] == registration_probe.STATUS_UNKNOWN
    # warmup 没成就该停住：注释里写明「没 oai-did 时 authorize/continue 必 409」
    assert instance.signup_called is False


def test_missing_sentinel_stops_before_signup(monkeypatch):
    import auth_flow

    instance = FakeFlow()
    instance.sentinel_ok = False
    monkeypatch.setattr(auth_flow, "AuthFlow", lambda *a, **k: instance)

    result = registration_probe.probe_registration("a@icloud.com")

    assert result["status"] == registration_probe.STATUS_UNKNOWN
    assert instance.signup_called is False


def test_flow_exception_is_reported_as_unknown(monkeypatch):
    import auth_flow

    class Boom(FakeFlow):
        def signup(self, email, sentinel_token):
            raise RuntimeError("authorize/continue 失败: HTTP 409 invalid_state")

    monkeypatch.setattr(auth_flow, "AuthFlow", Boom)

    result = registration_probe.probe_registration("a@icloud.com")

    assert result["status"] == registration_probe.STATUS_UNKNOWN
    assert "409" in result["error"]


def test_session_is_closed_even_on_failure(monkeypatch):
    import auth_flow

    instance = FakeFlow()
    instance.warmup_ok = False
    closed = {"n": 0}

    class Tracked(_FakeSession):
        def close(self):
            closed["n"] += 1

    instance.session = Tracked()
    monkeypatch.setattr(auth_flow, "AuthFlow", lambda *a, **k: instance)

    registration_probe.probe_registration("a@icloud.com")

    assert closed["n"] == 1


def test_result_never_carries_credentials(monkeypatch):
    """结论里不能带 sentinel / csrf / cookie —— 它会被写进报告和日志。"""
    result = _probe(monkeypatch, "login_password")

    blob = str(result).lower()
    for leaked in ("sentinel-token", "csrf-token", "device-id", "oai-did"):
        assert leaked not in blob
