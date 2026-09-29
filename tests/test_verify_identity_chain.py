"""链路对 identity_verification（Persona 证件验证）页的真实协议处理。

真实失败场景：create_account 返回 page.type=identity_verification +
persona_inquiry，页面协议是 get_inquiry_status -> complete_id_verification。
只有 approved 能推进；其余状态必须终止隔离（重发 OTP 只会 400 invalid_auth_step）。
"""
import pytest
from types import SimpleNamespace

from auth_flow import (
    AuthFlow,
    IdentityVerificationRequired,
    _looks_like_email_verify_url,
    _looks_like_identity_verification_url,
)
from config import Config
from fingerprint import generate_fingerprint


def _resp(status, json_body=None, location="", text=""):
    return SimpleNamespace(
        status_code=status,
        headers={"Location": location},
        text=text,
        json=lambda: json_body or {},
    )


class _FakeMail:
    def __init__(self, code="654321"):
        self.code = code
        self.seen = 0
        self.waited = 0

    def mark_all_current_seen(self):
        self.seen += 1

    def wait_for_otp(self, email, timeout=180, issued_after=None):
        self.waited += 1
        return self.code


def _build_flow(monkeypatch):
    fake_session = SimpleNamespace(get=lambda *a, **k: _resp(200))
    monkeypatch.setattr("auth_flow.create_http_session", lambda **kw: fake_session)
    flow = AuthFlow(
        config=Config(),
        fingerprint=generate_fingerprint(country_code="JP", browser_family="firefox"),
    )
    flow.session = fake_session
    flow.result.email = "chain-fixture@icloud.com"
    flow._last_sentinel_token = ""
    flow._last_sentinel_so_token = ""
    return flow


def _patch_persona(monkeypatch, flow, status):
    monkeypatch.setattr(flow, "_get_identity_verification_status", lambda: status)


def test_helpers_distinguish_email_otp_from_persona():
    assert _looks_like_email_verify_url("https://auth.openai.com/email-verification")
    assert not _looks_like_email_verify_url("https://auth.openai.com/verify-your-identity")
    assert _looks_like_identity_verification_url("https://auth.openai.com/verify-your-identity")
    assert not _looks_like_identity_verification_url("https://auth.openai.com/email-verification")


def test_follow_chain_completes_approved_persona(monkeypatch):
    flow = _build_flow(monkeypatch)
    verify_page = "https://auth.openai.com/verify-your-identity"
    next_step = "https://auth.openai.com/authorize/continue?state=STATE"
    callback = "https://chatgpt.com/api/auth/callback/openai?code=CODE&state=STATE"

    def fake_get(url, **kwargs):
        if url == verify_page:
            return _resp(200, text="<html>verify</html>")
        if url == next_step:
            return _resp(302, location=callback)
        return _resp(200)

    flow.session = SimpleNamespace(get=fake_get)
    _patch_persona(monkeypatch, flow, "approved")
    monkeypatch.setattr(
        flow,
        "_complete_identity_verification",
        lambda: {"continue_url": next_step},
    )

    got, _final = flow.follow_redirect_chain(verify_page, mail_provider=None, email="")

    assert got == callback


def test_follow_chain_raises_on_needs_review_persona(monkeypatch):
    flow = _build_flow(monkeypatch)
    verify_page = "https://auth.openai.com/verify-your-identity"
    flow.session = SimpleNamespace(get=lambda *a, **k: _resp(200, text="<html>"))
    _patch_persona(monkeypatch, flow, "needs_review")

    with pytest.raises(IdentityVerificationRequired) as exc:
        flow.follow_redirect_chain(verify_page, mail_provider=None, email="")
    assert exc.value.status == "needs_review"


def test_create_account_completes_approved_persona(monkeypatch):
    flow = _build_flow(monkeypatch)
    complete_calls = []

    class FakeSession:
        cookies = SimpleNamespace(get=lambda name, default="": default)

        def post(self, url, **kwargs):
            if url.endswith("/create_account"):
                return _resp(200, {
                    "continue_url": "https://auth.openai.com/verify-your-identity",
                    "page": {"type": "identity_verification"},
                    "oai-client-auth-session": {"persona_inquiry": {"id": "inq_abc"}},
                })
            raise AssertionError(f"unexpected post: {url}")

    flow.session = FakeSession()
    _patch_persona(monkeypatch, flow, "approved")
    monkeypatch.setattr(
        flow,
        "_complete_identity_verification",
        lambda: complete_calls.append(1)
        or {"continue_url": "https://auth.openai.com/authorize/continue?state=S"},
    )

    cont = flow.create_account()
    assert cont.startswith("https://auth.openai.com/authorize/continue")
    assert complete_calls == [1]


def test_create_account_raises_on_declined_persona(monkeypatch):
    flow = _build_flow(monkeypatch)

    class FakeSession:
        cookies = SimpleNamespace(get=lambda name, default="": default)

        def post(self, url, **kwargs):
            if url.endswith("/create_account"):
                return _resp(200, {
                    "continue_url": "https://auth.openai.com/verify-your-identity",
                    "page": {"type": "identity_verification"},
                    "oai-client-auth-session": {"persona_inquiry": {"id": "inq_abc"}},
                })
            raise AssertionError(f"unexpected post: {url}")

    flow.session = FakeSession()
    _patch_persona(monkeypatch, flow, "declined")

    with pytest.raises(IdentityVerificationRequired) as exc:
        flow.create_account()
    assert exc.value.status == "declined"


def test_reauthorize_completes_approved_persona(monkeypatch):
    flow = _build_flow(monkeypatch)
    authorize_url = "https://auth.openai.com/authorize?client_id=X&state=STATE"
    verify_page = "https://auth.openai.com/verify-your-identity"
    final_callback = "https://chatgpt.com/api/auth/callback/openai?code=CODE&state=STATE"

    def fake_get(url, **kwargs):
        if url == authorize_url:
            return _resp(302, location=verify_page)
        return _resp(200)

    flow.session = SimpleNamespace(get=fake_get)
    _patch_persona(monkeypatch, flow, "approved")
    monkeypatch.setattr(
        flow,
        "_complete_identity_verification",
        lambda: {"continue_url": final_callback},
    )

    got = flow._reauthorize_for_session(authorize_url, mail_provider=None)
    assert got == final_callback


def test_registrar_classifies_persona_as_account(monkeypatch):
    from webui import registrar

    assert (
        registrar.classify_error(IdentityVerificationRequired("needs_review", "inq_abc"))
        == "account"
    )
