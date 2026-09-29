"""A registration succeeds only with a confirmed, persisted password."""
import json
import queue
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import auth_flow
import browser_flow
import plus_trial_checker
from webui import db, registrar


EMAIL = "required-password@icloud.com"
PASSWORD = "fixture-confirmed-password"


@pytest.mark.parametrize("outcome", [200, 400, 409, 500, "timeout"])
def test_protocol_publishes_password_only_after_server_acceptance(outcome):
    flow = auth_flow.AuthFlow.__new__(auth_flow.AuthFlow)
    flow.result = auth_flow.AuthResult()
    flow._random_password = Mock(return_value=PASSWORD)
    flow._common_headers = Mock(return_value={})
    flow._last_sentinel_token = ""
    flow._trace_http = Mock()
    flow._on_password = Mock()
    flow.session = Mock()
    flow.session.get.return_value.status_code = 200

    def submit(*args, **kwargs):
        assert flow.result.password == ""
        flow._on_password.assert_not_called()
        if outcome == "timeout":
            raise TimeoutError("fixture timeout")
        return SimpleNamespace(status_code=outcome, text="fixture rejection")

    flow.session.post.side_effect = submit
    if outcome == "timeout":
        with pytest.raises(TimeoutError):
            flow.register_password(EMAIL)
    elif outcome != 200:
        with pytest.raises(RuntimeError, match=f"HTTP {outcome}"):
            flow.register_password(EMAIL)
    else:
        assert flow.register_password(EMAIL) is True
    if outcome == 200:
        assert flow.result.password == PASSWORD
        flow._on_password.assert_called_once_with(EMAIL, PASSWORD)
    else:
        assert not flow.result.password
        flow._on_password.assert_not_called()


def protocol_fixture(*, is_new, mode, saved_password=""):
    flow = auth_flow.AuthFlow.__new__(auth_flow.AuthFlow)
    flow.result = auth_flow.AuthResult()
    flow._env_overrides = {"WEBUI_ALLOW_LOGIN": "1"}
    flow._existing_email_verification_mode = mode
    flow._existing_page_type = "email_otp_verification"
    flow._account_callback = Mock(return_value={"password": saved_password})
    for name in ("check_proxy", "warmup", "get_csrf_token", "get_auth_url",
                 "auth_oauth_init", "get_sentinel_token"):
        setattr(flow, name, Mock(return_value=True))
    flow.signup = Mock(return_value=is_new)
    flow.register_password = Mock(return_value=False)
    flow.send_otp = Mock()
    mail = SimpleNamespace(
        kind="icloud_relay", pooled=True,
        create_mailbox=Mock(return_value=EMAIL), wait_for_otp=Mock(),
    )
    return flow, mail


@pytest.mark.parametrize("is_new,mode", [(True, ""), (False, "passwordless_signup")])
def test_password_rejection_stops_registration_before_otp(is_new, mode):
    flow, mail = protocol_fixture(is_new=is_new, mode=mode)
    # passwordless_signup is new registration even when pooled login is disabled.
    flow._env_overrides["WEBUI_ALLOW_LOGIN"] = "0"
    with pytest.raises(auth_flow.PasswordRequiredError):
        flow.run_register(mail)
    flow.register_password.assert_called_once_with(EMAIL)
    flow.send_otp.assert_not_called()
    mail.wait_for_otp.assert_not_called()


def test_existing_account_without_known_password_requires_reset(monkeypatch):
    monkeypatch.delenv("LOGIN_PASSWORD", raising=False)
    flow, mail = protocol_fixture(is_new=False, mode="passwordless_login")
    with pytest.raises(auth_flow.PasswordRequiredError, match="官网"):
        flow.run_register(mail)
    flow.register_password.assert_not_called()
    mail.wait_for_otp.assert_not_called()
    assert not flow.result.password


def test_existing_account_keeps_known_password_when_otp_fails(monkeypatch):
    monkeypatch.delenv("LOGIN_PASSWORD", raising=False)
    flow, mail = protocol_fixture(
        is_new=False, mode="passwordless_login", saved_password=PASSWORD,
    )
    mail.wait_for_otp.side_effect = RuntimeError("fixture OTP failure")
    with pytest.raises(RuntimeError, match="fixture OTP failure"):
        flow.run_register(mail)
    assert flow.result.password == PASSWORD
    flow.register_password.assert_not_called()


@pytest.mark.parametrize("step", ["password", "unknown", "email", "otp", "profile", "done"])
def test_browser_persists_only_after_accepted_password_step(monkeypatch, step):
    monkeypatch.setattr(browser_flow, "_random_password", lambda: PASSWORD)
    monkeypatch.setattr(browser_flow.time, "sleep", lambda _: None)
    flow = browser_flow.BrowserAuthFlow.__new__(browser_flow.BrowserAuthFlow)
    flow.result = auth_flow.AuthResult()
    flow.result.email = EMAIL
    flow._on_password = Mock()
    page = Mock()

    def click(_page):
        assert not flow.result.password
        flow._on_password.assert_not_called()

    flow._click_continue = Mock(side_effect=click)
    flow._wait_for_step = Mock(return_value=step)
    if step in {"otp", "profile", "done"}:
        assert flow._set_password(page) == PASSWORD
        flow._on_password.assert_called_once_with(EMAIL, PASSWORD)
    else:
        with pytest.raises(auth_flow.PasswordRequiredError):
            flow._set_password(page)
        assert not flow.result.password
        flow._on_password.assert_not_called()


@pytest.mark.parametrize("step", ["done", "otp", "profile"])
def test_browser_stops_passwordless_registration(step):
    flow = browser_flow.BrowserAuthFlow.__new__(browser_flow.BrowserAuthFlow)
    flow.result = auth_flow.AuthResult()
    flow._detect_step = Mock(return_value=step)
    flow._goto_password_page = Mock(return_value=False)
    flow._handle_otp = Mock()
    flow._complete_profile = Mock()
    with pytest.raises(auth_flow.PasswordRequiredError):
        flow._run_auth_steps(Mock(), Mock(), EMAIL)
    flow._handle_otp.assert_not_called()
    flow._complete_profile.assert_not_called()


@pytest.mark.parametrize("engine", ["protocol", "browser"])
@pytest.mark.parametrize("saved_password, failure", [
    ("", ""), ("", "partial"), (PASSWORD, ""),
    (PASSWORD, "password"), (PASSWORD, "storage"),
])
def test_worker_requires_password_and_does_not_downgrade_errors(
    tmp_path, monkeypatch, engine, saved_password, failure,
):
    run_id = "require-password-fixture"
    log_path = tmp_path / "worker.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(f"{EMAIL}----https://relay.example/messages/TOKEN/{EMAIL}", kind="icloud_relay")
    if saved_password:
        db.save_password_early(EMAIL, saved_password)
        db.save_totp_early(EMAIL, "fixture-existing-secret")
    account = db.claim_account(EMAIL)
    db.create_run(run_id, EMAIL, str(log_path))

    class FlowFixture:
        def __init__(self, *args, **kwargs):
            self.result = auth_flow.AuthResult()
            self.result.email = EMAIL
            self.result.access_token = "fixture-access"
            self.result.session_token = "fixture-session"
            if failure == "storage":
                self.result.password = "fixture-new-password"

        def run_register(self, mail):
            if failure == "password":
                raise auth_flow.PasswordRequiredError("fixture password failure")
            if failure == "partial":
                raise RuntimeError("fixture late failure")
            return self.result

    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    monkeypatch.setattr(browser_flow, "BrowserAuthFlow", FlowFixture)
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *args: SimpleNamespace(display_name="Fixture"))
    monkeypatch.setattr(plus_trial_checker, "check_plus_trial", Mock(return_value={"status": "free"}))
    export = Mock()
    monkeypatch.setattr(registrar, "_try_export_to_panels", export)
    if failure == "storage":
        monkeypatch.setattr(db, "save_registered", Mock())
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})
    registrar._do_register(run_id, account, {
        "engine": engine, "want_2fa": False, "want_refresh_token": False,
    }, log_path)

    successful = bool(saved_password) and not failure
    run = next(r for r in db.list_runs() if r["run_id"] == run_id)
    assert run["status"] == ("done" if successful else "failed")
    assert db.get_account(EMAIL)["status"] == ("done" if successful else "failed")
    events = []
    while not events_queue.empty():
        item = events_queue.get_nowait()
        if isinstance(item, str) and item.startswith("__EVENT__:"):
            events.append(json.loads(item.removeprefix("__EVENT__:")))
    assert bool([e for e in events if e["kind"] == "done"]) is successful
    if successful:
        assert db.get_registered(EMAIL)["password"] == PASSWORD
        assert db.get_registered(EMAIL)["totp_secret"] == "fixture-existing-secret"
        assert next(e for e in events if e["kind"] == "done")["password"] == PASSWORD
        export.assert_called_once()
    else:
        assert run["error_category"] == "account"
        export.assert_not_called()
