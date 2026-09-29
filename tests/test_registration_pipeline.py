"""Exercise real worker and engine orchestration with local service fixtures."""
import json
import queue
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import auth_flow
import browser_flow
import plus_trial_checker
from fingerprint import generate_fingerprint
from mail_providers import MailProviderError, icloud_relay
from webui import db, registrar


def test_oauth_phone_verification_reason_is_preserved_and_not_network_classified():
    error = registrar.RequestedCredentialError(
        ["refresh_token"],
        "phone_verification_required",
    )

    assert "refresh_token" in str(error)
    assert "OAuth: phone_verification_required" in str(error)
    assert registrar.classify_error(error) == "account"
    assert "TOKEN" not in str(error)


def test_requested_credential_without_oauth_reason_is_account_failure():
    error = registrar.RequestedCredentialError(["refresh_token"])

    assert str(error) == "注册流程未获取用户请求的凭证: refresh_token"
    assert registrar.classify_error(error) == "account"


def test_worker_accepts_missing_optional_refresh_token(
    tmp_path, monkeypatch,
):
    email = "phone-required@icloud.com"
    run_id = "phone-required-contract"
    log_path = tmp_path / "phone-required.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(
        f"{email}----https://relay.example/messages/TOKEN/{email}",
        kind="icloud_relay",
    )
    account = db.claim_account(email)
    db.create_run(run_id, email, str(log_path))

    class MailFixture:
        pooled = True
        kind = "icloud_relay"
        display_name = "Fixture mailbox"

        def set_proxy(self, _proxy):
            pass

    class FlowFixture:
        def __init__(self, _config, **_kwargs):
            self.result = auth_flow.AuthResult()
            self.result.email = email
            self.result.password = "fixture-password"
            self.result.access_token = "fixture-access"
            self.result.session_token = "fixture-session"
            self._oauth_failure_reason = "phone_verification_required"

        def run_register(self, _mail):
            return self.result

    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *args: MailFixture())
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})

    registrar._do_register(
        run_id,
        account,
        {
            "engine": "protocol",
            "environment": {"proxy": ""},
            "want_access_token": True,
            "want_session_token": True,
            "want_refresh_token": False,
            "want_2fa": False,
        },
        log_path,
    )

    run = next(row for row in db.list_runs() if row["run_id"] == run_id)
    assert run["status"] == "done"
    assert run["error_category"] is None
    assert db.get_account(email)["status"] == "done"
    assert not db.get_registered(email)["refresh_token"]


@pytest.mark.parametrize("engine, failure", [
    ("protocol", ""), ("protocol", "warmup"), ("protocol", "otp"),
    ("browser", ""), ("browser", "runtime"), ("browser", "network"),
])
def test_worker_runs_engine_and_persists_outcome(tmp_path, monkeypatch, engine, failure):
    email = "pipeline@icloud.com"
    run_id = f"fixture-{engine}-{failure or 'success'}"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(f"{email}----https://relay.example/messages/TOKEN/{email}", kind="icloud_relay")
    account = db.claim_account(email)
    db.create_run(run_id, email, str(tmp_path / "run.log"))
    profile = generate_fingerprint(country_code="JP", browser_type="firefox")
    expected = deepcopy(profile)
    environment = {
        "fingerprint": profile, "fingerprint_id": profile["fingerprint_id"],
        "country_code": "JP", "country_source": "manual", "exit_country": "JP",
        "exit_ip": "203.0.113.20",
        "proxy": "socks5h://fixture-user:fixture-pass@proxy.example:3000",
        "browser_family": "firefox",
    }
    db.update_run_environment(run_id, environment)
    calls = []

    class MailFixture:
        pooled = True
        kind = "icloud_relay"
        display_name = "Fixture mailbox"

        def set_proxy(self, proxy):
            calls.append(("mail_proxy", proxy))

        def create_mailbox(self):
            calls.append("mailbox")
            return email

        def wait_for_otp(self, *args, **kwargs):
            calls.append("otp")
            if failure == "otp":
                raise RuntimeError("mail network timeout token=fixture-secret")
            return "654321"

    class SessionFixture:
        def get(self, *args, **kwargs):
            return SimpleNamespace(status_code=200, text="ip=203.0.113.20\nloc=JP\n")

        def close(self):
            pass

    class ProtocolFixture(auth_flow.AuthFlow):
        # Keep AuthFlow.run_register and check_proxy; replace external steps.
        def warmup(self):
            return failure != "warmup"

        def get_csrf_token(self):
            return "fixture-csrf"

        def get_auth_url(self, *args, **kwargs):
            return "https://auth.example/authorize"

        def auth_oauth_init(self, *args):
            return "fixture-device"

        def get_sentinel_token(self, *args):
            return "fixture-sentinel"

        def signup(self, *args):
            calls.append("signup")
            return True

        def register_password(self, *args):
            self.result.password = "fixture-password"
            return True

        def send_otp(self):
            pass

        def verify_otp(self, code):
            assert code == "654321"
            return {}

        def fetch_client_auth_session_dump(self, *args):
            return {}

        def create_account(self):
            return "https://chatgpt.com/fixture"

        def follow_redirect_chain(self, *args, **kwargs):
            return "https://chatgpt.com/fixture", "https://chatgpt.com/"

        def _consume_callback_for_session(self, *args):
            return True

        def get_auth_session(self):
            self.result.session_token = "fixture-session"
            self.result.access_token = "fixture-access"
            return self.result.session_token, self.result.access_token

    class BrowserFixture(browser_flow.BrowserAuthFlow):
        # Keep run_register, runtime validation, exit observation and cleanup.
        def _warmup(self, page):
            pass

        def _click_signup(self, page):
            calls.append("signup")

        def _enter_email(self, page, address):
            assert address == email

        def _run_auth_steps(self, page, mail, address):
            mail.wait_for_otp(address)
            self.result.password = "fixture-password"

        def _wait_for_chat_page(self, page):
            pass

        def _extract_tokens(self, page, context):
            self.result.session_token = "fixture-session"

        def _fetch_access_token(self, page):
            self.result.access_token = "fixture-access"

        def _screenshot_on_error(self, *args):
            calls.append("error_capture")

    observed = {
        "user_agent": profile["user_agent"], "platform": profile["navigator_platform"],
        "vendor": profile["navigator_vendor"], "language": profile["locale"],
        "languages": profile["languages"], "hardware_concurrency": profile["hardware_concurrency"],
        "device_memory": profile["device_memory"], "max_touch_points": profile["max_touch_points"],
        "viewport": dict(profile["viewport"]),
        "screen": {
            "width": int(profile["screen"].split("x")[0]),
            "height": int(profile["screen"].split("x")[1]),
        },
        "device_pixel_ratio": profile["device_pixel_ratio"], "timezone": profile["timezone"],
        "webdriver_undefined": True, "permission_status_is_native": True,
    }
    if failure == "runtime":
        observed["screen"]["width"] += 1
    trace_ip = "203.0.113.21" if failure == "network" else "203.0.113.20"
    page = SimpleNamespace(
        evaluate=lambda script: observed,
        request=SimpleNamespace(get=lambda *a, **kw: SimpleNamespace(
            ok=True, status=200, text=lambda: f"ip={trace_ip}\nloc=JP\n",
        )),
    )

    def launch(**kwargs):
        assert kwargs["fingerprint"] == expected
        return "fixture-pw", "fixture-browser", SimpleNamespace(new_page=lambda: page)

    monkeypatch.setattr(auth_flow, "create_http_session", lambda **kw: SessionFixture())
    monkeypatch.setattr(registrar, "AuthFlow", ProtocolFixture)
    monkeypatch.setattr(browser_flow, "BrowserAuthFlow", BrowserFixture)
    monkeypatch.setattr(browser_flow, "launch_browser", launch)
    monkeypatch.setattr(browser_flow, "close_browser", lambda *a: calls.append("closed"))
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *a: MailFixture())
    monkeypatch.setattr(plus_trial_checker, "check_plus_trial", lambda *a, **kw: {
        "status": "free", "label": "Free", "trial_eligible": False,
    })
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})
    registrar._do_register(run_id, account, {
        "engine": engine, "environment": environment, "want_refresh_token": False,
        "want_2fa": False, "browser_engine": "playwright",
    }, tmp_path / "run.log")

    events = db.get_run_probes(run_id)
    final = next(event for event in events if event["stage"] == "task.finished")
    assert final["status"] == ("failed" if failure else "ok")
    assert profile == expected
    assert registrar._current_run.run_id is None
    drained = []
    while not events_queue.empty():
        drained.append(events_queue.get_nowait())
    assert drained[-1] is None
    log_text = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "fixture-password" not in log_text
    assert "fixture-secret" not in log_text
    assert any('"kind": "error"' in str(event) for event in drained) == bool(failure)
    assert any('"kind": "done"' in str(event) for event in drained) == (not failure)
    if engine == "browser":
        assert "closed" in calls
    # 收件与注册出口解耦：未配置 mailbox_proxy 时默认直连中转站。
    assert ("mail_proxy", "") in calls
    if failure:
        registered = db.get_registered(email)
        if engine == "protocol" and failure == "otp":
            assert registered["password"] == "fixture-password"
            assert registered["extra"]["pending"] is True
            assert all(not registered[key] for key in (
                "access_token", "session_token", "refresh_token", "id_token",
            ))
        else:
            assert registered is None
            expected_status = "failed" if (
                engine == "protocol" and failure == "otp"
            ) else "available"
            assert db.get_account(email)["status"] == expected_status
        if failure in {"runtime", "network"}:
            assert "signup" not in calls
            assert any(e["stage"] == "environment.runtime" and e["status"] == "failed" for e in events)
        assert all("fixture-secret" not in e.get("error", "") for e in events)
    else:
        assert not [e for e in events if e["status"] == "failed"]
        assert db.get_registered(email)["access_token"] == "fixture-access"
        assert db.get_account(email)["status"] == "done"
        trial = [e for e in events if e["stage"] == "plus_trial.check"][-1]
        assert trial["status"] == "ok"
        assert trial["details"]["result_status"] == "free"
        assert trial["duration_ms"] >= 0


@pytest.mark.parametrize("failure, expected_category, expected_pool_status", [
    ("preflight", "network", "available"),
    ("relay_401", "account", "failed"),
    ("transient_mail", "network", "available"),
])
def test_worker_typed_failure_preserves_account_state(
    tmp_path, monkeypatch, caplog, failure, expected_category, expected_pool_status,
):
    email = "worker-fixture@icloud.com"
    relay_url = f"https://relay.example/messages/TOKEN/{email}"
    run_id = f"typed-failure-{failure}"
    log_path = tmp_path / "worker.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(f"{email}----{relay_url}", kind="icloud_relay")
    account = db.claim_account(email)
    db.create_run(run_id, email, str(log_path))
    assert db.get_account(email)["status"] == "in_use"

    # Keep the real relay provider object, but replace its polling boundary with
    # a typed fixture so this worker-state test never waits on a network retry.
    if failure == "relay_401":
        relay_error = MailProviderError(
            "中转链接无效（HTTP 401）", fatal=True, kind="icloud_relay",
        )
    else:
        relay_error = MailProviderError(
            "authentication failed token=fixture-secret", fatal=False, kind="icloud_relay",
        )
    monkeypatch.setattr(
        icloud_relay.ICloudRelayProvider,
        "_messages",
        Mock(side_effect=relay_error),
    )

    class FlowFixture:
        def __init__(self, _config, **kwargs):
            self.result = auth_flow.AuthResult()
            self.on_password = kwargs["on_password"]

        def run_register(self, mail):
            if failure == "preflight":
                raise auth_flow.NetworkPreflightError("authentication failed")
            self.result.email = mail.create_mailbox()
            if failure == "relay_401":
                self.result.password = "fixture-password"
                self.on_password(self.result.email, self.result.password)
            mail.wait_for_otp(self.result.email)
            raise AssertionError("a failed fixture must stop before authentication completes")

    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    save_registered = Mock(wraps=db.save_registered)
    mark_done = Mock(wraps=db.mark_done)
    monkeypatch.setattr(db, "save_registered", save_registered)
    monkeypatch.setattr(db, "mark_done", mark_done)
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})

    registrar._do_register(run_id, account, {
        "engine": "protocol", "want_refresh_token": False, "want_2fa": False,
    }, log_path)

    assert db.get_account(email)["status"] == expected_pool_status
    run = next(row for row in db.list_runs() if row["run_id"] == run_id)
    assert run["status"] == "failed"
    assert run["error_category"] == expected_category
    final = [event for event in db.get_run_probes(run_id) if event["stage"] == "task.finished"]
    assert len(final) == 1
    assert final[0]["status"] == "failed"
    assert final[0]["error_category"] == expected_category
    assert "fixture-secret" not in caplog.text
    assert "fixture-password" not in caplog.text
    save_registered.assert_not_called()
    mark_done.assert_not_called()
    assert registrar._current_run.run_id is None

    drained = []
    while not events_queue.empty():
        drained.append(events_queue.get_nowait())
    assert drained[-1] is None
    status_events = [
        json.loads(item.removeprefix("__EVENT__:"))
        for item in drained if isinstance(item, str) and item.startswith("__EVENT__:")
    ]
    assert not [event for event in status_events if event["kind"] == "done"]
    errors = [event for event in status_events if event["kind"] == "error"]
    assert len(errors) == 1
    assert errors[0]["category"] == expected_category
    assert "fixture-secret" not in str(status_events)
    assert "fixture-secret" not in log_path.read_text(encoding="utf-8")
    assert "fixture-password" not in log_path.read_text(encoding="utf-8")

    registered = db.get_registered(email)
    if failure == "relay_401":
        assert "401" in run["error"]
        assert registered["password"] == "fixture-password"
        assert registered["extra"]["pending"] is True
        assert all(not registered[key] for key in (
            "access_token", "session_token", "refresh_token", "id_token",
        ))
    else:
        assert registered is None


def test_worker_rejects_normal_return_missing_requested_refresh_token(
    tmp_path, monkeypatch,
):
    email = "missing-refresh@icloud.com"
    run_id = "missing-refresh-contract"
    log_path = tmp_path / "missing-refresh.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(
        f"{email}----https://relay.example/messages/TOKEN/{email}",
        kind="icloud_relay",
    )
    account = db.claim_account(email)
    db.create_run(run_id, email, str(log_path))

    class MailFixture:
        pooled = True
        kind = "icloud_relay"
        display_name = "Fixture mailbox"

        def set_proxy(self, _proxy):
            pass

    class FlowFixture:
        def __init__(self, _config, **kwargs):
            self.result = auth_flow.AuthResult()
            self.result.email = email
            self.result.password = "fixture-password"
            self.result.access_token = "fixture-access"
            self.result.session_token = "fixture-session"
            self.on_password = kwargs["on_password"]

        def run_register(self, _mail):
            self.on_password(self.result.email, self.result.password)
            return self.result

    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *args: MailFixture())
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})

    registrar._do_register(
        run_id,
        account,
        {
            "engine": "protocol",
            "environment": {"proxy": ""},
            "want_access_token": True,
            "want_session_token": True,
            "want_refresh_token": True,
            "want_2fa": False,
        },
        log_path,
    )

    run = next(row for row in db.list_runs() if row["run_id"] == run_id)
    assert run["status"] == "failed"
    assert run["error_category"] == "account"
    assert db.get_account(email)["status"] == "failed"
    registered = db.get_registered(email)
    assert registered["password"] == "fixture-password"
    assert not registered["refresh_token"]

    probes = db.get_run_probes(run_id)
    registration_events = [event for event in probes if event["stage"] == "registration.run"]
    assert registration_events[-1]["status"] == "failed"
    assert not [event for event in probes if event["stage"] == "database.registered.save"]

    status_events = []
    while not events_queue.empty():
        item = events_queue.get_nowait()
        if isinstance(item, str) and item.startswith("__EVENT__:"):
            status_events.append(json.loads(item.removeprefix("__EVENT__:")))
    assert not [event for event in status_events if event["kind"] == "done"]
    assert [event for event in status_events if event["kind"] == "error"]


def test_worker_releases_account_when_oauth_session_is_rejected(
    tmp_path, monkeypatch,
):
    email = "stale-session@icloud.com"
    run_id = "stale-session-contract"
    log_path = tmp_path / "stale-session.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(
        f"{email}----https://relay.example/messages/TOKEN/{email}",
        kind="icloud_relay",
    )
    account = db.claim_account(email)
    db.create_run(run_id, email, str(log_path))

    class MailFixture:
        pooled = True
        kind = "icloud_relay"
        display_name = "Fixture mailbox"

        def set_proxy(self, _proxy):
            pass

    class FlowFixture:
        def __init__(self, _config, **_kwargs):
            self.result = auth_flow.AuthResult()

        def run_register(self, _mail):
            raise RuntimeError(
                "authorize/continue 失败(screen_hint=signup): HTTP 409 "
                "Your sign-in session is no longer valid. Please start over to continue."
            )

    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *args: MailFixture())
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})

    registrar._do_register(run_id, account, {
        "engine": "protocol",
        "environment": {"proxy": ""},
        "want_refresh_token": False,
        "want_2fa": False,
    }, log_path)

    run = next(row for row in db.list_runs() if row["run_id"] == run_id)
    assert run["status"] == "failed"
    assert run["error_category"] == "network"
    assert "session is no longer valid" in run["error"]
    assert db.get_account(email)["status"] == "available"
    assert "注册流程未获取用户请求的凭证" not in run["error"]


def test_worker_want_2fa_fails_before_persistence_when_secret_missing(
    tmp_path, monkeypatch,
):
    email = "missing-secret@icloud.com"
    run_id = "required-2fa-contract"
    log_path = tmp_path / "required-2fa.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(
        f"{email}----https://relay.example/messages/TOKEN/{email}",
        kind="icloud_relay",
    )
    account = db.claim_account(email)
    db.create_run(run_id, email, str(log_path))

    class MailFixture:
        pooled = True
        kind = "icloud_relay"
        display_name = "Fixture mailbox"

        def set_proxy(self, _proxy):
            pass

    class FlowFixture:
        def __init__(self, _config, **kwargs):
            self.result = auth_flow.AuthResult()
            self.result.email = email
            self.result.password = "fixture-password"
            self.result.access_token = "fixture-access"
            self.result.session_token = "fixture-session"
            self._oauth_failure_reason = ""
            self._on_password = kwargs.get("on_password")

        def run_register(self, _mail):
            self._on_password(email, self.result.password)
            return self.result

    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *args: MailFixture())
    monkeypatch.setattr(
        "webui.two_factor.bind_totp_2fa_inline", lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "webui.two_factor.bind_totp_2fa", lambda *args, **kwargs: None,
    )
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})

    registrar._do_register(run_id, account, {
        "engine": "protocol",
        "environment": {"proxy": ""},
        "want_refresh_token": False,
        "want_2fa": True,
    }, log_path)

    run = next(row for row in db.list_runs() if row["run_id"] == run_id)
    assert run["status"] == "failed"
    assert run["error_category"] == "account"
    assert db.get_account(email)["status"] == "failed"
    registered = db.get_registered(email)
    assert registered["password"] == "fixture-password"
    assert not registered["access_token"]
    assert not registered["totp_secret"]
    stages = db.get_run_probes(run_id)
    assert any(
        row["stage"] == "two_factor.bind" and row["status"] == "failed"
        for row in stages
    )
    assert not any(row["stage"] == "database.registered.save" for row in stages)


def test_worker_2fa_hook_falls_back_to_slow_path(
    tmp_path, monkeypatch,
):
    """快路径 enroll 瞬断失败时，钩子必须回落慢路径把 2FA 绑完，而不是废号。"""
    email = "2fa-hook-fallback@icloud.com"
    run_id = "2fa-hook-fallback-contract"
    log_path = tmp_path / "2fa-hook-fallback.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(
        f"{email}----https://relay.example/messages/TOKEN/{email}",
        kind="icloud_relay",
    )
    account = db.claim_account(email)
    db.create_run(run_id, email, str(log_path))

    class MailFixture:
        pooled = True
        kind = "icloud_relay"
        display_name = "Fixture mailbox"

        def set_proxy(self, _proxy):
            pass

    class FlowFixture:
        def __init__(self, _config, **kwargs):
            self.result = auth_flow.AuthResult()
            self.result.email = email
            self.result.password = "fixture-password"
            self.result.access_token = "fixture-access"
            self.result.session_token = "fixture-session"
            self._oauth_failure_reason = ""
            self._on_password = kwargs.get("on_password")
            self._on_session_ready = kwargs.get("on_session_ready")

        def run_register(self, _mail):
            self._on_password(email, self.result.password)
            # 模拟 AuthFlow.run_register 在拿到 session 后、Codex 授权前调钩子
            if self._on_session_ready:
                self._on_session_ready(self, self.result.access_token)
            return self.result

    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *args: MailFixture())
    monkeypatch.setattr(
        "webui.two_factor.bind_totp_2fa_inline", lambda *args, **kwargs: None,
    )
    slow_calls = []
    monkeypatch.setattr(
        "webui.two_factor.bind_totp_2fa",
        lambda *args, **kwargs: slow_calls.append(1)
        or {"secret": "JBSWY3DPEHPK3PXP", "factor_id": "f", "session_id": "s"},
    )
    monkeypatch.setattr(plus_trial_checker, "check_plus_trial", lambda *a, **kw: {
        "status": "free", "label": "Free", "trial_eligible": False,
    })
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})

    registrar._do_register(run_id, account, {
        "engine": "protocol",
        "environment": {"proxy": ""},
        "want_refresh_token": False,
        "want_2fa": True,
    }, log_path)

    assert slow_calls == [1]
    assert db.get_account(email)["status"] == "done"
    registered = db.get_registered(email)
    assert registered["totp_secret"] == "JBSWY3DPEHPK3PXP"


def test_worker_persona_terminal_is_not_retried_as_credential_gap(
    tmp_path, monkeypatch,
):
    """Persona 风控终态必须原样隔离，不能转成凭证缺失再走续取重试。"""
    email = "persona-terminal@icloud.com"
    run_id = "persona-terminal-contract"
    log_path = tmp_path / "persona-terminal.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(
        f"{email}----https://relay.example/messages/TOKEN/{email}",
        kind="icloud_relay",
    )
    account = db.claim_account(email)
    db.create_run(run_id, email, str(log_path))

    class MailFixture:
        pooled = True
        kind = "icloud_relay"
        display_name = "Fixture mailbox"

        def set_proxy(self, _proxy):
            pass

    class FlowFixture:
        def __init__(self, _config, **kwargs):
            self.result = auth_flow.AuthResult()
            self.result.email = email
            self.result.password = "fixture-password"
            self._oauth_failure_reason = ""
            self._on_password = kwargs.get("on_password")

        def run_register(self, _mail):
            self._on_password(email, self.result.password)
            raise auth_flow.IdentityVerificationRequired("needs_review", "inq_abc")

    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *args: MailFixture())
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})

    registrar._do_register(run_id, account, {
        "engine": "protocol",
        "environment": {"proxy": ""},
        "want_refresh_token": False,
        "want_2fa": True,
    }, log_path)

    run = next(row for row in db.list_runs() if row["run_id"] == run_id)
    assert run["status"] == "failed"
    assert "身份验证" in run["error"]
    assert "注册流程未获取用户请求的凭证" not in run["error"]
    pool_row = db.get_account(email)
    assert pool_row["status"] == "failed"
    assert "identity_verification_required" in (pool_row["fail_reason"] or "")


def test_worker_rejects_runtime_error_even_with_access_and_session_credentials(
    tmp_path, monkeypatch,
):
    email = "partial-refresh-runtime@icloud.com"
    run_id = "partial-refresh-runtime-contract"
    log_path = tmp_path / "partial-refresh-runtime.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(
        f"{email}----https://relay.example/messages/TOKEN/{email}",
        kind="icloud_relay",
    )
    account = db.claim_account(email)
    db.create_run(run_id, email, str(log_path))

    class MailFixture:
        pooled = True
        kind = "icloud_relay"
        display_name = "Fixture mailbox"

        def set_proxy(self, _proxy):
            pass

    class FlowFixture:
        def __init__(self, _config, **_kwargs):
            self.result = auth_flow.AuthResult()
            self.result.email = email
            self.result.password = "fixture-password"
            self.result.access_token = "fixture-access"
            self.result.session_token = "fixture-session"

        def run_register(self, _mail):
            raise RuntimeError("post-session fixture failure")

    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *args: MailFixture())
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})

    registrar._do_register(
        run_id,
        account,
        {
            "engine": "protocol",
            "environment": {"proxy": ""},
            "want_access_token": True,
            "want_session_token": True,
            "want_refresh_token": False,
            "want_2fa": False,
        },
        log_path,
    )

    run = next(row for row in db.list_runs() if row["run_id"] == run_id)
    assert run["status"] == "failed"
    assert run["error_category"] == "unknown"
    assert db.get_account(email)["status"] == "failed"
    registered = db.get_registered(email)
    assert registered["password"] == "fixture-password"
    assert (registered.get("extra") or {}).get("pending") is True
    assert not registered["access_token"]
    assert not registered["session_token"]
    assert not registered["refresh_token"]

    probes = db.get_run_probes(run_id)
    registration_events = [event for event in probes if event["stage"] == "registration.run"]
    assert registration_events[-1]["status"] == "failed"
    assert not [event for event in probes if event["stage"] == "database.registered.save"]

    status_events = []
    while not events_queue.empty():
        item = events_queue.get_nowait()
        if isinstance(item, str) and item.startswith("__EVENT__:"):
            status_events.append(json.loads(item.removeprefix("__EVENT__:")))
    assert not [event for event in status_events if event["kind"] == "done"]
    assert [event for event in status_events if event["kind"] == "error"]


def test_worker_rejects_silent_credential_persistence(
    tmp_path, monkeypatch,
):
    """A no-op save must not mark a fully credentialed result as done."""
    email = "silent-save@icloud.com"
    run_id = "silent-save-contract"
    log_path = tmp_path / "silent-save.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(
        f"{email}----https://relay.example/messages/TOKEN/{email}",
        kind="icloud_relay",
    )
    account = db.claim_account(email)
    db.create_run(run_id, email, str(log_path))

    class MailFixture:
        pooled = True
        kind = "icloud_relay"
        display_name = "Fixture mailbox"

        def set_proxy(self, _proxy):
            pass

    class FlowFixture:
        def __init__(self, _config, **_kwargs):
            self.result = auth_flow.AuthResult()
            self.result.email = email
            self.result.password = "fixture-password"
            self.result.access_token = "fixture-access"
            self.result.session_token = "fixture-session"

        def run_register(self, _mail):
            return self.result

    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *args: MailFixture())
    monkeypatch.setattr(registrar.db, "save_registered", lambda _d: None)
    events_queue = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {run_id: events_queue})

    registrar._do_register(
        run_id,
        account,
        {
            "engine": "protocol",
            "environment": {"proxy": ""},
            "want_refresh_token": False,
            "want_2fa": False,
        },
        log_path,
    )

    run = next(row for row in db.list_runs() if row["run_id"] == run_id)
    assert run["status"] == "failed"
    assert db.get_account(email)["status"] == "failed"
    assert not [event for event in db.get_run_probes(run_id) if event["stage"] == "task.finished" and event["status"] == "ok"]
