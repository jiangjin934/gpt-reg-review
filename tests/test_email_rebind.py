from types import SimpleNamespace

import pytest

from webui import db, probes
from webui import email_rebind


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    path = tmp_path / "webui.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    return path


def _save_registered(email, **fields):
    db.save_registered({"email": email, "password": "password-1", **fields})


def _save_icloud_account(email="source@icloud.com"):
    db.import_accounts(
        f"{email}----https://relay.example/messages/token/{email}",
        kind="icloud_relay",
    )


def test_email_in_use_checks_registered_and_pool_records(isolated_db):
    _save_registered("registered@example.com")
    _save_icloud_account()

    assert db.email_in_use("REGISTERED@example.com")
    assert db.email_in_use("SOURCE@icloud.com")
    assert not db.email_in_use("new@example.com")
    assert not db.email_in_use("source@icloud.com", exclude="source@icloud.com")


def test_complete_email_rebind_moves_credentials_and_metadata(isolated_db):
    _save_registered(
        "source@icloud.com",
        access_token="old-access",
        session_token="old-session",
        device_id="old-device",
    )

    db.complete_email_rebind(
        "SOURCE@icloud.com",
        "NewUser@example.com",
        credential_updates={"access_token": "new-access", "device_id": "new-device"},
        metadata={"source_kind": "icloud_relay", "target_kind": "cf_temp"},
    )

    assert db.get_registered("source@icloud.com") is None
    moved = db.get_registered("newuser@example.com")
    assert moved["access_token"] == "new-access"
    assert moved["session_token"] == "old-session"
    assert moved["device_id"] == "new-device"
    assert moved["extra"]["email_rebind"]["source_kind"] == "icloud_relay"


@pytest.mark.parametrize("conflict_kind", ["registered", "pool"])
def test_complete_email_rebind_rejects_conflict_without_changing_source(
    isolated_db, conflict_kind
):
    _save_registered("source@icloud.com", access_token="source-access")
    if conflict_kind == "registered":
        _save_registered("target@example.com")
    else:
        db.import_accounts(
            "target@example.com----https://relay.example/messages/token/target",
            kind="icloud_relay",
        )

    with pytest.raises(ValueError, match="目标邮箱已存在"):
        db.complete_email_rebind("source@icloud.com", "target@example.com")

    source = db.get_registered("source@icloud.com")
    assert source["access_token"] == "source-access"


def test_prepare_mail_com_target_claims_creates_and_releases(isolated_db, monkeypatch):
    db.import_accounts(
        "parent@mail.com----secret", kind="mail_com"
    )
    db.set_setting("mail_com_alias_domain", "dr.com")

    class FakeMailProvider:
        alias_domain = "dr.com"

        def __init__(self):
            self.closed = False

        def create_mailbox(self):
            return "gcabc123456@dr.com"

        def close(self):
            self.closed = True

    monkeypatch.setattr(
        email_rebind, "create_mail_provider",
        lambda kind, settings, account=None: FakeMailProvider(),
    )
    provider, alias = email_rebind._prepare_mail_com_target(
        db.get_mail_settings()
    )
    assert alias == "gcabc123456@dr.com"
    # 母号放回池子（还能挂更多别名），provider 保留取 OTP
    parent = db.get_account("parent@mail.com")
    assert parent["status"] == "available"


def test_prepare_mail_com_target_pool_exhausted(isolated_db):
    with pytest.raises(email_rebind.EmailRebindError, match="母号池耗尽"):
        email_rebind._prepare_mail_com_target(db.get_mail_settings())


def test_prepare_mail_com_target_marks_full_parent_failed_and_moves_on(
    isolated_db, monkeypatch
):
    db.import_accounts(
        "full@mail.com----secret\nnext@mail.com----secret",
        kind="mail_com",
    )

    class FakeMailProvider:
        alias_domain = "dr.com"
        calls = 0

        def create_mailbox(self):
            type(self).calls += 1
            if type(self).calls == 1:
                from mail_providers.mail_com import MailComAliasError
                raise MailComAliasError("母号别名已满", fatal=True)
            return "gcnext123456@dr.com"

        def close(self):
            pass

    monkeypatch.setattr(
        email_rebind, "create_mail_provider",
        lambda kind, settings, account=None: FakeMailProvider(),
    )
    provider, alias = email_rebind._prepare_mail_com_target(
        db.get_mail_settings()
    )
    assert alias == "gcnext123456@dr.com"
    assert db.get_account("full@mail.com")["status"] == "failed"
    assert db.get_account("next@mail.com")["status"] == "available"


def test_rebind_mail_com_pipeline_uses_mail_com_target(isolated_db, monkeypatch):
    source = "source@icloud.com"
    _save_registered(source, access_token="old-access")
    _save_icloud_account(source)
    db.import_accounts("parent@mail.com----secret", kind="mail_com")
    db.set_setting("mail_com_alias_domain", "dr.com")

    class FakeResponse:
        def __init__(self, payload):
            self.ok = True
            self.status_code = 200
            self._payload = payload

        def json(self):
            return self._payload

    class FakeSession:
        def get(self, url, **kwargs):
            return FakeResponse({"eligible": True} if url.endswith("/eligibility") else {"ok": True})

        def post(self, url, **kwargs):
            return FakeResponse({"success": True})

        def close(self):
            pass

    class FakeMailComProvider:
        alias_domain = "dr.com"

        def __init__(self):
            self.closed = False

        def create_mailbox(self):
            return "gcabc123456@dr.com"

        def wait_for_otp(self, email, *, timeout, issued_after):
            assert email == "gcabc123456@dr.com"
            return "654321"

        def close(self):
            self.closed = True

    class FakeRelayProvider:
        def set_proxy(self, proxy):
            pass

    class FakeFlow:
        def __init__(self, *_args, **_kwargs):
            self.session = FakeSession()
            self._client_auth_session_id = "session-fixture"
            self._ua = "fixture-ua"
            self.result = SimpleNamespace(
                access_token="fixture-access",
                device_id="fixture-device",
                cookie_header="fixture-cookie",
                to_dict=lambda: {"access_token": "fixture-access"},
            )

        def run_protocol_login(self, provider, email, password=""):
            return self.result

        def get_auth_session(self):
            return "fixture-session", "fixture-access"

    def fake_create_provider(kind, settings, account=None):
        return FakeMailComProvider() if kind == "mail_com" else FakeRelayProvider()

    monkeypatch.setattr(email_rebind, "create_mail_provider", fake_create_provider)
    monkeypatch.setattr(email_rebind, "AuthFlow", FakeFlow)
    monkeypatch.setattr(email_rebind, "_account_id", lambda _token: "account-fixture")
    monkeypatch.setattr(email_rebind, "_session_id", lambda _flow, _token: "session-fixture")

    result = email_rebind.rebind_registered_email(
        source, proxy="", otp_timeout=240, target_kind="mail_com"
    )
    assert result["target_email"] == "gcabc123456@dr.com"
    moved = db.get_registered("gcabc123456@dr.com")
    assert moved is not None
    assert moved["extra"]["email_rebind"]["target_kind"] == "mail_com"


def test_rebind_mail_com_rejects_explicit_target(isolated_db):
    _save_registered("source@icloud.com")
    _save_icloud_account("source@icloud.com")
    db.set_setting("mail_com_alias_domain", "dr.com")
    with pytest.raises(email_rebind.EmailRebindError, match="自动生成"):
        email_rebind.rebind_registered_email(
            "source@icloud.com",
            "manual@dr.com",
            proxy="",
            target_kind="mail_com",
        )


def test_rebind_mail_com_recycles_alias_when_failure_before_begin(isolated_db, monkeypatch):
    source = "source@icloud.com"
    _save_registered(source)
    _save_icloud_account(source)
    db.import_accounts("parent@mail.com----secret", kind="mail_com")
    db.set_setting("mail_com_alias_domain", "dr.com")

    deleted = []

    class FakeMailComProvider:
        alias_domain = "dr.com"

        def create_mailbox(self):
            return "gcfail000000@dr.com"

        def delete_mailbox(self, address):
            deleted.append(address)

        def close(self):
            pass

    class FakeRelayProvider:
        def set_proxy(self, proxy):
            pass

        def close(self):
            pass

    class BrokenFlow:
        def __init__(self, *_args, **_kwargs):
            self.session = SimpleNamespace(close=lambda: None)
            self.result = SimpleNamespace(to_dict=lambda: {})

        def run_protocol_login(self, provider, email, password=""):
            raise RuntimeError("curl timeout")

    monkeypatch.setattr(
        email_rebind, "create_mail_provider",
        lambda kind, settings, account=None: (
            FakeMailComProvider() if kind == "mail_com" else FakeRelayProvider()
        ),
    )
    monkeypatch.setattr(email_rebind, "AuthFlow", BrokenFlow)

    with pytest.raises(email_rebind.EmailRebindError):
        email_rebind.rebind_registered_email(source, proxy="", target_kind="mail_com")
    assert deleted == ["gcfail000000@dr.com"]
    assert db.get_registered(source) is not None


@pytest.mark.parametrize("failure_stage", [None, "mailbox.prepare", "eligibility", "begin", "otp.read", "verify"])
def test_rebind_pipeline_fixture_updates_local_key_and_records_all_phases(
    isolated_db, monkeypatch, failure_stage
):
    source = "source@icloud.com"
    target = "generated@example.com"
    _save_registered(source, access_token="old-access", session_token="old-session")
    _save_icloud_account(source)
    db.set_setting("cf_domain", "example.com")

    class FakeResponse:
        def __init__(self, payload):
            self.ok = True
            self.status_code = 200
            self._payload = payload

        def json(self):
            return self._payload

    class FakeSession:
        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append(("GET", url, kwargs))
            if url.endswith("/eligibility"):
                return FakeResponse({"eligible": failure_stage != "eligibility"})
            return FakeResponse({"ok": True})

        def post(self, url, **kwargs):
            self.calls.append(("POST", url, kwargs))
            return FakeResponse({"success": not url.endswith("/" + str(failure_stage))})

        def close(self):
            pass

    class FakeProvider:
        def __init__(self, mailbox=""):
            self.mailbox = mailbox
            self.closed = False

        def create_mailbox(self):
            return "generated@wrong.example" if failure_stage == "mailbox.prepare" else target

        def wait_for_otp(self, email, *, timeout, issued_after):
            assert email == target
            assert timeout == 240
            assert issued_after > 0
            return "invalid" if failure_stage == "otp.read" else "654321"

        def close(self):
            self.closed = True

    class FakeFlow:
        def __init__(self, *_args, **_kwargs):
            self.session = FakeSession()
            self._client_auth_session_id = "session-fixture"
            self._ua = "fixture-ua"
            self.result = SimpleNamespace(
                access_token="fixture-access",
                device_id="fixture-device",
                cookie_header="fixture-cookie",
                to_dict=lambda: {
                    "access_token": "fixture-access",
                    "device_id": "fixture-device",
                    "cookie_header": "fixture-cookie",
                },
            )

        def run_protocol_login(self, provider, email, password=""):
            assert email in (source, target)
            assert password == "password-1"
            return self.result

        def get_auth_session(self):
            return "fixture-session", "fixture-access"

    providers = []

    def fake_create_provider(kind, settings, account=None):
        provider = FakeProvider()
        providers.append((kind, provider))
        return provider

    monkeypatch.setattr(email_rebind, "create_mail_provider", fake_create_provider)
    monkeypatch.setattr(email_rebind, "AuthFlow", FakeFlow)
    monkeypatch.setattr(email_rebind, "_account_id", lambda _token: "account-fixture")
    monkeypatch.setattr(email_rebind, "_session_id", lambda _flow, _token: "session-fixture")
    monkeypatch.setattr(probes, "_OPERATION_HISTORY", [])

    if failure_stage:
        with pytest.raises(email_rebind.EmailRebindError):
            email_rebind.rebind_registered_email(source, proxy="", otp_timeout=240)
        assert db.get_registered(source)["access_token"] == "old-access"
        assert db.get_registered(target) is None
        events = probes.list_operation_probes(operation=f"email_rebind.{failure_stage}")
        assert [event["status"] for event in events] == ["started", "failed"]
        assert all(provider.closed for _kind, provider in providers)
        return

    result = email_rebind.rebind_registered_email(source, proxy="", otp_timeout=240)

    assert result == {
        "source_email": source,
        "target_email": target,
        "status": "changed",
    }
    assert db.get_registered(source) is None
    moved = db.get_registered(target)
    assert moved["access_token"] == "fixture-access"
    assert moved["extra"]["email_rebind"]["source_email"] == source
    assert [kind for kind, _provider in providers] == ["cf_temp", "icloud_relay"]
    assert all(provider.closed for _kind, provider in providers)

    operations = probes.list_operation_probes(limit=100)
    operation_names = {item["operation"] for item in operations}
    assert {
        "email_rebind.validate",
        "email_rebind.mailbox.prepare",
        "email_rebind.protocol.login",
        "email_rebind.eligibility",
        "email_rebind.mfa",
        "email_rebind.begin",
        "email_rebind.otp.read",
        "email_rebind.verify",
        "email_rebind.database.update",
    }.issubset(operation_names)
    assert all(item["status"] in {"started", "ok"} for item in operations)


