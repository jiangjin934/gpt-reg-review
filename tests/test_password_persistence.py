"""Keep failed-worker password persistence truthful and separate from success."""
import logging
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from mail_providers import MailProviderError
from webui import db, registrar


EMAIL = "password-fixture@icloud.com"
PASSWORD = "fixture-sensitive-password"


def _run_failed_worker(tmp_path, monkeypatch):
    run_id = "password-persistence-fixture"
    log_path = tmp_path / "worker.log"
    db.set_setting("mail_source", "icloud_relay")
    db.import_accounts(
        f"{EMAIL}----https://relay.example/messages/TOKEN/{EMAIL}",
        kind="icloud_relay",
    )
    account = db.claim_account(EMAIL)
    db.create_run(run_id, EMAIL, str(log_path))

    class FlowFixture:
        def __init__(self, _config, **kwargs):
            self.result = SimpleNamespace(email=EMAIL, password=PASSWORD)
            self.on_password = kwargs["on_password"]

        def run_register(self, _mail):
            self.on_password(EMAIL, PASSWORD)
            raise MailProviderError("fixture mail failure", fatal=True, kind="icloud_relay")

    mail = SimpleNamespace(display_name="Fixture mailbox")
    monkeypatch.setattr(registrar, "AuthFlow", FlowFixture)
    monkeypatch.setattr(registrar, "create_mail_provider", lambda *args: mail)
    save_registered = Mock(wraps=db.save_registered)
    mark_done = Mock(wraps=db.mark_done)
    monkeypatch.setattr(db, "save_registered", save_registered)
    monkeypatch.setattr(db, "mark_done", mark_done)

    registrar._do_register(run_id, account, {
        "engine": "protocol", "want_refresh_token": False, "want_2fa": False,
    }, log_path)

    save_registered.assert_not_called()
    mark_done.assert_not_called()
    assert db.get_account(EMAIL)["status"] == "failed"
    run = next(row for row in db.list_runs() if row["run_id"] == run_id)
    assert run["status"] == "failed"
    assert run["error_category"] == "account"
    return log_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("failed_writes", [0, 1, 2])
def test_failed_worker_preserves_password_or_reports_persistence_failure(
    tmp_path, monkeypatch, caplog, failed_writes,
):
    caplog.set_level(logging.INFO, logger="registrar")
    original_save = db.save_password_early
    attempts = []

    def save(email, password):
        attempts.append(email)
        if len(attempts) <= failed_writes:
            # Include an unlabeled password as well as a labeled token: neither
            # should reach logs, even when the storage exception contains both.
            raise sqlite3.OperationalError(
                f"fixture write failed {password} token=fixture-storage-token"
            )
        original_save(email, password)

    monkeypatch.setattr(db, "save_password_early", save)
    log_text = _run_failed_worker(tmp_path, monkeypatch)
    assert len(attempts) == (1 if failed_writes == 0 else 2)
    assert PASSWORD not in log_text + caplog.text
    assert "fixture-storage-token" not in log_text + caplog.text
    saved = db.get_registered(EMAIL)
    if failed_writes < 2:
        assert saved["password"] == PASSWORD
        assert saved["extra"]["pending"] is True
        assert not saved["access_token"]
        assert not saved["session_token"]
        assert not saved["refresh_token"]
        assert "请查看已保存凭证" in log_text
    else:
        assert saved is None
        assert "密码持久化失败，尚未确认保存；本轮仍为失败" in log_text
        assert "请查看已保存凭证" not in log_text + caplog.text
        assert "密码已落盘" not in log_text + caplog.text


def test_password_recovery_preserves_existing_tokens(tmp_path, monkeypatch):
    db.save_registered({
        "email": EMAIL,
        "password": "fixture-previous-password",
        "access_token": "fixture-existing-access",
        "session_token": "fixture-existing-session",
        "refresh_token": "fixture-existing-refresh",
    })
    original_save = db.save_password_early
    attempts = 0

    def save(email, password):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("fixture temporary write failure")
        original_save(email, password)

    monkeypatch.setattr(db, "save_password_early", save)
    _run_failed_worker(tmp_path, monkeypatch)
    saved = db.get_registered(EMAIL)
    assert saved["password"] == PASSWORD
    assert saved["access_token"] == "fixture-existing-access"
    assert saved["session_token"] == "fixture-existing-session"
    assert saved["refresh_token"] == "fixture-existing-refresh"


@pytest.mark.parametrize("email, password", [("", PASSWORD), (EMAIL, " ")])
def test_empty_password_save_returns_false_without_db_write(monkeypatch, email, password):
    save = Mock()
    monkeypatch.setattr(db, "save_password_early", save)
    assert registrar._save_password_early(email, password) is False
    save.assert_not_called()


def test_password_save_requires_matching_readback(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="registrar")
    # A backend that silently does nothing must not produce a saved claim.
    monkeypatch.setattr(db, "save_password_early", Mock())
    assert registrar._save_password_early(EMAIL, PASSWORD) is False
    assert "密码已落盘" not in caplog.text
    assert PASSWORD not in caplog.text


def test_password_save_confirms_persisted_value():
    assert registrar._save_password_early(f" {EMAIL.upper()} ", PASSWORD) is True
    assert db.get_registered(EMAIL)["password"] == PASSWORD
