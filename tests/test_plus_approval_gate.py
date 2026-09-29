"""Plus 开通必须经主人授权：命中试用只排队，授权后才提交「提炼 + 支付」。"""
from webui import db, plus_activate


def _fake_submit_factory(sink):
    def fake_submit(access_token, *, email="", **kwargs):
        sink.append((email, access_token))
        return {
            "taskId": f"task-{len(sink)}",
            "status": "RUNNING",
            "plusVerificationStatus": "",
            "progressPercent": 0,
        }

    return fake_submit


def test_eligible_account_queues_without_any_submission(monkeypatch):
    submitted = []
    monkeypatch.setattr(plus_activate, "submit_one", _fake_submit_factory(submitted))
    db.set_setting("plus_auto_submit", "1")
    db.set_setting("plus_require_approval", "1")

    result = plus_activate.auto_submit_if_eligible("pending@example.com", "tok-abc")

    assert result == {"ok": True, "pending": True}
    assert submitted == []
    row = db.get_plus_activation("pending@example.com")
    assert row["status"] == "pending_approval"
    assert not row["task_id"]
    assert int(row["activated"] or 0) == 0


def test_duplicate_queue_keeps_first_pending_row(monkeypatch):
    submitted = []
    monkeypatch.setattr(plus_activate, "submit_one", _fake_submit_factory(submitted))
    db.set_setting("plus_require_approval", "1")

    first = plus_activate.auto_submit_if_eligible("dup@example.com", "tok-1")
    second = plus_activate.auto_submit_if_eligible("dup@example.com", "tok-2")

    assert first["pending"] is True
    assert second is None
    assert submitted == []
    assert len(db.list_plus_pending_approval()) == 1


def test_approve_submits_only_after_authorization(monkeypatch):
    submitted = []
    monkeypatch.setattr(plus_activate, "submit_one", _fake_submit_factory(submitted))
    db.set_setting("plus_require_approval", "1")
    db.save_registered({
        "email": "approved@example.com",
        "access_token": "tok-approved",
        "password": "x",
    })
    plus_activate.queue_for_approval("approved@example.com")

    assert submitted == []
    result = plus_activate.approve_many(["approved@example.com"])

    assert result["succeeded"] == 1
    assert submitted == [("approved@example.com", "tok-approved")]
    row = db.get_plus_activation("approved@example.com")
    assert row["task_id"] == "task-1"
    assert db.count_plus_pending_approval() == 0


def test_approve_skips_missing_token(monkeypatch):
    submitted = []
    monkeypatch.setattr(plus_activate, "submit_one", _fake_submit_factory(submitted))
    plus_activate.queue_for_approval("notoken@example.com")

    result = plus_activate.approve_many(["notoken@example.com"])

    assert result["succeeded"] == 0
    assert submitted == []
    assert db.get_plus_activation("notoken@example.com")["status"] == "pending_approval"


def test_reject_marks_without_submitting(monkeypatch):
    submitted = []
    monkeypatch.setattr(plus_activate, "submit_one", _fake_submit_factory(submitted))
    plus_activate.queue_for_approval("rejected@example.com")

    result = plus_activate.reject_many(["rejected@example.com"])

    assert result == {"ok": True, "rejected": 1}
    assert submitted == []
    assert db.get_plus_activation("rejected@example.com")["status"] == "rejected"
    assert db.count_plus_pending_approval() == 0


def test_full_auto_still_available_when_approval_disabled(monkeypatch):
    """主人关掉授权闸门后，回到命中即提交的旧行为。"""
    submitted = []
    monkeypatch.setattr(plus_activate, "submit_one", _fake_submit_factory(submitted))
    db.set_setting("plus_auto_submit", "1")
    db.set_setting("plus_require_approval", "0")

    result = plus_activate.auto_submit_if_eligible("auto@example.com", "tok-auto")

    assert result["ok"] is True
    assert submitted == [("auto@example.com", "tok-auto")]
    assert db.get_plus_activation("auto@example.com")["status"] == "RUNNING"
