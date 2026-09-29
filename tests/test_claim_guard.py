"""防重复烧号：历史已注册成功但本地无密码的邮箱不允许再被 claim。"""
from webui import db


def test_claim_skips_historically_registered_without_password():
    db.import_accounts("used@example.com----https://relay/x", kind="icloud_relay")
    db.import_accounts("fresh@example.com----https://relay/y", kind="icloud_relay")
    db.create_run("run-used", "used@example.com", "used.log")
    db.finish_run("run-used", "done")

    claimed = db.claim_next(kind="icloud_relay")

    assert claimed is not None
    assert claimed["email"] == "fresh@example.com"
    used = db.get_account("used@example.com")
    assert used["status"] == "failed"
    assert "无密码" in (used["fail_reason"] or "")


def test_claim_allows_rerun_when_password_is_still_saved():
    db.import_accounts("known@example.com----https://relay/x", kind="icloud_relay")
    db.create_run("run-known", "known@example.com", "known.log")
    db.finish_run("run-known", "done")
    db.save_registered({"email": "known@example.com", "password": "pw-1"})

    claimed = db.claim_next(kind="icloud_relay")

    assert claimed is not None
    assert claimed["email"] == "known@example.com"
