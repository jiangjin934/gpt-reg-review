"""注册结果完整性闸门：缺密码 / 2FA / AT 的半成品不许进结果。

主人 2026-09-29 口径：凭证三件套（密码 + 2FA secret + access_token）缺任何
一样都是废物号。但半成品行**必须留在库里** —— password / totp_secret 是
一次性下发的，行一删，重跑「已有账号」分支就拿不到密码续跑了。所以这个
闸门只作用于展示/导出层，get_registered（恢复路径）必须照常可见。
"""
from __future__ import annotations

from webui import db


def _seed_complete(email: str = "full@example.com") -> None:
    db.save_registered({
        "email": email, "password": "p", "totp_secret": "ABCDEFGH",
        "access_token": "at", "session_token": "st",
    })


def _seed_incomplete(email: str = "half@example.com", missing: str = "at") -> None:
    payload = {"email": email, "password": "p", "totp_secret": "ABCDEFGH"}
    if missing != "at":
        payload["access_token"] = "at"
    if missing == "password":
        payload.pop("password")
    if missing == "totp":
        payload.pop("totp_secret")
    db.save_registered(payload)


def test_complete_row_appears_in_list_and_count():
    _seed_complete()

    rows = db.list_registered(limit=10)
    assert any(r["email"] == "full@example.com" for r in rows)
    assert db.count_registered("all") >= 1


def test_incomplete_row_hidden_from_list_and_count():
    _seed_incomplete()

    rows = db.list_registered(limit=50)
    assert all(r["email"] != "half@example.com" for r in rows)
    # 计数也不能把它算进去
    before = db.count_registered("all")
    assert before == sum(
        1 for r in rows if r["email"] != "half@example.com"
    )


def test_missing_password_row_hidden():
    _seed_incomplete("nopass@example.com", missing="password")

    assert all(r["email"] != "nopass@example.com" for r in db.list_registered(limit=50))


def test_missing_totp_row_hidden():
    _seed_incomplete("nototp@example.com", missing="totp")

    assert all(r["email"] != "nototp@example.com" for r in db.list_registered(limit=50))


def test_export_functions_exclude_incomplete():
    _seed_complete("exp-full@example.com")
    _seed_incomplete("exp-half@example.com")

    full = db.list_registered_full()
    by_email = db.list_registered_by_emails(["exp-full@example.com", "exp-half@example.com"])

    assert any(r["email"] == "exp-full@example.com" for r in full)
    assert all(r["email"] != "exp-half@example.com" for r in full)
    assert [r["email"] for r in by_email] == ["exp-full@example.com"]


def test_get_registered_still_returns_incomplete_for_recovery():
    """恢复路径必须可见：重跑「已有账号」分支靠它读密码。"""
    _seed_incomplete("recover@example.com")

    row = db.get_registered("recover@example.com")

    assert row is not None
    assert row.get("password") == "p"


def test_checkout_summary_ignores_incomplete():
    _seed_incomplete("sum-half@example.com")

    summary = db.checkout_summary()

    assert summary["total"] == 0
