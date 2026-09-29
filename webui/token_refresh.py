"""重登已注册账号，刷新 access / session token。

用途：注册结果页的「重新获取 AT」。AT 过期或已失效（401 token_invalid）时，
用本地保存的密码 + 2FA secret 走一次协议登录，把新凭证写回 registered：
  · 不重设密码、不重新绑 2FA、不动 created_at；
  · 只更新 token 列与 extra_json 里的 token_refresh 元数据；
  · 复用 email_rebind 的登录流程构造（同一套指纹/代理/OTP 口径）。
"""
from __future__ import annotations

import logging
import time

from mail_providers import MailProviderError, create_mail_provider

from . import db
from .email_rebind import _build_login_flow
from .probes import record_operation_probe

logger = logging.getLogger("webui.token_refresh")


def _family_country() -> tuple[str, str]:
    family = (db.get_setting("fingerprint_browser_family", "auto") or "auto").strip().lower()
    if family not in {"auto", "chrome", "firefox", "safari"}:
        family = "auto"
    country = (db.get_setting("fingerprint_country", "") or "").strip().upper()
    return country, family


def refresh_one(email: str, *, proxy: str = "", otp_timeout: int = 180) -> dict:
    """对单个已注册邮箱执行一次协议重登，成功则就地刷新凭证。"""
    email = (email or "").strip().lower()
    cred = db.get_registered(email)
    if not cred:
        return {"email": email, "ok": False, "error": "本地没有该号的注册记录"}
    password = (cred.get("password") or "").strip()
    if not password:
        return {"email": email, "ok": False, "error": "缺少密码，无法重登"}

    account = db.get_account(email) or {}
    kind = (account.get("kind") or "").strip().lower()
    if not kind:
        kind = "icloud_relay" if email.endswith("@icloud.com") else "outlook"
    account = {**account, "email": email, "kind": kind}

    try:
        mail = create_mail_provider(kind, db.get_mail_settings(), account)
    except MailProviderError as exc:
        return {"email": email, "ok": False, "error": f"邮箱来源不可用: {exc}"}

    set_proxy = getattr(mail, "set_proxy", None)
    if callable(set_proxy):
        set_proxy(proxy)

    country, family = _family_country()
    account_callback = lambda _email: {
        "password": password,
        "totp_secret": cred.get("totp_secret") or "",
    }

    started = time.perf_counter()
    flow = None
    try:
        flow = _build_login_flow(proxy, otp_timeout, account_callback, country, family)
        flow.run_protocol_login(mail, email, password=password)
        tokens = flow.result.to_dict() if flow.result else {}
        at = (tokens.get("access_token") or "").strip()
        st = (tokens.get("session_token") or "").strip()
        if not at or not st:
            return {"email": email, "ok": False, "error": "重登完成但没拿到 token"}
        db.update_registered_tokens(
            email,
            tokens,
            extra_meta={
                "token_refresh": {"refreshed_at": time.time(), "at_exp": db.jwt_exp(at)}
            },
        )
        record_operation_probe(
            "registered.token_refresh", "ok", email=email,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        return {
            "email": email, "ok": True,
            "at_len": len(at), "st_len": len(st), "at_exp": db.jwt_exp(at),
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("[token_refresh] 重登失败 email=%s: %s", email, type(exc).__name__)
        record_operation_probe(
            "registered.token_refresh", "failed", email=email,
            error=type(exc).__name__,
        )
        return {
            "email": email, "ok": False,
            "error": f"{type(exc).__name__}: {str(exc)[:160]}",
        }
    finally:
        try:
            if flow is not None:
                flow.session.close()
        except Exception:  # noqa: BLE001
            pass


def refresh_many(
    emails,
    *,
    proxy: str = "",
    otp_timeout: int = 180,
    limit: int = 20,
) -> dict:
    """按顺序重登一批邮箱（顺序执行，避免并发登录触发风控）。"""
    cleaned: list[str] = []
    for raw in emails or []:
        item = (raw or "").strip().lower()
        if item and item not in cleaned:
            cleaned.append(item)
    cleaned = cleaned[: max(1, min(int(limit or 20), 50))]
    results = [refresh_one(e, proxy=proxy, otp_timeout=otp_timeout) for e in cleaned]
    ok = sum(1 for r in results if r.get("ok"))
    return {
        "ok": True,
        "total": len(results),
        "succeeded": ok,
        "failed": len(results) - ok,
        "results": results,
    }
