"""Manual iCloud -> custom-domain email rebinding.

The workflow is deliberately separate from registration. It logs into the
selected existing account, performs the official ChatGPT email-change request
sequence, waits for the replacement mailbox OTP, and only then updates the
local registered-account key.
"""
from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Any, Mapping, Optional
from uuid import uuid4

from auth_flow import AuthFlow
from config import Config
from mail_providers import MailProviderError, create_mail_provider, validate_email

from . import db
from .probes import record_operation_probe, redact_probe_error

logger = logging.getLogger("webui.email_rebind")

CHATGPT_ORIGIN = "https://chatgpt.com"
CHANGE_PATHS = {
    "eligibility": "/backend-api/accounts/change_email/eligibility",
    "mfa_info": "/backend-api/accounts/mfa_info",
    "begin": "/backend-api/accounts/change_email/begin",
    "verify": "/backend-api/accounts/change_email/verify",
}
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)


class EmailRebindError(RuntimeError):
    """A user-facing, credential-free rebinding error."""


def _notify_phase(callback: Any, stage: str, status: str, **details: Any) -> None:
    """Send a redacted stage event to a batch snapshot when one is active."""
    if not callable(callback):
        return
    try:
        callback(stage, status, **details)
    except Exception:  # noqa: BLE001
        logger.debug("批量换绑阶段回调失败 stage=%s", stage, exc_info=True)


@contextmanager
def _phase(callback: Any, stage: str, **details: Any):
    started = time.perf_counter()
    record_operation_probe(f"email_rebind.{stage}", "started", **details)
    _notify_phase(callback, stage, "started", **details)
    try:
        yield
    except Exception as exc:
        elapsed = int((time.perf_counter() - started) * 1000)
        record_operation_probe(
            f"email_rebind.{stage}", "failed", duration_ms=elapsed, error=exc, **details
        )
        _notify_phase(callback, stage, "failed", duration_ms=elapsed, error=str(exc)[:240], **details)
        raise
    else:
        elapsed = int((time.perf_counter() - started) * 1000)
        record_operation_probe(f"email_rebind.{stage}", "ok", duration_ms=elapsed, **details)
        _notify_phase(callback, stage, "ok", duration_ms=elapsed, **details)


def _clean_email(value: str, label: str) -> str:
    value = (value or "").strip().lower()
    if not value:
        raise EmailRebindError(f"{label}不能为空")
    try:
        validate_email(value)
    except ValueError as exc:
        raise EmailRebindError(f"{label}格式无效") from exc
    return value


def _response_payload(response: Any) -> dict:
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        return {}
    return payload if isinstance(payload, dict) else {}


def _response_summary(response: Any) -> dict:
    payload = _response_payload(response)
    summary = {"status": getattr(response, "status_code", None)}
    for key in ("success", "eligible", "status", "code", "error"):
        value = payload.get(key)
        if isinstance(value, (bool, int, float, str)):
            summary[key] = str(value)[:80] if isinstance(value, str) else value
    return summary


def _close_provider(provider: Any) -> None:
    close = getattr(provider, "close", None)
    if callable(close):
        try:
            close()
            return
        except Exception:  # noqa: BLE001
            pass
    session = getattr(provider, "_session", None)
    close_session = getattr(session, "close", None)
    if callable(close_session):
        try:
            close_session()
        except Exception:  # noqa: BLE001
            pass


def _session_id(flow: AuthFlow, access_token: str) -> str:
    sid = str(getattr(flow, "_client_auth_session_id", "") or "").strip()
    if sid:
        return sid
    payload = {}
    try:
        from webui.exporter import _decode_jwt_payload

        payload = _decode_jwt_payload(access_token)
    except Exception:  # noqa: BLE001
        payload = {}
    sid = str(payload.get("session_id") or payload.get("sid") or "").strip()
    if sid:
        return sid
    dump = getattr(flow, "_client_auth_session_dump", {})
    if isinstance(dump, Mapping):
        client_dump = dump.get("client_auth_session")
        if isinstance(client_dump, Mapping):
            sid = str(client_dump.get("session_id") or "").strip()
            if sid:
                return sid
    return ""


def _account_id(access_token: str) -> str:
    try:
        from webui.exporter import _decode_jwt_payload, _get_auth

        auth = _get_auth(_decode_jwt_payload(access_token))
    except Exception:  # noqa: BLE001
        auth = {}
    return str(auth.get("chatgpt_account_id") or auth.get("account_id") or "").strip()


def _request(flow: AuthFlow, method: str, path: str, headers: dict, body: Optional[dict] = None):
    url = f"{CHATGPT_ORIGIN}{path}"
    try:
        if method == "GET":
            return flow.session.get(url, headers=headers, timeout=30)
        return flow.session.post(url, headers=headers, json=body or {}, timeout=30)
    except Exception as exc:  # noqa: BLE001
        raise EmailRebindError(f"换绑请求失败（{type(exc).__name__}）") from exc


def _build_headers(flow: AuthFlow, result: Any, path: str) -> dict[str, str]:
    access_token = str(getattr(result, "access_token", "") or "").strip()
    account_id = _account_id(access_token)
    session_id = _session_id(flow, access_token)
    device_id = str(getattr(result, "device_id", "") or "").strip()
    if not account_id:
        raise EmailRebindError("登录会话缺少账号标识，无法发起换绑")
    if not session_id:
        raise EmailRebindError("登录会话缺少 session 标识，请重新登录后重试")
    if not device_id:
        raise EmailRebindError("登录会话缺少设备标识，请重新登录后重试")

    headers = {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "OAI-Device-Id": device_id,
        "OAI-Session-Id": session_id,
        "ChatGPT-Account-Id": account_id,
        "Origin": CHATGPT_ORIGIN,
        "Referer": f"{CHATGPT_ORIGIN}/",
        "X-OpenAI-Target-Path": path,
        "X-OpenAI-Target-Route": path,
        "User-Agent": str(getattr(flow, "_ua", "") or DEFAULT_USER_AGENT),
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    cookie_header = str(getattr(result, "cookie_header", "") or "").strip()
    if cookie_header:
        headers["Cookie"] = cookie_header
    return headers


def _require_ok(response: Any, label: str) -> dict:
    summary = _response_summary(response)
    if not getattr(response, "ok", False):
        raise EmailRebindError(
            f"{label}失败（HTTP {summary.get('status') or 'unknown'}）"
        )
    return _response_payload(response)


def _change_email(
    flow: AuthFlow,
    target_email: str,
    target_mail: Any,
    otp_timeout: int,
    phase_callback: Any = None,
) -> None:
    path = CHANGE_PATHS["eligibility"]
    with _phase(phase_callback, "eligibility"):
        eligibility_response = _request(flow, "GET", path, _build_headers(flow, flow.result, path))
        eligibility = _require_ok(eligibility_response, "换绑资格检查")
        if eligibility.get("eligible") is not True:
            raise EmailRebindError("当前账号不满足邮箱换绑条件")

    path = CHANGE_PATHS["mfa_info"]
    with _phase(phase_callback, "mfa"):
        mfa_response = _request(flow, "GET", path, _build_headers(flow, flow.result, path))
        _require_ok(mfa_response, "MFA 状态检查")

    begin_started_at = time.time()
    path = CHANGE_PATHS["begin"]
    with _phase(phase_callback, "begin", target_email=target_email):
        begin_response = _request(
            flow, "POST", path, _build_headers(flow, flow.result, path), {"email": target_email}
        )
        begin = _require_ok(begin_response, "发起邮箱换绑")
        if begin.get("success") is not True:
            raise EmailRebindError("服务端拒绝发起邮箱换绑")

    with _phase(phase_callback, "otp.read", target_email=target_email):
        try:
            code = target_mail.wait_for_otp(
                target_email,
                timeout=otp_timeout,
                issued_after=begin_started_at,
            )
        except Exception as exc:  # noqa: BLE001
            raise EmailRebindError("目标域名邮箱验证码读取超时或失败") from exc
        if not code or len(str(code).strip()) != 6 or not str(code).strip().isdigit():
            raise EmailRebindError("目标邮箱验证码格式无效")

    path = CHANGE_PATHS["verify"]
    with _phase(phase_callback, "verify", target_email=target_email):
        verify_response = _request(
            flow,
            "POST",
            path,
            _build_headers(flow, flow.result, path),
            {"email": target_email, "code": str(code).strip()},
        )
        verify = _require_ok(verify_response, "确认邮箱换绑")
        if verify.get("success") is not True:
            raise EmailRebindError("服务端未确认邮箱换绑成功")


def _prepare_mail_com_target(settings: Mapping[str, Any]) -> tuple[Any, str]:
    """从号池挑一个 mail.com 母号，现场创建 dr 别名作为换绑目标。

    一个母号最多 10 个别名，创建成功后母号放回 available 继续供后续任务用；
    别名已满 / 凭证失效的母号标记 failed，自动换下一个。
    """
    for _ in range(50):
        parent = db.claim_next("mail_com")
        if not parent:
            raise EmailRebindError("mail.com 母号池耗尽：请导入更多母号或重置已满的母号")
        provider = create_mail_provider("mail_com", settings, parent)
        try:
            alias = provider.create_mailbox()
        except MailProviderError as exc:
            _close_provider(provider)
            if exc.fatal:
                db.mark_failed(parent["email"], f"[mail_com_alias] {exc}")
            else:
                db.release_unused(parent["email"])
            continue
        except Exception as exc:  # noqa: BLE001
            _close_provider(provider)
            db.release_unused(parent["email"])
            raise EmailRebindError(
                f"mail.com 别名创建异常（{type(exc).__name__}）"
            ) from exc

        alias = _clean_email(alias, "自动生成的 mail.com 别名")
        if alias.rsplit("@", 1)[1] != str(provider.alias_domain):
            _close_provider(provider)
            db.mark_failed(parent["email"], "[mail_com_alias] 别名域名不符")
            continue
        if db.email_in_use(alias):
            _close_provider(provider)
            db.release_unused(parent["email"])
            continue
        # 别名创建成功：母号放回池子（还能挂更多别名），凭据保留在 provider 里取 OTP
        db.release_unused(parent["email"])
        return provider, alias
    raise EmailRebindError("mail.com 母号池耗尽或全部不可用")


def _build_login_flow(
    proxy: str,
    otp_timeout: int,
    account_callback: Any,
    country: str,
    family: str,
) -> AuthFlow:
    """按换绑需要构造 AuthFlow（登录已有账号，不抢发码、不换 refresh）。"""
    return AuthFlow(
        Config(proxy=proxy or None),
        env_overrides={
            "WEBUI_ALLOW_LOGIN": "1",
            "OTP_TIMEOUT": str(otp_timeout),
            "OAUTH_CODEX_RT_BEFORE_CALLBACK": "0",
            "OAUTH_CODEX_RT_EXCHANGE": "0",
            "OAUTH_SECONDARY_AUTHORIZE_EXCHANGE": "0",
        },
        account_callback=account_callback,
        fingerprint_country=country,
        fingerprint_browser_family=family,
    )


def rebind_registered_email(
    source_email: str,
    target_email: str = "",
    *,
    proxy: str = "",
    otp_timeout: int = 180,
    phase_callback: Any = None,
    target_kind: str = "cf_temp",
) -> dict:
    """Run one explicit iCloud-to-domain rebinding task."""
    source_email = _clean_email(source_email, "源邮箱")
    target_email = (target_email or "").strip().lower()
    proxy = (proxy or "").strip()
    otp_timeout = max(60, min(int(otp_timeout or 180), 600))
    target_kind = (target_kind or "cf_temp").strip().lower()
    if target_kind not in {"cf_temp", "mail_com"}:
        raise EmailRebindError(f"不支持的目标邮箱来源: {target_kind}")

    with _phase(phase_callback, "validate", source_email=source_email):
        cred = db.get_registered(source_email)
        if not cred:
            raise EmailRebindError("未找到源账号的注册凭证")
        account = db.get_account(source_email)
        if not account or account.get("kind") != "icloud_relay":
            raise EmailRebindError("该账号不是已导入的 iCloud 中转邮箱")
        if not (cred.get("password") or "").strip():
            raise EmailRebindError("源账号缺少密码，无法执行手动换绑")

        settings = db.get_mail_settings()
        if target_kind == "cf_temp":
            domain = (settings.get("cf_domain") or "").strip().lstrip("@").lower()
            if not domain:
                raise EmailRebindError("请先在邮箱配置中设置目标域名")
        else:
            domain = (settings.get("mail_com_alias_domain") or "dr.com").strip().lstrip("@").lower()
            if not domain:
                raise EmailRebindError("请先在邮箱配置中设置 mail.com 别名域名")

    target_mail = None
    source_mail = None
    flow = None
    change_submitted = False
    rebind_done = False
    if target_email:
        target_email = _clean_email(target_email, "目标邮箱")
        if target_email.rsplit("@", 1)[1] != domain:
            raise EmailRebindError(f"目标邮箱必须使用已配置域名 @{domain}")
        if target_kind == "mail_com":
            raise EmailRebindError("mail.com 别名目标邮箱请留空，由系统自动生成")
    if target_email and target_email == source_email:
        raise EmailRebindError("源邮箱和目标邮箱不能相同")
    if target_email and db.email_in_use(target_email, exclude=source_email):
        raise EmailRebindError("目标邮箱已存在于本地账号或邮箱池")

    try:
        with _phase(phase_callback, "mailbox.prepare", target_email=target_email, domain=domain):
            if target_kind == "mail_com":
                target_mail, target_email = _prepare_mail_com_target(settings)
            else:
                target_mail = create_mail_provider("cf_temp", settings)
                if not target_email:
                    target_email = _clean_email(target_mail.create_mailbox(), "自动生成的目标邮箱")
                if target_email.rsplit("@", 1)[1] != domain:
                    raise EmailRebindError(f"目标邮箱必须使用已配置域名 @{domain}")
                if target_email == source_email:
                    raise EmailRebindError("源邮箱和目标邮箱不能相同")
                if db.email_in_use(target_email, exclude=source_email):
                    raise EmailRebindError("自动生成的目标邮箱已存在，请重试")

        source_mail = create_mail_provider("icloud_relay", settings, account)
        set_proxy = getattr(source_mail, "set_proxy", None)
        if callable(set_proxy):
            set_proxy(proxy)
        family = (db.get_setting("fingerprint_browser_family", "auto") or "auto").strip().lower()
        country = (db.get_setting("fingerprint_country", "") or "").strip().upper()
        if family not in {"auto", "chrome", "firefox", "safari"}:
            family = "auto"
        account_callback = lambda _email: {
            "password": cred.get("password") or "",
            "totp_secret": cred.get("totp_secret") or "",
        }
        flow = _build_login_flow(proxy, otp_timeout, account_callback, country, family)
        logger.info("[email_rebind] 开始手动换绑 source=%s target=%s", source_email, target_email)
        with _phase(phase_callback, "protocol.login", source_email=source_email):
            flow.run_protocol_login(
                source_mail,
                source_email,
                password=(cred.get("password") or "").strip(),
            )

        # 记录 OpenAI 到底有没有见过这个目标地址：begin 之前的失败（登录/网络）
        # 目标别名还没被提交过，可以直接删掉回收名额；begin 之后必须留着。
        def _tracking_phase(stage: str, status: str, **details: Any) -> None:
            nonlocal change_submitted
            if stage == "begin" and status == "started":
                change_submitted = True
            if callable(phase_callback):
                phase_callback(stage, status, **details)

        _change_email(flow, target_email, target_mail, otp_timeout, _tracking_phase)

        # 换邮箱会把旧 session 的 token 全部作废（实测换绑后 check/v4 直接
        # token_invalid）。用新邮箱 + 原密码 + 原 TOTP 重新登录拿一套有效凭证。
        # 重登失败不整体回滚：邮箱已经换成功了，只是凭证要稍后手动补。
        credential_updates = flow.result.to_dict()
        relogin_ok = False
        relogin_started = time.perf_counter()
        _notify_phase(
            phase_callback, "relogin", "started",
            source_email=source_email, target_email=target_email,
        )
        record_operation_probe(
            "email_rebind.relogin", "started",
            source_email=source_email, target_email=target_email,
        )
        try:
            relogin_flow = _build_login_flow(proxy, otp_timeout, account_callback, country, family)
            try:
                for attempt in range(3):
                    try:
                        relogin_flow.run_protocol_login(
                            target_mail,
                            target_email,
                            password=(cred.get("password") or "").strip(),
                        )
                        break
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "[email_rebind] 换绑后重登失败 attempt=%s: %s",
                            attempt + 1, type(exc).__name__,
                        )
                        if attempt == 2:
                            raise
                        time.sleep(3 * (attempt + 1))
                credential_updates = relogin_flow.result.to_dict()
                relogin_ok = True
            finally:
                try:
                    relogin_flow.session.close()
                except Exception:  # noqa: BLE001
                    pass
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[email_rebind] 换绑后重登未成功，保留登录会话旧凭证: %s",
                type(exc).__name__,
            )
        relogin_elapsed = int((time.perf_counter() - relogin_started) * 1000)
        if relogin_ok:
            record_operation_probe(
                "email_rebind.relogin", "ok", duration_ms=relogin_elapsed,
                source_email=source_email, target_email=target_email,
            )
            _notify_phase(
                phase_callback, "relogin", "ok", duration_ms=relogin_elapsed,
                source_email=source_email, target_email=target_email,
            )
        else:
            record_operation_probe(
                "email_rebind.relogin", "failed", duration_ms=relogin_elapsed,
                error="relogin_failed", source_email=source_email, target_email=target_email,
            )
            _notify_phase(
                phase_callback, "relogin", "failed", duration_ms=relogin_elapsed,
                error="换绑后重登失败", source_email=source_email, target_email=target_email,
            )

        with _phase(phase_callback, "database.update", source_email=source_email, target_email=target_email):
            db.complete_email_rebind(
                source_email,
                target_email,
                credential_updates=credential_updates,
                metadata={
                    "source_email": source_email,
                    "target_email": target_email,
                    "source_kind": "icloud_relay",
                    "target_kind": target_kind,
                    "relogin_ok": relogin_ok,
                    "completed_at": time.time(),
                },
            )
        logger.info("[email_rebind] 换绑完成 source=%s target=%s", source_email, target_email)
        rebind_done = True
        return {"source_email": source_email, "target_email": target_email, "status": "changed"}
    except EmailRebindError:
        raise
    except MailProviderError as exc:
        raise EmailRebindError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("[email_rebind] 未预期失败 source=%s", source_email)
        raise EmailRebindError(f"换绑失败（{type(exc).__name__}）") from exc
    finally:
        if (
            target_kind == "mail_com"
            and target_email
            and target_mail is not None
            and not change_submitted
            and not rebind_done
        ):
            delete_mailbox = getattr(target_mail, "delete_mailbox", None)
            if callable(delete_mailbox):
                try:
                    delete_mailbox(target_email)
                    logger.info(
                        "[email_rebind] 换绑未提交（%s），已回收别名 %s",
                        source_email, target_email,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "[email_rebind] 别名回收失败 %s: %s",
                        target_email, type(exc).__name__,
                    )
        if flow is not None:
            try:
                flow.session.close()
            except Exception:  # noqa: BLE001
                pass
        if target_mail is not None:
            _close_provider(target_mail)
        if source_mail is not None:
            _close_provider(source_mail)


__all__ = [
    "EmailRebindError",
    "rebind_registered_email",
]