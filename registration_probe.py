"""邮箱注册状态判定（纯协议，只读判定点）。

回答的是「这个邮箱在 OpenAI 是新号还是老号」——典型场景是换机器后丢了本地库，
想反查一批邮箱的注册情况。

判定点选在注册链路的第 5 步 ``authorize/continue(screen_hint="signup")``：
服务端在那一步返回的页面类型直接说明它是新号还是老号。之后再执行的
register_password / email-otp/send / create_account 才是真正改动账号状态
（设密码、发码、建号）的动作，本函数一律不碰。

⚠️ 已知边界：signup 那一步服务端**可能**顺手发一封验证码（代码里有「signup
   阶段自动发的那封 OTP 立即失效」的记录）。所以这不是绝对零邮件；
   它不改账号状态，但收件箱里会多一封 OTP。
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

from config import Config

logger = logging.getLogger("registration_probe")

STATUS_UNREGISTERED = "unregistered"
STATUS_REGISTERED = "registered"
STATUS_UNKNOWN = "unknown"

_PAGE_CREATE_PASSWORD = "create_account_password"
_PAGE_OTP_VERIFY = "email_otp_verification"
_PAGE_LOGIN_PASSWORD = "login_password"
_PAGE_MFA_CHALLENGE = "mfa_challenge"
_MODE_PASSWORDLESS_SIGNUP = "passwordless_signup"

# 服务端要密码或要 TOTP：只可能是已经存在的账号。
_REGISTERED_PAGES = {_PAGE_LOGIN_PASSWORD, _PAGE_MFA_CHALLENGE}


def _result(email: str, status: str, **extra: Any) -> dict[str, Any]:
    out = {
        "email": email,
        "status": status,
        "checked_at": time.time(),
    }
    out.update(extra)
    return out


def _close(flow: Any) -> None:
    session = getattr(flow, "session", None)
    if session is None:
        return
    try:
        session.close()
    except Exception:  # noqa: BLE001
        pass


def probe_registration(
    email: str,
    *,
    proxy: str = "",
    fingerprint: Optional[dict] = None,
    country: str = "IN",
    use_sentinel: bool = True,
) -> dict[str, Any]:
    """判定一个邮箱在 OpenAI 的注册状态。

    use_sentinel=False 会跳过 sentinel PoW。实测这不影响判定：不带 token
    提交 authorize/continue 依然返回 200 + page_type（判定只要页面类型，
    不需要能收到 OTP）。而 sentinel 要 spawn node 跑真 sdk.js，占单号耗时
    约三分之一，批量反查时关掉更划算。

    返回 {email, status, page_type, verification_mode, reason, elapsed_ms}，
    status 取 unregistered / registered / unknown。失败一律归 unknown 并带
    error —— 「没探成」和「判定为老号」是两件事，不能混。
    """
    addr = (email or "").strip().lower()
    if not addr:
        return _result("", STATUS_UNKNOWN, error="邮箱为空")

    flow = None
    started = time.perf_counter()
    try:
        from auth_flow import AuthFlow

        flow = AuthFlow(
            Config(proxy=proxy),
            fingerprint=fingerprint,
            fingerprint_country=(country or "").strip().upper(),
        )

        # 出口可用性：拿不到 oai-did 就没必要继续（后续 authorize/continue 必 409）
        if not flow.check_proxy():
            return _result(
                addr, STATUS_UNKNOWN,
                error=getattr(flow, "_network_preflight_error", "") or "网络预检未通过",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
            )
        if not flow.warmup():
            return _result(
                addr, STATUS_UNKNOWN,
                error="warmup 未拿到 oai-did（出口可能被 CF 拦）",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
            )

        csrf = flow.get_csrf_token()
        if not csrf:
            return _result(addr, STATUS_UNKNOWN, error="未取到 csrf token",
                           elapsed_ms=int((time.perf_counter() - started) * 1000))

        auth_url = flow.get_auth_url(csrf, email=addr)
        if not auth_url:
            return _result(addr, STATUS_UNKNOWN, error="未取到 authorize URL",
                           elapsed_ms=int((time.perf_counter() - started) * 1000))

        device_id = flow.auth_oauth_init(auth_url)

        # sentinel 按需计算：判定只需要服务端回页面类型，不带 token 提交
        # 实测同样返回 200 + page_type。它要 spawn node 跑真 sdk.js，
        # 是单号耗时的大头，批量反查时可以关掉。
        sentinel = ""
        if use_sentinel:
            sentinel = flow.get_sentinel_token(device_id)
            if not sentinel:
                return _result(addr, STATUS_UNKNOWN, error="sentinel token 未取到",
                               elapsed_ms=int((time.perf_counter() - started) * 1000))

        flow.result.email = addr
        # ★ 判定点：这一步之后才进发码/建号，本函数到此为止。
        flow.signup(addr, sentinel)

        page_type = str(getattr(flow, "_existing_page_type", "") or "").strip()
        mode = str(getattr(flow, "_existing_email_verification_mode", "") or "").strip()

        if page_type == _PAGE_CREATE_PASSWORD:
            status, reason = STATUS_UNREGISTERED, "服务端给出创建密码页（标准注册流程）"
        elif page_type in _REGISTERED_PAGES:
            # 要密码（login_password）或要 TOTP（mfa_challenge）：只有已存在的账号才会这样。
            # 实测 2026-09-28：老号在 signup 阶段就直接落到 login_password。
            status, reason = STATUS_REGISTERED, f"服务端要求登录（{page_type}）"
        elif page_type == _PAGE_OTP_VERIFY:
            if mode == _MODE_PASSWORDLESS_SIGNUP:
                status, reason = STATUS_UNREGISTERED, "服务端选择无密码注册流程"
            elif mode:
                status, reason = STATUS_REGISTERED, f"服务端走已有账号流程（{mode}）"
            else:
                # 走 OTP 但没给 mode：区分不了"无密码注册"和"无密码登录"，
                # 不猜 —— 这两者对用户的意义完全相反。
                status, reason = STATUS_UNKNOWN, "OTP 页未给出 verification_mode"
        elif page_type:
            status, reason = STATUS_UNKNOWN, f"非标准页面类型: {page_type}"
        else:
            status, reason = STATUS_UNKNOWN, "未取到页面类型"

        return _result(
            addr, status,
            page_type=page_type,
            verification_mode=mode,
            reason=reason,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )
    except Exception as exc:  # noqa: BLE001
        return _result(
            addr, STATUS_UNKNOWN,
            error=f"{type(exc).__name__}: {str(exc)[:200]}",
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )
    finally:
        _close(flow)


__all__ = [
    "STATUS_REGISTERED",
    "STATUS_UNKNOWN",
    "STATUS_UNREGISTERED",
    "probe_registration",
]
