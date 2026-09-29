"""注册 worker：调 auth_flow.run_register，并把日志/状态实时推到队列。

每个注册任务跑在独立线程；通过 `RunLogger` 把 `logging` 记录 + tail 状态推
到队列，前端用 SSE 实时收日志。
"""
from __future__ import annotations

import logging
import queue
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]  # gpt-outlook-register/
sys.path.insert(0, str(ROOT))

from config import Config  # noqa: E402
from auth_flow import (  # noqa: E402
    AuthFlow,
    IdentityVerificationRequired,
    NetworkPreflightError,
    PasswordRequiredError,
)
from browser_launcher import FingerprintRuntimeMismatch  # noqa: E402
from mail_providers import (  # noqa: E402
    MailProviderError,
    create_mail_provider,
    get_provider_class,
)
from sms_provider import PhoneCallbackController  # noqa: E402

from . import db  # noqa: E402
from .environment import EnvironmentAllocationError, allocate_environment  # noqa: E402
from .probes import ProbeSession, instrument_method, redact_log_message, redact_probe_error  # noqa: E402


class RequestedCredentialError(RuntimeError):
    """The flow returned without a credential requested by the user."""

    def __init__(self, missing: list[str], oauth_reason: str = ""):
        self.missing = tuple(missing)
        self.oauth_reason = str(oauth_reason or "").strip()[:120]
        suffix = f" (OAuth: {self.oauth_reason})" if self.oauth_reason else ""
        super().__init__(
            "注册流程未获取用户请求的凭证: " + ", ".join(self.missing) + suffix
        )

# run_id -> queue of log strings; sentinel = None 表示流结束
_run_queues: dict[str, queue.Queue] = {}
_lock = threading.Lock()

# 当前线程正在跑哪个 run。
# ⚠️ 为什么需要这个：QueueLogHandler 是挂在 **root logger** 上的，而 root logger
#    是进程全局的。auto_loop 并发时 N 个 run 各挂一个 handler，每条日志会被
#    广播进**所有** run 的文件和 SSE 流 —— 实测 2026-08-04 三 worker 并发，
#    一个号的记录同时出现在 3 个 .log 里，WebUI 上三个号的日志搅在一起，
#    而 "[4/10] 获取 Sentinel Token..." 这类行不带邮箱，根本分不清是谁的。
#
#    注册链路（auth_flow / mail_providers / sentinel）内部不开任何线程，
#    一个 run 的日志全在自己那条线程上产生，所以线程绑定就能干净切开。
_current_run = threading.local()

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def _instrument_flow_for_probe(flow: Any, probe: ProbeSession, engine: str) -> Any:
    """Attach run-scoped probes to the important protocol/browser boundaries."""
    if engine == "browser":
        stages = {
            "_warmup": "browser.warmup",
            "_detect_country": "browser.network.observe",
            "_click_signup": "browser.signup.open",
            "_enter_email": "browser.signup.email",
            "_run_auth_steps": "browser.auth.steps",
            "_wait_for_chat_page": "browser.chat.ready",
            "_extract_tokens": "browser.tokens.extract",
            "_fetch_access_token": "browser.tokens.access",
        }
    else:
        stages = {
            "check_proxy": "network.preflight",
            "warmup": "auth.warmup",
            "get_csrf_token": "auth.csrf",
            "get_auth_url": "auth.url",
            "auth_oauth_init": "auth.oauth_init",
            "get_sentinel_token": "auth.sentinel",
            "signup": "auth.signup",
            "register_password": "auth.password",
            "send_otp": "mail.otp.send",
            "verify_otp": "mail.otp.verify",
            "create_account": "auth.account.create",
            "get_auth_session": "auth.session",
            "oauth_codex_rt_exchange": "oauth.codex.exchange",
            "oauth_token_exchange": "oauth.token.exchange",
            "oauth_secondary_authorize_exchange": "oauth.secondary.exchange",
        }
    for method_name, stage in stages.items():
        instrument_method(
            flow, method_name, probe, stage,
            # Codex RT is a required credential for this stage.  The method
            # reports a boolean result, so a 200 response that omits
            # refresh_token must be visible as a failed probe rather than an
            # apparently successful OAuth step.
            false_is_failure=method_name in {
                "check_proxy",
                "warmup",
                "register_password",
                "oauth_codex_rt_exchange",
                "oauth_token_exchange",
                "oauth_secondary_authorize_exchange",
            },
        )
    return flow


def record_environment_observation(
    run_id: str, probe: ProbeSession, observation: dict,
) -> None:
    """Persist the latest runtime observation and append its probe event."""
    if not isinstance(observation, dict):
        return
    try:
        db.record_run_observation(run_id, observation)
    except Exception as observer_error:
        logging.getLogger("registrar").debug(
            "[environment] 记录运行时观测失败: %s", observer_error
        )
    all_passed = observation.get("all_passed")
    runtime_status = (
        "ok" if all_passed is True
        else "failed" if all_passed is False
        else "skipped"
    )
    probe.mark(
        "environment.runtime",
        runtime_status,
        kind=observation.get("kind", ""),
        all_passed=all_passed,
        checks=observation.get("checks", {}),
        network=observation.get("network", {}),
    )


class QueueLogHandler(logging.Handler):
    """把 logging 记录扔进 run queue + 写 log 文件。

    只收**本 run 线程**产生的日志，见 emit 里的过滤。
    """

    def __init__(self, run_id: str, log_file: Path):
        super().__init__()
        self.run_id = run_id
        self._fh = open(log_file, "a", encoding="utf-8")
        self.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))

    def emit(self, record: logging.LogRecord):
        try:
            # emit 是在**打日志的那条线程**里同步跑的，所以这里读到的就是
            # 日志产生者的 run_id。别人 run 的日志直接丢掉。
            rid = getattr(_current_run, "run_id", None)
            if rid != self.run_id:
                return
            msg = redact_log_message(self.format(record))
            self._fh.write(msg + "\n")
            self._fh.flush()
            q = _run_queues.get(self.run_id)
            if q is not None:
                try:
                    # 有上限：没人订阅时也不让队列无限堆日志（日志本来就落盘）
                    q.put_nowait(msg)
                except queue.Full:
                    pass
            # 同一行也镜像给批量任务的总线。否则「全自动批量」页的实时日志
            # 只有「开始注册」和「失败完成」两条，中间十几个阶段、失败原因
            # 全看不见 —— 2026-09-29 主人反馈「日志显示不全、不知道进度」。
            _mirror_run_log(self.run_id, msg)
        except Exception:
            pass

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass
        super().close()


def _mirror_run_log(run_id: str, message: str) -> None:
    """把一次 run 的日志行镜像给批量任务的总线。

    批量页（全自动批量）订阅的是 auto_loop 的总线，而 run 的详细日志只进
    `_run_queues`（供单跑的 SSE 用）—— 两条总线不通，批量页就只剩开始/结束。

    延迟 import：auto_loop 反过来依赖 registrar，模块级 import 会成环。
    任何失败都静默：日志投递是装饰性的，绝不能影响注册本身。
    """
    try:
        from .auto_loop import CONTROLLER

        CONTROLLER.publish_run_log(run_id, message)
    except Exception:  # noqa: BLE001
        pass


def _redact_status_payload(value: Any) -> Any:
    """Redact free-form diagnostic text before it enters the SSE queue."""
    if isinstance(value, dict):
        return {str(key): _redact_status_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_status_payload(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_status_payload(item) for item in value]
    if isinstance(value, str):
        return redact_log_message(value)
    return value


def _emit_status(run_id: str, kind: str, payload: dict | str = ""):
    """前端约定：以 `__EVENT__:` 开头的行被解析成 JSON 状态事件。"""
    import json as _json
    q = _run_queues.get(run_id)
    if q is None:
        return
    body = payload if isinstance(payload, dict) else {"message": str(payload)}
    if kind in {"phase", "error"}:
        body = _redact_status_payload(body)
    body["kind"] = kind
    q.put("__EVENT__:" + _json.dumps(body, ensure_ascii=False))


# 网络/环境层错误特征：命中任一就把号放回 available（号本身没问题，是环境炸了）
_NETWORK_ERROR_PATTERNS = [
    "tls", "ssl", "sslerror", "connection", "connect error", "timeout", "timed out",
    "proxy", "socks", "dns", "name resolution", "name or service",
    "cloudflare", "just a moment", "403 forbidden",
    "csrf token 获取失败", "csrf token 失败",
    "/sentinel/req", "sentinel /req", "sentinel quickjs",
    "check_proxy 失败", "网络预检查",
    "没有可分配的全新任务环境",
    "未种到 oai-did", "warmup 均未", "warmup 4 次",
    "curl: (35)", "curl: (28)", "curl: (6)", "curl: (7)",
    "remote disconnected", "connection reset", "connection aborted",
    "max retries exceeded",
    "invalid_state",
    "icloud 中转 otp 超时", "icloud中转 otp 超时", "中转 otp 超时",
    "中转otp超时",
    "任务出口 ip", "浏览器出口环境校验失败",
]


def classify_error(err: str | BaseException, mail_source: str = "") -> str:
    """分类错误：'network'（环境/代理问题，号无辜）/ 'account'（号本身有问题）/ 'unknown'。

    mail_source 用来问 provider 要不要豁免某些模式 —— 比如 iCloud 中转号
    本来就是买的老号，"已有账号"是正常流程不是失败（见
    MailProvider.accepts_existing_account）。留空则按最严格的规则判。
    """
    if isinstance(err, PasswordRequiredError):
        return "account"
    if isinstance(err, IdentityVerificationRequired):
        # OpenAI 风控升级：该号要过 Persona 证件身份验证才能继续。协议层
        # 唯一正确动作是终止隔离；回池重试只会继续吃 400 invalid_auth_step
        # 并把号/新 IP 的风险分越刷越高。
        return "account"
    if isinstance(err, RequestedCredentialError):
        # A requested credential that is absent means this account did not
        # reach the required completed state. Returning it to available would
        # make the auto loop retry an already-partially-processed account.
        return "account"
    if isinstance(err, NetworkPreflightError):
        return "network"
    if isinstance(err, FingerprintRuntimeMismatch):
        return "network"
    raw_text = str(err or "").lower()
    relay_configuration_error = (
        "中转链接无效" in raw_text
        or (
            any(marker in raw_text for marker in ("401", "403", "404", "410"))
            and ("relay" in raw_text or "icloud_relay" in str(getattr(err, "kind", "")).lower())
        )
    )
    terminal_otp_timeout = any(marker in raw_text for marker in (
        "icloud 中转 otp 超时", "icloud中转 otp 超时",
        "中转 otp 超时", "中转otp超时",
    ))
    requested_credential_missing = (
        "注册流程未获取用户请求的凭证" in raw_text
    )
    if isinstance(err, MailProviderError) and not err.fatal:
        if relay_configuration_error or terminal_otp_timeout:
            return "account"
        if requested_credential_missing:
            return "account"
        return "network"
    if relay_configuration_error or terminal_otp_timeout or requested_credential_missing:
        return "account"
    if "中转链接无效" in raw_text or (
        "relay" in raw_text and any(
            marker in raw_text for marker in ("http 401", "http 403", "http 404", "http 410")
        )
    ):
        return "account"
    if any(marker in raw_text for marker in (
        "2fa 绑定失败", "2fa 绑定未成功", "mfa 验证失败",
    )):
        return "account"
    if isinstance(err, MailProviderError):
        if any(marker in str(err).lower() for marker in (
            "icloud 中转 otp 超时", "icloud中转 otp 超时",
            "中转 otp 超时", "中转otp超时",
        )):
            return "account"
        if any(marker in str(err).lower() for marker in (
            "中转链接无效", "http 401", "http 403", "http 404", "http 410",
        )):
            return "account"
        return "account" if err.fatal else "network"
    s = str(err or "").lower()
    if any(marker in s for marker in (
        "sign-in session is no longer valid", "session is no longer valid",
        "authorize/continue 状态连续失效", "invalid_state",
        "环境指纹运行时检查失败", "任务出口 ip 发生变化",
        "浏览器出口环境校验失败",
    )):
        return "network"
    # Keep this classification independent of the provider label: older runs
    # and manually-triggered jobs may omit mail_source, but a terminal relay
    # timeout still identifies the mailbox as exhausted.

    # A relay endpoint returning 401 means its token/link is invalid or
    # expired. Retrying the same row cannot repair that configuration.
    account_patterns = [
        "wrong_email_otp_code", "invalid_grant", "imap xoauth2",
        "outlook imap account unusable", "user is authenticated but not connected",
        "outlook refresh failed", "authentication failed", "authenticate failed",
        "outlook otp timeout", "registration_disallowed",
        "已有账号", "账号被", "refresh_token 失效",
        "历史运行缺少请求的",
        "凭证保存后",
    ]
    if mail_source:
        try:
            exempt = get_provider_class(mail_source).accepts_existing_account
        except MailProviderError:
            exempt = False  # 未知来源 —— 按默认最严格规则走
        # ⚠️ 用 if-in 而不是裸 remove()：上面的模式表将来被人改动/重排后，
        #    remove 抛的 ValueError 会跟 get_provider_class 的错混在同一个
        #    except 里被一起吞掉，豁免静默失效且没人看得出来。
        if exempt and "已有账号" in account_patterns:
            account_patterns.remove("已有账号")

    # 先匹配 account 特征（更具体），避免子串误命中（如 "outlook OTP timeout" 含 "timeout"）
    if any(p in s for p in account_patterns):
        return "account"
    # Terminal mailbox polling is not repaired by retrying the same account
    # through the proxy. Keep it ahead of the generic timeout/network rules.
    if any(p in s for p in _NETWORK_ERROR_PATTERNS):
        return "network"
    return "unknown"


def _do_register(
    run_id: str,
    account: dict,
    options: dict,
    log_file: Path,
):
    """实际注册任务。

    options:
        want_access_token: bool
        want_session_token: bool
        want_refresh_token: bool
        proxy: Optional[str]
        otp_timeout: int
        allow_existing_login: bool
    """
    # 先认领本线程，再挂 handler —— 顺序不能反：中间要是有日志产生，
    # 没打标记的话会被广播到其他并发 run 的日志里去。
    _current_run.run_id = run_id
    # 流量计数按线程累计；任务开始先清零，收尾时统一写进 runs 表。
    try:
        from http_client import reset_thread_traffic

        reset_thread_traffic()
    except Exception:  # noqa: BLE001
        pass

    handler = QueueLogHandler(run_id, log_file)
    handler.setLevel(logging.INFO)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    # 第一次需要的话提到 INFO 级别
    if root_logger.level > logging.INFO or root_logger.level == 0:
        root_logger.setLevel(logging.INFO)

    email = account["email"]
    probe = ProbeSession(run_id)
    environment = options.get("environment") or {}
    if not isinstance(environment, dict):
        environment = dict(environment)

    def _record_environment_observation(observation: dict) -> None:
        record_environment_observation(run_id, probe, observation)

    def _rebind_environment(old_ip: str, new_ip: str, new_country: str) -> bool:
        """预检阶段出口漂移自愈：把台账/运行行改绑到稳定观察到的新出口。

        只在 AuthFlow 的预检里被调用（那时还没向 OpenAI 发过任何请求）。
        返回 False 时上层照旧中止任务；返回 True 时内存环境与库一起改绑。
        """
        candidate = dict(environment)
        candidate["exit_ip"] = new_ip
        if new_country:
            candidate["exit_country"] = new_country
        candidate["session_reserved_at"] = time.time()
        if not db.rebind_environment_exit(run_id, candidate, old_exit_ip=old_ip):
            logging.getLogger("registrar").warning(
                "[register] 出口改绑被拒绝（新出口已被占用或台账缺行），任务按原逻辑中止: "
                "%s -> %s", old_ip, new_ip,
            )
            return False
        # 上层（run 收尾、导出、报告）读的是这个 dict，同步改掉。
        environment.update(candidate)
        try:
            probe.mark("environment.exit_rebind", "ok", exit_ip=new_ip, exit_country=new_country)
        except Exception:  # noqa: BLE001
            logging.getLogger("registrar").debug("改绑探针记录失败", exc_info=True)
        return True

    # 提前读取，避免在 try 块前异常时 except 引用未定义
    mail_source = db.get_setting("mail_source", "outlook")
    # 要不要操作号池（mark_done / mark_failed / release）由 provider 声明的
    # pooled 决定。未知 kind 时保守当池化处理 —— 号池里真有这行的话
    # 至少不会漏掉状态回写，把号永远卡在 in_use。
    try:
        is_pooled = get_provider_class(mail_source).pooled
    except MailProviderError:
        is_pooled = True

    try:
        probe.mark(
            "task.started",
            "ok",
            email=email,
            engine=options.get("engine", "protocol"),
            fingerprint_id=environment.get("fingerprint_id", ""),
            country_code=environment.get("country_code", ""),
            browser_family=environment.get("browser_family", ""),
            screen=(environment.get("fingerprint") or {}).get("screen", ""),
            viewport=(environment.get("fingerprint") or {}).get("viewport", {}),
        )
        # 本次注册专属的配置覆盖。
        # ⚠️ 以前是写 os.environ + finally 还原，但 auto_loop 并发跑多个 worker，
        #    os.environ 是**进程全局**的：A 设的 OTP_TIMEOUT/WEBUI_ALLOW_LOGIN 会被
        #    B 读到，B 跑完还原成 A 之前的值，A 后半程就用上别人的配置了。
        #    现在整个 dict 直接传给 AuthFlow，只挂在实例上，谁都污染不到谁。
        env_overrides = {}
        # outlook 接码邮箱常被 OpenAI 走 passwordless_signup 流程（新号收码而非设密码），
        # auth_flow 会误判为"已有账号"分支 → 不设 WEBUI_ALLOW_LOGIN 会 fast-fail。
        # 单号 WebUI 场景下 fast-fail 没意义（批量跑才需要"跳过被识别的号"），故强制 ON。
        env_overrides["WEBUI_ALLOW_LOGIN"] = "1"
        env_overrides["OTP_TIMEOUT"] = str(int(options.get("otp_timeout") or 180))
        # 人类操作节奏：关键步骤之间插随机停顿（只改时序，不改请求内容）。
        # 放在生产路径开启而不是默认开启，避免拖慢单元测试。
        env_overrides["WEBUI_HUMANIZE"] = "1"
        # refresh_token 是可选凭证；默认跳过 Codex OAuth，避免它阻断普通注册。
        if not options.get("want_refresh_token", False):
            env_overrides["SKIP_OAUTH_TOKEN_EXCHANGE"] = "1"
            env_overrides["OAUTH_CODEX_RT_EXCHANGE"] = "0"
            env_overrides["OAUTH_CODEX_RT_BEFORE_CALLBACK"] = "0"
        # PROXY 走 cfg.proxy，无需 env

        cfg = Config()
        cfg.proxy = (
            environment.get("proxy") if environment else options.get("proxy")
        ) or None
        # ⚠️ 必须先 or "" 再 str：直接 str(None) 会得到字符串 "None"，
        # 它非空，于是"没有代理"被当成"代理地址叫 None"发给 curl，
        # 报出 curl (5) Could not resolve proxy: None 这种指向错误的方向。
        cfg.proxy = str(cfg.proxy or "").strip() or None

        # ─ 邮箱来源路由 ─
        # 原来是 if cf_temp / else outlook 的写死分支，加一种邮箱就得回来改。
        # 现在交给注册表工厂：provider 自己从 settings + account 里取需要的字段。
        with probe.step("mail.provider.create", source=mail_source):
            mail = create_mail_provider(mail_source, db.get_mail_settings(), account)
            # 收件与注册解耦：默认**不走**注册出口，避免注册代理会话到期后
            # 中转取件跟着一起死（日志里 OTP 超时 60s 成片的直接原因：拉取
            # 邮件 curl(28) 连续超时，而信其实已经送到了）。可显式配置
            # mailbox_proxy 走专用收件代理；留空 = 直连中转站。
            set_proxy = getattr(mail, "set_proxy", None)
            if callable(set_proxy):
                mailbox_proxy = str(
                    options.get("mailbox_proxy")
                    or db.get_setting("mailbox_proxy", "")
                    or ""
                ).strip()
                set_proxy(mailbox_proxy)
        instrument_method(
            mail,
            "wait_for_otp",
            probe,
            "mail.otp.read",
            capture_first_arg=True,
        )
        # 中转链接预检：无效/过期 token 在动 OpenAI 之前就终止（fatal）。
        # 暂态错误由 preflight 自己吞掉，不拦正常任务。
        with probe.step("mail.provider.preflight", source=mail_source):
            preflight = getattr(mail, "preflight", None)
            if callable(preflight):
                preflight()
        logging.getLogger("registrar").info(
            f"[register] 邮箱来源: {mail_source} ({mail.display_name})"
        )

        # ─ 2FA 绑定钩子：插在「拿到 session」和「Codex 授权」之间 ─
        #   主人指定的顺序：注册完 → 绑 2FA → Codex 授权 → 接码。
        #   2FA 必须有 access_token 才能打 mfa/enroll，而 at 只能从 get_auth_session 拿，
        #   所以这是唯一「已有 at 且 Codex 还没跑」的位置（见 auth_flow.py 那处注释）。
        #   钩子里绑成了就把结果存进 _tfa_box，run_register 返回后直接取，不再重绑。
        _tfa_box: dict = {}

        def _bind_2fa_hook(_flow, at: str) -> None:
            # ⚠️ 这里**不查密码**。快路径 bind_totp_2fa_inline 只拿 access_token 打
            #    mfa_info / enroll / activate，全程不碰密码（two_factor.py:153）。
            #    以前拿 flow.result.password 当门禁，把**重跑的老号全挡在门外**：
            #    老号被 OpenAI 认成已有账号 → 本轮不走 register_password →
            #    内存里密码是空的（真密码在库里，靠下面那段回读补），于是 at 明明齐活
            #    也绑不上（实测一个重跑的老号：at 长度 1762 齐活，却被跳过）。
            from .two_factor import bind_totp_2fa, bind_totp_2fa_inline
            real_email = getattr(getattr(_flow, "result", None), "email", "") or email
            existing_secret = ""
            try:
                existing_secret = (
                    db.get_registered(real_email) or {}
                ).get("totp_secret", "") or ""
            except Exception as e:
                logging.getLogger("registrar").warning(
                    "[register] 读取已有 2FA secret 失败: %s", redact_probe_error(e)
                )
            info = bind_totp_2fa_inline(
                _flow,
                at,
                existing_secret=existing_secret,
            )
            if not info or not info.get("secret"):
                # 快路径没成（enroll 瞬断、会话态不符等）→ 按设计回落慢路径：
                # 新起 flow 重走 login 正式链再 enroll。账号已注册成功，这一步
                # 只补 2FA，不碰号本身。密码优先取本轮 result，空则回读库里
                # 早落盘的密码。
                password = getattr(getattr(_flow, "result", None), "password", "") or ""
                if not password:
                    try:
                        password = (db.get_registered(real_email) or {}).get("password", "") or ""
                    except Exception as e:
                        logging.getLogger("registrar").warning(
                            "[register] 回读密码失败: %s", redact_probe_error(e)
                        )
                logging.getLogger("registrar").info(
                    "[register] 2FA 快路径未成功，回落慢路径（重登再绑）"
                )
                info = bind_totp_2fa(
                    cfg,
                    real_email,
                    password,
                    mail_provider=mail,
                    env_overrides=dict(env_overrides),
                    existing_secret=existing_secret,
                    fingerprint=(environment or {}).get("fingerprint"),
                )
            if info and info.get("secret"):
                _tfa_box.update(info)
                # ★ 一拿到 secret 立刻落盘，别等后面 Codex 授权 + 接码那几分钟。
                #   接码太久用户一关进程，_tfa_box 内存里的 secret 就永久没了，
                #   而 secret 一次性下发、服务端取不回（跟 _save_password_early 同理）。
                #   ⚠️ 必须用【真正的注册邮箱】flow.result.email，绝不能用外层 email：
                #      非池化 provider（CF 等）外层 email 是占位符
                #      xxx_placeholder_N@placeholder.local，用它落盘会跟后面 save_registered
                #      的真实邮箱对不上 —— 库里凭空多出一条占位垃圾行（两行）。
                #      run_register 一开头就设了 result.email（auth_flow.py:3102），
                #      走到这个钩子时它必然已是真实邮箱；取不到再退回外层 email 兜底。
                if not _save_totp_early(
                    real_email, info["secret"], info.get("factor_id", "")
                ):
                    # A TOTP secret is emitted once and cannot be recovered
                    # from the service. Continuing after an unverified write
                    # could mark a permanently locked account as successful.
                    raise RuntimeError("2FA secret 早落盘校验失败")
            else:
                raise RuntimeError("2FA 绑定失败：授权前绑定未返回已验证 secret")

        def _account_callback_for_flow(email: str) -> dict:
            """从数据库加载账号凭证（密码和 totp_secret）供 AuthFlow 登录时使用。

            用于既有账号登录场景：当服务端返回 mfa-challenge 时，AuthFlow 需要
            totp_secret 来计算 6 位动态码完成 2FA 验证。
            """
            try:
                data = db.get_registered(email)
                if data:
                    return {
                        "password": data.get("password", ""),
                        "totp_secret": data.get("totp_secret", ""),
                    }
            except Exception as e:
                logging.getLogger("registrar").warning(f"[register] account_callback 异常: {e}")
            return {}

        engine = options.get("engine", "protocol")
        probe.mark("flow.init", "started", engine=engine)
        if engine == "browser":
            from browser_flow import BrowserAuthFlow
            flow = BrowserAuthFlow(
                cfg,
                sms_callback=_build_sms_callback(run_id, probe),
                env_overrides={**env_overrides, "want_2fa": bool(options.get("want_2fa"))},
                on_password=_save_password_early,
                # ⚠ 不传 on_session_ready：浏览器引擎在 _bind_2fa_via_api 内部完成 2FA，
                # _bind_2fa_hook 调的 bind_totp_2fa_inline 需要协议引擎的 _common_headers，
                # 对 BrowserAuthFlow 会直接崩。
                on_session_ready=None,
                account_callback=_account_callback_for_flow,
                headless=options.get("browser_headless", True),
                engine_type=options.get("browser_engine") or "auto",
                fingerprint=environment.get("fingerprint"),
                fingerprint_country=(
                    environment.get("country_code")
                    or options.get("fingerprint_country", "")
                ),
                browser_family=(
                    environment.get("browser_family")
                    or options.get("fingerprint_browser_family")
                    or "auto"
                ),
                fingerprint_weighted=bool(options.get("fingerprint_weighted", True)),
                environment=environment,
                environment_observer=_record_environment_observation,
            )
        else:
            flow = AuthFlow(
                cfg,
                sms_callback=_build_sms_callback(run_id, probe),
                env_overrides=env_overrides,
                on_password=_save_password_early,
                on_session_ready=_bind_2fa_hook if options.get("want_2fa") else None,
                account_callback=_account_callback_for_flow,
                fingerprint=environment.get("fingerprint"),
                fingerprint_country=(
                    environment.get("country_code")
                    or options.get("fingerprint_country", "")
                ),
                fingerprint_browser_family=(
                    environment.get("browser_family")
                    or options.get("fingerprint_browser_family")
                    or "auto"
                ),
                fingerprint_weighted=bool(options.get("fingerprint_weighted", True)),
                environment=environment,
                environment_observer=_record_environment_observation,
                environment_rebind=_rebind_environment,
            )
        _instrument_flow_for_probe(flow, probe, engine)
        probe.mark("flow.init", "ok", engine=engine)
        _emit_status(run_id, "phase", {"phase": "starting", "email": email})
        logging.getLogger("registrar").info(f"[register] 开始: {email}")

        partial = False
        d: dict
        probe.mark("registration.run", "started", engine=engine)
        try:
            result = flow.run_register(mail)
            d = result.to_dict()
            requested = (
                ("access_token", options.get("want_access_token", True)),
                ("session_token", options.get("want_session_token", True)),
                ("refresh_token", options.get("want_refresh_token", False)),
            )
            missing = [key for key, wanted in requested if wanted and not d.get(key)]
            if missing:
                error = RequestedCredentialError(
                    missing,
                    getattr(flow, "_oauth_failure_reason", "") if "refresh_token" in missing else "",
                )
                probe.mark(
                    "registration.run",
                    "failed",
                    error=error,
                    missing_credentials=missing,
                )
                raise error
            probe.mark(
                "registration.run",
                "ok",
                engine=engine,
                access_token_present=bool(d.get("access_token")),
                session_token_present=bool(d.get("session_token")),
            )
        except (RequestedCredentialError, PasswordRequiredError):
            raise
        except (NetworkPreflightError, FingerprintRuntimeMismatch):
            # Preserve preflight/environment failures verbatim. Converting
            # them to a missing-credential error hides the real proxy timeout
            # and makes diagnostics and pool handling incorrect.
            raise
        except RuntimeError as e:
            # An exception from the flow is still a failed run, even if an
            # intermediate AuthResult contains access/session values.  The old
            # fallback converted generic late-stage failures into a successful
            # partial result and hid the actual registration error.
            # Persona 证件验证是风控终态：必须原样上抛并隔离，绝不能被下面
            # 的通用分支转成「凭证缺失」再进 credential-retry 续取循环——
            # 重试风暴正是把号越刷越死的原因（实测 dawn 号被连续续取 20 次）。
            if isinstance(e, IdentityVerificationRequired):
                probe.mark("registration.run", "failed", error=e)
                raise
            root_text = str(e or "").lower()
            # Preserve the concrete upstream error even when the flow failed
            # before credentials were produced.  Converting preflight,
            # environment, and OAuth-chain failures into a missing-token
            # error hides the real proxy/session root cause and would
            # quarantine an account whose environment is at fault.
            if any(marker in root_text for marker in (
                "operation returned false", "failed to perform", "connection timed out",
                "proxy closed connection", "出口 ip", "environment",
                "出口环境校验失败", "出口与冻结环境不一致", "环境校验失败",
            )):
                probe.mark("registration.run", "failed", error=e)
                raise
            if any(marker in root_text for marker in (
                "sentinel quickjs", "invalid_state", "sign-in session is no longer valid",
                "session is no longer valid", "authorize/continue 状态连续失效",
                "warmup 失败", "oauth", "otp", "socks", "proxy", "tls",
            )):
                probe.mark("registration.run", "failed", error=e)
                raise
            #
            # Classify the partially-processed account so the auto loop can
            # never treat it as a clean network retry: missing requested
            # credentials and a missing confirmed password are account states,
            # while a failure with every requested value present stays visible
            # as an unclassified flow error for diagnosis.
            d = flow.result.to_dict()
            missing = [
                key for key, wanted in (
                    ("access_token", options.get("want_access_token", True)),
                    ("session_token", options.get("want_session_token", True)),
                    ("refresh_token", options.get("want_refresh_token", False)),
                ) if wanted and not d.get(key)
            ]
            if missing:
                error = RequestedCredentialError(
                    missing,
                    getattr(flow, "_oauth_failure_reason", "")
                    if "refresh_token" in missing else "",
                )
                probe.mark(
                    "registration.run", "failed",
                    error=error, missing_credentials=missing,
                )
                raise error from e
            if not (d.get("password") or "").strip():
                probe.mark("registration.run", "failed", error=e)
                raise PasswordRequiredError(
                    f"注册流程中途失败（{e}）且未获得已确认密码，本次注册未完成"
                ) from e
            probe.mark("registration.run", "failed", error=e)
            raise

        # ─ 用户选项过滤：未勾选的字段从结果里抹掉，DB 只存用户想要的
        full = d
        d = {
            "email": full.get("email", ""),
            "password": full.get("password", ""),
        }
        if options.get("want_access_token", True):
            d["access_token"] = full.get("access_token", "")
        if options.get("want_session_token", True):
            d["session_token"] = full.get("session_token", "")
            d["cookie_header"] = full.get("cookie_header", "")  # 同样是浏览器注入用
        if options.get("want_refresh_token", False):
            d["refresh_token"] = full.get("refresh_token", "")
            d["id_token"] = full.get("id_token", "")

        # A run is only complete when every explicitly requested credential is
        # present in the exact payload that will be persisted. This second
        # guard also covers partial-return paths after a late flow exception.
        requested_after_filter = [
            key for key, wanted in (
                ("access_token", options.get("want_access_token", True)),
                ("session_token", options.get("want_session_token", True)),
                ("refresh_token", options.get("want_refresh_token", False)),
            ) if wanted and not d.get(key)
        ]
        if requested_after_filter:
            raise RequestedCredentialError(requested_after_filter)

        # ─ 密码回读：必须在 2FA 之前 ─
        # ⚠️ d 是**本轮内存里**的结果，它不一定知道这个号有密码：
        #    重跑一个之前设过密码的邮箱时，OpenAI 会认成已有账号 → passwordless_login
        #    → register_password 根本不执行 → d["password"] 是空的，
        #    但上一轮 save_password_early 存的密码还在库里。
        #    两个下游都要它：① 2FA 慢路径要用密码重走 login 链；
        #    ② 前端 done 事件 `v-if="lastRunResult.password"` 判空会把密码行
        #       连同两个复制按钮一起藏掉，主人会以为密码丢了。
        #    以前这段在 2FA **之后**，于是老号在 2FA 眼里永远"无密码"→ 被跳过。
        #    只在 d 里密码为空时查一次，正常路径零额外开销。
        if not (d.get("password") or "").strip():
            try:
                _saved = db.get_registered(d.get("email") or "")
                _pw = ((_saved or {}).get("password") or "").strip()
                if _pw:
                    d["password"] = _pw
                    logging.getLogger("registrar").info(
                        "[register] 本轮未设密码，沿用库中已存密码（上一轮 register_password 留下的）"
                    )
            except Exception as e:
                logging.getLogger("registrar").warning(f"[register] 回读已存密码失败: {e}")

        if not (d.get("password") or "").strip():
            raise PasswordRequiredError(
                "本次注册缺少已确认密码；请先在官网设置或重置密码，"
                "再更新本地凭证后重试"
            )

        # ─ 可选：绑定 TOTP 2FA（仅用户勾选 want_2fa 时才跑） ─
        #   正常情况上面的 on_session_ready 钩子已经在【Codex 授权之前】绑完了，
        #   这里只是兜底：钩子没跑到（run_register 中途抛异常走 partial 分支、
        #   或那时 access_token 还是空）时再补一次。
        #   兜底本身也是先快后慢两条路（见 two_factor.py 模块头）：
        #     快 bind_totp_2fa_inline —— 直接复用刚跑完注册的 flow + access_token，
        #        6.2s 搞定，零 PoW 零邮件（实测 2026-08-08 <测试号>@<自建域>
        #        四个请求全 200，mfa_enabled=true）。
        #     慢 bind_totp_2fa —— 新起 AuthFlow 重走 login 正式链，约 40s + 一次 PoW
        #        + 一封验证码邮件。只在快路径没成时兜底。
        #   失败仅告警、绝不废掉已注册成功的号；secret 一次性下发，成功即随 d 落库+推前端。
        #   ⚠️ 入口条件**不查密码**：快路径只要 access_token。密码只是慢路径
        #      （重走 login 链）的前提，所以判断挪到回落那一步再做。
        if options.get("want_2fa"):
            probe.mark("two_factor.bind", "started")
            _emit_status(run_id, "phase", {"phase": "binding_2fa", "email": d.get("email")})
            try:
                from .two_factor import bind_totp_2fa, bind_totp_2fa_inline
                existing_totp_secret = ""
                try:
                    existing_totp_secret = (
                        db.get_registered(d.get("email") or "") or {}
                    ).get("totp_secret", "") or ""
                except Exception as e:
                    logging.getLogger("registrar").warning(
                        "[register] 读取已有 2FA secret 失败: %s", redact_probe_error(e)
                    )
                # 钩子（Codex 授权之前那次）已经绑好就直接用，别再打一遍 enroll
                tinfo = dict(_tfa_box) if _tfa_box.get("secret") else None
                # 浏览器引擎在 _bind_2fa_via_api 内部已经绑好了，结果存在 result.totp_secret
                if not tinfo and getattr(flow.result, "totp_secret", ""):
                    tinfo = {"secret": flow.result.totp_secret}
                if not tinfo:
                    tinfo = bind_totp_2fa_inline(
                        flow,
                        full.get("access_token", ""),
                        existing_secret=existing_totp_secret,
                    )
                if not (tinfo and tinfo.get("secret")):
                    # 慢路径要拿密码重登一次，没密码就只能到此为止
                    if (d.get("password") or "").strip():
                        logging.getLogger("registrar").info(
                            "[register] 2FA 快路径未成，回落重走登录链..."
                        )
                        tinfo = bind_totp_2fa(
                            cfg, d.get("email", ""), d.get("password", ""),
                            mail_provider=mail, env_overrides=env_overrides,
                            existing_secret=existing_totp_secret,
                        )
                    else:
                        logging.getLogger("registrar").warning(
                            "[register] 2FA 快路径未成，且该号无密码（库里也没有），无法执行慢路径"
                        )
                if tinfo and tinfo.get("secret"):
                    d["totp_secret"] = tinfo["secret"]
                    d["totp_factor_id"] = tinfo.get("factor_id", "")
                    logging.getLogger("registrar").info(
                        f"[register] 2FA 绑定成功 email={d.get('email')}"
                    )
                    _emit_status(run_id, "phase", {"phase": "2fa_bound", "email": d.get("email")})
                    probe.mark("two_factor.bind", "ok", secret_present=True)
                else:
                    probe.mark("two_factor.bind", "failed", reason="provider returned no secret")
                    raise RuntimeError("2FA 绑定未成功：未获取到已验证的 TOTP secret")
            except Exception as e:
                probe.mark("two_factor.bind", "failed", error=e)
                raise RuntimeError(f"2FA 绑定失败: {e}") from e
        # 落库（密码已在 2FA 之前回读补齐，这里 d 里该有的都有了）
        # device_id / cookie_header 之前一直没写进 d：device_id 落库 0/100，
        # 导致后续 plus 检测拿不到注册时的设备身份，只能发“冷请求”。
        # 与密码/totp 同理，空值不覆盖旧值（device_id 是服务端认识这台设备的标识）。
        if not d.get("device_id"):
            d["device_id"] = full.get("device_id") or ""
        if not d.get("cookie_header"):
            d["cookie_header"] = full.get("cookie_header") or ""
        with probe.step("database.registered.save", email=d.get("email", "")):
            db.save_registered(d)
            saved = db.get_registered(d["email"])
            if not saved:
                raise RuntimeError("凭证保存后无法读取注册记录，本次注册未完成")
            # 注册完就排队等支付能力探测（后台队列按 6 秒一个慢慢探，
            # 遇到限流自动退避）。主人要求"每次注册完后自动检测"。
            try:
                from . import checkout_capability

                checkout_capability.enqueue(d["email"])
            except Exception:  # noqa: BLE001
                logging.getLogger("registrar").debug(
                    "支付能力探测入队失败", exc_info=True
                )
            persisted_mismatches = []
            for field in ("password", "access_token", "session_token", "refresh_token"):
                wanted = (
                    field == "password"
                    or field == "access_token" and options.get("want_access_token", True)
                    or field == "session_token" and options.get("want_session_token", True)
                    or field == "refresh_token" and options.get("want_refresh_token", False)
                )
                if wanted and (saved.get(field) or "") != (d.get(field) or ""):
                    persisted_mismatches.append(field)
            if options.get("want_2fa") and (
                not d.get("totp_secret")
                or (saved.get("totp_secret") or "") != d.get("totp_secret")
            ):
                persisted_mismatches.append("totp_secret")
            if persisted_mismatches:
                raise RuntimeError(
                    "凭证保存后校验失败，本次注册未完成: "
                    + ", ".join(persisted_mismatches)
                )

        # 注册完成后只读查询一次 Plus 一个月试用资格。检测使用本任务冻结的
        # 代理和指纹，结果写入已有 plus_check 字段；检测失败不影响已保存账号。
        plus_check = None
        if full.get("access_token"):
            # ── 账号预热（拟人化）──
            # 真人注册完不会立刻去点订阅：先回首页看一眼、等几秒、再进账户页。
            # 协议链路能补的"人工痕迹"只有会话行为与节奏，所以按真实顺序补上，
            # 全部用任务冻结的同一代理 + 同一指纹。失败不影响账号。
            with probe.step("account.warm", email=d.get("email", "")):
                try:
                    from .account_warm import warm_account

                    warm_account(
                        access_token=full.get("access_token", ""),
                        cookie_header=(
                            full.get("cookie_header", "") or d.get("cookie_header", "")
                        ),
                        proxy=(environment.get("proxy") or cfg.proxy or ""),
                        fingerprint=environment.get("fingerprint"),
                        device_id=full.get("device_id") or d.get("device_id") or "",
                    )
                except Exception as exc:  # noqa: BLE001
                    logging.getLogger("registrar").info(
                        "[register] 账号预热跳过（不影响注册）: %s", str(exc)[:160]
                    )
            probe.mark("plus_trial.check", "started")
            _emit_status(
                run_id,
                "phase",
                {"phase": "checking_plus_trial", "email": d.get("email")},
            )
            try:
                from plus_trial_checker import check_plus_trial

                plus_check = check_plus_trial(
                    full.get("access_token", ""),
                    proxy=(environment.get("proxy") or cfg.proxy or ""),
                    fingerprint=environment.get("fingerprint"),
                    device_id=full.get("device_id", ""),
                    cookie_header=full.get("cookie_header", ""),
                )
                d["plus_check"] = plus_check
                if plus_check.get("status") not in ("error", "no_at"):
                    db.update_plus_check(d.get("email", ""), plus_check)
                logging.getLogger("registrar").info(
                    "[register] 0元试用资格: email=%s status=%s label=%s",
                    d.get("email"),
                    plus_check.get("status"),
                    plus_check.get("label"),
                )
                _emit_status(
                    run_id,
                    "phase",
                    {
                        "phase": "plus_trial_checked",
                        "email": d.get("email"),
                        "status": plus_check.get("status"),
                        "label": plus_check.get("label"),
                        "trial_eligible": bool(plus_check.get("trial_eligible")),
                    },
                )
                probe.mark(
                    "plus_trial.check",
                    "failed" if plus_check.get("status") == "error" else "ok",
                    error=plus_check.get("error") if plus_check.get("status") == "error" else None,
                    result_status=plus_check.get("status"),
                    trial_eligible=bool(plus_check.get("trial_eligible")),
                )
                # 命中试用 → 自动走「提炼 + UPI 支付」开通 Plus（可在 Plus 设置里关）。
                # 放在这里而不是外部轮询：账号刚落库、token 最新鲜，且只对真命中的号做。
                if plus_check.get("trial_eligible"):
                    # 支付能力探测（本机协议链路，走印度出口）：
                    # 先把能不能走通 0 元 checkout 实探出来，探不过就不排队等授权，
                    # 避免白花提炼/支付额度。sync_eligible 打开时会在注册流程里
                    # 同步探测（会拉长注册耗时，默认关）。
                    try:
                        from . import checkout_capability

                        cap_cfg = checkout_capability.config()
                        if cap_cfg["enabled"] and cap_cfg["auto"] and cap_cfg.get("sync_eligible", False):
                            outcome = checkout_capability.probe_email(
                                d.get("email", "")
                            )
                            probe.mark(
                                "plus_checkout_capability",
                                "ok" if outcome.get("ok") else "failed",
                                status=outcome.get("status"),
                                failure_type=outcome.get("failure_type"),
                                transport_failed=bool(outcome.get("transport_failed")),
                                free_trial=bool(outcome.get("free_trial")),
                                amount_minor=outcome.get("amount_minor"),
                            )
                            # 只有「探通了且真 0 元」才排队等授权；探出来要付钱
                            # （amount_minor>0）说明不是 0 元试用，别占用授权队列。
                            # 探测本身失败（含出口不通）时照旧排队，由主人决定。
                            if outcome.get("ok") and not outcome.get("free_trial"):
                                logging.getLogger("registrar").info(
                                    "[register] 探测到非 0 元 checkout（amount=%s %s），"
                                    "不计入可领试用: %s",
                                    outcome.get("amount_minor"),
                                    outcome.get("currency"),
                                    d.get("email"),
                                )
                                plus_check = {**plus_check, "trial_eligible": False}
                            elif outcome.get("failure_type") in (
                                "TokenInvalid", "AccountDeactivated",
                            ):
                                # 只有账号级结论（凭证失效 / 封号）才跳过排队。
                                # 传输失败（出口不通）和请求被拒（参数形状）都不是
                                # 账号结论，照旧排队，免得链路问题误杀好号。
                                logging.getLogger("registrar").info(
                                    "[register] 支付能力探测未通过，跳过排队: %s (%s)",
                                    d.get("email"),
                                    outcome.get("failure_type") or outcome.get("status"),
                                )
                                plus_check = {**plus_check, "trial_eligible": False}
                    except Exception as cap_exc:  # noqa: BLE001
                        logging.getLogger("registrar").warning(
                            "[register] 支付能力探测异常（不影响账号）: %s",
                            str(cap_exc)[:160],
                        )
                if plus_check.get("trial_eligible"):
                    try:
                        from . import plus_activate

                        auto = plus_activate.auto_submit_if_eligible(
                            d.get("email", ""), full.get("access_token", "")
                        )
                        if auto and auto.get("pending"):
                            # 主人 2026-09-26 的硬规则：可开通 Plus 的号必须先授权，
                            # 才允许提交「提炼 + 支付」。这里只排队落状态。
                            probe.mark("plus_auto_submit", "pending", reason="awaiting_authorization")
                            _emit_status(
                                run_id, "phase",
                                {
                                    "phase": "plus_pending_authorization",
                                    "email": d.get("email"),
                                },
                            )
                        elif auto and auto.get("ok"):
                            probe.mark("plus_auto_submit", "ok", task_id=auto.get("task_id"))
                            _emit_status(
                                run_id, "phase",
                                {
                                    "phase": "plus_auto_submitted",
                                    "email": d.get("email"),
                                    "task_id": auto.get("task_id"),
                                },
                            )
                        elif auto:
                            probe.mark("plus_auto_submit", "failed", error=auto.get("error"))
                    except Exception as exc:  # noqa: BLE001
                        probe.mark("plus_auto_submit", "failed", error=str(exc)[:160])
                        logging.getLogger("registrar").warning(
                            "[register] 自动开通 Plus 失败（账号不受影响）: %s", str(exc)[:200]
                        )
            except Exception as exc:  # noqa: BLE001
                probe.mark("plus_trial.check", "failed", error=exc)
                logging.getLogger("registrar").warning(
                    "[register] 0元试用资格检测失败（账号仍有效）: %s",
                    str(exc)[:240],
                )
        else:
            probe.mark("plus_trial.check", "skipped", reason="access token not requested")
            logging.getLogger("registrar").info(
                "[register] 未请求 access_token，跳过 0元试用资格检测"
            )
        # 非池化 provider 的 email 是虚拟占位（xxx_placeholder_N@placeholder.local），
        # 号池里根本没这行，不能去 mark。判据用 provider 的 pooled，不写死 kind。
        if is_pooled:
            db.mark_done(email)

        # ─ 可选：导出到 CPA / SUB2API 面板（仅勾选启用时才执行） ─
        _try_export_to_panels(run_id, d, probe=probe)

        result_summary = {
            "email": d.get("email"),
            # 密码走明文推给前端：token 只给长度是因为太长且必须点按钮复制，
            # 但密码是随机 16 位、用户注册完第一件事就是拿去登录，
            # 藏在「查看凭证」弹窗里等于每次都要多点两下。
            # 这是本机自用工具，SSE 只发给本地浏览器，不外传。
            "password": d.get("password") or "",
            "access_token_len": len(d.get("access_token") or ""),
            "session_token_len": len(d.get("session_token") or ""),
            # 2FA secret 一次性下发、服务端取不回，明文推前端让用户当场导入验证器
            # （理由同密码；本机自用工具，SSE 只发本地浏览器）。未绑则为空串。
            "totp_secret": d.get("totp_secret") or "",
            "plus_trial_status": (plus_check or {}).get("status", ""),
            "plus_trial_label": (plus_check or {}).get("label", ""),
            "plus_trial_eligible": bool((plus_check or {}).get("trial_eligible")),
            "partial": partial,
        }
        _emit_status(run_id, "done", result_summary)
        logging.getLogger("registrar").info(
            f"[register] 完成 email={d.get('email')} "
            f"password_present={bool(d.get('password'))} "
            f"at={result_summary['access_token_len']} "
            f"st={result_summary['session_token_len']}"
        )
        db.finish_run(run_id, "done")
        probe.mark("task.finished", "ok", partial=partial)

    except Exception as e:
        err = redact_probe_error(e)
        category = classify_error(e, mail_source)
        logging.getLogger("registrar").error(f"[register] 失败 (category={category}): {err}")
        # 失败仍保留已经生成的密码；读回确认后才提示已保存。
        # 仅补写密码，不覆盖已有 token，也不改变本轮失败状态。
        _result = getattr(locals().get("flow"), "result", None)
        _pw = (getattr(_result, "password", "") or "").strip()
        if _pw:
            _credential_email = (getattr(_result, "email", "") or email).strip().lower()
            _password_saved = False
            try:
                _saved = db.get_registered(_credential_email)
                _password_saved = bool(_saved and _saved.get("password") == _pw)
            except Exception as storage_error:
                logging.getLogger("registrar").warning(
                    "[register] 密码保存状态读取失败: %s",
                    redact_probe_error(str(storage_error).replace(_pw, "[REDACTED]")),
                )
            if not _password_saved:
                _password_saved = _save_password_early(_credential_email, _pw)
            if _password_saved:
                logging.getLogger("registrar").error(
                    "[register] 该号已生成密码，请查看已保存凭证: %s", _credential_email,
                )
            else:
                logging.getLogger("registrar").error(
                    "[register] 密码持久化失败，尚未确认保存；本轮仍为失败: %s", _credential_email,
                )
        if category != "account":
            trace = traceback.format_exc()
            if _pw:
                trace = trace.replace(_pw, "[REDACTED]")
            logging.getLogger("registrar").error("%s", redact_log_message(trace))
        # 非池化 provider 没有号池记录，不操作
        if is_pooled:
            # OpenAI 风控把号升级为 Persona 证件身份验证：协议无法代答。
            # 立即终结核验并隔离（不回池、不重试）。重试风暴正是把号推进
            # 这个风控的原因，任何 OTP 重发在该步骤只会得到 400 invalid_auth_step。
            if isinstance(e, IdentityVerificationRequired):
                db.mark_failed(email, "[identity_verification_required] " + err)
                logging.getLogger("registrar").error(
                    f"[register] {email} 需 Persona 证件验证（status={e.status or 'required'}），"
                    "协议无法代答，已终结核验并隔离"
                )
                db.finish_run(run_id, "failed", err, category=category)
                _emit_status(run_id, "error", {"message": err, "category": category})
                probe.fail_open(e)
                probe.mark("task.finished", "failed", error=e, error_category=category)
                return
            # Terminal relay OTP exhaustion is account-specific even when an
            # upstream exception is classified as network. Persist failure so
            # the auto loop cannot reclaim the same mailbox.
            relay_otp_exhausted = any(
                marker in err.lower()
                for marker in (
                    "icloud 中转 otp 超时", "icloud中转 otp 超时",
                    "中转 otp 超时", "中转otp超时",
                )
            )
            if category in ("network", "pool") and not relay_otp_exhausted:
                db.release_unused(email)
                logging.getLogger("registrar").warning(
                    f"[register] {email} 判定为网络/环境错误，号已 release 回 available"
                )
            else:
                requested_credential_missing = (
                    "注册流程未获取用户请求的凭证" in err.lower()
                )
                # 只有核心凭证（access_token/session_token）缺失才走登录续取；
                # 仅 refresh_token 缺失仍按原契约判为账号失败，不自动重试。
                core_credential_missing = (
                    "access_token" in err.lower() or "session_token" in err.lower()
                )
                # 账户已建好、密码已落盘，只是最后换 token 那一步被链路打断
                # 返回空：这是可恢复的中间态，不是号坏了。回池排到队尾，下一轮
                # 走 allow_existing_login 的登录路径用密码+OTP 续取凭证。
                if (
                    requested_credential_missing
                    and core_credential_missing
                    and _password_saved
                ):
                    # 防无限重试：同一号连续 N 次都在最后换凭证一步失败，
                    # 通常是 OpenAI 已对其 OTP 重发限流（429）或登录态异常，
                    # 继续立即重试只会加速触发限流。达到上限后隔离待冷却，
                    # 由人工稍后重置或走登录续取，而不是永久卡在重试循环里。
                    try:
                        prior = db._conn().execute(
                            "SELECT COUNT(*) FROM runs WHERE email=? AND status='failed'"
                            " AND error LIKE '%注册流程未获取用户请求的凭证%'",
                            (email,),
                        ).fetchone()[0]
                    except Exception:
                        prior = 0
                    if prior >= 3:
                        db.mark_failed(email, "[credential_retry_exhausted] " + err)
                        logging.getLogger("registrar").error(
                            f"[register] {email} 凭证续取连续失败 {prior} 次，已隔离待冷却"
                            "（疑似 OpenAI OTP 限流，稍后可手动重置或登录续取）"
                        )
                    else:
                        db.release_retryable(email, "[credential_retry] " + err)
                        logging.getLogger("registrar").warning(
                            f"[register] {email} 凭证缺失但密码已落盘，号已回 available 走登录续取"
                        )
                elif relay_otp_exhausted:
                    # 中转站健康、信确实没在窗口内读到：这是暂态（邮件延迟），
                    # 不是号坏了。回池排到队尾稍后自动重试，而不是永久隔离。
                    db.release_retryable(email, "[mail_otp_timeout_retry] " + err)
                    logging.getLogger("registrar").warning(
                        f"[register] {email} OTP 超时，号已回 available（排到队尾稍后重试）"
                    )
                else:
                    db.mark_failed(email, f"[{category}] " + err)
        db.finish_run(run_id, "failed", err, category=category)
        _emit_status(run_id, "error", {"message": err, "category": category})
        probe.fail_open(e)
        probe.mark("task.finished", "failed", error=e, error_category=category)

    finally:
        probe.fail_open("task ended before stage completion")
        # 流量快照：线程级计数器 → runs.traffic_rx / traffic_tx。
        # 只统计经过 create_http_session 的请求，是近似口径（见 http_client 注释）。
        try:
            from http_client import thread_traffic

            _traffic = thread_traffic()
            db.update_run_traffic(run_id, _traffic.get("rx", 0), _traffic.get("tx", 0))
            # 按域名打印流量去向，排查「流量偏高」时一眼能看到花在哪。
            hosts = _traffic.get("hosts") or {}
            top_hosts = sorted(
                hosts.items(), key=lambda kv: -(kv[1].get("rx") or 0)
            )[:5]
            if top_hosts:
                detail = ", ".join(
                    f"{host}={round((slot.get('rx') or 0) / 1048576, 2)}MB"
                    for host, slot in top_hosts
                )
                top_paths = sorted(
                    (_traffic.get("paths") or {}).items(),
                    key=lambda kv: -(kv[1].get("rx") or 0),
                )[:5]
                path_detail = ", ".join(
                    f"[{slot.get('n')}x] {key}={round((slot.get('rx') or 0) / 1024)}KB"
                    for key, slot in top_paths
                )
                top_redirects = sorted(
                    (_traffic.get("redirects") or {}).items(),
                    key=lambda kv: -(kv[1].get("rx") or 0),
                )[:3]
                redirect_detail = ", ".join(
                    f"[{slot.get('n')}x] {key}={round((slot.get('rx') or 0) / 1024)}KB"
                    for key, slot in top_redirects
                )
                logging.getLogger("registrar").info(
                    "[流量] %s 合计 %.2fMB 接收 / %.1fKB 发送；去向: %s；路径: %s；重定向: %s",
                    (account or {}).get("email", ""),
                    (_traffic.get("rx") or 0) / 1048576,
                    (_traffic.get("tx") or 0) / 1024,
                    detail,
                    path_detail,
                    redirect_detail or "-",
                )
        except Exception:  # noqa: BLE001
            logging.getLogger("registrar").debug("流量计数写入失败", exc_info=True)
        # env 覆盖现在只挂在 AuthFlow 实例上，随实例一起回收，无需还原。
        # 关闭 handler
        try:
            root_logger.removeHandler(handler)
            handler.close()
        except Exception:
            pass
        q = _run_queues.get(run_id)
        if q is not None:
            try:
                q.put_nowait(None)  # sentinel: 流结束
            except queue.Full:
                pass
        # 队列生命周期只跟任务走：以前只有 SSE 生成器的 finally 才删，
            # 没人订阅（或被前端断开）时队列会常驻内存，跑几百个任务后
        # python 进程只涨不降。这里任务收尾就摘掉，SSE 已经持有引用，
        # 仍能把剩余日志读完。
        remove_run_queue(run_id)
        # 线程标记清掉。理论上线程跑完就回收了，但 threading.local 是绑在
        # 线程对象上的，万一以后换成线程池复用线程，残留的 run_id 会让下一个
        # 任务的日志全被投递到上一个 run 的（已关闭的）文件里去。
        _current_run.run_id = None


def _try_export_to_panels(run_id: str, cred: dict, *, probe: Optional[ProbeSession] = None) -> None:
    """注册完成后可选地把凭证导出到 CPA / SUB2API 面板。

    - 任一目标的"启用"开关关闭时,该目标跳过(不发请求);两者都未启用时整段 no-op。
    - 任何异常都不抛,只 emit 日志/状态(不影响注册主流程)。
    """
    try:
        cfg = db.get_export_internal_config()
    except Exception as e:
        logging.getLogger("registrar").warning(f"[export] 读取配置失败: {e}")
        return

    cpa_enabled = bool(cfg.get("cpa", {}).get("enabled"))
    sub2api_enabled = bool(cfg.get("sub2api", {}).get("enabled"))
    if not (cpa_enabled or sub2api_enabled):
        if probe:
            probe.mark("export.panels", "skipped", reason="no export target enabled")
        return  # 用户没勾选任何目标 → 完全不执行

    from . import exporter  # 懒 import,避免未启用时强依赖

    explog = logging.getLogger("registrar")

    def _log(msg: str, level: str = "info") -> None:
        if level == "error":
            explog.error(f"[export] {msg}")
        elif level == "warn":
            explog.warning(f"[export] {msg}")
        else:
            explog.info(f"[export] {msg}")
        try:
            _emit_status(run_id, "phase", {"phase": "export", "message": msg, "level": level})
        except Exception:
            pass

    try:
        if probe:
            probe.mark("export.panels", "started", cpa=cpa_enabled, sub2api=sub2api_enabled)
        results = exporter.run_exports(
            cred,
            cpa_cfg=cfg.get("cpa") if cpa_enabled else None,
            sub2api_cfg=cfg.get("sub2api") if sub2api_enabled else None,
            log_fn=_log,
        )
    except Exception as e:
        if probe:
            probe.mark("export.panels", "failed", error=e)
        _log(f"导出整体异常: {e}", "error")
        return

    # 汇总成一个事件给前端
    summary = {}
    if results.get("cpa") is not None:
        summary["cpa"] = {"ok": bool(results["cpa"].get("ok")),
                          "message": results["cpa"].get("message") or results["cpa"].get("error") or ""}
    if results.get("sub2api") is not None:
        summary["sub2api"] = {"ok": bool(results["sub2api"].get("ok")),
                              "message": results["sub2api"].get("message") or results["sub2api"].get("error") or ""}
    try:
        _emit_status(run_id, "phase", {"phase": "export_done", "summary": summary})
        if probe:
            probe.mark("export.panels", "ok", summary=summary)
    except Exception:
        pass


def _save_password_early(email: str, password: str) -> bool:
    """AuthFlow 的 on_password 回调：密码在 OpenAI 侧一生效就落盘。

    这里存的是"有密码、无凭证"的半成品行，跑通后 save_registered 会用
    同一个 email 主键覆盖补全。读回确认保存结果；失败只报告状态，不记录密码。
    """
    log = logging.getLogger("registrar")
    email = (email or "").strip().lower()
    password = (password or "").strip()
    if not email or not password:
        log.warning("[register] 密码保存参数为空，未执行持久化")
        return False
    try:
        db.save_password_early(email, password)
        saved = db.get_registered(email)
        if not saved or saved.get("password") != password:
            log.warning("[register] 密码写入后校验失败，尚未确认保存: %s", email)
            return False
        log.info(f"[register] 密码已落盘: {email}（凭证待补）")
        return True
    except Exception as e:
        log.warning(
            "[register] 密码持久化失败，尚未确认保存: %s",
            redact_probe_error(str(e).replace(password, "[REDACTED]")),
        )
        return False


def _save_totp_early(email: str, secret: str, factor_id: str = "") -> bool:
    """Persist a one-time TOTP secret and verify the readback immediately."""
    log = logging.getLogger("registrar")
    email = (email or "").strip().lower()
    secret = (secret or "").strip()
    if not email or not secret:
        log.warning("[register] 2FA secret 保存参数为空，未执行持久化")
        return False
    try:
        db.save_totp_early(email, secret, factor_id)
        saved = db.get_registered(email)
        if not saved or (saved.get("totp_secret") or "").strip() != secret:
            log.warning("[register] 2FA secret 写入后校验失败，尚未确认保存: %s", email)
            return False
        log.info("[register] 2FA secret 已早落盘 email=%s", email)
        return True
    except Exception as e:
        log.warning(
            "[register] 2FA secret 持久化失败，尚未确认保存: %s",
            redact_probe_error(e),
        )
        return False


def _build_sms_callback(
    run_id: str,
    probe: Optional[ProbeSession] = None,
) -> Optional[PhoneCallbackController]:
    """根据 webui 配置创建 SMS 接码 controller。

    未启用接码或未配置 API key 时返回 None，flow 会回退到环境变量路径。
    log_fn 把租号/等码的状态推到 SSE 流，前端可见。
    """
    cfg = db.get_sms_internal_config()
    if not cfg.get("sms_enabled"):
        return None
    api_key = (cfg.get("sms_api_key") or "").strip()
    if not api_key:
        logging.getLogger("registrar").warning("[sms] 已启用接码但未配置 sms_api_key，跳过")
        return None

    smslog = logging.getLogger("registrar")

    def _log(msg: str) -> None:
        # 既写日志、又通过 _emit_status 推 phase 事件给前端
        smslog.info(f"[sms] {msg}")
        try:
            _emit_status(run_id, "phase", {"phase": "sms", "message": msg})
        except Exception:
            pass

    try:
        controller = PhoneCallbackController(
            provider_key=cfg["sms_provider"],
            config=cfg,
            service=cfg.get("sms_service") or "openai",
            country=cfg.get("sms_country") or "52",
            log_fn=_log,
            auto_select_country=bool(cfg.get("sms_auto_country")),
        )
        if probe:
            instrument_method(controller, "get_phone", probe, "sms.rent")
            instrument_method(controller, "get_code", probe, "sms.otp.read")
            instrument_method(controller, "report_success", probe, "sms.report_success")
            instrument_method(controller, "cleanup", probe, "sms.cleanup")
        return controller
    except Exception as e:
        smslog.warning(f"[sms] 创建接码 controller 失败: {e}")
        return None


def start_registration(account: dict, options: dict) -> str:
    """启动一次注册任务，返回 run_id。"""
    run_id = uuid.uuid4().hex[:12]
    log_file = LOG_DIR / f"{run_id}.log"
    db.create_run(run_id, account["email"], str(log_file))
    probe = ProbeSession(run_id)
    probe.mark("task.requested", "ok", email=account.get("email", ""))

    # Freeze the complete task environment before the worker thread starts.
    # This makes the protocol and browser flows consume the same proxy/profile,
    # and lets SQLite reject historical IP/profile reuse atomically.
    try:
        probe.mark("environment.allocate", "started")
        environment = allocate_environment(run_id, options or {})
        db.update_run_environment(run_id, environment)
        # 粘性会话 TTL 守卫：剩余寿命必须覆盖 OTP 等待窗口 + 缓冲，
        # 否则宁可在开始前拒绝并换新会话，也不让流程跑到一半会话过期、
        # 出口变化。纯动态（轮换）代理没有 TTL 标记时跳过此检查，
        # 由 preflight / _verify_session_exit 的中途出口守卫兜底。
        session_ttl = environment.get("session_ttl_seconds")
        if session_ttl:
            reserved_at = float(environment.get("session_reserved_at") or time.time())
            remaining = session_ttl - (time.time() - reserved_at)
            needed = float(options.get("otp_timeout") or 180) + 240.0
            if remaining < needed:
                raise EnvironmentAllocationError(
                    f"粘性会话剩余寿命不足: remaining={int(remaining)}s < "
                    f"needed={int(needed)}s（OTP 窗口 + 缓冲）"
                )
        probe.mark(
            "environment.allocate",
            "ok",
            exit_ip=environment.get("exit_ip", ""),
            exit_country=environment.get("exit_country", ""),
            country_code=environment.get("country_code", ""),
            fingerprint_id=environment.get("fingerprint_id", ""),
            browser_family=environment.get("browser_family", ""),
            browser_engine=environment.get("browser_engine", ""),
        )
    except Exception as exc:
        probe.mark("environment.allocate", "failed", error=exc)
        _text = str(exc or "").lower()
        _pool_exhausted = (
            "没有可分配的全新任务环境" in _text
            or "出口 ip 已在历史账本" in _text
            or "出口 ip 在历史账本" in _text
        )
        db.finish_run(run_id, "failed", str(exc), category="pool" if _pool_exhausted else "network")
        # A claimed pooled account must not remain in_use when allocation fails.
        db.release_unused(account.get("email", ""))
        if isinstance(exc, EnvironmentAllocationError):
            raise
        raise EnvironmentAllocationError(f"任务环境初始化失败: {exc}") from exc

    frozen_options = dict(options or {})
    frozen_options["environment"] = environment
    # The selected proxy/profile are authoritative for this task. Keep the
    # original pool in options only for diagnostics; it is never re-selected.
    frozen_options["proxy"] = environment.get("proxy", "")
    frozen_options["fingerprint"] = environment["fingerprint"]
    frozen_options["fingerprint_country"] = environment.get("country_code", "")
    frozen_options["fingerprint_browser_family"] = environment.get(
        "browser_family", "auto"
    )

    # 有上限：没人订阅时也不会无限堆日志（日志同时写文件）
    q: queue.Queue = queue.Queue(maxsize=4000)
    with _lock:
        _run_queues[run_id] = q

    th = threading.Thread(
        target=_do_register,
        args=(run_id, account, frozen_options, log_file),
        daemon=True,
        name=f"register-{run_id}",
    )
    th.start()
    return run_id


def get_run_queue(run_id: str) -> Optional[queue.Queue]:
    return _run_queues.get(run_id)


def remove_run_queue(run_id: str) -> None:
    with _lock:
        _run_queues.pop(run_id, None)
