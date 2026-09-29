"""Structured, redacted run probes used by the WebUI pipeline.

The logger remains the live human-readable channel. This module adds a small
machine-readable channel so a failed stage can be located from the run record
without exposing passwords, OTPs, cookies, or bearer tokens.
"""
from __future__ import annotations

import logging
import re
import time
from contextlib import contextmanager
from copy import copy
from functools import wraps
from typing import Any, Iterator, Mapping
from uuid import uuid4

from . import db

logger = logging.getLogger("webui.probes")

_SECRET_KEY = re.compile(
    r"(?:password|passwd|token|secret|cookie|authorization|otp|code|api[_-]?key|refresh)",
    re.IGNORECASE,
)
_NETWORK_MARKERS = (
    "timeout", "timed out", "connection", "proxy", "socks", "dns", "tls", "ssl",
    "cloudflare", "network", "出口", "环境",
)
_ACCOUNT_MARKERS = (
    "注册流程未获取用户请求的凭证",
    "icloud 中转 otp 超时", "icloud中转 otp 超时",
    "中转 otp 超时", "中转otp超时",
    "中转链接无效", "relay http 401", "relay http 403",
    "relay http 404", "relay http 410",
)

# ── 日志中文化 ──
#
# 阶段名与状态词是**受控词汇**（ProbeSession.mark 的 stage/status 实参都是代码
# 里的常量），所以可以稳定映射成中文。没收录的阶段名原样输出 —— 新加的阶段
# 立刻可见，不需要同步改这张表。
_STAGE_LABELS = {
    "task.requested": "任务已受理",
    "task.started": "任务开始",
    "task.finished": "任务结束",
    "environment.allocate": "分配任务环境（出口 + 画像）",
    "environment.runtime": "运行时环境复核",
    "mail.provider.create": "创建邮箱提供者",
    "mail.provider.preflight": "邮箱取件预检",
    "flow.init": "初始化注册流程",
    "registration.run": "执行注册",
    "network.preflight": "网络连通性预检",
    "auth.warmup": "预热（给 chatgpt.com 种 cookie）",
    "auth.csrf": "获取 CSRF 令牌",
    "auth.url": "获取授权地址",
    "auth.oauth_init": "OAuth 初始化（拿 oai-did）",
    "auth.sentinel": "计算 Sentinel 令牌（PoW）",
    "auth.signup": "提交注册邮箱（判定新号/老号）",
    "auth.password": "设置账号密码",
    "auth.account.create": "创建账户",
    "mail.otp.send": "发送验证码",
    "mail.otp.read": "等待并读取验证码",
    "mail.otp.verify": "校验验证码",
    "database.registered.save": "保存注册凭证",
    "two_factor.bind": "绑定 2FA",
    "account.warm": "账号预热（拟人化）",
    "plus_trial.check": "检测 Plus 试用资格",
    "plus_checkout_capability": "支付能力探测",
    "plus_auto_submit": "自动提交开通",
    "export.panels": "导出到面板",
}

_STATUS_LABELS = {
    "started": "开始",
    "ok": "完成",
    "failed": "失败",
    "partial": "部分完成",
    "skipped": "跳过",
    "cancelled": "已取消",
}

# curl 错误码 → 中文含义。主人要判断「是代理问题还是程序问题」时，这几句就是答案；
# 光看 "Failed to perform, curl: (35) BoringSSL SSL_connect..." 判断不出来。
_CURL_HINTS = (
    ("curl: (5)", "代理地址无法解析"),
    ("curl: (6)", "域名解析失败"),
    ("curl: (7)", "连不上代理或目标主机"),
    ("curl: (28)", "请求超时"),
    ("curl: (35)", "TLS 握手被中断（链路抖动，重试通常可恢复）"),
    ("curl: (52)", "服务端没有返回内容"),
    ("curl: (56)", "连接被对端重置"),
    ("curl: (97)", "代理关闭了连接（常见于代理会话过期或鉴权失败）"),
    ("Failed to perform", "请求未能发出"),
    ("Could not resolve proxy", "代理地址无法解析"),
)


def stage_label(stage: str) -> str:
    key = str(stage or "")
    return _STAGE_LABELS.get(key, key)


def status_label(status: str) -> str:
    key = str(status or "")
    return _STATUS_LABELS.get(key, key)


def _translate_curl_errors(text: str) -> str:
    """给 curl 报错补一句中文说明（幂等：已加过〔…〕的不重复加）。"""
    out = text
    for marker, hint in _CURL_HINTS:
        if marker in out and f"〔{hint}〕" not in out:
            out = out.replace(marker, f"{marker}〔{hint}〕", 1)
    return out


_OPERATION_HISTORY: list[dict[str, Any]] = []
_OPERATION_HISTORY_LIMIT = 500
_SENSITIVE_ERROR_VALUE = re.compile(
    r"(?i)(?:bearer\s+|\b(?:[\w-]*(?:token|password|passwd|secret|api[_-]?key)|pw|totp|otp|code)"
    r"[\"']?\s*[=:]\s*)(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;]+)"
)
_COOKIE_VALUE = re.compile(r"(?i)(?:set-cookie|cookie|authorization)[\"']?\s*[=:]\s*[^\r\n]+")
_URL_CREDENTIALS = re.compile(r"(?i)(https?|socks5h?)://[^/\s@]+@")
_OTP_VALUE = re.compile(r"\b\d{6}\b")
_API_EMAIL_SEGMENT = re.compile(r"^[^/\s@]+@[^/\s@]+$")
_API_HEX_ID_SEGMENT = re.compile(r"^[0-9a-f]{8,64}$", re.IGNORECASE)
_API_LONG_ID_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{20,}$")


def classify_probe_error(error: BaseException | str) -> str:
    """Classify a probe error with the same rules as the registrar worker.

    The worker classifier keeps the account/network/unknown semantics in one
    place, so probe events and run records never disagree about the category
    of the same failure.  The import is deferred because ``registrar`` itself
    imports this module.
    """
    try:
        from . import registrar

        return registrar.classify_error(error)
    except Exception:  # pragma: no cover - fallback for early/partial imports
        text = str(error or "").lower()
        if any(marker in text for marker in _ACCOUNT_MARKERS):
            return "account"
        if any(marker in text for marker in _NETWORK_MARKERS):
            return "network"
        return "unknown"


def _redact(value: Any, *, key: str = "") -> Any:
    if key == "status_code" and type(value) is int:
        return value
    if key == "country_code" and isinstance(value, str) and re.fullmatch(r"[A-Za-z]{2}", value):
        return value
    if key.endswith(("_present", "_len")) and isinstance(value, (bool, int)):
        return value
    if _SECRET_KEY.search(key):
        if value in (None, ""):
            return False
        return {"present": True, "length": len(str(value))}
    if isinstance(value, Mapping):
        return {str(k): _redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value[:20]]
    if isinstance(value, str):
        return _redact_error(value)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return _redact_error(str(value))


def redact_log_message(value: BaseException | str) -> str:
    text = str(value or "")
    text = _COOKIE_VALUE.sub("[redacted]", text)
    text = _URL_CREDENTIALS.sub(r"\1://[redacted]@", text)
    text = _SENSITIVE_ERROR_VALUE.sub("[redacted]", text)
    return _OTP_VALUE.sub("[redacted]", text)


class RedactingFormatter(logging.Formatter):
    """Scrub rendered tracebacks as well as messages without changing shared records."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_log_message(super().format(copy(record)))


def _redact_error(value: BaseException | str) -> str:
    return redact_log_message(value)[:240]


def redact_probe_error(value: BaseException | str) -> str:
    """Return a short error suitable for logs and operation snapshots."""
    return _redact_error(value)


def normalize_api_path(path: str) -> str:
    """Replace dynamic API path values before using a route as an operation key."""
    segments = []
    for segment in str(path or "").split("/"):
        if not segment:
            continue
        if _API_EMAIL_SEGMENT.match(segment):
            segment = "{email}"
        elif _API_HEX_ID_SEGMENT.match(segment) or _API_LONG_ID_SEGMENT.match(segment):
            segment = "{id}"
        segments.append(segment)
    return "/" + "/".join(segments)


class ProbeSession:
    """Append structured stage events for one run."""

    def __init__(self, run_id: str):
        self.run_id = str(run_id or "")
        self._active: dict[str, float] = {}

    def mark(
        self,
        stage: str,
        status: str,
        *,
        duration_ms: int | None = None,
        error: BaseException | str | None = None,
        error_category: str = "",
        **details: Any,
    ) -> dict[str, Any]:
        if status != "started" and duration_ms is None and str(stage) in self._active:
            duration_ms = int((time.perf_counter() - self._active[str(stage)]) * 1000)
        event = {
            "event_id": uuid4().hex[:12],
            "stage": str(stage),
            "status": str(status),
            "timestamp": time.time(),
        }
        if duration_ms is not None:
            event["duration_ms"] = max(0, int(duration_ms))
        if error is not None:
            event["error"] = _redact_error(error)
            event["error_category"] = error_category or classify_probe_error(error)
        if details:
            event["details"] = _redact(details)
        if status == "started":
            self._active[str(stage)] = time.perf_counter()
        elif status in {"ok", "failed", "partial", "cancelled", "skipped"}:
            self._active.pop(str(stage), None)
        try:
            if self.run_id:
                db.record_run_probe(self.run_id, event)
        except Exception as exc:
            logger.debug("记录探针失败 run=%s stage=%s: %s", self.run_id, stage, exc)
        suffix = ""
        if "error" in event:
            suffix = f" 错误={str(event['error'])[:120]}"
        # 逐步中文：阶段名与状态词都是受控词汇，用 _STAGE_LABELS / _STATUS_LABELS
        # 翻译（没收录的 stage 原样输出，新加阶段立刻可见）。
        # 存储值仍是英文键 —— 前端与测试按 event["stage"] 判断，只改显示。
        duration = event.get("duration_ms")
        logger.info(
            "[探针] 任务=%s 阶段=%s 状态=%s 耗时=%s%s",
            self.run_id or "-",
            stage_label(stage),
            status_label(status),
            f"{duration}毫秒" if duration is not None else "-",
            suffix,
        )
        return event

    @contextmanager
    def step(self, stage: str, **details: Any) -> Iterator[None]:
        started = time.perf_counter()
        self.mark(stage, "started", **details)
        try:
            yield
            self.mark(
                stage, "ok",
                duration_ms=int((time.perf_counter() - started) * 1000),
                **details,
            )
        except Exception as exc:
            self.mark(
                stage, "failed",
                duration_ms=int((time.perf_counter() - started) * 1000),
                error=exc,
                **details,
            )
            raise

    def fail_open(
        self,
        error: BaseException | str = "task ended before stage completion",
    ) -> None:
        for stage, started in list(self._active.items()):
            self.mark(
                stage, "failed",
                duration_ms=int((time.perf_counter() - started) * 1000),
                error=error,
            )


def record_operation_probe(
    operation: str,
    status: str,
    *,
    duration_ms: int | None = None,
    error: BaseException | str | None = None,
    **details: Any,
) -> dict[str, Any]:
    """Log a structured probe for non-run operations (check/export/rebind)."""
    event = {
        "operation": str(operation),
        "status": str(status),
        "timestamp": time.time(),
    }
    if error is not None:
        event["error"] = _redact_error(error)
        event["error_category"] = classify_probe_error(error)
    if duration_ms is not None:
        event["duration_ms"] = max(0, int(duration_ms))
    if details:
        event["details"] = _redact(details)
    _OPERATION_HISTORY.append(dict(event))
    if len(_OPERATION_HISTORY) > _OPERATION_HISTORY_LIMIT:
        del _OPERATION_HISTORY[:-_OPERATION_HISTORY_LIMIT]
    try:
        db.record_operation_probe(event)
    except Exception as exc:
        logger.debug("持久化操作探针失败 operation=%s: %s", operation, exc)
    logger.info("[探针] 操作=%s 状态=%s", operation, status_label(status))
    return event


def list_operation_probes(limit: int = 100, operation: str = "") -> list[dict[str, Any]]:
    """Return recent persisted operation probes, with memory as a fallback."""
    count = max(1, min(int(limit or 100), _OPERATION_HISTORY_LIMIT))
    wanted = str(operation or "").strip()
    try:
        persisted = db.list_operation_probes(count, wanted)
    except Exception as exc:
        logger.debug("读取持久化操作探针失败: %s", exc)
        persisted = []
    if persisted:
        return persisted
    items = _OPERATION_HISTORY
    if wanted:
        items = [item for item in items if item.get("operation") == wanted]
    return [dict(item) for item in items[-count:]]


@contextmanager
def operation_probe(operation: str, **details: Any) -> Iterator[dict[str, Any]]:
    """Emit started/ok/failed events for an operation outside a run row."""
    started = time.perf_counter()
    record_operation_probe(operation, "started", **details)
    try:
        yield details
        record_operation_probe(
            operation, "ok",
            duration_ms=int((time.perf_counter() - started) * 1000),
            **details,
        )
    except Exception as exc:
        record_operation_probe(
            operation, "failed",
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=exc,
            **details,
        )
        raise


def instrument_method(
    target: Any,
    method_name: str,
    probe: ProbeSession,
    stage: str,
    *,
    capture_first_arg: bool = False,
    false_is_failure: bool = False,
) -> Any:
    """Wrap one provider callback while preserving its public method shape."""
    original = getattr(target, method_name, None)
    if not callable(original):
        return target
    if getattr(original, "_probe_instrumented", False):
        return target

    @wraps(original)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        details = {}
        if capture_first_arg and args and isinstance(args[0], str):
            details["email"] = args[0]
        probe.mark(stage, "started", **details)
        try:
            result = original(*args, **kwargs)
        except Exception as exc:
            probe.mark(
                stage, "failed",
                duration_ms=int((time.perf_counter() - started) * 1000),
                error=exc,
                **details,
            )
            raise
        failed = false_is_failure and result is False
        failure_error = None
        failure_details = {}
        if failed:
            failure_error = "operation returned false"
        if failed and stage.startswith("oauth."):
            reason = str(getattr(target, "_oauth_failure_reason", "") or "").strip()
            if reason:
                failure_error = reason
            raw_details = getattr(target, "_oauth_failure_details", {})
            if isinstance(raw_details, Mapping):
                allowed = {
                    "response_keys", "status_code", "exception_type",
                    "sms_configured", "final_path", "error_code",
                }
                failure_details["oauth"] = {
                    str(key): value
                    for key, value in raw_details.items()
                    if str(key) in allowed
                }
        probe.mark(
            stage,
            "failed" if failed else "ok",
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=failure_error,
            **details,
            **failure_details,
        )
        return result

    wrapped._probe_instrumented = True
    setattr(target, method_name, wrapped)
    return target


def probed_operation(operation: str):
    def decorator(function: Any):
        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            record_operation_probe(operation, "started")
            try:
                result = function(*args, **kwargs)
            except Exception as exc:
                record_operation_probe(
                    operation, "failed",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                    error=exc,
                )
                raise
            failed_result = isinstance(result, Mapping) and result.get("ok") is False
            record_operation_probe(
                operation,
                "failed" if failed_result else "ok",
                duration_ms=int((time.perf_counter() - started) * 1000),
                error=(
                    result.get("error") or result.get("message")
                    or "operation returned ok=false"
                ) if failed_result else None,
            )
            return result
        return wrapped
    return decorator


__all__ = [
    "ProbeSession",
    "classify_probe_error",
    "instrument_method",
    "list_operation_probes",
    "normalize_api_path",
    "operation_probe",
    "probed_operation",
    "record_operation_probe",
    "redact_probe_error",
    "redact_log_message",
]
