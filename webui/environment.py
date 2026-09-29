"""Per-task network and browser environment allocation.

The allocator freezes the network observation and the generated fingerprint before
the registration thread starts. SQLite owns the historical uniqueness guarantees so
concurrent workers cannot reserve the same exit IP or semantic profile.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import secrets
import random
import re
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from fingerprint import (
    check_version_consistency,
    generate_fingerprint,
    header_profile,
    has_country_profile,
    validate_fingerprint,
)

from . import db

logger = logging.getLogger("environment")

TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
CHATGPT_HOME = "https://chatgpt.com"
# 轻量「种 oai-did」路径（2026-09-29 实测 241B 即可拿到 oai-did + __cf_bm，
# 首页要 ~358KB —— 探测/预热优先用这个，失败再回退首页）
CHATGPT_SESSION_URL = "https://chatgpt.com/api/auth/session"


class EnvironmentAllocationError(RuntimeError):
    """Raised when a task cannot receive a fresh, verifiable environment."""


def proxy_fingerprint(proxy: str | None) -> str:
    value = (proxy or "").strip()
    if not value:
        return "direct"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


_SESSION_TTL_RE = re.compile(r"-t-(\d+)(?:m|min)?(?:[^0-9]|$)", re.IGNORECASE)
_SID_MARKER = "-sid-"
_SID_ALPHABET = string.ascii_letters + string.digits


def sessionize_proxy(proxy: str, ttl_minutes: int = 30) -> str:
    """把 1024Proxy 式"轮换端点"改写成每任务独立的粘性会话。

    轮换端点（如 `...-region-JP`，用户名里没有 `-sid-`）每次新连接都换出口
    IP，任务中途会话重建就会换 IP —— 实测还会换出日本以外的出口（柬埔寨）。
    给每个任务注入新的 `-sid-XXXXXXXX-t-NN` 后：
      - 任务内：同一 sid 的所有连接走同一条粘性会话，出口 IP 恒定；
      - 任务间：每个任务新生成的 sid 不同，出口 IP 必然不同。
    非该格式、已带 sid、或解析失败的 URL 原样返回。
    """
    value = str(proxy or "").strip()
    if not value or _SID_MARKER in value.lower():
        return value
    try:
        parts = urlsplit(value)
    except Exception:
        return value
    user = parts.username or ""
    if not user or "region-" not in user.lower():
        return value
    try:
        ttl = max(1, min(120, int(ttl_minutes)))
    except (TypeError, ValueError):
        ttl = 30
    token = "".join(secrets.choice(_SID_ALPHABET) for _ in range(8))
    new_user = f"{user}-sid-{token}-t-{ttl}"
    host = parts.hostname or ""
    if not host:
        return value
    netloc = f"{host}:{parts.port}" if parts.port else host
    if parts.password:
        netloc = f"{quote(new_user, safe='')}:{quote(parts.password, safe='')}@{netloc}"
    else:
        netloc = f"{quote(new_user, safe='')}@{netloc}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def parse_session_ttl(proxy: str | None) -> int | None:
    """Extract sticky-session TTL in seconds from vendor proxy URLs.

    1024Proxy 的 `-t-30` 表示该会话粘性 30 分钟：窗口内同一 SID 保持同一出口，
    窗口过后整个会话失效（curl 97）。把 TTL 解析进冻结环境，调用方可以在
    长流程（OTP 等待等）开始前判断会话剩余寿命是否够用。
    """
    match = _SESSION_TTL_RE.search(str(proxy or ""))
    if not match:
        return None
    minutes = int(match.group(1))
    if minutes <= 0:
        return None
    return minutes * 60


def parse_proxy_pool(text: str | list[str] | tuple[str, ...] | None) -> list[str]:
    """Normalize a proxy pool while preserving input order and removing duplicates."""
    if isinstance(text, (list, tuple)):
        values = text
    else:
        values = str(text or "").splitlines()
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        proxy = normalize_proxy_entry(str(item or ""))
        if not proxy or proxy.startswith("#") or proxy in seen:
            continue
        seen.add(proxy)
        out.append(proxy)
    return out


def normalize_proxy_entry(value: str) -> str:
    """把一行代理文本规范成显式 URL，隐藏供应商差异。

    支持两种粘贴形态（1024Proxy / 各家导出都在这两类里）：
      1. ``[scheme://][user:pass@]host:port``
         —— scheme 统一小写，``socks5://`` 升级成 ``socks5h://``
            （远端 DNS，避免本地解析泄露 / 解析失败）。
      2. ``host:port:user:pass`` 四段供应商格式
         —— 固定按 SOCKS5H 处理，user/pass 做 URL 转义。

    认不出来的原样返回，交给下游继续校验。
    """
    text = str(value or "").strip()
    if not text:
        return ""
    scheme = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://", text)
    if scheme:
        proto = scheme.group(1).lower()
        if proto == "socks5":
            proto = "socks5h"
        return f"{proto}://{text[scheme.end():]}"
    parts = text.split(":")
    if len(parts) >= 4 and parts[1].isdigit() and parts[0] and parts[2]:
        host, port, user = parts[0], parts[1], parts[2]
        password = ":".join(parts[3:])
        return (
            f"socks5h://{quote(user, safe='')}:{quote(password, safe='')}"
            f"@{host}:{port}"
        )
    return text


def fingerprint_signature(fingerprint: Mapping[str, Any]) -> str:
    """Hash the semantic profile, excluding only the per-task opaque ID."""
    validate_fingerprint(fingerprint)
    payload = {key: value for key, value in fingerprint.items() if key != "fingerprint_id"}
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_trace(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in (text or "").splitlines():
        key, separator, value = raw_line.partition("=")
        if separator:
            values[key.strip().lower()] = value.strip()
    exit_ip = values.get("ip", "")
    if not exit_ip:
        raise EnvironmentAllocationError("出口探测响应缺少 ip")
    try:
        normalized_ip = str(ipaddress.ip_address(exit_ip))
    except ValueError:
        raise EnvironmentAllocationError(f"出口探测返回了无效 IP: {exit_ip!r}") from None
    return {"exit_ip": normalized_ip, "exit_country": values.get("loc", "").upper()}


def compare_exit_observation(
    environment: Mapping[str, Any],
    *,
    exit_ip: str = "",
    exit_country: str = "",
    status_code: int | None = None,
) -> dict[str, Any]:
    """Compare a live task exit with the frozen allocation.

    A manually selected country is an intentional profile override: it is shown
    in the report and remains unchanged even when the proxy country differs.
    The exit IP itself is always strict because it identifies the network path.
    """
    expected_ip = str(environment.get("exit_ip") or "").strip()
    expected_country = str(
        environment.get("country_code") or environment.get("exit_country") or ""
    ).strip().upper()
    country_source = str(environment.get("country_source") or "default").strip().lower()
    observed_ip = str(exit_ip or "").strip()
    if observed_ip:
        try:
            observed_ip = str(ipaddress.ip_address(observed_ip))
        except ValueError:
            pass
    observed_country = str(exit_country or "").strip().upper()
    ip_matches = not expected_ip or observed_ip == expected_ip
    country_matches = (
        not expected_country
        or not observed_country
        or observed_country == expected_country
        or country_source == "manual"
    )
    status_ok = status_code is None or int(status_code) == 200
    checks = {
        "trace_reachable": status_ok,
        "exit_ip_matches": ip_matches,
        "country_matches_profile": country_matches,
        "country_policy_respected": country_source == "manual" or country_matches,
    }
    return {
        "expected": {
            "exit_ip": expected_ip,
            "country_code": expected_country,
            "country_source": country_source,
        },
        "observed": {
            "exit_ip": observed_ip,
            "exit_country": observed_country,
            "status_code": status_code,
        },
        "checks": checks,
        "all_passed": all(checks.values()),
    }


def _warmup_impersonate_and_headers(
    family: str,
    *,
    weighted: bool = True,
    country_code: str = "",
    fingerprint: Mapping[str, Any] | None = None,
) -> tuple[str, str, dict[str, str], dict[str, Any]]:
    """按任务家族的加权分布抽一套指纹，返回 (impersonate, UA, 完整浏览器头)。

    探测必须和真实任务同分布：探测只抽"家族"、任务再抽一次具体版本，
    就会再现「探测说 chrome110 能过、任务却拿 firefox147 跑」的错位
    （2026-09-26 实测 firefox 全族 CF 403，chrome110 29/30、safari 30/30）。
    """
    family_lc = (family or "").strip().lower()
    if fingerprint is None:
        # _fingerprint_policy 已经解析过：auto/random 会落到 mixed。
        fingerprint = generate_fingerprint(
            browser_family=family_lc or "mixed",
            weighted=weighted,
            country_code=(country_code or "").strip().upper(),
        )
    impersonate = fingerprint["impersonate"]
    headers = _navigation_headers_from_fingerprint(fingerprint)
    return impersonate, fingerprint["user_agent"], headers, dict(fingerprint)


def _navigation_headers_from_fingerprint(fingerprint: Mapping[str, Any]) -> dict[str, str]:
    """从指纹构建整页导航请求头（与 AuthFlow._navigation_headers 同源）。

    Chrome 补全 client hints、Safari/Firefox 一个不发——这是真实浏览器行为。
    缺 client hints 的 Chrome 会被 CF 一眼识破，这是历史上 403 的真因。
    """
    fp = dict(fingerprint or {})
    profile = header_profile(fp, kind="document")
    headers = {
        "Accept": profile["accept"],
        "Accept-Language": fp.get("lang_full") or "en-US,en;q=0.9",
        "Accept-Encoding": profile["accept_encoding"],
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": fp.get("user_agent") or "",
    }
    if profile["priority"]:
        headers["priority"] = profile["priority"]
    if fp.get("sec_ch_ua"):
        headers["sec-ch-ua"] = fp["sec_ch_ua"]
        headers["sec-ch-ua-mobile"] = fp.get("sec_ch_ua_mobile") or "?0"
        headers["sec-ch-ua-platform"] = fp.get("sec_ch_ua_platform") or '"Windows"'
        for key, name in (
            ("sec_ch_ua_full_version_list", "sec-ch-ua-full-version-list"),
            ("sec_ch_ua_arch", "sec-ch-ua-arch"),
            ("sec_ch_ua_bitness", "sec-ch-ua-bitness"),
            ("sec_ch_ua_model", "sec-ch-ua-model"),
            ("sec_ch_ua_platform_version", "sec-ch-ua-platform-version"),
        ):
            if fp.get(key):
                headers[name] = fp[key]
    return headers


def probe_exit(
    proxy: str | None,
    timeout: float = 15.0,
    family: str = "chrome",
    require_chatgpt: bool = False,
    weighted: bool = True,
    country_code: str = "",
    fingerprint: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """Read the real egress IP and country through the task's proxy.

    require_chatgpt=True 时用同一会话再 GET 一次 chatgpt.com 并核对 oai-did
    cookie：被 CF 拦的出口在此处直接淘汰，任务不必跑 warmup 空烧 6 次。
    合并进同一个会话/函数是为了省一次建连，分配阶段每个候选只花一次往返。
    """
    try:
        # Use the same client factory as the registration flow.  The previous
        # requests.get call had two material differences from AuthFlow: it let
        # requests merge process-level proxy environment variables and it used
        # a different SOCKS/DNS implementation.  That made allocation freeze
        # one exit while the task session later used another.
        from http_client import create_http_session
    except ImportError as exc:
        raise EnvironmentAllocationError(
            "出口探测依赖 HTTP 客户端未安装，请先安装 requirements.txt"
        ) from exc
    proxy_value = (proxy or "").strip()
    impersonate, probe_ua, chatgpt_headers, probe_fp = _warmup_impersonate_and_headers(
        family,
        weighted=bool(weighted),
        country_code=country_code,
        fingerprint=fingerprint,
    )
    # chatgpt.com 首屏比 trace 慢，给足时间；同时下面用 cookie 兜底，
    # 即使 body 读超时，只要 oai-did 已经种上就照样算这个出口可用。
    try:
        chatgpt_timeout = max(8.0, min(float(timeout), 20.0))
    except (TypeError, ValueError):
        chatgpt_timeout = 8.0
    session = None
    try:
        try:
            session = create_http_session(
                proxy=proxy_value or None,
                impersonate=impersonate,
                user_agent=probe_ua,
            )
            response = session.get(TRACE_URL, timeout=timeout)
        except Exception as exc:
            raise EnvironmentAllocationError(
                f"出口探测失败 ({proxy_fingerprint(proxy_value)}): {exc}"
            ) from exc
        if response.status_code != 200:
            raise EnvironmentAllocationError(
                f"出口探测返回 HTTP {response.status_code} "
                f"({proxy_fingerprint(proxy_value)})"
            )
        observed = _parse_trace(response.text)
        if require_chatgpt:
            # ⚠️ 必须复用同一个 session 探 chatgpt（同一出口、同一 TLS 指纹），
            #    所以关闭 session 只能放在整个函数最后 —— 提前 close 会让这里
            #    直接 SessionClosed，所有候选出口被判失败、任务卡在环境分配。
            #
            # 流量优化（2026-09-29 实测）：oai-did 种不种得上，是判断「出口能不能
            # 过 CF」的信号 —— 但 GET 首页要 ~358KB，而 GET /api/auth/session 只有
            # ~241B 且同样会种 oai-did + __cf_bm。轻量路径优先，种不上再回退首页，
            # 平均每个候选省 ~350KB；失败路径（CF 403/challenge）两种请求都会被拦，
            # 判定结果一致。
            home = None
            probe_error: Exception | None = None
            try:
                session.get(
                    CHATGPT_SESSION_URL, headers=chatgpt_headers, timeout=chatgpt_timeout
                )
            except Exception as exc:  # noqa: BLE001
                probe_error = exc
            try:
                planted = "oai-did" in session.cookies.get_dict()
            except Exception:
                planted = False
            if not planted:
                # 轻量路径没种上（出口被 CF 拦 / 会话异常）→ 用首页兜底确认一次，
                # 避免把「轻量路径偶发问题」误判成「出口不可用」。
                try:
                    home = session.get(
                        CHATGPT_HOME, headers=chatgpt_headers, timeout=chatgpt_timeout
                    )
                except Exception as exc:  # noqa: BLE001
                    probe_error = exc
                try:
                    planted = "oai-did" in session.cookies.get_dict()
                except Exception:
                    planted = False
            if not planted:
                detail = f"HTTP {getattr(home, 'status_code', '-')}"
                if probe_error is not None:
                    detail += f"，{type(probe_error).__name__}"
                raise EnvironmentAllocationError(
                    f"出口无法给 chatgpt.com 种 oai-did（{detail}，疑似 CF 拦截）"
                )
        observed["probe_fingerprint"] = probe_fp
        return observed
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass




def _requested_country(options: Mapping[str, Any], observed_country: str) -> tuple[str, str]:
    manual = str(options.get("fingerprint_country") or "").strip().upper()
    if manual:
        return manual, "manual"
    if observed_country:
        return observed_country, "proxy"
    return "", "default"


def _fingerprint_policy(options: Mapping[str, Any]) -> tuple[str, str, bool]:
    family = str(options.get("fingerprint_browser_family") or "auto").strip().lower()
    engine = str(options.get("browser_engine") or "auto").strip().lower()
    task_engine = str(options.get("engine") or "protocol").strip().lower()
    if task_engine == "browser":
        # 浏览器链路：Camoufox 是 Firefox 内核，auto 也可能落到 Camoufox，
        # 此时才需要 Firefox 指纹偏好。
        prefer_firefox = engine in ("auto", "camoufox") and family in ("", "auto", "random")
        resolved_family = family or "auto"
    else:
        # 协议注册：不需要 Firefox 偏好。此前把 browser_engine 默认值 "auto"
        # 也当成 Camoufox 候选，导致 protocol 注册的账号 100% 都是 Firefox 指纹。
        # 未显式指定家族时默认走"混池"轮换（chrome/firefox/safari 加权随机），
        # 避免整批账号共用一套指纹配置；显式指定则原样尊重。
        prefer_firefox = False
        resolved_family = family if family not in ("", "auto", "random") else "mixed"
    return resolved_family, engine or "auto", prefer_firefox


def _candidate_proxies(options: Mapping[str, Any]) -> list[str]:
    # 轮换端点默认改写成"每任务一个新粘性会话"：任务内一条 IP、
    # 任务间不重复。显式配置 proxy_session_mode=as-is 时保持原样。
    mode = str(options.get("proxy_session_mode") or "sticky").strip().lower()
    ttl_minutes = options.get("sticky_ttl_minutes") or 30
    try:
        variants = max(1, min(6, int(options.get("proxy_session_variants") or 3)))
    except (TypeError, ValueError):
        variants = 3

    def _prepare(entry: str) -> list[str]:
        if mode == "as-is":
            return [entry]
        prepared = [sessionize_proxy(entry, ttl_minutes)]
        # 同一个轮换端点每次改写都会生成一个新 sid。多备几个变体，让分配器在
        # 抽到非目标地区出口时有替换项，而不是把整个任务判成环境不可用。
        if prepared[0] != entry:
            for _ in range(variants - 1):
                candidate = sessionize_proxy(entry, ttl_minutes)
                if candidate not in prepared:
                    prepared.append(candidate)
        return prepared

    pool = parse_proxy_pool(options.get("proxy_pool"))
    if pool:
        # Start each task at a different pool position. Reservation remains the
        # authority when workers happen to probe the same entry concurrently.
        pool = [variant for entry in pool for variant in _prepare(entry)]
        random.SystemRandom().shuffle(pool)
        return pool
    return _prepare(str(options.get("proxy") or "").strip())


def _summarize_allocation_failures(failures: list[str]) -> str:
    """把分配失败明细归成「主因 + 各类计数 + 该做什么」。

    原来是 ``"; ".join(failures[-6:])``：把互不相干的原因拼成一长串、还只留
    最后 6 条。主人看到的是「没有可分配的全新任务环境（代理池/出口 IP/画像
    去重失败）: 出口 IP 已在历史台账中: 1.2.3.4」—— 既看不出卡在哪个环节，
    也不知道该动什么。2026-09-29 的 50 次失败里绝大多数是「出口 IP 被用过」，
    但报错读起来像五种原因都有。

    这里按原因归类计数、主因排前，并附上对应动作。
    """
    if not failures:
        return "没有可分配的全新任务环境：代理池为空且未提供可用代理"

    # (判据子串, 类别名, 对应动作)
    #
    # ⚠️ 类别名刻意沿用它匹配到的原始措辞（"已在历史台账中""版本自洽"…）：
    #    这些字样是项目里的既有术语，别的代码和测试会按它们判断失败类型。
    #    2026-09-29 踩过：把"版本自洽"改写成"版本自相矛盾"，直接让
    #    test_protocol_realism 里那条断言失败 —— 归类可以新写，术语不能乱换。
    buckets = (
        ("已在历史台账中", "出口 IP 已在历史台账中（任务间出口需唯一）",
         "扩大代理池：多加几条不同地区的端点"),
        ("已被并发任务预留", "出口 IP 已被并发任务预留",
         "降低并发，或扩大代理池"),
        ("出口探测失败", "出口探测失败（网络/TLS）",
         "检查该代理是否可用"),
        ("没有配套画像", "出口国家没有配套画像",
         "给该地区补画像，或限定出口地区"),
        ("画像版本自洽", "画像版本自洽校验未通过",
         "查 fingerprint 版本一致性检查的输出"),
        ("不等于要求", "出口地区不等于要求",
         "核对 required_exit_country 与代理地区"),
    )
    counts = {name: 0 for _, name, _ in buckets}
    hints = {name: hint for _, name, hint in buckets}
    others = 0
    for item in failures:
        text = str(item or "")
        for marker, name, _ in buckets:
            if marker in text:
                counts[name] += 1
                break
        else:
            others += 1

    total = len(failures)
    ranked = sorted(((n, c) for n, c in counts.items() if c), key=lambda pair: -pair[1])
    if not ranked:
        sample = "；".join(str(x) for x in failures[-3:])
        return f"没有可分配的全新任务环境（共 {total} 次尝试）：{sample}"

    top_name, top_count = ranked[0]
    parts = [f"{top_name} ×{top_count}"]
    parts.extend(f"{name} ×{count}" for name, count in ranked[1:4])
    if others:
        parts.append(f"其他 ×{others}")
    return (
        f"没有可分配的全新任务环境（共 {total} 次尝试）："
        + "；".join(parts)
        + f"。主因「{top_name}」→ {hints[top_name]}"
    )


def allocate_environment(run_id: str, options: Mapping[str, Any]) -> dict[str, Any]:
    """Probe, generate, and atomically reserve one complete task environment.

    任务级不变量：
    1) 任务内稳定 —— 出口 IP 与指纹在分配时冻结，preflight/中途守卫保证
       整个任务只用这一条 IP、这一套指纹；
    2) 任务间唯一 —— exit_ip / fingerprint 在历史台账中有 UNIQUE 约束，
       每个新任务必须拿到从未用过的出口与指纹，绝不与上一个任务相同。
    """
    family, engine, prefer_firefox = _fingerprint_policy(options)
    try:
        timeout = float(options.get("environment_probe_timeout") or 15.0)
    except (TypeError, ValueError):
        timeout = 15.0
    timeout = max(3.0, min(timeout, 60.0))

    failures: list[str] = []
    candidates = _candidate_proxies(options)
    # 出口地区闸门：显式要求某个地区时，探测到别的地区直接换下一个候选，
    # 不让 PH/KH 这类非目标出口悄悄跑完整条注册链。
    required_country = str(
        options.get("require_exit_country")
        or db.get_setting("required_exit_country", "")
        or ""
    ).strip().upper()
    probe_country = required_country or str(
        options.get("fingerprint_country") or ""
    ).strip().upper()

    # ── 并行探测 ──
    # 背景（2026-09-26 实测）：同一批出口 IP 上 safari 探测 12/12 通过、
    # firefox147 只有 4/12（CF 对 firefox 的 403 拦截率高）。串行逐条探等于
    # 把 2/3 的探测时间浪费在注定失败的候选上，吞吐掉到三分之一。
    # 这里一次并发探 N 个候选，谁先通过就用谁；台账去重与指纹冻结仍在主线程
    # 串行完成，「探测指纹 = 任务指纹」「出口 IP/画像全历史唯一」不变。
    try:
        parallel = int(options.get("environment_probe_parallel") or 5)
    except (TypeError, ValueError):
        parallel = 5
    parallel = max(1, min(parallel, 8))

    def _probe_candidate(candidate: str):
        """探一条候选：生成探测指纹（种子留给任务复用）→ 种 oai-did。"""
        seed = secrets.randbits(64)
        try:
            probe_fingerprint = generate_fingerprint(
                rng=random.Random(seed),
                country_code=probe_country,
                browser_family=family,
                prefer_firefox=prefer_firefox,
                weighted=bool(options.get("fingerprint_weighted", True)),
            )
            observed = probe_exit(
                candidate,
                timeout=timeout,
                family=family,
                require_chatgpt=True,
                weighted=bool(options.get("fingerprint_weighted", True)),
                country_code=probe_country,
                fingerprint=probe_fingerprint,
            )
            return candidate, observed, None, seed
        except EnvironmentAllocationError as exc:
            return candidate, None, str(exc), seed

    # ── 渐进式探测（省流量）──
    # 以前一次性并行探 parallel 个候选、"谁先通过用谁"：通过的第一个虽然快，
    # 但剩下几个已经在飞，每个都要抓一次 chatgpt.com 首页（实测 359KB），
    # 平均每个任务白烧 ~1.4MB。现在改成先探 1 个（95% 的出口一次就过），
    # 这一批全失败才把并发翻倍，把流量花在真正需要的候选上。
    batch_size = 1
    cursor = 0
    while cursor < len(candidates):
        batch = candidates[cursor:cursor + batch_size]
        cursor += len(batch)
        if not batch:
            break
        executor = None
        parallel_batch = len(batch)
        if parallel_batch > 1:
            executor = ThreadPoolExecutor(max_workers=len(batch))
            futures = [executor.submit(_probe_candidate, item) for item in batch]
            results = (fut.result() for fut in as_completed(futures))
        else:
            results = iter([_probe_candidate(batch[0])])
        try:
            for proxy, observed, err, fingerprint_seed in results:
                if err is not None:
                    failures.append(err)
                    logger.warning("任务 %s 环境探测失败: %s", run_id, err)
                    continue

                if required_country and (observed.get("exit_country") or "").upper() != required_country:
                    failures.append(
                        f"出口地区 {observed.get('exit_country') or '未知'} "
                        f"不等于要求 {required_country}（{observed.get('exit_ip')}）"
                    )
                    logger.warning(
                        "任务 %s 出口地区不符：观察=%s 要求=%s ip=%s，换下一个候选",
                        run_id,
                        observed.get("exit_country"),
                        required_country,
                        observed.get("exit_ip"),
                    )
                    continue

                # 全球随机出口专用闸门：出口国在画像表里没有时区/语言配套时
                # 直接跳过。宁可换一个候选，也不要造出「出口在 A 国、画像却是
                # UTC/en-US」这种一眼假的环境（主人硬指定国家时不受此限）。
                observed_country_for_profile = (observed.get("exit_country") or "").upper()
                if (
                    observed_country_for_profile
                    and not has_country_profile(observed_country_for_profile)
                    and not str(options.get("fingerprint_country") or "").strip()
                ):
                    failures.append(
                        f"出口国家 {observed_country_for_profile} 没有配套画像（时区/语言对不上），跳过"
                    )
                    logger.warning(
                        "任务 %s 出口国家 %s 无画像配套，换下一个候选（ip=%s）",
                        run_id,
                        observed_country_for_profile,
                        observed.get("exit_ip"),
                    )
                    continue

                if db.environment_seen(exit_ip=observed["exit_ip"]):
                    failures.append(f"出口 IP 已在历史账本中: {observed['exit_ip']}")
                    continue

                profile_country, country_source = _requested_country(options, observed["exit_country"])
                if (
                    country_source == "manual"
                    and observed["exit_country"]
                    and observed["exit_country"] != profile_country
                ):
                    logger.info(
                        "任务 %s 使用手动地区 %s，出口探测为 %s；保留手动画像地区",
                        run_id,
                        profile_country,
                        observed["exit_country"],
                    )

                for attempt in range(32):
                    # 每轮换一个种子：以前每轮都用同一个 fingerprint_seed，
                    # 32 次抽出来的是同一套画像，签名撞了就 32 次原地打转，
                    # 最后报「画像去重失败」。第 0 轮必须用探测时的种子，
                    # 保证「探测指纹 = 任务指纹」的既有不变量。
                    fingerprint = generate_fingerprint(
                        rng=random.Random(fingerprint_seed + attempt),
                        country_code=profile_country,
                        browser_family=family,
                        prefer_firefox=prefer_firefox,
                        weighted=bool(options.get("fingerprint_weighted", True)),
                    )
                    # 版本自洽闸门：impersonate / UA / client hints / 头画像
                    # 必须说同一个版本号，否则宁可换一套，也不让任务带着
                    # 自相矛盾的画像出门。
                    version_report = check_version_consistency(fingerprint)
                    if not version_report["ok"]:
                        logger.warning(
                            "任务 %s 指纹版本自洽校验未通过，重新生成: %s",
                            run_id,
                            "; ".join(version_report["errors"])[:240],
                        )
                        failures.append("画像版本自洽校验未通过: " + "; ".join(version_report["errors"])[:120])
                        continue
                    signature = fingerprint_signature(fingerprint)
                    if db.environment_seen(fingerprint_signature=signature):
                        continue

                    environment = {
                        "allocation_id": f"{run_id}:{fingerprint['fingerprint_id']}",
                        "run_id": run_id,
                        "proxy": proxy,
                        "proxy_fingerprint": proxy_fingerprint(proxy),
                        "exit_ip": observed["exit_ip"],
                        "exit_country": observed["exit_country"],
                        "country_code": profile_country,
                        "country_source": country_source,
                        "browser_family": fingerprint["browser_family"],
                        "browser_engine": engine,
                        "fingerprint_id": fingerprint["fingerprint_id"],
                        "fingerprint_signature": signature,
                        "fingerprint": fingerprint,
                        "session_ttl_seconds": parse_session_ttl(proxy),
                        "session_reserved_at": time.time(),
                        "realism": {
                            "version": version_report,
                            "exit_country": observed.get("exit_country") or "",
                            "profile_country": profile_country or "",
                            "country_source": country_source,
                            "country_matches_exit": (
                                not observed.get("exit_country")
                                or not profile_country
                                or profile_country == observed.get("exit_country")
                                or country_source == "manual"
                            ),
                            "timezone": fingerprint.get("timezone") or "",
                            "lang": fingerprint.get("lang") or "",
                            "checked_at": time.time(),
                        },
                    }
                    if db.reserve_environment(run_id, environment):
                        logger.info(
                            "任务 %s 环境已冻结: ip=%s exit_country=%s profile_country=%s "
                            "fingerprint=%s proxy=%s 版本自洽=%s/%s/%s",
                            run_id,
                            observed["exit_ip"],
                            observed["exit_country"] or "N/A",
                            profile_country or "default",
                            fingerprint["fingerprint_id"],
                            environment["proxy_fingerprint"],
                            version_report["impersonate"],
                            version_report["ua_version"],
                            version_report["client_hint_version"] or "-",
                        )
                        return environment

                    # A concurrent task won the reservation between the existence check
                    # and INSERT. Generate another profile and let the unique constraints
                    # arbitrate the race again.
                    if db.environment_seen(exit_ip=observed["exit_ip"]):
                        failures.append(f"出口 IP 已被并发任务预留: {observed['exit_ip']}")
                        break
        finally:
            if executor is not None:
                executor.shutdown(wait=False)
        # 这一批没有任何可用候选取才走到这里 → 下一批把并发翻倍（封顶 parallel）
        batch_size = min(parallel, max(2, batch_size * 2))

    raise EnvironmentAllocationError(_summarize_allocation_failures(failures))
