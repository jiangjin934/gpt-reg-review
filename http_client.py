"""
HTTP 客户端 - 使用 curl_cffi 实现 TLS 指纹模拟
支持 Cloudflare 绕过，降级到 requests
"""
import json
import logging
import re
import threading
from typing import Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)


# ──────────────────────── 线程级流量计数 ────────────────────────
# 注册任务的每个 worker 独占一个线程，任务期间的所有 HTTP 会话都在这个线程里
# 收发。这里按线程累计字节数，registrar 在任务收尾时取一次快照写进 runs 表，
# 注册结果页就能显示「这个号用了多少流量」。
# 口径说明：只统计经过 create_http_session 的会话（含重试时的请求体），
# 不含请求头/连接开销，也不含绕过本模块直连的第三方 SDK —— 是近似值，不是
# 运营商账单口径。
_thread_traffic = threading.local()


def reset_thread_traffic() -> None:
    """任务开始时清零当前线程的流量计数。"""
    _thread_traffic.rx = 0
    _thread_traffic.tx = 0
    _thread_traffic.hosts = {}
    _thread_traffic.paths = {}
    _thread_traffic.redirects = {}


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlsplit

        return (urlsplit(str(url)).netloc or "?").split(":")[0]
    except Exception:  # noqa: BLE001
        return "?"


def _is_nextauth_error_url(url: str) -> bool:
    """NextAuth 的错误页（/api/auth/error、/auth/error）——整页 HTML 约 500KB。

    链路里只需要它的状态码/Location 来决定下一步，正文没有任何用途，
    所以这类 URL 一律不跟重定向，避免白拉半兆流量。
    """
    try:
        from urllib.parse import urlsplit

        path = urlsplit(str(url)).path or ""
    except Exception:  # noqa: BLE001
        return False
    return path.startswith("/api/auth/error") or path.startswith("/auth/error")


def add_thread_traffic(rx: int = 0, tx: int = 0, host: str = "") -> None:
    _thread_traffic.rx = int(getattr(_thread_traffic, "rx", 0)) + int(rx or 0)
    _thread_traffic.tx = int(getattr(_thread_traffic, "tx", 0)) + int(tx or 0)
    if host:
        hosts = getattr(_thread_traffic, "hosts", None)
        if not isinstance(hosts, dict):
            hosts = {}
            _thread_traffic.hosts = hosts
        slot = hosts.setdefault(host, {"rx": 0, "tx": 0})
        slot["rx"] += int(rx or 0)
        slot["tx"] += int(tx or 0)


def count_thread_request(url: str, rx: int = 0) -> None:
    """按 host+path 记请求次数与字节（只留前 60 个，避免长任务无限增长）。"""
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(str(url))
        key = f"{parts.netloc.split(':')[0]}{parts.path}"
    except Exception:  # noqa: BLE001
        key = "?"
    paths = getattr(_thread_traffic, "paths", None)
    if not isinstance(paths, dict):
        paths = {}
        _thread_traffic.paths = paths
    if key not in paths and len(paths) >= 60:
        return
    slot = paths.setdefault(key, {"n": 0, "rx": 0})
    slot["n"] += 1
    slot["rx"] += int(rx or 0)


def note_thread_redirect(url: str, final_url: str, rx: int = 0) -> None:
    """记录一次重定向（请求 URL → 最终 URL），排查"跟到错误页白拉几百 KB"。"""
    try:
        from urllib.parse import urlsplit

        def key_of(value: str) -> str:
            parts = urlsplit(str(value))
            return f"{parts.netloc.split(':')[0]}{parts.path}"

        key = f"{key_of(url)} -> {key_of(final_url)}"
    except Exception:  # noqa: BLE001
        return
    redirects = getattr(_thread_traffic, "redirects", None)
    if not isinstance(redirects, dict):
        redirects = {}
        _thread_traffic.redirects = redirects
    if key not in redirects and len(redirects) >= 30:
        return
    slot = redirects.setdefault(key, {"n": 0, "rx": 0})
    slot["n"] += 1
    slot["rx"] += int(rx or 0)


def thread_traffic() -> dict:
    return {
        "rx": int(getattr(_thread_traffic, "rx", 0)),
        "tx": int(getattr(_thread_traffic, "tx", 0)),
        "hosts": {
            host: {"rx": int(v.get("rx") or 0), "tx": int(v.get("tx") or 0)}
            for host, v in (getattr(_thread_traffic, "hosts", {}) or {}).items()
        },
        "paths": {
            key: {"n": int(v.get("n") or 0), "rx": int(v.get("rx") or 0)}
            for key, v in (getattr(_thread_traffic, "paths", {}) or {}).items()
        },
        "redirects": {
            key: {"n": int(v.get("n") or 0), "rx": int(v.get("rx") or 0)}
            for key, v in (getattr(_thread_traffic, "redirects", {}) or {}).items()
        },
    }


def _response_bytes(resp) -> int:
    try:
        content = getattr(resp, "content", None)
        if content is None:
            content = getattr(resp, "text", "") or ""
        if isinstance(content, (bytes, bytearray)):
            return len(content)
        return len(str(content).encode("utf-8", "ignore"))
    except Exception:  # noqa: BLE001
        return 0


def _request_bytes(args, kwargs) -> int:
    total = 0
    try:
        data = kwargs.get("data")
        if data is None and len(args) > 1:
            data = args[1]
        if data is not None:
            total += len(data) if isinstance(data, (bytes, bytearray)) else len(
                str(data).encode("utf-8", "ignore")
            )
        body = kwargs.get("json")
        if body is not None:
            total += len(json.dumps(body).encode("utf-8", "ignore"))
    except Exception:  # noqa: BLE001
        pass
    return total

# 尝试使用 curl_cffi（推荐，自带 TLS 指纹模拟）
try:
    from curl_cffi.requests import Session as CffiSession

    _HAS_CFFI = True
    logger.debug("curl_cffi 可用，使用 TLS 指纹模拟")
except ImportError:
    _HAS_CFFI = False
    logger.debug("curl_cffi 不可用，降级到 requests")

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 通用 UA（fallback，优先使用 fingerprint.generate_fingerprint() 生成的值）
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
)

# 连接建立阶段的瞬断标记（与 AuthFlow._is_tls_error 保持同一套口径）：
#   35 = TLS 握手瞬断；56 = 连接被对端重置；97 = SOCKS 代理关闭连接。
# 三类都发生在请求真正发出之前，服务端没有收到任何字节，原 session 重试安全。
# curl 28（超时）不在此列：请求可能已送达而响应丢失，重试有重复提交风险。
_TLS_ERROR_MARKERS = (
    "curl: (35)",
    "curl: (56)",
    "curl: (97)",
    "tls connect error",
    "openssl_internal",
    "sslerror",
)


_PROXY_SCHEME_RE = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.-]*)://(?P<rest>.+)$", re.I)


def normalize_proxy_url(proxy: Optional[str]) -> str:
    """Normalize the proxy formats accepted by the WebUI.

    The UI accepts normal URLs such as ``socks5h://user:pass@host:port``.
    Residential proxy vendors commonly export the equivalent as
    ``host:port:user:pass``.  Treat that four-field form as SOCKS5 with remote
    DNS so allocation probes and the registration client use the same route.
    Existing URLs and bare ``host:port`` values are preserved.
    """
    value = str(proxy or "").strip()
    if not value:
        return ""

    match = _PROXY_SCHEME_RE.match(value)
    if match:
        scheme = match.group("scheme").lower()
        if scheme == "socks5":
            scheme = "socks5h"
        return f"{scheme}://{match.group('rest')}"

    # Vendor export: host:port:username:password.  Split only the first three
    # separators so a password containing ':' remains intact.
    parts = value.split(":", 3)
    if len(parts) == 4 and parts[1].isdigit() and parts[0] and parts[2] and parts[3]:
        host, port, username, password = parts
        return (
            "socks5h://"
            f"{quote(username, safe='')}:{quote(password, safe='')}"
            f"@{host}:{port}"
        )
    return value


def _is_tls_handshake_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(m in msg for m in _TLS_ERROR_MARKERS)


class _TlsRetrySession:
    """给 session 的 get/post 套一层 TLS 瞬断重试，其余属性原样透传。

    ── 为什么要有这东西 ──
    代理链路会偶发 `curl: (35) TLS connect error ... OPENSSL_internal`，
    连 HTTP 请求都没发出去就炸。2026-08-10 实测（148 轮扫描）：

        发生率            5.4%（8/148）
        与指纹的关系      无 —— chrome146/142/136、safari18_0/15_3、firefox133 都中过
        与域名的关系      无 —— chatgpt.com 3/25、auth.openai.com 1/25，
                          且见过同一轮两个域一起炸（那一路出口链路整个坏了）

    换句话说这是**链路级瞬断**，不是风控、不是指纹问题，摘掉任何一个指纹都没用。

    ── 为什么必须原 session 重试，不能重建 ──
    warmup 那处的重试是重建 session（换出口 IP），因为那时还没 cookie。
    但链路中后段（auth_oauth_init / sentinel / authorize_continue …）session 里
    已经装着 warmup 种的 oai-did 和 csrf，**一重建就全丢，直接变 409 invalid_state**
    —— 那正是上一轮刚修好的病。所以这里只重试，绝不碰 session。

    实测原 session 重试的效果（8 次 TLS35 事件全部捕获后立即重试）：

        恢复 8/8，全部**第 1 次重试就成功**，恢复后 oai-did 仍在 8/8

    ── 为什么包在 session 层，而不是逐个调用点加 try ──
    这个错能打在链上**任意一步**。主人 2026-08-10 那批 10 个号的两次失败就分别
    炸在 `[3/10] auth_oauth_init` 和 `[4/10] sentinel`（后者还被 sentinel_quickjs
    的 catch-all 吞成 "QuickJS 失败/主 token 缺失"，真因全被掩盖）。auth_flow 里
    有 35 处 session.get/post，且 sentinel.py 是直接拿 session 对象自己发请求的，
    逐点打补丁既治不完也漏得到 —— 包在出口这一层才是一次覆盖全部。

    ── 透传安全性（已实测）──
    全项目在 session 上访问的非 get/post 属性只有 cookies(20处) / trust_env(3) /
    proxies(3) / mount(2) / headers(1)，实测包装后全部行为一致：
    cookies.get_dict() / cookies.get() / cookies.jar / 迭代 / __setattr__ 透传均 OK。
    （注：迭代 session.cookies 产出的是 str 而非 Cookie 对象、拿不到 .name，
    这是 curl_cffi **原生行为**，包装前后一致，与本类无关。）
    """

    def __init__(self, inner, retries: int = 2, backoff: float = 1.5):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_retries", max(0, int(retries)))
        object.__setattr__(self, "_backoff", float(backoff))

    # 除 get/post 外的一切读写都直达真 session
    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_inner"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_inner"), name, value)

    def __iter__(self):
        return iter(object.__getattribute__(self, "_inner"))

    def _call_with_retry(self, method: str, *args, **kwargs):
        import time

        inner = object.__getattribute__(self, "_inner")
        retries = object.__getattribute__(self, "_retries")
        backoff = object.__getattribute__(self, "_backoff")
        fn = getattr(inner, method)
        request_url = args[0] if args else kwargs.get("url", "")
        # 错误页正文没有任何用途：不跟随重定向，省掉 ~500KB/次。
        # 无条件生效：错误页正文对任何调用方都没有用途，跟着重定向就是白拉
        # 半兆 HTML（实测占单任务流量 24%）。调用方仍然能拿到 302 + Location。
        if _is_nextauth_error_url(request_url):
            kwargs = dict(kwargs, allow_redirects=False)

        for attempt in range(retries + 1):
            # 请求体字节先记：失败重试的请求也是真花出去的流量。
            url = args[0] if args else kwargs.get("url", "")
            host = _host_of(url)
            add_thread_traffic(tx=_request_bytes(args, kwargs), host=host)
            try:
                resp = fn(*args, **kwargs)
                rbytes = _response_bytes(resp)
                add_thread_traffic(rx=rbytes, host=host)
                count_thread_request(url, rbytes)
                final_url = str(getattr(resp, "url", "") or "")
                if final_url and final_url != str(url):
                    note_thread_redirect(url, final_url, rbytes)
                return resp
            except Exception as e:
                # 只兜 TLS 瞬断：HTTP 错误码、超时、业务异常一律原样抛，
                # 免得把"服务端明确拒绝"也变成重试，反而更像异常流量。
                if not _is_tls_handshake_error(e) or attempt >= retries:
                    raise
                wait = backoff * (attempt + 1)
                url = args[0] if args else kwargs.get("url", "?")
                logger.warning(
                    "TLS 瞬断，%.1fs 后原 session 重试 (%d/%d): %s",
                    wait, attempt + 1, retries, str(url)[:80],
                )
                time.sleep(wait)

    def get(self, *args, **kwargs):
        return self._call_with_retry("get", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._call_with_retry("post", *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._call_with_retry("put", *args, **kwargs)


def create_http_session(
    proxy: Optional[str] = None,
    impersonate: str = "safari18_0",
    user_agent: Optional[str] = None,
):
    """
    创建 HTTP 会话。优先使用 curl_cffi 模拟浏览器 TLS 指纹，
    不可用时降级到 requests。
    """
    normalized_proxy = normalize_proxy_url(proxy)
    if _HAS_CFFI:
        # ── 显式锁定 HTTP/2（防御性）──
        # 实测（2026-09-29）：curl_cffi 的 impersonate 本来就协商到 HTTP/2.0
        # （CURLINFO_HTTP_VERSION=3 即 CURL_HTTP_VERSION_2_0，HTTP/3 是 30），
        # 且指纹数据带浏览器精确的 HTTP2 SETTINGS / 伪头顺序 / STREAM_WEIGHT。
        # 这里显式写死 V2_0 是为了防未来某个指纹把 http_version 换成 v3：
        # QUIC 走 UDP，在 SOCKS5 链路上极不稳定（"15 秒超时 0 字节"类故障的
        # 疑似诱因），而 curl 的 QUIC 指纹与真实 Chrome 差异也更大。
        try:
            from curl_cffi.const import CurlHttpVersion

            session = CffiSession(impersonate=impersonate,
                                  http_version=CurlHttpVersion.V2_0)
        except Exception:  # noqa: BLE001
            session = CffiSession(impersonate=impersonate)
        # 使用显式配置，避免被系统 HTTP(S)_PROXY 隐式污染。
        session.trust_env = False
        if normalized_proxy:
            # curl_cffi 在 SOCKS 代理下建议使用 socks5h，让 DNS 走代理端解析。
            # 这能减少本地 DNS/链路导致的 TLS 握手异常。
            session.proxies = {"https": normalized_proxy, "http": normalized_proxy}
        else:
            # 显式设置空代理，覆盖系统环境变量 (trust_env=False 对 libcurl 不够)
            session.proxies = {"https": "", "http": ""}
        # 代理链路 5.4% 偶发 TLS 瞬断，原 session 重试实测 8/8 一次即恢复。
        # 包在这里才能同时覆盖 auth_flow 的 35 处调用和 sentinel（它直接拿 session 自己发请求）。
        return _TlsRetrySession(session)
    else:
        session = requests.Session()
        session.trust_env = False
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        if normalized_proxy:
            session.proxies = {"https": normalized_proxy, "http": normalized_proxy}
        session.headers["User-Agent"] = user_agent or USER_AGENT
        return session
