"""mail.com 母号 + 别名域名 provider（dr.com / post.com 等）。

mail.com 的机制：一个母号（如 user@mail.com）最多可挂 10 个别名地址，
别名可以用平台 100+ 个顶级域名里的任意一个（dr.com、post.com…），
发到别名的信落在母号同一个收件箱，登录也是同一个密码。

对换绑场景的意义：目标地址用「随机前缀@dr.com」，OpenAI 当新邮箱处理，
OTP 走母号 IMAP 取件，别名本身用 mail.com 官方 web settings API 现场创建。

    pooled=True     母号是有限的导入资源，用完（别名满 / 凭证废）换下一个
    ephemeral=True  每个目标地址现场新建（随机前缀），OpenAI 永远当新号

别名创建走 mail.com 官方 web OAuth / CATS 流程（与浏览器版邮件设置同一套
接口），协议参考开源实现 maildotcom-sdk（MIT）逐端口：
  https://github.com/tanu360/maildotcom-sdk/blob/main/src/web-aliases.ts

取件走 IMAP：imap.mail.com:993，母号 + 密码登录。
官方文档称 IMAP 是 Premium 功能，但实测免费号 IMAP 可用。
"""
from __future__ import annotations

import email as _email
import email.utils as _eu
import html as _html
import imaplib
import json as _json
import logging
import random
import re
import string
import threading
import time
from typing import Optional
from urllib.parse import urljoin

from .base import ConfigField, MailProvider, MailProviderError, register, validate_email
from .outlook import _check_from_domain, _extract_otp_from_html

logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════
#  web settings OAuth / CATS 常量（与官方 webmail 一致的客户端身份）
# ════════════════════════════════════════════════════════════

WEB_OAUTH_CLIENT_ID = "mailcom_mailcheck_chrome"
WEB_OAUTH_REDIRECT_URI = "https://lpebgcnlaohcgdfhbffjajlnpifdkllg.chromiumapp.org/"
WEB_OAUTH_BASIC_AUTH = (
    "Basic bWFpbGNvbV9tYWlsY2hlY2tfY2hyb21lOnRJWkNZWjFZOFFhNUt0MjJMVXJXSDJTc29td1VhV1F5dGszWWdNem4="
)
SETTINGS_OAUTH_BASIC_AUTH = "Basic bWFpbGNvbV9tYWlsc2V0X3Jvb3RfbGl2ZToqKioqKioq"
MAIL_SETTINGS_PARTNER_DATA = (
    "eyJ1c2VjYXNlIjoiaW5ib3hfdW5yZWFkIiwiYXJncyI6W10sImlkIjoyLCJjYWxsZXJfYXBwIjoidG9vbGJhciIsImNhbGxlcl92ZXJzaW9uIjoiQ2hyb21lLzguMC41LjAifQ=="
)
SETTINGS_CATS_BASE_URL = "https://settings-cats.mail.com"
SETTINGS_OAUTH_BRIDGE_URL = "https://oauthbridge.navigator-lxa.mail.com/navigator/oauth2/token"
SETTINGS_OAUTH_GRANT_TYPE = "urn:mam:oauth:grant-type:spa"
SETTINGS_OAUTH_SCOPE = "mail_mailbox_w webmailer_setting_r webmailer_setting_w mail_confix_w"
SETTINGS_UI_APP = "mailcom.mailset-compose/1.0.5-build.322"
WEB_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/149.0.0.0 Safari/537.36"
)

IMAP_HOST = "imap.mail.com"
IMAP_PORT = 993
ALIAS_LIMIT = 10

# settings access token 缓存：同一母号一次登录重复用，降低批量换绑的登录开销。
_TOKEN_CACHE: dict[str, tuple[float, str]] = {}
_TOKEN_CACHE_LOCK = threading.Lock()
_TOKEN_CACHE_TTL = 20 * 60  # 秒


def _random_local_part(prefix: str = "gc", length: int = 12) -> str:
    charset = string.ascii_lowercase + string.digits
    return prefix + "".join(random.choices(charset, k=length))


def _html_decode(value: str) -> str:
    return (
        value.replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&#x27;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
    )


class MailComAliasError(MailProviderError):
    """别名创建链路错误。fatal 表示母号本身不可用（凭证废 / 别名已满）。"""


class _HttpSession:
    """curl_cffi 优先（模拟 Chrome 指纹过防护），requests 兜底。"""

    def __init__(self):
        self._impl = None
        try:
            from curl_cffi.requests import Session as CffiSession

            self._impl = CffiSession(impersonate="chrome136")
            try:
                self._impl.trust_env = False
            except Exception:
                pass
        except ImportError:
            import requests

            self._impl = requests.Session()
        self._impl.headers.update({
            "User-Agent": WEB_USER_AGENT,
            "Accept-Language": "en-US,en;q=0.9",
        })

    def request(self, method: str, url: str, *, headers=None, data=None, timeout=30):
        kwargs = {"headers": headers or {}, "timeout": timeout, "allow_redirects": False}
        if data is not None:
            kwargs["data"] = data
        resp = self._impl.request(method, url, **kwargs)
        return _Response(resp)

    def close(self):
        try:
            self._impl.close()
        except Exception:
            pass


class _Response:
    def __init__(self, raw):
        self._raw = raw

    @property
    def status_code(self) -> int:
        return int(getattr(self._raw, "status_code", 0) or 0)

    @property
    def headers(self):
        return getattr(self._raw, "headers", {}) or {}

    @property
    def text(self) -> str:
        try:
            return self._raw.text or ""
        except Exception:
            return ""

    def json(self) -> dict:
        try:
            data = self._raw.json()
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def location(self) -> str:
        return str(self.headers.get("location") or self.headers.get("Location") or "")


def _is_redirect(status: int) -> bool:
    return 300 <= status < 400


class MailComAliasClient:
    """mail.com 母号的别名管理客户端（官方 web settings OAuth/CATS 协议）。"""

    def __init__(self, email: str, password: str, session: Optional[_HttpSession] = None):
        if not email or not password:
            raise MailComAliasError("mail.com 母号缺 email/password", fatal=True)
        self.email = email.strip().lower()
        self.password = password
        self.session = session or _HttpSession()
        self._settings_token: str = ""

    # ──────────────────────── 登录（settings token）────────────────────────

    def login(self) -> str:
        cached = _token_from_cache(self.email)
        if cached:
            self._settings_token = cached
            return cached
        self._settings_token = self._open_settings_session()
        _token_to_cache(self.email, self._settings_token)
        return self._settings_token

    def _open_settings_session(self) -> str:
        state = "".join(random.choices(string.hexdigits.lower(), k=24))
        params = {
            "client_id": WEB_OAUTH_CLIENT_ID,
            "redirect_uri": WEB_OAUTH_REDIRECT_URI,
            "scope": "mailbox_user_status_access mailbox_user_full_access login",
            "response_type": "code",
            "hl": "en-US",
            "state": state,
            "login_hint": self.email,
        }
        authorize_url = _with_query("https://oauth2.mail.com/authorize", params)
        authorize = self.session.request(
            "GET", authorize_url,
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        mlogin_url = self._redirect_location(authorize, authorize_url)

        mlogin = self.session.request(
            "GET", mlogin_url,
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        login_params = _login_form_params(mlogin.text, mlogin_url)
        login_params["username"] = self.email
        login_params["password"] = self.password

        login = self.session.request(
            "POST", "https://login.mail.com/login",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://mlogin.mail.com",
                "Referer": mlogin_url,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            data=login_params,
        )
        authcode_url = self._redirect_location(login, "https://login.mail.com/")
        authcode = self.session.request(
            "GET", authcode_url,
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        callback_url = self._redirect_location(authcode, "https://oauth2.mail.com/")
        callback = _parse_url(callback_url)
        code = callback.query.get("code")
        if not code:
            raise MailComAliasError(
                "mail.com 登录未返回授权码（可能触发验证码/风控，或密码错误）", fatal=True
            )
        if callback.query.get("state") != state:
            raise MailComAliasError("mail.com 登录 state 校验失败", fatal=False)

        token_resp = self.session.request(
            "POST", "https://oauth2.mail.com/token",
            headers={
                "Authorization": WEB_OAUTH_BASIC_AUTH,
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "code": code,
                "client_id": WEB_OAUTH_CLIENT_ID,
                "redirect_uri": WEB_OAUTH_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )
        token = token_resp.json()
        access_token = token.get("access_token")
        if not access_token:
            raise MailComAliasError("mail.com OAuth 未返回 access_token", fatal=True)

        oauth2login = self.session.request(
            "POST", "https://login.mail.com/oauth2login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "service": "mailint",
                "origin": "toolbar",
                "access_token": access_token,
                "successURL": "https://navigator-lxa.mail.com/login",
                "loginFailedURL": "http://www.mail.com/?status=nologin",
                "loginErrorURL": "http://www.mail.com/?status=nologin",
                "statistics": "",
                "partnerdata": MAIL_SETTINGS_PARTNER_DATA,
            },
        )
        navigator_login_url = _parse_url(self._redirect_location(oauth2login, "https://login.mail.com/"))
        self.session.request(
            "GET", navigator_login_url.full,
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        navigator_login_url.path = "/halogin"
        navigator_login_url.query["tz"] = "8"
        halogin = self.session.request(
            "GET", navigator_login_url.full,
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        navigator_root_url = _parse_url(self._redirect_location(halogin, navigator_login_url.full))
        sid = navigator_root_url.query.get("sid")
        if not sid:
            raise MailComAliasError("mail.com navigator 未返回 session id", fatal=True)
        self.session.request(
            "GET", navigator_root_url.full,
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )

        bridge_url = _parse_url(SETTINGS_OAUTH_BRIDGE_URL)
        bridge_url.query["sid"] = sid
        settings_token_resp = self.session.request(
            "POST", bridge_url.full,
            headers={
                "Authorization": SETTINGS_OAUTH_BASIC_AUTH,
                "Accept": "*/*",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://mailset-root.mail.com",
                "Referer": "https://mailset-root.mail.com/",
            },
            data={
                "grant_type": SETTINGS_OAUTH_GRANT_TYPE,
                "scope": SETTINGS_OAUTH_SCOPE,
            },
        )
        settings_token = settings_token_resp.json()
        token_value = settings_token.get("access_token")
        if not token_value:
            raise MailComAliasError("mail.com settings bridge 未返回 access_token", fatal=True)
        return token_value

    def _redirect_location(self, resp: _Response, base: str) -> str:
        if not _is_redirect(resp.status_code):
            raise MailComAliasError(
                f"mail.com 流程期望 3xx 跳转，实际 HTTP {resp.status_code}", fatal=False
            )
        location = resp.location()
        if not location:
            raise MailComAliasError("mail.com 跳转缺少 Location", fatal=False)
        return urljoin(base, location)

    # ──────────────────────── settings API ────────────────────────

    def _settings_request(self, method: str, path: str, *, headers=None, body=None) -> _Response:
        token = self.login()
        full_headers = dict(headers or {})
        full_headers.update({
            "Authorization": f"Bearer {token}",
            "Origin": "https://mailset-root.mail.com",
            "Referer": "https://mailset-root.mail.com/",
            "X-UI-App": SETTINGS_UI_APP,
            "X-Request-ID": _random_local_part("", 32),
        })
        url = urljoin(SETTINGS_CATS_BASE_URL + "/", path)
        resp = self.session.request(method, url, headers=full_headers, data=body)
        if resp.status_code == 401 and token == _token_from_cache(self.email):
            _token_clear(self.email)
            self._settings_token = ""
            token = self.login()
            full_headers["Authorization"] = f"Bearer {token}"
            resp = self.session.request(method, url, headers=full_headers, data=body)
        if resp.status_code not in (200, 201, 204):
            raise MailComAliasError(
                f"mail.com settings {method} {path} HTTP {resp.status_code}", fatal=False
            )
        return resp

    def list_aliases(self) -> list[dict]:
        resp = self._settings_request(
            "GET",
            "/mailaccount/primary/emailAddresses?absoluteURI=false"
            "&q.state.in=ACTIVE&q.type.in=MANAGED%2CDOMAIN_HOSTING",
            headers={
                "Accept": "application/vnd.ui.trinity.mailaddress.list-v5+json",
                "Content-Type": "application/vnd.ui.trinity.mailaddress.list-v5+json",
            },
        )
        data = resp.json()
        items = data.get("mailaddresslist") or []
        return [item for item in items if isinstance(item, dict)]

    def available_domains(self) -> list[str]:
        resp = self._settings_request(
            "GET",
            "/domains?absoluteURI=false&q.state.eq=ACTIVE&q.legacySupport.eq=true",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        data = resp.json()
        domains = data.get("domains") or []
        out = []
        for item in domains:
            if isinstance(item, dict) and (item.get("domain") or "").strip():
                out.append(item["domain"].strip().lower())
        return out

    def _validate_address(self, address: str) -> None:
        resp = self._settings_request(
            "POST",
            "/mailaccount/emailAddressValidations?absoluteURI=false",
            headers={
                "Accept": "application/vnd.ui.trinity.email-address-validation-response+json",
                "Content-Type": "application/vnd.ui.trinity.email-address-validation-request+json",
            },
            body=_json.dumps([address]),
        )
        if resp.json():
            raise MailComAliasError(f"别名不可用: {address}", fatal=False)

    def create_alias(self, address: str) -> str:
        address = address.strip().lower()
        _validate_alias_address(address)

        aliases = self.list_aliases()
        if len(aliases) >= ALIAS_LIMIT:
            raise MailComAliasError(
                f"母号 {self.email} 别名已满（{ALIAS_LIMIT} 个上限）", fatal=True
            )
        if any((a.get("address") or "").lower() == address for a in aliases):
            raise MailComAliasError(f"别名已存在: {address}", fatal=False)

        domain = address.rsplit("@", 1)[1]
        if domain not in self.available_domains():
            raise MailComAliasError(f"母号不支持该别名域名: {domain}", fatal=False)
        self._validate_address(address)

        self._settings_request(
            "POST",
            "/mailaccount/primary/emailAddresses?absoluteURI=false",
            headers={
                "Accept": "application/vnd.ui.trinity.minimalmailaddress-v3+json",
                "Content-Type": "application/vnd.ui.trinity.minimalmailaddress-v3+json",
            },
            body=_json.dumps({
                "address": address,
                "deletable": True,
                "pgpEnabled": False,
                "defaultSenderAddress": False,
                "defaultReceiverAddress": False,
                "state": "ACTIVE",
            }),
        )

        for attempt in range(4):
            if any((a.get("address") or "").lower() == address for a in self.list_aliases()):
                logger.info("[mail_com] 创建别名成功: %s (母号 %s)", address, self.email)
                return address
            if attempt < 3:
                time.sleep(1 + attempt)
        raise MailComAliasError(f"别名创建未确认: {address}", fatal=False)

    def delete_alias(self, address: str) -> None:
        """删除一个别名（回收名额）。母号被删或不存在时抛非致命错误。"""
        normalized = address.strip().lower()
        match = next(
            (a for a in self.list_aliases() if (a.get("address") or "").lower() == normalized),
            None,
        )
        if not match:
            raise MailComAliasError(f"别名不存在: {normalized}", fatal=False)
        if match.get("deletable") is False:
            raise MailComAliasError(f"别名不允许删除: {normalized}", fatal=False)
        self._settings_request(
            "POST",
            "/mailaccount/primary/emailAddressesRemovals/"
            f"{_url_quote(normalized)}/removals?absoluteURI=false",
            headers={
                "Accept": "text/plain;charset=UTF-8",
                "Content-Type": "text/plain;charset=UTF-8",
            },
        )
        for attempt in range(4):
            if not any(
                (a.get("address") or "").lower() == normalized
                for a in self.list_aliases()
            ):
                logger.info("[mail_com] 删除别名成功: %s (母号 %s)", normalized, self.email)
                return
            if attempt < 3:
                time.sleep(1 + attempt)
        raise MailComAliasError(f"别名删除未确认: {normalized}", fatal=False)

    def close(self) -> None:
        self.session.close()


def _with_query(url: str, params: dict) -> str:
    from urllib.parse import urlencode

    return f"{url}?{urlencode(params)}"


def _login_form_params(html_text: str, page_url: str) -> dict:
    params: dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", html_text, re.IGNORECASE):
        name_m = re.search(r"\bname=([\"'])(.*?)\1", tag, re.IGNORECASE)
        if not name_m:
            continue
        name = name_m.group(2)
        value_m = re.search(r"\bvalue=([\"'])(.*?)\1", tag, re.IGNORECASE)
        params[name] = _html_decode(value_m.group(2) if value_m else "")
    if "service" not in params:
        params["service"] = "oauth2"
    if "successURL" not in params:
        parsed = _parse_url(page_url)
        authcode_context = parsed.query.get("authcode-context")
        if not authcode_context:
            raise MailComAliasError("mail.com 登录页缺少 authcode-context", fatal=False)
        params["successURL"] = (
            f"https://oauth2.mail.com/authcode?authcode-context={authcode_context}"
        )
        login_hint = parsed.query.get("login_hint") or ""
        params["loginFailedURL"] = (
            "https://mlogin.mail.com/oauth2/?status=login-failed"
            f"&login_hint={_url_quote(login_hint)}&authcode-context={authcode_context}"
        )
        params["loginErrorURL"] = "https://mlogin.mail.com/loginapplication/error/loginerror"
    return params


def _url_quote(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


class _ParsedUrl:
    def __init__(self):
        self.base = ""
        self.path = "/"
        self.query: dict[str, str] = {}

    @property
    def full(self) -> str:
        from urllib.parse import urlencode

        return (
            f"{self.base}{self.path}"
            + (f"?{urlencode(self.query)}" if self.query else "")
        )


def _parse_url(url: str) -> _ParsedUrl:
    from urllib.parse import urlsplit, parse_qsl

    parts = urlsplit(url)
    out = _ParsedUrl()
    out.base = f"{parts.scheme}://{parts.netloc}"
    out.path = parts.path or "/"
    out.query = dict(parse_qsl(parts.query, keep_blank_values=True))
    return out


def _validate_alias_address(address: str) -> None:
    local, _, domain = address.partition("@")
    if not local or not domain or address.count("@") != 1:
        raise MailComAliasError(f"别名地址无效: {address}", fatal=False)
    if not re.fullmatch(r"[a-z0-9._-]{3,62}", local):
        raise MailComAliasError(
            "别名前缀必须为 3-62 位字母/数字/点/横杠/下划线", fatal=False
        )
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", domain):
        raise MailComAliasError(f"别名域名无效: {domain}", fatal=False)


# ════════════════════════════════════════════════════════════
#  settings token 进程级缓存
# ════════════════════════════════════════════════════════════

def _token_from_cache(email: str) -> str:
    with _TOKEN_CACHE_LOCK:
        hit = _TOKEN_CACHE.get(email.lower())
        if not hit:
            return ""
        created, token = hit
        if time.time() - created > _TOKEN_CACHE_TTL:
            _TOKEN_CACHE.pop(email.lower(), None)
            return ""
        return token


def _token_to_cache(email: str, token: str) -> None:
    with _TOKEN_CACHE_LOCK:
        _TOKEN_CACHE[email.lower()] = (time.time(), token)


def _token_clear(email: str) -> None:
    with _TOKEN_CACHE_LOCK:
        _TOKEN_CACHE.pop(email.lower(), None)


# ════════════════════════════════════════════════════════════
#  MailProvider 适配
# ════════════════════════════════════════════════════════════

@register
class MailComMailProvider(MailProvider):
    """mail.com 母号 provider：别名现场造，OTP 走母号 IMAP。"""

    kind = "mail_com"
    display_name = "mail.com 母号（别名域名）"
    pooled = True           # 母号有限，别名满 / 凭证废换下一个
    ephemeral = True        # 每次创建全新别名地址

    line_segments = 2
    import_hint = "每行一个：email----password（mail.com 母号 + 密码）"
    import_placeholder = "you@mail.com----Pass123"

    config_fields = [
        ConfigField(
            "mail_com_alias_domain",
            "别名域名",
            placeholder="dr.com",
            help="目标别名使用的 mail.com 域名（dr.com / post.com 等）",
        ),
    ]

    def __init__(
        self,
        email: str,
        password: str,
        alias_domain: str = "dr.com",
        session=None,
    ):
        if not email or not password:
            raise MailProviderError("mail_com 需要母号 email 和 password", fatal=True)
        self.email = email.strip().lower()
        self.password = password
        self.alias_domain = (alias_domain or "dr.com").strip().lower().lstrip("@")
        self.last_persona = None
        self._dead = False
        self._alias_client = MailComAliasClient(
            self.email, self.password,
            session=session if session is not None else _HttpSession(),
        )

    # ── 构造入口 ─────────────────────────────────────────

    @classmethod
    def from_config(cls, settings: dict, account: Optional[dict] = None):
        if not account:
            raise ValueError("mail_com provider 需要从号池 claim 到的母号 account")
        domain = (settings.get("mail_com_alias_domain") or "dr.com").strip().lower().lstrip("@")
        return cls(
            email=account["email"],
            password=account.get("password") or "",
            alias_domain=domain or "dr.com",
        )

    @classmethod
    def parse_line(cls, line: str) -> dict:
        parts = [p.strip() for p in line.split("----")]
        if len(parts) != 2:
            raise ValueError(
                f"需要 2 段（email----password），实际 {len(parts)} 段"
            )
        email, password = parts
        validate_email(email)
        if not password:
            raise ValueError("password 为空")
        return {"email": email.lower(), "password": password, "kind": cls.kind}

    # ── 号池语义 ─────────────────────────────────────────

    @property
    def exhausted(self) -> bool:
        return self._dead

    def mark_dead(self, reason: str = "") -> None:
        logger.warning("[mail_com] 母号 %s mark dead: %s", self.email, reason)
        self._dead = True

    # ── 别名创建 ─────────────────────────────────────────

    def create_mailbox(self) -> str:
        """现场造一个别名，返回别名地址。"""
        last_error: Optional[Exception] = None
        for _ in range(5):
            address = f"{_random_local_part()}@{self.alias_domain}"
            try:
                return self._alias_client.create_alias(address)
            except MailComAliasError as exc:
                last_error = exc
                if exc.fatal:
                    raise MailProviderError(
                        f"mail.com 母号 {self.email} 不可用: {exc}",
                        fatal=True, kind="mail_com_alias",
                    )
                # 非致命：地址被占或流程抖动，换个随机前缀重试
                logger.debug("[mail_com] 别名创建重试: %s", exc)
                continue
        raise MailProviderError(
            f"mail.com 别名创建失败: {last_error}", fatal=False, kind="mail_com_alias"
        )

    def delete_mailbox(self, address: str) -> None:
        """回收一个还没提交给 OpenAI 的别名（换绑失败时清理用）。"""
        self._alias_client.delete_alias(address)

    # ── OTP 取件（母号 IMAP，过滤 To=别名）────────────────

    def wait_for_otp(
        self,
        email_addr: str,
        timeout: int = 120,
        issued_after: Optional[float] = None,
    ) -> str:
        timeout = max(int(timeout), 60)
        deadline = time.time() + timeout
        threshold = (issued_after - 5) if issued_after else (time.time() - 300)
        seen: set = set()
        folders: Optional[list[str]] = None
        logger.info(
            "[mail_com] 等待 OTP -> %s (母号 %s, timeout=%ss)",
            email_addr, self.email, timeout,
        )

        while time.time() < deadline:
            conn = None
            try:
                conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=30)
                conn.login(self.email, self.password)
            except Exception as exc:
                raise MailProviderError(
                    f"mail.com IMAP 登录失败 {self.email}: {exc}",
                    fatal=True, kind="mail_com_imap",
                )

            try:
                if folders is None:
                    folders = self._discover_folders(conn)
                for folder in folders:
                    code = self._scan_folder(conn, folder, email_addr, threshold, seen)
                    if code:
                        return code
            except Exception as exc:
                logger.warning("[mail_com] IMAP 轮询异常 (重试): %s", exc)
            finally:
                try:
                    conn.logout()
                except Exception:
                    pass
            time.sleep(3)

        raise TimeoutError(f"mail.com OTP timeout {timeout}s for {email_addr}")

    def peek_otp(
        self,
        email_addr: str,
        issued_after: Optional[float] = None,
        wait: float = 0.0,
    ) -> Optional[str]:
        """非破坏性预读：看收件箱里是不是已经躺着一封本轮的码。"""
        deadline = time.time() + max(0.0, float(wait))
        threshold = (issued_after - 5) if issued_after else (time.time() - 300)
        seen: set = set()
        while True:
            try:
                conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=30)
                conn.login(self.email, self.password)
                try:
                    for folder in self._discover_folders(conn):
                        code = self._scan_folder(conn, folder, email_addr, threshold, seen)
                        if code:
                            return code
                finally:
                    try:
                        conn.logout()
                    except Exception:
                        pass
            except Exception as exc:
                logger.debug("[mail_com] peek 异常（当作没探到）: %s", exc)
            if time.time() >= deadline:
                return None
            time.sleep(1)

    def _discover_folders(self, conn) -> list[str]:
        folders = ["INBOX"]
        try:
            _, listing = conn.list()
            for raw in listing or []:
                if not raw:
                    continue
                text = raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)
                m = re.search(r'"([^"]+)"\s*$', text) or re.search(r"\s(\S+)\s*$", text)
                if not m:
                    continue
                name = m.group(1).strip('"')
                if any(token in name.lower() for token in ("junk", "spam", "bulk")):
                    if name not in folders:
                        folders.append(name)
        except Exception as exc:
            logger.warning("[mail_com] LIST 失败，仅扫 INBOX: %s", exc)
        return folders

    def _scan_folder(
        self,
        conn,
        folder: str,
        target_email: str,
        threshold: float,
        seen: set,
    ) -> Optional[str]:
        sel_arg = f'"{folder}"' if " " in folder else folder
        try:
            typ, _ = conn.select(sel_arg, readonly=True)
            if typ != "OK":
                return None
        except Exception:
            return None
        try:
            typ, data = conn.search(None, "ALL")
            ids = data[0].split() if data and data[0] else []
        except Exception as exc:
            logger.warning("[mail_com] SEARCH 失败 %s: %s", folder, exc)
            return None

        target_lower = target_email.lower()
        for mid in reversed(ids[-10:]):
            key = (folder, mid)
            if key in seen:
                continue
            seen.add(key)
            try:
                typ, raw = conn.fetch(mid, "(BODY.PEEK[])")
                msg = _email.message_from_bytes(raw[0][1])
            except Exception:
                continue
            date_str = msg.get("Date") or ""
            try:
                msg_ts = _eu.parsedate_to_datetime(date_str).timestamp()
            except Exception:
                msg_ts = 0
            if msg_ts and msg_ts < threshold:
                continue
            if not _check_from_domain(msg.get("From") or ""):
                continue
            if target_lower not in (msg.get("To") or "").lower():
                continue
            body = ""
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True) or b""
                        body += payload.decode(
                            part.get_content_charset() or "utf-8", errors="replace"
                        ) + "\n"
                    except Exception:
                        continue
            otp = _extract_otp_from_html(body)
            if otp:
                logger.info(
                    "[mail_com] ✅ OTP=%s for %s (folder=%s, 母号=%s)",
                    otp, target_email, folder, self.email,
                )
                return otp
        return None

    # ── 自检 ─────────────────────────────────────────

    def self_test(self) -> dict:
        try:
            client = self._alias_client
            client.login()
            aliases = client.list_aliases()
            domains = client.available_domains()
            domain_ok = self.alias_domain in domains
            return {
                "ok": True,
                "message": (
                    f"母号 {self.email} 登录成功；已有别名 {len(aliases)}/{ALIAS_LIMIT}；"
                    f"别名域名 {self.alias_domain}: {'可用' if domain_ok else '不可用'}"
                ),
            }
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    def close(self) -> None:
        self._alias_client.close()


__all__ = [
    "MailComMailProvider",
    "MailComAliasClient",
    "MailComAliasError",
    "IMAP_HOST",
    "IMAP_PORT",
    "ALIAS_LIMIT",
]
