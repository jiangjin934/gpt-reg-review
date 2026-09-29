"""浏览器启动工厂 —— 隔离 Playwright / Camoufox 依赖。

后期换 Camoufox 只改这个文件，browser_flow.py 和其它模块零改动。
"""
from __future__ import annotations

import logging
import json
import re
from typing import Any, Mapping, Optional

from fingerprint import (
    browser_family_for_type,
    country_context,
    diagnose_fingerprint,
    generate_fingerprint,
    validate_fingerprint,
)

logger = logging.getLogger(__name__)

def geo_for_country(country_code: str) -> tuple[str, str]:
    """兼容旧调用方；地区信息唯一来源是 fingerprint.py。"""
    return country_context(country_code)


def stealth_script_for_fingerprint(fp: dict) -> str:
    """Build one profile-aware init script for the selected browser family.

    Every engine receives the same injection operations. Values come from the
    already frozen profile, and engine-specific globals are deliberately not
    manufactured on engines that do not expose them natively.
    """
    validate_fingerprint(fp)
    profile = {
        "platform": fp["navigator_platform"],
        "vendor": fp["navigator_vendor"],
        "language": fp["locale"],
        "languages": list(fp.get("languages") or [fp["locale"]]),
        "hardwareConcurrency": fp["hardware_concurrency"],
        "maxTouchPoints": fp["max_touch_points"],
        "deviceMemory": fp.get("device_memory"),
    }
    # The template is intentionally identical for Chromium, Firefox, and WebKit.
    # Only this JSON payload changes with the frozen task profile.
    return (
        "globalThis.__codexFingerprintProfile = "
        + json.dumps(profile, ensure_ascii=False, separators=(",", ":"))
        + ";\n"
        + STEALTH_JS
    )


# One shared injection path for Chromium, Firefox, and WebKit. A direct import
# remains valid: without a profile payload it only applies the webdriver getter.
STEALTH_JS = """
(() => {
  try { Object.defineProperty(navigator, 'webdriver', { configurable: true, get: () => undefined }); } catch (_) {}
  const profile = globalThis.__codexFingerprintProfile;
  try { delete globalThis.__codexFingerprintProfile; } catch (_) {}
  if (!profile) return;

  const define = (name, value) => {
    try {
      Object.defineProperty(navigator, name, {
        configurable: true,
        get: () => value,
      });
    } catch (_) {}
  };

  define('platform', profile.platform);
  define('vendor', profile.vendor);
  define('language', profile.language);
  define('languages', profile.languages);
  define('hardwareConcurrency', profile.hardwareConcurrency);
  define('maxTouchPoints', profile.maxTouchPoints);
  if (profile.deviceMemory === null) {
    try {
      Object.defineProperty(navigator, 'deviceMemory', {
        configurable: true,
        get: () => undefined,
      });
    } catch (_) {}
  } else {
    define('deviceMemory', profile.deviceMemory);
  }

})();
"""


def context_options_for_fingerprint(fp: dict) -> dict:
    """Translate a validated profile into the complete Playwright context setup."""
    validate_fingerprint(fp)
    viewport = dict(fp["viewport"])
    screen_w, screen_h = (int(v) for v in fp["screen"].split("x"))
    return {
        "viewport": viewport,
        # 真实浏览器：屏幕是屏幕、窗口是窗口，窗口比屏幕小一圈
        "screen": {"width": screen_w, "height": screen_h},
        "locale": fp["locale"],
        "timezone_id": fp["timezone"],
        "user_agent": fp["user_agent"],
        "device_scale_factor": fp["device_pixel_ratio"],
        "is_mobile": fp["is_mobile"],
        "has_touch": fp["has_touch"],
        "extra_http_headers": {"Accept-Language": fp["lang_full"]},
    }


class FingerprintRuntimeMismatch(RuntimeError):
    """Raised when a live browser page does not expose the frozen profile."""

    def __init__(self, report: dict):
        self.report = report
        mismatches = ", ".join(report.get("mismatches") or ["unknown"])
        super().__init__(f"浏览器运行时画像不一致: {mismatches}")


def inspect_page_fingerprint(page) -> dict:
    """Read the browser-visible values used to verify a frozen task profile."""
    return page.evaluate(
        """async () => {
          let permissionStatusIsNative = null;
          if (navigator.permissions && typeof PermissionStatus !== 'undefined') {
            try {
              permissionStatusIsNative = (await navigator.permissions.query({name: 'notifications'}))
                instanceof PermissionStatus;
            } catch (_) {
              permissionStatusIsNative = false;
            }
          }
          return {
          user_agent: navigator.userAgent,
          platform: navigator.platform,
          vendor: navigator.vendor,
          language: navigator.language,
          languages: Array.from(navigator.languages || []),
          hardware_concurrency: navigator.hardwareConcurrency,
          device_memory: typeof navigator.deviceMemory === 'number'
            ? navigator.deviceMemory : null,
          max_touch_points: navigator.maxTouchPoints,
          viewport: { width: window.innerWidth, height: window.innerHeight },
          screen: { width: window.screen.width, height: window.screen.height },
          device_pixel_ratio: window.devicePixelRatio,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
          webdriver_undefined: typeof navigator.webdriver === 'undefined',
          permission_status_is_native: permissionStatusIsNative,
          };
        }"""
    )


def validate_page_fingerprint(page, fp: dict) -> dict:
    """Validate all high-signal profile fields after a context creates a page."""
    validate_fingerprint(fp)
    observed = inspect_page_fingerprint(page)
    expected_viewport = {
        "width": int(fp["viewport"]["width"]),
        "height": int(fp["viewport"]["height"]),
    }
    expected_languages = list(fp.get("languages") or [fp["locale"]])
    screen_w, screen_h = (int(v) for v in fp["screen"].split("x"))
    expected_screen = {"width": screen_w, "height": screen_h}
    observed_viewport = observed.get("viewport") or {}
    observed_screen = observed.get("screen") or {}

    checks = {
        "user_agent": observed.get("user_agent") == fp["user_agent"],
        "platform": observed.get("platform") == fp["navigator_platform"],
        "vendor": observed.get("vendor") == fp["navigator_vendor"],
        "language": observed.get("language") == fp["locale"],
        "languages": list(observed.get("languages") or []) == expected_languages,
        "hardware_concurrency": observed.get("hardware_concurrency") == fp["hardware_concurrency"],
        "device_memory": observed.get("device_memory") == fp.get("device_memory"),
        "max_touch_points": observed.get("max_touch_points") == fp["max_touch_points"],
        "viewport": observed_viewport == expected_viewport,
        "screen": observed_screen == expected_screen,
        "screen_matches_viewport": (
            observed_screen == expected_screen
            and observed_viewport == expected_viewport
            and expected_viewport["height"] < expected_screen["height"]
        ),
        "device_pixel_ratio": abs(
            float(observed.get("device_pixel_ratio") or 0)
            - float(fp["device_pixel_ratio"])
        ) < 0.01,
        "timezone": observed.get("timezone") == fp["timezone"],
        "webdriver_undefined": observed.get("webdriver_undefined") is True,
        # Do not replace the Permissions API with an object-shaped imitation.
        # Engines without this API report null and are left out of this check.
        "permission_status_is_native": observed.get("permission_status_is_native") is not False,
    }
    report = {
        "fingerprint_id": fp["fingerprint_id"],
        "expected": {
            "user_agent": fp["user_agent"],
            "platform": fp["navigator_platform"],
            "vendor": fp["navigator_vendor"],
            "language": fp["locale"],
            "languages": expected_languages,
            "hardware_concurrency": fp["hardware_concurrency"],
            "device_memory": fp.get("device_memory"),
            "max_touch_points": fp["max_touch_points"],
            "viewport": expected_viewport,
            "screen": expected_screen,
            "device_pixel_ratio": fp["device_pixel_ratio"],
            "timezone": fp["timezone"],
        },
        "observed": observed,
        "checks": checks,
        "mismatches": [name for name, passed in checks.items() if not passed],
    }
    report["all_passed"] = not report["mismatches"]
    if not report["all_passed"]:
        raise FingerprintRuntimeMismatch(report)
    return report


def launch_browser(
    engine_type: str = "auto",
    proxy: Optional[str] = None,
    headless: bool = True,
    country_code: str = "",
    fingerprint: Optional[dict] = None,
):
    """启动浏览器并返回 (pw_instance, browser, context)。

    Parameters
    ----------
    engine_type : "auto" | "camoufox" | "playwright"
        浏览器引擎类型。
        - "auto"（默认）: 优先 Camoufox，未安装则降级 Playwright。
        - "camoufox": 反指纹 Firefox 分支，能过 Cloudflare。
        - "playwright": 原版 Playwright Firefox，可能被 CF 拦截。
    proxy : str | None
        代理 URL（socks5://user:pass@host:port 或 http://...）。
    headless : bool
        是否无头模式运行。
    country_code : str
        代理 IP 国家码。仅在没有传入画像时用于生成画像。
    fingerprint : dict | None
        任务级完整画像。传入后启动器严格消费，不再随机 viewport 或地区字段。

    Returns
    -------
    tuple of (playwright_instance_or_cm, browser, context)
        调用方负责最后通过 close_browser() 关闭。
    """
    normalized_engine = (engine_type or "auto").strip().lower()
    if fingerprint is None:
        # Camoufox is Firefox-based. Auto mode therefore starts with a Firefox
        # profile so a Camoufox-first launch cannot silently change the family.
        fingerprint = generate_fingerprint(
            country_code=country_code,
            prefer_firefox=normalized_engine in ("auto", "camoufox"),
        )
    else:
        validate_fingerprint(fingerprint)
        if country_code and str(fingerprint.get("country_code", "")).upper() != str(country_code).upper():
            raise ValueError(
                "country_code conflicts with the supplied fingerprint: "
                f"{country_code!r} != {fingerprint.get('country_code')!r}"
            )

    family = browser_family_for_type(str(fingerprint["browser_type"]))
    if normalized_engine not in ("auto", "camoufox", "playwright"):
        raise ValueError(f"unsupported browser engine: {engine_type!r}")

    if normalized_engine == "camoufox":
        if family != "firefox":
            raise ValueError("Camoufox requires a Firefox-family fingerprint")
        return _launch_camoufox(proxy, headless, fingerprint)
    elif normalized_engine == "playwright":
        return _launch_playwright(proxy, headless, fingerprint)
    else:
        # auto: use Camoufox only for Firefox profiles, otherwise preserve the
        # requested Chrome/Safari family in Playwright.
        if family == "firefox":
            try:
                return _launch_camoufox(proxy, headless, fingerprint)
            except RuntimeError as e:
                if "未安装" in str(e):
                    logger.warning(
                        "Camoufox 未安装，降级到 Playwright；将继续使用同一 Firefox 画像。"
                    )
                    return _launch_playwright(proxy, headless, fingerprint)
                raise
        return _launch_playwright(proxy, headless, fingerprint)


def _proxy_for_playwright(proxy: str):
    """把代理 URL 转成 Playwright 的 proxy 配置；带认证时先起一个本地中继。

    ⚠️ Playwright / Camoufox **不支持带用户名密码的 SOCKS5**，实测直接报
       `BrowserType.launch: Browser does not support socks5 proxy authentication`。
       而代理池里全是 `socks5h://user:pass@host:port` —— 浏览器引擎因此在真机上
       一直起不来（runs 表里 0 条 browser 记录就是这么来的）。

    解决办法：带认证时起一个本地免认证 SOCKS5 中继（local_socks_relay），
    浏览器连 `127.0.0.1`，由中继带着凭据去连上游代理。
    返回 (proxy_cfg, relay)；relay 必须在浏览器关闭时 stop()。
    """
    value = (proxy or "").strip()
    if not value:
        return None, None
    if "://" in value and "@" in value:
        from local_socks_relay import LocalSocksRelay

        relay = LocalSocksRelay(value)
        return _parse_proxy_for_playwright(relay.start()), relay
    return _parse_proxy_for_playwright(value), None


def _launch_playwright(proxy, headless, fingerprint):
    """Use the Playwright engine matching the supplied profile family."""
    from playwright.sync_api import sync_playwright

    # Playwright 的 proxy.server 不含认证信息，认证走 username/password；
    # 带认证的 SOCKS5 由本地中继兜住（见 _proxy_for_playwright）。
    proxy_cfg, relay = _proxy_for_playwright(proxy or "")

    pw = sync_playwright().start()
    try:
        family = fingerprint["browser_family"]
        launcher_name = {"chrome": "chromium", "safari": "webkit", "firefox": "firefox"}[family]
        browser_launcher = getattr(pw, launcher_name)
        browser = browser_launcher.launch(
            headless=headless,
            proxy=proxy_cfg,
        )
        context = browser.new_context(**context_options_for_fingerprint(fingerprint))
        context.add_init_script(stealth_script_for_fingerprint(fingerprint))
        # 设置合理的默认超时
        context.set_default_timeout(30_000)       # 元素操作 30s
        context.set_default_navigation_timeout(60_000)  # 页面导航 60s

        if relay is not None:
            # 交给 close_browser 收尾，避免中继线程泄漏
            setattr(pw, "_local_socks_relay", relay)

        logger.info(
            f"浏览器已启动: engine=playwright/{family} headless={headless} "
            f"fingerprint={fingerprint['fingerprint_id']} "
            f"viewport={fingerprint['screen']} locale={fingerprint['locale']} "
            f"tz={fingerprint['timezone']} "
            f"proxy={'(本地中继)' if relay else ('(有)' if proxy else '(无)')}"
        )
        return pw, browser, context

    except Exception:
        if relay is not None:
            try:
                relay.stop()
            except Exception:  # noqa: BLE001
                pass
        pw.stop()
        raise


def _camoufox_config_for_fingerprint(fingerprint: dict) -> dict:
    """把冻结画像里的屏幕/视口钉进 Camoufox 的 config。

    为什么必须这么做：Camoufox 默认在合理范围内**随机生成** screen/window（见其
    browserforge 集成说明），而本项目的画像是任务开始前冻结、并写进台账的唯一一套；
    `validate_page_fingerprint` 会逐项比对，screen 对不上就直接中止任务。实测（2026-09-29）：
    不传 config 时 Camoufox 报的 screen 会跟着宿主显示器走（2560x1440），而画像里是
    1440x900 → 每个浏览器任务都挂在 `屏幕/窗口尺寸不一致` 上。传 config 后实测
    screen 1440x900 / outer 1440x900 / inner 与画像 viewport 一致。
    """
    out: dict[str, Any] = {}
    screen = str(fingerprint.get("screen") or "").strip()
    match = re.match(r"^(\d{3,5})\s*[xX*]\s*(\d{3,5})$", screen)
    if match:
        width, height = int(match.group(1)), int(match.group(2))
        out["screen.width"] = width
        out["screen.height"] = height
        out["screen.availWidth"] = width
        # 任务栏占一点高度：screen==avail 会被 CreepJS 的 noTaskbar 一眼认出
        out["screen.availHeight"] = max(1, height - 27)
        out["window.outerWidth"] = width
        out["window.outerHeight"] = height
    viewport = fingerprint.get("viewport")
    if isinstance(viewport, Mapping):
        try:
            vw = int(viewport.get("width") or 0)
            vh = int(viewport.get("height") or 0)
        except (TypeError, ValueError):
            vw = vh = 0
        if vw > 0 and vh > 0:
            out["window.innerWidth"] = vw
            out["window.innerHeight"] = vh
    return out


def _launch_camoufox(proxy, headless, fingerprint):
    """使用 Camoufox（反指纹 Firefox 分支）启动。

    Camoufox 优势：
      - 修改过的 TLS/HTTP2 指纹，能过 Cloudflare
      - 内置 Canvas/WebGL/Font 反指纹，不需要 stealth JS
      - geoip 明确关闭，避免覆盖任务画像里的 locale/timezone
      - API 兼容 Playwright（Browser + BrowserContext）
    """
    try:
        from camoufox.sync_api import Camoufox
    except ImportError:
        raise RuntimeError(
            "Camoufox 未安装。请运行:\n"
            "  pip install -U camoufox\n"
            "  python -m camoufox fetch"
        )

    # 代理配置：带认证的 SOCKS5 交给本地中继（浏览器不支持带认证的 SOCKS5）
    proxy_cfg, relay = _proxy_for_playwright(proxy or "")

    # Camoufox 构造参数
    if fingerprint["browser_family"] != "firefox":
        raise ValueError("Camoufox requires a Firefox-family fingerprint")

    cf_kwargs = {"headless": headless, "geoip": False}
    if proxy_cfg:
        cf_kwargs["proxy"] = proxy_cfg
    # 屏幕/视口必须等于冻结画像，否则 validate_page_fingerprint 会判「运行时不符」中止
    camoufox_config = _camoufox_config_for_fingerprint(fingerprint)
    if camoufox_config:
        cf_kwargs["config"] = camoufox_config
        # Camoufox 对「手动固定 screen/window」会发 LeakWarning；这里是刻意为之
        # （画像已冻结并写台账），显式声明避免刷警告。
        cf_kwargs["i_know_what_im_doing"] = True

    cm = Camoufox(**cf_kwargs)
    try:
        # Camoufox.__enter__() 返回 Browser（不是 BrowserContext）
        browser = cm.__enter__()

        context = browser.new_context(**context_options_for_fingerprint(fingerprint))
        context.add_init_script(stealth_script_for_fingerprint(fingerprint))

        context.set_default_timeout(30_000)
        context.set_default_navigation_timeout(60_000)

        if relay is not None:
            # 交给 close_browser 收尾，避免中继线程泄漏
            setattr(cm, "_local_socks_relay", relay)

        logger.info(
            f"浏览器已启动: engine=camoufox headless={headless} "
            f"geoip={cf_kwargs['geoip']} "
            f"fingerprint={fingerprint['fingerprint_id']} "
            f"viewport={fingerprint['screen']} locale={fingerprint['locale']} "
            f"tz={fingerprint['timezone']} "
            f"proxy={'(本地中继)' if relay else ('(有)' if proxy else '(无)')}"
        )
        return cm, browser, context

    except Exception:
        if relay is not None:
            try:
                relay.stop()
            except Exception:  # noqa: BLE001
                pass
        try:
            cm.__exit__(None, None, None)
        except Exception:
            pass
        raise


def close_browser(pw_or_cm, browser):
    """安全关闭浏览器和 Playwright/Camoufox 实例（含本地代理中继）。"""
    try:
        browser.close()
    except Exception:
        pass
    try:
        # Playwright 的 stop() 或 Camoufox 的 __exit__
        if hasattr(pw_or_cm, "stop"):
            pw_or_cm.stop()
        elif hasattr(pw_or_cm, "__exit__"):
            pw_or_cm.__exit__(None, None, None)
    except Exception:
        pass
    relay = getattr(pw_or_cm, "_local_socks_relay", None)
    if relay is not None:
        try:
            relay.stop()
        except Exception:  # noqa: BLE001
            pass


def _parse_proxy_for_playwright(proxy_url: str) -> dict:
    """把 socks5://user:pass@host:port 格式解析成 Playwright proxy dict。

    Playwright 的 proxy 参数格式：
      {"server": "socks5://host:port", "username": "...", "password": "..."}
    """
    from urllib.parse import unquote, urlparse
    from http_client import normalize_proxy_url

    # socks5h → socks5（Playwright 不认 socks5h，但效果一样——DNS 走代理）
    url = normalize_proxy_url(proxy_url).replace("socks5h://", "socks5://")
    # 没有 scheme 时补 http://（代理池常见格式: user:pass@host:port）
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)

    result = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
    if parsed.username:
        result["username"] = unquote(parsed.username)
    if parsed.password:
        result["password"] = unquote(parsed.password)
    return result
