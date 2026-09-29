import sys
from copy import deepcopy
from types import ModuleType

import pytest

import browser_launcher
from fingerprint import diagnose_fingerprint, generate_fingerprint, validate_fingerprint


@pytest.mark.parametrize("browser_type", ["chrome", "firefox", "mac_safari", "ios_safari"])
def test_each_task_gets_a_valid_unique_profile(browser_type):
    first = generate_fingerprint(country_code="JP", browser_type=browser_type)
    second = generate_fingerprint(country_code="JP", browser_type=browser_type)

    assert first["fingerprint_id"] != second["fingerprint_id"]
    # 真实窗口比屏幕小：宽度不超过屏幕，高度留出菜单栏/工具栏
    for profile in (first, second):
        screen_w, screen_h = (int(v) for v in profile["screen"].split("x"))
        assert profile["viewport"]["width"] <= screen_w
        assert 40 <= screen_h - profile["viewport"]["height"] <= 300
    validate_fingerprint(first)
    validate_fingerprint(second)


def test_validation_rejects_screen_viewport_mismatch():
    profile = generate_fingerprint(country_code="US", browser_type="chrome")
    wider = deepcopy(profile)
    wider["viewport"]["width"] += 1

    with pytest.raises(ValueError, match="cannot exceed the screen"):
        validate_fingerprint(wider)

    no_chrome = deepcopy(profile)
    no_chrome["viewport"]["height"] = int(profile["screen"].split("x")[1])

    with pytest.raises(ValueError, match="browser chrome"):
        validate_fingerprint(no_chrome)


def test_country_profile_links_locale_language_and_timezone():
    profile = generate_fingerprint(country_code="JP", browser_type="firefox")

    assert profile["country_code"] == "JP"
    assert profile["locale"] == "ja-JP"
    assert profile["lang"] == "ja-JP"
    assert profile["lang_full"].startswith("ja-JP")
    assert profile["timezone"] == "Asia/Tokyo"

    report = diagnose_fingerprint(profile, engine_type="playwright", detected_country="JP")
    assert report["checks"]["all_passed"] is True
    assert report["checks"]["country_matches_detected"] is True


@pytest.mark.parametrize("browser_type", ["chrome", "firefox", "mac_safari", "ios_safari"])
def test_all_browser_families_use_the_same_profile_aware_stealth_logic(browser_type):
    profile = generate_fingerprint(browser_type=browser_type)
    script = browser_launcher.stealth_script_for_fingerprint(profile)

    assert "__codexFingerprintProfile" in script
    for marker in (
        "navigator, 'webdriver'",
        "define('platform'",
        "define('vendor'",
        "define('language'",
        "define('languages'",
        "define('hardwareConcurrency'",
        "define('maxTouchPoints'",
        "deviceMemory",
    ):
        assert marker in script
    assert "permissions.query" not in script


def test_context_options_use_real_screen_and_window():
    profile = generate_fingerprint(country_code="DE", browser_type="chrome")
    options = browser_launcher.context_options_for_fingerprint(profile)

    assert options["viewport"] == profile["viewport"]
    # 屏幕是屏幕、窗口是窗口，窗口比屏幕矮（真实浏览器）
    assert options["screen"] == {
        "width": int(profile["screen"].split("x")[0]),
        "height": int(profile["screen"].split("x")[1]),
    }
    assert options["viewport"]["height"] < options["screen"]["height"]
    assert options["locale"] == profile["locale"]
    assert options["timezone_id"] == profile["timezone"]
    assert options["user_agent"] == profile["user_agent"]
    assert options["device_scale_factor"] == profile["device_pixel_ratio"]
    assert options["is_mobile"] == profile["is_mobile"]
    assert options["has_touch"] == profile["has_touch"]
    assert options["extra_http_headers"]["Accept-Language"] == profile["lang_full"]


def test_launch_browser_passes_the_frozen_profile_without_regenerating(monkeypatch):
    profile = generate_fingerprint(browser_type="chrome")
    captured = {}

    def fake_launch(proxy, headless, fingerprint):
        captured.update(proxy=proxy, headless=headless, fingerprint=fingerprint)
        return "pw", "browser", "context"

    monkeypatch.setattr(browser_launcher, "_launch_playwright", fake_launch)
    result = browser_launcher.launch_browser(
        engine_type="playwright",
        proxy="http://proxy.example:8080",
        headless=False,
        fingerprint=profile,
    )

    assert result == ("pw", "browser", "context")
    assert captured == {
        "proxy": "http://proxy.example:8080",
        "headless": False,
        "fingerprint": profile,
    }


def test_camoufox_disables_geoip_and_receives_complete_context(monkeypatch):
    profile = generate_fingerprint(country_code="CN", browser_type="firefox")
    captured = {}

    class FakeContext:
        def __init__(self):
            self.options = None
            self.script = None

        def add_init_script(self, script):
            self.script = script

        def set_default_timeout(self, value):
            captured["timeout"] = value

        def set_default_navigation_timeout(self, value):
            captured["navigation_timeout"] = value

    class FakeBrowser:
        def __init__(self):
            self.context = FakeContext()

        def new_context(self, **options):
            self.context.options = options
            return self.context

    class FakeCamoufox:
        def __init__(self, **kwargs):
            captured["camoufox_kwargs"] = kwargs
            self.browser = FakeBrowser()

        def __enter__(self):
            return self.browser

        def __exit__(self, *args):
            captured["closed"] = True

    camoufox_package = ModuleType("camoufox")
    camoufox_api = ModuleType("camoufox.sync_api")
    camoufox_api.Camoufox = FakeCamoufox
    camoufox_package.sync_api = camoufox_api
    monkeypatch.setitem(sys.modules, "camoufox", camoufox_package)
    monkeypatch.setitem(sys.modules, "camoufox.sync_api", camoufox_api)

    cm, browser, context = browser_launcher.launch_browser(
        engine_type="camoufox",
        proxy="socks5://user:pass@proxy.example:1080",
        fingerprint=profile,
    )

    assert cm.__class__ is FakeCamoufox
    assert browser is cm.browser
    assert context is browser.context
    assert captured["camoufox_kwargs"]["geoip"] is False
    assert context.options == browser_launcher.context_options_for_fingerprint(profile)
    assert profile["locale"] in context.options["extra_http_headers"]["Accept-Language"]
    assert "__codexFingerprintProfile" in context.script


def test_diagnosis_always_exposes_named_checks():
    profile = generate_fingerprint(country_code="FR", browser_type="mac_safari")
    report = diagnose_fingerprint(profile)

    assert set(
        (
            "screen_matches_viewport",
            "ua_matches_browser_family",
            "platform_matches_browser_family",
            "language_matches_locale",
            "timezone_is_explicit",
            "geoip_override_disabled",
            "country_matches_detected",
            "all_passed",
        )
    ).issubset(report["checks"])
    assert report["checks"]["all_passed"] is True

def test_mixed_family_policy_spans_desktop_families():
    """全版本对照模式：协议注册混池覆盖三个桌面家族（无 iOS）。"""
    from fingerprint import _browser_type_for_policy
    import random as _random

    r = _random.Random(7)
    kinds = {_browser_type_for_policy("mixed", r) for _ in range(300)}
    assert kinds <= {"chrome", "firefox", "mac_safari", "edge"}
    assert "ios_safari" not in kinds
    assert len(kinds) >= 2
    assert "chrome" in kinds


def test_chrome_pool_includes_current_versions():
    from fingerprint import _CHROME_VERSIONS

    versions = {entry["impersonate"] for entry in _CHROME_VERSIONS}
    assert "chrome146" in versions
    assert "chrome150" in versions


def test_device_silhouette_deterministic_and_distinct():
    from fingerprint import device_silhouette

    first = device_silhouette("device-aaa")
    second = device_silhouette("device-aaa")
    other = device_silhouette("device-bbb")

    assert first == second
    assert first["time_origin"] > 0
    assert first["js_heap_size_limit"] > 0
    distinct = (
        first["screen"] != other["screen"]
        or first["gpu_renderer"] != other["gpu_renderer"]
        or first["hardware_concurrency"] != other["hardware_concurrency"]
        or first["time_origin"] != other["time_origin"]
    )
    assert distinct
