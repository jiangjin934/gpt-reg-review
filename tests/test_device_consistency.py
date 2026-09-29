"""机型 ↔ 浏览器版本 ↔ 系统版本 ↔ 屏幕/DPR/核心/GPU 必须同源（德要配位）。"""
import random

from fingerprint import (
    _CHROME_RELEASE_YM,
    _MAC_DEVICES,
    _MACOS_RELEASES,
    _browser_min_macos,
    device_silhouette,
    generate_fingerprint,
)

DEVICES = {device["id"]: device for device in _MAC_DEVICES}
RELEASES = {version: released for version, released in _MACOS_RELEASES}


def test_device_is_from_real_mac_table_and_fields_match():
    rng = random.Random(20260927)
    for _ in range(300):
        fp = generate_fingerprint(rng=rng, country_code="DE", browser_type="chrome")
        device = DEVICES[fp["device_model"]]
        assert fp["screen"] == device["screen"]
        assert fp["hardware_concurrency"] == device["cores"]
        assert fp["device_pixel_ratio"] == device["dpr"]
        assert fp["gpu_vendor"] == device["gpu_vendor"]
        assert fp["gpu_renderer"] == device["gpu_renderer"]


def test_macos_version_predates_browser_release():
    rng = random.Random(4242)
    for _ in range(300):
        fp = generate_fingerprint(rng=rng, country_code="JP", browser_type="chrome")
        major = fp["impersonate"].replace("chrome", "").rstrip("a")
        browser_ym = _CHROME_RELEASE_YM[major]
        device = DEVICES[fp["device_model"]]
        assert int(device["since"]) <= browser_ym, (device["id"], major)
        low, high = device["macos"]
        assert low <= fp["macos_version"] <= high
        assert RELEASES[fp["macos_version"]] <= browser_ym, (device["id"], major)
        # 浏览器最低系统要求也必须满足：Chrome 128+ 不能跑在 10.15 上
        assert fp["macos_version"] >= _browser_min_macos("chrome", int(major))
        # client hints 报的系统版本必须就是这台机器的系统版本
        assert fp["sec_ch_ua_platform_version"] == f'"{fp["macos_version"]}.0"'


def test_modern_chrome_never_pairs_with_legacy_macos():
    rng = random.Random(31337)
    for _ in range(400):
        fp = generate_fingerprint(rng=rng, country_code="GB", browser_type="chrome")
        major = int(fp["impersonate"].replace("chrome", "").rstrip("a"))
        if major >= 128:
            assert fp["macos_version"] >= "11.0", (major, fp["macos_version"])
        if major >= 110:
            assert fp["macos_version"] >= "10.15", (major, fp["macos_version"])


def test_accept_language_keeps_base_language_first():
    fp = generate_fingerprint(country_code="DE", browser_type="chrome")
    tags = [part.split(";")[0].strip() for part in fp["lang_full"].split(",")]
    assert tags[0] == fp["lang"]
    assert tags[1].lower() == fp["lang"].split("-")[0].lower()


def test_intel_mac_never_gets_newer_than_supported_macos():
    rng = random.Random(99)
    for _ in range(200):
        fp = generate_fingerprint(rng=rng, country_code="US", browser_type="edge")
        device = DEVICES[fp["device_model"]]
        if device["arch"] != "intel":
            continue
        assert fp["macos_version"] <= "12.7"
        assert "Intel" in fp["gpu_renderer"] or "AMD" in fp["gpu_renderer"]


def test_viewport_is_a_real_window_inside_the_screen():
    for family, browser_type in (
        ("chrome", "chrome"), ("firefox", "firefox"), ("safari", "mac_safari"),
    ):
        fp = generate_fingerprint(country_code="FR", browser_type=browser_type)
        screen_w, screen_h = (int(v) for v in fp["screen"].split("x"))
        assert fp["viewport"]["width"] <= screen_w
        chrome_px = screen_h - fp["viewport"]["height"]
        assert 40 <= chrome_px <= 300, (family, fp["screen"], fp["viewport"])


def test_sentinel_silhouette_reuses_the_same_mac_device():
    fp = generate_fingerprint(country_code="US", browser_type="chrome")
    silhouette = device_silhouette("device-fixture-1", fp)

    assert silhouette["screen"] == fp["screen"]
    assert silhouette["hardware_concurrency"] == fp["hardware_concurrency"]
    assert silhouette["device_pixel_ratio"] == fp["device_pixel_ratio"]
    assert silhouette["gpu_renderer"] == fp["gpu_renderer"]
    assert silhouette["device_model"] == fp["device_model"]
    assert "D3D11" not in silhouette["gpu_renderer"]
    # 同一设备同一指纹必须稳定（时间锚点也固定）
    assert device_silhouette("device-fixture-1", fp) == silhouette


def test_sentinel_silhouette_without_fingerprint_is_still_a_mac():
    silhouette = device_silhouette("device-fixture-2")
    devices = {d["gpu_renderer"] for d in _MAC_DEVICES}
    assert silhouette["gpu_renderer"] in devices
    assert "D3D11" not in silhouette["gpu_renderer"]
    assert silhouette["screen"] in {d["screen"] for d in _MAC_DEVICES}
