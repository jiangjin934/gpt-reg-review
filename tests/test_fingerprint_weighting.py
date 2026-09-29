import random

from fingerprint import generate_fingerprint, validate_fingerprint


def test_weighted_firefox_is_macos_and_uniform():
    """全版本对照模式：firefox 为 macOS 轮廓，版本/屏幕/核数字段均匀随机。"""
    screens = {}
    versions = {}
    cores = {}
    rng = random.Random(20260925)
    for _ in range(3000):
        fp = generate_fingerprint(
            rng=rng, country_code="JP", browser_type="firefox", weighted=True
        )
        validate_fingerprint(fp)
        assert fp["navigator_platform"] == "MacIntel"
        assert "Macintosh" in fp["user_agent"]
        assert fp["device_memory"] is None
        screens[fp["screen"]] = screens.get(fp["screen"], 0) + 1
        versions[fp["impersonate"]] = versions.get(fp["impersonate"], 0) + 1
        cores[fp["hardware_concurrency"]] = cores.get(fp["hardware_concurrency"], 0) + 1

    # 四档版本大致等权
    for ver in ("firefox133", "firefox135", "firefox144", "firefox147"):
        assert versions.get(ver, 0) > 300
    # 核数来自真机机型表（M1/M1 Pro/M2/M3 Pro/M4 Pro/Intel 机型）
    assert set(cores) <= {6, 8, 10, 12, 14}
    assert len(screens) >= 2


def test_unweighted_profiles_stay_valid():
    for browser_type in ("chrome", "firefox", "mac_safari", "ios_safari"):
        fp = generate_fingerprint(
            country_code="JP", browser_type=browser_type, weighted=False
        )
        validate_fingerprint(fp)
        assert fp["fingerprint_id"].startswith("fp_")


def test_mixed_pool_spans_all_desktop_versions_macos_only():
    """全版本对照模式：混池覆盖全部 8 个桌面版本，且全为 macOS 轮廓。"""
    rng = random.Random(20260926)
    seen_versions = set()
    for _ in range(4000):
        fp = generate_fingerprint(
            rng=rng, country_code="NL", browser_family="mixed", weighted=True
        )
        validate_fingerprint(fp)
        assert fp["browser_type"] in ("mac_safari", "chrome", "edge", "firefox")
        assert fp["navigator_platform"] == "MacIntel"
        if fp["browser_type"] in ("chrome", "edge"):
            assert "Macintosh" in fp["user_agent"]
            assert fp["sec_ch_ua_platform"] == '"macOS"'
        seen_versions.add(fp["impersonate"])
    assert seen_versions == {
        "safari15_3", "safari15_5", "safari17_0", "safari18_0",
        "safari184", "safari260", "safari2601",
        "chrome99", "chrome100", "chrome101", "chrome104", "chrome107",
        "chrome110", "chrome116", "chrome119", "chrome120", "chrome123",
        "chrome124", "chrome131", "chrome133a", "chrome136", "chrome142",
        "chrome145", "chrome146", "chrome150",
        "edge99", "edge101",
        "firefox133", "firefox135", "firefox144", "firefox147",
    }


def test_weighted_profile_is_deterministic_for_same_seed():
    a = generate_fingerprint(
        rng=random.Random(42), country_code="JP", browser_type="firefox", weighted=True
    )
    b = generate_fingerprint(
        rng=random.Random(42), country_code="JP", browser_type="firefox", weighted=True
    )
    # fingerprint_id 用系统加密随机数生成，天然不参与 RNG 确定性
    a.pop("fingerprint_id", None)
    b.pop("fingerprint_id", None)
    assert a == b
