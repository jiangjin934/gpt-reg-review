"""请求头画像与国家级画像的拟真性测试。"""
import random

from fingerprint import generate_fingerprint, header_profile, supported_country_codes


def test_header_profile_follows_browser_version():
    """zstd / priority 必须按浏览器版本给，不能所有版本一个样。"""
    fp = generate_fingerprint(rng=random.Random(1), browser_type="chrome", weighted=True)

    fp["impersonate"] = "chrome110"  # 老版本：无 zstd、无 priority
    prof = header_profile(fp, kind="document")
    assert "zstd" not in prof["accept_encoding"]
    assert prof["priority"] == ""

    fp["impersonate"] = "chrome136"  # 新版本：有 zstd、导航带 priority
    prof = header_profile(fp, kind="document")
    assert "zstd" in prof["accept_encoding"]
    assert prof["priority"] == "u=0, i"
    assert header_profile(fp, kind="fetch")["priority"] == "u=1, i"

    fp["impersonate"] = "chrome99"
    prof = header_profile(fp, kind="document")
    assert "zstd" not in prof["accept_encoding"]
    assert prof["priority"] == ""


def test_header_profile_safari_and_firefox():
    safari = generate_fingerprint(
        rng=random.Random(2), browser_type="mac_safari", weighted=True
    )
    prof = header_profile(safari, kind="document")
    assert "zstd" not in prof["accept_encoding"]
    assert prof["priority"] == ""
    assert "avif" not in prof["accept"]

    firefox = generate_fingerprint(
        rng=random.Random(3), browser_type="firefox", weighted=True
    )
    firefox["impersonate"] = "firefox147"
    prof = header_profile(firefox, kind="item")
    assert "zstd" in prof["accept_encoding"]
    assert prof["priority"] == ""
    assert "avif" in prof["accept"]


def test_country_profiles_cover_proxy_exit_countries():
    """代理实际落过的出口国家必须有画像，否则会掉进 UTC/en-US 兜底。"""
    codes = set(supported_country_codes())
    for cc in ("IS", "NL", "GB", "DO", "KH", "PY", "HN", "IE", "MT"):
        assert cc in codes, f"{cc} 缺国家画像（会退化成 UTC + en-US）"
