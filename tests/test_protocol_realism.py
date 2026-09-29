"""协议画像"绝对真实"闸门：版本 / 画像 / 国家三个维度都要自洽。"""
import copy

import pytest

from fingerprint import (
    check_version_consistency,
    diagnose_fingerprint,
    generate_fingerprint,
    has_country_profile,
)
from webui import environment


@pytest.mark.parametrize(
    "family",
    ["chrome", "edge", "firefox", "safari"],
)
def test_generated_profiles_are_version_consistent(family):
    for _ in range(6):
        fp = generate_fingerprint(country_code="GB", browser_family=family)
        report = check_version_consistency(fp)
        assert report["ok"], report["errors"]
        # impersonate / UA / client hints 必须是同一个版本号
        assert report["impersonate_major"]
        if fp["browser_type"] in ("chrome", "edge"):
            assert report["ua_version"] == report["impersonate_major"]
            assert report["client_hint_version"] == report["impersonate_major"]
        else:
            assert fp["sec_ch_ua"] == ""


def test_chrome_133a_keeps_real_version_number():
    """curl_cffi 的 target 名带补丁后缀，UA/CH 里不能出现 '133a'。"""
    for _ in range(40):
        fp = generate_fingerprint(country_code="GB", browser_type="chrome")
        if fp["impersonate"] != "chrome133a":
            continue
        assert "133a" not in fp["user_agent"]
        assert "Chrome/133.0.0.0" in fp["user_agent"]
        assert 'v="133"' in fp["sec_ch_ua"]
        assert check_version_consistency(fp)["ok"]
        return
    pytest.skip("本轮没有抽到 chrome133a")


@pytest.mark.parametrize(
    "mutate, expect",
    [
        (lambda fp: fp.update(user_agent=fp["user_agent"].replace("Chrome/", "Chrome/999.")), "UA"),
        (lambda fp: fp.update(sec_ch_ua='"Chromium";v="999", "Google Chrome";v="999"'), "sec-ch-ua"),
        (lambda fp: fp.update(sec_ch_ua_platform='"Windows"'), "platform"),
        (lambda fp: fp.update(navigator_platform="Win32"), "MacIntel"),
    ],
)
def test_chrome_version_mismatch_is_rejected(mutate, expect):
    fp = generate_fingerprint(country_code="GB", browser_type="chrome")
    mutate(fp)
    report = check_version_consistency(fp)
    assert report["ok"] is False
    assert any(expect in err for err in report["errors"])
    assert diagnose_fingerprint(fp)["checks"]["version_consistency"] is False


def test_client_hints_on_safari_or_firefox_are_rejected():
    for family in ("safari", "firefox"):
        fp = generate_fingerprint(country_code="GB", browser_family=family)
        fp["sec_ch_ua"] = '"Chromium";v="131", "Google Chrome";v="131"'
        report = check_version_consistency(fp)
        assert report["ok"] is False
        assert any("client hint" in err for err in report["errors"])


def test_header_profile_thresholds_follow_claimed_version():
    """zstd / priority 是版本相关头，不能给老版本发新头。"""
    old = {
        "browser_type": "chrome",
        "browser_family": "chrome",
        "impersonate": "chrome99",
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": '"Chromium";v="99", "Google Chrome";v="99", "Not A;Brand";v="99"',
        "sec_ch_ua_full_version_list": (
            '"Chromium";v="99.0.0.0", "Google Chrome";v="99.0.0.0", "Not A;Brand";v="99"'
        ),
        "sec_ch_ua_platform": '"macOS"',
        "navigator_platform": "MacIntel",
    }
    report = check_version_consistency(old)
    assert report["ok"], report["errors"]
    assert report["accept_encoding"] == "gzip, deflate, br"
    assert report["priority"] == ""


def test_diagnose_reports_country_profile_alignment():
    fp = generate_fingerprint(country_code="JP", browser_type="firefox")
    report = diagnose_fingerprint(fp)
    assert report["checks"]["timezone_matches_country"] is True
    assert report["checks"]["language_matches_country"] is True

    broken = copy.deepcopy(fp)
    broken["timezone"] = "America/New_York"
    assert diagnose_fingerprint(broken)["checks"]["timezone_matches_country"] is False


def test_allocation_skips_inconsistent_fingerprint(monkeypatch):
    """版本自洽闸门：不一致的画像不允许冻结进任务环境。"""
    good = generate_fingerprint(country_code="JP", browser_type="firefox")

    def fake_generate(*_args, **_kwargs):
        broken = copy.deepcopy(good)
        broken["user_agent"] = broken["user_agent"].replace("Firefox/", "Firefox/999.")
        return broken

    monkeypatch.setattr(environment, "probe_exit", lambda *a, **k: {
        "exit_ip": "203.0.113.77", "exit_country": "JP",
    })
    monkeypatch.setattr(environment, "generate_fingerprint", fake_generate)

    with pytest.raises(environment.EnvironmentAllocationError) as raised:
        environment.allocate_environment("run-realism", {"proxy": "http://proxy.example:8080"})

    assert "版本自洽" in str(raised.value)


def test_profiled_countries_cover_major_random_exits():
    # 全球随机出口常用国家必须有画像，否则会被环境闸门跳过
    for code in ("US", "GB", "DE", "FR", "BR", "IN", "JP", "KR", "VN", "TH",
                 "TN", "MA", "KZ", "JO", "VE", "GH", "MM", "FJ"):
        assert has_country_profile(code) is True, code
    assert has_country_profile("ZZ") is False


def test_allocation_skips_exit_without_country_profile(monkeypatch):
    """出口国家没有画像配套时必须换候选，不能拿 UTC/en-US 硬凑。"""
    probes = []

    def fake_probe(proxy, timeout=15.0, family="chrome", require_chatgpt=False,
                   **kwargs):
        probes.append(proxy)
        if len(probes) == 1:
            return {"exit_ip": "203.0.113.31", "exit_country": "ZZ"}
        return {"exit_ip": "203.0.113.32", "exit_country": "JP"}

    monkeypatch.setattr(environment, "probe_exit", fake_probe)

    allocated = environment.allocate_environment(
        "run-country-profile-gate",
        {"proxy_pool": "socks5h://u:p@h1:3000\nsocks5h://u:p@h2:3000"},
    )

    assert allocated["exit_country"] == "JP"
    assert len(probes) == 2
