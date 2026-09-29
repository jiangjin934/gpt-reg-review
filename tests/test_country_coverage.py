"""全球随机出口：国家画像必须全量覆盖，且时区/语言自洽。"""
import re

import pytest
import pytz

from fingerprint import (
    _COUNTRY_PROFILES,
    generate_fingerprint,
    has_country_profile,
)
from country_profiles_extra import EXTRA_COUNTRY_PROFILES


def test_extra_profiles_are_merged_at_import():
    assert len(EXTRA_COUNTRY_PROFILES) >= 100
    for code in ("AQ", "TF", "AD", "AF", "CU", "GL", "KI", "PS"):
        assert has_country_profile(code) is True, code


def test_every_profile_has_valid_iana_timezone_and_language():
    for code, profile in _COUNTRY_PROFILES.items():
        zones = profile.get("timezones") or []
        assert zones, code
        for zone, weight in zones:
            try:
                pytz.timezone(zone)
            except Exception:  # noqa: BLE001 - 断言失败信息
                pytest.fail(f"{code} 的时区不存在: {zone}")
            assert weight > 0
        languages = profile.get("languages") or []
        assert languages, code
        primary = str(languages[0])
        assert re.fullmatch(r"[a-z]{2,3}(-[A-Za-z0-9]{2,8})?", primary), (code, primary)


def test_country_context_prefers_real_zone_over_utc_fallback():
    assert _COUNTRY_PROFILES["TN"]["timezones"][0][0] == "Africa/Tunis"
    assert _COUNTRY_PROFILES["KZ"]["timezones"][0][0] == "Asia/Almaty"
    assert _COUNTRY_PROFILES["AQ"]["timezones"][0][0].startswith("Antarctica/")


def test_fingerprint_follows_each_country_profile():
    for code in ("TN", "KZ", "PS", "CU", "GL", "MM", "FJ", "ZW"):
        fp = generate_fingerprint(country_code=code, browser_family="chrome")
        allowed_zones = {zone for zone, _ in _COUNTRY_PROFILES[code]["timezones"]}
        allowed_languages = {str(v).lower() for v in _COUNTRY_PROFILES[code]["languages"]}
        assert fp["timezone"] in allowed_zones
        assert fp["lang"].lower() in allowed_languages
