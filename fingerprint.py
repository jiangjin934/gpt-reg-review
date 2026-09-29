"""浏览器指纹随机化（多浏览器家族）。

每次注册调用 generate_fingerprint() 生成一套一致的指纹组合：
  - TLS impersonate（curl_cffi 用）
  - User-Agent
  - sec-ch-ua / sec-ch-ua-platform / sec-ch-ua-mobile（仅 Chrome）
  - 屏幕分辨率
  - Accept-Language
  - browser_type 标识（mac_safari / ios_safari / chrome / firefox）
  - fallback_impersonates 同家族回退列表
"""
from __future__ import annotations

import hashlib
import random
import re
import secrets
import time
from collections.abc import Mapping

# ---------------------------------------------------------------------------
# macOS Safari（保留原有）
# ---------------------------------------------------------------------------
_SAFARI_VERSIONS = [
    {
        "impersonate": "safari15_3",
        "safari_ver": "15.3",
        "webkit_ver": "605.1.15",
        "macos_versions": ["12_0", "12_1", "12_2"],
    },
    {
        "impersonate": "safari15_5",
        "safari_ver": "15.5",
        "webkit_ver": "605.1.15",
        "macos_versions": ["12_3", "12_4", "12_5"],
    },
    {
        "impersonate": "safari17_0",
        "safari_ver": "17.0",
        "webkit_ver": "605.1.15",
        "macos_versions": ["13_5", "13_6", "14_0"],
    },
    {
        "impersonate": "safari18_0",
        "safari_ver": "18.0",
        "webkit_ver": "605.1.15",
        "macos_versions": ["14_4", "14_5", "15_0"],
    },
    {
        "impersonate": "safari184",
        "safari_ver": "18.4",
        "webkit_ver": "605.1.15",
        "macos_versions": ["14_5", "15_0", "15_1", "15_2"],
    },
    {
        "impersonate": "safari260",
        "safari_ver": "26.0",
        "webkit_ver": "605.1.15",
        "macos_versions": ["15_5", "26_0"],
    },
    {
        "impersonate": "safari2601",
        "safari_ver": "26.1",
        "webkit_ver": "605.1.15",
        "macos_versions": ["26_0", "26_1"],
    },
]

_MAC_SCREENS = [
    "1440x900",
    "1512x982",
    "1728x1117",
    "2560x1440",
    "1920x1080",
]

# ---------------------------------------------------------------------------
# iOS Safari
# ---------------------------------------------------------------------------
_IOS_SAFARI_VERSIONS = [
    {
        "impersonate": "safari17_2_ios",
        "safari_ver": "17.2",
        "webkit_ver": "605.1.15",
        "ios_versions": ["17_1_2", "17_2"],
    },
    {
        "impersonate": "safari18_0_ios",
        "safari_ver": "18.0",
        "webkit_ver": "605.1.15",
        "ios_versions": ["18_0", "18_1", "18_1_1"],
    },
    {
        "impersonate": "safari184_ios",
        "safari_ver": "18.4",
        "webkit_ver": "605.1.15",
        "ios_versions": ["18_4"],
    },
]

_IPHONE_SCREENS = [
    "390x844",   # iPhone 13 / 14
    "393x852",   # iPhone 14 Pro / 15
    "428x926",   # iPhone 13 Pro Max / 14 Plus
    "430x932",   # iPhone 14 Pro Max / 15 Plus
]

# ---------------------------------------------------------------------------
# Chrome（macOS 轮廓）—— curl_cffi 0.16.3 支持的全部桌面版本
# not_a_brand 按 Chrome 各时期的 GREASE 品牌串分段取值（同段内共用）。
# ---------------------------------------------------------------------------
def _chrome_entry(version: str, not_a_brand: str) -> dict:
    # curl_cffi 的 target 名允许带补丁后缀（chrome133a），但 UA / client hints
    # 里必须是真实发布的版本号（133.0.0.0）。UA 里出现 "133a" 这种字符串
    # 等于自曝自动化客户端，所以这里单独取数字部分。
    display = re.sub(r"\D+$", "", version) or version
    return {
        "impersonate": f"chrome{version}",
        "ver": display,
        "full_ver": f"{display}.0.0.0",
        "not_a_brand": not_a_brand,
    }


_NAB_OLD = '"Not A;Brand";v="99"'        # ≤105
_NAB_110 = '"Not A(Brand";v="24"'        # 106–135
_NAB_136 = '"Not.A/Brand";v="99"'        # 136–145
_NAB_146 = '"Not?A_Brand";v="99"'        # 146–149
_NAB_150 = '"Not(A:Brand";v="99"'        # ≥150

_CHROME_VERSIONS = [
    _chrome_entry("99", _NAB_OLD),
    _chrome_entry("100", _NAB_OLD),
    _chrome_entry("101", _NAB_OLD),
    _chrome_entry("104", _NAB_OLD),
    _chrome_entry("107", _NAB_110),
    _chrome_entry("110", _NAB_110),
    _chrome_entry("116", _NAB_110),
    _chrome_entry("119", _NAB_110),
    _chrome_entry("120", _NAB_110),
    _chrome_entry("123", _NAB_110),
    _chrome_entry("124", _NAB_110),
    _chrome_entry("131", _NAB_110),
    _chrome_entry("133a", _NAB_110),
    _chrome_entry("136", _NAB_136),
    _chrome_entry("142", _NAB_136),
    _chrome_entry("145", _NAB_136),
    _chrome_entry("146", _NAB_146),
    _chrome_entry("150", _NAB_150),
]

# Edge（Chromium 内核，独立 TLS 画像）
_EDGE_VERSIONS = [
    {"impersonate": "edge99", "ver": "99", "full_ver": "99.0.0.0", "not_a_brand": _NAB_OLD},
    {"impersonate": "edge101", "ver": "101", "full_ver": "101.0.0.0", "not_a_brand": _NAB_OLD},
]

_WIN_SCREENS = [
    "1920x1080",
    "1366x768",
    "2560x1440",
    "1536x864",
    "1440x900",
]

# ---------------------------------------------------------------------------
# Firefox（macOS 轮廓）—— curl_cffi 支持的全部桌面版本
# ---------------------------------------------------------------------------
_FIREFOX_VERSIONS = [
    {"impersonate": "firefox133", "ver": "133.0"},
    {"impersonate": "firefox135", "ver": "135.0"},
    {"impersonate": "firefox144", "ver": "144.0"},
    {"impersonate": "firefox147", "ver": "147.0"},
]

# ── TLS 指纹版本级权重（2026-09-26 全版本数据采集模式）──
# 全部桌面版本等权入池：每个版本在 1600 号批次里拿到大致相同的样本量，
# 用实网结果统计各版本的 CF 通过率 / 试用率。iOS 三档不在桌面注册池。
_SAFARI_VERSION_WEIGHTS = {
    "safari15_3": 1, "safari15_5": 1, "safari17_0": 1, "safari18_0": 1,
    "safari184": 1, "safari260": 1, "safari2601": 1,
}
_CHROME_VERSION_WEIGHTS = {entry["impersonate"]: 1 for entry in _CHROME_VERSIONS}
_EDGE_VERSION_WEIGHTS = {entry["impersonate"]: 1 for entry in _EDGE_VERSIONS}

# ── 2026-09-26 全版本对照模式（恢复）──
# 第一轮全版本对照：2 个可领试用号出自 firefox（147+NL、144+JP），但样本太小，
# 且随后 147 单版本跑了 460 个号 0 试用 —— 无法证明版本与试用相关。
# 按主人要求恢复全版本测试：8 个桌面版本等权，继续用实网数据说话。
_FIREFOX_CORE_WEIGHTS = [(8, 25), (10, 25), (12, 25), (16, 25)]
_FIREFOX_VERSION_WEIGHTS = {
    "firefox133": 1, "firefox135": 1, "firefox144": 1, "firefox147": 1,
}


def _weighted_pick(r: random.Random, options: list, weights: list[int]):
    """按权重从 options 里抽一个值。weights 与 options 一一对应。"""
    if len(options) != len(weights):
        raise ValueError("weighted pick: options/weights 长度不一致")
    return r.choices(options, weights=weights, k=1)[0]

# ---------------------------------------------------------------------------
# 国家 → 时区/语言画像（IP 地理联动优化）
# ---------------------------------------------------------------------------
_COUNTRY_PROFILES = {
    # 亚洲
    "JP": {
        "timezones": [("Asia/Tokyo", 1.0)],
        "languages": ["ja-JP", "ja", "en-US", "en", "zh-CN"],
    },
    "CN": {
        "timezones": [("Asia/Shanghai", 1.0)],
        "languages": ["zh-CN", "zh", "en-US", "en"],
    },
    "HK": {
        "timezones": [("Asia/Hong_Kong", 1.0)],
        "languages": ["zh-HK", "zh-CN", "zh", "en-US", "en"],
    },
    "TW": {
        "timezones": [("Asia/Taipei", 1.0)],
        "languages": ["zh-TW", "zh", "en-US", "en", "ja"],
    },
    "KR": {
        "timezones": [("Asia/Seoul", 1.0)],
        "languages": ["ko-KR", "ko", "en-US", "en", "ja"],
    },
    "SG": {
        "timezones": [("Asia/Singapore", 1.0)],
        "languages": ["zh-CN", "zh", "en-US", "en", "ms-MY", "ms"],
    },
    "MY": {
        "timezones": [("Asia/Kuala_Lumpur", 1.0)],
        "languages": ["ms-MY", "ms", "zh-CN", "zh", "en-US", "en"],
    },
    "TH": {
        "timezones": [("Asia/Bangkok", 1.0)],
        "languages": ["th-TH", "th", "en-US", "en"],
    },
    "VN": {
        "timezones": [("Asia/Ho_Chi_Minh", 1.0)],
        "languages": ["vi-VN", "vi", "en-US", "en"],
    },
    "IN": {
        "timezones": [("Asia/Kolkata", 1.0)],
        "languages": ["en-IN", "en-US", "en", "hi-IN", "hi"],
    },
    "ID": {
        "timezones": [("Asia/Jakarta", 1.0)],
        "languages": ["id-ID", "id", "en-US", "en"],
    },
    "PH": {
        "timezones": [("Asia/Manila", 1.0)],
        "languages": ["en-US", "en", "tl-PH", "tl"],
    },
    "PK": {
        "timezones": [("Asia/Karachi", 1.0)],
        "languages": ["en-US", "en", "ur-PK", "ur"],
    },
    "BD": {
        "timezones": [("Asia/Dhaka", 1.0)],
        "languages": ["bn-BD", "bn", "en-US", "en"],
    },
    "IL": {
        "timezones": [("Asia/Jerusalem", 1.0)],
        "languages": ["he-IL", "he", "en-US", "en", "ar"],
    },
    "TR": {
        "timezones": [("Europe/Istanbul", 1.0)],
        "languages": ["tr-TR", "tr", "en-US", "en"],
    },
    "SA": {
        "timezones": [("Asia/Riyadh", 1.0)],
        "languages": ["ar-SA", "ar", "en-US", "en"],
    },
    "AE": {
        "timezones": [("Asia/Dubai", 1.0)],
        "languages": ["ar-AE", "ar", "en-US", "en"],
    },
    # 北美
    "US": {
        "timezones": [
            ("America/New_York", 0.4),      # 东部（数据中心多）
            ("America/Los_Angeles", 0.3),   # 西部
            ("America/Chicago", 0.2),       # 中部
            ("America/Denver", 0.1),        # 山地
        ],
        "languages": ["en-US", "en", "es-US", "es", "zh-CN"],
    },
    "CA": {
        "timezones": [
            ("America/Toronto", 0.6),       # 东部（安大略）
            ("America/Vancouver", 0.3),     # 西部（BC）
            ("America/Edmonton", 0.1),      # 山地（阿尔伯塔）
        ],
        "languages": ["en-CA", "en-US", "en", "fr-CA", "fr"],
    },
    "MX": {
        "timezones": [("America/Mexico_City", 1.0)],
        "languages": ["es-MX", "es", "en-US", "en"],
    },
    # 南美
    "BR": {
        "timezones": [
            ("America/Sao_Paulo", 0.7),
            ("America/Manaus", 0.2),
            ("America/Fortaleza", 0.1),
        ],
        "languages": ["pt-BR", "pt", "en-US", "en", "es"],
    },
    "AR": {
        "timezones": [("America/Argentina/Buenos_Aires", 1.0)],
        "languages": ["es-AR", "es", "en-US", "en"],
    },
    "CL": {
        "timezones": [("America/Santiago", 1.0)],
        "languages": ["es-CL", "es", "en-US", "en"],
    },
    "CO": {
        "timezones": [("America/Bogota", 1.0)],
        "languages": ["es-CO", "es", "en-US", "en"],
    },
    # 欧洲
    "GB": {
        "timezones": [("Europe/London", 1.0)],
        "languages": ["en-GB", "en-US", "en", "fr", "de"],
    },
    "DE": {
        "timezones": [("Europe/Berlin", 1.0)],
        "languages": ["de-DE", "de", "en-US", "en", "fr"],
    },
    "FR": {
        "timezones": [("Europe/Paris", 1.0)],
        "languages": ["fr-FR", "fr", "en-US", "en", "de"],
    },
    "IT": {
        "timezones": [("Europe/Rome", 1.0)],
        "languages": ["it-IT", "it", "en-US", "en", "fr"],
    },
    "ES": {
        "timezones": [("Europe/Madrid", 1.0)],
        "languages": ["es-ES", "es", "en-US", "en", "fr"],
    },
    "NL": {
        "timezones": [("Europe/Amsterdam", 1.0)],
        "languages": ["nl-NL", "nl", "en-US", "en", "de"],
    },
    "BE": {
        "timezones": [("Europe/Brussels", 1.0)],
        "languages": ["nl-BE", "fr-BE", "nl", "fr", "en-US", "en"],
    },
    "CH": {
        "timezones": [("Europe/Zurich", 1.0)],
        "languages": ["de-CH", "fr-CH", "de", "fr", "it", "en-US", "en"],
    },
    "SE": {
        "timezones": [("Europe/Stockholm", 1.0)],
        "languages": ["sv-SE", "sv", "en-US", "en"],
    },
    "NO": {
        "timezones": [("Europe/Oslo", 1.0)],
        "languages": ["nb-NO", "nb", "en-US", "en"],
    },
    "DK": {
        "timezones": [("Europe/Copenhagen", 1.0)],
        "languages": ["da-DK", "da", "en-US", "en"],
    },
    "FI": {
        "timezones": [("Europe/Helsinki", 1.0)],
        "languages": ["fi-FI", "fi", "sv", "en-US", "en"],
    },
    "PL": {
        "timezones": [("Europe/Warsaw", 1.0)],
        "languages": ["pl-PL", "pl", "en-US", "en"],
    },
    "RU": {
        "timezones": [
            ("Europe/Moscow", 0.7),         # 莫斯科（MSK，主要数据中心）
            ("Asia/Yekaterinburg", 0.15),   # 叶卡捷琳堡（+5）
            ("Asia/Novosibirsk", 0.15),     # 新西伯利亚（+7）
        ],
        "languages": ["ru-RU", "ru", "en-US", "en"],
    },
    "UA": {
        "timezones": [("Europe/Kiev", 1.0)],
        "languages": ["uk-UA", "uk", "ru", "en-US", "en"],
    },
    "CZ": {
        "timezones": [("Europe/Prague", 1.0)],
        "languages": ["cs-CZ", "cs", "en-US", "en", "de"],
    },
    "AT": {
        "timezones": [("Europe/Vienna", 1.0)],
        "languages": ["de-AT", "de", "en-US", "en"],
    },
    "GR": {
        "timezones": [("Europe/Athens", 1.0)],
        "languages": ["el-GR", "el", "en-US", "en"],
    },
    "PT": {
        "timezones": [("Europe/Lisbon", 1.0)],
        "languages": ["pt-PT", "pt", "en-US", "en", "es"],
    },
    # 大洋洲
    "AU": {
        "timezones": [
            ("Australia/Sydney", 0.5),      # 悉尼（NSW，数据中心多）
            ("Australia/Melbourne", 0.3),   # 墨尔本（VIC）
            ("Australia/Brisbane", 0.2),    # 布里斯班（QLD）
        ],
        "languages": ["en-AU", "en-US", "en", "zh-CN", "zh"],
    },
    "NZ": {
        "timezones": [("Pacific/Auckland", 1.0)],
        "languages": ["en-NZ", "en-US", "en"],
    },
    # 非洲
    "ZA": {
        "timezones": [("Africa/Johannesburg", 1.0)],
        "languages": ["en-ZA", "en-US", "en", "af"],
    },
    "EG": {
        "timezones": [("Africa/Cairo", 1.0)],
        "languages": ["ar-EG", "ar", "en-US", "en"],
    },
    "NG": {
        "timezones": [("Africa/Lagos", 1.0)],
        "languages": ["en-NG", "en-US", "en"],
    },
    "KE": {
        "timezones": [("Africa/Nairobi", 1.0)],
        "languages": ["sw-KE", "sw", "en-US", "en"],
    },
    # ── 补充：代理实际会落到的国家（2026-09-26 实测出口出现过 / 高概率出现）──
    # 缺画像会掉进 _DEFAULT_COUNTRY_PROFILE（UTC + en-US），出口国家与浏览器
    # 时区/语言对不上，是最典型的「环境不干净」特征，所以宁可把表补全。
    "IS": {
        "timezones": [("Atlantic/Reykjavik", 1.0)],
        "languages": ["is-IS", "is", "en-US", "en"],
    },
    "IE": {
        "timezones": [("Europe/Dublin", 1.0)],
        "languages": ["en-IE", "en-GB", "en-US", "en"],
    },
    "LU": {
        "timezones": [("Europe/Luxembourg", 1.0)],
        "languages": ["fr-LU", "fr", "de-LU", "de", "en-US", "en"],
    },
    "MT": {
        "timezones": [("Europe/Malta", 1.0)],
        "languages": ["mt-MT", "mt", "en-GB", "en"],
    },
    "CY": {
        "timezones": [("Asia/Nicosia", 1.0)],
        "languages": ["el-CY", "el", "en-US", "en"],
    },
    "EE": {
        "timezones": [("Europe/Tallinn", 1.0)],
        "languages": ["et-EE", "et", "en-US", "en", "ru"],
    },
    "LV": {
        "timezones": [("Europe/Riga", 1.0)],
        "languages": ["lv-LV", "lv", "en-US", "en", "ru"],
    },
    "LT": {
        "timezones": [("Europe/Vilnius", 1.0)],
        "languages": ["lt-LT", "lt", "en-US", "en", "ru"],
    },
    "SI": {
        "timezones": [("Europe/Ljubljana", 1.0)],
        "languages": ["sl-SI", "sl", "en-US", "en"],
    },
    "SK": {
        "timezones": [("Europe/Bratislava", 1.0)],
        "languages": ["sk-SK", "sk", "cs", "en-US", "en"],
    },
    "HR": {
        "timezones": [("Europe/Zagreb", 1.0)],
        "languages": ["hr-HR", "hr", "en-US", "en"],
    },
    "BG": {
        "timezones": [("Europe/Sofia", 1.0)],
        "languages": ["bg-BG", "bg", "en-US", "en"],
    },
    "RO": {
        "timezones": [("Europe/Bucharest", 1.0)],
        "languages": ["ro-RO", "ro", "en-US", "en"],
    },
    "HU": {
        "timezones": [("Europe/Budapest", 1.0)],
        "languages": ["hu-HU", "hu", "en-US", "en"],
    },
    "RS": {
        "timezones": [("Europe/Belgrade", 1.0)],
        "languages": ["sr-RS", "sr", "en-US", "en"],
    },
    "MD": {
        "timezones": [("Europe/Chisinau", 1.0)],
        "languages": ["ro-MD", "ro", "ru", "en-US", "en"],
    },
    "HN": {
        "timezones": [("America/Tegucigalpa", 1.0)],
        "languages": ["es-HN", "es", "en-US", "en"],
    },
    "DO": {
        "timezones": [("America/Santo_Domingo", 1.0)],
        "languages": ["es-DO", "es", "en-US", "en"],
    },
    "PY": {
        "timezones": [("America/Asuncion", 1.0)],
        "languages": ["es-PY", "es", "gn", "en-US", "en"],
    },
    "KH": {
        "timezones": [("Asia/Phnom_Penh", 1.0)],
        "languages": ["km-KH", "km", "en-US", "en"],
    },
    "MO": {
        "timezones": [("Asia/Macau", 1.0)],
        "languages": ["zh-MO", "zh-HK", "zh", "pt", "en-US", "en"],
    },
    "BN": {
        "timezones": [("Asia/Brunei", 1.0)],
        "languages": ["ms-BN", "ms", "en-US", "en"],
    },
    "MN": {
        "timezones": [("Asia/Ulaanbaatar", 1.0)],
        "languages": ["mn-MN", "mn", "en-US", "en"],
    },
    "NP": {
        "timezones": [("Asia/Kathmandu", 1.0)],
        "languages": ["ne-NP", "ne", "en-US", "en"],
    },
    "LK": {
        "timezones": [("Asia/Colombo", 1.0)],
        "languages": ["si-LK", "si", "en-US", "en", "ta"],
    },
    "CR": {
        "timezones": [("America/Costa_Rica", 1.0)],
        "languages": ["es-CR", "es", "en-US", "en"],
    },
    "PA": {
        "timezones": [("America/Panama", 1.0)],
        "languages": ["es-PA", "es", "en-US", "en"],
    },
    "GT": {
        "timezones": [("America/Guatemala", 1.0)],
        "languages": ["es-GT", "es", "en-US", "en"],
    },
    "EC": {
        "timezones": [("America/Guayaquil", 1.0)],
        "languages": ["es-EC", "es", "en-US", "en"],
    },
    "PE": {
        "timezones": [("America/Lima", 1.0)],
        "languages": ["es-PE", "es", "en-US", "en"],
    },
    "UY": {
        "timezones": [("America/Montevideo", 1.0)],
        "languages": ["es-UY", "es", "en-US", "en"],
    },
    "PR": {
        "timezones": [("America/Puerto_Rico", 1.0)],
        "languages": ["es-PR", "es", "en-US", "en"],
    },
    # ── 全球随机出口补充（2026-09-27）──
    # 主人改用全球随机 IP 后，这里把常见出口国的时区/语言补齐；
    # 表里仍没有的国家由 environment.allocate_environment 直接跳过，
    # 不会出现「出口在 A 国、画像却是 UTC/en-US」的破绽。
    "TN": {"timezones": [("Africa/Tunis", 1.0)],
           "languages": ["ar-TN", "ar", "fr-TN", "fr", "en-US", "en"]},
    "DZ": {"timezones": [("Africa/Algiers", 1.0)],
           "languages": ["ar-DZ", "ar", "fr-FR", "fr", "en-US", "en"]},
    "MA": {"timezones": [("Africa/Casablanca", 1.0)],
           "languages": ["ar-MA", "ar", "fr-MA", "fr", "en-US", "en"]},
    "EG": {"timezones": [("Africa/Cairo", 1.0)],
           "languages": ["ar-EG", "ar", "en-US", "en"]},
    "JO": {"timezones": [("Asia/Amman", 1.0)],
           "languages": ["ar-JO", "ar", "en-US", "en"]},
    "LB": {"timezones": [("Asia/Beirut", 1.0)],
           "languages": ["ar-LB", "ar", "fr-LB", "fr", "en-US", "en"]},
    "KW": {"timezones": [("Asia/Kuwait", 1.0)],
           "languages": ["ar-KW", "ar", "en-US", "en"]},
    "QA": {"timezones": [("Asia/Qatar", 1.0)],
           "languages": ["ar-QA", "ar", "en-US", "en"]},
    "BH": {"timezones": [("Asia/Bahrain", 1.0)],
           "languages": ["ar-BH", "ar", "en-US", "en"]},
    "OM": {"timezones": [("Asia/Muscat", 1.0)],
           "languages": ["ar-OM", "ar", "en-US", "en"]},
    "IQ": {"timezones": [("Asia/Baghdad", 1.0)],
           "languages": ["ar-IQ", "ar", "en-US", "en"]},
    "KZ": {"timezones": [("Asia/Almaty", 1.0)],
           "languages": ["kk-KZ", "kk", "ru-KZ", "ru", "en-US", "en"]},
    "UZ": {"timezones": [("Asia/Tashkent", 1.0)],
           "languages": ["uz-UZ", "uz", "ru-RU", "ru", "en-US", "en"]},
    "KG": {"timezones": [("Asia/Bishkek", 1.0)],
           "languages": ["ky-KG", "ky", "ru-RU", "ru", "en-US", "en"]},
    "GE": {"timezones": [("Asia/Tbilisi", 1.0)],
           "languages": ["ka-GE", "ka", "en-US", "en", "ru-RU", "ru"]},
    "AM": {"timezones": [("Asia/Yerevan", 1.0)],
           "languages": ["hy-AM", "hy", "ru-RU", "ru", "en-US", "en"]},
    "AZ": {"timezones": [("Asia/Baku", 1.0)],
           "languages": ["az-AZ", "az", "ru-RU", "ru", "en-US", "en"]},
    "VE": {"timezones": [("America/Caracas", 1.0)],
           "languages": ["es-VE", "es", "en-US", "en"]},
    "BO": {"timezones": [("America/La_Paz", 1.0)],
           "languages": ["es-BO", "es", "en-US", "en"]},
    "JM": {"timezones": [("America/Jamaica", 1.0)],
           "languages": ["en-JM", "en-US", "en"]},
    "TT": {"timezones": [("America/Port_of_Spain", 1.0)],
           "languages": ["en-TT", "en-US", "en"]},
    "BS": {"timezones": [("America/Nassau", 1.0)],
           "languages": ["en-BS", "en-US", "en"]},
    "BA": {"timezones": [("Europe/Sarajevo", 1.0)],
           "languages": ["bs-BA", "bs", "hr-HR", "sr-RS", "en-US", "en"]},
    "AL": {"timezones": [("Europe/Tirane", 1.0)],
           "languages": ["sq-AL", "sq", "en-US", "en", "it-IT", "it"]},
    "MK": {"timezones": [("Europe/Skopje", 1.0)],
           "languages": ["mk-MK", "mk", "en-US", "en"]},
    "ME": {"timezones": [("Europe/Podgorica", 1.0)],
           "languages": ["sr-ME", "sr", "en-US", "en"]},
    "BY": {"timezones": [("Europe/Minsk", 1.0)],
           "languages": ["ru-BY", "ru", "be-BY", "en-US", "en"]},
    "GH": {"timezones": [("Africa/Accra", 1.0)],
           "languages": ["en-GH", "en-US", "en"]},
    "TZ": {"timezones": [("Africa/Dar_es_Salaam", 1.0)],
           "languages": ["sw-TZ", "sw", "en-US", "en"]},
    "UG": {"timezones": [("Africa/Kampala", 1.0)],
           "languages": ["en-UG", "en-US", "en", "sw-KE", "sw"]},
    "ZM": {"timezones": [("Africa/Lusaka", 1.0)],
           "languages": ["en-ZM", "en-US", "en"]},
    "ZW": {"timezones": [("Africa/Harare", 1.0)],
           "languages": ["en-ZW", "en-US", "en"]},
    "MZ": {"timezones": [("Africa/Maputo", 1.0)],
           "languages": ["pt-MZ", "pt", "en-US", "en"]},
    "SN": {"timezones": [("Africa/Dakar", 1.0)],
           "languages": ["fr-SN", "fr", "en-US", "en"]},
    "CI": {"timezones": [("Africa/Abidjan", 1.0)],
           "languages": ["fr-CI", "fr", "en-US", "en"]},
    "CM": {"timezones": [("Africa/Douala", 1.0)],
           "languages": ["fr-CM", "fr", "en-US", "en"]},
    "MG": {"timezones": [("Indian/Antananarivo", 1.0)],
           "languages": ["fr-MG", "fr", "mg-MG", "en-US", "en"]},
    "MU": {"timezones": [("Indian/Mauritius", 1.0)],
           "languages": ["en-MU", "en-US", "en", "fr-FR", "fr"]},
    "LA": {"timezones": [("Asia/Vientiane", 1.0)],
           "languages": ["lo-LA", "lo", "th-TH", "en-US", "en"]},
    "MM": {"timezones": [("Asia/Yangon", 1.0)],
           "languages": ["my-MM", "my", "en-US", "en"]},
    "FJ": {"timezones": [("Pacific/Fiji", 1.0)],
           "languages": ["en-FJ", "en-US", "en"]},
    "PG": {"timezones": [("Pacific/Port_Moresby", 1.0)],
           "languages": ["en-PG", "en-US", "en"]},
}

# 兜底策略（未知国家）
_DEFAULT_COUNTRY_PROFILE = {
    "timezones": [("UTC", 1.0)],
    "languages": ["en-US", "en"],
}

# 全量国家画像：主人在用全球随机出口，pytz+babel 生成的补充表把剩余国家
# （124 个）全部补上，出口在任何国家都能配到本地时区 + 主流语言。
try:  # pragma: no cover - 数据文件缺失时退回原行为
    from country_profiles_extra import EXTRA_COUNTRY_PROFILES as _EXTRA_PROFILES

    for _code, _profile in _EXTRA_PROFILES.items():
        _COUNTRY_PROFILES.setdefault(str(_code).upper(), _profile)
except Exception:  # noqa: BLE001
    _EXTRA_PROFILES = {}


def country_context(country_code: str = "") -> tuple[str, str]:
    """Return deterministic fallback (timezone, locale) for a country code.

    Per-task fingerprints still choose weighted values from the same profile. This
    helper is for callers that need a stable preview without creating a profile.
    """
    code = (country_code or "").strip().upper()
    profile = _COUNTRY_PROFILES.get(code, _DEFAULT_COUNTRY_PROFILE)
    return profile["timezones"][0][0], profile["languages"][0]


def supported_country_codes() -> tuple[str, ...]:
    """Return country codes available for explicit task-profile selection."""
    return tuple(sorted(_COUNTRY_PROFILES))


def has_country_profile(country_code: str) -> bool:
    """该国家有没有配套画像（时区/语言）——全球随机出口用它做准入。"""
    return (country_code or "").strip().upper() in _COUNTRY_PROFILES


def screen_dimensions(screen: str) -> tuple[int, int]:
    """Parse a ``WIDTHxHEIGHT`` screen value and reject invalid dimensions."""
    value = str(screen or "").strip().lower()
    try:
        width_text, height_text = value.split("x", 1)
        width, height = int(width_text), int(height_text)
    except (TypeError, ValueError):
        raise ValueError(f"invalid screen dimensions: {screen!r}") from None
    if width <= 0 or height <= 0:
        raise ValueError(f"screen dimensions must be positive: {screen!r}")
    return width, height


def validate_fingerprint(fp: Mapping[str, object]) -> None:
    """Validate the cross-layer invariants required by browser startup.

    A generated profile is intentionally strict here. Silently repairing one field
    at the launcher boundary would make the HTTP/session profile diverge from the
    browser profile again.
    """
    required = (
        "fingerprint_id",
        "browser_type",
        "browser_family",
        "country_code",
        "user_agent",
        "screen",
        "viewport",
        "screen_width",
        "screen_height",
        "locale",
        "lang",
        "lang_full",
        "timezone",
        "navigator_platform",
        "navigator_vendor",
        "hardware_concurrency",
        "max_touch_points",
        "device_pixel_ratio",
        "is_mobile",
        "has_touch",
    )
    missing = [key for key in required if key not in fp]
    if missing:
        raise ValueError(f"fingerprint is missing fields: {', '.join(missing)}")

    browser_type = str(fp["browser_type"])
    family_by_type = {
        "mac_safari": "safari",
        "ios_safari": "safari",
        "chrome": "chrome",
        "edge": "edge",
        "firefox": "firefox",
    }
    expected_family = family_by_type.get(browser_type)
    if expected_family is None:
        raise ValueError(f"unsupported browser_type: {browser_type!r}")
    if fp["browser_family"] != expected_family:
        raise ValueError(
            f"browser family mismatch: {browser_type!r} -> {fp['browser_family']!r}"
        )

    screen_width, screen_height = screen_dimensions(str(fp["screen"]))
    viewport = fp["viewport"]
    if not isinstance(viewport, Mapping):
        raise ValueError("fingerprint viewport must be a mapping")
    try:
        viewport_width = int(viewport["width"])
        viewport_height = int(viewport["height"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("fingerprint viewport must contain integer width/height") from None
    if viewport_width <= 0 or viewport_height <= 0:
        raise ValueError("fingerprint viewport must be positive")
    if viewport_width > screen_width or viewport_height > screen_height:
        raise ValueError(
            "viewport cannot exceed the screen: "
            f"screen={screen_width}x{screen_height}, "
            f"viewport={viewport_width}x{viewport_height}"
        )
    # 真实浏览器窗口一定比屏幕矮（菜单栏 + 标签栏 + 工具栏），宽度可以等于
    # 屏幕（最大化）但不能反过来比屏幕大。
    if viewport_height > screen_height - 40:
        raise ValueError(
            "viewport must leave room for browser chrome: "
            f"screen={screen_width}x{screen_height}, "
            f"viewport={viewport_width}x{viewport_height}"
        )
    try:
        if int(fp["screen_width"]) != screen_width or int(fp["screen_height"]) != screen_height:
            raise ValueError("fingerprint screen_width/screen_height do not match screen")
    except (TypeError, ValueError):
        raise ValueError("fingerprint screen_width/screen_height must match screen") from None
    if str(fp["locale"]).strip() != str(fp["lang"]).strip():
        raise ValueError("fingerprint locale and lang must match")
    if not str(fp["lang"]).strip() or not str(fp["lang_full"]).strip():
        raise ValueError("fingerprint language fields must not be empty")
    if not str(fp["lang_full"]).strip().startswith(str(fp["lang"]).strip()):
        raise ValueError("fingerprint Accept-Language must start with lang")
    if not str(fp["timezone"]).strip():
        raise ValueError("fingerprint timezone must not be empty")
    if bool(fp["has_touch"]) != (int(fp["max_touch_points"]) > 0):
        raise ValueError("fingerprint has_touch and max_touch_points disagree")
    if bool(fp["is_mobile"]) != (browser_type == "ios_safari"):
        raise ValueError("fingerprint is_mobile does not match browser_type")
    if browser_type == "chrome":
        if "Chrome/" not in str(fp["user_agent"]) or fp["navigator_platform"] != "MacIntel":
            raise ValueError("Chrome fingerprint has an incompatible UA or platform")
    elif browser_type == "edge":
        if "Edg/" not in str(fp["user_agent"]) or fp["navigator_platform"] != "MacIntel":
            raise ValueError("Edge fingerprint has an incompatible UA or platform")
    elif browser_type == "firefox":
        if "Firefox/" not in str(fp["user_agent"]) or fp["navigator_platform"] != "MacIntel":
            raise ValueError("Firefox fingerprint has an incompatible UA or platform")
    elif browser_type == "mac_safari":
        if "Safari/" not in str(fp["user_agent"]) or fp["navigator_platform"] != "MacIntel":
            raise ValueError("macOS Safari fingerprint has an incompatible UA or platform")
    elif browser_type == "ios_safari":
        if "iPhone" not in str(fp["user_agent"]) or fp["navigator_platform"] != "iPhone":
            raise ValueError("iOS Safari fingerprint has an incompatible UA or platform")

    try:
        if float(fp["device_pixel_ratio"]) <= 0:
            raise ValueError("fingerprint device_pixel_ratio must be positive")
    except (TypeError, ValueError):
        raise ValueError("fingerprint device_pixel_ratio must be positive") from None

    languages = fp.get("languages")
    if languages is not None:
        if not isinstance(languages, (list, tuple)) or not languages:
            raise ValueError("fingerprint languages must be a non-empty list")
        if str(languages[0]).strip() != str(fp["lang"]).strip():
            raise ValueError("fingerprint languages must start with lang")


# ---------------------------------------------------------------------------
# 浏览器原生请求头画像（按家族 + 版本给差异）
# ---------------------------------------------------------------------------
# 协议注册时服务端能看到的只有 TLS + 请求头 + 时序，头部「值」必须和自称的
# 浏览器版本对得上，否则就是自相矛盾的假画像。已知的真实差异：
#   · Accept-Encoding 的 zstd：Chrome/Edge ≥123、Firefox ≥126 才发；
#     更老的 Chrome 和所有 Safari 都不发（发了等于自称未来版本浏览器）。
#   · Priority 头（document: u=0,i / fetch: u=1,i）：Chrome/Edge ≥117 才发。
#   · Accept：Safari 不带 image/avif/apng 与 signed-exchange；Firefox 不带 apng。
_CHROME_LIKE_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8,"
    "application/signed-exchange;v=b3;q=0.7"
)
_SAFARI_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_FIREFOX_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,*/*;q=0.8"
)


def _impersonate_major(impersonate: str) -> int:
    """从 impersonate 名里取主版本号（chrome133a → 133，edge99 → 99）。"""
    digits = ""
    for ch in str(impersonate or "")[::-1]:
        if ch.isdigit():
            digits = ch + digits
        elif digits:
            break
    return int(digits) if digits else 0


def header_profile(fp: Mapping[str, object], *, kind: str = "document") -> dict[str, str]:
    """按指纹的家族/版本给出真实浏览器会发的头字段值。

    kind="document" 用于整页导航（priority u=0,i），
    kind="fetch" 用于 XHR（priority u=1,i）。
    返回的 priority 为空串表示该浏览器/版本根本不发这个头。
    """
    browser_type = str(fp.get("browser_type") or "")
    major = _impersonate_major(str(fp.get("impersonate") or ""))
    if browser_type in ("chrome", "edge"):
        accept = _CHROME_LIKE_ACCEPT
        encoding = "gzip, deflate, br, zstd" if major >= 123 else "gzip, deflate, br"
        priority = ("u=0, i" if kind == "document" else "u=1, i") if major >= 117 else ""
    elif browser_type == "firefox":
        accept = _FIREFOX_ACCEPT
        encoding = "gzip, deflate, br, zstd" if major >= 126 else "gzip, deflate, br"
        priority = ""
    elif browser_type == "mac_safari":
        accept = _SAFARI_ACCEPT
        encoding = "gzip, deflate, br"
        priority = ""
    else:
        # 未知家族退回最保守的集合（老版本 Chrome 口径）
        accept = _CHROME_LIKE_ACCEPT
        encoding = "gzip, deflate, br"
        priority = ""
    return {"accept": accept, "accept_encoding": encoding, "priority": priority}


# ---------------------------------------------------------------------------
# 版本自洽闸门：TLS 指纹 / UA / Client Hints / 请求头画像必须说同一个版本
# ---------------------------------------------------------------------------
_UA_CHROME_RE = re.compile(r"Chrome/(\d+)(?:\.\d+)*")
_UA_EDG_RE = re.compile(r"Edg/(\d+)(?:\.\d+)*")
_UA_FIREFOX_RE = re.compile(r"Firefox/(\d+)(?:\.\d+)*")
_UA_SAFARI_RE = re.compile(r"Version/(\d+(?:\.\d+)*)")


def _ua_version_number(pattern: re.Pattern[str], ua: str) -> str:
    match = pattern.search(ua or "")
    return match.group(1) if match else ""


def _hint_brand_version(value: str, brand: str) -> str:
    match = re.search(rf'"{re.escape(brand)}";v="([^"]*)"', value or "")
    return match.group(1) if match else ""


def check_version_consistency(fp: Mapping[str, object]) -> dict:
    """校验「TLS 指纹 / UA / Client Hints / 头画像」是不是同一套版本。

    这是协议链路"绝对真实"的硬门槛：服务端只要发现 UA 自称 Chrome/136、
    sec-ch-ua 却写 v="146"，或者 Safari/Firefox 发了 client hints，就能一眼
    判定是伪装的自动化客户端。生成端本来就不该造出这种组合，这个函数负责在
    任务启动前挡住它，并给出可存档的自检报告。
    """
    browser_type = str(fp.get("browser_type") or "")
    family = str(fp.get("browser_family") or "")
    impersonate = str(fp.get("impersonate") or "")
    ua = str(fp.get("user_agent") or "")
    entry = _ALL_IMPERSONATES.get(impersonate) or {}
    entry_data = entry.get("data") or {}
    # Safari 的 impersonate 名带平台后缀（safari18_0_ios），版本号只能从
    # 版本表里取；Chrome/Edge/Firefox 才用尾部数字。
    if family == "safari":
        declared_safari = str(entry_data.get("safari_ver") or "")
        major_s = declared_safari.split(".")[0] if declared_safari else ""
        major = int(major_s) if major_s.isdigit() else 0
    else:
        declared_safari = ""
        major = _impersonate_major(impersonate)
        major_s = str(major) if major else ""
    profile = header_profile(fp, kind="document")
    sec_ch_ua = str(fp.get("sec_ch_ua") or "")
    full_list = str(fp.get("sec_ch_ua_full_version_list") or "")
    errors: list[str] = []
    ua_version = ""
    hint_version = ""

    if not major:
        errors.append(f"impersonate 没有版本号: {impersonate!r}")

    if browser_type == "chrome":
        ua_version = _ua_version_number(_UA_CHROME_RE, ua)
        hint_version = _hint_brand_version(sec_ch_ua, "Google Chrome") or _hint_brand_version(
            sec_ch_ua, "Chromium"
        )
        if ua_version != major_s:
            errors.append(
                f"UA Chrome/{ua_version or '?'} 与 impersonate {impersonate or '?'} 版本不一致"
            )
        for brand in ("Chromium", "Google Chrome"):
            version = _hint_brand_version(sec_ch_ua, brand)
            if version != major_s:
                errors.append(
                    f'sec-ch-ua {brand} v="{version or "?"}" 与 '
                    f"impersonate {impersonate or '?'} 不一致"
                )
        full_version = f"{major_s}.0.0.0" if major_s else ""
        if full_list and _hint_brand_version(full_list, "Google Chrome") != full_version:
            errors.append(f"sec-ch-ua-full-version-list 与 {full_version or '?'} 不一致")
        if str(fp.get("sec_ch_ua_platform") or "") != '"macOS"':
            errors.append('Chrome 轮廓的 sec-ch-ua-platform 必须是 "macOS"')
        if str(fp.get("navigator_platform") or "") != "MacIntel":
            errors.append("Chrome 轮廓的 navigator.platform 必须是 MacIntel")
    elif browser_type == "edge":
        ua_version = _ua_version_number(_UA_EDG_RE, ua)
        chrome_version = _ua_version_number(_UA_CHROME_RE, ua)
        hint_version = _hint_brand_version(sec_ch_ua, "Microsoft Edge")
        if ua_version != major_s:
            errors.append(
                f"UA Edg/{ua_version or '?'} 与 impersonate {impersonate or '?'} 版本不一致"
            )
        if chrome_version != major_s:
            errors.append(
                f"UA Chrome/{chrome_version or '?'} 与 Edge 内核版本 {major_s or '?'} 不一致"
            )
        for brand in ("Microsoft Edge", "Chromium"):
            version = _hint_brand_version(sec_ch_ua, brand)
            if version != major_s:
                errors.append(
                    f'sec-ch-ua {brand} v="{version or "?"}" 与 '
                    f"impersonate {impersonate or '?'} 不一致"
                )
        if str(fp.get("navigator_platform") or "") != "MacIntel":
            errors.append("Edge 轮廓的 navigator.platform 必须是 MacIntel")
    elif browser_type == "firefox":
        ua_version = _ua_version_number(_UA_FIREFOX_RE, ua)
        if not ua_version or (major_s and not ua_version.startswith(major_s)):
            errors.append(
                f"UA Firefox/{ua_version or '?'} 与 impersonate {impersonate or '?'} 版本不一致"
            )
        if sec_ch_ua:
            errors.append("Firefox 一个 client hint 都不发，sec_ch_ua 必须为空")
    elif family == "safari":
        ua_version = _ua_version_number(_UA_SAFARI_RE, ua)
        if not ua_version or (declared_safari and ua_version != declared_safari):
            errors.append(
                f"UA Version/{ua_version or '?'} 与 impersonate {impersonate or '?'} 不一致"
            )
        if sec_ch_ua:
            errors.append("Safari 一个 client hint 都不发，sec_ch_ua 必须为空")
    else:
        errors.append(f"未知 browser_type: {browser_type!r}")

    # 请求头画像的版本阈值：zstd / priority 发不发必须和自称的版本对得上
    if browser_type in ("chrome", "edge"):
        wants_zstd, wants_priority = major >= 123, major >= 117
    elif browser_type == "firefox":
        wants_zstd, wants_priority = major >= 126, False
    else:
        wants_zstd, wants_priority = False, False
    has_zstd = "zstd" in str(profile.get("accept_encoding") or "")
    has_priority = bool(str(profile.get("priority") or ""))
    if has_zstd != wants_zstd:
        errors.append(
            f"Accept-Encoding zstd={'有' if has_zstd else '无'} 与版本 {major_s or '?'} 不符"
        )
    if has_priority != wants_priority:
        errors.append(
            f"priority={'有' if has_priority else '无'} 与版本 {major_s or '?'} 不符"
        )

    return {
        "ok": not errors,
        "impersonate": impersonate,
        "impersonate_major": major_s,
        "ua_version": ua_version,
        "client_hint_version": hint_version,
        "accept_encoding": str(profile.get("accept_encoding") or ""),
        "priority": str(profile.get("priority") or ""),
        "errors": errors,
    }


def browser_family_for_type(browser_type: str) -> str:
    """Map a generated browser type to the actual Playwright engine family."""
    try:
        return {
            "mac_safari": "safari",
            "ios_safari": "safari",
            "chrome": "chrome",
            "edge": "edge",
            "firefox": "firefox",
        }[browser_type]
    except KeyError:
        raise ValueError(f"unsupported browser_type: {browser_type!r}") from None


def browser_types_for_family(browser_family: str) -> tuple[str, ...]:
    """Return concrete profile types for a UI-level browser family policy."""
    family = (browser_family or "auto").strip().lower()
    if family in ("auto", "random"):
        return tuple(_BROWSER_TYPES)
    if family == "safari":
        return ("mac_safari", "ios_safari")
    if family in ("chrome", "firefox"):
        return (family,)
    if family in _GENERATORS:
        return (family,)
    raise ValueError(f"unsupported browser_family: {browser_family!r}")


def _browser_type_for_policy(
    browser_family: str,
    r: random.Random,
    *,
    prefer_firefox: bool = False,
) -> str:
    family = (browser_family or "auto").strip().lower()
    if prefer_firefox and family in ("", "auto", "random"):
        return "firefox"
    if family == "mixed":
        kinds = list(_MIXED_FAMILY_WEIGHTS)
        weights = [_MIXED_FAMILY_WEIGHTS[k] for k in kinds]
        return r.choices(kinds, weights=weights, k=1)[0]
    choices = browser_types_for_family(family)
    return r.choice(list(choices))

# ---------------------------------------------------------------------------
# 共享（旧的固定语言列表，保留兼容性）
# ---------------------------------------------------------------------------
_LANGUAGES = [
    ("en-US", "en-US,en;q=0.9"),
    ("en-US", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7"),
    ("en-GB", "en-GB,en;q=0.9,en-US;q=0.8"),
    ("en-US", "en-US,en;q=0.9,ja;q=0.8"),
]

_BROWSER_WEIGHTS = [
    ("mac_safari", 30),
    ("ios_safari", 15),
    ("chrome",     35),
    ("firefox",    20),
]

_BROWSER_TYPES = [t for t, _ in _BROWSER_WEIGHTS]
_WEIGHTS = [w for _, w in _BROWSER_WEIGHTS]

# 协议注册"混池"轮换：每个新任务按权重抽一个浏览器家族，避免整批账号共用
# 一套指纹配置。2026-09-26 全版本对照模式：mac_safari 2 档 / chrome 4 档 /
# firefox 2 档全部入池、每档等权（家族权重 2:4:2），用实网数据统计各版本表现。
# 整个混池只呈现 macOS 环境，不含 iOS、不含 Windows。
# 每档版本等权：家族权重 = 该家族的版本数（safari 7 / chrome 18 / firefox 4 /
# edge 2，共 31 档），抽到每个具体版本的概率都是 1/31。
_MIXED_FAMILY_WEIGHTS = {"mac_safari": 7, "chrome": 18, "firefox": 4, "edge": 2}


# ---------------------------------------------------------------------------
# 硬件 / navigator 一致性画像（按浏览器家族绑定）
#
# 关键点：navigator.platform / vendor / deviceMemory 在不同引擎行为不同——
#   - vendor:       Safari/iOS="Apple Computer, Inc."，Chrome="Google Inc."，
#                   Firefox=""（空串，不是 undefined）
#   - deviceMemory: 仅 Chromium 暴露且 spec 封顶 8；Safari/Firefox 为 None(undefined)
#   - platform:     mac_safari/chrome/firefox=MacIntel, ios_safari=iPhone（全 macOS 化）
#   - maxTouchPoints: 只有 iOS 触摸屏=5，其余=0
#   - devicePixelRatio: Retina=2.0/3.0，Windows 常见 1.0/1.25/1.5
# 这些值在一次注册内必须**固定**（真实浏览器同会话不会变），故在
# generate_fingerprint() 里用同一个 RNG 一次性定死，写进指纹 dict。
# ---------------------------------------------------------------------------
_HARDWARE_PROFILES = {
    "mac_safari": {
        "navigator_platform": "MacIntel",
        "navigator_vendor": "Apple Computer, Inc.",
        "hardware_concurrency": [8, 10, 12, 16],
        "device_memory": [None],          # Safari 不暴露 deviceMemory
        "max_touch_points": [0],
        "device_pixel_ratio": [2.0],      # Retina 必定 2.0
    },
    "ios_safari": {
        "navigator_platform": "iPhone",
        "navigator_vendor": "Apple Computer, Inc.",
        "hardware_concurrency": [4, 6],   # A15/A16/A17
        "device_memory": [None],          # iOS Safari 不暴露
        "max_touch_points": [5],          # 触摸屏
        "device_pixel_ratio": [2.0, 3.0],
    },
    "chrome": {
        "navigator_platform": "MacIntel",
        "navigator_vendor": "Google Inc.",
        "hardware_concurrency": [8, 10, 12, 16],
        "device_memory": [8],             # spec 封顶 8，Mac Chrome 实测为 8
        "max_touch_points": [0],
        "device_pixel_ratio": [2.0],      # Retina
    },
    "edge": {
        # Edge 与 Chrome 同为 Chromium：navigator.vendor 同样是 "Google Inc."
        "navigator_platform": "MacIntel",
        "navigator_vendor": "Google Inc.",
        "hardware_concurrency": [8, 10, 12, 16],
        "device_memory": [8],
        "max_touch_points": [0],
        "device_pixel_ratio": [2.0],
    },
    "firefox": {
        "navigator_platform": "MacIntel",
        "navigator_vendor": "",           # Firefox navigator.vendor 为空串
        "hardware_concurrency": [8, 10, 12, 16],
        "device_memory": [None],          # Firefox 不暴露 deviceMemory
        "max_touch_points": [0],
        "device_pixel_ratio": [2.0],      # Retina
    },
}


def _apply_hardware(fp: dict, r: random.Random, weighted: bool = True) -> None:
    """按 browser_type 从画像池抽一套一致的硬件参数写进指纹 dict。"""
    prof = _HARDWARE_PROFILES.get(fp["browser_type"], _HARDWARE_PROFILES["chrome"])
    fp["navigator_platform"] = prof["navigator_platform"]
    fp["navigator_vendor"] = prof["navigator_vendor"]
    if weighted and fp["browser_type"] == "firefox":
        fp["hardware_concurrency"] = _weighted_pick(
            r,
            [c for c, _ in _FIREFOX_CORE_WEIGHTS],
            [w for _, w in _FIREFOX_CORE_WEIGHTS],
        )
    else:
        fp["hardware_concurrency"] = r.choice(prof["hardware_concurrency"])
    fp["device_memory"] = r.choice(prof["device_memory"])
    fp["max_touch_points"] = r.choice(prof["max_touch_points"])
    fp["device_pixel_ratio"] = r.choice(prof["device_pixel_ratio"])


# ---------------------------------------------------------------------------
# macOS 真机机型表：屏幕 / DPR / 核心数 / GPU / 系统版本必须同源
#
# 主人要求「德要配位」：不能再出现 Chrome 104（2022-08）配 macOS 15.3、
# 或 12 核 M2 Pro 配 1366x768 这种不可能的组合。每个任务先抽一台真实机型，
# 屏幕、DPR、核心数、GPU、系统版本全从这台机器推导；机型上市时间必须早于
# 所抽浏览器版本的发布时间，系统版本必须是该浏览器发布时已经存在的版本。
# ---------------------------------------------------------------------------
_MAC_DEVICES = (
    {"id": "mbp13_intel19", "screen": "1440x900", "dpr": 2.0, "cores": 8,
     "gpu_vendor": "Intel Inc.",
     "gpu_renderer": "Intel Iris Plus Graphics 655 OpenGL Engine",
     "macos": ("10.15", "12.7"), "since": 201905, "arch": "intel"},
    {"id": "mbp16_intel19", "screen": "1792x1120", "dpr": 2.0, "cores": 8,
     "gpu_vendor": "AMD Inc.",
     "gpu_renderer": "AMD Radeon Pro 5500M OpenGL Engine",
     "macos": ("10.15", "12.7"), "since": 201911, "arch": "intel"},
    {"id": "imac5k_2019", "screen": "2560x1440", "dpr": 2.0, "cores": 6,
     "gpu_vendor": "AMD Inc.",
     "gpu_renderer": "AMD Radeon Pro 580X OpenGL Engine",
     "macos": ("10.15", "12.7"), "since": 201903, "arch": "intel"},
    {"id": "mba_m1", "screen": "1440x900", "dpr": 2.0, "cores": 8,
     "gpu_vendor": "Apple GPU", "gpu_renderer": "Apple M1",
     "macos": ("11.0", "15.7"), "since": 202011, "arch": "apple_silicon"},
    {"id": "mbp14_m1pro", "screen": "1512x982", "dpr": 2.0, "cores": 10,
     "gpu_vendor": "Apple GPU", "gpu_renderer": "Apple M1 Pro",
     "macos": ("12.0", "15.7"), "since": 202110, "arch": "apple_silicon"},
    {"id": "mbp16_m1pro", "screen": "1728x1117", "dpr": 2.0, "cores": 10,
     "gpu_vendor": "Apple GPU", "gpu_renderer": "Apple M1 Pro",
     "macos": ("12.0", "15.7"), "since": 202110, "arch": "apple_silicon"},
    {"id": "mba_m2", "screen": "1470x956", "dpr": 2.0, "cores": 8,
     "gpu_vendor": "Apple GPU", "gpu_renderer": "Apple M2",
     "macos": ("13.0", "15.7"), "since": 202207, "arch": "apple_silicon"},
    {"id": "mac_mini_m2_ext", "screen": "2560x1440", "dpr": 1.0, "cores": 8,
     "gpu_vendor": "Apple GPU", "gpu_renderer": "Apple M2",
     "macos": ("13.0", "15.7"), "since": 202301, "arch": "apple_silicon"},
    {"id": "mbp14_m3pro", "screen": "1512x982", "dpr": 2.0, "cores": 12,
     "gpu_vendor": "Apple GPU", "gpu_renderer": "Apple M3 Pro",
     "macos": ("14.0", "15.7"), "since": 202311, "arch": "apple_silicon"},
    {"id": "mbp16_m4pro", "screen": "1728x1117", "dpr": 2.0, "cores": 14,
     "gpu_vendor": "Apple GPU", "gpu_renderer": "Apple M4 Pro",
     "macos": ("15.0", "26.9"), "since": 202411, "arch": "apple_silicon"},
)

# 浏览器大版本 → 发布时间（YYYYMM）。用于卡住系统版本与机型的上限。
_CHROME_RELEASE_YM = {
    "99": 202203, "100": 202203, "101": 202204, "104": 202208, "107": 202210,
    "110": 202302, "116": 202308, "119": 202311, "120": 202312, "123": 202403,
    "124": 202404, "131": 202411, "133": 202501, "136": 202503, "142": 202509,
    "145": 202512, "146": 202602, "150": 202606,
}
_FIREFOX_RELEASE_YM = {
    "133": 202411, "135": 202501, "144": 202509, "147": 202512,
}
_EDGE_RELEASE_YM = {"99": 202203, "101": 202204}

# macOS 版本发布时间（YYYYMM），系统版本只能从中挑「浏览器发布时已存在」的。
_MACOS_RELEASES = (
    ("10.15", 201910), ("11.0", 202011), ("11.6", 202109), ("12.0", 202110),
    ("12.5", 202207), ("13.0", 202210), ("13.5", 202307), ("14.0", 202309),
    ("14.5", 202405), ("15.0", 202409), ("15.3", 202501), ("15.5", 202505),
    ("26.0", 202509),
)


def _browser_release_ym(family: str, impersonate: str) -> int:
    """所抽浏览器版本的发布时间（YYYYMM），未知返回 0=不限。"""
    major = str(_impersonate_major(impersonate))
    table = {
        "chrome": _CHROME_RELEASE_YM,
        "firefox": _FIREFOX_RELEASE_YM,
        "edge": _EDGE_RELEASE_YM,
    }.get((family or "").strip().lower())
    if table and major in table:
        return table[major]
    return 0


def _safari_macos_from_ua(user_agent: str) -> str:
    """Safari UA 里的 macOS 版本（12_0 → 12.0），没有返回空串。"""
    match = re.search(r"Mac OS X (\d+)_(\d+)", user_agent or "")
    return f"{match.group(1)}.{match.group(2)}" if match else ""


def _browser_min_macos(family: str, major: int) -> str:
    """浏览器版本能跑的最低 macOS：Chrome 128+ 要求 macOS 11+，Firefox 128+ 要 10.15+。"""
    family = (family or "").strip().lower()
    if family in ("chrome", "edge"):
        if major >= 128:
            return "11.0"
        if major >= 110:
            return "10.15"
        return "10.13"
    if family == "firefox":
        return "10.15" if major >= 128 else "10.12"
    return ""


def _eligible_mac_devices(
    browser_ym: int, macos_constraint: str = "", min_macos: str = ""
) -> list[dict]:
    out = []
    for device in _MAC_DEVICES:
        if browser_ym and int(device["since"]) > browser_ym:
            continue
        low, high = device["macos"]
        if macos_constraint:
            if not (low <= macos_constraint <= high):
                continue
        if min_macos:
            # 这台机器在这个浏览器年代里必须有一个「既 ≥ 浏览器最低要求、
            # 又 ≤ 浏览器发布时间」的系统版本可选，否则这台机器配不上这个浏览器。
            usable = [
                version for version, released in _MACOS_RELEASES
                if low <= version <= high
                and version >= min_macos
                and (not browser_ym or released <= browser_ym)
            ]
            if not usable:
                continue
        out.append(device)
    return out or list(_MAC_DEVICES)


def _macos_for_device(device: dict, browser_ym: int, min_macos: str = "") -> str:
    """这台机器在这个浏览器年代能跑的系统版本（取最新且已发布的）。"""
    low, high = device["macos"]
    best = ""
    for version, released in _MACOS_RELEASES:
        if browser_ym and released > browser_ym:
            continue
        if min_macos and version < min_macos:
            continue
        if low <= version <= high:
            best = version
    return best or low


def _apply_device_profile(fp: dict, r: random.Random) -> None:
    """把屏幕/DPR/核心数/GPU/系统版本绑到一台真实 Mac 上，并卡住年代。"""
    family = str(fp.get("browser_family") or "")
    impersonate = str(fp.get("impersonate") or "")
    browser_ym = _browser_release_ym(family, impersonate)
    major = _impersonate_major(impersonate)
    min_macos = _browser_min_macos(family, major)
    # 只有 Safari 的 UA 里写真实 macOS 版本；Chrome/Edge/Firefox 的 UA 被浏览器
    # 冻结在 10_15_7（Chromium 系）或 10.15（Firefox），不能拿来当机型系统版本。
    safari_macos = (
        _safari_macos_from_ua(str(fp.get("user_agent") or ""))
        if str(fp.get("browser_type")) == "mac_safari"
        else ""
    )
    device = r.choice(_eligible_mac_devices(browser_ym, safari_macos, min_macos))

    fp["device_model"] = device["id"]
    fp["device_arch"] = device["arch"]
    fp["screen"] = device["screen"]
    fp["device_pixel_ratio"] = device["dpr"]
    fp["hardware_concurrency"] = device["cores"]
    fp["gpu_vendor"] = device["gpu_vendor"]
    fp["gpu_renderer"] = device["gpu_renderer"]

    macos_version = safari_macos or _macos_for_device(device, browser_ym, min_macos)
    fp["macos_version"] = macos_version
    if str(fp.get("browser_type")) in ("chrome", "edge"):
        # Chrome/Edge 的 client hints 报真实 macOS 版本（UA 里被冻结成 10_15_7）
        fp["sec_ch_ua_platform_version"] = f'"{macos_version}.0"'


def _window_viewport(family: str, screen_width: int, screen_height: int) -> dict:
    """真实浏览器窗口比屏幕小：菜单栏 + 标签栏 + 工具栏吃掉一块高度。"""
    chrome_px = {"chrome": 105, "edge": 105, "firefox": 98}.get(family, 90)
    return {"width": int(screen_width), "height": int(screen_height) - chrome_px}


# ---------------------------------------------------------------------------
# 指纹生成
# ---------------------------------------------------------------------------

def _gen_mac_safari(r: random.Random, weighted: bool = True) -> dict:
    if weighted:
        safari = _weighted_pick(
            r,
            _SAFARI_VERSIONS,
            [_SAFARI_VERSION_WEIGHTS.get(s["impersonate"], 1) for s in _SAFARI_VERSIONS],
        )
    else:
        safari = r.choice(_SAFARI_VERSIONS)
    macos_ver = r.choice(safari["macos_versions"])
    others = [s["impersonate"] for s in _SAFARI_VERSIONS if s["impersonate"] != safari["impersonate"]]
    return {
        "browser_type": "mac_safari",
        "impersonate": safari["impersonate"],
        "fallback_impersonates": [safari["impersonate"]] + r.sample(others, min(2, len(others))),
        "user_agent": (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X {macos_ver}) "
            f"AppleWebKit/{safari['webkit_ver']} (KHTML, like Gecko) "
            f"Version/{safari['safari_ver']} Safari/{safari['webkit_ver']}"
        ),
        "sec_ch_ua": "",
        "sec_ch_ua_platform": "",
        "sec_ch_ua_mobile": "",
        "screen": r.choice(_MAC_SCREENS),
    }


def _gen_ios_safari(r: random.Random, weighted: bool = True) -> dict:
    safari = r.choice(_IOS_SAFARI_VERSIONS)
    ios_ver = r.choice(safari["ios_versions"])
    others = [s["impersonate"] for s in _IOS_SAFARI_VERSIONS if s["impersonate"] != safari["impersonate"]]
    fallbacks = [safari["impersonate"]] + others
    return {
        "browser_type": "ios_safari",
        "impersonate": safari["impersonate"],
        "fallback_impersonates": fallbacks,
        "user_agent": (
            f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios_ver} like Mac OS X) "
            f"AppleWebKit/{safari['webkit_ver']} (KHTML, like Gecko) "
            f"Version/{safari['safari_ver']} Mobile/15E148 Safari/604.1"
        ),
        "sec_ch_ua": "",
        "sec_ch_ua_platform": "",
        "sec_ch_ua_mobile": "",
        "screen": r.choice(_IPHONE_SCREENS),
    }


def _gen_chrome(r: random.Random, weighted: bool = True) -> dict:
    # 从正权重档位抽（全版本数据采集模式下即全部四档），回退列表同样只含
    # 正权重档位；将来若某档被归零，TLS 失败重试也不会轮转回它。
    active = [
        c for c in _CHROME_VERSIONS
        if _CHROME_VERSION_WEIGHTS.get(c["impersonate"], 1) > 0
    ]
    if not active:
        active = _CHROME_VERSIONS
    if weighted:
        chrome = _weighted_pick(
            r,
            active,
            [_CHROME_VERSION_WEIGHTS.get(c["impersonate"], 1) for c in active],
        )
    else:
        chrome = r.choice(active)
    others = [c["impersonate"] for c in active if c["impersonate"] != chrome["impersonate"]]
    sec_ch_ua = (
        f'"Chromium";v="{chrome["ver"]}", '
        f'"Google Chrome";v="{chrome["ver"]}", '
        f'{chrome["not_a_brand"]}'
    )
    # Client Hints 全套：full-version-list 带完整版本号
    sec_ch_ua_full_version_list = (
        f'"Chromium";v="{chrome["full_ver"]}", '
        f'"Google Chrome";v="{chrome["full_ver"]}", '
        f'{chrome["not_a_brand"]}'  # Not.A/Brand 保持主版本号
    )
    # macOS Chrome：UA 里的 macOS 版本被 Chrome 冻结为 10_15_7（真实行为），
    # sec-ch-ua-platform-version 用真实的 macOS 版本号。
    mac_platform_versions = ["14.7.0", "15.3.0", "15.5.0"]
    platform_version = r.choice(mac_platform_versions)

    return {
        "browser_type": "chrome",
        "impersonate": chrome["impersonate"],
        "fallback_impersonates": [chrome["impersonate"]] + r.sample(others, min(2, len(others))),
        "user_agent": (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{chrome['full_ver']} Safari/537.36"
        ),
        "sec_ch_ua": sec_ch_ua,
        "sec_ch_ua_platform": '"macOS"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_full_version_list": sec_ch_ua_full_version_list,
        "sec_ch_ua_arch": '"x86"',  # Intel Mac：UA/MacIntel 与 x86 自洽
        "sec_ch_ua_bitness": '"64"',
        "sec_ch_ua_model": '""',  # 桌面 Chrome model 为空串（引号包空串）
        "sec_ch_ua_platform_version": f'"{platform_version}"',
        "screen": r.choice(_MAC_SCREENS),
    }


# macOS 的 sec-ch-ua-platform-version 取值池（Chrome/Edge 共用）
_MAC_OS_PLATFORM_VERSIONS = ["14.7.0", "15.3.0", "15.5.0"]


def _gen_edge(r: random.Random, weighted: bool = True) -> dict:
    """Edge（Chromium 内核）macOS 轮廓：字段结构与 Chrome 同源，UA/CH 带 Edg 标记。"""
    active = [
        e for e in _EDGE_VERSIONS
        if _EDGE_VERSION_WEIGHTS.get(e["impersonate"], 1) > 0
    ]
    if not active:
        active = _EDGE_VERSIONS
    if weighted:
        edge = _weighted_pick(
            r, active, [_EDGE_VERSION_WEIGHTS.get(e["impersonate"], 1) for e in active]
        )
    else:
        edge = r.choice(active)
    others = [e["impersonate"] for e in active if e["impersonate"] != edge["impersonate"]]
    sec_ch_ua = (
        f'"Microsoft Edge";v="{edge["ver"]}", '
        f'"Chromium";v="{edge["ver"]}", '
        f'{edge["not_a_brand"]}'
    )
    sec_ch_ua_full_version_list = (
        f'"Microsoft Edge";v="{edge["full_ver"]}", '
        f'"Chromium";v="{edge["full_ver"]}", '
        f'{edge["not_a_brand"]}'
    )
    return {
        "browser_type": "edge",
        "impersonate": edge["impersonate"],
        "fallback_impersonates": [edge["impersonate"]] + r.sample(others, min(2, len(others))),
        "user_agent": (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{edge['full_ver']} Safari/537.36 "
            f"Edg/{edge['full_ver']}"
        ),
        "sec_ch_ua": sec_ch_ua,
        "sec_ch_ua_platform": '"macOS"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_full_version_list": sec_ch_ua_full_version_list,
        "sec_ch_ua_arch": '"x86"',
        "sec_ch_ua_bitness": '"64"',
        "sec_ch_ua_model": '""',
        "sec_ch_ua_platform_version": f'"{r.choice(_MAC_OS_PLATFORM_VERSIONS)}"',
        "screen": r.choice(_MAC_SCREENS),
    }


def _gen_firefox(r: random.Random, weighted: bool = True) -> dict:
    # 只从正权重档位抽（当前仅 firefox147）；回退列表同样只含正权重档位，
    # 未加权分支也走这份白名单，保证任何入口都不会冒出 firefox144。
    active = [
        f for f in _FIREFOX_VERSIONS
        if _FIREFOX_VERSION_WEIGHTS.get(f["impersonate"], 1) > 0
    ]
    if not active:
        active = _FIREFOX_VERSIONS
    if weighted:
        ff = _weighted_pick(
            r,
            active,
            [_FIREFOX_VERSION_WEIGHTS.get(v["impersonate"], 1) for v in active],
        )
    else:
        ff = r.choice(active)
    others = [f["impersonate"] for f in active if f["impersonate"] != ff["impersonate"]]
    fallbacks = [ff["impersonate"]] + others
    return {
        "browser_type": "firefox",
        "impersonate": ff["impersonate"],
        "fallback_impersonates": fallbacks,
        "user_agent": (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{ff['ver']}) "
            f"Gecko/20100101 Firefox/{ff['ver']}"
        ),
        "sec_ch_ua": "",
        "sec_ch_ua_platform": "",
        "sec_ch_ua_mobile": "",
        "screen": r.choice(_MAC_SCREENS),
    }


_GENERATORS = {
    "mac_safari": _gen_mac_safari,
    "ios_safari": _gen_ios_safari,
    "chrome": _gen_chrome,
    "edge": _gen_edge,
    "firefox": _gen_firefox,
}


def generate_fingerprint(
    rng: random.Random | None = None,
    country_code: str = "",
    browser_type: str | None = None,
    browser_family: str = "auto",
    *,
    prefer_firefox: bool = False,
    weighted: bool = True,
) -> dict:
    """生成一套一致的浏览器指纹。

    参数:
        rng: 随机数生成器（传入可保证会话内一致性）
        country_code: IP 地理国家码（如 JP/US/DE），用于时区/语言联动优化
        browser_type: 具体画像类型；传入后不会再次随机浏览器家族
        browser_family: auto/random/chrome/firefox/safari 策略
        prefer_firefox: auto 策略下优先使用 Firefox（Camoufox 需要）
        weighted: True 时按历史试用命中率加权抽取屏幕 / 核数 / 版本，
                  False 时退回均匀随机（探索模式）

    返回 dict:
        browser_type: str     — 浏览器家族
        impersonate: str      — curl_cffi TLS 指纹名
        fallback_impersonates: list[str] — 同家族回退 impersonate 列表
        user_agent: str       — 完整 UA 字符串
        sec_ch_ua: str        — Client Hints（仅 Chrome 非空）
        sec_ch_ua_platform: str
        sec_ch_ua_mobile: str
        sec_ch_ua_full_version_list: str — 完整版本号列表（仅 Chrome）
        sec_ch_ua_arch: str              — CPU 架构（仅 Chrome）
        sec_ch_ua_bitness: str           — 位数（仅 Chrome）
        sec_ch_ua_model: str             — 设备型号（仅 Chrome，桌面为空串）
        sec_ch_ua_platform_version: str  — OS 版本号（仅 Chrome）
        screen: str           — 屏幕分辨率 (WxH)
        lang: str             — 主语言
        lang_full: str        — 完整 Accept-Language
        timezone: str         — IANA 时区名（如 Asia/Tokyo）
        navigator_platform: str  — navigator.platform（MacIntel/iPhone/Win32）
        navigator_vendor: str    — navigator.vendor（按引擎；Firefox 为空串）
        hardware_concurrency: int — CPU 逻辑核心数
        device_memory: int|None   — navigator.deviceMemory（仅 Chromium 有值）
        max_touch_points: int     — navigator.maxTouchPoints（iOS=5）
        device_pixel_ratio: float — window.devicePixelRatio
        viewport: dict — 与 screen 完全相同的浏览器 viewport
        fingerprint_id: str — 本次任务唯一画像 ID
    """
    if rng is None:
        # Do not use the process-global RNG: concurrent tasks must not influence
        # each other's profile sequence.
        r = random.Random(secrets.randbits(128))
    else:
        r = rng

    if browser_type is None:
        browser_type = _browser_type_for_policy(
            browser_family,
            r,
            prefer_firefox=prefer_firefox,
        )
    browser_type = str(browser_type).strip().lower()
    if browser_type not in _GENERATORS:
        raise ValueError(f"unsupported browser_type: {browser_type!r}")
    expected_family = browser_family_for_type(browser_type)
    requested_family = (browser_family or "auto").strip().lower()
    if requested_family not in ("", "auto", "random", "mixed", expected_family, browser_type):
        raise ValueError(
            f"browser_type {browser_type!r} does not match browser_family {browser_family!r}"
        )

    fp = _GENERATORS[browser_type](r, weighted=weighted)
    # 机型层/窗口层都要先知道家族，不能等到最后再赋值
    fp["browser_family"] = expected_family

    # IP 地理联动：按国家码选择时区/语言
    country_code = (country_code or "").strip().upper()
    profile = _COUNTRY_PROFILES.get(country_code, _DEFAULT_COUNTRY_PROFILE)

    # 加权随机选择时区
    tz_choices = profile["timezones"]
    tz_list = [tz for tz, _ in tz_choices]
    tz_weights = [w for _, w in tz_choices]
    timezone = r.choices(tz_list, weights=tz_weights, k=1)[0]

    # 多语言优化：从池中随机选 3~5 个，保证第一语言是主语言
    lang_pool = profile["languages"].copy()
    # 目标 3~5 个语言；语言池不足 3 个时按池长度取（避免 randint 下界>上界）
    lo = min(3, len(lang_pool))
    hi = min(5, len(lang_pool))
    num_langs = r.randint(lo, hi)
    primary_lang = lang_pool[0]  # 主语言固定第一位
    primary_base = primary_lang.split("-")[0].lower()
    other_langs = [lang for lang in lang_pool[1:]]
    # 真实浏览器的 Accept-Language 紧跟在主语言后面的是同一语言的裸语言码
    # （de-DE,de;q=0.9,en-US;q=0.8…），其余语言才随机打乱。
    base_lang = next(
        (lang for lang in other_langs if lang.lower() == primary_base), ""
    )
    rest = [lang for lang in other_langs if lang != base_lang]
    r.shuffle(rest)
    selected = [primary_lang] + ([base_lang] if base_lang else []) + rest
    selected = selected[:num_langs]

    # 构建 Accept-Language header（带 q 值权重递减）
    # 真实浏览器格式：主语言无 q，第一个副语言 q=0.9，之后 0.8/0.7…
    lang_parts = []
    for i, lang in enumerate(selected):
        if i == 0:
            lang_parts.append(lang)
        else:
            q = round(1.0 - i * 0.1, 1)  # i=1→0.9, i=2→0.8, ...
            lang_parts.append(f"{lang};q={q}")
    lang_full = ",".join(lang_parts)

    fp["lang"] = primary_lang
    fp["lang_full"] = lang_full
    fp["languages"] = selected
    fp["locale"] = primary_lang
    fp["country_code"] = country_code
    fp["timezone"] = timezone
    _apply_hardware(fp, r, weighted=weighted)
    # 机型层：屏幕/DPR/核心/GPU/系统版本从一台真实 Mac 推导，且必须和
    # 所抽浏览器版本的年代对得上（iPhone 走 _IPHONE_SCREENS，不套机型表）。
    if browser_type != "ios_safari":
        _apply_device_profile(fp, r)

    width, height = screen_dimensions(fp["screen"])
    fp["screen_width"] = width
    fp["screen_height"] = height
    fp["viewport"] = _window_viewport(fp["browser_family"], width, height)
    fp["browser_family"] = expected_family
    fp["is_mobile"] = browser_type == "ios_safari"
    fp["has_touch"] = fp["max_touch_points"] > 0
    fp["fingerprint_id"] = f"fp_{secrets.token_urlsafe(12)}"

    # 非 Chrome 家族补齐空值键（保证调用方统一取值不报 KeyError）
    if browser_type != "chrome":
        fp.setdefault("sec_ch_ua_full_version_list", "")
        fp.setdefault("sec_ch_ua_arch", "")
        fp.setdefault("sec_ch_ua_bitness", "")
        fp.setdefault("sec_ch_ua_model", "")
        fp.setdefault("sec_ch_ua_platform_version", "")

    validate_fingerprint(fp)
    return fp


# Sentinel 侧读数也必须是 Mac：屏幕/DPR/核心/GPU 直接沿用指纹里那台机器，
# 没有指纹时才从真机机型表抽一台（旧版这里是 Windows 屏幕 + ANGLE D3D11 的
# GPU 字符串，跟全 macOS 的协议画像对不上，属于典型的「德不配位」）。
_SILHOUETTE_HEAP = (2172649472, 3221225472, 4294705152, 4395630592)

_SILHOUETTE_CACHE: dict[str, dict] = {}


def device_silhouette(
    device_id: str, fingerprint: Mapping[str, object] | None = None
) -> dict:
    """按 device_id 确定性派生每号设备画像（Sentinel 侧用）。

    同一账号每次调用得到同一套屏幕/CPU/内存/GPU 读数（时间锚点除外，
    首次调用固定后缓存复用），不同账号之间天然不同。此前所有账号共享
    一套硬编码读数（jsHeapSizeLimit 4294967296、固定 Intel GPU、进程时钟
    timeOrigin），整批账号像同一台机器，是可被服务端免费识别的聚类信号。

    传入 fingerprint 时，屏幕 / DPR / 核心数 / GPU / 内存全部取该指纹里
    那台真机（Mac）的字段——协议层和 Sentinel 层必须是同一台机器。
    """
    key = str(device_id or "").strip()
    fp = dict(fingerprint or {})
    fp_id = str(fp.get("fingerprint_id") or "")
    cache_key = f"{key}|{fp_id}" if fp_id else key
    cached = _SILHOUETTE_CACHE.get(cache_key)
    if isinstance(cached, dict):
        return cached
    seed = (key or "device").encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    rng = random.Random(int.from_bytes(digest[:8], "big"))
    now_ms = int(time.time() * 1000)

    device = rng.choice(_MAC_DEVICES)
    screen = str(fp.get("screen") or device["screen"])
    cores = fp.get("hardware_concurrency")
    dpr = fp.get("device_pixel_ratio")
    gpu_vendor = str(fp.get("gpu_vendor") or device["gpu_vendor"])
    gpu_renderer = str(fp.get("gpu_renderer") or device["gpu_renderer"])
    silhouette = {
        "screen": screen,
        "device_pixel_ratio": float(dpr or device["dpr"]),
        "hardware_concurrency": int(cores or device["cores"]),
        # Safari/Firefox 不暴露 deviceMemory，指纹里是 None 就保持 None
        "device_memory": fp.get("device_memory", 8),
        "js_heap_size_limit": rng.choice(_SILHOUETTE_HEAP),
        "time_origin": now_ms - rng.randint(2_000, 900_000),
        "performance_now": round(rng.uniform(500.0, 60_000.0), 3),
        "gpu_vendor": gpu_vendor,
        "gpu_renderer": gpu_renderer,
        "device_model": str(fp.get("device_model") or device["id"]),
    }
    if len(_SILHOUETTE_CACHE) > 4096:
        _SILHOUETTE_CACHE.clear()
    _SILHOUETTE_CACHE[cache_key] = silhouette
    return silhouette


def diagnose_fingerprint(
    fp: Mapping[str, object],
    *,
    engine_type: str = "auto",
    detected_country: str = "",
) -> dict:
    """Return a serialisable consistency report for the WebUI and tests."""
    errors: list[str] = []
    try:
        validate_fingerprint(fp)
    except ValueError as exc:
        errors.append(str(exc))

    version_report = check_version_consistency(fp)
    errors.extend(version_report["errors"])

    browser_type = str(fp.get("browser_type", ""))
    family = str(fp.get("browser_family", ""))
    ua = str(fp.get("user_agent", ""))
    platform = str(fp.get("navigator_platform", ""))
    lang = str(fp.get("lang", ""))
    locale = str(fp.get("locale", ""))
    viewport = fp.get("viewport") if isinstance(fp.get("viewport"), Mapping) else {}
    screen = str(fp.get("screen", ""))

    try:
        screen_size = screen_dimensions(screen)
        viewport_size = (int(viewport.get("width", 0)), int(viewport.get("height", 0)))
    except (TypeError, ValueError):
        screen_size = (0, 0)
        viewport_size = (0, 0)

    ua_matches = {
        "chrome": "Chrome/" in ua and ("Windows NT" in ua or "Macintosh" in ua),
        "edge": "Edg/" in ua and "Chrome/" in ua and "Macintosh" in ua,
        "firefox": "Firefox/" in ua and ("Windows NT" in ua or "Macintosh" in ua),
        "safari": "Safari/" in ua and "AppleWebKit" in ua,
    }.get(family, False)
    platform_matches = {
        "chrome": platform in ("Win32", "MacIntel"),
        "edge": platform in ("Win32", "MacIntel"),
        "firefox": platform in ("Win32", "MacIntel"),
        "safari": platform in ("MacIntel", "iPhone"),
    }.get(family, False)
    country = str(fp.get("country_code", "")).upper()
    observed = (detected_country or "").strip().upper()
    # 画像层：出口国家 → 时区 / 语言必须来自同一个国家的画像表。
    # 表里没有的国家（自定义画像）不参与这条判定。
    country_profile = _COUNTRY_PROFILES.get(country) or {}
    allowed_timezones = {tz for tz, _weight in (country_profile.get("timezones") or [])}
    allowed_languages = {str(v).lower() for v in (country_profile.get("languages") or [])}
    timezone_matches_country = (
        not allowed_timezones or str(fp.get("timezone", "")) in allowed_timezones
    )
    language_matches_country = (
        not allowed_languages or lang.lower() in allowed_languages
    )
    checks = {
        # 真实窗口比屏幕小但不会小得离谱（40~300px 的窗口装饰）
        "screen_matches_viewport": (
            screen_size[0] > 0
            and 0 < viewport_size[0] <= screen_size[0]
            and 40 <= screen_size[1] - viewport_size[1] <= 300
        ),
        "ua_matches_browser_family": ua_matches,
        "platform_matches_browser_family": platform_matches,
        "language_matches_locale": bool(lang and locale and lang == locale),
        "timezone_is_explicit": bool(str(fp.get("timezone", "")).strip()),
        "geoip_override_disabled": True,
        "country_matches_detected": not observed or not country or country == observed,
        "version_consistency": bool(version_report["ok"]),
        "timezone_matches_country": timezone_matches_country,
        "language_matches_country": language_matches_country,
    }
    checks["all_passed"] = not errors and all(checks.values())
    return {
        "fingerprint_id": fp.get("fingerprint_id", ""),
        "browser_type": browser_type,
        "browser_family": family,
        "engine_type": engine_type,
        "country_code": country,
        "detected_country": observed,
        "user_agent": ua,
        "navigator_platform": platform,
        "screen": screen,
        "viewport": dict(viewport),
        "locale": locale,
        "lang": lang,
        "languages": list(fp.get("languages") or []),
        "accept_language": fp.get("lang_full", ""),
        "timezone": fp.get("timezone", ""),
        "device_pixel_ratio": fp.get("device_pixel_ratio"),
        "version": version_report,
        "checks": checks,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# impersonate → UA 映射（TLS 旋转用）
# ---------------------------------------------------------------------------

_ALL_IMPERSONATES: dict[str, dict] = {}

for s in _SAFARI_VERSIONS:
    _ALL_IMPERSONATES[s["impersonate"]] = {"type": "mac_safari", "data": s}
for s in _IOS_SAFARI_VERSIONS:
    _ALL_IMPERSONATES[s["impersonate"]] = {"type": "ios_safari", "data": s}
for c in _CHROME_VERSIONS:
    _ALL_IMPERSONATES[c["impersonate"]] = {"type": "chrome", "data": c}
for e in _EDGE_VERSIONS:
    _ALL_IMPERSONATES[e["impersonate"]] = {"type": "edge", "data": e}
for f in _FIREFOX_VERSIONS:
    _ALL_IMPERSONATES[f["impersonate"]] = {"type": "firefox", "data": f}


def fingerprint_for_impersonate(impersonate: str, current_fp: dict) -> dict:
    """把指纹里**随 impersonate 版本变化**的字段同步到新版本，其余原样保留。

    TLS 旋转（_rotate_impersonate_session）换 impersonate 时，光换 UA 是不够的：
    _common_headers / _navigation_headers 的 sec-ch-ua* 全从指纹取，不同步就会出现
    「UA 说 Chrome/136、sec-ch-ua 说 v=146」，连 not_a_brand 都对不上
    （136:"Not.A/Brand";v="99" / 142:"Not/A)Brand";v="8" / 146:"Not?A_Brand";v="99"），
    是 CF 一抓一个准的自相矛盾特征。

    只动版本相关字段（sec_ch_ua / full_version_list / user_agent），
    屏幕、语言、时区、硬件等会话级属性保持不变 —— 那些跟浏览器版本无关，
    换了反而破坏"同一台机器"的一致性。

    未知 impersonate 或非 Chrome 家族：Safari/Firefox 本就不发 client hints
    （sec_ch_ua 为空串），无需同步，原样返回副本。
    """
    entry = _ALL_IMPERSONATES.get(impersonate)
    fp = dict(current_fp or {})
    if not entry:
        return fp

    t, d = entry["type"], entry["data"]
    fp["impersonate"] = impersonate
    fp["browser_type"] = t
    fp["browser_family"] = browser_family_for_type(t)
    fp["is_mobile"] = t == "ios_safari"
    fp["user_agent"] = ua_for_impersonate(impersonate, fp.get("user_agent", ""))

    if t in ("chrome", "edge"):
        if t == "edge":
            fp["sec_ch_ua"] = (
                f'"Microsoft Edge";v="{d["ver"]}", '
                f'"Chromium";v="{d["ver"]}", '
                f'{d["not_a_brand"]}'
            )
            fp["sec_ch_ua_full_version_list"] = (
                f'"Microsoft Edge";v="{d["full_ver"]}", '
                f'"Chromium";v="{d["full_ver"]}", '
                f'{d["not_a_brand"]}'
            )
        else:
            fp["sec_ch_ua"] = (
                f'"Chromium";v="{d["ver"]}", '
                f'"Google Chrome";v="{d["ver"]}", '
                f'{d["not_a_brand"]}'
            )
            fp["sec_ch_ua_full_version_list"] = (
                f'"Chromium";v="{d["full_ver"]}", '
                f'"Google Chrome";v="{d["full_ver"]}", '
                f'{d["not_a_brand"]}'
            )
        # platform/mobile/arch/bitness/model/platform_version 只跟设备走，
        # 不随 Chrome 版本变，沿用原指纹即可（缺失时给桌面 macOS 默认值）
        fp.setdefault("sec_ch_ua_platform", '"macOS"')
        fp.setdefault("sec_ch_ua_mobile", "?0")
        fp.setdefault("sec_ch_ua_arch", '"x86"')
        fp.setdefault("sec_ch_ua_bitness", '"64"')
        fp.setdefault("sec_ch_ua_model", '""')
        fp.setdefault("sec_ch_ua_platform_version", '"15.3.0"')
    else:
        # 非 Chromium：一个 client hint 都不发（真实浏览器行为）
        fp["sec_ch_ua"] = ""
        fp["sec_ch_ua_platform"] = ""
        fp["sec_ch_ua_mobile"] = ""
        fp["sec_ch_ua_full_version_list"] = ""
        fp["sec_ch_ua_arch"] = ""
        fp["sec_ch_ua_bitness"] = ""
        fp["sec_ch_ua_model"] = ""
        fp["sec_ch_ua_platform_version"] = ""
    fp["has_touch"] = int(fp.get("max_touch_points", 0)) > 0
    validate_fingerprint(fp)
    return fp


def ua_for_impersonate(impersonate: str, current_ua: str) -> str:
    """根据 impersonate 名生成匹配的 UA。"""
    entry = _ALL_IMPERSONATES.get(impersonate)
    if not entry:
        return current_ua

    t, d = entry["type"], entry["data"]

    if t == "mac_safari":
        macos_ver = random.choice(d["macos_versions"])
        return (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X {macos_ver}) "
            f"AppleWebKit/{d['webkit_ver']} (KHTML, like Gecko) "
            f"Version/{d['safari_ver']} Safari/{d['webkit_ver']}"
        )
    elif t == "ios_safari":
        ios_ver = random.choice(d["ios_versions"])
        return (
            f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios_ver} like Mac OS X) "
            f"AppleWebKit/{d['webkit_ver']} (KHTML, like Gecko) "
            f"Version/{d['safari_ver']} Mobile/15E148 Safari/604.1"
        )
    elif t == "chrome":
        return (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{d['full_ver']} Safari/537.36"
        )
    elif t == "edge":
        return (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{d['full_ver']} Safari/537.36 "
            f"Edg/{d['full_ver']}"
        )
    elif t == "firefox":
        return (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{d['ver']}) "
            f"Gecko/20100101 Firefox/{d['ver']}"
        )
    return current_ua
