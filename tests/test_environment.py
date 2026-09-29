import sqlite3

import pytest

import browser_launcher
from auth_flow import AuthFlow
from browser_flow import BrowserAuthFlow
from fingerprint import generate_fingerprint
from webui import db, environment


@pytest.mark.parametrize(
    "proxy, expected",
    [
        ("socks5h://u:p@host:3000", None),
        ("socks5h://jg-region-JP-sid-abc-t-30:pp@us.1024proxy.io:3000", 1800),
        ("socks5h://jg-region-JP-sid-abc-t-5:pp@host:3000", 300),
        ("socks5h://jg-region-JP-sid-abc-T-15m:pp@host:3000", 900),
    ],
)
def test_parse_session_ttl(proxy, expected):
    assert environment.parse_session_ttl(proxy) == expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        (
            "us.1024proxy.io:3000:jg734696-region-JP-sid-A5DUYMHt-t-30:ppudtfgf",
            "socks5h://jg734696-region-JP-sid-A5DUYMHt-t-30:ppudtfgf@us.1024proxy.io:3000",
        ),
        ("socks5://u:p@host:3000", "socks5h://u:p@host:3000"),
        ("http://1.2.3.4:8080", "http://1.2.3.4:8080"),
        ("host:3000", "host:3000"),
        ("  ", ""),
    ],
)
def test_normalize_proxy_entry(raw, expected):
    assert environment.normalize_proxy_entry(raw) == expected


def test_parse_proxy_pool_normalizes_and_dedupes():
    text = "\n".join([
        "us.1024proxy.io:3000:user-region-JP-sid-aaaa-t-30:pw",
        "us.1024proxy.io:3000:user-region-JP-sid-aaaa-t-30:pw",
        "# 注释行",
        "socks5://x:y@host:1080",
        "",
    ])
    pool = environment.parse_proxy_pool(text)
    assert pool == [
        "socks5h://user-region-JP-sid-aaaa-t-30:pw@us.1024proxy.io:3000",
        "socks5h://x:y@host:1080",
    ]


def test_proxy_pool_api_roundtrip(isolated_db):
    from webui import app as web_app

    payload = web_app.ProxyPoolReq(
        text=(
            "us.1024proxy.io:3000:user-region-JP-sid-aaaa-t-30:pw\n"
            "us.1024proxy.io:3000:user-region-JP-sid-aaaa-t-30:pw\n"
            "socks5://x:y@host:1080\n"
        ),
        mode="replace",
    )
    saved = web_app.api_proxy_pool_save(payload)
    assert saved["ok"] is True
    assert saved["count"] == 2

    got = web_app.api_proxy_pool_get()
    assert got["count"] == 2
    lines = got["text"].splitlines()
    assert lines[0] == (
        "socks5h://user-region-JP-sid-aaaa-t-30:pw@us.1024proxy.io:3000"
    )

    # append 模式：追加去重后并入同一份服务端池子
    web_app.api_proxy_pool_save(
        web_app.ProxyPoolReq(text="socks5://z:z@host:2080", mode="append")
    )
    got = web_app.api_proxy_pool_get()
    assert got["count"] == 3
    assert "socks5h://z:z@host:2080" in got["text"]


def test_exit_ip_never_reused_across_tasks(isolated_db):
    env = _make_environment(run_id="run-a", exit_ip="203.0.113.10")
    assert db.reserve_environment("run-a", env)
    db.create_run("run-a", "a@example.com", "a.log")
    db.update_run_environment("run-a", env)

    # 同出口再预留必须被台账拒绝：任务之间不允许复用同一条 IP
    next_env = _make_environment(run_id="run-b", exit_ip="203.0.113.10")
    assert not db.reserve_environment("run-b", next_env)


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    path = tmp_path / "webui.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    return path


def _make_environment(*, run_id="run-a", exit_ip="203.0.113.10"):
    fingerprint = generate_fingerprint(country_code="JP", browser_type="firefox")
    return {
        "allocation_id": f"{run_id}:{fingerprint['fingerprint_id']}",
        "run_id": run_id,
        "proxy": "http://proxy.example:8080",
        "proxy_fingerprint": "proxy-hash",
        "exit_ip": exit_ip,
        "exit_country": "JP",
        "country_code": "JP",
        "country_source": "manual",
        "browser_family": fingerprint["browser_family"],
        "browser_engine": "playwright",
        "fingerprint_id": fingerprint["fingerprint_id"],
        "fingerprint_signature": environment.fingerprint_signature(fingerprint),
        "fingerprint": fingerprint,
    }


def test_old_runs_table_gets_environment_columns_during_migration(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE runs (run_id TEXT PRIMARY KEY, email TEXT, status TEXT, "
        "started_at REAL, finished_at REAL, log_path TEXT, error TEXT)"
    )
    con.commit()
    con.close()

    db.init_db()

    con = db._conn()
    try:
        columns = {row[1] for row in con.execute("PRAGMA table_info(runs)")}
        assert {
            "error_category",
            "allocation_id",
            "exit_ip",
            "fingerprint_id",
            "fingerprint_signature",
            "fingerprint_json",
            "environment_json",
            "runtime_observation_json",
        }.issubset(columns)
    finally:
        con.close()


def test_environment_ledger_rejects_reused_ip_and_profile(isolated_db):
    db.create_run("run-a", "a@example.com", "a.log")
    first = _make_environment()
    assert db.reserve_environment("run-a", first) is True
    assert db.environment_seen(exit_ip=first["exit_ip"])
    assert db.environment_seen(fingerprint_id=first["fingerprint_id"])
    assert db.environment_seen(fingerprint_signature=first["fingerprint_signature"])

    db.create_run("run-b", "b@example.com", "b.log")
    same_ip = _make_environment(run_id="run-b", exit_ip=first["exit_ip"])
    assert db.reserve_environment("run-b", same_ip) is False

    same_profile = _make_environment(run_id="run-b", exit_ip="203.0.113.11")
    same_profile["fingerprint_id"] = first["fingerprint_id"]
    same_profile["fingerprint_signature"] = first["fingerprint_signature"]
    assert db.reserve_environment("run-b", same_profile) is False


def test_stats_counts_only_plus_eligible_registered_accounts(isolated_db):
    db.save_registered({
        "email": "eligible@example.com",
        "access_token": "token",
        "plus_check": {"status": "plus_eligible", "label": "可领Plus试用"},
    })
    db.save_registered({
        "email": "active@example.com",
        "access_token": "token",
        "plus_check": {"status": "plus_active", "label": "已是Plus"},
    })
    db.save_registered({
        "email": "free@example.com",
        "access_token": "token",
        "plus_check": {"status": "free", "label": "Free"},
    })

    stats = db.stats()

    assert stats["plus_eligible"] == 1


def test_environment_allocation_keeps_manual_country(isolated_db, monkeypatch):
    monkeypatch.setattr(
        environment,
        "probe_exit",
        lambda proxy, timeout=15.0, family="chrome", require_chatgpt=False, **kwargs: {
            "exit_ip": "198.51.100.44", "exit_country": "US",
        },
    )

    allocated = environment.allocate_environment(
        "run-manual",
        {
            "proxy": "http://proxy.example:8080",
            "fingerprint_country": "jp",
            "fingerprint_browser_family": "firefox",
            "browser_engine": "playwright",
        },
    )

    assert allocated["exit_country"] == "US"
    assert allocated["country_code"] == "JP"
    assert allocated["country_source"] == "manual"
    assert allocated["fingerprint"]["locale"] == "ja-JP"
    assert allocated["fingerprint"]["timezone"] == "Asia/Tokyo"
    # 窗口比屏幕小（真实浏览器），但必须落在屏幕里
    screen_w, screen_h = (
        int(v) for v in allocated["fingerprint"]["screen"].split("x")
    )
    assert allocated["fingerprint"]["viewport"]["width"] <= screen_w
    assert 40 <= screen_h - allocated["fingerprint"]["viewport"]["height"] <= 300


def test_run_environment_decodes_frozen_profile_and_observation(isolated_db):
    db.create_run("run-a", "a@example.com", "a.log")
    frozen = _make_environment()
    db.update_run_environment("run-a", frozen)
    db.record_run_observation("run-a", {"all_passed": True, "screen_matches_viewport": True})

    result = db.get_run_environment("run-a")

    assert result["fingerprint_id"] == frozen["fingerprint_id"]
    assert result["fingerprint"]["fingerprint_id"] == frozen["fingerprint_id"]
    assert result["environment"]["country_code"] == "JP"
    assert result["runtime_observation"]["all_passed"] is True


class _FakePage:
    def __init__(self, observed):
        self.observed = observed

    def evaluate(self, _script):
        return self.observed


def test_runtime_page_validation_checks_screen_viewport_and_timezone():
    profile = generate_fingerprint(country_code="DE", browser_type="chrome")
    observed = {
        "user_agent": profile["user_agent"],
        "platform": profile["navigator_platform"],
        "vendor": profile["navigator_vendor"],
        "language": profile["locale"],
        "languages": list(profile["languages"]),
        "hardware_concurrency": profile["hardware_concurrency"],
        "device_memory": profile["device_memory"],
        "max_touch_points": profile["max_touch_points"],
        "viewport": dict(profile["viewport"]),
        "screen": {
            "width": int(profile["screen"].split("x")[0]),
            "height": int(profile["screen"].split("x")[1]),
        },
        "device_pixel_ratio": profile["device_pixel_ratio"],
        "timezone": profile["timezone"],
        "webdriver_undefined": True,
        "permission_status_is_native": True,
    }

    report = browser_launcher.validate_page_fingerprint(_FakePage(observed), profile)

    assert report["all_passed"] is True
    assert report["checks"]["screen_matches_viewport"] is True


def test_runtime_page_validation_rejects_screen_mismatch():
    profile = generate_fingerprint(browser_type="firefox")
    observed = {
        "user_agent": profile["user_agent"],
        "platform": profile["navigator_platform"],
        "vendor": profile["navigator_vendor"],
        "language": profile["locale"],
        "languages": list(profile["languages"]),
        "hardware_concurrency": profile["hardware_concurrency"],
        "device_memory": profile["device_memory"],
        "max_touch_points": profile["max_touch_points"],
        "viewport": dict(profile["viewport"]),
        "screen": {"width": profile["viewport"]["width"] + 1, "height": profile["viewport"]["height"]},
        "device_pixel_ratio": profile["device_pixel_ratio"],
        "timezone": profile["timezone"],
        "webdriver_undefined": True,
        "permission_status_is_native": True,
    }

    with pytest.raises(browser_launcher.FingerprintRuntimeMismatch) as exc_info:
        browser_launcher.validate_page_fingerprint(_FakePage(observed), profile)

    assert "screen" in exc_info.value.report["mismatches"]
    assert "screen_matches_viewport" in exc_info.value.report["mismatches"]


def test_exit_observation_normalizes_ip_and_honors_manual_country():
    report = environment.compare_exit_observation(
        {
            "exit_ip": "2001:db8::1",
            "country_code": "JP",
            "country_source": "manual",
        },
        exit_ip="2001:0DB8:0:0:0:0:0:1",
        exit_country="US",
        status_code=200,
    )

    assert report["observed"]["exit_ip"] == "2001:db8::1"
    assert report["checks"]["exit_ip_matches"] is True
    assert report["checks"]["country_matches_profile"] is True
    assert report["all_passed"] is True


class _FakeTraceResponse:
    status_code = 200
    text = "ip=203.0.113.20\nloc=JP\n"


class _FakeSession:
    def get(self, *_args, **_kwargs):
        return _FakeTraceResponse()


def test_protocol_environment_observation_contains_consistency_checks():
    profile = generate_fingerprint(country_code="JP", browser_type="firefox")
    observations = []
    flow = AuthFlow.__new__(AuthFlow)
    flow.session = _FakeSession()
    flow._environment = {
        "exit_ip": "203.0.113.20",
        "country_code": "JP",
        "country_source": "proxy",
    }
    flow._fingerprint = profile
    flow._country_code = ""
    flow._environment_observer = observations.append

    assert flow.check_proxy() is True
    assert observations[-1]["all_passed"] is True
    assert observations[-1]["checks"]["screen_matches_viewport"] is True
    assert observations[-1]["checks"]["exit_ip_matches"] is True


class _FakeBrowserResponse:
    ok = True
    status = 200

    def text(self):
        return "ip=203.0.113.21\nloc=US\n"


class _FakeRequest:
    def get(self, *_args, **_kwargs):
        return _FakeBrowserResponse()


class _FakeBrowserPage:
    request = _FakeRequest()


def test_browser_exit_observation_merges_with_fingerprint_report():
    profile = generate_fingerprint(country_code="US", browser_type="chrome")
    observations = []
    flow = BrowserAuthFlow.__new__(BrowserAuthFlow)
    flow._environment = {
        "exit_ip": "203.0.113.21",
        "country_code": "US",
        "country_source": "proxy",
    }
    flow._fingerprint = profile
    flow._runtime_diagnostic = {
        "checks": {"screen_matches_viewport": True},
        "all_passed": True,
    }
    flow._environment_observer = observations.append
    flow._detected_country = ""

    flow._detect_country(_FakeBrowserPage())

    assert observations[-1]["all_passed"] is True
    assert observations[-1]["network"]["checks"]["exit_ip_matches"] is True
    assert observations[-1]["checks"]["screen_matches_viewport"] is True

def test_protocol_default_family_is_mixed_pool():
    family, engine, prefer_firefox = environment._fingerprint_policy(
        {"engine": "protocol"}
    )
    assert family == "mixed"
    assert engine == "auto"
    assert prefer_firefox is False


def test_explicit_family_still_respected_for_protocol():
    family, engine, prefer_firefox = environment._fingerprint_policy(
        {"engine": "protocol", "fingerprint_browser_family": "chrome"}
    )
    assert family == "chrome"
    assert prefer_firefox is False

def test_sessionize_proxy_injects_sticky_sid():
    base = "socks5h://jgpy744696-region-JP:ppudtfgf@us.1024proxy.io:3000"
    first = environment.sessionize_proxy(base)
    second = environment.sessionize_proxy(base)

    assert "-sid-" in first and "-t-30" in first
    assert first != second  # 每个任务一个新的粘性会话
    assert "us.1024proxy.io:3000" in first
    assert "ppudtfgf" in first
    assert environment.parse_session_ttl(first) == 1800


def test_sessionize_proxy_leaves_other_urls_untouched():
    already = "socks5h://user-region-JP-sid-AbCd1234-t-30:pass@host:3000"
    plain = "socks5h://user:pass@host:3000"

    assert environment.sessionize_proxy(already) == already
    assert environment.sessionize_proxy(plain) == plain


def test_candidate_proxies_expands_session_variants():
    base = "socks5h://jgpy744696-region-JP:ppudtfgf@us.1024proxy.io:3000"
    candidates = environment._candidate_proxies({"proxy_pool": base})

    assert len(candidates) >= 2
    assert all("-sid-" in item for item in candidates)
    assert len(set(candidates)) == len(candidates)


def test_environment_allocation_skips_wrong_exit_country(isolated_db, monkeypatch):
    probed = []

    def fake_probe(proxy, timeout=15.0, family="chrome", require_chatgpt=False, **kwargs):
        probed.append(proxy)
        if len(probed) == 1:
            return {"exit_ip": "203.0.113.10", "exit_country": "PH"}
        return {"exit_ip": "203.0.113.11", "exit_country": "JP"}

    monkeypatch.setattr(environment, "probe_exit", fake_probe)
    monkeypatch.setattr(
        environment.db, "get_setting",
        lambda key, default="": "JP" if key == "required_exit_country" else default,
    )

    allocated = environment.allocate_environment(
        "run-country-gate",
        {"proxy_pool": "socks5h://u:p@h1:3000\nsocks5h://u:p@h2:3000"},
    )

    assert allocated["exit_country"] == "JP"
    assert allocated["exit_ip"] == "203.0.113.11"
    assert len(probed) == 2


def test_environment_allocation_skips_cf_blocked_exit(isolated_db, monkeypatch):
    probed = []

    def fake_probe(proxy, timeout=15.0, family="chrome", require_chatgpt=False, **kwargs):
        probed.append(proxy)
        if len(probed) == 1:
            raise environment.EnvironmentAllocationError(
                "出口无法给 chatgpt.com 种 oai-did（HTTP 403，疑似 CF 拦截）"
            )
        return {
            "exit_ip": "203.0.113.13",
            "exit_country": "JP",
        }

    monkeypatch.setattr(environment, "probe_exit", fake_probe)

    allocated = environment.allocate_environment(
        "run-cf-gate",
        {"proxy_pool": "socks5h://u:p@h1:3000\nsocks5h://u:p@h2:3000"},
    )

    assert allocated["exit_ip"] == "203.0.113.13"
    assert len(probed) == 2


def test_environment_seen_checks_historical_runs(isolated_db):
    db.create_run("run-hist", "h@example.com", "h.log")
    frozen = _make_environment(run_id="run-hist", exit_ip="198.51.100.77")
    db.update_run_environment("run-hist", frozen)

    # 台账被清空后，历史 run 用过的出口仍必须判为"已用"，
    # 否则换池后新任务可能复用旧 IP。
    assert db.environment_seen(exit_ip="198.51.100.77")
    assert db.environment_seen(fingerprint_id=frozen["fingerprint_id"])
    assert not db.environment_seen(exit_ip="198.51.100.99")


def test_allocation_probes_only_one_candidate_when_first_passes(isolated_db, monkeypatch):
    """第一个候选就通过时只探 1 个：其余候选的 chatgpt.com 首页流量（359KB/个）省掉。"""
    probed = []

    def fake_probe(proxy, timeout=15.0, family="chrome", require_chatgpt=False, **kwargs):
        probed.append(proxy)
        return {"exit_ip": f"203.0.113.{10 + len(probed)}", "exit_country": "JP"}

    monkeypatch.setattr(environment, "probe_exit", fake_probe)

    allocated = environment.allocate_environment(
        "run-progressive-probe",
        {"proxy_pool": "\n".join(f"socks5h://u:p@h{i}:3000" for i in range(1, 6))},
    )

    assert allocated["exit_country"] == "JP"
    assert len(probed) == 1
