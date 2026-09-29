"""Regression coverage for misleading success in local diagnostic reports."""
from copy import deepcopy

import pytest

from scripts.check_browser_runtime import assess_runtime


@pytest.fixture
def observation():
    profile = {
        "browser_type": "chrome",
        "user_agent": "Mozilla/5.0 Chrome/151.0.0.0",
        "lang_full": "ja-JP,ja;q=0.9",
    }
    result = {
        "native_version": "151.0.7922.34",
        "page_environment": {"all_passed": True},
        "ua_matches_native_major": True,
        "request_headers": {
            "user-agent": profile["user_agent"],
            "accept-language": profile["lang_full"],
            "sec-ch-ua": '"Chromium";v="151"',
        },
        "client_hints_and_features": {
            "user_agent_data": {
                "brands": [{"brand": "Chromium", "version": "151"}],
                "fullVersionList": [{"brand": "Chromium", "version": "151.0.7922.34"}],
            },
            "features": {"bigint": True},
            "permission_status_is_native": True,
        },
        "native_baseline": {
            "status": "passed",
            "capabilities": {"features": {"bigint": True}},
        },
    }
    return profile, result


def test_matching_page_fields_do_not_hide_engine_or_client_hint_mismatch(observation):
    profile, result = observation
    profile["user_agent"] = "Mozilla/5.0 Chrome/136.0.0.0"
    result["request_headers"]["user-agent"] = profile["user_agent"]
    result["ua_matches_native_major"] = False

    report = assess_runtime(result, profile)

    assert report["status"] == "failed"
    assert report["checks"]["page_fields"] is True
    assert "ua_matches_native_major" in report["failures"]
    assert "client_hints_match_ua_major" in report["failures"]


def test_local_http_success_leaves_transport_and_remote_work_unmeasured(observation):
    profile, result = observation
    before = deepcopy((profile, result))

    report = assess_runtime(result, profile)

    assert report["status"] == "incomplete"
    assert report["failures"] == []
    assert {"tls_handshake", "http2_settings", "remote_workflows"} <= set(report["unmeasured"])
    assert (profile, result) == before


@pytest.mark.parametrize("mismatch", ["language", "permissions", "features"])
def test_request_and_native_object_mismatches_are_visible(observation, mismatch):
    profile, result = observation
    if mismatch == "language":
        result["request_headers"]["accept-language"] = "ja-JP"
        failed_check = "request_accept_language"
    elif mismatch == "permissions":
        result["client_hints_and_features"]["permission_status_is_native"] = False
        failed_check = "native_permission_status"
    else:
        result["client_hints_and_features"]["features"]["bigint"] = False
        failed_check = "features_match_native_baseline"

    report = assess_runtime(result, profile)

    assert report["status"] == "failed"
    assert failed_check in report["failures"]


def test_startup_failure_is_not_reported_as_success_or_missing_transport_measurement():
    result = {"error": "TargetClosedError", "stage": "new_page"}

    report = assess_runtime(result, {"browser_type": "mac_safari"})

    assert report["status"] == "failed"
    assert report["failures"] == ["browser_context"]
    assert "tls_handshake" in report["unmeasured"]


def test_firefox_does_not_require_chromium_client_hints(observation):
    profile, result = observation
    profile["browser_type"] = "firefox"
    result["client_hints_and_features"]["user_agent_data"] = None
    result["request_headers"].pop("sec-ch-ua")

    report = assess_runtime(result, profile)

    assert report["failures"] == []
    assert "client_hints_match_ua_major" not in report["checks"]
