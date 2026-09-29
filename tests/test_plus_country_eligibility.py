"""试用资格按国家发：单国复检不能把已知可领的号降级成 free。"""
from webui.app import _merge_plus_check_result


def _existing(status="plus_eligible", country="BR", label="可领Plus试用"):
    return {"extra": {"plus_check": {
        "status": status, "label": label,
        "trial_eligible": status == "plus_eligible",
        "eligible_country": country,
    }}}


def test_eligible_result_records_country():
    payload = _merge_plus_check_result(
        None,
        {"status": "plus_eligible", "label": "可领Plus试用", "trial_eligible": True},
        "BR",
        100.0,
    )
    assert payload["eligible_country"] == "BR"
    assert payload["checked_country"] == "BR"
    assert payload["status"] == "plus_eligible"


def test_free_result_keeps_previous_eligible_country():
    payload = _merge_plus_check_result(
        _existing(),
        {"status": "free", "label": "Free", "trial_eligible": False},
        "GB",
        200.0,
    )
    assert payload["status"] == "plus_eligible"
    assert payload["label"] == "可领Plus试用"
    assert payload["trial_eligible"] is True
    assert payload["eligible_country"] == "BR"
    assert payload["last_not_eligible_country"] == "GB"
    assert payload["last_not_eligible_at"] == 200.0


def test_free_result_without_history_stays_free():
    payload = _merge_plus_check_result(
        {"extra": {"plus_check": {"status": "free"}}},
        {"status": "free", "label": "Free"},
        "GB",
        300.0,
    )
    assert payload["status"] == "free"
    assert "eligible_country" not in payload


def test_token_invalid_is_never_upgraded_by_history():
    payload = _merge_plus_check_result(
        _existing(),
        {"status": "token_invalid", "label": "凭证失效"},
        "GB",
        400.0,
    )
    assert payload["status"] == "token_invalid"
    assert payload["label"] == "凭证失效"


def test_banned_is_written_as_is():
    payload = _merge_plus_check_result(
        _existing(),
        {"status": "banned", "label": "封号"},
        "GB",
        500.0,
    )
    assert payload["status"] == "banned"
