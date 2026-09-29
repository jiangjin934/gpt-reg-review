import asyncio
import io
import json
import logging
import queue
from types import SimpleNamespace

import pytest

from webui import app as web_app
from webui import db, probes, registrar


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    path = tmp_path / "webui.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    return path


def test_probe_error_redaction_removes_credentials_and_otp():
    value = probes.redact_probe_error(
        "Bearer access-secret password=mail-secret code=123456"
    )

    assert "access-secret" not in value
    assert "mail-secret" not in value
    assert "123456" not in value
    assert value.count("[redacted]") == 3


def test_fail_open_closes_started_stages(isolated_db):
    db.create_run("run-probe", "probe@example.com", "probe.log")
    probe = probes.ProbeSession("run-probe")
    probe.mark("mail.otp", "started")
    probe.mark("sms.otp", "started")

    probe.fail_open("Bearer access-secret code=123456")

    events = db.get_run_probes("run-probe")
    closed = [event for event in events if event["status"] == "failed"]
    assert {event["stage"] for event in closed} == {"mail.otp", "sms.otp"}
    assert all("access-secret" not in event["error"] for event in closed)
    assert all("123456" not in event["error"] for event in closed)


def test_probed_operation_marks_ok_false_as_failed(isolated_db, monkeypatch):
    monkeypatch.setattr(probes, "_OPERATION_HISTORY", [])

    @probes.probed_operation("unit.operation")
    def operation():
        return {"ok": False, "error": "Bearer access-secret code=123456"}

    result = operation()
    probes._OPERATION_HISTORY.clear()
    events = probes.list_operation_probes(operation="unit.operation")

    assert result["ok"] is False
    assert [event["status"] for event in events] == ["started", "failed"]
    assert "access-secret" not in events[-1]["error"]
    assert "123456" not in events[-1]["error"]


def test_normalize_api_path_hides_email_and_run_id():
    assert probes.normalize_api_path(
        "/api/registered/user@example.com"
    ) == "/api/registered/{email}"
    assert probes.normalize_api_path(
        "/api/runs/0123456789abcdef/probes"
    ) == "/api/runs/{id}/probes"


def test_api_middleware_records_success_and_http_failure(monkeypatch):
    events = []
    monkeypatch.setattr(web_app, "record_operation_probe", lambda *args, **kwargs: events.append((args, kwargs)))

    async def next_ok(_request):
        return SimpleNamespace(status_code=200)

    async def next_failed(_request):
        return SimpleNamespace(status_code=404)

    request = SimpleNamespace(url=SimpleNamespace(path="/api/registered/user@example.com"), method="GET")
    asyncio.run(web_app.probe_api_requests(request, next_ok))
    asyncio.run(web_app.probe_api_requests(
        SimpleNamespace(url=SimpleNamespace(path="/api/runs/0123456789abcdef/probes"), method="GET"),
        next_failed,
    ))

    assert [(item[0][0], item[0][1]) for item in events] == [
        ("api.get./api/registered/{email}", "started"),
        ("api.get./api/registered/{email}", "ok"),
        ("api.get./api/runs/{run_id}/probes", "started"),
        ("api.get./api/runs/{run_id}/probes", "failed"),
    ]
    assert events[-1][1]["status_code"] == 404


def test_flow_instrumentation_records_protocol_and_browser_stages(isolated_db):
    db.create_run("run-flow", "flow@example.com", "flow.log")

    class ProtocolFixture:
        def check_proxy(self):
            return True

        def get_csrf_token(self):
            return "csrf"

    protocol = ProtocolFixture()
    protocol_probe = probes.ProbeSession("run-flow")
    registrar._instrument_flow_for_probe(protocol, protocol_probe, "protocol")
    assert protocol.check_proxy() is True
    assert protocol.get_csrf_token() == "csrf"

    class BrowserFixture:
        def _warmup(self, _page):
            return True

        def _extract_tokens(self, _page, _ctx):
            return True

    browser = BrowserFixture()
    browser_probe = probes.ProbeSession("run-flow")
    registrar._instrument_flow_for_probe(browser, browser_probe, "browser")
    assert browser._warmup(None) is True
    assert browser._extract_tokens(None, None) is True

    events = db.get_run_probes("run-flow")
    stages = {(event["stage"], event["status"]) for event in events}
    assert ("network.preflight", "ok") in stages
    assert ("auth.csrf", "ok") in stages
    assert ("browser.warmup", "ok") in stages
    assert ("browser.tokens.extract", "ok") in stages


def test_codex_refresh_exchange_false_is_recorded_as_failed(isolated_db):
    db.create_run("run-codex", "codex@example.com", "codex.log")

    class ProtocolFixture:
        def oauth_codex_rt_exchange(self):
            self._oauth_failure_reason = "phone_verification_required"
            self._oauth_failure_details = {
                "final_path": "/add-phone",
                "sms_configured": False,
            }
            return False

    flow = ProtocolFixture()
    probe = probes.ProbeSession("run-codex")
    registrar._instrument_flow_for_probe(flow, probe, "protocol")

    assert flow.oauth_codex_rt_exchange() is False
    event = db.get_run_probes("run-codex")[-1]
    assert event["stage"] == "oauth.codex.exchange"
    assert event["status"] == "failed"
    assert event["error"] == "phone_verification_required"
    assert event["details"]["oauth"]["final_path"] == "/add-phone"
    assert event["details"]["oauth"]["sms_configured"] is False


def test_false_probe_without_diagnostic_keeps_legacy_error(isolated_db):
    db.create_run("run-codex-legacy", "codex-legacy@example.com", "codex-legacy.log")

    class ProtocolFixture:
        def oauth_codex_rt_exchange(self):
            return False

    flow = ProtocolFixture()
    probe = probes.ProbeSession("run-codex-legacy")
    registrar._instrument_flow_for_probe(flow, probe, "protocol")

    assert flow.oauth_codex_rt_exchange() is False
    event = db.get_run_probes("run-codex-legacy")[-1]
    assert event["error"] == "operation returned false"


def test_network_probe_does_not_use_previous_oauth_failure(isolated_db):
    db.create_run("run-no-stale-oauth", "fixture@example.com", "fixture.log")

    class ProtocolFixture:
        _oauth_failure_reason = "phone_verification_required"
        _oauth_failure_details = {"final_path": "/add-phone"}

        def check_proxy(self):
            return False

    flow = ProtocolFixture()
    registrar._instrument_flow_for_probe(flow, probes.ProbeSession("run-no-stale-oauth"), "protocol")
    assert flow.check_proxy() is False
    event = db.get_run_probes("run-no-stale-oauth")[-1]
    assert event["error"] == "operation returned false"
    assert "oauth" not in event.get("details", {})


@pytest.mark.parametrize("all_passed, expected_status", [(True, "ok"), (False, "failed")])
def test_runtime_environment_observation_is_in_run_timeline(isolated_db, all_passed, expected_status):
    db.create_run("run-env", "env@example.com", "env.log")
    probe = probes.ProbeSession("run-env")
    registrar.record_environment_observation(
        "run-env",
        probe,
        {
            "kind": "browser_environment",
            "all_passed": all_passed,
            "checks": {"screen_matches_viewport": all_passed},
            "network": {"exit_ip": "203.0.113.5"},
        },
    )

    environment = db.get_run_environment("run-env")
    assert environment["runtime_observation"]["all_passed"] is all_passed
    events = db.get_run_probes("run-env")
    runtime = [event for event in events if event["stage"] == "environment.runtime"]
    assert runtime[-1]["status"] == expected_status
    assert runtime[-1]["details"]["checks"]["screen_matches_viewport"] is all_passed


def test_runtime_environment_probe_preserves_native_permission_failure(isolated_db):
    db.create_run("run-permissions", "permissions@example.com", "permissions.log")
    probe = probes.ProbeSession("run-permissions")

    registrar.record_environment_observation(
        "run-permissions",
        probe,
        {
            "kind": "browser_environment",
            "all_passed": False,
            "checks": {"permission_status_is_native": False},
        },
    )

    event = db.get_run_probes("run-permissions")[-1]
    assert event["stage"] == "environment.runtime"
    assert event["status"] == "failed"
    assert event["details"]["checks"]["permission_status_is_native"] is False


def test_probe_metadata_survives_redaction():
    event = probes.record_operation_probe(
        "unit.metadata", "ok", status_code=503, country_code="JP",
        access_token_present=False, session_token_len=128,
        token="hidden-token", otp="654321", password="hidden-password",
        summary={"message": 'provider: {"password": "quoted secret"}'},
    )
    details = event["details"]
    assert details["status_code"] == 503
    assert details["country_code"] == "JP"
    assert details["access_token_present"] is False
    assert details["session_token_len"] == 128
    assert "hidden-token" not in str(event)
    assert "654321" not in str(event)
    assert "quoted secret" not in str(event)


def test_api_exception_keeps_request_pair_and_redacts_error():
    async def fail(_request):
        raise RuntimeError('network password="quoted secret" Bearer access-secret')

    request = SimpleNamespace(url=SimpleNamespace(path="/api/runs/short-id/probes"), method="GET")
    with pytest.raises(RuntimeError):
        asyncio.run(web_app.probe_api_requests(request, fail))
    events = probes.list_operation_probes()
    assert [event["status"] for event in events] == ["started", "failed"]
    assert events[0]["details"]["request_id"] == events[1]["details"]["request_id"]
    assert events[1]["operation"] == "api.get./api/runs/{run_id}/probes"
    assert "short-id" not in str(events)
    assert "quoted secret" not in str(events)
    assert "access-secret" not in str(events)


@pytest.mark.parametrize("path", ["/", "/api/runs/a/stream", "/api/auto/stream"])
def test_middleware_leaves_streams_and_static_requests_alone(path):
    response = object()

    async def next_response(_request):
        return response

    request = SimpleNamespace(url=SimpleNamespace(path=path), method="GET")
    assert asyncio.run(web_app.probe_api_requests(request, next_response)) is response
    assert probes.list_operation_probes() == []


def test_instance_probe_does_not_duplicate_or_change_branch_result():
    db.create_run("branch-run", "fixture@example.com", "fixture.log")
    target = SimpleNamespace(signup=lambda *args: False, warmup=lambda: False)
    probe = probes.ProbeSession("branch-run")
    registrar._instrument_flow_for_probe(target, probe, "protocol")
    registrar._instrument_flow_for_probe(target, probe, "protocol")
    assert target.signup("fixture@example.com", "secret") is False
    assert target.warmup() is False
    events = db.get_run_probes("branch-run")
    assert [(e["stage"], e["status"]) for e in events] == [
        ("auth.signup", "started"), ("auth.signup", "ok"),
        ("auth.warmup", "started"), ("auth.warmup", "failed"),
    ]


def test_queue_logs_are_owned_and_redacted(tmp_path, monkeypatch):
    messages = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {"owner": messages})
    handler = registrar.QueueLogHandler("owner", tmp_path / "task.log")
    record = logging.LogRecord("fixture", logging.INFO, __file__, 1,
        'network password="quoted secret" Cookie: session=secret-cookie', (), None)
    try:
        for run_id in (None, "another"):
            monkeypatch.setattr(registrar._current_run, "run_id", run_id, raising=False)
            handler.emit(record)
        assert messages.empty()
        monkeypatch.setattr(registrar._current_run, "run_id", "owner")
        handler.emit(record)
        output = messages.get_nowait()
        assert "quoted secret" not in output
        assert "secret-cookie" not in output
        assert "network" in output
    finally:
        handler.close()
    assert "quoted secret" not in (tmp_path / "task.log").read_text(encoding="utf-8")


def test_phase_status_messages_are_redacted_before_entering_sse_queue(monkeypatch):
    messages = queue.Queue()
    monkeypatch.setattr(registrar, "_run_queues", {"owner": messages})
    payload = {
        "phase": "sms",
        "message": 'provider api_key="fictional-status-secret" code=123456',
    }

    registrar._emit_status("owner", "phase", payload)

    event = json.loads(messages.get_nowait().removeprefix("__EVENT__:"))
    assert "fictional-status-secret" not in str(event)
    assert "123456" not in str(event)
    assert event["phase"] == "sms"
    assert payload["message"].endswith("code=123456")


@pytest.mark.parametrize("field", ["api_key", "api-key", "apikey", "totp"])
def test_free_text_api_keys_and_totp_are_redacted(field):
    message = f"provider {field}=fictional-credential request failed"

    output = probes.redact_log_message(message)

    assert "fictional-credential" not in output
    assert "request failed" in output


def test_json_password_with_escaped_quotes_is_fully_redacted():
    message = json.dumps({"password": 'prefix"private-tail', "result": "failed"})

    output = probes.redact_log_message(message)

    assert "prefix" not in output
    assert "private-tail" not in output
    assert '"result": "failed"' in output


def test_metadata_exemptions_do_not_bypass_nested_redaction():
    event = probes.record_operation_probe(
        "unit.metadata-types", "failed",
        status_code={"password": "fictional-nested-password"},
        country_code="token=fictional-country-token",
    )

    assert "fictional-nested-password" not in str(event)
    assert "fictional-country-token" not in str(event)


def test_bytes_and_custom_detail_objects_are_redacted():
    class Detail:
        def __str__(self):
            return "password=fictional-object-secret"

    event = probes.record_operation_probe(
        "unit.detail-types", "failed", detail=Detail(),
        response=b'api_key="fictional-bytes-secret"',
    )

    assert "fictional-object-secret" not in str(event)
    assert "fictional-bytes-secret" not in str(event)


def test_console_formatter_redacts_message_and_traceback_without_mutating_record():
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(probes.RedactingFormatter("%(levelname)s %(message)s"))
    try:
        raise RuntimeError('password="fictional-traceback-secret"')
    except RuntimeError:
        import sys

        record = logging.LogRecord(
            "unit.console", logging.ERROR, __file__, 1,
            "provider api_key=%s", ("fictional-message-secret",), sys.exc_info(),
        )
    try:
        handler.handle(record)
        text = output.getvalue()
        assert "fictional-message-secret" not in text
        assert "fictional-traceback-secret" not in text
        assert "RuntimeError" in text
        assert record.args == ("fictional-message-secret",)
    finally:
        handler.close()
