from unittest.mock import Mock

import pytest

from auth_flow import AuthFlow, AuthResult


class _Response:
    status_code = 200
    headers = {}
    url = "https://auth.openai.com/oauth/token"
    text = "{}"

    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self._payload


class _Session:
    def __init__(self, payload):
        self.payload = payload

    def post(self, *args, **kwargs):
        return _Response(self.payload)


def _flow(payload):
    flow = AuthFlow.__new__(AuthFlow)
    flow.result = AuthResult()
    flow.session = _Session(payload)
    flow._ua = "test-agent"
    flow._captured_login_verifier = ""
    flow._oauth_client_id = "client"
    flow._oauth_redirect_uri = "https://chatgpt.com/api/auth/callback/openai"
    flow._oauth_auth_url = ""
    flow._oauth_scope = ""
    flow._oauth_client_secret = ""
    flow._trace_http = lambda *args, **kwargs: None
    flow._sniff_login_verifier = lambda *args, **kwargs: None
    flow._collect_code_verifier_candidates = lambda *_args: []
    return flow


def test_codex_exchange_rejects_http_200_without_refresh_token():
    flow = _flow({"access_token": "access", "id_token": "identity"})

    ok = flow._exchange_codex_callback_code(
        "https://chatgpt.com/api/auth/callback/openai?code=CODE&state=STATE",
        "STATE",
        "VERIFIER",
        "https://chatgpt.com/api/auth/callback/openai",
        "client",
    )

    assert ok is False
    assert flow.result.access_token == "access"
    assert flow.result.refresh_token == ""
    assert flow._oauth_failure_reason == "token_missing_refresh_token"
    assert flow._oauth_failure_details["status_code"] == 200


def test_codex_exchange_rejects_non_json_success_response():
    class NonJsonResponse(_Response):
        def json(self):
            raise ValueError("not json")

    class NonJsonSession(_Session):
        def post(self, *args, **kwargs):
            return NonJsonResponse({})

    flow = _flow({})
    flow.session = NonJsonSession({})

    ok = flow._exchange_codex_callback_code(
        "https://chatgpt.com/api/auth/callback/openai?code=CODE&state=STATE",
        "STATE",
        "VERIFIER",
        "https://chatgpt.com/api/auth/callback/openai",
        "client",
    )

    assert ok is False


def test_codex_exchange_accepts_refresh_token():
    flow = _flow({"access_token": "access", "refresh_token": "refresh"})

    ok = flow._exchange_codex_callback_code(
        "https://chatgpt.com/api/auth/callback/openai?code=CODE&state=STATE",
        "STATE",
        "VERIFIER",
        "https://chatgpt.com/api/auth/callback/openai",
        "client",
    )

    assert ok is True
    assert flow.result.refresh_token == "refresh"
    assert flow._oauth_failure_reason == ""


@pytest.mark.parametrize("state_query", ["&state=SECRET_STATE", ""])
def test_codex_exchange_rejects_callback_state_mismatch_without_leaking_query(state_query, caplog):
    flow = _flow({})
    flow.session.post = Mock()

    ok = flow._exchange_codex_callback_code(
        "https://chatgpt.com/api/auth/callback/openai?code=CODE" + state_query,
        "EXPECTED_STATE",
        "VERIFIER",
        "https://chatgpt.com/api/auth/callback/openai",
        "client",
    )

    assert ok is False
    assert flow._oauth_failure_reason == "callback_state_mismatch"
    assert "SECRET_STATE" not in str(flow._oauth_failure_details)
    assert flow._oauth_failure_details["final_path"] == "/api/auth/callback/openai"
    assert "SECRET_STATE" not in caplog.text
    flow.session.post.assert_not_called()


def test_codex_exchange_classifies_add_phone_as_actionable_failure():
    flow = _flow({})
    flow._env_overrides = {}
    flow._sms_callback = None
    flow._codex_rt_attempted = False
    flow._build_codex_authorize = lambda: (
        "https://auth.openai.com/oauth/authorize?prompt=login",
        "STATE",
        "VERIFIER",
        "http://localhost:1455/auth/callback",
        "client",
    )
    flow._follow_authorize_for_callback = lambda *args, **kwargs: (
        "",
        "https://auth.openai.com/add-phone?token=SECRET_TOKEN",
    )

    ok = flow.oauth_codex_rt_exchange()

    assert ok is False
    assert flow._oauth_failure_reason == "phone_verification_required"
    assert flow._oauth_failure_details["final_path"] == "/add-phone"
    assert "SECRET_TOKEN" not in str(flow._oauth_failure_details)
    assert flow._oauth_failure_details["sms_configured"] is False


def test_generic_exchange_rejects_http_error_without_logging_body():
    class ErrorSession(_Session):
        def post(self, *args, **kwargs):
            return _Response({"error": "invalid_grant", "detail": "secret"}, status_code=400)

    flow = _flow({})
    flow.session = ErrorSession({})

    ok = flow.oauth_token_exchange(
        "https://chatgpt.com/api/auth/callback/openai?code=CODE",
        "",
    )

    assert ok is False


def test_generic_exchange_rejects_http_200_without_refresh_token():
    flow = _flow({"access_token": "new-access", "id_token": "identity"})
    flow.result.refresh_token = "existing-refresh"

    ok = flow.oauth_token_exchange(
        "https://chatgpt.com/api/auth/callback/openai?code=CODE",
        "",
    )

    assert ok is False
    assert flow.result.refresh_token == "existing-refresh"


def test_generic_exchange_rejects_non_json_success_response():
    class NonJsonResponse(_Response):
        def json(self):
            raise ValueError("not json")

    class NonJsonSession(_Session):
        def post(self, *args, **kwargs):
            return NonJsonResponse({})

    flow = _flow({})
    flow.session = NonJsonSession({})

    ok = flow.oauth_token_exchange(
        "https://chatgpt.com/api/auth/callback/openai?code=CODE",
        "",
    )

    assert ok is False


def test_generic_exchange_accepts_refresh_token():
    flow = _flow({"access_token": "access", "refresh_token": "refresh"})

    ok = flow.oauth_token_exchange(
        "https://chatgpt.com/api/auth/callback/openai?code=CODE",
        "",
    )

    assert ok is True
    assert flow.result.access_token == "access"
    assert flow.result.refresh_token == "refresh"


def _exchange(flow, exchange):
    callback = "https://chatgpt.com/api/auth/callback/openai?code=CODE&state=STATE"
    if exchange == "codex":
        return flow._exchange_codex_callback_code(
            callback, "STATE", "VERIFIER", "https://chatgpt.com/api/auth/callback/openai", "client",
        )
    return flow.oauth_token_exchange(callback, "")


@pytest.mark.parametrize("exchange", ["codex", "generic"])
@pytest.mark.parametrize("value", [None, "", " \t ", False, 17, [], {}, {"unexpected": "object"}, ["bad"]])
def test_empty_or_malformed_refresh_never_succeeds_or_erases_saved_token(exchange, value):
    flow = _flow({"refresh_token": value})
    flow.result.refresh_token = "previous-refresh"

    assert _exchange(flow, exchange) is False
    assert flow.result.refresh_token == "previous-refresh"
    assert flow._oauth_failure_reason == (
        "token_missing_refresh_token" if value is None or isinstance(value, str) else "token_invalid_payload"
    )


@pytest.mark.parametrize("exchange", ["codex", "generic"])
@pytest.mark.parametrize("error", [
    {"code": "invalid_grant", "message": "fixture-private-message"},
    "fixture-private-message",
])
def test_token_error_logs_only_safe_metadata(exchange, error, caplog):
    flow = _flow({})
    flow.session.post = Mock(return_value=_Response({
        "error": error,
        "fixture-private-key": "fixture-private-value",
    }, status_code=400))

    assert _exchange(flow, exchange) is False
    assert flow._oauth_failure_reason == "token_http_error"
    assert flow._oauth_failure_details["error_code"] == (
        "invalid_grant" if isinstance(error, dict) else "unrecognized_error"
    )
    for secret in ("fixture-private-message", "fixture-private-key", "fixture-private-value"):
        assert secret not in caplog.text
        assert secret not in str(flow._oauth_failure_details)


@pytest.mark.parametrize("payload, reason", [
    ({"access_token": "access"}, "token_missing_refresh_token"),
    ([], "token_invalid_payload"),
    (ValueError("private response body"), "token_invalid_json"),
])
def test_generic_http_200_failure_stops_before_reusing_consumed_code(payload, reason):
    flow = _flow({})
    flow._oauth_scope = "openid offline_access"  # More than one exchange candidate exists.

    class Response(_Response):
        def json(self):
            if isinstance(self._payload, Exception):
                raise self._payload
            return self._payload

    flow.session.post = Mock(side_effect=[
        Response(payload), _Response({"error": "invalid_grant"}, status_code=400),
    ])

    assert _exchange(flow, "generic") is False
    assert flow.session.post.call_count == 1
    assert flow._oauth_failure_reason == reason


def test_generic_missing_code_replaces_stale_phone_failure():
    flow = _flow({})
    flow._oauth_failure_reason = "phone_verification_required"
    flow._oauth_failure_details = {"final_path": "/add-phone"}
    flow.session.post = Mock()

    assert flow.oauth_token_exchange("", "") is False
    assert flow._oauth_failure_reason == "callback_missing_code"
    assert "final_path" not in flow._oauth_failure_details
    flow.session.post.assert_not_called()


def test_secondary_init_failure_replaces_stale_phone_failure(caplog):
    flow = _flow({})
    flow._oauth_failure_reason = "phone_verification_required"
    flow.get_csrf_token = Mock(side_effect=RuntimeError("private-init-message"))

    assert flow.oauth_secondary_authorize_exchange() is False
    assert flow._oauth_failure_reason == "authorize_init_failed"
    assert flow._oauth_failure_details["exception_type"] == "RuntimeError"
    assert "private-init-message" not in caplog.text


@pytest.mark.parametrize("path, status, reason", [
    ("/add-phone", 200, "phone_verification_required"),
    ("/phone-verification", 200, "phone_verification_required"),
    ("/add-phone", 403, "authorize_http_error"),
    ("/unexpected", 200, "callback_not_returned"),
    ("/unexpected", 503, "authorize_http_error"),
])
def test_authorize_failure_uses_observed_status_and_final_path(path, status, reason, caplog):
    flow = _flow({})
    flow._env_overrides = {}
    flow._sms_callback = None
    flow._codex_rt_attempted = False
    flow._build_codex_authorize = lambda: (
        "https://auth.openai.com/oauth/authorize", "STATE", "VERIFIER",
        "http://localhost:1455/auth/callback", "client",
    )
    redirect = _Response({}, status_code=302)
    redirect.headers = {"Location": f"{path}?token=private-query&next=add-phone"}
    flow.session.get = Mock(side_effect=[redirect, _Response({}, status_code=status)])

    assert flow.oauth_codex_rt_exchange() is False
    assert flow._oauth_failure_reason == reason
    assert flow._oauth_failure_details["final_path"] == path
    assert flow._oauth_failure_details["status_code"] == status
    assert "private-query" not in str(flow._oauth_failure_details)
    assert "private-query" not in caplog.text


def test_authorize_transport_exception_does_not_log_raw_url(caplog):
    flow = _flow({})
    flow._env_overrides = {}
    flow._codex_rt_attempted = False
    flow._build_codex_authorize = Mock(side_effect=TimeoutError("https://auth.example/?code=private-query"))

    assert flow.oauth_codex_rt_exchange() is False
    assert flow._oauth_failure_reason == "oauth_exception"
    assert flow._oauth_failure_details["exception_type"] == "TimeoutError"
    assert "private-query" not in caplog.text
