from types import SimpleNamespace

from auth_flow import AuthFlow, AuthResult
import auth_flow


class Response:
    def __init__(self, status_code, text, payload=None, headers=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload
        self.headers = headers or {}

    def json(self):
        return self._payload


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def _flow(responses):
    flow = AuthFlow.__new__(AuthFlow)
    flow.result = AuthResult()
    flow.result.csrf_token = "initial-csrf"
    flow.result.device_id = "device-fixture"
    flow.session = Session(responses)
    flow.config = SimpleNamespace(proxy="")
    flow._impersonate_candidates = ["chrome"]
    flow._impersonate_idx = 0
    flow._ua = "fixture-agent"
    flow._last_sentinel_so_token = ""
    flow._trace_http = lambda *args, **kwargs: None
    flow._common_headers = lambda _referer: {"User-Agent": "fixture-agent"}
    flow.get_csrf_token = lambda: "fresh-csrf"
    flow.get_auth_url = lambda csrf, email="": f"https://auth.example/?csrf={csrf}"
    flow.auth_oauth_init = lambda url: "fresh-device"
    flow.get_sentinel_token = lambda device: "fresh-sentinel"
    flow.warmup = lambda: True
    return flow


def _stale(req_id):
    return Response(
        409,
        "Your sign-in session is no longer valid.",
        headers={"x-request-id": req_id},
    )


def test_stale_session_retry_success_returns_rebuilt_state_response():
    flow = _flow([
        _stale("old-request"),
        Response(200, '{"page": "fresh"}', {"page": "fresh"}),
    ])

    result = flow.authorize_continue("fixture@example.com", "old-sentinel")

    assert result == {"page": "fresh"}
    assert len(flow.session.calls) == 2
    retry = flow.session.calls[1][1]
    assert retry["headers"]["openai-sentinel-token"] == "fresh-sentinel"
    assert retry["json"] == {
        "username": {"value": "fixture@example.com", "kind": "email"},
        "screen_hint": "signup",
    }


def test_non_stale_409_does_not_rebuild_session():
    flow = _flow([Response(409, "account blocked", headers={"x-request-id": "blocked"})])

    try:
        flow.authorize_continue("fixture@example.com", "sentinel")
    except RuntimeError as exc:
        assert "req_id=blocked" in str(exc)
    else:
        raise AssertionError("expected authorize_continue to raise")

    assert len(flow.session.calls) == 1


def test_final_stale_error_uses_last_response_request_id_and_body(monkeypatch):
    final = Response(
        409, "Your sign-in session is no longer valid: final response",
        headers={"x-request-id": "final-request"},
    )
    flow = _flow([_stale("first"), _stale("second"), _stale("third"), final])
    monkeypatch.setattr(
        auth_flow,
        "create_http_session",
        lambda **_kwargs: flow.session,
    )

    try:
        flow.authorize_continue("fixture@example.com", "old-sentinel")
    except RuntimeError as exc:
        message = str(exc)
        assert "req_id=final-request" in message
        assert "final response" in message
    else:
        raise AssertionError("expected authorize_continue to raise")

    assert len(flow.session.calls) == 4
