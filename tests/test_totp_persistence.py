"""Local-only checks for TOTP reuse and one-time secret handling."""

from types import SimpleNamespace

from webui import two_factor


class _Response:
    status_code = 200
    text = ""

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _Session:
    def __init__(self, payload):
        self.payload = payload
        self.post_calls = 0

    def get(self, *_args, **_kwargs):
        return _Response(self.payload)

    def post(self, *_args, **_kwargs):
        self.post_calls += 1
        raise AssertionError("an already-enabled TOTP account must not enroll again")


class _Flow:
    def __init__(self, payload):
        self.session = _Session(payload)
        self.result = SimpleNamespace(cookie_header="")

    def _common_headers(self, _referer):
        return {}


def test_existing_totp_reuses_saved_secret_without_enroll():
    flow = _Flow({"mfa_enabled": True, "factors": {"totp": {"id": "factor"}}})

    result = two_factor._enroll_and_activate(
        flow,
        "fixture-access",
        existing_secret="JBSWY3DPEHPK3PXP",
    )

    assert result["secret"] == "JBSWY3DPEHPK3PXP"
    assert result["existing"] is True
    assert flow.session.post_calls == 0


def test_enabled_totp_without_saved_secret_fails_closed():
    flow = _Flow({"mfa_enabled": True, "factors": {"totp": {"id": "factor"}}})

    result = two_factor._enroll_and_activate(flow, "fixture-access")

    assert result is None
    assert flow.session.post_calls == 0
