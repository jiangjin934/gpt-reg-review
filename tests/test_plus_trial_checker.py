from __future__ import annotations

import plus_trial_checker


class FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or ("" if payload is None else "{}")

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        key = "coupon" if "check_coupon" in url else "accounts"
        response = self.responses[key]
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        pass


def _account_response(**account):
    return FakeResponse(
        200,
        {
            "accounts": {
                "account-id": {
                    "account": {"plan_type": "free", **account},
                    "entitlement": {},
                    "eligible_promo_campaigns": {},
                }
            }
        },
    )


def _run(monkeypatch, responses, fingerprint=None):
    session = FakeSession(responses)
    monkeypatch.setattr(
        plus_trial_checker,
        "create_http_session",
        lambda **kwargs: session,
    )
    result = plus_trial_checker.check_plus_trial(
        "access-token",
        proxy="socks5://proxy.example:1080",
        fingerprint=fingerprint,
    )
    return result, session


def test_coupon_eligibility_is_primary(monkeypatch):
    result, session = _run(
        monkeypatch,
        {
            "coupon": FakeResponse(200, {"state": "eligible"}),
            "accounts": _account_response(),
        },
        {
            "impersonate": "chrome146",
            "user_agent": "Chrome/146.0.0.0",
            "lang": "en-US",
            "lang_full": "en-US,en;q=0.9",
            "sec_ch_ua": '"Chromium";v="146"',
            "sec_ch_ua_platform": '"Windows"',
            "sec_ch_ua_mobile": "?0",
        },
    )

    assert result["status"] == "plus_eligible"
    assert result["trial_eligible"] is True
    assert session.calls[0][1]["headers"]["sec-ch-ua"] == '"Chromium";v="146"'


def test_redeemed_coupon_is_reported_separately(monkeypatch):
    result, _ = _run(
        monkeypatch,
        {
            "coupon": FakeResponse(
                200,
                {
                    "state": "ineligible",
                    "redemption": {
                        "redeemed": True,
                        "redeemed_at": "2026-09-20T00:00:00Z",
                        "expires_at": "2026-10-20T00:00:00Z",
                    },
                },
            ),
            "accounts": _account_response(),
        },
    )

    assert result["status"] == "plus_active"
    assert result["label"] == "Plus试用已兑换"
    assert result["trial_redeemed"] is True
    assert result["redeemed_at"] == "2026-09-20T00:00:00Z"


def test_free_account_is_reported_when_coupon_is_ineligible(monkeypatch):
    result, _ = _run(
        monkeypatch,
        {
            "coupon": FakeResponse(200, {"state": "ineligible"}),
            "accounts": _account_response(),
        },
    )

    assert result["status"] == "free"
    assert result["trial_eligible"] is False


def test_invalid_token_is_distinguished_from_network_failure(monkeypatch):
    result, _ = _run(
        monkeypatch,
        {
            "coupon": FakeResponse(401, {"error": "invalid token"}, "invalid token"),
            "accounts": FakeResponse(401, {"error": "invalid token"}, "invalid token"),
        },
    )

    assert result["status"] == "token_invalid"


def test_network_failure_does_not_raise(monkeypatch):
    result, _ = _run(
        monkeypatch,
        {
            "coupon": RuntimeError("proxy timeout"),
            "accounts": RuntimeError("proxy timeout"),
        },
    )

    assert result["status"] == "error"
    assert "proxy timeout" in result["error"]

