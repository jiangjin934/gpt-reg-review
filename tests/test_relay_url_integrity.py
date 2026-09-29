"""Imported relay links can authenticate the exact path and query string."""
from io import BytesIO
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import pytest

from mail_providers import MailProviderError, icloud_relay


@pytest.mark.parametrize("url", [
    "https://relay.example/api/v1/gpt/otp?token=fixture%2Bsecret&tag=a&tag=b&empty=",
    "https://relay.example/messages/fixture?signature=abc%2fdef&n=1",
])
def test_opaque_relay_url_is_not_rewritten(monkeypatch, url):
    seen = []

    def fetch(request, **kwargs):
        seen.append(request.full_url)
        if request.full_url != url:
            raise HTTPError(request.full_url, 401, "Invalid link", {}, None)
        return BytesIO(b'[{"fixture": true}]')

    monkeypatch.setattr(icloud_relay.urllib.request, "urlopen", fetch)
    provider = icloud_relay.ICloudRelayProvider(
        email="fixture@icloud.com", relay_url=url,
    )

    assert provider._fetch() == '[{"fixture": true}]'
    assert seen == [url]


@pytest.mark.parametrize("host", ["mail.ai1998.xyz", "icloud-api.top"])
def test_legacy_html_pagination_is_preserved(monkeypatch, host):
    seen = []

    def fetch(request, **kwargs):
        seen.append(request.full_url)
        return BytesIO(b"<html></html>")

    monkeypatch.setattr(icloud_relay.urllib.request, "urlopen", fetch)
    provider = icloud_relay.ICloudRelayProvider(
        email="fixture@icloud.com",
        relay_url=f"https://{host}/messages/fixture?token=abc&n=7",
    )

    assert provider._fetch() == "<html></html>"
    assert parse_qs(urlsplit(seen[0]).query) == {"token": ["abc"], "all": ["1"], "n": ["7"]}


def test_real_authentication_rejection_remains_fatal(monkeypatch):
    url = "https://relay.example/api/v1/gpt/otp?token=fixture"

    def fetch(request, **kwargs):
        raise HTTPError(request.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(icloud_relay.urllib.request, "urlopen", fetch)
    provider = icloud_relay.ICloudRelayProvider(email="fixture@icloud.com", relay_url=url)

    with pytest.raises(MailProviderError) as failure:
        provider._fetch()

    assert failure.value.fatal is True
    assert "401" in str(failure.value)
    assert "token=fixture" not in str(failure.value)


def test_relay_fetch_uses_the_task_proxy(monkeypatch):
    seen = []

    class Response:
        status_code = 200
        headers = {}
        text = '[{"fixture": true}]'

        def raise_for_status(self):
            return None

    class Session:
        def get(self, url, **kwargs):
            seen.append((url, kwargs))
            return Response()

        def close(self):
            return None

    created = []

    def make_session(**kwargs):
        created.append(kwargs)
        return Session()

    monkeypatch.setattr(icloud_relay, "create_http_session", make_session)
    provider = icloud_relay.ICloudRelayProvider(
        email="fixture@icloud.com",
        relay_url="https://relay.example/messages/fixture",
        proxy="socks5h://user:pass@proxy.example:3000",
    )

    assert provider._fetch() == '[{"fixture": true}]'
    assert created == [{"proxy": "socks5h://user:pass@proxy.example:3000", "impersonate": "chrome110"}]
    assert seen[0][0] == "https://relay.example/messages/fixture"
    assert seen[0][1]["timeout"] == provider.http_timeout


def test_direct_api_error_record_is_fatal():
    raw = '{"error":{"code":"INVALID_GPT_LINK","message":"opaque detail"}}'

    with pytest.raises(MailProviderError) as failure:
        icloud_relay._parse_direct_otp_json(raw)

    assert failure.value.fatal is True
    assert "INVALID_GPT_LINK" in str(failure.value)
    assert "opaque detail" not in str(failure.value)


@pytest.mark.parametrize("code", ["RATE_LIMITED", "SERVICE_UNAVAILABLE", "TIMEOUT"])
def test_direct_api_transient_error_is_retryable(code):
    raw = '{"error":{"code":"' + code + '","message":"opaque detail"}}'

    with pytest.raises(MailProviderError) as failure:
        icloud_relay._parse_direct_otp_json(raw)

    assert failure.value.fatal is False
    assert code in str(failure.value)
    assert "opaque detail" not in str(failure.value)


@pytest.mark.parametrize("sep", ["----", "-----", "------"])
def test_parse_line_accepts_four_or_more_dashes(sep):
    line = f"relay-example@icloud.com{sep}https://relay.example.com/api/v1/otp?token=icm_abc"
    row = icloud_relay.ICloudRelayProvider.parse_line(line)

    assert row["email"] == "relay-example@icloud.com"
    assert row["relay_url"] == "https://relay.example.com/api/v1/otp?token=icm_abc"
    assert row["kind"] == "icloud_relay"


def test_parse_line_keeps_single_dash_in_email():
    line = "relay-example2@icloud.com----https://relay.example/api/v1/code?key=k"
    row = icloud_relay.ICloudRelayProvider.parse_line(line)
    assert row["email"] == "relay-example2@icloud.com"


def test_new_generic_otp_endpoint_is_direct_api():
    url = "https://relay.example.com/api/v1/otp?token=icm_abc"
    parts = urlsplit(url)
    assert icloud_relay._looks_like_direct_otp_api(parts) is True


def test_tibosb_access_page_is_direct_code_api():
    url = (
        "https://ic-mail.tibosb.cloud/api/v1/access/abc123/"
        "mailboxes/fixture%40icloud.com/code"
    )
    assert icloud_relay._looks_like_direct_otp_api(urlsplit(url)) is True


def test_preflight_raises_fatal_on_invalid_token(monkeypatch):
    url = "https://relay.example.com/api/v1/otp?token=icm_dead"

    def fetch(request, **kwargs):
        raise HTTPError(request.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(icloud_relay.urllib.request, "urlopen", fetch)
    provider = icloud_relay.ICloudRelayProvider(
        email="fixture@icloud.com", relay_url=url,
    )

    with pytest.raises(MailProviderError) as failure:
        provider.preflight()

    assert failure.value.fatal is True
    assert "401" in str(failure.value)


def test_preflight_swallows_transient_5xx(monkeypatch):
    url = "https://relay.example.com/api/v1/otp?token=icm_ok"

    def fetch(request, **kwargs):
        raise HTTPError(request.full_url, 502, "Bad Gateway", {}, None)

    monkeypatch.setattr(icloud_relay.urllib.request, "urlopen", fetch)
    provider = icloud_relay.ICloudRelayProvider(
        email="fixture@icloud.com", relay_url=url,
    )

    provider.preflight()  # 不抛异常：暂态错误放行，接码轮询自己重试


def test_invalid_api_key_error_body_is_fatal():
    raw = '{"error":{"code":"INVALID_API_KEY","message":"API Key 无效"}}'

    with pytest.raises(MailProviderError) as failure:
        icloud_relay._parse_direct_otp_json(raw)

    assert failure.value.fatal is True
