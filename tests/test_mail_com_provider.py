from types import SimpleNamespace

import pytest

from mail_providers.mail_com import (
    ALIAS_LIMIT,
    MailComAliasError,
    MailComMailProvider,
    _login_form_params,
    _parse_url,
    _validate_alias_address,
)
from mail_providers import get_provider_class


def test_provider_registered_and_metadata():
    cls = get_provider_class("mail_com")
    assert cls is MailComMailProvider
    assert cls.pooled is True
    assert cls.ephemeral is True
    assert cls.line_segments == 2


def test_parse_line_ok_and_rejections():
    row = MailComMailProvider.parse_line("User@Mail.COM----Pass123")
    assert row == {"email": "user@mail.com", "password": "Pass123", "kind": "mail_com"}

    with pytest.raises(ValueError, match="2 段"):
        MailComMailProvider.parse_line("user@mail.com----pass----extra")
    with pytest.raises(ValueError, match="password 为空"):
        MailComMailProvider.parse_line("user@mail.com----")
    with pytest.raises(ValueError):
        MailComMailProvider.parse_line("not-an-email----pass")


def test_from_config_requires_account_and_reads_domain():
    with pytest.raises(ValueError, match="claim"):
        MailComMailProvider.from_config({}, None)
    provider = MailComMailProvider.from_config(
        {"mail_com_alias_domain": "DR.com"},
        {"email": "user@mail.com", "password": "secret"},
    )
    assert provider.alias_domain == "dr.com"
    provider.close()

    provider = MailComMailProvider.from_config(
        {}, {"email": "user@mail.com", "password": "secret"}
    )
    assert provider.alias_domain == "dr.com"
    provider.close()


def test_login_form_params_fills_oauth_context():
    page = (
        "https://mlogin.mail.com/loginapplication/login/login"
        "?authcode-context=abc123&login_hint=user%40mail.com"
    )
    html = (
        '<form>'
        '<input name="token" value="t&amp;t">'
        '<input name="noscript" value="0">'
        "</form>"
    )
    params = _login_form_params(html, page)
    assert params["service"] == "oauth2"
    assert params["token"] == "t&t"
    assert params["successURL"].endswith("authcode-context=abc123")
    assert "login_hint=user%40mail.com" in params["loginFailedURL"]


def test_parse_url_keeps_base_host():
    parsed = _parse_url("https://navigator-lxa.mail.com/login?sid=SID123")
    assert parsed.base == "https://navigator-lxa.mail.com"
    parsed.path = "/halogin"
    parsed.query["tz"] = "8"
    assert parsed.full.startswith("https://navigator-lxa.mail.com/halogin?")
    assert "sid=SID123" in parsed.full
    assert "tz=8" in parsed.full


def test_validate_alias_address():
    _validate_alias_address("gcabc123456@dr.com")
    with pytest.raises(MailComAliasError):
        _validate_alias_address("a@dr.com")
    with pytest.raises(MailComAliasError):
        _validate_alias_address("bad address@dr.com")


class _FakeAliasClient:
    def __init__(self, email, password, session=None):
        self.email = email
        self.created = []
        self.fail_next_with = None
        self.closed = False

    def create_alias(self, address):
        if self.fail_next_with:
            exc = self.fail_next_with
            self.fail_next_with = None
            raise exc
        self.created.append(address)
        return address

    def close(self):
        self.closed = True


def test_create_mailbox_retries_transient_and_propagates_fatal():
    client = _FakeAliasClient("user@mail.com", "secret")
    provider = MailComMailProvider("user@mail.com", "secret", alias_domain="dr.com")
    provider._alias_client = client
    assert provider.create_mailbox() == client.created[0]
    assert client.created[0].endswith("@dr.com")
    provider.close()
    assert client.closed

    client2 = _FakeAliasClient("user@mail.com", "secret")
    client2.fail_next_with = MailComAliasError("别名已满", fatal=True)
    provider2 = MailComMailProvider("user@mail.com", "secret", alias_domain="dr.com")
    provider2._alias_client = client2
    with pytest.raises(Exception, match="不可用"):
        provider2.create_mailbox()
    assert not client2.created


def test_create_mailbox_retries_non_fatal_error():
    client = _FakeAliasClient("user@mail.com", "secret")
    provider = MailComMailProvider("user@mail.com", "secret", alias_domain="dr.com")
    provider._alias_client = client
    client.fail_next_with = MailComAliasError("别名不可用", fatal=False)
    address = provider.create_mailbox()
    assert address == client.created[0]
    assert len(client.created) == 1


def test_alias_limit_constant():
    assert ALIAS_LIMIT == 10
