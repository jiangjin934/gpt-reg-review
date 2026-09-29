from webui import registrar
from webui.probes import classify_probe_error
from mail_providers import MailProviderError


def test_icloud_otp_timeout_is_terminal_account_error():
    assert registrar.classify_error(
        "iCloud 中转 OTP 超时 60s（fixture@icloud.com）"
    ) == "account"


def test_icloud_otp_timeout_with_duration_is_not_swallowed_by_generic_timeout():
    error = (
        "iCloud 中转 OTP 超时 180s（fixture@icloud.com）"
        "—— 确认中转站能收到这个邮箱的信"
    )
    assert registrar.classify_error(error) == "account"


def test_requested_credential_failure_remains_account_failure_with_network_words():
    error = registrar.RequestedCredentialError(
        ["access_token", "session_token"],
    )
    assert registrar.classify_error(error) == "account"


def test_stale_oauth_session_failure_remains_network_failure():
    error = (
        "authorize/continue 失败(screen_hint=signup): HTTP 409 "
        "Your sign-in session is no longer valid. Please start over to continue."
    )
    assert registrar.classify_error(error) == "network"


def test_probe_classifies_relay_timeout_before_generic_network_timeout():
    error = "iCloud 中转 OTP 超时 180s"
    assert classify_probe_error(error) == "account"


def test_probe_classifies_missing_requested_credentials_as_account_failure():
    error = registrar.RequestedCredentialError(["access_token", "session_token"])
    assert classify_probe_error(error) == "account"


def test_nonfatal_mail_provider_does_not_override_invalid_relay_link():
    error = MailProviderError(
        "中转链接无效（HTTP 401）", fatal=False, kind="icloud_relay",
    )
    assert registrar.classify_error(error) == "account"


def test_raw_http_401_from_icloud_relay_is_account_failure():
    error = MailProviderError(
        "HTTP Error 401: Unauthorized", fatal=False, kind="icloud_relay",
    )
    assert registrar.classify_error(error) == "account"


def test_invalid_relay_link_precedes_session_network_markers():
    error = "中转链接无效（HTTP 401）: session is no longer valid"
    assert registrar.classify_error(error) == "account"
    assert registrar.classify_error(
        MailProviderError(error, fatal=False, kind="icloud_relay")
    ) == "account"


def test_stale_auth_session_remains_network_error():
    error = "authorize/continue failed: sign-in session is no longer valid"
    assert registrar.classify_error(error) == "network"


def test_probe_classifies_invalid_relay_link_as_account_failure():
    assert classify_probe_error("中转链接无效（HTTP 401）") == "account"
