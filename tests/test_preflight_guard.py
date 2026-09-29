"""Keep protocol preflight failures before every account or auth operation."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import auth_flow
from fingerprint import generate_fingerprint
from mail_providers import MailProviderError
from webui import registrar


EXPECTED_IP = "203.0.113.20"
CHANGED_IP = "203.0.113.21"
FAILURES = ("changed_ip", "http_503", "transport")


def _trace_response(ip=EXPECTED_IP, status=200):
    return SimpleNamespace(status_code=status, text=f"ip={ip}\nloc=JP\n")


def _flow_fixture(failure):
    observations = []
    flow = auth_flow.AuthFlow.__new__(auth_flow.AuthFlow)
    flow._fingerprint = generate_fingerprint(country_code="JP", browser_type="firefox")
    flow._country_code = "JP"
    flow._environment = {
        "exit_ip": EXPECTED_IP,
        "country_code": "JP",
        "country_source": "manual",
    }
    flow._environment_observer = observations.append
    flow.result = auth_flow.AuthResult()
    request = Mock()
    if failure == "transport":
        request.side_effect = RuntimeError("authentication failed token=fixture-secret")
    else:
        request.return_value = _trace_response(
            ip=CHANGED_IP if failure == "changed_ip" else EXPECTED_IP,
            status=503 if failure == "http_503" else 200,
        )
    flow.session = SimpleNamespace(get=request)
    flow.warmup = Mock(return_value=False)
    flow.get_csrf_token = Mock(side_effect=AssertionError("unexpected CSRF request"))
    mail = SimpleNamespace(
        create_mailbox=Mock(side_effect=AssertionError("unexpected mailbox creation")),
        wait_for_otp=Mock(side_effect=AssertionError("unexpected mailbox polling")),
    )
    return flow, mail, observations


def _assert_failure_details(flow, observations, failure, caplog):
    reason = flow._network_preflight_error
    assert isinstance(reason, str) and reason.strip()
    assert "fixture-secret" not in reason
    assert "fixture-secret" not in repr(observations)
    assert "fixture-secret" not in caplog.text
    assert len(observations) == 1
    observation = observations[0]
    assert observation["all_passed"] is False
    assert observation["checks"]["trace_reachable"] is (failure == "changed_ip")
    assert observation["network"]["checks"]["trace_reachable"] is (failure == "changed_ip")
    if failure == "changed_ip":
        assert EXPECTED_IP in reason
        assert CHANGED_IP in reason
        assert observation["observed"]["exit_ip"] == CHANGED_IP
        assert observation["network"]["observed"]["exit_ip"] == CHANGED_IP
        assert observation["network"]["observed"]["status_code"] == 200
        assert observation["checks"]["exit_ip_matches"] is False
    elif failure == "http_503":
        assert "503" in reason
        assert observation["network"]["observed"]["status_code"] == 503
    else:
        assert "authentication failed" in reason.lower()


@pytest.mark.parametrize("failure", FAILURES)
def test_check_proxy_returns_false_with_one_accurate_redacted_observation(failure, caplog):
    flow, _mail, observations = _flow_fixture(failure)

    assert flow.check_proxy() is False

    # transport 类失败会重试 3 次（劣质出口抖动不该直接判死任务），
    # changed_ip 走一次复核，HTTP 503 属于明确响应不重试。
    expected_calls = {"changed_ip": 2, "http_503": 1, "transport": 3}[failure]
    assert flow.session.get.call_count == expected_calls
    _assert_failure_details(flow, observations, failure, caplog)


def test_transient_transport_failure_is_retried_once_more():
    """出口抖一下（curl 28）不该判死任务：前两次超时、第三次成功应通过。"""
    flow, _mail, observations = _flow_fixture("transport")
    calls = {"n": 0}

    def flaky_get(*_args, **_kwargs):
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("curl: (28) Operation timed out")
        return _trace_response()

    flow.session = SimpleNamespace(get=flaky_get)

    assert flow.check_proxy() is True
    assert calls["n"] == 3
    assert len(observations) == 1
    assert observations[0]["all_passed"] is True


@pytest.mark.parametrize("entrypoint", ("run_register", "run_protocol_login"))
@pytest.mark.parametrize("failure", FAILURES)
def test_failed_preflight_stops_before_auth_or_mail(entrypoint, failure, caplog):
    flow, mail, observations = _flow_fixture(failure)
    args = (mail,) if entrypoint == "run_register" else (mail, "fixture@example.test")

    with pytest.raises(auth_flow.NetworkPreflightError) as raised:
        getattr(flow, entrypoint)(*args)

    assert isinstance(raised.value, RuntimeError)
    assert flow._network_preflight_error in str(raised.value)
    assert "fixture-secret" not in str(raised.value)
    assert registrar.classify_error(raised.value) == "network"
    # transport 失败会重试 3 次才放弃（见 test_transient_transport_failure_is_retried_once_more）
    expected_calls = {"changed_ip": 2, "http_503": 1, "transport": 3}[failure]
    assert flow.session.get.call_count == expected_calls
    flow.warmup.assert_not_called()
    flow.get_csrf_token.assert_not_called()
    mail.create_mailbox.assert_not_called()
    mail.wait_for_otp.assert_not_called()
    _assert_failure_details(flow, observations, failure, caplog)


@pytest.mark.parametrize("failure", FAILURES)
def test_successful_preflight_retry_clears_previous_error(failure):
    flow, _mail, observations = _flow_fixture(failure)
    assert flow.check_proxy() is False
    assert flow._network_preflight_error
    flow.session.get.side_effect = None
    flow.session.get.return_value = _trace_response()

    assert flow.check_proxy() is True

    assert flow._network_preflight_error == ""
    assert len(observations) == 2
    assert observations[-1]["all_passed"] is True
    assert observations[-1]["network"]["observed"]["exit_ip"] == EXPECTED_IP


def test_replaced_session_exit_is_checked_again():
    observations = []
    flow = auth_flow.AuthFlow.__new__(auth_flow.AuthFlow)
    flow._environment = {
        "exit_ip": EXPECTED_IP,
        "country_code": "JP",
        "country_source": "proxy",
    }
    flow._environment_observer = observations.append
    flow.session = SimpleNamespace(get=Mock(return_value=_trace_response(CHANGED_IP)))
    flow._network_preflight_error = ""

    assert flow._verify_session_exit("warmup.retry") is False
    assert CHANGED_IP in flow._network_preflight_error
    assert observations[-1]["kind"] == "protocol_runtime"
    assert observations[-1]["all_passed"] is False


def test_typed_preflight_error_takes_precedence_over_account_error_text():
    error = auth_flow.NetworkPreflightError("authentication failed")

    assert registrar.classify_error(error) == "network"
    assert registrar.classify_error(RuntimeError("authentication failed")) == "account"


@pytest.mark.parametrize("fatal, expected", ((True, "account"), (False, "network")))
@pytest.mark.parametrize("message", ("authentication failed", "connection timeout"))
def test_mail_provider_fatal_contract_takes_precedence_over_message(fatal, expected, message):
    error = MailProviderError(message, fatal=fatal, kind="fixture")

    assert registrar.classify_error(error) == expected
