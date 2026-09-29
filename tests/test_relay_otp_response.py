"""Verified relay response parsing and first-poll behavior use local fixtures."""
import json
import logging
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from mail_providers import icloud_relay


EMAIL = "relay-fixture@icloud.com"
DIRECT_URL = "https://icloud.tongsheep.cyou/api/v1/gpt/otp?token=fixture"
STAMP = "2026-09-21T23:29:12+08:00"
NOW = datetime.fromisoformat(STAMP).timestamp()
CODE = "654321"


def _payload(code=CODE, stamp=STAMP):
    return json.dumps([{"otp": code, "time": stamp}])


def _single_payload(code=CODE, stamp=STAMP):
    return json.dumps({"otp": code, "time": stamp})


def _direct_provider(monkeypatch, raw):
    provider = icloud_relay.ICloudRelayProvider(email=EMAIL, relay_url=DIRECT_URL)
    monkeypatch.setattr(provider, "_fetch", Mock(return_value=raw))
    monkeypatch.setattr(provider, "_try_api", Mock(side_effect=AssertionError("unexpected API discovery")))
    monkeypatch.setattr(icloud_relay, "_discover_endpoints", Mock(side_effect=AssertionError("unexpected discovery")))
    monkeypatch.setattr(icloud_relay, "parse_relay_html", Mock(side_effect=AssertionError("unexpected text fallback")))
    return provider


@pytest.fixture
def clock(monkeypatch):
    state = SimpleNamespace(now=NOW + 1, sleeps=[])

    def sleep(seconds):
        state.sleeps.append(seconds)
        state.now += seconds

    monkeypatch.setattr(icloud_relay, "time", SimpleNamespace(time=lambda: state.now, sleep=sleep))
    return state


def test_direct_api_parses_initial_and_subsequent_responses(monkeypatch):
    provider = _direct_provider(monkeypatch, _payload())
    provider._fetch.side_effect = [_payload(), "[]", _payload("123456")]
    first = provider._load()
    assert first[0]["otp"] == CODE
    assert first[0]["ts"] == NOW
    assert first[0]["layout"] == "direct-otp-json"
    assert CODE not in first[0]["subject"] + first[0]["body"]
    assert provider._load() == []
    assert provider._load()[0]["otp"] == "123456"
    assert provider._source == "direct-json"
    assert provider._fetch.call_count == 3


CODE_URL = "http://47.108.184.137/api/v1/code?key=fixturekey"
TIBOSB_URL = (
    "https://ic-mail.tibosb.cloud/api/v1/access/KEY123/"
    "mailboxes/relay-fixture@icloud.com/code"
)


def _code_provider(monkeypatch, raw):
    provider = icloud_relay.ICloudRelayProvider(email=EMAIL, relay_url=CODE_URL)
    monkeypatch.setattr(provider, "_fetch", Mock(return_value=raw))
    monkeypatch.setattr(provider, "_try_api", Mock(side_effect=AssertionError("unexpected API discovery")))
    monkeypatch.setattr(icloud_relay, "_discover_endpoints", Mock(side_effect=AssertionError("unexpected discovery")))
    monkeypatch.setattr(icloud_relay, "parse_relay_html", Mock(side_effect=AssertionError("unexpected text fallback")))
    return provider


def _tibosb_page(code):
    return (
        "<!doctype html><html><head><title>x</title></head><body>"
        '<main class="shell"><p class="status">x</p><pre class="box">{\n'
        f'  &#34;success&#34;: true,\n  &#34;code&#34;: &#34;{code}&#34;,\n'
        '  &#34;message&#34;: &#34;ok&#34;\n}</pre></main></body></html>'
    )


def test_direct_code_api_waits_until_six_digit_code_arrives(monkeypatch):
    provider = _code_provider(monkeypatch, '{"success":false,"code":"no_code","message":"暂未收到验证码","retryable":true}')
    assert provider._direct_otp_api is True
    assert provider._load() == []
    assert provider._source == "direct-json"

    provider._fetch.return_value = '{"success":true,"code":"123456","time":"2026-09-23T21:30:00+08:00"}'
    msgs = provider._load()
    assert msgs[0]["otp"] == "123456"
    assert msgs[0]["layout"] == "direct-code-json"
    assert msgs[0]["uid"].startswith("direct-code:")
    assert msgs[0]["ts"] == datetime.fromisoformat("2026-09-23T21:30:00+08:00").timestamp()


def test_tibosb_html_wrapped_page_waits_then_parses_code(monkeypatch):
    """ic-mail.tibosb.cloud 把同一个 JSON 包在 <pre> 里返回。"""
    provider = icloud_relay.ICloudRelayProvider(email=EMAIL, relay_url=TIBOSB_URL)
    assert provider._direct_otp_api is True
    monkeypatch.setattr(provider, "_fetch", Mock(return_value=_tibosb_page("no_code")))
    monkeypatch.setattr(provider, "_try_api", Mock(side_effect=AssertionError("unexpected")))
    monkeypatch.setattr(icloud_relay, "_discover_endpoints", Mock(side_effect=AssertionError("unexpected")))
    monkeypatch.setattr(icloud_relay, "parse_relay_html", Mock(side_effect=AssertionError("unexpected")))

    assert provider._load() == []
    assert provider._source == "direct-json"

    provider._fetch.return_value = _tibosb_page("654321")
    msgs = provider._load()
    assert msgs[0]["otp"] == "654321"
    assert msgs[0]["layout"] == "direct-code-json"


def test_direct_code_api_accepts_missing_time_with_stable_uid(monkeypatch):
    provider = _code_provider(monkeypatch, '{"success":true,"code":"654321","message":"ok"}')
    msgs = provider._load()
    assert msgs[0]["otp"] == "654321"
    assert msgs[0]["ts"] is None
    assert msgs[0]["uid"]


def test_direct_code_api_parses_non_padded_received_at(monkeypatch):
    raw = ('{"success":true,"email":"relay-fixture@icloud.com","code":"831636",'
           '"subject":"ChatGPT の一時的な認証コード",'
           '"received_at":"2026-9-23 23:07:10","message_id":"3e7147e1-9e4e"}')
    provider = _code_provider(monkeypatch, raw)
    msgs = provider._load()
    assert msgs[0]["otp"] == "831636"
    assert msgs[0]["ts"] == datetime(2026, 9, 23, 23, 7, 10).timestamp()
    assert msgs[0]["uid"] == "direct-code:3e7147e1-9e4e"


def _code_msg(code, ts, uid):
    return {
        "sender": "openai (configured OTP API)",
        "subject": "OpenAI OTP",
        "body": "",
        "date_str": "",
        "ts": ts,
        "layout": "direct-code-json",
        "otp": code,
        "uid": uid,
    }


def test_mark_all_current_seen_excludes_preexisting_codes(monkeypatch):
    provider = icloud_relay.ICloudRelayProvider(email=EMAIL, relay_url=CODE_URL)
    old = _code_msg("111111", NOW, "direct-code:old")
    provider._messages = Mock(return_value=[old])
    provider.mark_all_current_seen()
    assert provider._snapshot_done is True
    assert provider._fp(old) in provider._seen


def test_wait_for_otp_uses_only_post_mark_code(monkeypatch, clock):
    provider = icloud_relay.ICloudRelayProvider(email=EMAIL, relay_url=CODE_URL)
    old = _code_msg("111111", NOW, "direct-code:old")
    new = _code_msg("222222", NOW + 30, "direct-code:new")
    provider._messages = Mock(side_effect=[[old], [new]])
    provider.mark_all_current_seen()
    code = provider.wait_for_otp(EMAIL, timeout=60, issued_after=NOW + 10)
    assert code == "222222"


def test_direct_api_parses_single_otp_object(monkeypatch, clock):
    provider = _direct_provider(monkeypatch, _single_payload("200228"))

    messages = provider._load()

    assert len(messages) == 1
    assert messages[0]["otp"] == "200228"
    assert messages[0]["ts"] == NOW
    assert provider.wait_for_otp(EMAIL, timeout=60, issued_after=NOW) == "200228"


@pytest.mark.parametrize("raw", [
    "", "[]", "null", "{}", "{broken", "<p>OpenAI</p><p>654321</p>",
    _payload(123456), _payload(True), _payload("12345"), _payload("1234567"),
    _payload("１２３４５６"), _payload(" 654321"),
    _payload(stamp=None), _payload(stamp="invalid"),
    _payload(stamp="2026-09-21T23:29:12"),
    json.dumps([{"otp": CODE}, {"time": STAMP}, None]),
    json.dumps({"otp": CODE}),
    json.dumps({"time": STAMP}),
])
def test_direct_api_rejects_invalid_records_without_text_fallback(monkeypatch, raw):
    provider = _direct_provider(monkeypatch, raw)
    assert provider._load() == []
    assert provider._load() == []


def test_direct_api_fingerprints_time_and_code_and_sorts_newest_first():
    later = "2026-09-21T23:29:13+08:00"
    records = [
        {"otp": CODE, "time": STAMP},
        {"otp": CODE, "time": "2026-09-21T15:29:12Z"},
        {"otp": "123456", "time": STAMP},
        {"otp": CODE, "time": later},
        {"otp": CODE, "time": "2026-09-21T23:29:13"},
    ]
    messages = icloud_relay._parse_direct_otp_json(json.dumps(records))
    assert len(messages) == 3
    assert messages[0]["ts"] == NOW + 1
    assert len({icloud_relay.ICloudRelayProvider._fp(message) for message in messages}) == 3
    equivalent = icloud_relay._parse_direct_otp_json(_payload(stamp="2026-09-21T15:29:12+00:00"))[0]
    original = next(message for message in messages if message["ts"] == NOW and message["otp"] == CODE)
    assert original["uid"] == equivalent["uid"]


@pytest.mark.parametrize("url", [
    "https://relay.example/api/v1/gpt/otp?token=fixture",
    "https://icloud.tongsheep.cyou.example/api/v1/gpt/otp",
    "https://icloud.tongsheep.cyou/api/v1/gpt/otp/",
    "https://icloud.tongsheep.cyou/messages",
    "http://icloud.tongsheep.cyou/api/v1/gpt/otp",
])
def test_explicit_schema_is_scoped_to_verified_https_endpoint(monkeypatch, url):
    provider = icloud_relay.ICloudRelayProvider(email=EMAIL, relay_url=url)
    raw = _payload()
    monkeypatch.setattr(provider, "_fetch", Mock(return_value=raw))
    generic_result = [{"otp": "generic-fixture"}]
    generic_parser = Mock(return_value=generic_result)
    monkeypatch.setattr(icloud_relay, "parse_relay_html", generic_parser)
    assert provider._load() == generic_result
    generic_parser.assert_called_once_with(raw)


@pytest.mark.parametrize("raw, expected_layout", [
    (f"<h1>OpenAI</h1><div>{STAMP}</div><div>{CODE}</div>", "scan"),
    (json.dumps([{"subject": "ChatGPT verification", "time": STAMP, "code": CODE}]), "scan-json"),
])
def test_ordinary_html_and_generic_json_keep_existing_parser(monkeypatch, raw, expected_layout):
    provider = icloud_relay.ICloudRelayProvider(
        email=EMAIL, relay_url="https://relay.example/messages/fixture",
    )
    monkeypatch.setattr(provider, "_fetch", Mock(return_value=raw))
    expected = icloud_relay.parse_relay_html(raw)
    assert expected[0]["layout"] == expected_layout
    assert expected[0]["otp"] == CODE
    assert provider._load() == expected
    assert provider._load() == expected


def test_fresh_first_poll_is_consumed_without_a_second_fetch(monkeypatch, clock, caplog):
    caplog.set_level(logging.DEBUG, logger=icloud_relay.__name__)
    provider = _direct_provider(monkeypatch, _payload())
    provider._fetch.side_effect = [_payload(), "[]"]
    assert provider.wait_for_otp(EMAIL, timeout=60, issued_after=NOW) == CODE
    assert provider._fetch.call_count == 1
    assert clock.sleeps == []
    assert CODE not in caplog.text


def test_old_direct_response_is_excluded(monkeypatch, clock):
    old_stamp = (datetime.fromisoformat(STAMP) - timedelta(seconds=91)).isoformat()
    provider = _direct_provider(monkeypatch, _payload(stamp=old_stamp))
    with pytest.raises(TimeoutError):
        provider.wait_for_otp(EMAIL, timeout=60, issued_after=NOW)
    assert len(provider._seen) == 1
    assert sum(clock.sleeps) == 60


def test_snapshot_skips_old_and_undated_rows_but_accepts_cutoff_boundary(monkeypatch, clock):
    provider = icloud_relay.ICloudRelayProvider(email=EMAIL, relay_url=DIRECT_URL)
    rows = [
        {"uid": "old", "ts": NOW - 91, "otp": "111111", "sender": "openai"},
        {"uid": "undated", "ts": None, "otp": "222222", "sender": "openai"},
        {"uid": "boundary", "ts": NOW - 90, "otp": CODE, "sender": "openai"},
    ]
    messages = Mock(return_value=rows)
    monkeypatch.setattr(provider, "_messages", messages)
    assert provider.wait_for_otp(EMAIL, timeout=60, issued_after=NOW) == CODE
    messages.assert_called_once()
    assert provider._seen == {"uid:old", "uid:undated", "uid:boundary"}


def test_identical_response_is_not_returned_twice(monkeypatch, clock):
    provider = _direct_provider(monkeypatch, _payload())
    assert provider.wait_for_otp(EMAIL, timeout=60, issued_after=NOW) == CODE
    with pytest.raises(TimeoutError):
        provider.wait_for_otp(EMAIL, timeout=60, issued_after=NOW)
    assert len(provider._seen) == 1


def test_html_same_second_subject_different_body_keeps_both_messages():
    first = {
        "date_str": "2026-09-21 23:29:12",
        "subject": "ChatGPT verification",
        "body": "OpenAI\n654321",
    }
    second = {
        "date_str": first["date_str"],
        "subject": first["subject"],
        "body": "OpenAI\n123456",
    }
    assert icloud_relay.ICloudRelayProvider._fp(first) != (
        icloud_relay.ICloudRelayProvider._fp(second)
    )
    assert icloud_relay.ICloudRelayProvider._fp(first) == (
        icloud_relay.ICloudRelayProvider._fp(dict(first))
    )


def test_html_timestamp_with_space_before_offset_is_fresh():
    raw = "<div>OpenAI</div><div>2026-09-21 23:29:12 +08:00</div><div>654321</div>"
    messages = icloud_relay._scan_html(raw)
    assert len(messages) == 1
    assert messages[0]["otp"] == CODE
    assert messages[0]["ts"] == NOW


def test_without_issued_after_existing_snapshot_behavior_is_preserved(monkeypatch, clock):
    provider = _direct_provider(monkeypatch, _payload())
    provider._fetch.side_effect = [_payload(), _payload("123456")]
    assert provider.wait_for_otp(EMAIL, timeout=60) == "123456"
    assert provider._fetch.call_count == 2


@pytest.mark.parametrize("layout, timestamp", [("scan", None), ("scan-json", NOW)])
def test_polling_logs_do_not_include_code_or_subject(monkeypatch, clock, caplog, layout, timestamp):
    caplog.set_level(logging.DEBUG, logger=icloud_relay.__name__)
    provider = icloud_relay.ICloudRelayProvider(email=EMAIL, relay_url=DIRECT_URL)
    provider._snapshot_done = True
    monkeypatch.setattr(provider, "_messages", Mock(return_value=[{
        "uid": "candidate", "otp": CODE, "sender": "openai", "subject": f"code {CODE}",
        "layout": layout, "ts": timestamp, "date_str": STAMP,
    }]))
    assert provider.wait_for_otp(EMAIL, timeout=60, issued_after=NOW) == CODE
    assert CODE not in caplog.text


def test_blind_whole_page_fallback_is_not_accepted_for_fresh_otp(monkeypatch, clock):
    provider = _direct_provider(monkeypatch, _payload())
    provider._snapshot_done = True
    monkeypatch.setattr(provider, "_messages", Mock(return_value=[{
        "uid": "fallback-page", "otp": CODE, "sender": "openai",
        "subject": f"code {CODE}", "layout": "fallback", "ts": None,
        "date_str": "fallback:fixture",
    }]))
    with pytest.raises(TimeoutError):
        provider.wait_for_otp(EMAIL, timeout=60, issued_after=NOW)


def test_connectivity_result_reports_count_without_otp(monkeypatch):
    provider = _direct_provider(monkeypatch, _payload())
    result = provider.self_test()
    assert result["ok"] is True
    assert CODE not in str(result)


def _embedded_page(code=None, message_id="msg_216384", stamp="2026-09-26 05:31:15"):
    """ic-mail.tibosb.cloud 形态：HTML 壳里嵌 <pre> JSON，引号被转义成 &#34;。"""
    if code is None:
        body = '{ "success": false, "code": "no_code", "message": "尚未收到验证码", "retryable": true }'
    else:
        body = (
            '{ "success": true, "code": "%s", "message_id": "%s", "received_at": "%s" }'
            % (code, message_id, stamp)
        )
    body = body.replace('"', "&#34;")
    return (
        '<!doctype html><html><head><title>取件码</title></head><body>'
        '<main class="shell"><p class="status">收件后自动停止</p>'
        '<pre class="box">%s</pre></main></body></html>' % body
    )


def test_embedded_code_json_inside_html_shell_is_extracted():
    msgs = icloud_relay.parse_relay_html(_embedded_page(code="235272"))
    assert len(msgs) == 1
    assert msgs[0]["otp"] == "235272"
    assert msgs[0]["layout"] == "direct-code-json"
    assert msgs[0]["uid"] == "direct-code:msg_216384"
    assert msgs[0]["ts"] is not None


def test_embedded_code_json_no_code_keeps_polling_semantics():
    msgs = icloud_relay.parse_relay_html(_embedded_page(code=None))
    # 没到货时不允许产出"有码"的消息；落到兜底并保持 otp=None
    assert not any(m.get("otp") for m in msgs)


def test_embedded_code_json_survives_cf_email_protection_anchor():
    """真实页面里 email 字段带 CF 邮件保护 <a>，反转义后整段 JSON 非法，
    也必须能把 6 位码抠出来（uid 仍在，时间窗校验不丢）。"""
    pre = (
        '{ &#34;success&#34;: true, &#34;code&#34;: &#34;394827&#34;, '
        '&#34;email&#34;: &#34;<a href=&#34;/cdn-cgi/l/email-protection&#34; '
        'class=&#34;__cf_email__&#34;>[email&#160;protected]</a>&#34;, '
        '&#34;message_id&#34;: &#34;msg_999&#34;, '
        '&#34;received_at&#34;: &#34;2026-09-26 12:05:38&#34; }'
    )
    html = (
        '<!doctype html><html><body><main><pre class="box">%s</pre></main>'
        "</body></html>" % pre
    )
    msgs = icloud_relay.parse_relay_html(html)
    assert len(msgs) == 1
    assert msgs[0]["otp"] == "394827"
    assert msgs[0]["layout"] == "direct-code-json"
    assert msgs[0]["uid"] == "direct-code:msg_999"
    assert msgs[0]["ts"] is not None
