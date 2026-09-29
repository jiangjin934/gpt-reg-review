"""取码响应解析覆盖：结构化 JSON / HTML 壳内 JSON / 字段内混入标记片段。

这组用例固定住三种真实响应形态，验证归一化与字段级兜底解析都能稳定读出
6 位验证码与消息标识（uid），保证解析链路的覆盖面不随版本退化。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mail_providers.icloud_relay import (  # noqa: E402
    _parse_direct_code_json,
    _rescue_direct_code,
    _unwrap_html_json,
)


def _page(pre_body: str) -> str:
    """套上真实页面外壳：JSON 放在 ``<pre class="box">`` 里，引号是 HTML 实体。"""
    return (
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        "<title>取码结果</title><style>.box{white-space:pre-wrap}</style></head>"
        '<body><main class="shell"><p class="status">正在自动刷新，拿到结果后会自动停止</p>'
        f'<pre class="box">{pre_body}</pre></main>'
        "<script>setTimeout(function(){location.reload()},8000)</script></body></html>"
    )


# 已到码：email 字段为带标记的富文本片段
HTML_WITH_CODE_INJECTED = _page(
    "{\n"
    "  &#34;success&#34;: true,\n"
    "  &#34;code&#34;: &#34;800715&#34;,\n"
    "  &#34;email&#34;: &#34;<a href=\"/protected/link\" "
    "class=\"email-shield\" data-token=\"8f8c8e8d8c\">someone&#64;example.com</a>&#34;,\n"
    "  &#34;message_id&#34;: &#34;msg-abc123&#34;,\n"
    "  &#34;received_at&#34;: &#34;2026-09-29 07:15:03&#34;\n"
    "}"
)

# 未到码：直接返回结构化 JSON
HTML_NO_CODE = _page(
    "{\n"
    "  &#34;success&#34;: false,\n"
    "  &#34;code&#34;: &#34;no_code&#34;,\n"
    "  &#34;message&#34;: &#34;暂未收到验证码&#34;,\n"
    "  &#34;retryable&#34;: true\n"
    "}"
)


def test_unwrap_strips_injected_tag_and_yields_valid_json():
    body = _unwrap_html_json(HTML_WITH_CODE_INJECTED)
    assert "email-shield" not in body
    data = json.loads(body)          # 回退之前这里必抛 JSONDecodeError
    assert data["code"] == "800715"
    assert data["message_id"] == "msg-abc123"


def test_parse_direct_code_json_reads_code_despite_injected_markup():
    records = _parse_direct_code_json(HTML_WITH_CODE_INJECTED)
    assert len(records) == 1
    rec = records[0]
    assert rec["otp"] == "800715"
    assert rec["uid"] == "direct-code:msg-abc123"
    assert rec["layout"] == "direct-code-json"
    assert rec["ts"] is not None


def test_no_code_response_still_returns_nothing():
    assert _parse_direct_code_json(HTML_NO_CODE) == []


def test_rescue_scans_original_text_when_stripping_cannot_save_json():
    """还有没预料到的注入形态时，原样文本里的 code 键要能捞出来。"""
    broken = (
        '{"success": true, "code": "800715", "email": "someone@icloud.com" junk, '
        '"message_id": "msg-x9"}'
    )
    records = _parse_direct_code_json(broken)
    assert [r["otp"] for r in records] == ["800715"]
    assert records[0]["uid"] == "direct-code:msg-x9"


def test_rescue_ignores_other_six_digit_numbers():
    """兜底只认 ``"code": "NNNNNN"`` 键值对，不能把别的 6 位数当验证码。"""
    payload = '{"success": true, "amount": 123456, "note": "order 654321", broken'
    assert _parse_direct_code_json(payload) == []
    assert _rescue_direct_code(payload) is None


def test_rescue_handles_html_escaped_quotes():
    escaped = '&#34;code&#34;: &#34;424242&#34;, oops'
    rescued = _rescue_direct_code(escaped)
    assert rescued is not None and rescued["otp"] == "424242"


def test_rescue_returns_none_without_code():
    assert _rescue_direct_code("<html><body>nothing here</body></html>") is None
    assert _rescue_direct_code("") is None


def test_plain_json_payload_still_works():
    """非 HTML 的纯 JSON 响应（另一家中转站）行为不变。"""
    raw = json.dumps({"success": True, "code": "112233", "message_id": "m-1"})
    records = _parse_direct_code_json(raw)
    assert [r["otp"] for r in records] == ["112233"]
