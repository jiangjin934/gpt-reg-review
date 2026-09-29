"""出口探测的回归测试。

背景：probe_exit(require_chatgpt=True) 需要在**同一个 session** 里先探出口、
再探 chatgpt.com 种 oai-did。曾经把 session.close() 放在两个探测中间，
导致每个候选出口都在 chatgpt 探测那步抛 SessionClosed、环境分配永远失败、
任务卡死且日志一片空白。这里盯住这个顺序。
"""
import pytest

from webui import environment


class _FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class _FakeSession:
    """关闭后再用会抛错，用来抓 close 提前发生的回归。"""

    def __init__(self, trace_body, chatgpt_status=200, plant_cookie=True):
        self.closed = False
        self.calls = []
        self._trace_body = trace_body
        self._chatgpt_status = chatgpt_status
        self._plant = plant_cookie
        self.cookies = _FakeCookies()

    def get(self, url, **kwargs):
        if self.closed:
            raise RuntimeError("Session is closed, cannot send request.")
        self.calls.append(url)
        if url == environment.TRACE_URL:
            return _FakeResponse(200, self._trace_body)
        if self._plant:
            self.cookies._data["oai-did"] = "fixture"
        return _FakeResponse(self._chatgpt_status, "<html></html>")

    def close(self):
        self.closed = True


class _FakeCookies:
    def __init__(self):
        self._data = {}

    def get_dict(self):
        return dict(self._data)


TRACE_BODY = "fl=x\nip=203.0.113.9\nloc=JP\nts=1\n"


def test_probe_exit_uses_session_before_closing(monkeypatch):
    session = _FakeSession(TRACE_BODY)
    monkeypatch.setattr(
        "http_client.create_http_session", lambda **kwargs: session, raising=False
    )
    observed = environment.probe_exit(
        "socks5h://u:p@host:3000", timeout=15, family="mixed", require_chatgpt=True
    )

    assert observed["exit_ip"] == "203.0.113.9"
    assert observed["exit_country"] == "JP"
    # 两次探测都必须发生，且发生在关闭之前。
    # 流量优化（2026-09-29）：种 oai-did 走轻量路径 /api/auth/session（~241B），
    # 首页（~358KB）只在轻量路径没种上时兜底 —— cookie 种上就不该碰首页。
    assert environment.TRACE_URL in session.calls
    assert environment.CHATGPT_SESSION_URL in session.calls
    assert environment.CHATGPT_HOME not in session.calls
    assert session.closed is True


def test_probe_exit_falls_back_to_homepage_when_light_path_misses(monkeypatch):
    """轻量路径没种上 oai-did 时，必须回退首页兜底（判定结果不能变）。"""

    class FlakySession(_FakeSession):
        def get(self, url, **kwargs):
            if self.closed:
                raise RuntimeError("Session is closed, cannot send request.")
            self.calls.append(url)
            if url == environment.TRACE_URL:
                return _FakeResponse(200, self._trace_body)
            if url == environment.CHATGPT_SESSION_URL:
                # 轻量路径不种 cookie（模拟被拦/异常）
                return _FakeResponse(200, "{}")
            if self._plant:
                self.cookies._data["oai-did"] = "fixture"
            return _FakeResponse(self._chatgpt_status, "<html></html>")

    session = FlakySession(TRACE_BODY)
    monkeypatch.setattr(
        "http_client.create_http_session", lambda **kwargs: session, raising=False
    )
    observed = environment.probe_exit(
        "socks5h://u:p@host:3000", timeout=15, family="mixed", require_chatgpt=True
    )

    assert observed["exit_ip"] == "203.0.113.9"
    assert environment.CHATGPT_SESSION_URL in session.calls
    assert environment.CHATGPT_HOME in session.calls


def test_probe_exit_rejects_exit_without_oai_did(monkeypatch):
    session = _FakeSession(TRACE_BODY, plant_cookie=False)
    monkeypatch.setattr(
        "http_client.create_http_session", lambda **kwargs: session, raising=False
    )
    with pytest.raises(environment.EnvironmentAllocationError, match="oai-did"):
        environment.probe_exit(
            "socks5h://u:p@host:3000", timeout=15, family="mixed", require_chatgpt=True
        )
    assert session.closed is True


def test_probe_exit_timeout_with_cookie_still_counts_as_usable(monkeypatch):
    class _TimeoutSession(_FakeSession):
        def get(self, url, **kwargs):
            if url == environment.CHATGPT_HOME:
                self.cookies._data["oai-did"] = "fixture"
                raise TimeoutError("timed out after 8s with 40 KB received")
            return super().get(url, **kwargs)

    session = _TimeoutSession(TRACE_BODY)
    monkeypatch.setattr(
        "http_client.create_http_session", lambda **kwargs: session, raising=False
    )
    observed = environment.probe_exit(
        "socks5h://u:p@host:3000", timeout=15, family="mixed", require_chatgpt=True
    )
    assert observed["exit_ip"] == "203.0.113.9"
