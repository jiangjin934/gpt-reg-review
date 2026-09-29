"""OAuth callback 被拒后的链路内恢复测试。

现场（2026-09-25 run 77ce055d6a73）：重定向链最后一跳落在
https://chatgpt.com/auth/error?error=OAuthCallback，session/access 全缺。
归因：callback 的 code 已作废，必须重新 authorize 换新 code 再消费。
这组测试盯住恢复流程的顺序与退出条件。
"""
from auth_flow import AuthFlow, AuthResult


def _bare_flow() -> AuthFlow:
    flow = AuthFlow.__new__(AuthFlow)
    flow.result = AuthResult()
    flow.result.email = "fixture@example.com"
    return flow


def test_recover_missing_session_reauthorizes_and_consumes():
    flow = _bare_flow()
    calls = []
    new_callback = "https://chatgpt.com/api/auth/callback/openai?code=NEW&state=st"
    flow._reauthorize_for_session = lambda url, mail_provider=None: (
        calls.append(("reauthorize", url)) or new_callback
    )

    def consume(url):
        calls.append(("consume", url))
        flow.result.session_token = "st-value"
        flow.result.access_token = "at-value"
        return True

    flow._consume_callback_for_session = consume
    flow.get_auth_session = lambda: calls.append(("get_session", ""))

    assert flow._recover_missing_session("https://auth.openai.com/authorize?x=1") == new_callback
    assert [c[0] for c in calls] == ["reauthorize", "consume", "get_session"]
    assert calls[1][1] == new_callback


def test_recover_missing_session_gives_up_without_callback():
    flow = _bare_flow()
    flow._reauthorize_for_session = lambda url, mail_provider=None: None

    def _no_consume(url):
        raise AssertionError("不应消费空的 callback")

    def _no_session():
        raise AssertionError("没有 callback 时不应再拉 session")

    flow._consume_callback_for_session = _no_consume
    flow.get_auth_session = _no_session

    assert flow._recover_missing_session("https://auth.openai.com/authorize") == ""


def test_recover_missing_session_retries_when_first_code_still_fails():
    flow = _bare_flow()
    attempts = []

    def reauth(url, mail_provider=None):
        attempts.append(len(attempts) + 1)
        return f"https://chatgpt.com/api/auth/callback/openai?code=C{len(attempts)}"

    def consume(url):
        if url.endswith("code=C2"):
            flow.result.session_token = "st-2"
            flow.result.access_token = "at-2"
        return True

    flow._reauthorize_for_session = reauth
    flow._consume_callback_for_session = consume
    flow.get_auth_session = lambda: None

    callback = flow._recover_missing_session("https://auth.openai.com/authorize", attempts=2)
    assert callback.endswith("code=C2")
    assert len(attempts) == 2


def test_recover_missing_session_handles_reauthorize_exception():
    flow = _bare_flow()

    def boom(url, mail_provider=None):
        raise RuntimeError("network down")

    flow._reauthorize_for_session = boom
    flow._consume_callback_for_session = lambda url: True
    flow.get_auth_session = lambda: None

    assert flow._recover_missing_session("https://auth.openai.com/authorize") == ""
