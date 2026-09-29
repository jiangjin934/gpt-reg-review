"""流量记账：总字节 + 按域名的去向，供「流量偏高」排查。"""
from http_client import (
    _is_nextauth_error_url,
    add_thread_traffic,
    reset_thread_traffic,
    thread_traffic,
)


def test_thread_traffic_accumulates_total_and_per_host():
    reset_thread_traffic()
    add_thread_traffic(rx=359_211, tx=900, host="chatgpt.com")
    add_thread_traffic(rx=3_900, tx=120, host="remail.aishop6.com")
    add_thread_traffic(rx=1_000, host="chatgpt.com")

    stats = thread_traffic()

    assert stats["rx"] == 359_211 + 3_900 + 1_000
    assert stats["tx"] == 1_020
    assert stats["hosts"]["chatgpt.com"] == {"rx": 360_211, "tx": 900}
    assert stats["hosts"]["remail.aishop6.com"] == {"rx": 3_900, "tx": 120}


def test_reset_clears_hosts():
    add_thread_traffic(rx=10, host="example.com")
    reset_thread_traffic()

    stats = thread_traffic()

    assert stats["rx"] == 0
    assert stats["hosts"] == {}


def test_nextauth_error_pages_are_recognized():
    assert _is_nextauth_error_url("https://chatgpt.com/api/auth/error?error=OAuthCallback")
    assert _is_nextauth_error_url("https://chatgpt.com/auth/error?error=Configuration")
    assert not _is_nextauth_error_url("https://chatgpt.com/api/auth/callback/openai?code=x")
    assert not _is_nextauth_error_url("https://chatgpt.com/")
