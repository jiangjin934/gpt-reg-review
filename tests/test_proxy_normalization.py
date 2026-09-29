from browser_launcher import _parse_proxy_for_playwright
from http_client import normalize_proxy_url


def test_vendor_four_field_proxy_becomes_socks5h_url():
    assert normalize_proxy_url(
        "proxy.example:3000:user-region-JP-sid-abc:pa:ss"
    ) == "socks5h://user-region-JP-sid-abc:pa%3Ass@proxy.example:3000"


def test_socks5_scheme_uses_remote_dns():
    assert normalize_proxy_url("SOCKS5://user:pass@proxy.example:3000") == (
        "socks5h://user:pass@proxy.example:3000"
    )


def test_existing_http_and_bare_host_port_are_preserved():
    assert normalize_proxy_url("http://proxy.example:8080") == "http://proxy.example:8080"
    assert normalize_proxy_url("proxy.example:8080") == "proxy.example:8080"


def test_browser_parser_accepts_vendor_four_field_proxy():
    assert _parse_proxy_for_playwright(
        "proxy.example:3000:user:pass"
    ) == {
        "server": "socks5://proxy.example:3000",
        "username": "user",
        "password": "pass",
    }
