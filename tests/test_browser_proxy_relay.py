"""浏览器启动器必须能给「带认证的 SOCKS5」接上本地中继。

背景：Playwright/Camoufox 不支持带用户名密码的 SOCKS5，实测直接报
`BrowserType.launch: Browser does not support socks5 proxy authentication`，
而代理池里全是 `socks5h://user:pass@host:port` —— 浏览器引擎因此一直起不来。
"""
import pytest

import browser_launcher


class FakeRelay:
    def __init__(self, upstream: str):
        self.upstream = upstream
        self.started = False
        self.stopped = False

    def start(self) -> str:
        self.started = True
        return "socks5://127.0.0.1:41234"

    def stop(self) -> None:
        self.stopped = True


@pytest.fixture
def fake_relay(monkeypatch):
    created = []

    def factory(upstream):
        relay = FakeRelay(upstream)
        created.append(relay)
        return relay

    import local_socks_relay

    monkeypatch.setattr(local_socks_relay, "LocalSocksRelay", factory)
    return created


def test_authenticated_proxy_goes_through_local_relay(fake_relay):
    proxy_cfg, relay = browser_launcher._proxy_for_playwright(
        "socks5h://user:pass@gate.example:3010"
    )

    assert relay is not None and relay.started
    assert relay.upstream == "socks5h://user:pass@gate.example:3010"
    # 交给浏览器的地址必须是本地免认证的，且不能带凭据
    assert proxy_cfg["server"] == "socks5://127.0.0.1:41234"
    assert "username" not in proxy_cfg


def test_plain_proxy_needs_no_relay(fake_relay):
    proxy_cfg, relay = browser_launcher._proxy_for_playwright("socks5://127.0.0.1:7890")

    assert relay is None
    assert proxy_cfg["server"] == "socks5://127.0.0.1:7890"


def test_http_proxy_with_credentials_also_relayed(fake_relay):
    """HTTP 代理同样带凭据 → 也走中继（统一一条路径，避免两套行为）。"""
    proxy_cfg, relay = browser_launcher._proxy_for_playwright("http://user:pass@gate.example:8080")

    assert relay is not None and relay.started
    assert proxy_cfg["server"].startswith("socks5://127.0.0.1:")


def test_no_proxy_returns_empty_config(fake_relay):
    proxy_cfg, relay = browser_launcher._proxy_for_playwright("")

    assert proxy_cfg is None and relay is None
    assert fake_relay == []


def test_close_browser_stops_relay(monkeypatch):
    relay = FakeRelay("socks5h://u:p@h:1")
    relay.start()

    class FakeBrowser:
        def close(self):
            pass

    launcher = type("Launcher", (), {})()
    launcher._local_socks_relay = relay

    browser_launcher.close_browser(launcher, FakeBrowser())

    assert relay.stopped is True


# ── 屏幕/视口必须钉在冻结画像上 ──


def test_camoufox_config_pins_screen_and_viewport():
    """Camoufox 默认随机生成 screen；项目画像已冻结并写台账，必须钉成一致。

    实测踩过：不传 config 时 Camoufox 报宿主显示器的 screen（2560x1440），
    而画像是 1440x900 → validate_page_fingerprint 判「运行时不符」直接中止任务。
    """
    cfg = browser_launcher._camoufox_config_for_fingerprint(
        {"screen": "1440x900", "viewport": {"width": 1440, "height": 802}}
    )

    assert cfg["screen.width"] == 1440
    assert cfg["screen.height"] == 900
    # screen == avail 会被 CreepJS 当无任务栏识别
    assert cfg["screen.availHeight"] < cfg["screen.height"]
    assert cfg["window.innerHeight"] == 802
    assert cfg["window.outerHeight"] >= cfg["window.innerHeight"]


def test_camoufox_config_is_empty_for_unusable_fingerprint():
    assert browser_launcher._camoufox_config_for_fingerprint({}) == {}
    assert browser_launcher._camoufox_config_for_fingerprint({"screen": "auto"}) == {}


def test_camoufox_config_without_viewport_still_pins_screen():
    cfg = browser_launcher._camoufox_config_for_fingerprint({"screen": "1920x1080"})

    assert cfg["screen.width"] == 1920
    assert "window.innerHeight" not in cfg
