"""熔断自愈测试：网络连续失败不再暂停任务，而是自动体检代理后继续。"""
from webui.auto_loop import AutoLoopController, AutoLoopState


def test_circuit_break_starts_recovery_without_pausing(monkeypatch):
    ctl = AutoLoopController()
    ctl._state = AutoLoopState.RUNNING
    started = []
    monkeypatch.setattr(ctl, "_start_auto_recovery", lambda: started.append(True))

    for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        ctl._record_finish(False, "network", exit_ip=ip)

    assert started, "连续 3 个不同出口失败应触发自愈线程"
    assert ctl._state == AutoLoopState.RUNNING, "不允许再把任务暂停"
    assert not ctl._pause_event.is_set()
    assert "自动体检代理" in ctl._last_break_reason


def test_auto_recovery_continues_after_proxy_recovers(monkeypatch):
    ctl = AutoLoopController()
    ctl._state = AutoLoopState.RUNNING
    monkeypatch.setattr(ctl._stop_event, "wait", lambda _t: False)
    checks = [(False, "抽样 3 条均不可用（Timeout）"), (True, "代理正常（1.2.3.4 VN）")]

    def fake_check(sample: int = 3):
        return checks.pop(0) if checks else (True, "代理正常")

    monkeypatch.setattr(ctl, "_proxy_health_check", fake_check)
    ctl._recovering = True
    ctl._auto_recovery_loop()

    assert ctl._recovering is False
    assert "代理正常，继续执行" in ctl._last_message


def test_health_check_false_when_every_candidate_fails(monkeypatch):
    ctl = AutoLoopController()
    import webui.environment as environment

    monkeypatch.setattr(
        environment, "_candidate_proxies", lambda _o: ["socks5h://a", "socks5h://b"]
    )

    def boom(*_a, **_k):
        raise RuntimeError("curl: (28) timed out")

    monkeypatch.setattr(environment, "probe_exit", boom)
    ok, detail = ctl._proxy_health_check(sample=2)
    assert ok is False
    assert "不可用" in detail
