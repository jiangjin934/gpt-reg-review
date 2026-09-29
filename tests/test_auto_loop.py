from webui import auto_loop, db, probes


def test_auto_lifecycle_without_live_workers(monkeypatch):
    class DeferredThread:
        def __init__(self, **kwargs):
            self.target = kwargs["target"]

        def start(self):
            pass

        def join(self):
            pass

    monkeypatch.setattr(auto_loop.threading, "Thread", DeferredThread)
    monkeypatch.setattr(auto_loop.time, "sleep", lambda delay: None)
    controller = auto_loop.AutoLoopController()
    subscriber = controller.subscribe()
    assert controller.status()["state"] == "stopped"
    assert controller.pause()["ok"] is False
    assert controller.start({"concurrency": 1})["state"] == "running"
    assert controller.start({})["ok"] is False
    assert controller.pause()["state"] == "paused"
    assert controller._pause_event.is_set()
    assert controller.resume()["state"] == "running"
    assert not controller._pause_event.is_set()
    assert controller.stop()["ok"] is True
    controller._manage_loop()
    assert controller.status()["state"] == "stopped"
    assert controller.status()["workers"] == []
    assert subscriber.qsize() >= 6
    controller.unsubscribe(subscriber)
    for operation in ("auto.start", "auto.pause", "auto.resume", "auto.stop"):
        events = probes.list_operation_probes(operation=operation)
        assert any(e["status"] == "started" for e in events)
        assert any(e["status"] == "ok" for e in events)


def test_stop_waits_for_current_registration_and_keeps_its_result(monkeypatch):
    db.create_run("in-flight", "test@example.com", "fixture.log")
    controller = auto_loop.AutoLoopController()
    controller._stop_event.set()
    sleeps = []

    def complete_run(_delay):
        sleeps.append(_delay)
        db.finish_run("in-flight", "done")

    monkeypatch.setattr(auto_loop.time, "sleep", complete_run)
    assert controller._wait_run_finish("in-flight", timeout=1) == (True, "")
    assert len(sleeps) == 1


def test_network_failures_trigger_recovery_and_target_completion_stops(monkeypatch):
    controller = auto_loop.AutoLoopController()
    controller._state = auto_loop.AutoLoopState.RUNNING
    recovered = []
    monkeypatch.setattr(
        controller, "_start_auto_recovery", lambda: recovered.append(True)
    )
    for _ in range(3):
        controller._record_finish(False, "network")
    # 现在熔断不再暂停任务，改为自动体检代理后继续
    assert recovered, "连续网络失败应触发一次代理自愈"
    assert controller.status()["state"] == "running"
    assert not controller._pause_event.is_set()
    assert controller.status()["registered_fail"] == 3
    controller._target_count = 1
    controller._record_finish(True, "")
    assert controller._stop_event.is_set()
    assert controller.status()["registered_ok"] == 1

def test_circuit_break_distinguishes_exits(monkeypatch):
    controller = auto_loop.AutoLoopController()
    controller._state = auto_loop.AutoLoopState.RUNNING
    recovered = []
    monkeypatch.setattr(
        controller, "_start_auto_recovery", lambda: recovered.append(True)
    )
    # 同一个出口连续失败 3 次 → 触发自愈（该出口已死，别无限重试），但不暂停任务
    for _ in range(3):
        controller._record_finish(False, "network", "203.0.113.7")
    assert recovered
    assert controller.status()["state"] == "running"


def test_circuit_break_alternating_exits_do_not_pause():
    controller = auto_loop.AutoLoopController()
    controller._state = auto_loop.AutoLoopState.RUNNING
    # 两条出口交替失败：池里还有别的候选，不该停掉整批
    for ip in ("203.0.113.7", "203.0.113.8"):
        controller._record_finish(False, "network", ip)
    controller._record_finish(False, "network", "203.0.113.7")
    assert controller.status()["state"] == "running"


def test_circuit_break_success_resets_window():
    controller = auto_loop.AutoLoopController()
    controller._state = auto_loop.AutoLoopState.RUNNING
    controller._record_finish(False, "network", "203.0.113.7")
    controller._record_finish(False, "network", "203.0.113.7")
    controller._record_finish(True, "")
    controller._record_finish(False, "network", "203.0.113.7")
    controller._record_finish(False, "network", "203.0.113.7")
    assert controller.status()["state"] == "running"


def test_release_retryable_keeps_account_retryable():
    db.import_accounts(
        "retryable@icloud.com----https://relay.example/messages/TOKEN/retryable@icloud.com",
        kind="icloud_relay",
    )
    db.claim_account("retryable@icloud.com")
    db.mark_failed("retryable@icloud.com", "old failure")
    assert db.get_account("retryable@icloud.com")["status"] == "failed"

    db.release_retryable("retryable@icloud.com", "otp timeout retry")
    account = db.get_account("retryable@icloud.com")
    assert account["status"] == "available"
    assert "otp timeout retry" in (account["fail_reason"] or "")
    assert account["imported_at"] > 0

def test_resolve_proxy_pool_falls_back_to_settings():
    db.set_setting("proxy_pool", "socks5h://user:pass@host:3000")
    resolved = auto_loop._resolve_proxy_pool({"concurrency": 1})
    assert resolved["proxy_pool"] == "socks5h://user:pass@host:3000"
    assert resolved["concurrency"] == 1


def test_resolve_proxy_pool_prefers_explicit_request_pool():
    db.set_setting("proxy_pool", "socks5h://stale:pass@host:3000")
    resolved = auto_loop._resolve_proxy_pool({"proxy_pool": "socks5h://fresh:p@h:3000"})
    assert resolved["proxy_pool"] == "socks5h://fresh:p@h:3000"


def test_resolve_proxy_pool_empty_without_settings():
    db.set_setting("proxy_pool", "")
    resolved = auto_loop._resolve_proxy_pool({})
    assert resolved.get("proxy_pool", "") == ""


def test_start_without_pool_field_keeps_persisted_pool(monkeypatch):
    """API 重启不带 proxy_pool 时，内存池必须回落到服务端持久化的那一份。

    否则状态页 proxy_pool_size=0，看着像没代理在跑（实测踩过）。
    """
    class DeferredThread:
        def __init__(self, **kwargs):
            self.target = kwargs["target"]

        def start(self):
            pass

        def join(self):
            pass

    monkeypatch.setattr(auto_loop.threading, "Thread", DeferredThread)
    db.set_setting(
        "proxy_pool",
        "socks5h://u:p@h1:3000\nsocks5h://u:p@h2:3000",
    )
    controller = auto_loop.AutoLoopController()

    result = controller.start({"concurrency": 20})

    assert result["ok"] is True
    assert result["proxy_pool_size"] == 2
    assert controller.status()["proxy_pool_size"] == 2


def test_idle_patience_is_longer_when_auto_supply_enabled():
    """自动供号开着时要给补货留时间，否则 worker 撤光、并发塌到 1。"""
    from webui import mail_supply

    db.set_setting("remail_auto_buy", "1")
    assert auto_loop._idle_patience_rounds() == 40
    db.set_setting("remail_auto_buy", "0")
    assert auto_loop._idle_patience_rounds() == 10
