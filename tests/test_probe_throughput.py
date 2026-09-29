"""并发与节流相关的用例：
  · 并发数可配且有上下限；
  · 多 worker 只按配置数量拉起，不多不少；
  · 提交侧有全局最小间隔（防突发），但不会把连续提交拖得太慢。
"""
from __future__ import annotations

import threading
import time

import pytest

import checkout_service_probe as csp
from webui import checkout_capability, db


def _noop_loop():
    while True:
        time.sleep(0.05)


@pytest.fixture
def quiet_workers(monkeypatch):
    """把 worker 体替换成空转，测「拉起几个」而不真去探测。"""
    monkeypatch.setattr(checkout_capability, "_worker_loop", _noop_loop)
    monkeypatch.setattr(checkout_capability, "_WORKERS", [])
    monkeypatch.setattr(checkout_capability, "_PROCESSING", {})
    yield
    for thread in list(checkout_capability._WORKERS):
        thread.join(timeout=0.2)
    monkeypatch.setattr(checkout_capability, "_WORKERS", [])


def test_concurrency_default_and_clamp():
    db.set_setting("checkout_capability_concurrency", "")
    # 2026-09-29 提速：默认 8 路（限流按 token，号与号互不影响，8 路安全）
    assert checkout_capability.config()["concurrency"] == 8

    db.set_setting("checkout_capability_concurrency", "99")
    assert checkout_capability.config()["concurrency"] == 8

    db.set_setting("checkout_capability_concurrency", "0")
    assert checkout_capability.config()["concurrency"] == 1


def test_worker_pool_fills_up_to_configured_concurrency(quiet_workers):
    db.set_setting("checkout_capability_concurrency", "3")

    checkout_capability._ensure_worker()
    alive = [t for t in checkout_capability._WORKERS if t.is_alive()]
    assert len(alive) == 3

    # 再叫一次不会重复拉人
    checkout_capability._ensure_worker()
    assert len([t for t in checkout_capability._WORKERS if t.is_alive()]) == 3


def test_enqueue_is_deduplicated_across_workers(quiet_workers):
    db.set_setting("checkout_capability_enabled", "1")
    db.set_setting("checkout_capability_auto", "1")
    db.set_setting("checkout_capability_concurrency", "2")
    while not checkout_capability._QUEUE.empty():
        checkout_capability._QUEUE.get_nowait()

    assert checkout_capability.enqueue("dup@example.com") is True
    assert checkout_capability.enqueue("dup@example.com") is False
    assert checkout_capability.enqueue("other@example.com") is True


def test_submit_throttle_spaces_out_concurrent_submissions(monkeypatch):
    """并发 worker 同时提交时，提交点之间要有全局最小间隔（防突发限流）。"""
    stamps: list[float] = []

    def fake_http_json(method, url, *, payload=None, timeout=45.0):
        stamps.append(time.time())
        return 202, {"taskId": "t"}

    monkeypatch.setattr(csp, "_http_json", fake_http_json)
    monkeypatch.setattr(csp, "_MIN_SUBMIT_GAP", 0.25)
    monkeypatch.setattr(csp, "_LAST_SUBMIT_AT", 0.0)

    def submit_once(_i):
        csp._submit("tok", "socks5h://u:p@h:1")

    threads = [threading.Thread(target=submit_once, args=(i,)) for i in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert len(stamps) == 3
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    assert all(gap >= 0.2 for gap in gaps), gaps


def test_poll_interval_is_short_enough():
    """轮询间隔要短（2.5s）：单号探测时间主要花在等服务端结论上。"""
    import inspect

    signature = inspect.signature(csp.probe_via_service)
    assert signature.parameters["poll_every"].default <= 3.0
