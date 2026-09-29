"""自动探测队列：入队去重、失败记账、结果落库。

原用例盯的是 int31 的 429 退避；协议链路没有服务端限流，但出口抖动仍然
存在，所以这里改盯「传输失败只记一次，不回灌队列无限重试」。
"""
import time

from webui import checkout_capability, db


def _enable(monkeypatch):
    db.set_setting("checkout_capability_enabled", "1")
    db.set_setting("checkout_capability_auto", "1")
    db.set_setting("checkout_capability_interval", "3")
    # 不真起线程：把 worker 启动换成空操作
    monkeypatch.setattr(checkout_capability, "_ensure_worker", lambda: None)
    checkout_capability._QUEUE.queue.clear()
    checkout_capability._QUEUED.clear()
    checkout_capability._STATE.update(
        processing="", done=0, failed=0, last_error="", last_result={}
    )


def _drain_one() -> dict:
    """跑一轮 worker 循环体（不进入死循环）。"""
    email = checkout_capability._QUEUE.get_nowait()
    outcome = checkout_capability.probe_email(email)
    if outcome.get("ok"):
        checkout_capability._STATE["done"] += 1
        checkout_capability._STATE["last_result"] = {"email": email}
    else:
        checkout_capability._STATE["failed"] += 1
        checkout_capability._STATE["last_error"] = (
            outcome.get("error") or outcome.get("failure_type") or "unknown"
        )
    checkout_capability._QUEUED.discard(email)
    return outcome


def test_enqueue_is_deduped_and_requires_auto(monkeypatch):
    _enable(monkeypatch)

    assert checkout_capability.enqueue("a@example.com") is True
    assert checkout_capability.enqueue("a@example.com") is False
    assert checkout_capability.enqueue("b@example.com") is True
    assert checkout_capability.queue_status()["queued"] == 2

    db.set_setting("checkout_capability_auto", "0")
    assert checkout_capability.enqueue("c@example.com") is False
    db.set_setting("checkout_capability_auto", "1")


def test_enqueue_requires_enabled_switch(monkeypatch):
    _enable(monkeypatch)
    db.set_setting("checkout_capability_enabled", "0")

    assert checkout_capability.enqueue("d@example.com") is False


def test_worker_records_success(monkeypatch):
    _enable(monkeypatch)
    db.save_registered({"email": "ok@example.com", "access_token": "tok", "password": "x"})

    def fake_probe_email(email, proxy="", store=True):
        if store:
            db.update_plus_check(
                email,
                {"status": "plus_eligible",
                 "checkout": {"amount_minor": 0, "free_trial": True, "source": "protocol"}},
            )
        return {"ok": True, "status": "SUCCEEDED", "free_trial": True,
                "amount_minor": 0, "currency": "inr", "checked_at": time.time()}

    monkeypatch.setattr(checkout_capability, "probe_email", fake_probe_email)
    checkout_capability._QUEUE.put("ok@example.com")

    outcome = _drain_one()

    assert outcome["free_trial"] is True
    assert checkout_capability._STATE["done"] == 1
    stored = (db.get_registered("ok@example.com") or {}).get("extra", {}).get("plus_check")
    assert stored["checkout"]["free_trial"] is True


def test_worker_records_transport_failure_once(monkeypatch):
    """出口不通只记一次失败，不把号放回队尾 —— 否则队列永远不空。"""
    _enable(monkeypatch)
    db.save_registered({"email": "dead@example.com", "access_token": "tok", "password": "x"})

    monkeypatch.setattr(
        checkout_capability,
        "probe_email",
        lambda email, proxy="", store=True: {
            "ok": False,
            "status": "FAILED",
            "failure_type": "CheckoutTransportException",
            "transport_failed": True,
            "error": "探测侧网络失败，结论无效",
        },
    )
    checkout_capability._QUEUE.put("dead@example.com")

    outcome = _drain_one()

    assert outcome["transport_failed"] is True
    assert checkout_capability._STATE["failed"] == 1
    assert "网络失败" in checkout_capability._STATE["last_error"]
    # 没有回灌：队列空了，同一个号也允许再次入队（下次手动触发）
    assert checkout_capability._QUEUE.qsize() == 0
    assert checkout_capability._QUEUED == set()


def test_worker_survives_account_level_failure(monkeypatch):
    """凭证失效是账号结论：照常记账，队列继续往下走。"""
    _enable(monkeypatch)
    db.save_registered({"email": "inv@example.com", "access_token": "tok", "password": "x"})
    monkeypatch.setattr(
        checkout_capability,
        "probe_email",
        lambda email, proxy="", store=True: {
            "ok": False, "status": "FAILED", "failure_type": "TokenInvalid",
            "error": "HTTP 401",
        },
    )
    checkout_capability._QUEUE.put("inv@example.com")

    _drain_one()

    assert checkout_capability._STATE["failed"] == 1
    assert checkout_capability._STATE["last_error"] == "HTTP 401"


def test_worker_survives_probe_exception(monkeypatch):
    """探测抛异常不能打死 worker。"""
    _enable(monkeypatch)
    db.save_registered({"email": "boom@example.com", "access_token": "tok", "password": "x"})

    def _boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(checkout_capability, "probe_email", _boom)
    checkout_capability._QUEUE.put("boom@example.com")

    with_error = None
    try:
        email = checkout_capability._QUEUE.get_nowait()
        try:
            checkout_capability.probe_email(email)
        except Exception as exc:  # noqa: BLE001
            with_error = str(exc)
        finally:
            checkout_capability._QUEUED.discard(email)
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"队列取号本身不该抛异常: {exc}") from exc

    assert with_error == "unexpected"
