"""预检阶段出口漂移自愈：改绑到稳定观察到的新出口继续跑，而不是整单作废。

背景（2026-09-29 实测）：20 并发刚启动那一波，有 3 个任务在预检时就发现
「分配时探测到的出口 A」和「任务建连后连续两次拿到的出口 B」不一样 ——
厂商把粘性会话重分配了（B 两次一致，说明那同样是一条稳定路径）。
那时任务还没向 OpenAI 发出任何请求，改绑比整单作废划算。
"""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import auth_flow
from fingerprint import generate_fingerprint
from webui import db

EXPECTED_IP = "203.0.113.20"
NEW_IP = "203.0.113.99"
OTHER_IP = "203.0.113.77"


def _trace(ip, loc="JP", status=200):
    return SimpleNamespace(status_code=status, text=f"ip={ip}\nloc={loc}\n")


def _flow(*, rebind, responses, profile_country="JP"):
    observations = []
    flow = auth_flow.AuthFlow.__new__(auth_flow.AuthFlow)
    flow._fingerprint = generate_fingerprint(country_code=profile_country, browser_type="firefox")
    flow._country_code = profile_country
    flow._environment = {
        "exit_ip": EXPECTED_IP,
        "exit_country": profile_country,
        "country_code": profile_country,
        "country_source": "manual",
    }
    flow._environment_observer = observations.append
    flow._environment_rebind = rebind
    flow.result = auth_flow.AuthResult()
    flow.session = SimpleNamespace(get=Mock(side_effect=responses))
    flow._network_preflight_error = ""
    return flow, observations


def test_stable_new_exit_is_rebound_and_task_continues():
    calls = []

    def rebind(old_ip, new_ip, country):
        calls.append((old_ip, new_ip, country))
        return True

    flow, observations = _flow(rebind=rebind, responses=[_trace(NEW_IP), _trace(NEW_IP)])

    assert flow.check_proxy() is True

    assert calls == [(EXPECTED_IP, NEW_IP, "JP")]
    assert flow._environment["exit_ip"] == NEW_IP
    assert flow._network_preflight_error == ""
    # 时间线里既能看到那次漂移（未通过），也能看到改绑后校验通过，
    # 不会留下一条 all_passed=False 却继续跑的矛盾记录。
    assert [item["all_passed"] for item in observations] == [False, True]
    assert observations[-1]["stage"] == "preflight.exit_rebind"
    assert observations[-1]["rebound_from"] == EXPECTED_IP
    assert observations[-1]["network"]["checks"]["exit_ip_matches"] is True


def test_refused_rebind_keeps_previous_abort_behaviour():
    flow, _observations = _flow(
        rebind=lambda *_args: False, responses=[_trace(NEW_IP), _trace(NEW_IP)]
    )

    assert flow.check_proxy() is False

    assert EXPECTED_IP in flow._network_preflight_error
    assert NEW_IP in flow._network_preflight_error
    assert flow._environment["exit_ip"] == EXPECTED_IP


def test_country_change_is_never_rebound():
    """出口国家变了就一眼假（画像时区/语言按国家生成），宁可换一轮任务。"""
    calls = []
    flow, _observations = _flow(
        rebind=lambda *_args: calls.append(_args) or True,
        responses=[_trace(NEW_IP, loc="BR"), _trace(NEW_IP, loc="BR")],
    )

    assert flow.check_proxy() is False
    assert calls == []
    assert flow._environment["exit_ip"] == EXPECTED_IP


def test_exit_that_keeps_changing_is_not_rebound():
    """两次探测各是一个不同的新 IP = 链路真的在变，不做改绑。"""
    calls = []
    flow, _observations = _flow(
        rebind=lambda *_args: calls.append(_args) or True,
        responses=[_trace(NEW_IP), _trace(OTHER_IP)],
    )

    assert flow.check_proxy() is False
    assert calls == []


def test_without_rebind_hook_drift_still_aborts():
    """CLI 单独跑（没有持久层）时不接线，行为与改动前一致。"""
    flow, _observations = _flow(rebind=None, responses=[_trace(NEW_IP), _trace(NEW_IP)])

    assert flow.check_proxy() is False


def test_rebind_hook_exception_aborts_instead_of_crashing():
    def boom(*_args):
        raise RuntimeError("db is gone")

    flow, _observations = _flow(rebind=boom, responses=[_trace(NEW_IP), _trace(NEW_IP)])

    assert flow.check_proxy() is False
    assert flow._network_preflight_error


# ──────────────────────── 持久层 ────────────────────────


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    path = tmp_path / "webui.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    return path


def _environment_for(run_id: str, exit_ip: str, country: str = "JP") -> dict:
    fingerprint = generate_fingerprint(country_code=country, browser_type="firefox")
    return {
        "allocation_id": f"{run_id}:{fingerprint['fingerprint_id']}",
        "run_id": run_id,
        "proxy": "socks5h://user:pass@proxy.example:3010",
        "proxy_fingerprint": f"proxy-{run_id}",
        "exit_ip": exit_ip,
        "exit_country": country,
        "country_code": country,
        "country_source": "proxy",
        "browser_family": fingerprint["browser_family"],
        "browser_engine": "auto",
        "fingerprint_id": fingerprint["fingerprint_id"],
        "fingerprint_signature": __import__("webui.environment", fromlist=["x"]).fingerprint_signature(
            fingerprint
        ),
        "fingerprint": fingerprint,
    }


def test_rebind_moves_ledger_and_run_row(isolated_db):
    environment = _environment_for("run-a", EXPECTED_IP)
    db.create_run("run-a", "a@example.com", "a.log")
    assert db.reserve_environment("run-a", environment)
    db.update_run_environment("run-a", environment)

    rebound = dict(environment, exit_ip=NEW_IP, exit_country="JP")
    assert db.rebind_environment_exit("run-a", rebound, old_exit_ip=EXPECTED_IP) is True

    assert db.environment_seen(exit_ip=NEW_IP) is True
    assert db.environment_seen(exit_ip=EXPECTED_IP) is False
    assert db.get_run_environment("run-a")["exit_ip"] == NEW_IP
    ledger = {row["run_id"]: row for row in db.list_environment_ledger()}
    assert ledger["run-a"]["exit_ip"] == NEW_IP


def test_rebind_refuses_an_exit_another_task_owns(isolated_db):
    first = _environment_for("run-a", EXPECTED_IP)
    db.create_run("run-a", "a@example.com", "a.log")
    assert db.reserve_environment("run-a", first)
    db.update_run_environment("run-a", first)

    second = _environment_for("run-b", OTHER_IP)
    db.create_run("run-b", "b@example.com", "b.log")
    assert db.reserve_environment("run-b", second)

    stolen = dict(first, exit_ip=OTHER_IP)
    assert db.rebind_environment_exit("run-a", stolen, old_exit_ip=EXPECTED_IP) is False

    ledger = {row["run_id"]: row for row in db.list_environment_ledger()}
    assert ledger["run-a"]["exit_ip"] == EXPECTED_IP
    assert ledger["run-b"]["exit_ip"] == OTHER_IP


def test_rebind_requires_a_matching_ledger_row(isolated_db):
    missing = _environment_for("run-ghost", NEW_IP)
    assert db.rebind_environment_exit("run-ghost", missing, old_exit_ip=EXPECTED_IP) is False
