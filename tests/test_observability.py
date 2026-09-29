"""可观测性：僵尸运行记录清理 + 环境分配失败原因归类。

这两个都是「让主人看得懂」的改动 —— 它们不改变任务成败，但决定主人能不能
判断出到底卡在哪。所以行为要固定住，别哪天又被简化回一句笼统的报错。
"""
from __future__ import annotations

from webui import db, environment


# ──────────────────────── 僵尸运行记录 ────────────────────────


def _run_ids() -> dict[str, str]:
    return {r["run_id"]: r["status"] for r in db.list_runs(limit=50)}


def test_interrupt_marks_only_running_runs():
    db.create_run("run-alive", "a@example.com", "/tmp/a.log")
    db.create_run("run-done", "b@example.com", "/tmp/b.log")
    db.finish_run("run-done", "done")

    changed = db.interrupt_running_runs()

    assert changed == 1
    statuses = _run_ids()
    assert statuses["run-alive"] == "interrupted"
    # 已经收尾的记录不能被改写
    assert statuses["run-done"] == "done"


def test_interrupt_is_idempotent():
    db.create_run("run-x", "a@example.com", "/tmp/x.log")

    assert db.interrupt_running_runs() == 1
    assert db.interrupt_running_runs() == 0


def test_interrupt_records_reason_and_category():
    db.create_run("run-y", "a@example.com", "/tmp/y.log")

    db.interrupt_running_runs(reason="进程重启")

    row = next(r for r in db.list_runs(limit=10) if r["run_id"] == "run-y")
    assert row["status"] == "interrupted"
    assert "进程重启" in (row.get("error") or "")
    assert row.get("error_category") == "interrupted"
    # 有结束时间，界面上才能算耗时
    assert row.get("finished_at")


def test_release_stale_in_use_with_zero_releases_everything():
    """启动清理用 stale_seconds=0：进程刚起，in_use 必然是上次遗留的。"""
    db.import_accounts("a@example.com----https://relay.example/x", kind="icloud_relay")
    db.claim_next(kind="icloud_relay")
    assert db.stats()["in_use"] == 1

    released = db.release_stale_in_use(stale_seconds=0)

    assert released == 1
    assert db.stats()["available"] == 1
    assert db.stats()["in_use"] == 0


# ──────────────────────── 失败原因归类 ────────────────────────


def test_summary_ranks_top_cause_and_gives_action():
    failures = (
        ["出口 IP 已在历史台账中: 181.115.172.87"] * 5
        + ["出口探测失败 (81e18c54): Failed to perform"]
    )

    msg = environment._summarize_allocation_failures(failures)

    assert "共 6 次尝试" in msg
    assert "已在历史台账中" in msg and "×5" in msg
    assert "出口探测失败" in msg
    # 主因要带动作，否则主人还是不知道该改什么
    assert "扩大代理池" in msg
    assert msg.index("已在历史台账中") < msg.index("出口探测失败")


def test_summary_keeps_existing_terminology():
    """归类名必须沿用它匹配到的原始措辞 —— 项目里别处按这些字样判断失败类型。

    2026-09-29 踩过：把「版本自洽」改写成「版本自相矛盾」，直接让
    test_protocol_realism 里那条按"版本自洽"做的断言失败。
    """
    msg = environment._summarize_allocation_failures(
        ["画像版本自洽校验未通过: UA Firefox/999 与 impersonate firefox135 版本不一致"]
    )

    assert "版本自洽" in msg


def test_summary_handles_empty_failures():
    msg = environment._summarize_allocation_failures([])

    assert "代理池为空" in msg


def test_summary_falls_back_to_sample_for_unknown_reasons():
    msg = environment._summarize_allocation_failures(["某种没归类过的原因 A", "原因 B"])

    assert "共 2 次尝试" in msg
    assert "原因 B" in msg


def test_summary_does_not_crash_on_non_string_entries():
    """failures 里混进异常对象也不能让报错构造本身炸掉。"""
    msg = environment._summarize_allocation_failures([RuntimeError("boom"), "出口探测失败 x"])

    assert "共 2 次尝试" in msg


def test_summary_output_is_bounded():
    """报错会被写进 runs.error（截断 500 字符），别自己先撑爆。"""
    failures = [f"出口 IP 已在历史台账中: 10.0.0.{i}" for i in range(200)]

    msg = environment._summarize_allocation_failures(failures)

    assert len(msg) <= 500
