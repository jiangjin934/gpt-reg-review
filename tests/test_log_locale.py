"""日志中文化：阶段名与状态词必须翻译，且不能丢信息。

主人要求「日志用中文显示每一个步骤」。这两张映射表是受控词汇
（ProbeSession.mark 的实参都是代码里的常量），所以可以稳定翻译；
**存储值必须仍是英文键** —— 前端与测试按 event["stage"] 判断，只改显示层。
"""
from __future__ import annotations

import logging

from webui import probes


def test_known_stage_and_status_are_translated():
    assert probes.stage_label("auth.warmup") != "auth.warmup"
    assert probes.status_label("ok") == "完成"
    assert probes.status_label("failed") == "失败"


def test_unknown_stage_passes_through():
    """没收录的阶段原样输出 —— 新加阶段立刻可见，不用同步改表。"""
    assert probes.stage_label("brand.new.stage") == "brand.new.stage"


def test_probe_log_line_is_chinese(caplog):
    session = probes.ProbeSession("run-zh")

    with caplog.at_level(logging.INFO, logger="webui.probes"):
        session.mark("auth.warmup", "ok", duration_ms=1234)

    line = " ".join(
        rec.getMessage() for rec in caplog.records if "探针" in rec.getMessage()
    )
    assert "预热" in line
    assert "完成" in line
    assert "1234毫秒" in line
    # 面向主人的日志里不该再出现英文键
    assert "auth.warmup" not in line
    assert "duration_ms" not in line


def test_probe_log_reports_error_in_chinese(caplog):
    session = probes.ProbeSession("run-err")

    with caplog.at_level(logging.INFO, logger="webui.probes"):
        session.mark("auth.signup", "failed", error="boom")

    line = " ".join(
        rec.getMessage() for rec in caplog.records if "探针" in rec.getMessage()
    )
    assert "失败" in line
    assert "错误=" in line


def test_operation_probe_log_is_chinese(caplog):
    with caplog.at_level(logging.INFO, logger="webui.probes"):
        probes.record_operation_probe("checkout_capability", "ok")

    line = " ".join(
        rec.getMessage() for rec in caplog.records if "探针" in rec.getMessage()
    )
    assert "操作=checkout_capability" in line
    assert "完成" in line


def test_stored_stage_key_stays_english():
    """存储层不能跟着改：DB/前端/测试都按英文键索引。"""
    session = probes.ProbeSession("")
    event = session.mark("auth.warmup", "ok")

    assert event["stage"] == "auth.warmup"
    assert event["status"] == "ok"


def test_missing_duration_does_not_render_unit(caplog):
    """没有耗时的时候别渲染成「-毫秒」。"""
    session = probes.ProbeSession("run-nodur")

    with caplog.at_level(logging.INFO, logger="webui.probes"):
        session.mark("auth.csrf", "started")

    line = " ".join(
        rec.getMessage() for rec in caplog.records if "探针" in rec.getMessage()
    )
    assert "-毫秒" not in line
