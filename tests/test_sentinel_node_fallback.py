"""Sentinel 找 node 的顺序：环境变量（存在才认） → PATH → 项目自带的 node。

2026-09-29 事故：服务被直接 `python start_webui.py` 起来（没走 run_webui.ps1），
环境变量没设、PATH 上也没有 node，整批 43 个任务全挂在 Sentinel 上。
现在没环境变量也必须能找到随项目附带的 node。

另一条同样重要的语义：**环境变量里指向一个不存在的文件时不能照用**。新机器部署包里
的 run_webui.ps1 曾把固定的 C:\\Users\\Administrator\\...\\node.exe 塞进这个变量，
文件不存在就会让每个号都卡在 Sentinel 上（报错还看不出真因）。所以这里先验存在性。
"""
from pathlib import Path

import pytest

from sentinel_quickjs import _resolve_node_binary


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("OPENAI_SENTINEL_NODE_PATH", raising=False)
    monkeypatch.setattr("shutil.which", lambda _name: None)


def test_env_var_wins_when_file_exists(tmp_path, monkeypatch):
    custom = tmp_path / "node.exe"
    custom.write_text("stub")
    monkeypatch.setenv("OPENAI_SENTINEL_NODE_PATH", str(custom))
    monkeypatch.setattr("shutil.which", lambda _name: r"C:\path\node.exe")

    assert _resolve_node_binary() == str(custom)


def test_dead_env_var_falls_back_to_path(tmp_path, monkeypatch, caplog):
    """环境变量指向不存在的文件 → 不能照用，回退到 PATH / 自带 node。"""
    monkeypatch.setenv("OPENAI_SENTINEL_NODE_PATH", r"C:\Users\Administrator\node.exe")
    monkeypatch.setattr("shutil.which", lambda _name: r"C:\path\node.exe")

    assert _resolve_node_binary() == r"C:\path\node.exe"


def test_path_node_is_used_when_env_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: r"C:\path\node.exe" if "node" in name else None)

    assert _resolve_node_binary() == r"C:\path\node.exe"


def test_project_bundled_node_is_used_as_last_resort(tmp_path, monkeypatch):
    bundled = tmp_path / "node.exe"
    bundled.write_text("stub")
    monkeypatch.setattr("sentinel_quickjs._node_candidates", lambda: [bundled])

    assert _resolve_node_binary() == str(bundled)


def test_missing_candidates_fall_back_to_bare_name(monkeypatch, tmp_path):
    monkeypatch.setattr("sentinel_quickjs._node_candidates", lambda: [tmp_path / "nope.exe"])

    assert _resolve_node_binary() == "node"


def test_candidates_prefer_project_paths_over_path_lookup():
    """候选里既要有 Playwright 自带的 node，也要有 launcher 的兜底路径。"""
    from sentinel_quickjs import _node_candidates

    rendered = [str(p).replace("\\", "/") for p in _node_candidates()]
    assert any("playwright" in p for p in rendered)
    assert any("codex-runtimes" in p for p in rendered)
