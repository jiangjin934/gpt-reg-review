"""人类节奏停顿：分布形状 + 开关 + 上界。

分布形状这次被改过（均匀 → 右偏长尾），而这个东西一旦退回去是看不出来的
（链路照样跑，只是又变成机器节奏），所以这里把形状固定住。
"""
from __future__ import annotations

import random

import pytest

import auth_flow


def _flow(humanize: str = "1") -> auth_flow.AuthFlow:
    """用 __new__ 构造，避开 __init__ 的网络/会话初始化 —— 这里只测时序。"""
    flow = auth_flow.AuthFlow.__new__(auth_flow.AuthFlow)
    flow._env_overrides = {"WEBUI_HUMANIZE": humanize}
    return flow


@pytest.fixture(autouse=True)
def _restore_random():
    state = random.getstate()
    yield
    random.setstate(state)


@pytest.fixture
def captured(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(auth_flow.time, "sleep", lambda v: slept.append(v))
    return slept


def test_disabled_by_default_does_not_sleep(captured):
    flow = _flow("0")
    flow._human_pause(0.2, 1.0)

    assert captured == []


def test_actually_sleeps_when_enabled(captured):
    flow = _flow("1")
    flow._human_pause(0.2, 1.0)

    assert len(captured) == 1
    assert 0.2 <= captured[0] <= 3.0


def test_distribution_is_right_skewed(captured):
    """真人操作间隔右偏：多数是短间隔，而不是在区间里均匀铺开。

    uniform 下"落在下半段"的比例约为 50%；三段混合后应显著更高（≈80%）。
    """
    random.seed(20260929)
    flow = _flow()
    lo, hi = 0.2, 1.0
    for _ in range(400):
        flow._human_pause(lo, hi)

    mid = lo + (hi - lo) * 0.5
    lower_half = [v for v in captured if v <= mid]

    assert len(captured) == 400
    assert len(lower_half) / len(captured) > 0.70


def test_long_tail_exists(captured):
    """要有超过 hi 的长尾样本 —— 那是"想了一下才继续"的那部分。"""
    random.seed(20260929)
    flow = _flow()
    for _ in range(400):
        flow._human_pause(0.2, 1.0)

    assert any(v > 1.0 for v in captured), "长尾样本缺失，分布退化成均匀/截断"


def test_bounded_by_three_times_hi(captured):
    """长尾提供形状，但不能让链路莫名睡很久。"""
    random.seed(7)
    flow = _flow()
    for _ in range(500):
        flow._human_pause(0.2, 1.0)

    assert max(captured) <= 3.0 + 1e-9


def test_values_are_non_negative(captured):
    random.seed(11)
    flow = _flow()
    for _ in range(200):
        flow._human_pause(0.2, 1.0)

    assert min(captured) >= 0.0


def test_zero_span_does_not_crash(captured):
    """lo == hi（固定停顿）不能因为 span=0 算出越界值。"""
    random.seed(3)
    flow = _flow()
    for _ in range(50):
        flow._human_pause(0.5, 0.5)

    assert len(captured) == 50
    assert all(0.0 <= v <= 1.5 for v in captured)


def test_never_raises_even_if_sleep_breaks(monkeypatch):
    """停顿是装饰性的：sleep 出问题也绝不能中断注册链路。"""
    def _boom(_v):
        raise OSError("sleep interrupted")

    monkeypatch.setattr(auth_flow.time, "sleep", _boom)
    flow = _flow("1")

    flow._human_pause(0.2, 1.0)   # 不抛异常即通过


# ── 覆盖：链路最前面那四个请求之间必须都有停顿 ──


@pytest.mark.parametrize(
    "method, args",
    [
        ("get_csrf_token", ()),
        ("get_auth_url", ("csrf", "a@b.com")),
        ("auth_oauth_init", ("https://auth.openai.com/authorize?x=1",)),
        ("get_sentinel_token", ("device-id",)),
    ],
)
def test_densely_packed_steps_now_pause(monkeypatch, method, args):
    """[csrf → auth_url → oauth_init → sentinel] 以前是零间隔连发，这四步都要有停顿。

    只验证"该方法在真正发请求前调了 _human_pause"，不触发任何真实请求：
    把后续会用到的东西全部短路。
    """
    calls: list[tuple] = []

    flow = _flow("1")
    monkeypatch.setattr(
        flow, "_human_pause",
        lambda lo=0.0, hi=0.0: calls.append((lo, hi)),
    )
    # 让方法在停顿之后尽快失败退出（我们只关心停顿发生在最前面）
    monkeypatch.setattr(flow, "_common_headers", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stop")))
    monkeypatch.setattr(flow, "_navigation_headers", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stop")))

    with pytest.raises(Exception):
        getattr(flow, method)(*args)

    assert calls, f"{method} 在最前面没有调用 _human_pause"
