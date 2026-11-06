"""group_cpu: aggregation math, group keys, work rates and the tool."""

from __future__ import annotations

from typing import Any

import pytest

from heapspy_mcp.system import groups as grp


def test_percentiles_and_describe() -> None:
    xs = [1.0, 2.0, 3.0, 4.0, 10.0]
    assert grp.percentile(xs, 0.5) == 3.0
    assert grp.percentile(xs, 0.9) == pytest.approx(7.6)
    d = grp.describe([4.0, None, 1.0, 10.0, 2.0, 3.0], "sum")
    assert d["members_with_value"] == 5
    assert d["sum"] == 20.0 and d["mean"] == 4.0 and d["p50"] == 3.0
    assert d["min"] == 1.0 and d["max"] == 10.0 and d["spread"] == 9.0
    assert d["max_to_min_ratio"] == 10.0
    assert d["cv"] == pytest.approx(3.162 / 4, rel=0.01)
    assert grp.describe([0.5], "pooled")["sum"] is None
    assert grp.describe([None], "sum")["mean"] is None


def test_pooled_ratios_weigh_by_counts() -> None:
    raws = [
        dict(
            run_ns=100e6,
            wait_ns=50e6,
            slices=1000,
            vol=0,
            nonvol=1000,
            cpu_s=0.1,
            runnable_samples=10,
            thread_samples=10,
        ),
        dict(
            run_ns=900e6,
            wait_ns=50e6,
            slices=500,
            vol=500,
            nonvol=0,
            cpu_s=0.9,
            runnable_samples=2,
            thread_samples=10,
        ),
    ]
    p = grp.pooled(raws)
    assert p["avg_timeslice_us"] == pytest.approx(1e9 / 1500 / 1000, rel=0.001)
    assert p["runqueue_wait_ratio"] == pytest.approx(0.1)
    assert p["voluntary_share"] == pytest.approx(1 / 3, rel=0.01)
    assert p["runnable_share"] == pytest.approx(0.6)
    assert p["switches_per_cpu_second"] == pytest.approx(1500.0)


def static(**kw: Any) -> Any:
    from heapspy_mcp.system.search import Static

    base = dict(
        pid=1,
        comm="svc-worker",
        ppid=9,
        state="S",
        uid=0,
        exe="/opt/svc-worker",
        cmdline=None,
        cgroup_path="/system.slice/api.service",
        kernel_thread=False,
        starttime_ticks=0,
    )
    return Static(**{**base, **kw})


def test_group_keys() -> None:
    api = static(cmdline=["/opt/svc-worker", "1572864", "6500", "--token=abc", "/run/api-3"])
    assert grp.parse_group_by("cmdline_arg:1", None)(api) == "1572864"
    assert grp.parse_group_by("cmdline_arg:3", None)(api) == "--token=<redacted>"
    assert grp.parse_group_by("cmdline_arg:9", None)(api) == "(missing)"
    rx = grp.parse_group_by("cmdline_regex", r"/(api|edge)-\d+$")
    assert rx(api) == "api"
    assert rx(static(cmdline=["x"])) == "(no match)"
    assert grp.parse_group_by("parent", None)(api) == "9"
    assert grp.parse_group_by("cgroup", None)(api) == "/system.slice/api.service"
    assert grp.parse_group_by("none", None)(api) == "all"
    for bad in ("cmdline_arg:x", "nope"):
        with pytest.raises(grp.GroupError):
            grp.parse_group_by(bad, None)
    with pytest.raises(grp.GroupError):
        grp.parse_group_by("cmdline_regex", None)
    with pytest.raises(grp.GroupError):
        grp.parse_group_by("cmdline_regex", "(")


def test_work_block() -> None:
    agg = {
        "on_cpu_seconds_per_s": {"sum": 1.6},
        "cpu_cores_used": {"sum": 1.5},
        "timeslices_per_s": {"sum": 8000.0},
    }
    w = grp.work_block(agg, 40000.0)
    assert w["cpu_seconds_per_unit_work"] == pytest.approx(4e-5)
    assert w["timeslices_per_unit_work"] == pytest.approx(0.2)
    assert w["units_of_work_per_timeslice"] == pytest.approx(5.0)
    assert grp.work_block(agg, None) is None
