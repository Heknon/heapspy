"""cpu_colocation: per-CPU totals, placement and the wakeup-preemption inference on a fake /proc."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from heapspy_mcp.system import colocation as co
from heapspy_mcp.system import diagnose as dg
from tests.test_contention_parsers import stat_line


class FakeProc:
    def __init__(self, root: Path) -> None:
        self.root = root

    def task(
        self,
        pid: int,
        tid: int,
        *,
        comm: str,
        state: str,
        cpu: int,
        run_ns: int,
        wait_ns: int,
        slices: int,
        vol: int,
        nonvol: int,
        allowed: str = "0-1",
        slice_ns: int | None = 2100000,
    ) -> None:
        d = self.root / str(pid) / "task" / str(tid)
        d.mkdir(parents=True, exist_ok=True)
        (d / "stat").write_text(stat_line(tid, comm, state, cpu))
        (d / "schedstat").write_text(f"{run_ns} {wait_ns} {slices}\n")
        (d / "status").write_text(
            f"Name:\t{comm}\nState:\t{state}\nCpus_allowed_list:\t{allowed}\n"
            f"voluntary_ctxt_switches:\t{vol}\nnonvoluntary_ctxt_switches:\t{nonvol}\n"
        )
        (d / "sched").write_text(f"se.slice : {slice_ns}\n" if slice_ns else "policy : 0\n")


def colocation_scenario(tmp_path: Path) -> dict[str, Any]:
    """Two CPUs. Targets 100 (cpu0), 101 and 102 (cpu1). A short sleeper 200 on cpu1 wakes
    5000 times a second; a long sleeper 300 on cpu0 wakes twice a second."""
    fp = FakeProc(tmp_path)
    start = {
        100: dict(comm="api", state="R", cpu=0, run_ns=0, wait_ns=0, slices=0, vol=0, nonvol=0),
        101: dict(comm="api", state="R", cpu=1, run_ns=0, wait_ns=0, slices=0, vol=0, nonvol=0),
        102: dict(comm="api", state="R", cpu=1, run_ns=0, wait_ns=0, slices=0, vol=0, nonvol=0),
        200: dict(comm="edge", state="S", cpu=1, run_ns=0, wait_ns=0, slices=0, vol=0, nonvol=0),
        300: dict(comm="kw", state="S", cpu=0, run_ns=0, wait_ns=0, slices=0, vol=0, nonvol=0),
    }
    for pid, kw in start.items():
        fp.task(pid, pid, **kw)
    s = co.CoSampler(tmp_path, {(100, 100), (101, 101), (102, 102)})
    s.start()
    assert set(s.tracks) == {(100, 100), (101, 101), (102, 102)}  # 200 and 300 sleep
    end = {
        100: dict(run_ns=800_000_000, wait_ns=100_000_000, slices=500, vol=0, nonvol=100),
        101: dict(run_ns=300_000_000, wait_ns=600_000_000, slices=4100, vol=0, nonvol=4000),
        102: dict(run_ns=330_000_000, wait_ns=600_000_000, slices=3600, vol=0, nonvol=3500),
        200: dict(run_ns=100_000_000, wait_ns=50_000_000, slices=5050, vol=5000, nonvol=50),
        300: dict(run_ns=1_000_000, wait_ns=0, slices=2, vol=2, nonvol=0),
    }
    for pid, kw in end.items():
        fp.task(pid, pid, **{**start[pid], **kw})
    s.rescan()  # 200 and 300 ran since the start: tracked from here on
    assert {(200, 200), (300, 300)} <= set(s.tracks)
    for k in range(10):
        # 200 is runnable on cpu1 in 3 of 10 samples; 300 never runnable.
        fp.task(200, 200, **{**start[200], **end[200], "state": "R" if k < 3 else "S"})
        s.tick()
    s.finish()
    s.t1 = s.t0 + 1.0
    return co.build_view(s, rate_hz=10.0, rate_note=None, describe=lambda pid: {"svc": pid})


def test_colocation_per_cpu_and_attribution(tmp_path: Path) -> None:
    v = colocation_scenario(tmp_path)
    cpus = {c["cpu"]: c for c in v["cpus"]}
    assert set(cpus) == {0, 1}
    c1, c0 = cpus[1], cpus[0]
    assert c1["target_tasks_here"] == 2 and c0["target_tasks_here"] == 1
    assert c1["colocated_wakeups_per_s"] == pytest.approx(5000, rel=0.01)
    assert c1["colocated_short_sleeper_wakeup_share"] == 1.0
    assert c0["colocated_wakeups_per_s"] == pytest.approx(2, rel=0.01)
    assert c0["colocated_short_sleeper_wakeup_share"] == 0.0
    assert c1["target_nonvoluntary_switches_per_s"] == pytest.approx(7500, rel=0.01)
    assert c1["target_preemptions_per_colocated_wakeup"] == pytest.approx(1.5, rel=0.01)
    # mean runnable: two targets in every sample plus 200 in 3 of 10
    assert c1["mean_runnable_tasks"] == pytest.approx(2.3)
    edge = c1["colocated_tasks"][0]
    assert edge["pid"] == 200 and edge["short_sleeper"] is True
    assert edge["avg_sleep_us"] == pytest.approx((1 - 0.15) / 5000 * 1e6, rel=0.01)
    assert edge["avg_timeslice_us"] == pytest.approx(0.1 / 5050 * 1e6, rel=0.01)
    assert edge["svc"] == 200  # describe() fields are merged in

    t101 = next(t for t in v["target_tasks"] if t["pid"] == 101)
    assert t101["avg_timeslice_us"] == pytest.approx(300e3 / 4100, rel=0.01)
    assert t101["avg_timeslice_source"].startswith("on-CPU time / schedstat timeslices")
    assert t101["sched_slice_us"] == 2100.0

    att = v["wakeup_preemption_attribution"]
    assert att["basis"].startswith("inference")
    assert att["correlation_target_nonvoluntary_vs_colocated_wakeups"] > 0.9
    assert att["top_short_sleepers_on_target_cpus"][0]["pid"] == 200
    assert att["colocated_short_sleeper_wakeup_share_on_target_cpus"] == pytest.approx(
        5000 / 5002, rel=0.001
    )

    pl = v["placement"]
    assert pl["target_tasks_by_cpu"] == {0: 1, 1: 2}
    assert pl["other_busy_tasks_by_cpu"] == {0: 1, 1: 1}
    assert pl["runnable_max_minus_min"] == pytest.approx(1.3)
    assert v["targets"]["avg_timeslice_us_pooled"] == pytest.approx(1430e3 / 8200, rel=0.01)


def test_colocation_timeslice_fallback_without_pcount(tmp_path: Path) -> None:
    tr = co.Track(
        co.TaskCounters(0.0, 1, 1, "x", "R", 0, 0, 0, 0, 0, 0, 0),
        co.TaskCounters(1.0, 1, 1, "x", "R", 0, 0, 500_000_000, 0, 0, 400, 100),
    )
    rates = co.task_rates(tr, 1.0)
    assert rates is not None
    assert rates["avg_timeslice_us"] == pytest.approx(1000.0)
    assert "voluntary + non-voluntary" in rates["avg_timeslice_source"]


def test_colocation_rate_budget() -> None:
    rate, note = co.effective_rate(50, 100, 10)
    assert rate == 50 and note is None
    rate, note = co.effective_rate(500, 100, 10)
    assert rate == 100 and "max-stall-rate" in note
    rate, note = co.effective_rate(50, 100, 1000)
    assert rate == pytest.approx(20) and "task samples per second" in note


def test_colocation_signals_from_a_view(tmp_path: Path) -> None:
    v = colocation_scenario(tmp_path)
    s: dict[str, Any] = {}
    reasons: dict[str, str] = {}
    dg._colocation_signals(s, reasons, v, None)
    assert s["colocated_wakeups_per_s"] == pytest.approx(5002, rel=0.01)
    assert s["colocated_short_sleeper_wakeup_share"] > 0.99
    dg._colocation_signals(s, reasons, None, "gone")
    assert s["colocated_wakeups_per_s"] is None and reasons["colocated_wakeups_per_s"] == "gone"
