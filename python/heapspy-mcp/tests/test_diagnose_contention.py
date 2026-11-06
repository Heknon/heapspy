"""diagnose: a runnable thread that gets no CPU is starved, not idle; short timeslices
from co-located wakeups."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from heapspy_mcp.system import diagnose as dg

FIX = Path(__file__).resolve().parent / "fixtures" / "contention"


def blind_test_signals() -> dict[str, Any]:
    data = json.loads((FIX / "diag_api_2c_signals.json").read_text())
    return data["signals"]


def test_starved_worker_is_not_read_as_idle() -> None:
    # Regression: the blind test's api worker at 2 cores (runnable in every sample,
    # runqueue_wait_ratio 5.6, cpu_cores_used 0.151) had spin/compute marked
    # not_indicated because 0.151 cores is under the "mostly idle" threshold.
    s = blind_test_signals()
    res = {h["id"]: h for h in dg.evaluate(s, {})}
    spin = res["spin_waiting_or_compute"]
    assert spin["assessment"] != "not_indicated"
    assert not any(e["signal"] == "cpu_cores_used" for e in spin["evidence_against"])
    demand = next(e for e in spin["evidence_for"] if e["signal"] == "cpu_demand_cores")
    assert demand["value"] == pytest.approx(0.151 + 5.588 * 0.151, abs=0.01)
    assert "waited for a CPU" in demand["note"]
    rq = res["runqueue_contention"]
    assert any(e["signal"] == "runnable_share" for e in rq["evidence_for"])
    # Preemption-driven switches no longer count as the thread blocking on its own.
    assert not any(e["signal"] == "switches_per_cpu_second" for e in spin["evidence_against"])


def test_idle_thread_is_still_idle() -> None:
    s = {
        **blind_test_signals(),
        "runqueue_wait_ratio": 0.01,
        "mean_runnable_threads": 0.05,
        "voluntary_share": 0.95,
        "cpu_cores_used": 0.02,
    }
    spin = next(h for h in dg.evaluate(s, {}) if h["id"] == "spin_waiting_or_compute")
    assert any(e["signal"] == "cpu_cores_used" for e in spin["evidence_against"])
    assert spin["assessment"] == "not_indicated"


def with_colocation(**over: Any) -> dict[str, Any]:
    return {
        **blind_test_signals(),
        "avg_timeslice_us": 140.0,
        "sched_slice_us": 2100.0,
        "sched_slice_source": "se.slice",
        "avg_timeslice_to_sched_slice_ratio": round(140 / 2100, 3),
        "colocated_wakeups_per_s": 9975.0,
        "colocated_short_sleeper_wakeup_share": 0.999,
        **over,
    }


def test_short_timeslices_with_colocated_wakeups() -> None:
    res = {h["id"]: h for h in dg.evaluate(with_colocation(), {})}
    h = res["short_timeslices"]
    assert h["assessment"] == "consistent_with_measurements"
    signals = {e["signal"] for e in h["evidence_for"]}
    assert {
        "avg_timeslice_to_sched_slice_ratio",
        "voluntary_share",
        "colocated_wakeups_per_s",
        "colocated_short_sleeper_wakeup_share",
    } <= signals
    text = " ".join(h["next_measurements"])
    assert "cpuset" in text and "fit_per_slice_cost" in text
    assert "short_timeslices" in dg.FOCUS["cpu"]


def test_short_slices_from_own_blocking_are_not_preemption() -> None:
    # An edge-like worker: short slices because it sleeps after each request.
    s = with_colocation(
        voluntary_share=0.97,
        voluntary_switches_per_s=5000.0,
        nonvoluntary_switches_per_s=150.0,
        avg_timeslice_to_sched_slice_ratio=0.014,
        colocated_wakeups_per_s=300.0,
        colocated_short_sleeper_wakeup_share=0.1,
    )
    h = next(x for x in dg.evaluate(s, {}) if x["id"] == "short_timeslices")
    assert any(e["signal"] == "voluntary_share" for e in h["evidence_against"])
    assert h["assessment"] != "consistent_with_measurements"


def test_short_timeslices_unknown_without_colocation() -> None:
    s = {**blind_test_signals(), "avg_timeslice_to_sched_slice_ratio": None}
    h = next(
        x
        for x in dg.evaluate(s, {"colocated_wakeups_per_s": "not run"})
        if x["id"] == "short_timeslices"
    )
    assert {u["signal"] for u in h["unknown"]} == {
        "avg_timeslice_to_sched_slice_ratio",
        "colocated_wakeups_per_s",
    }


def test_new_thresholds_have_meanings() -> None:
    for name in (
        "runnable_share_starved",
        "cpu_demand_cores_busy",
        "timeslice_ratio_short",
        "colocated_wakeups_per_s_high",
        "short_sleeper_wakeup_share_high",
    ):
        assert dg.THRESHOLDS[name][2]
