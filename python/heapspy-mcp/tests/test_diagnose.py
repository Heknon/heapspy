"""Hypothesis scoring on synthetic signals."""

from __future__ import annotations

from typing import Any

import pytest

from heapspy_mcp.system import diagnose as dg

BASE: dict[str, Any] = {
    "cpu_cores_used": 0.5,
    "user_share": 0.8,
    "threads": 4,
    "voluntary_switches_per_s": 100.0,
    "nonvoluntary_switches_per_s": 10.0,
    "voluntary_share": 0.9,
    "switches_per_cpu_second": 220.0,
    "runqueue_wait_ratio": 0.02,
    "mean_runnable_threads": 0.5,
    "futex_wait_share": 0.1,
    "mean_futex_waiting_threads": 0.3,
    "disk_wait_share": 0.0,
    "major_faults_per_s": 0.0,
    "iowait_seconds_per_s": 0.0,
    "procs_running_per_core": 0.4,
    "steal_pct": 0.2,
    "psi_cpu_some_window_pct": 1.0,
    "psi_memory_some_window_pct": 0.0,
    "psi_memory_full_window_pct": 0.0,
    "psi_io_some_window_pct": 0.0,
    "cgroup_available": True,
    "cgroup_reason": None,
    "cfs_throttled_ratio": None,
    "tightest_limit_cores": None,
    "process_cpu_cores_to_tightest_limit_ratio": None,
    "throttled_seconds_per_s": 0.0,
    "ipc": 1.6,
    "llc_mpki": 1.0,
    "is_python": False,
    "python_free_threaded": False,
}


def rank(overrides: dict[str, Any], reasons: dict[str, str] | None = None) -> list[dict]:
    return dg.evaluate({**BASE, **overrides}, reasons or {})


def top(overrides: dict[str, Any]) -> str:
    return rank(overrides)[0]["id"]


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        (
            {
                "runqueue_wait_ratio": 1.2,
                "nonvoluntary_switches_per_s": 400,
                "voluntary_share": 0.1,
                "procs_running_per_core": 3.0,
                "psi_cpu_some_window_pct": 80,
            },
            "runqueue_contention",
        ),
        ({"ipc": 0.4, "llc_mpki": 25}, "cache_or_memory_bound_contention"),
        (
            {
                "cfs_throttled_ratio": 0.6,
                "tightest_limit_cores": 1.0,
                "throttled_seconds_per_s": 0.4,
                "process_cpu_cores_to_tightest_limit_ratio": 0.98,
                "runqueue_wait_ratio": 0.9,
            },
            "cfs_throttling",
        ),
        (
            {
                "voluntary_switches_per_s": 5000,
                "voluntary_share": 0.95,
                "futex_wait_share": 0.8,
                "switches_per_cpu_second": 9000,
            },
            "lock_contention",
        ),
        (
            {
                "cpu_cores_used": 4.0,
                "user_share": 0.99,
                "switches_per_cpu_second": 5,
                "voluntary_switches_per_s": 5,
                "voluntary_share": 0.5,
            },
            "spin_waiting_or_compute",
        ),
        (
            {
                "is_python": True,
                "cpu_cores_used": 1.0,
                "mean_runnable_threads": 1.0,
                "mean_futex_waiting_threads": 3.0,
                "voluntary_switches_per_s": 400,
                "futex_wait_share": 0.9,
            },
            "gil_convoy",
        ),
        ({"steal_pct": 25.0}, "steal"),
        (
            {
                "psi_memory_some_window_pct": 30,
                "psi_memory_full_window_pct": 10,
                "major_faults_per_s": 900,
                "refaults_per_s": 5000,
                "memory_stall_share_of_active": 0.8,
            },
            "memory_thrashing",
        ),
        (
            {"psi_io_some_window_pct": 40, "iowait_seconds_per_s": 0.6, "disk_wait_share": 0.5},
            "io_pressure",
        ),
    ],
)
def test_each_hypothesis_can_rank_first(overrides: dict[str, Any], expected: str) -> None:
    assert top(overrides) == expected


def test_missing_signals_are_unknown_not_zero() -> None:
    res = rank(
        {"ipc": None, "llc_mpki": None},
        {"ipc": "cycles: unavailable: no PMU exposed (common in VMs)", "llc_mpki": "no PMU"},
    )
    cache = next(h for h in res if h["id"] == "cache_or_memory_bound_contention")
    assert cache["assessment"] == "insufficient_signals"
    assert cache["score"] == 0
    assert {u["signal"] for u in cache["unknown"]} == {"ipc", "llc_mpki"}
    assert "no PMU" in cache["unknown"][0]["reason"]


def test_every_judgement_carries_raw_value_and_threshold() -> None:
    for h in rank({"runqueue_wait_ratio": 0.6, "steal_pct": 12}):
        for e in h["evidence_for"] + h["evidence_against"]:
            assert "signal" in e and "value" in e and "weight" in e
            if "threshold_name" in e:
                assert e["threshold_name"] in dg.THRESHOLDS
        assert h["next_measurements"]
        assert h["assessment"] in dg.ASSESSMENTS


def test_no_certainty_words() -> None:
    import json

    text = json.dumps(rank({})) + json.dumps(dg.threshold_table())
    for word in ("root cause", "certain", "definitely", "proven", "the cause"):
        assert word not in text.lower()


def test_throttling_explains_runqueue_wait_on_idle_host() -> None:
    res = rank(
        {
            "runqueue_wait_ratio": 4.0,
            "cfs_throttled_ratio": 1.0,
            "tightest_limit_cores": 0.2,
            "throttled_seconds_per_s": 0.8,
            "process_cpu_cores_to_tightest_limit_ratio": 1.0,
            "procs_running_per_core": 0.3,
        }
    )
    assert res[0]["id"] == "cfs_throttling"
    rq = next(h for h in res if h["id"] == "runqueue_contention")
    assert any(e["signal"] == "cfs_throttled_ratio" for e in rq["evidence_against"])


def test_throttling_explains_runqueue_wait_on_busy_host() -> None:
    # Regression: with other load on the host (procs_running_per_core >= 1 and CPU PSI
    # up), run-queue contention tied the quota even though throttled time made up
    # nearly all of the process's run-queue wait.
    res = rank(
        {
            "runqueue_wait_ratio": 4.0,
            "runqueue_wait_seconds_per_s": 0.8,
            "cfs_throttled_ratio": 1.0,
            "tightest_limit_cores": 0.2,
            "throttled_seconds_per_s": 0.75,
            "process_cpu_cores_to_tightest_limit_ratio": 1.0,
            "procs_running_per_core": 1.3,
            "psi_cpu_some_window_pct": 60.0,
            "nonvoluntary_switches_per_s": 150.0,
            "voluntary_share": 0.1,
        }
    )
    assert res[0]["id"] == "cfs_throttling"
    rq = next(h for h in res if h["id"] == "runqueue_contention")
    assert rq["score"] < res[0]["score"]
    assert any(e["signal"] == "throttled_share_of_runqueue_wait" for e in rq["evidence_against"])


def test_runqueue_wait_not_explained_by_light_throttling() -> None:
    res = rank(
        {
            "runqueue_wait_ratio": 4.0,
            "runqueue_wait_seconds_per_s": 0.8,
            "cfs_throttled_ratio": 0.06,
            "tightest_limit_cores": 4.0,
            "throttled_seconds_per_s": 0.01,
            "procs_running_per_core": 2.0,
            "psi_cpu_some_window_pct": 60.0,
        }
    )
    assert res[0]["id"] == "runqueue_contention"


THRASH = {
    "major_faults_per_s": 150.0,
    "refaults_per_s": 1000.0,
    "refaults_source": "cgroup memory.stat",
    "psi_memory_some_window_pct": 0.4,
    "psi_memory_full_window_pct": 0.4,
    "memory_stall_share_of_active": 1.0,
    "memory_stall_no_progress_seconds_per_s": 0.95,
    "cpu_cores_used": 0.01,
    # The same fault waits show up as I/O pressure and D state.
    "psi_io_some_window_pct": 60.0,
    "disk_wait_share": 0.0,
    "block_io_wait_share": 0.0,
    "stopped_or_frozen_share": 0.0,
    "deliberately_frozen": False,
}


def test_thrashing_with_slow_refaults_ranks_above_io_pressure() -> None:
    res = rank(THRASH)
    assert res[0]["id"] == "memory_thrashing"
    io = next(h for h in res if h["id"] == "io_pressure")
    assert io["score"] < res[0]["score"]
    assert any(e["signal"] == "disk_wait_share" for e in io["evidence_against"])


def test_no_memory_stall_signals_is_not_indicated() -> None:
    res = rank({"refaults_per_s": 0.0, "memory_stall_share_of_active": 0.0})
    mem = next(h for h in res if h["id"] == "memory_thrashing")
    assert mem["assessment"] == "not_indicated"
    signals = {e["signal"] for e in mem["evidence_against"]}
    assert {"major_faults_per_s", "refaults_per_s", "memory_stall_share_of_active"} <= signals


def test_memory_signals_missing_are_unknown() -> None:
    res = rank(
        {"refaults_per_s": None, "memory_stall_share_of_active": None},
        {"refaults_per_s": "no counters", "memory_stall_share_of_active": "not sampled"},
    )
    mem = next(h for h in res if h["id"] == "memory_thrashing")
    unknown = {u["signal"] for u in mem["unknown"]}
    assert unknown >= {"refaults_per_s", "memory_stall_share_of_active"}


def test_deliberately_frozen_makes_the_rest_moot() -> None:
    s = {**BASE, **THRASH, "deliberately_frozen": True, "stopped_or_frozen_share": 1.0}
    s["cgroup_frozen"] = True
    res = dg.evaluate(s, {})
    assert all(h["moot_because"] == "deliberately_frozen" for h in res)
    mem = next(h for h in res if h["id"] == "memory_thrashing")
    assert any(e["threshold_name"] == "frozen_share" for e in mem["evidence_against"])
    (fact,) = dg.fact_checks(s, {})
    assert fact["id"] == "deliberately_frozen" and fact["value"] is True
    assert "moot" in fact["consequence"]
    (fact,) = dg.fact_checks({**BASE, "deliberately_frozen": None}, {"deliberately_frozen": "x"})
    assert fact["value"] is None and fact["reason"] == "x"


def test_stall_signals_from_a_watch_result() -> None:
    stalls = {
        "process": {
            "memory_stall_share_of_active": 0.6,
            "memory_stall_no_progress_seconds_per_s": 0.0,
            "category_share": {"page_fault_io": 0.6, "running": 0.3, "block_io": 0.1},
            "system_share": 0.97,
        },
        "environment": {"cgroup_memory": {"refaults_per_s": 2500.0}, "host": {}},
        "frozen_or_stopped": {"cgroup_frozen": False, "assessment": "not_frozen_or_stopped"},
    }
    s: dict[str, Any] = {}
    reasons: dict[str, str] = {}
    dg._stall_signals(s, reasons, stalls, None)
    assert s["refaults_per_s"] == 2500.0 and s["refaults_source"] == "cgroup memory.stat"
    assert s["disk_wait_share"] == 0.1 and s["deliberately_frozen"] is False
    s, reasons = {}, {}
    dg._stall_signals(s, reasons, None, "pid exited")
    assert s["memory_stall_share_of_active"] is None
    assert reasons["memory_stall_share_of_active"] == "pid exited"


def test_every_new_threshold_has_a_meaning() -> None:
    for name in ("refaults_per_s_high", "memory_stall_share_high", "frozen_share"):
        value, unit, meaning = dg.THRESHOLDS[name]
        assert value > 0 and unit and len(meaning) > 10


def test_focus_groups_name_real_hypotheses() -> None:
    ids = {h["id"] for h in rank({})}
    for group in dg.FOCUS.values():
        assert group <= ids
    assert "memory_pressure" not in ids
