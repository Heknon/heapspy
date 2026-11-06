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
            },
            "memory_pressure",
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
