"""Snapshots of measured windows and their comparison."""

from __future__ import annotations

from typing import Any

import pytest

from heapspy_mcp.system import windows


def test_snapshot_compare_work_rate() -> None:
    store = windows.WindowStore()

    def view(cores: float) -> dict[str, Any]:
        return {"measurement": {"window_s": 2.0}, "cpu": {"cpu_cores_used": cores}}

    a = store.put(7, view(1.0), 100.0, "before")
    b = store.put(7, view(3.0), 150.0, "after")
    out = windows.compare(store.get(a["token"]), store.get(b["token"]))
    assert out["metrics"]["cpu_cores_used"]["after_to_before_ratio"] == 3.0
    assert out["work"]["work_rate_ratio"] == 1.5
    assert out["work"]["cpu_per_unit_work_ratio"] == 2.0
    assert out["work"]["cpu_seconds_per_unit_work_before"] == 0.01
    assert out["metrics"]["ipc"]["before"] is None  # missing stays None
    c = store.put(7, view(1.0), None, None)
    assert windows.compare(store.get(a["token"]), store.get(c["token"]))["work"] is None
    with pytest.raises(windows.SnapshotError):
        store.get("pm-00000000")


def test_snapshot_store_is_bounded() -> None:
    store = windows.WindowStore()
    first = store.put(1, {}, None, None)["token"]
    for _ in range(windows.MAX_SNAPSHOTS):
        store.put(1, {}, None, None)
    with pytest.raises(windows.SnapshotError):
        store.get(first)
