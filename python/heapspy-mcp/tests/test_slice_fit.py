"""Group snapshots, their comparison, and the per-slice cost fit."""

from __future__ import annotations

from typing import Any

import pytest

from heapspy_mcp.system import groups as grp
from heapspy_mcp.system import windows


def group_view(key: str, on_cpu: float, slices: float, rate: float | None) -> dict[str, Any]:
    metrics = {name: {"sum": None, "mean": None, "pooled": None} for name in grp.METRICS}
    metrics["on_cpu_seconds_per_s"] = {"sum": on_cpu, "mean": on_cpu / 8}
    metrics["cpu_cores_used"] = {"sum": on_cpu, "mean": on_cpu / 8}
    metrics["timeslices_per_s"] = {"sum": slices, "mean": slices / 8}
    metrics["avg_timeslice_us"] = {"pooled": on_cpu / slices * 1e6}
    agg = {k: {**{"sum": None, "mean": None, "pooled": None}, **v} for k, v in metrics.items()}
    return {
        "measurement": {"window_s": 3.0},
        "group_by": "cmdline_regex",
        "groups": [
            {
                "key": key,
                "members": 8,
                "pids": [1],
                "metrics": agg,
                "work": grp.work_block(agg, rate),
            }
        ],
    }


def test_fit_recovers_per_slice_cost() -> None:
    # 28 us per request plus 70 us per timeslice, at three slice densities.
    store = windows.WindowStore()
    a, b = 28e-6, 70e-6
    toks = []
    for rate, slices in ((50000.0, 2000.0), (30000.0, 9000.0), (52000.0, 1000.0)):
        on = rate * a + slices * b
        toks.append(store.put_group(group_view("api", on, slices, rate), None, {})["token"])
    out = windows.fit_per_slice_cost([store.get(t) for t in toks])
    f = out["fit"]
    assert f["fixed_cost_per_timeslice_us"] == pytest.approx(70.0, abs=0.01)
    assert f["cost_per_unit_work_without_slicing_us"] == pytest.approx(28.0, abs=0.01)
    assert f["r_squared"] == pytest.approx(1.0)
    assert max(abs(e) for e in f["residuals_us_per_unit_work"]) < 1e-6
    assert f["degrees_of_freedom"] == 1
    assert out["warnings"] == []
    assert out["points"][1]["avg_timeslice_us"] == pytest.approx(
        (30000 * a + 9000 * b) / 9000 * 1e6
    )


def test_fit_warns_with_two_points_and_uses_late_work_rates() -> None:
    store = windows.WindowStore()
    t1 = store.put_group(group_view("api", 1.5, 2000, None), None, {})["token"]
    t2 = store.put_group(group_view("api", 1.6, 9000, None), None, {})["token"]
    out = windows.fit_per_slice_cost([store.get(t1), store.get(t2)])
    assert out["fit"] is None and len(out["skipped"]) == 2
    out = windows.fit_per_slice_cost(
        [store.get(t1), store.get(t2)], work_rates={t1: 50000.0, t2: 30000.0}
    )
    assert out["fit"] is not None
    assert any("fewer than 3" in w for w in out["warnings"])


def test_fit_rejects_equal_x_and_flags_negative_slope() -> None:
    store = windows.WindowStore()
    same = [store.put_group(group_view("g", c, 1000, 1000.0), None, {}) for c in (1.0, 1.1, 1.2)]
    out = windows.fit_per_slice_cost(same)
    assert out["fit"] is None and "same timeslices" in out["fit_unavailable_reason"]
    neg = [
        store.put_group(group_view("g", c, s, 1000.0), None, {})
        for c, s in ((1.0, 1000), (0.8, 2000), (0.6, 3000))
    ]
    out = windows.fit_per_slice_cost(neg)
    assert out["fit"]["fixed_cost_per_timeslice_us"] < 0
    assert any("negative" in w for w in out["warnings"])


def test_fit_on_process_snapshots_and_kind_checks() -> None:
    store = windows.WindowStore()

    def view(on: float, slices: float) -> dict[str, Any]:
        return {
            "measurement": {"window_s": 2.0},
            "cpu": {"cpu_cores_used": on},
            "scheduler": {"on_cpu_seconds_per_s": on, "timeslices_per_s": slices},
        }

    pts = [
        store.put(7, view(r * 3e-5 + s * 5e-5, s), r, None)
        for r, s in ((5000, 100), (4000, 1000), (4500, 600))
    ]
    out = windows.fit_per_slice_cost(pts)
    assert out["fit"]["fixed_cost_per_timeslice_us"] == pytest.approx(50.0, abs=0.01)
    g = store.put_group(group_view("g", 1.0, 1000, 1000.0), None, {})
    with pytest.raises(windows.SnapshotError):
        windows.fit_per_slice_cost([pts[0], g])
    with pytest.raises(windows.SnapshotError):
        windows.compare(pts[0], g)


def test_group_snapshot_compare() -> None:
    store = windows.WindowStore()
    a = store.put_group(group_view("api", 1.0, 2000, 40000.0), "4c", {"cmdline": "svc"})
    b = store.put_group(group_view("api", 1.5, 9000, 30000.0), "2c", {"cmdline": "svc"})
    assert a["token"].startswith("pg-")
    out = windows.compare(store.get(a["token"]), store.get(b["token"]))
    g = out["groups"]["api"]
    assert g["metrics"]["timeslices_per_s.sum"]["after_to_before_ratio"] == 4.5
    assert g["work"]["cpu_per_unit_work_ratio"] == pytest.approx(2.0)
    assert out["groups_only_before"] == []
