"""Measured windows kept in memory, so an agent can compare a process before and
after a change (a load step, a config change, an experiment).

``snapshot_process_metrics`` measures one window and stores the key numbers
under a token; ``compare_process_snapshots`` reports each number before and
after. With a caller-supplied ``work_rate`` (requests/s or any unit of work per
second from the caller's own metrics) it also reports CPU seconds per unit of
work, and how fast CPU grew relative to work.

``snapshot_group_metrics`` does the same for a group of processes
(``group_cpu``): per group key, the summed and pooled metrics and, with a
work rate, CPU seconds and timeslices per unit of work.

``fit_per_slice_cost`` takes three or more snapshots of one process or group
at different settings and fits CPU seconds per unit of work against
timeslices per unit of work, ``y = a + b * x``: ``b`` is a fixed cost paid
once per timeslice (for example refilling caches after another task ran),
``a`` the cost per unit of work that does not depend on slicing. The same fit
reads ``a + b / units_per_slice``.
"""

from __future__ import annotations

import secrets
import time
from collections import OrderedDict
from typing import Any

MAX_SNAPSHOTS = 64

# (label, path into the process_cpu view or the hw block)
KEY_METRICS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("cpu_cores_used", ("cpu", "cpu_cores_used")),
    ("cpu_seconds_user", ("cpu", "cpu_seconds_user")),
    ("cpu_seconds_system", ("cpu", "cpu_seconds_system")),
    ("voluntary_switches_per_s", ("context_switches", "voluntary_switches_per_s")),
    ("nonvoluntary_switches_per_s", ("context_switches", "nonvoluntary_switches_per_s")),
    ("switches_per_cpu_second", ("context_switches", "switches_per_cpu_second")),
    ("runqueue_wait_ratio", ("scheduler", "runqueue_wait_ratio")),
    ("runqueue_wait_seconds_per_s", ("scheduler", "runqueue_wait_seconds_per_s")),
    ("on_cpu_seconds_per_s", ("scheduler", "on_cpu_seconds_per_s")),
    ("timeslices_per_s", ("scheduler", "timeslices_per_s")),
    ("avg_timeslice_us", ("scheduler", "avg_timeslice_us")),
    ("sched_slice_us", ("scheduler", "sched_slice_us")),
    ("cpu_migrations_per_s", ("scheduler", "cpu_migrations_per_s")),
    ("iowait_seconds", ("iowait_seconds",)),
    ("major_faults_per_s", ("page_faults", "major_faults_per_s")),
    ("threads", ("threads", "count")),
    ("cfs_throttled_ratio", ("environment", "cgroup", "max_cfs_throttled_ratio")),
    (
        "cgroup_psi_cpu_some_window_pct",
        ("environment", "cgroup", "pressure", "cpu", "some", "window_pct"),
    ),
    ("host_procs_running_per_core", ("environment", "host", "procs_running_per_core")),
    ("host_steal_pct", ("environment", "host", "cpu_time_pct", "steal_pct")),
    ("host_psi_cpu_some_window_pct", ("environment", "host", "psi", "cpu", "some", "window_pct")),
    ("ipc", ("hw", "ipc")),
    ("llc_mpki", ("hw", "llc_mpki")),
)


class SnapshotError(Exception):
    pass


def _get(d: Any, path: tuple[str, ...]) -> Any:
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


class WindowStore:
    def __init__(self) -> None:
        self._items: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def put(self, pid: int, view: dict[str, Any], work_rate: float | None, label: str | None):
        token = f"pm-{secrets.token_hex(4)}"
        metrics = {name: _get(view, path) for name, path in KEY_METRICS}
        cores = metrics.get("cpu_cores_used")
        per_work = None
        if work_rate is not None and work_rate > 0 and cores is not None:
            per_work = round(cores / work_rate, 6)
        entry = {
            "token": token,
            "kind": "process",
            "pid": pid,
            "label": label,
            "taken_at_unix": round(time.time(), 3),
            "window_s": _get(view, ("measurement", "window_s")),
            "work_rate": work_rate,
            "cpu_seconds_per_unit_work": per_work,
            "metrics": metrics,
        }
        self._keep(entry)
        return entry

    def _keep(self, entry: dict[str, Any]) -> None:
        self._items[entry["token"]] = entry
        while len(self._items) > MAX_SNAPSHOTS:
            self._items.popitem(last=False)

    def put_group(
        self, view: dict[str, Any], label: str | None, selector: dict[str, Any]
    ) -> dict[str, Any]:
        """Keep the per-group numbers of a ``group_cpu`` result."""
        groups = {}
        for g in view["groups"]:
            groups[g["key"]] = {
                "members": g["members"],
                "pids": g["pids"],
                "metrics": {
                    name: {k: d.get(k) for k in ("sum", "mean", "pooled", "p90", "max")}
                    for name, d in g["metrics"].items()
                },
                "work": g["work"],
            }
        entry = {
            "token": f"pg-{secrets.token_hex(4)}",
            "kind": "group",
            "label": label,
            "taken_at_unix": round(time.time(), 3),
            "window_s": _get(view, ("measurement", "window_s")),
            "group_by": view.get("group_by"),
            "selector": selector,
            "groups": groups,
        }
        self._keep(entry)
        return entry

    def get(self, token: str) -> dict[str, Any]:
        entry = self._items.get(token.strip())
        if entry is None:
            raise SnapshotError(
                f"unknown snapshot token {token!r}; tokens live in server memory and the "
                f"newest {MAX_SNAPSHOTS} are kept"
            )
        return entry


def compare(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    ka, kb = a.get("kind", "process"), b.get("kind", "process")
    if ka != kb:
        raise SnapshotError("cannot compare a process snapshot with a group snapshot")
    if ka == "group":
        return compare_group_snapshots(a, b)
    rows = {}
    for name, _ in KEY_METRICS:
        x, y = a["metrics"].get(name), b["metrics"].get(name)
        rows[name] = {
            "before": x,
            "after": y,
            "change": round(y - x, 4) if x is not None and y is not None else None,
            "after_to_before_ratio": round(y / x, 3) if x and y is not None else None,
        }
    out: dict[str, Any] = {
        "before": {k: a[k] for k in ("token", "pid", "label", "taken_at_unix", "window_s")},
        "after": {k: b[k] for k in ("token", "pid", "label", "taken_at_unix", "window_s")},
        "metrics": rows,
    }
    if a["pid"] != b["pid"]:
        out["note"] = "the two snapshots are of different pids"
    wa, wb = a.get("work_rate"), b.get("work_rate")
    ca, cb = a["metrics"].get("cpu_cores_used"), b["metrics"].get("cpu_cores_used")
    if wa and wb and ca and cb is not None:
        work_ratio = wb / wa
        cpu_ratio = cb / ca
        out["work"] = {
            "work_rate_before": wa,
            "work_rate_after": wb,
            "cpu_seconds_per_unit_work_before": a["cpu_seconds_per_unit_work"],
            "cpu_seconds_per_unit_work_after": b["cpu_seconds_per_unit_work"],
            "work_rate_ratio": round(work_ratio, 3),
            "cpu_cores_ratio": round(cpu_ratio, 3),
            "cpu_per_unit_work_ratio": round(cpu_ratio / work_ratio, 3),
            "meaning": "cpu_per_unit_work_ratio above 1 means CPU grew faster than work "
            "between the windows; 1 means CPU scaled with work",
        }
    else:
        out["work"] = None
        out["work_unavailable_reason"] = (
            "work_rate was not given for both snapshots (or CPU was 0 before)"
        )
    return out


# --- groups ---------------------------------------------------------------------------

GROUP_COMPARE_METRICS = (
    ("cpu_cores_used", "sum"),
    ("on_cpu_seconds_per_s", "sum"),
    ("voluntary_switches_per_s", "sum"),
    ("nonvoluntary_switches_per_s", "sum"),
    ("runqueue_wait_seconds_per_s", "sum"),
    ("timeslices_per_s", "sum"),
    ("cpu_migrations_per_s", "sum"),
    ("voluntary_share", "pooled"),
    ("switches_per_cpu_second", "pooled"),
    ("runqueue_wait_ratio", "pooled"),
    ("avg_timeslice_us", "pooled"),
    ("runnable_share", "pooled"),
    ("nonvoluntary_switches_per_s", "max"),
)


def _row(x: float | None, y: float | None) -> dict[str, Any]:
    return {
        "before": x,
        "after": y,
        "change": round(y - x, 4) if x is not None and y is not None else None,
        "after_to_before_ratio": round(y / x, 3) if x and y is not None else None,
    }


def compare_group_snapshots(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    keys = sorted(set(a["groups"]) & set(b["groups"]))
    out_groups = {}
    for key in keys:
        ga, gb = a["groups"][key], b["groups"][key]
        rows = {}
        for name, stat in GROUP_COMPARE_METRICS:
            x = (ga["metrics"].get(name) or {}).get(stat)
            y = (gb["metrics"].get(name) or {}).get(stat)
            rows[f"{name}.{stat}"] = _row(x, y)
        wa, wb = ga.get("work") or {}, gb.get("work") or {}
        work = None
        pa, pb = wa.get("cpu_seconds_per_unit_work"), wb.get("cpu_seconds_per_unit_work")
        if pa and pb:
            work = {
                "work_rate_before": wa["work_rate"],
                "work_rate_after": wb["work_rate"],
                "cpu_seconds_per_unit_work_before": pa,
                "cpu_seconds_per_unit_work_after": pb,
                "cpu_per_unit_work_ratio": round(pb / pa, 3),
                "timeslices_per_unit_work_before": wa.get("timeslices_per_unit_work"),
                "timeslices_per_unit_work_after": wb.get("timeslices_per_unit_work"),
                "meaning": "cpu_per_unit_work_ratio above 1 means each unit of work cost more "
                "CPU after than before",
            }
        out_groups[key] = {
            "members_before": ga["members"],
            "members_after": gb["members"],
            "metrics": rows,
            "work": work,
            **({} if work else {"work_unavailable_reason": "work_rate not given for both"}),
        }
    meta = ("token", "label", "taken_at_unix", "window_s", "group_by")
    return {
        "kind": "group",
        "before": {k: a.get(k) for k in meta},
        "after": {k: b.get(k) for k in meta},
        "groups": out_groups,
        "groups_only_before": sorted(set(a["groups"]) - set(b["groups"])),
        "groups_only_after": sorted(set(b["groups"]) - set(a["groups"])),
    }


# --- per-slice cost fit -----------------------------------------------------------------

MIN_FIT_POINTS = 3
MAX_FIT_POINTS = 32


def _point(
    entry: dict[str, Any], group: str | None, work_rate: float | None
) -> tuple[dict[str, Any] | None, str | None]:
    """(point, reason it could not be used)."""
    if entry.get("kind") == "group":
        groups = entry["groups"]
        if group is None:
            if len(groups) != 1:
                return None, f"snapshot has groups {sorted(groups)}; name one with group"
            group = next(iter(groups))
        g = groups.get(group)
        if g is None:
            return None, f"no group {group!r} in this snapshot"
        m = g["metrics"]
        on = (m.get("on_cpu_seconds_per_s") or {}).get("sum")
        cpu_source = "schedstat on-CPU time"
        if on is None:
            on = (m.get("cpu_cores_used") or {}).get("sum")
            cpu_source = "utime+stime clock ticks"
        slices = (m.get("timeslices_per_s") or {}).get("sum")
        avg_slice = (m.get("avg_timeslice_us") or {}).get("pooled")
        rate = work_rate or (g.get("work") or {}).get("work_rate")
    else:
        m = entry["metrics"]
        on = m.get("on_cpu_seconds_per_s")
        cpu_source = "schedstat on-CPU time"
        if on is None:
            on = m.get("cpu_cores_used")
            cpu_source = "utime+stime clock ticks"
        slices = m.get("timeslices_per_s")
        avg_slice = m.get("avg_timeslice_us")
        rate = work_rate or entry.get("work_rate")
    if not rate:
        return None, "no work_rate for this snapshot (pass work_rates)"
    if on is None or slices is None:
        return None, "snapshot has no on-CPU time or timeslice count"
    return {
        "token": entry["token"],
        "label": entry.get("label"),
        "group": group,
        "work_rate": rate,
        "cpu_seconds_per_unit_work": on / rate,
        "timeslices_per_s": slices,
        "timeslices_per_unit_work": slices / rate,
        "units_of_work_per_timeslice": rate / slices if slices else None,
        "avg_timeslice_us": avg_slice,
        "cpu_source": cpu_source,
    }, None


def fit_line(xs: list[float], ys: list[float]) -> dict[str, Any] | None:
    """Least-squares ``y = a + b x``, with residuals, R squared and standard errors."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx <= 0:
        return None
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True)) / sxx
    a = my - b * mx
    res = [y - (a + b * x) for x, y in zip(xs, ys, strict=True)]
    ss_res = sum(e * e for e in res)
    ss_tot = sum((y - my) ** 2 for y in ys)
    out: dict[str, Any] = {
        "a": a,
        "b": b,
        "residuals": res,
        "r_squared": 1 - ss_res / ss_tot if ss_tot > 0 else None,
        "b_stderr": None,
        "a_stderr": None,
    }
    if n > 2:
        s2 = ss_res / (n - 2)
        out["b_stderr"] = (s2 / sxx) ** 0.5
        out["a_stderr"] = (s2 * (1 / n + mx * mx / sxx)) ** 0.5
    return out


def fit_per_slice_cost(
    entries: list[dict[str, Any]],
    *,
    group: str | None = None,
    work_rates: dict[str, float] | None = None,
) -> dict[str, Any]:
    if len(entries) > MAX_FIT_POINTS:
        raise SnapshotError(f"at most {MAX_FIT_POINTS} snapshots")
    kinds = {e.get("kind", "process") for e in entries}
    if len(kinds) > 1:
        raise SnapshotError("mix of process and group snapshots; fit one kind at a time")
    points, skipped = [], []
    for e in entries:
        pt, why = _point(e, group, (work_rates or {}).get(e["token"]))
        if pt is None:
            skipped.append({"token": e["token"], "reason": why})
        else:
            points.append(pt)
    warnings = []
    if len(points) < MIN_FIT_POINTS:
        warnings.append(
            f"{len(points)} usable points: a line through fewer than {MIN_FIT_POINTS} points "
            "has no residuals to judge it by; take snapshots at three or more settings"
        )
    if len({e.get("pid") for e in entries}) > 1 and "process" in kinds:
        warnings.append("the process snapshots are of different pids")
    result: dict[str, Any] = {
        "model": "cpu_seconds_per_unit_work = a + b * timeslices_per_unit_work "
        "(equivalently a + b / units_of_work_per_timeslice)",
        "points": [
            {
                **{k: v for k, v in p.items() if k != "cpu_seconds_per_unit_work"},
                "cpu_us_per_unit_work": round(p["cpu_seconds_per_unit_work"] * 1e6, 3),
                "timeslices_per_unit_work": round(p["timeslices_per_unit_work"], 5),
                "units_of_work_per_timeslice": round(p["units_of_work_per_timeslice"], 3)
                if p["units_of_work_per_timeslice"]
                else None,
            }
            for p in points
        ],
        "skipped": skipped,
        "warnings": warnings,
        "fit": None,
    }
    if len(points) < 2:
        result["fit_unavailable_reason"] = "need at least two usable points"
        return result
    xs = [p["timeslices_per_unit_work"] for p in points]
    ys = [p["cpu_seconds_per_unit_work"] for p in points]
    f = fit_line(xs, ys)
    if f is None:
        result["fit_unavailable_reason"] = (
            "every point has the same timeslices per unit of work; change the setting that "
            "changes slicing (CPUs, co-location, slice length) between snapshots"
        )
        return result
    if f["b"] < 0:
        warnings.append(
            "the fitted per-slice cost is negative: CPU per unit of work did not rise with "
            "timeslices per unit of work, so this model does not describe these points"
        )
    us = 1e6
    result["fit"] = {
        "fixed_cost_per_timeslice_us": round(f["b"] * us, 3),
        "fixed_cost_per_timeslice_us_stderr": round(f["b_stderr"] * us, 3)
        if f["b_stderr"] is not None
        else None,
        "cost_per_unit_work_without_slicing_us": round(f["a"] * us, 3),
        "cost_per_unit_work_without_slicing_us_stderr": round(f["a_stderr"] * us, 3)
        if f["a_stderr"] is not None
        else None,
        "r_squared": round(f["r_squared"], 4) if f["r_squared"] is not None else None,
        "residuals_us_per_unit_work": [round(e * us, 3) for e in f["residuals"]],
        "max_abs_residual_share": round(
            max(abs(e) / y for e, y in zip(f["residuals"], ys, strict=True) if y), 4
        ),
        "degrees_of_freedom": len(points) - 2,
        "meaning": "fixed_cost_per_timeslice_us is CPU time each timeslice costs on top of "
        "the work done in it (for example refilling caches after other tasks ran); "
        "cost_per_unit_work_without_slicing_us is the cost with infinitely long slices. "
        "A fit across settings shows how well the points follow the model; it does not "
        "show why",
    }
    return result
