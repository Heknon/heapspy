"""Measured windows kept in memory, so an agent can compare a process before and
after a change (a load step, a config change, an experiment).

``snapshot_process_metrics`` measures one window and stores the key numbers
under a token; ``compare_process_snapshots`` reports each number before and
after. With a caller-supplied ``work_rate`` (requests/s or any unit of work per
second from the caller's own metrics) it also reports CPU seconds per unit of
work, and how fast CPU grew relative to work.
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
            "pid": pid,
            "label": label,
            "taken_at_unix": round(time.time(), 3),
            "window_s": _get(view, ("measurement", "window_s")),
            "work_rate": work_rate,
            "cpu_seconds_per_unit_work": per_work,
            "metrics": metrics,
        }
        self._items[token] = entry
        while len(self._items) > MAX_SNAPSHOTS:
            self._items.popitem(last=False)
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
