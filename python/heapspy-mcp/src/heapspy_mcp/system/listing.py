"""Cheap per-process CPU and thread fields for ``list_python_processes``."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from . import procfs as pf
from .sampling import thread_states

MAX_MEASURE_S = 2.0
LIST_THREAD_CAP = 256


def _cpu_ticks(proc_root: Path, pid: int) -> int | None:
    text = pf.read_text(proc_root / str(pid) / "stat")
    if text is None:
        return None
    try:
        st = pf.parse_pid_stat(text)
    except (ValueError, IndexError):
        return None
    return st.utime_ticks + st.stime_ticks


def annotate(
    rows: list[dict[str, Any]], measure_s: float, proc_root: Path = Path("/proc")
) -> dict[str, Any]:
    """Add ``threads``, ``threads_by_state`` and ``cpu_percent_on_cpu`` to each row.

    ``cpu_percent_on_cpu`` is CPU time over one shared window of ``measure_s``
    seconds (100 = one core busy); with ``measure_s=0`` it is null. Returns the
    measurement description for the listing.
    """
    window = max(0.0, min(measure_s, MAX_MEASURE_S))
    start: dict[int, int | None] = {}
    t0 = time.monotonic()
    if window > 0:
        start = {row["pid"]: _cpu_ticks(proc_root, row["pid"]) for row in rows}
        time.sleep(window)
    elapsed = time.monotonic() - t0
    for row in rows:
        pid = row["pid"]
        ts = thread_states(proc_root, pid, LIST_THREAD_CAP)
        row["threads"] = ts["threads_seen"] or None
        row["threads_by_state"] = ts["counts"] if ts["threads_seen"] else None
        if ts["truncated"]:
            row["threads_by_state_truncated"] = True
        if window > 0:
            a, b = start.get(pid), _cpu_ticks(proc_root, pid)
            row["cpu_percent_on_cpu"] = (
                round((b - a) / pf.USER_HZ / elapsed * 100, 1)
                if a is not None and b is not None
                else None
            )
        else:
            row["cpu_percent_on_cpu"] = None
    if window > 0:
        return {"cpu_percent_window_s": round(elapsed, 3)}
    return {
        "cpu_percent_window_s": None,
        "cpu_percent_unavailable_reason": "measure_s=0: pass measure_s (up to 2) to measure",
    }
