"""Search and rank every process the server can see (``find_processes``,
``scan_processes``).

One sampling pass reads a bounded set of ``/proc`` files per process at the
start and the end of the window, plus cheap in-window samples (``statm`` for
RSS, thread states for processes with threads in disk wait). Processes that
exit or cannot be read are skipped and counted, never an error.

Listing and ranking only read ``/proc`` metadata that ``ps`` and ``top`` show,
so it is not gated by the pid allowlist. Command lines are redacted.
"""

from __future__ import annotations

import itertools
import os
import pwd
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import anyio

from . import cgroups as cg
from . import procfs as pf
from .redact import redact_cmdline

MAX_CMDLINE = 200
MAX_LIMIT = 200
MAX_PER_METRIC = 20
MAX_THREADS_PER_PROCESS = 64
MAX_THREADS_TOTAL = 20000
SCAN_TICKS = 3
MAX_FACT_ROWS = 20
DEFAULT_FD_THRESHOLD_PCT = 80.0

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

# metric name -> needs a window (rate); the unit is in the name.
METRICS: dict[str, bool] = {
    "cpu_percent_on_cpu": True,
    "rss_bytes": False,
    "rss_growth_bytes_per_s": True,
    "threads": False,
    "nonvoluntary_switches_per_s": True,
    "voluntary_switches_per_s": True,
    "runqueue_wait_ratio": True,
    "iowait_seconds": True,
    "open_fds": False,
    "fd_limit_used_pct": False,
    "read_bytes_per_s": True,
    "write_bytes_per_s": True,
    "uptime_s": False,
    "cfs_throttled_ratio": True,
}

_PY_NAME = re.compile(r"^python(?:w)?(?:\d(?:\.?\d+)?)?[dmt]*(?:\.exe)?$", re.IGNORECASE)


class SearchError(Exception):
    """An argument to a search tool is invalid."""


@dataclass
class Static:
    pid: int
    comm: str
    ppid: int
    state: str
    uid: int | None
    exe: str | None
    cmdline: list[str] | None
    cgroup_path: str | None
    kernel_thread: bool
    starttime_ticks: int


@dataclass
class Counters:
    t: float
    utime: int
    stime: int
    rss_pages: int
    threads: int
    vol: int | None
    nonvol: int | None
    run_ns: int | None
    wait_ns: int | None
    blkio: int | None
    d_tids: set[int]
    threads_truncated: bool
    read_bytes: int | None
    write_bytes: int | None


@dataclass
class ScanState:
    proc_root: Path
    statics: dict[int, Static] = field(default_factory=dict)
    first: dict[int, Counters] = field(default_factory=dict)
    last: dict[int, Counters] = field(default_factory=dict)
    rss_series: dict[int, list[int]] = field(default_factory=lambda: defaultdict(list))
    d_all_window: dict[int, set[int]] = field(default_factory=dict)
    cgroup_of_pid: dict[int, str] = field(default_factory=dict)
    skipped_exited: int = 0
    partially_unreadable: int = 0
    thread_budget: int = MAX_THREADS_TOTAL
    sample_wall_s: float = 0.0
    sample_cpu_s: float = 0.0
    samples: int = 0


def _list_pids(proc_root: Path) -> list[int]:
    try:
        return sorted(int(p) for p in os.listdir(proc_root) if p.isdigit())
    except OSError:
        return []


def _read_static(proc_root: Path, pid: int) -> Static | None:
    base = proc_root / str(pid)
    stat_text = pf.read_text(base / "stat")
    if stat_text is None:
        return None
    try:
        st = pf.parse_pid_stat(stat_text)
    except (ValueError, IndexError):
        return None
    status = pf.parse_pid_status(pf.read_text(base / "status") or "")
    try:
        exe: str | None = os.readlink(base / "exe")
    except OSError:
        exe = None
    raw = pf.read_text(base / "cmdline")
    cmdline = [a for a in raw.split("\0") if a] if raw else None
    cgroup_text = pf.read_text(base / "cgroup")
    path = None
    if cgroup_text:
        pc = cg.parse_pid_cgroup(cgroup_text)
        path = pc.v2_path if pc.v2_path not in (None, "/") else pc.v1_paths.get("cpu", pc.v2_path)
        # Prefer a kubepods path wherever it appears.
        for p in [pc.v2_path, *pc.v1_paths.values()]:
            if p and "kubepods" in p:
                path = p
                break
    kthread = (pid == 2 or st.ppid == 2) and not cmdline
    return Static(
        pid=pid,
        comm=st.comm,
        ppid=st.ppid,
        state=st.state,
        uid=status.get("Uid"),
        exe=exe,
        cmdline=cmdline,
        cgroup_path=path,
        kernel_thread=kthread,
        starttime_ticks=st.starttime_ticks,
    )


def _read_counters(state: ScanState, pid: int) -> Counters | None:
    base = state.proc_root / str(pid)
    stat_text = pf.read_text(base / "stat")
    if stat_text is None:
        return None
    try:
        st = pf.parse_pid_stat(stat_text)
    except (ValueError, IndexError):
        return None
    vol = nonvol = run = wait = blkio = 0
    have_sw = have_sched = have_blk = True
    d_tids: set[int] = set()
    try:
        tids = sorted(int(t) for t in os.listdir(base / "task") if t.isdigit())
    except OSError:
        tids = [pid]
    cap = min(MAX_THREADS_PER_PROCESS, max(state.thread_budget, 1))
    truncated = len(tids) > cap
    for tid in tids[:cap]:
        tdir = base / "task" / str(tid)
        if len(tids) == 1:
            tstat = st
        else:
            ttext = pf.read_text(tdir / "stat")
            if ttext is None:
                continue
            try:
                tstat = pf.parse_pid_stat(ttext)
            except (ValueError, IndexError):
                continue
        if tstat.state == "D":
            d_tids.add(tid)
        if tstat.delayacct_blkio_ticks is None:
            have_blk = False
        else:
            blkio += tstat.delayacct_blkio_ticks
        status = pf.parse_pid_status(pf.read_text(tdir / "status") or "")
        v, n = status.get("voluntary_ctxt_switches"), status.get("nonvoluntary_ctxt_switches")
        if v is None or n is None:
            have_sw = False
        else:
            vol += v
            nonvol += n
        ss = pf.parse_pid_schedstat(pf.read_text(tdir / "schedstat") or "")
        if ss is None:
            have_sched = False
        else:
            run += ss.run_ns
            wait += ss.wait_ns
    state.thread_budget -= min(len(tids), cap)
    io = pf.parse_pid_io(pf.read_text(base / "io") or "")
    return Counters(
        t=time.monotonic(),
        utime=st.utime_ticks,
        stime=st.stime_ticks,
        rss_pages=st.rss_pages,
        threads=st.num_threads,
        vol=vol if have_sw else None,
        nonvol=nonvol if have_sw else None,
        run_ns=run if have_sched else None,
        wait_ns=wait if have_sched else None,
        blkio=blkio if have_blk else None,
        d_tids=d_tids,
        threads_truncated=truncated,
        read_bytes=io.get("read_bytes"),
        write_bytes=io.get("write_bytes"),
    )


def _rss_pages(proc_root: Path, pid: int) -> int | None:
    text = pf.read_text(proc_root / str(pid) / "statm")
    if not text:
        return None
    parts = text.split()
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None


def _d_tids(proc_root: Path, pid: int) -> set[int]:
    base = proc_root / str(pid) / "task"
    out = set()
    try:
        tids = [t for t in os.listdir(base) if t.isdigit()][:MAX_THREADS_PER_PROCESS]
    except OSError:
        return out
    for t in tids:
        text = pf.read_text(base / t / "stat")
        if text:
            try:
                if pf.parse_pid_stat(text).state == "D":
                    out.add(int(t))
            except (ValueError, IndexError):
                continue
    return out


class _Cost:
    def __init__(self, state: ScanState) -> None:
        self.state = state

    def __enter__(self) -> None:
        self.w0, self.c0 = time.monotonic(), time.process_time()

    def __exit__(self, *exc: object) -> None:
        self.state.sample_wall_s += time.monotonic() - self.w0
        self.state.sample_cpu_s += time.process_time() - self.c0
        self.state.samples += 1


# --- filters ------------------------------------------------------------------


@dataclass
class Filters:
    name: str | None = None
    cmdline: str | None = None
    cmdline_regex: str | None = None
    user: str | None = None
    pids: list[int] | None = None
    parent_pid: int | None = None
    include_descendants: bool = True
    cgroup: str | None = None
    container_id: str | None = None
    pod_uid: str | None = None
    state: str | None = None
    is_python: bool | None = None
    include_kernel_threads: bool = False
    _regex: re.Pattern[str] | None = None
    _uid: int | None = None

    def prepare(self) -> None:
        if self.cmdline_regex:
            if len(self.cmdline_regex) > 500:
                raise SearchError("cmdline_regex is longer than 500 characters")
            try:
                self._regex = re.compile(self.cmdline_regex)
            except re.error as e:
                raise SearchError(f"cmdline_regex does not compile: {e}") from e
        if self.user is not None:
            if self.user.isdigit():
                self._uid = int(self.user)
            else:
                try:
                    self._uid = pwd.getpwnam(self.user).pw_uid
                except KeyError as e:
                    raise SearchError(f"unknown user {self.user!r}") from e
        if self.state is not None and not re.fullmatch(r"[RSDZTtXIWPK]+", self.state):
            raise SearchError("state must be /proc state letters, e.g. 'D' or 'RD'")
        if self.pod_uid:
            self.pod_uid = self.pod_uid.lower().replace("_", "-")


def is_python_static(s: Static, proc_root: Path, check_maps: bool) -> bool:
    for cand in (s.comm, Path(s.exe).name if s.exe else None):
        if cand and _PY_NAME.match(cand):
            return True
    if check_maps:
        text = pf.read_text(proc_root / str(s.pid) / "maps") or ""
        return bool(re.search(r"libpython\d\.\d+", text))
    return False


def _descendants(statics: dict[int, Static], root: int) -> set[int]:
    children: dict[int, list[int]] = defaultdict(list)
    for s in statics.values():
        children[s.ppid].append(s.pid)
    out: set[int] = set()
    stack = [root]
    while stack:
        p = stack.pop()
        for c in children.get(p, []):
            if c not in out:
                out.add(c)
                stack.append(c)
    return out


def apply_filters(statics: dict[int, Static], f: Filters, proc_root: Path) -> list[int]:
    allowed_parent: set[int] | None = None
    if f.parent_pid is not None:
        allowed_parent = (
            _descendants(statics, f.parent_pid)
            if f.include_descendants
            else {s.pid for s in statics.values() if s.ppid == f.parent_pid}
        )
    out = []
    for pid, s in statics.items():
        if s.kernel_thread and not f.include_kernel_threads:
            continue
        if f.pids is not None and pid not in f.pids:
            continue
        if allowed_parent is not None and pid not in allowed_parent:
            continue
        if f.name and not any(
            fnmatchcase(c, f.name) for c in (s.comm, Path(s.exe).name if s.exe else None) if c
        ):
            continue
        joined = " ".join(s.cmdline or [])
        if f.cmdline and f.cmdline.lower() not in joined.lower():
            continue
        if f._regex is not None and not f._regex.search(joined):
            continue
        if f._uid is not None and s.uid != f._uid:
            continue
        if f.state and s.state not in f.state:
            continue
        if f.cgroup and (s.cgroup_path is None or f.cgroup not in s.cgroup_path):
            continue
        if f.container_id or f.pod_uid:
            k8s = cg.parse_kubepods_path(s.cgroup_path or "") or {}
            if f.container_id and not (k8s.get("container_id") or "").startswith(
                f.container_id.lower()
            ):
                continue
            if f.pod_uid and k8s.get("pod_uid") != f.pod_uid:
                continue
        if f.is_python is not None and is_python_static(s, proc_root, True) != f.is_python:
            continue
        out.append(pid)
    return out


# --- sampling pass ------------------------------------------------------------


@dataclass
class CgroupCounters:
    location: cg.CgroupLocation | None
    a: dict[str, int | None] = field(default_factory=dict)
    b: dict[str, int | None] = field(default_factory=dict)
    oom_a: dict[str, int] | None = None
    oom_b: dict[str, int] | None = None
    pids: list[int] = field(default_factory=list)


def _oom_events(loc: cg.CgroupLocation) -> dict[str, int] | None:
    if loc.pressure_dir is not None:  # v2 directory of the process
        text = pf.read_text(loc.pressure_dir / "memory.events")
        if text:
            ev = cg.parse_flat_keyed(text)
            return {k: v for k, v in ev.items() if k in ("oom", "oom_kill", "oom_group_kill")}
    return None


async def sample_all(
    proc_root: Path,
    pids: list[int],
    window_s: float,
    state: ScanState,
    *,
    want_cgroups: bool,
    cgroup_root: Path | None,
) -> dict[str, CgroupCounters]:
    """First and last counters for ``pids``, in-window RSS and disk-wait samples, and
    cgroup CPU counters for each distinct cgroup of those pids."""
    cgroups: dict[str, CgroupCounters] = {}
    mounts = cg.discover_mounts(proc_root, cgroup_root) if want_cgroups else None
    loc_by_pid: dict[int, str] = {}
    with _Cost(state):
        for pid in pids:
            c = _read_counters(state, pid)
            if c is None:
                state.skipped_exited += 1
                continue
            state.first[pid] = c
            state.rss_series[pid].append(c.rss_pages)
            if c.d_tids:
                state.d_all_window[pid] = set(c.d_tids)
            if mounts is not None:
                text = pf.read_text(proc_root / str(pid) / "cgroup")
                if text:
                    loc = cg.locate(cg.parse_pid_cgroup(text), mounts)
                    if loc is not None and loc.cpu_dir is not None:
                        key = str(loc.cpu_dir)
                        entry = cgroups.get(key)
                        if entry is None:
                            entry = CgroupCounters(loc)
                            entry.a = cg.read_cpu_stat(loc)
                            entry.oom_a = _oom_events(loc)
                            cgroups[key] = entry
                        entry.pids.append(pid)
                        loc_by_pid[pid] = key
    if window_s > 0:
        step = window_s / (SCAN_TICKS + 1)
        for _ in range(SCAN_TICKS):
            await anyio.sleep(step)
            with _Cost(state):
                for pid in list(state.first):
                    rss = _rss_pages(proc_root, pid)
                    if rss is not None:
                        state.rss_series[pid].append(rss)
                for pid in list(state.d_all_window):
                    state.d_all_window[pid] &= _d_tids(proc_root, pid)
        await anyio.sleep(step)
    with _Cost(state):
        state.thread_budget = MAX_THREADS_TOTAL
        for pid in list(state.first):
            c = _read_counters(state, pid)
            if c is None:
                state.skipped_exited += 1
                del state.first[pid]
                continue
            state.last[pid] = c
            state.rss_series[pid].append(c.rss_pages)
            if pid in state.d_all_window:
                state.d_all_window[pid] &= c.d_tids
        for entry in cgroups.values():
            assert entry.location is not None
            entry.b = cg.read_cpu_stat(entry.location)
            entry.oom_b = _oom_events(entry.location)
    state.cgroup_of_pid = loc_by_pid
    return cgroups


def _fd_info(proc_root: Path, pid: int) -> tuple[int | None, int | None]:
    try:
        n = len(os.listdir(proc_root / str(pid) / "fd"))
    except OSError:
        n = None
    lim = pf.parse_nofile_limit(pf.read_text(proc_root / str(pid) / "limits") or "")
    return n, lim


def _user_name(uid: int | None, cache: dict[int, str | None]) -> str | None:
    if uid is None:
        return None
    if uid not in cache:
        try:
            cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            cache[uid] = None
    return cache[uid]


def _r(x: float | None, nd: int = 3) -> float | None:
    return None if x is None else round(x, nd)


def build_rows(
    state: ScanState,
    cgroups: dict[str, CgroupCounters],
    proc_root: Path,
    delayacct: bool | None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    hz = pf.USER_HZ
    uptime_text = pf.read_text(proc_root / "uptime")
    uptime = pf.parse_uptime(uptime_text) if uptime_text else None
    reasons: dict[str, str] = {}
    if delayacct is False:
        reasons["iowait_seconds"] = (
            "delay accounting is off (kernel.task_delayacct=0); enable with "
            "sysctl kernel.task_delayacct=1"
        )
    if uptime is None:
        reasons["uptime_s"] = "/proc/uptime unreadable"
    cg_ratio: dict[str, tuple[float | None, dict[str, Any]]] = {}
    for key, entry in cgroups.items():
        p = (entry.b.get("nr_periods") or 0) - (entry.a.get("nr_periods") or 0)
        t = (entry.b.get("nr_throttled") or 0) - (entry.a.get("nr_throttled") or 0)
        cg_ratio[key] = (round(t / p, 4) if p > 0 else None, {"nr_periods": p, "nr_throttled": t})
    me = os.getpid()
    users: dict[int, str | None] = {}
    rows = []
    for pid, b in state.last.items():
        a = state.first[pid]
        s = state.statics[pid]
        w = b.t - a.t
        rate = w > 0.05

        def per_s(x: int | None, y: int | None, w=w, rate=rate) -> float | None:
            if not rate or x is None or y is None:
                return None
            return round((y - x) / w, 1)

        fds, lim = _fd_info(proc_root, pid)
        cg_key = state.cgroup_of_pid.get(pid)
        if fds is None or b.read_bytes is None:
            state.partially_unreadable += 1
        k8s = cg.parse_kubepods_path(s.cgroup_path or "")
        run = (b.run_ns - a.run_ns) if a.run_ns is not None and b.run_ns is not None else None
        wait = (b.wait_ns - a.wait_ns) if a.wait_ns is not None and b.wait_ns is not None else None
        metrics: dict[str, Any] = {
            "cpu_percent_on_cpu": _r(((b.utime + b.stime) - (a.utime + a.stime)) / hz / w * 100, 1)
            if rate
            else None,
            "rss_bytes": b.rss_pages * PAGE_SIZE,
            "rss_growth_bytes_per_s": _r((b.rss_pages - a.rss_pages) * PAGE_SIZE / w, 0)
            if rate
            else None,
            "threads": b.threads,
            "nonvoluntary_switches_per_s": per_s(a.nonvol, b.nonvol),
            "voluntary_switches_per_s": per_s(a.vol, b.vol),
            "runqueue_wait_ratio": _r(wait / run) if rate and run and wait is not None else None,
            "iowait_seconds": _r((b.blkio - a.blkio) / hz)
            if rate and delayacct is not False and a.blkio is not None and b.blkio is not None
            else None,
            "open_fds": fds,
            "fd_limit_used_pct": _r(fds / lim * 100, 1) if fds is not None and lim else None,
            "read_bytes_per_s": per_s(a.read_bytes, b.read_bytes),
            "write_bytes_per_s": per_s(a.write_bytes, b.write_bytes),
            "uptime_s": _r(uptime - s.starttime_ticks / hz, 1) if uptime is not None else None,
            "cfs_throttled_ratio": cg_ratio[cg_key][0] if cg_key in cg_ratio else None,
        }
        rows.append(
            {
                "pid": pid,
                "ppid": s.ppid,
                "comm": s.comm,
                "exe": s.exe,
                "cmdline": redact_cmdline(s.cmdline, MAX_CMDLINE),
                "user": _user_name(s.uid, users),
                "uid": s.uid,
                "state": s.state,
                "is_python_by_name": is_python_static(s, proc_root, False),
                "is_this_server": pid == me,
                "kernel_thread": s.kernel_thread,
                "cgroup": s.cgroup_path,
                "kubernetes": k8s,
                "threads_truncated": b.threads_truncated,
                "metrics": metrics,
            }
        )
    return rows, reasons


def describe_skips(state: ScanState) -> dict[str, int]:
    return {
        "exited_during_scan": state.skipped_exited,
        "rows_with_unreadable_fields": state.partially_unreadable,
    }


def collect_statics(proc_root: Path) -> ScanState:
    state = ScanState(proc_root)
    with _Cost(state):
        for pid in _list_pids(proc_root):
            s = _read_static(proc_root, pid)
            if s is None:
                state.skipped_exited += 1
                continue
            state.statics[pid] = s
    return state


def _cost(state: ScanState) -> dict[str, Any]:
    return {
        "processes_seen": len(state.statics),
        "sampling_passes": state.samples,
        "sampling_wall_seconds": round(state.sample_wall_s, 4),
        "sampling_cpu_seconds": round(state.sample_cpu_s, 4),
        "note": "time spent reading /proc in this call, excluding the window's sleeps",
    }


def _window(window_s: float, cap: float) -> float:
    if window_s < 0:
        raise SearchError("window_s must be zero or positive")
    return min(window_s, cap)


async def find_processes(
    proc_root: Path,
    filters: Filters,
    *,
    sort_by: str | None,
    descending: bool,
    limit: int,
    window_s: float,
    window_cap: float,
    cgroup_root: Path | None,
) -> dict[str, Any]:
    if sort_by is not None and sort_by not in METRICS:
        raise SearchError(f"sort_by must be one of {', '.join(METRICS)}")
    filters.prepare()
    w = _window(window_s, window_cap)
    state = collect_statics(proc_root)
    pids = apply_filters(state.statics, filters, proc_root)
    cgroups = await sample_all(
        proc_root, pids, w, state, want_cgroups=True, cgroup_root=cgroup_root
    )
    rows, reasons = build_rows(state, cgroups, proc_root, pf.read_task_delayacct(proc_root))
    if w == 0:
        for name, is_rate in METRICS.items():
            if is_rate:
                reasons.setdefault(name, "window_s=0: rates need a window")
    key = sort_by or ("cpu_percent_on_cpu" if w > 0 else "rss_bytes")

    def sort_key(row: dict[str, Any]) -> tuple[int, float]:
        v = row["metrics"].get(key)
        return (0, 0.0) if v is None else (1, v if descending else -v)

    rows.sort(key=sort_key, reverse=True)
    return {
        "measurement": {"window_s": w, "window_requested_s": window_s},
        "sorted_by": key,
        "descending": descending,
        "matched": len(rows),
        "processes": rows[:limit],
        "metric_unavailable_reasons": reasons,
        "skipped": describe_skips(state),
        "cost": _cost(state),
    }


def _compact(row: dict[str, Any], metric: str) -> dict[str, Any]:
    k8s = row.get("kubernetes") or {}
    return {
        "pid": row["pid"],
        "comm": row["comm"],
        "value": row["metrics"][metric],
        "cmdline": row["cmdline"][:120],
        "cgroup": row["cgroup"],
        "pod_uid": k8s.get("pod_uid"),
        "container_id": (k8s.get("container_id") or "")[:12] or None,
    }


async def scan_processes(
    proc_root: Path,
    *,
    window_s: float,
    window_cap: float,
    limit_per_metric: int,
    fd_threshold_pct: float,
    include_kernel_threads: bool,
    cgroup_root: Path | None,
) -> dict[str, Any]:
    w = _window(window_s, window_cap)
    if w <= 0:
        raise SearchError("scan_processes needs window_s > 0")
    state = collect_statics(proc_root)
    filters = Filters(include_kernel_threads=include_kernel_threads)
    pids = apply_filters(state.statics, filters, proc_root)
    cgroups = await sample_all(
        proc_root, pids, w, state, want_cgroups=True, cgroup_root=cgroup_root
    )
    rows, reasons = build_rows(state, cgroups, proc_root, pf.read_task_delayacct(proc_root))
    by_metric: dict[str, list[dict[str, Any]]] = {}
    for metric in METRICS:
        ranked = sorted(
            (row for row in rows if row["metrics"].get(metric)),
            key=lambda row, m=metric: row["metrics"][m],
            reverse=True,
        )
        by_metric[metric] = [_compact(row, metric) for row in ranked[:limit_per_metric]]

    facts: dict[str, Any] = {}
    row_by_pid = {row["pid"]: row for row in rows}
    samples = SCAN_TICKS + 2
    facts["disk_wait_whole_window"] = {
        "definition": f"threads in state D in all {samples} samples of the window",
        "rows": [
            {
                "pid": pid,
                "comm": state.statics[pid].comm,
                "threads_in_disk_wait": len(tids),
                "tids": sorted(tids)[:10],
            }
            for pid, tids in sorted(state.d_all_window.items())
            if tids and pid in row_by_pid
        ][:MAX_FACT_ROWS],
    }
    zombies: dict[int, list[int]] = defaultdict(list)
    for pid, s in state.statics.items():
        if s.state == "Z":
            zombies[s.ppid].append(pid)
    facts["zombies_by_parent"] = {
        "definition": "processes in state Z, grouped by parent pid",
        "rows": [
            {
                "parent_pid": ppid,
                "parent_comm": state.statics[ppid].comm if ppid in state.statics else None,
                "zombie_count": len(kids),
                "zombie_pids": sorted(kids)[:10],
            }
            for ppid, kids in sorted(zombies.items(), key=lambda kv: -len(kv[1]))
        ][:MAX_FACT_ROWS],
    }
    facts["fd_usage_above_threshold"] = {
        "definition": f"open fds above {fd_threshold_pct:g}% of the soft RLIMIT_NOFILE",
        "threshold_pct": fd_threshold_pct,
        "rows": [
            {
                "pid": row["pid"],
                "comm": row["comm"],
                "open_fds": row["metrics"]["open_fds"],
                "fd_limit_used_pct": row["metrics"]["fd_limit_used_pct"],
            }
            for row in sorted(
                rows, key=lambda row: row["metrics"]["fd_limit_used_pct"] or 0, reverse=True
            )
            if (row["metrics"]["fd_limit_used_pct"] or 0) > fd_threshold_pct
        ][:MAX_FACT_ROWS],
    }
    growing = []
    for pid, series in state.rss_series.items():
        if (
            pid in row_by_pid
            and len(series) >= 3
            and all(y > x for x, y in itertools.pairwise(series))
        ):
            growing.append(
                {
                    "pid": pid,
                    "comm": state.statics[pid].comm,
                    "rss_samples": len(series),
                    "rss_start_bytes": series[0] * PAGE_SIZE,
                    "rss_end_bytes": series[-1] * PAGE_SIZE,
                    "rss_growth_bytes_per_s": row_by_pid[pid]["metrics"]["rss_growth_bytes_per_s"],
                }
            )
    growing.sort(key=lambda g: -(g["rss_growth_bytes_per_s"] or 0))
    facts["rss_grew_every_sample"] = {
        "definition": f"RSS strictly increased between each of the {samples} samples",
        "rows": growing[:MAX_FACT_ROWS],
    }
    throttled = []
    ooms = []
    for entry in cgroups.values():
        loc = entry.location
        assert loc is not None
        p = (entry.b.get("nr_periods") or 0) - (entry.a.get("nr_periods") or 0)
        t = (entry.b.get("nr_throttled") or 0) - (entry.a.get("nr_throttled") or 0)
        tu_a, tu_b = entry.a.get("throttled_usec"), entry.b.get("throttled_usec")
        if t > 0:
            throttled.append(
                {
                    "cgroup": loc.path,
                    "kubernetes": cg.parse_kubepods_path(loc.path),
                    "nr_periods": p,
                    "nr_throttled": t,
                    "cfs_throttled_ratio": round(t / p, 4) if p else None,
                    "throttled_seconds": round((tu_b - tu_a) / 1e6, 4)
                    if tu_a is not None and tu_b is not None
                    else None,
                    "pids": sorted(entry.pids)[:10],
                }
            )
        if entry.oom_b and entry.oom_b.get("oom_kill"):
            ooms.append(
                {
                    "cgroup": loc.path,
                    "oom_kill_total": entry.oom_b.get("oom_kill"),
                    "oom_kill_in_window": entry.oom_b.get("oom_kill", 0)
                    - (entry.oom_a or {}).get("oom_kill", 0),
                    "pids": sorted(entry.pids)[:10],
                }
            )
    throttled.sort(key=lambda x: -x["nr_throttled"])
    facts["cgroups_throttled_in_window"] = {
        "definition": "cgroups (of scanned processes) whose nr_throttled rose in the window",
        "rows": throttled[:MAX_FACT_ROWS],
    }
    facts["oom_kill_counters"] = {
        "definition": "cgroups whose memory.events oom_kill counter is above 0 (cumulative)",
        "rows": ooms[:MAX_FACT_ROWS],
        "note": "read from cgroup v2 memory.events; not available for cgroup v1 memory",
    }
    return {
        "measurement": {"window_s": w, "window_requested_s": window_s, "samples": samples},
        "processes_scanned": len(rows),
        "outliers_by_metric": by_metric,
        "conditions": facts,
        "metric_unavailable_reasons": reasons,
        "skipped": describe_skips(state),
        "cost": _cost(state),
    }
