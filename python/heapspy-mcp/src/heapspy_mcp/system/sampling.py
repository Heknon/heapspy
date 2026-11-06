"""Cumulative-counter samples of a process, its threads, its cgroup and the host.

A measurement takes a sample at the start of a window, a few cheap samples
inside it (thread states, wait sites, runnable count), and one at the end.
Rates and ratios are computed from the start and end samples in
:mod:`heapspy_mcp.system.views`.
"""

from __future__ import annotations

import os
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import cgroups as cg
from . import procfs as pf

MAX_THREADS = 1024
MAX_WAIT_SITE_THREADS = 256


class ProcessGone(Exception):
    """The process exited or its /proc entry cannot be read."""


@dataclass
class ThreadSample:
    tid: int
    comm: str
    state: str
    utime_ticks: int
    stime_ticks: int
    voluntary: int | None
    nonvoluntary: int | None
    sched: pf.SchedStat | None
    migrations: int | None
    processor: int | None
    blkio_ticks: int | None
    slice_ns: int | None = None
    cpus_allowed: str | None = None


@dataclass
class ProcessSample:
    t: float
    wall: float
    pid: int
    stat: pf.PidStat
    threads: dict[int, ThreadSample]
    threads_total: int
    threads_truncated: bool


def _read_thread(task_dir: Path, tid: int) -> ThreadSample | None:
    stat_text = pf.read_text(task_dir / "stat")
    if stat_text is None:
        return None
    try:
        st = pf.parse_pid_stat(stat_text)
    except (ValueError, IndexError):
        return None
    status = pf.parse_pid_status(pf.read_text(task_dir / "status") or "")
    sched_text = pf.read_text(task_dir / "schedstat")
    mig_text = pf.read_text(task_dir / "sched")
    fields = pf.parse_pid_sched(mig_text) if mig_text else {}
    return ThreadSample(
        tid=tid,
        comm=st.comm,
        state=st.state,
        utime_ticks=st.utime_ticks,
        stime_ticks=st.stime_ticks,
        voluntary=status.get("voluntary_ctxt_switches"),
        nonvoluntary=status.get("nonvoluntary_ctxt_switches"),
        sched=pf.parse_pid_schedstat(sched_text) if sched_text else None,
        migrations=int(fields["se.nr_migrations"]) if "se.nr_migrations" in fields else None,
        processor=st.processor,
        blkio_ticks=st.delayacct_blkio_ticks,
        slice_ns=pf.sched_slice_ns(fields),
        cpus_allowed=status.get("Cpus_allowed_list"),
    )


def list_tids(proc_root: Path, pid: int) -> list[int]:
    try:
        return sorted(int(t) for t in os.listdir(proc_root / str(pid) / "task") if t.isdigit())
    except OSError:
        return []


def sample_process(proc_root: Path, pid: int, max_threads: int = MAX_THREADS) -> ProcessSample:
    base = proc_root / str(pid)
    stat_text = pf.read_text(base / "stat")
    if stat_text is None:
        raise ProcessGone(f"no process with pid {pid}")
    stat = pf.parse_pid_stat(stat_text)
    tids = list_tids(proc_root, pid)
    threads: dict[int, ThreadSample] = {}
    for tid in tids[:max_threads]:
        ts = _read_thread(base / "task" / str(tid), tid)
        if ts is not None:
            threads[tid] = ts
    return ProcessSample(
        t=time.monotonic(),
        wall=time.time(),
        pid=pid,
        stat=stat,
        threads=threads,
        threads_total=len(tids),
        threads_truncated=len(tids) > max_threads,
    )


def thread_states(proc_root: Path, pid: int, cap: int = MAX_THREADS) -> dict[str, Any]:
    """Counts of threads by state bucket from ``/proc/<pid>/task/*/stat``."""
    counts = pf.empty_state_counts()
    tids = list_tids(proc_root, pid)
    for tid in tids[:cap]:
        text = pf.read_text(proc_root / str(pid) / "task" / str(tid) / "stat")
        if text is None:
            continue
        try:
            counts[pf.state_bucket(pf.parse_pid_stat(text).state)] += 1
        except (ValueError, IndexError):
            continue
    return {"counts": counts, "threads_seen": len(tids), "truncated": len(tids) > cap}


@dataclass
class TickAccumulator:
    """In-window samples: thread states, sleeping threads' wait sites, host runnable count."""

    proc_root: Path
    pid: int
    futex_nr: int | None = field(default_factory=pf.futex_syscall_nr)
    ticks: int = 0
    states: Counter[str] = field(default_factory=Counter)
    wait_sites: Counter[str] = field(default_factory=Counter)
    wchans: Counter[str] = field(default_factory=Counter)
    procs_running: list[int] = field(default_factory=list)
    threads_sampled: int = 0
    cpu_s: float = 0.0

    def tick(self, host: bool) -> None:
        c0 = time.process_time()
        try:
            self._tick(host)
        finally:
            self.cpu_s += time.process_time() - c0

    def _tick(self, host: bool) -> None:
        self.ticks += 1
        base = self.proc_root / str(self.pid) / "task"
        tids = list_tids(self.proc_root, self.pid)[:MAX_WAIT_SITE_THREADS]
        self.threads_sampled = max(self.threads_sampled, len(tids))
        for tid in tids:
            d = base / str(tid)
            text = pf.read_text(d / "stat")
            if text is None:
                continue
            try:
                state = pf.parse_pid_stat(text).state
            except (ValueError, IndexError):
                continue
            bucket = pf.state_bucket(state)
            self.states[bucket] += 1
            if bucket in ("sleeping", "disk_wait"):
                wchan = (pf.read_text(d / "wchan") or "").strip()
                nr = pf.parse_syscall_nr(pf.read_text(d / "syscall"))
                site = "block_io" if bucket == "disk_wait" else None
                site = site or pf.classify_wait_site(wchan, nr, self.futex_nr)
                self.wait_sites[site] += 1
                if wchan and wchan != "0":
                    self.wchans[wchan] += 1
        if host:
            ps = pf.read_text(self.proc_root / "stat")
            if ps:
                running = pf.parse_proc_stat(ps).procs_running
                if running is not None:
                    self.procs_running.append(running)


@dataclass
class HostSample:
    t: float
    stat: pf.ProcStat | None
    psi: dict[str, dict[str, dict[str, float]] | None]
    schedstat: pf.ProcSchedStat | None
    schedstat_reason: str | None
    loadavg: dict[str, Any] | None


def sample_host(proc_root: Path) -> HostSample:
    stat_text = pf.read_text(proc_root / "stat")
    psi: dict[str, dict[str, dict[str, float]] | None] = {}
    for res in ("cpu", "memory", "io"):
        text = pf.read_text(proc_root / "pressure" / res)
        psi[res] = pf.parse_psi(text) if text else None
    ss_text = pf.read_text(proc_root / "schedstat")
    schedstat = None
    reason = None
    if ss_text is None:
        reason = "/proc/schedstat is not present (kernel built without CONFIG_SCHEDSTATS)"
    else:
        schedstat = pf.parse_proc_schedstat(ss_text)
        if schedstat.note:
            reason, schedstat = schedstat.note, None
    la = pf.read_text(proc_root / "loadavg")
    return HostSample(
        t=time.monotonic(),
        stat=pf.parse_proc_stat(stat_text) if stat_text else None,
        psi=psi,
        schedstat=schedstat,
        schedstat_reason=reason,
        loadavg=pf.parse_loadavg(la) if la else None,
    )


@dataclass
class CgroupSample:
    t: float
    location: cg.CgroupLocation
    stats: dict[str, dict[str, int | None]]  # directory -> counters
    limits: dict[str, dict[str, Any] | None]
    pressure: dict[str, dict[str, dict[str, float]] | None]


def locate_cgroup(
    proc_root: Path, pid: int, cgroup_root: Path | None
) -> tuple[cg.CgroupLocation | None, str | None]:
    text = pf.read_text(proc_root / str(pid) / "cgroup")
    if text is None:
        return None, f"cannot read {proc_root}/{pid}/cgroup"
    mounts = cg.discover_mounts(proc_root, cgroup_root)
    loc = cg.locate(cg.parse_pid_cgroup(text), mounts)
    if loc is None:
        return None, "no cgroup v2 mount and no cgroup v1 cpu mount found"
    return loc, None


def sample_cgroup(loc: cg.CgroupLocation) -> CgroupSample:
    dirs = cg.limited_ancestors(loc)
    return CgroupSample(
        t=time.monotonic(),
        location=loc,
        stats={str(d): cg.read_cpu_stat(loc, d) for d in dirs},
        limits={str(d): cg.read_limit(loc, d) for d in dirs},
        pressure=cg.read_pressure(loc),
    )


def identify(proc_root: Path, pid: int) -> dict[str, Any]:
    """Name, executable and command line of a pid, for the allowlist check."""
    base = proc_root / str(pid)
    stat_text = pf.read_text(base / "stat")
    if stat_text is None:
        raise ProcessGone(f"no process with pid {pid}")
    name = pf.parse_pid_stat(stat_text).comm
    try:
        exe: str | None = os.readlink(base / "exe")
    except OSError:
        exe = None
    raw = pf.read_text(base / "cmdline")
    cmdline = [a for a in raw.split("\0") if a] if raw else None
    return {"name": name, "exe": exe, "cmdline": cmdline}
