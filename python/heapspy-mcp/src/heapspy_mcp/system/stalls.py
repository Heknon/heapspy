"""Per-thread memory-stall sampling for ``watch_process_stalls``.

Over a window, every thread of a process is sampled at a fixed rate: its
state letter, minor and major fault counts and ``utime + stime`` from
``/proc/<pid>/task/<tid>/stat``, its ``wchan``, and (as root) its kernel stack
from ``/proc/<pid>/task/<tid>/stack``. Each sample gets a wait category from
:mod:`heapspy_mcp.system.wait_categories`.

A *no-progress interval* is a run of consecutive samples in which the
thread's CPU time (``utime + stime``, in clock ticks) did not advance and the
thread was not voluntarily idle (futex, poll, nanosleep, IPC waits). Its
dominant category says where it was held: page-fault I/O and reclaim point at
memory, ``stopped_or_frozen`` at a signal stop or the freezer, ``running`` at
a runnable thread that got no CPU.

The process-level reads (its fault counters, RSS and swap, its memory cgroup,
freezer state, host memory PSI and ``/proc/vmstat``, delay accounting) are
taken at the start and the end of the window.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio

from . import cgroups as cg
from . import procfs as pf
from . import taskstats as tstats
from . import wait_categories as wc
from .sampling import ProcessGone, list_tids
from .views import _psi_block as psi_window
from .views import r

DEFAULT_RATE_HZ = 20.0
MAX_RATE_HZ = 100.0
DEFAULT_STALL_WINDOW = 5.0
MAX_STALL_THREADS = 64
MAX_THREAD_ROWS = 20
MAX_PROCESS_INTERVALS = 10
MAX_THREAD_INTERVALS = 3
MAX_EXAMPLE_FRAMES = 8
MAX_UNKNOWN_FRAMES = 10

VMSTAT_KEYS = (
    "pgmajfault",
    "pgfault",
    "workingset_refault_anon",
    "workingset_refault_file",
    "workingset_refault",
    "pgscan_direct",
    "pgscan_kswapd",
    "pgsteal_direct",
    "pswpin",
    "pswpout",
    "compact_stall",
    "oom_kill",
)
DELAY_FIELDS = (
    "thrashing_delay_total_ns",
    "swapin_delay_total_ns",
    "freepages_delay_total_ns",
    "blkio_delay_total_ns",
    "compact_delay_total_ns",
    "cpu_delay_total_ns",
)
DELAYACCT_OFF = (
    "delay accounting is off (kernel.task_delayacct=0). Enable it with "
    "'sysctl kernel.task_delayacct=1' or the 'delayacct' boot option; this server never "
    "changes it"
)


# --- samples --------------------------------------------------------------------


@dataclass
class TSample:
    t: float
    state: str
    minflt: int
    majflt: int
    cpu_ticks: int
    utime: int
    stime: int
    wchan: str | None
    frames: list[str] | None
    category: str
    matched: str | None


@dataclass
class ThreadTrack:
    tid: int
    comm: str
    samples: list[TSample] = field(default_factory=list)


def stack_access(proc_root: Path, pid: int) -> str | None:
    """None if ``/proc/<pid>/stack`` is readable, else why not."""
    try:
        with open(proc_root / str(pid) / "stack", encoding="utf-8", errors="replace") as f:
            f.read()
    except PermissionError:
        return (
            "/proc/<tid>/stack needs root (CAP_SYS_ADMIN); categories come from wchan, "
            "so page or folio lock waits are told apart only by a rise in major faults"
        )
    except FileNotFoundError:
        return "/proc/<tid>/stack is not present (kernel without CONFIG_STACKTRACE)"
    except OSError as e:
        return f"/proc/<tid>/stack is not readable: {e}"
    return None


@dataclass
class StallSampler:
    proc_root: Path
    pid: int
    max_threads: int = MAX_STALL_THREADS
    read_stacks: bool = True
    tracks: dict[int, ThreadTrack] = field(default_factory=dict)
    ticks: int = 0
    late_ticks: int = 0
    threads_seen: int = 0
    threads_total_max: int = 0
    truncated: bool = False
    cpu_s: float = 0.0
    first_t: float | None = None
    last_t: float | None = None
    gone: bool = False

    def tick(self) -> None:
        c0 = time.process_time()
        base = self.proc_root / str(self.pid) / "task"
        tids = list_tids(self.proc_root, self.pid)
        if not tids and not (self.proc_root / str(self.pid)).exists():
            self.gone = True
            return
        self.threads_total_max = max(self.threads_total_max, len(tids))
        if len(tids) > self.max_threads:
            self.truncated = True
            # Keep threads already followed, then fill with the lowest tids.
            known = [t for t in tids if t in self.tracks]
            tids = (known + [t for t in tids if t not in self.tracks])[: self.max_threads]
        now = time.monotonic()
        self.first_t = self.first_t if self.first_t is not None else now
        self.last_t = now
        self.ticks += 1
        for tid in tids:
            d = base / str(tid)
            text = pf.read_text(d / "stat")
            if text is None:
                continue
            try:
                st = pf.parse_pid_stat(text)
            except (ValueError, IndexError):
                continue
            wchan_text = pf.read_text(d / "wchan")
            wchan = pf.parse_wchan(wchan_text)
            frames = None
            if self.read_stacks:
                raw = pf.read_text(d / "stack")
                frames = pf.parse_stack(raw) if raw is not None else None
            track = self.tracks.get(tid)
            if track is None:
                track = self.tracks[tid] = ThreadTrack(tid, st.comm)
            prev = track.samples[-1] if track.samples else None
            faulted = prev is not None and st.majflt > prev.majflt
            if frames is not None and (frames or st.state == "R"):
                c = wc.classify_stack(frames, st.state)
            else:
                c = wc.classify_wchan(wchan, st.state, faulted, wchan_text is not None)
            track.samples.append(
                TSample(
                    t=now,
                    state=st.state,
                    minflt=st.minflt,
                    majflt=st.majflt,
                    cpu_ticks=st.utime_ticks + st.stime_ticks,
                    utime=st.utime_ticks,
                    stime=st.stime_ticks,
                    wchan=wchan,
                    frames=frames[:MAX_EXAMPLE_FRAMES] if frames is not None else None,
                    category=c.category,
                    matched=c.matched_frame,
                )
            )
        self.threads_seen = len(self.tracks)
        self.cpu_s += time.process_time() - c0

    async def run(self, window_s: float, rate_hz: float) -> None:
        period = 1.0 / rate_hz
        n = max(2, round(window_s * rate_hz) + 1)
        t0 = anyio.current_time()
        for k in range(n):
            target = t0 + k * period
            delay = target - anyio.current_time()
            if delay > 0:
                await anyio.sleep(delay)
            elif k:
                self.late_ticks += 1
            self.tick()
            if self.gone:
                break


# --- intervals ------------------------------------------------------------------


@dataclass
class Interval:
    tid: int
    comm: str
    start: float
    end: float
    samples: list[TSample]
    open_at_start: bool
    open_at_end: bool

    @property
    def duration(self) -> float:
        return self.end - self.start


def no_progress_intervals(track: ThreadTrack) -> list[Interval]:
    """Runs of consecutive samples with no CPU-time advance and no voluntary idle."""
    s = track.samples
    out: list[Interval] = []
    i = 1
    while i < len(s):
        if s[i].cpu_ticks == s[i - 1].cpu_ticks and s[i].category not in wc.VOLUNTARY_IDLE:
            j = i
            while (
                j + 1 < len(s)
                and s[j + 1].cpu_ticks == s[j].cpu_ticks
                and s[j + 1].category not in wc.VOLUNTARY_IDLE
            ):
                j += 1
            out.append(
                Interval(
                    track.tid,
                    track.comm,
                    s[i - 1].t,
                    s[j].t,
                    s[i : j + 1],
                    open_at_start=i == 1,
                    open_at_end=j == len(s) - 1,
                )
            )
            i = j + 1
        else:
            i += 1
    return out


def _dominant(samples: list[TSample]) -> tuple[str, Counter[str]]:
    counts = Counter(x.category for x in samples)
    return counts.most_common(1)[0][0], counts


def interval_view(iv: Interval, t0: float) -> dict[str, Any]:
    dom, counts = _dominant(iv.samples)
    stacks = Counter(
        tuple(x.frames) for x in iv.samples if x.category == dom and x.frames
    ).most_common(1)
    wchans = Counter(x.wchan for x in iv.samples if x.category == dom and x.wchan).most_common(1)
    majflt = iv.samples[-1].majflt - iv.samples[0].majflt
    return {
        "tid": iv.tid,
        "comm": iv.comm,
        "start_offset_s": r(iv.start - t0),
        "duration_s": r(iv.duration),
        "samples": len(iv.samples),
        "dominant_category": dom,
        "samples_by_category": dict(counts.most_common()),
        "states": dict(Counter(x.state for x in iv.samples).most_common()),
        "major_faults": majflt,
        "example_stack": list(stacks[0][0]) if stacks else None,
        "example_wchan": wchans[0][0] if wchans else None,
        "began_before_window": iv.open_at_start,
        "still_open_at_window_end": iv.open_at_end,
    }


# --- per-thread and per-process summaries --------------------------------------


def _shares(counter: Counter[str], total: int) -> dict[str, float | None]:
    return {k: r(v / total) for k, v in counter.most_common()} if total else {}


def thread_view(track: ThreadTrack, ivs: list[Interval], t0: float) -> dict[str, Any]:
    s = track.samples
    span = s[-1].t - s[0].t if len(s) > 1 else 0.0
    hz = pf.USER_HZ
    cats = Counter(x.category for x in s)
    states = Counter(x.state for x in s)
    stalled = sum(iv.duration for iv in ivs)
    return {
        "tid": track.tid,
        "comm": track.comm,
        "samples": len(s),
        "state_share": _shares(states, len(s)),
        "category_share": _shares(cats, len(s)),
        "major_faults_per_s": r((s[-1].majflt - s[0].majflt) / span, 1) if span else None,
        "minor_faults_per_s": r((s[-1].minflt - s[0].minflt) / span, 1) if span else None,
        "cpu_seconds_user": r((s[-1].utime - s[0].utime) / hz),
        "cpu_seconds_system": r((s[-1].stime - s[0].stime) / hz),
        "no_progress_seconds": r(stalled),
        "no_progress_share": r(stalled / span) if span else None,
        "longest_no_progress_intervals": [
            interval_view(iv, t0)
            for iv in sorted(ivs, key=lambda x: -x.duration)[:MAX_THREAD_INTERVALS]
        ],
    }


def summarize(sampler: StallSampler) -> dict[str, Any]:
    """Thread rows, process totals and the longest no-progress intervals."""
    t0 = sampler.first_t or 0.0
    span = (sampler.last_t or t0) - t0
    all_ivs: list[Interval] = []
    rows = []
    cats: Counter[str] = Counter()
    states: Counter[str] = Counter()
    unknown: Counter[str] = Counter()
    matched: dict[str, Counter[str]] = {}
    total = 0
    stalled_by_cat: Counter[str] = Counter()
    for track in sampler.tracks.values():
        if not track.samples:
            continue
        ivs = no_progress_intervals(track)
        all_ivs.extend(ivs)
        for iv in ivs:
            stalled_by_cat[_dominant(iv.samples)[0]] += iv.duration
        rows.append(thread_view(track, ivs, t0))
        for x in track.samples:
            total += 1
            cats[x.category] += 1
            states[x.state] += 1
            if x.category == "other" and x.frames:
                unknown[" < ".join(x.frames[: wc.MAX_UNKNOWN_FRAMES])] += 1
            if x.matched:
                matched.setdefault(x.category, Counter())[x.matched] += 1
    rows.sort(key=lambda row: (-(row["no_progress_seconds"] or 0), row["tid"]))
    idle = sum(v for k, v in cats.items() if k in wc.VOLUNTARY_IDLE)
    active = total - idle
    mem = sum(v for k, v in cats.items() if k in wc.MEMORY_STALL)
    ticks = max(sampler.ticks, 1)
    return {
        "thread_samples": total,
        "state_share": _shares(states, total),
        "category_share": _shares(cats, total),
        "mean_threads_by_category": {k: r(v / ticks, 2) for k, v in cats.most_common()},
        "active_thread_samples": active,
        "category_share_of_active": _shares(
            Counter({k: v for k, v in cats.items() if k not in wc.VOLUNTARY_IDLE}), active
        ),
        "memory_stall_share_of_active": r(mem / active) if active else None,
        "memory_stall_categories": sorted(wc.MEMORY_STALL),
        "no_progress_seconds_by_category": {k: r(v) for k, v in stalled_by_cat.most_common()},
        "memory_stall_no_progress_seconds_per_s": r(
            sum(v for k, v in stalled_by_cat.items() if k in wc.MEMORY_STALL) / span
        )
        if span
        else None,
        "longest_no_progress_intervals": [
            interval_view(iv, t0)
            for iv in sorted(all_ivs, key=lambda x: -x.duration)[:MAX_PROCESS_INTERVALS]
        ],
        "matched_frames_by_category": {
            k: dict(v.most_common(5)) for k, v in sorted(matched.items())
        },
        "unclassified_stacks": [
            {"frames_innermost_first": k, "samples": v}
            for k, v in unknown.most_common(MAX_UNKNOWN_FRAMES)
        ],
        "threads": rows,
    }


# --- process, cgroup and host reads -----------------------------------------------


@dataclass
class Endpoint:
    """Cumulative values read at the start or the end of the window."""

    t: float
    stat: pf.PidStat | None
    memory: dict[str, Any] | None
    vmstat: dict[str, int] | None
    host_psi_memory: dict[str, dict[str, float]] | None
    delay: dict[str, Any] | None
    delay_reason: str | None


def _delay(pid: int, enabled: bool | None) -> tuple[dict[str, Any] | None, str | None]:
    if enabled is False:
        return None, DELAYACCT_OFF
    try:
        return tstats.read_tgid(pid), None
    except tstats.TaskstatsError as e:
        return None, str(e)


def read_endpoint(
    proc_root: Path,
    pid: int,
    mem_loc: cg.MemoryLocation | None,
    host: bool,
    delayacct: bool | None,
) -> Endpoint:
    text = pf.read_text(proc_root / str(pid) / "stat")
    stat = None
    if text is not None:
        try:
            stat = pf.parse_pid_stat(text)
        except (ValueError, IndexError):
            stat = None
    vm = psi = None
    if host:
        vm_text = pf.read_text(proc_root / "vmstat")
        vm = pf.parse_vmstat(vm_text) if vm_text else None
        psi_text = pf.read_text(proc_root / "pressure" / "memory")
        psi = pf.parse_psi(psi_text) if psi_text else None
    delay, reason = _delay(pid, delayacct) if stat is not None else (None, "process exited")
    return Endpoint(
        t=time.monotonic(),
        stat=stat,
        memory=cg.read_memory(mem_loc) if mem_loc is not None else None,
        vmstat=vm,
        host_psi_memory=psi,
        delay=delay,
        delay_reason=reason,
    )


def _delta(a: dict[str, Any] | None, b: dict[str, Any] | None, key: str) -> int | None:
    x = (a or {}).get(key)
    y = (b or {}).get(key)
    return None if x is None or y is None else y - x


def cgroup_memory_view(
    loc: cg.MemoryLocation | None, reason: str | None, a: Endpoint, b: Endpoint
) -> dict[str, Any]:
    if loc is None or a.memory is None or b.memory is None:
        return {"available": False, "reason": reason or "memory cgroup not found"}
    w = max(b.t - a.t, 1e-9)
    ma, mb = a.memory, b.memory
    usage = mb.get("usage_bytes")
    mx, hi = mb.get("max_bytes"), mb.get("high_bytes")
    stat_d = {k: _delta(ma["stat"], mb["stat"], k) for k in mb["stat"] if k in cg.MEMORY_STAT_KEYS}
    refault = [
        v
        for k, v in stat_d.items()
        if k in ("workingset_refault_anon", "workingset_refault_file", "workingset_refault")
        and v is not None
    ]
    unavailable = dict(mb.get("unavailable") or {})
    limits = cg.memory_limits(loc)
    tight_max = min((lv["max_bytes"] for lv in limits if lv["max_bytes"]), default=None)
    tight_high = min((lv["high_bytes"] for lv in limits if lv["high_bytes"]), default=None)
    return {
        "available": True,
        "cgroup_version": loc.version,
        "path": loc.path,
        "usage_bytes": usage,
        "max_bytes": mx,
        "high_bytes": hi,
        "swap_usage_bytes": mb.get("swap_usage_bytes"),
        "usage_to_max_ratio": r(usage / mx) if usage is not None and mx else None,
        "usage_to_high_ratio": r(usage / hi) if usage is not None and hi else None,
        "limits": limits,
        "tightest_max_bytes": tight_max,
        "tightest_high_bytes": tight_high,
        "under_oom": mb.get("under_oom"),
        "events_in_window": {k: _delta(ma["events"], mb["events"], k) for k in mb["events"]},
        "events_total": mb["events"],
        "stat_delta": stat_d,
        "stat_per_s": {k: r(v / w, 1) if v is not None else None for k, v in stat_d.items()},
        "refaults_per_s": r(sum(refault) / w, 1) if refault else None,
        "levels_bytes": {k: v for k, v in mb["stat"].items() if k in cg.MEMORY_STAT_LEVELS},
        "pressure": psi_window(ma.get("pressure"), mb.get("pressure"), w),
        "pressure_dir": str(loc.pressure_dir) if loc.pressure_dir else None,
        "notes": loc.notes,
        "unavailable": unavailable,
    }


def host_memory_view(a: Endpoint, b: Endpoint, proc_root: Path) -> dict[str, Any]:
    w = max(b.t - a.t, 1e-9)
    unavailable: dict[str, str] = {}
    out: dict[str, Any] = {}
    if a.vmstat is not None and b.vmstat is not None:
        deltas = {k: _delta(a.vmstat, b.vmstat, k) for k in VMSTAT_KEYS if k in b.vmstat}
        alloc = [_delta(a.vmstat, b.vmstat, k) for k in b.vmstat if k.startswith("allocstall_")]
        if alloc and all(v is not None for v in alloc):
            deltas["allocstall_total"] = sum(v for v in alloc if v is not None)
        out["vmstat_delta"] = deltas
        out["vmstat_per_s"] = {k: r(v / w, 1) if v is not None else None for k, v in deltas.items()}
        refault = [
            deltas[k]
            for k in ("workingset_refault_anon", "workingset_refault_file", "workingset_refault")
            if deltas.get(k) is not None
        ]
        out["refaults_per_s"] = r(sum(v for v in refault if v is not None) / w, 1)
    else:
        out["vmstat_delta"] = None
        unavailable["vmstat"] = "/proc/vmstat unreadable"
    out["psi_memory"] = psi_window(a.host_psi_memory, b.host_psi_memory, w)
    if out["psi_memory"] is None:
        unavailable["psi_memory"] = "/proc/pressure/memory missing (CONFIG_PSI off or psi=0)"
    mi = pf.read_text(proc_root / "meminfo")
    out["meminfo_bytes"] = pf.parse_kb_fields(mi, pf.MEMINFO_KEYS) if mi else None
    if out["meminfo_bytes"] is not None and out["meminfo_bytes"].get("SwapTotal") == 0:
        out["swap_note"] = (
            "no swap is configured: anonymous memory cannot be paged out, so refaults are "
            "of file-backed pages (including executables and mapped files)"
        )
    out["window_s"] = r(w)
    out["unavailable"] = unavailable
    return out


def delay_view(a: Endpoint, b: Endpoint, delayacct: bool | None) -> dict[str, Any]:
    w = max(b.t - a.t, 1e-9)
    if a.delay is None or b.delay is None:
        reason = b.delay_reason or a.delay_reason or "not measured"
        return {
            "enabled": delayacct,
            "available": False,
            "reason": reason,
            **{k.replace("_total_ns", "_seconds_per_s"): None for k in DELAY_FIELDS},
        }
    out: dict[str, Any] = {"enabled": delayacct, "available": True, "source": "taskstats (TGID)"}
    for k in DELAY_FIELDS:
        d = _delta(a.delay, b.delay, k)
        out[k.replace("_total_ns", "_seconds_per_s")] = r(d / 1e9 / w, 4) if d is not None else None
    out["note"] = (
        "seconds of delay per second of wall time, summed over threads; thrashing is time "
        "waiting for refaulted workingset pages, freepages is direct reclaim"
    )
    return out


def memory_levels(proc_root: Path, pid: int) -> dict[str, Any]:
    base = proc_root / str(pid)
    status = pf.parse_status_memory(pf.read_text(base / "status") or "")
    rollup_text = pf.read_text(base / "smaps_rollup")
    rollup = pf.parse_smaps_rollup(rollup_text) if rollup_text else None
    unavailable = {}
    if rollup is None:
        unavailable["smaps_rollup"] = (
            "/proc/<pid>/smaps_rollup not readable (kernel before 4.14, or no ptrace access)"
        )
    if "VmSwap" not in status:
        unavailable["vm_swap_bytes"] = "VmSwap missing from /proc/<pid>/status"
    return {
        "rss_bytes": status.get("VmRSS"),
        "rss_peak_bytes": status.get("VmHWM"),
        "rss_anon_bytes": status.get("RssAnon"),
        "rss_file_bytes": status.get("RssFile"),
        "vm_swap_bytes": status.get("VmSwap"),
        "smaps_rollup_bytes": {
            "rss": rollup.get("Rss"),
            "pss": rollup.get("Pss"),
            "swap": rollup.get("Swap"),
            "swap_pss": rollup.get("SwapPss"),
        }
        if rollup is not None
        else None,
        "unavailable": unavailable,
    }


def frozen_view(
    freezer: dict[str, Any], summary: dict[str, Any], main_state: str | None
) -> dict[str, Any]:
    """Whether the process is held on purpose: a frozen cgroup or a signal stop."""
    share = (summary["category_share"] or {}).get("stopped_or_frozen") or 0.0
    stopped = (summary["state_share"] or {}).get("T", 0.0) + (summary["state_share"] or {}).get(
        "t", 0.0
    )
    if freezer.get("frozen"):
        assessment = "frozen_by_cgroup_freezer"
    elif stopped >= 0.9:
        assessment = "stopped_by_signal_or_ptrace"
    elif share >= 0.9:
        assessment = "held_in_freezer_or_signal_stop"
    elif share > 0:
        assessment = "partly_stopped_or_frozen"
    else:
        assessment = "not_frozen_or_stopped"
    return {
        "assessment": assessment,
        "cgroup_frozen": freezer.get("frozen"),
        "freezer": freezer,
        "process_state": main_state,
        "stopped_thread_sample_share": r(stopped),
        "stopped_or_frozen_category_share": r(share),
        "note": "a frozen cgroup or a stopped process makes no progress by design; its "
        "no-progress intervals are not evidence of memory stalls",
    }


# --- the tool -----------------------------------------------------------------


async def watch(
    proc_root: Path,
    pid: int,
    window_s: float,
    rate_hz: float,
    *,
    host: bool,
    cgroup_root: Path | None,
    max_threads: int = MAX_STALL_THREADS,
    rate_cap_hz: float = MAX_RATE_HZ,
) -> dict[str, Any]:
    if not (proc_root / str(pid) / "stat").exists():
        raise ProcessGone(f"no process with pid {pid}")
    requested_rate = rate_hz
    rate = min(max(rate_hz, 1.0), rate_cap_hz)
    stack_reason = stack_access(proc_root, pid)
    cgroup_text = pf.read_text(proc_root / str(pid) / "cgroup")
    mounts = cg.discover_mounts(proc_root, cgroup_root)
    pc = cg.parse_pid_cgroup(cgroup_text or "")
    mem_loc = cg.locate_memory(pc, mounts) if cgroup_text else None
    mem_reason = (
        None
        if mem_loc is not None
        else (
            f"cannot read {proc_root}/{pid}/cgroup"
            if cgroup_text is None
            else "no memory controller mount (v1) and no cgroup v2 mount found"
        )
    )
    delayacct = pf.read_task_delayacct(proc_root)
    a = read_endpoint(proc_root, pid, mem_loc, host, delayacct)
    sampler = StallSampler(
        proc_root, pid, max_threads=max_threads, read_stacks=stack_reason is None
    )
    wall0 = time.time()
    await sampler.run(window_s, rate)
    b = read_endpoint(proc_root, pid, mem_loc, host, delayacct)
    if not sampler.tracks:
        raise ProcessGone(f"pid {pid} exited before it could be sampled")
    summary = summarize(sampler)
    w = max(b.t - a.t, 1e-9)
    hz = pf.USER_HZ
    sa, sb = a.stat, b.stat
    unavailable: dict[str, str] = {}
    if stack_reason:
        unavailable["kernel_stacks"] = stack_reason
    process: dict[str, Any] = {}
    if sa is not None and sb is not None:
        user = (sb.utime_ticks - sa.utime_ticks) / hz
        system = (sb.stime_ticks - sa.stime_ticks) / hz
        process["major_faults"] = sb.majflt - sa.majflt
        process["minor_faults"] = sb.minflt - sa.minflt
        process["major_faults_per_s"] = r(process["major_faults"] / w, 1)
        process["minor_faults_per_s"] = r(process["minor_faults"] / w, 1)
        process["cpu_seconds_user"] = r(user)
        process["cpu_seconds_system"] = r(system)
        process["cpu_cores_used"] = r((user + system) / w)
        process["system_share"] = r(system / (user + system)) if user + system > 0 else None
    else:
        unavailable["process_counters"] = "the process exited during the window"
    process.update(
        {k: v for k, v in summary.items() if k not in ("threads",)},
    )
    process["memory"] = memory_levels(proc_root, pid)
    process["delay_accounting"] = delay_view(a, b, delayacct)
    freezer = cg.read_freezer(pc, mounts)
    env: dict[str, Any] = {
        "description": "what this process is subject to: its memory cgroup and, unless "
        "disabled, host-wide memory pressure and reclaim counters over the same window",
        "cgroup_memory": cgroup_memory_view(mem_loc, mem_reason, a, b),
    }
    if host:
        env["host"] = host_memory_view(a, b, proc_root)
    else:
        env["host"] = None
        env["host_unavailable_reason"] = "host context disabled by the server (--no-host-context)"
    threads = summary["threads"]
    return {
        "pid": pid,
        "comm": sb.comm if sb else (sa.comm if sa else None),
        "measurement": {
            "window_s": r(w),
            "window_requested_s": window_s,
            "rate_hz": rate,
            "rate_hz_requested": requested_rate,
            "rate_hz_cap": rate_cap_hz,
            "samples": sampler.ticks,
            "achieved_rate_hz": r(
                (sampler.ticks - 1) / ((sampler.last_t or 0) - (sampler.first_t or 0)), 1
            )
            if sampler.ticks > 1 and sampler.last_t != sampler.first_t
            else None,
            "late_samples": sampler.late_ticks,
            "started_at_unix": round(wall0, 3),
            "threads_sampled": sampler.threads_seen,
            "threads_total_max": sampler.threads_total_max,
            "threads_truncated": sampler.truncated,
            "thread_cap": max_threads,
            "stack_source": "/proc/<tid>/stack" if stack_reason is None else "wchan",
            "cpu_progress_source": "utime+stime from /proc/<pid>/task/<tid>/stat, "
            f"in 1/{hz} s clock ticks",
            "sampling_cpu_seconds": r(sampler.cpu_s, 4),
            "process_exited": sampler.gone or sb is None,
        },
        "frozen_or_stopped": frozen_view(freezer, summary, sb.state if sb else None),
        "process": process,
        "threads": threads[:MAX_THREAD_ROWS],
        "threads_listed": min(len(threads), MAX_THREAD_ROWS),
        "threads_with_samples": len(threads),
        "wait_category_meanings": {
            k: v for k, v in wc.meanings().items() if k in (summary["category_share"] or {})
        },
        "environment": env,
        "unavailable": unavailable,
    }
