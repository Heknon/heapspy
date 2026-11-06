"""Which tasks share CPUs with a target over a window (``cpu_colocation``).

Over the window, every task on the host that runs is sampled at a fixed rate
for its state and the CPU it last ran on (``/proc/<pid>/task/<tid>/stat`` field
39). For a runnable task that CPU is the run queue it waits on. Counters are
read at the start and the end of the window: voluntary and non-voluntary
switches from ``status``, on-CPU time, run-queue wait and timeslice count
(``pcount``) from ``schedstat``, and ``se.slice`` from ``sched`` where the
kernel has it.

Each task's rates are spread over the CPUs in proportion to its samples on
each, which gives per-CPU totals: switches, wakeups, on-CPU time and the mean
number of runnable tasks. A task's voluntary switches are taken as its
wakeups: every voluntary switch is a sleep, and every sleep ends in a wakeup.

Which co-located task preempted which is not traced. The attribution in the
result is an inference from rates on the same CPU over the same window, and it
is labelled as such.

The host pass reads the same per-task files as ``ps``. Tasks that never ran in
the window are left out after the first pass. Costs are bounded and reported.
"""

from __future__ import annotations

import math
import os
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio

from . import procfs as pf

DEFAULT_RATE_HZ = 50.0
MAX_HOST_TASKS = 8192
MAX_ACTIVE_TASKS = 512
MAX_TASK_SAMPLES_PER_S = 20000.0
RESCAN_S = 0.5
MAX_COLOCATED_ROWS = 10
MAX_TARGET_ROWS = 64
# A short sleeper wakes often and sleeps briefly each time: the kind of task whose
# wakeups preempt a CPU-bound task sharing its CPU.
SHORT_SLEEP_US = 1000.0
SHORT_SLEEPER_MIN_WAKEUPS_PER_S = 100.0


@dataclass
class TaskCounters:
    t: float
    pid: int
    tid: int
    comm: str
    state: str
    processor: int | None
    cpu_ticks: int
    run_ns: int | None
    wait_ns: int | None
    slices: int | None
    vol: int | None
    nonvol: int | None
    cpus_allowed: str | None = None
    slice_ns: int | None = None


def read_task(proc_root: Path, pid: int, tid: int, *, full: bool) -> TaskCounters | None:
    d = proc_root / str(pid) / "task" / str(tid)
    text = pf.read_text(d / "stat")
    if text is None:
        return None
    try:
        st = pf.parse_pid_stat(text)
    except (ValueError, IndexError):
        return None
    ss = pf.parse_pid_schedstat(pf.read_text(d / "schedstat") or "")
    status = pf.parse_pid_status(pf.read_text(d / "status") or "")
    slice_ns = None
    if full:
        sched = pf.read_text(d / "sched")
        slice_ns = pf.sched_slice_ns(pf.parse_pid_sched(sched)) if sched else None
    return TaskCounters(
        t=time.monotonic(),
        pid=pid,
        tid=tid,
        comm=st.comm,
        state=st.state,
        processor=st.processor,
        cpu_ticks=st.utime_ticks + st.stime_ticks,
        run_ns=ss.run_ns if ss else None,
        wait_ns=ss.wait_ns if ss else None,
        slices=ss.timeslices if ss else None,
        vol=status.get("voluntary_ctxt_switches"),
        nonvol=status.get("nonvoluntary_ctxt_switches"),
        cpus_allowed=status.get("Cpus_allowed_list"),
        slice_ns=slice_ns,
    )


def list_tasks(proc_root: Path, cap: int) -> tuple[list[tuple[int, int]], bool]:
    out: list[tuple[int, int]] = []
    try:
        pids = sorted(int(p) for p in os.listdir(proc_root) if p.isdigit())
    except OSError:
        return out, False
    for pid in pids:
        try:
            tids = sorted(int(t) for t in os.listdir(proc_root / str(pid) / "task") if t.isdigit())
        except OSError:
            continue
        for tid in tids:
            if len(out) >= cap:
                return out, True
            out.append((pid, tid))
    return out, False


def _schedstat_run(proc_root: Path, pid: int, tid: int) -> int | None:
    ss = pf.parse_pid_schedstat(
        pf.read_text(proc_root / str(pid) / "task" / str(tid) / "schedstat") or ""
    )
    return ss.run_ns if ss else None


@dataclass
class Track:
    first: TaskCounters
    last: TaskCounters | None = None
    cpu_samples: Counter[int] = field(default_factory=Counter)
    runnable_samples: Counter[int] = field(default_factory=Counter)
    samples: int = 0


@dataclass
class CoSampler:
    """Samples the host's running tasks; ``targets`` are (pid, tid) pairs of interest."""

    proc_root: Path
    targets: set[tuple[int, int]]
    exclude_pids: set[int] = field(default_factory=set)
    first: dict[tuple[int, int], TaskCounters] = field(default_factory=dict)
    run_seen: dict[tuple[int, int], int | None] = field(default_factory=dict)
    tracks: dict[tuple[int, int], Track] = field(default_factory=dict)
    ticks: int = 0
    late_ticks: int = 0
    host_tasks: int = 0
    host_truncated: bool = False
    active_truncated: bool = False
    cpu_s: float = 0.0
    t0: float = 0.0
    t1: float = 0.0
    rescans: int = 0

    def _cost(self, c0: float) -> None:
        self.cpu_s += time.process_time() - c0

    def start(self) -> None:
        c0 = time.process_time()
        tasks, self.host_truncated = list_tasks(self.proc_root, MAX_HOST_TASKS)
        self.host_tasks = len(tasks)
        self.t0 = time.monotonic()
        for pid, tid in tasks:
            if pid in self.exclude_pids:
                continue
            c = read_task(self.proc_root, pid, tid, full=(pid, tid) in self.targets)
            if c is None:
                continue
            self.first[(pid, tid)] = c
            self.run_seen[(pid, tid)] = c.run_ns
            if (pid, tid) in self.targets or c.state == "R":
                self._activate((pid, tid))
        self._cost(c0)

    def _activate(self, key: tuple[int, int]) -> None:
        if key in self.tracks:
            return
        if len(self.tracks) >= MAX_ACTIVE_TASKS and key not in self.targets:
            self.active_truncated = True
            return
        self.tracks[key] = Track(self.first[key])

    def rescan(self) -> None:
        """Start tracking tasks whose on-CPU time advanced since the last look."""
        c0 = time.process_time()
        self.rescans += 1
        for key, before in list(self.run_seen.items()):
            if key in self.tracks:
                continue
            now = _schedstat_run(self.proc_root, *key)
            if now is None:
                continue
            if before is not None and now > before:
                self._activate(key)
            self.run_seen[key] = now
        self._cost(c0)

    def tick(self) -> None:
        c0 = time.process_time()
        self.ticks += 1
        for key, tr in self.tracks.items():
            text = pf.read_text(self.proc_root / str(key[0]) / "task" / str(key[1]) / "stat")
            if text is None:
                continue
            try:
                st = pf.parse_pid_stat(text)
            except (ValueError, IndexError):
                continue
            if st.processor is None:
                continue
            tr.samples += 1
            tr.cpu_samples[st.processor] += 1
            if st.state == "R":
                tr.runnable_samples[st.processor] += 1
        self._cost(c0)

    def finish(self) -> None:
        c0 = time.process_time()
        self.t1 = time.monotonic()
        for key, tr in self.tracks.items():
            tr.last = read_task(self.proc_root, *key, full=True)
        self._cost(c0)

    async def run(self, window_s: float, rate_hz: float, cap_hz: float) -> tuple[float, str | None]:
        """Sample for ``window_s``; the rate is lowered while many tasks are tracked.
        Returns the lowest rate used and why it was lowered, if it was."""
        self.start()
        start = anyio.current_time()
        end = start + window_s
        next_rescan = start + RESCAN_S
        low, note = effective_rate(rate_hz, cap_hz, len(self.tracks))
        rate = low
        target = start
        while True:
            target += 1.0 / rate
            if target >= end:
                break
            delay = target - anyio.current_time()
            if delay > 0:
                await anyio.sleep(delay)
            else:
                self.late_ticks += 1
                target = anyio.current_time()
            if anyio.current_time() >= next_rescan:
                self.rescan()
                next_rescan += RESCAN_S
                rate, why = effective_rate(rate_hz, cap_hz, len(self.tracks))
                if rate < low:
                    low, note = rate, why
            self.tick()
        delay = end - anyio.current_time()
        if delay > 0:
            await anyio.sleep(delay)
        self.finish()
        return low, note


def effective_rate(rate_hz: float, cap_hz: float, tracked: int) -> tuple[float, str | None]:
    rate = max(1.0, min(rate_hz, cap_hz))
    note = (
        f"rate capped at the server's --max-stall-rate ({cap_hz:g} Hz)" if rate < rate_hz else None
    )
    budget = MAX_TASK_SAMPLES_PER_S / max(tracked, 1)
    if budget < rate:
        rate = max(1.0, budget)
        note = (
            f"rate lowered to {rate:.1f} Hz so that {tracked} tracked tasks stay within "
            f"{MAX_TASK_SAMPLES_PER_S:g} task samples per second"
        )
    return rate, note


# --- per-task rates ---------------------------------------------------------------


def _r(x: float | None, nd: int = 3) -> float | None:
    return None if x is None else round(x, nd)


def task_rates(tr: Track, window_s: float) -> dict[str, Any] | None:
    a, b = tr.first, tr.last
    if b is None:
        return None
    w = max(window_s, 1e-9)

    def d(x: int | None, y: int | None) -> int | None:
        return None if x is None or y is None else y - x

    run, wait, slices = d(a.run_ns, b.run_ns), d(a.wait_ns, b.wait_ns), d(a.slices, b.slices)
    vol, nonvol = d(a.vol, b.vol), d(a.nonvol, b.nonvol)
    hz = pf.USER_HZ
    on_cpu = run / 1e9 if run is not None else (b.cpu_ticks - a.cpu_ticks) / hz
    out: dict[str, Any] = {
        "on_cpu_seconds_per_s": _r(on_cpu / w, 4),
        "on_cpu_source": "schedstat" if run is not None else "utime+stime clock ticks",
        "runqueue_wait_seconds_per_s": _r(wait / 1e9 / w, 4) if wait is not None else None,
        "voluntary_switches_per_s": _r(vol / w, 1) if vol is not None else None,
        "nonvoluntary_switches_per_s": _r(nonvol / w, 1) if nonvol is not None else None,
        "timeslices_per_s": _r(slices / w, 1) if slices is not None else None,
    }
    if slices:
        out["avg_timeslice_us"] = _r(on_cpu / slices * 1e6, 1)
        out["avg_timeslice_source"] = "on-CPU time / schedstat timeslices (pcount)"
    elif vol is not None and nonvol is not None and vol + nonvol:
        out["avg_timeslice_us"] = _r(on_cpu / (vol + nonvol) * 1e6, 1)
        out["avg_timeslice_source"] = (
            "on-CPU time / (voluntary + non-voluntary switches): schedstat has no timeslice "
            "count here"
        )
    else:
        out["avg_timeslice_us"] = None
        out["avg_timeslice_source"] = None
    out["sched_slice_us"] = _r(b.slice_ns / 1000, 1) if b.slice_ns else None
    if vol and wait is not None:
        sleep_s = max(w - on_cpu - wait / 1e9, 0.0)
        out["avg_sleep_us"] = _r(sleep_s / vol * 1e6, 1)
    else:
        out["avg_sleep_us"] = None
    wakeups = out["voluntary_switches_per_s"]
    out["short_sleeper"] = bool(
        wakeups is not None
        and wakeups >= SHORT_SLEEPER_MIN_WAKEUPS_PER_S
        and out["avg_sleep_us"] is not None
        and out["avg_sleep_us"] < SHORT_SLEEP_US
    )
    return out


def _cpu_weights(tr: Track) -> dict[int, float]:
    total = sum(tr.cpu_samples.values())
    if not total:
        last = tr.last or tr.first
        return {last.processor: 1.0} if last.processor is not None else {}
    return {c: n / total for c, n in tr.cpu_samples.items()}


def _home(tr: Track) -> int | None:
    if tr.cpu_samples:
        return tr.cpu_samples.most_common(1)[0][0]
    last = tr.last or tr.first
    return last.processor


def pearson(xs: list[float], ys: list[float]) -> float | None:
    n = len(xs)
    if n < 3:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx <= 0 or syy <= 0:
        return None
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True))
    return sxy / math.sqrt(sxx * syy)


# --- the view ---------------------------------------------------------------------


def build_view(
    s: CoSampler,
    *,
    rate_hz: float,
    rate_note: str | None,
    describe: Any,
    max_colocated: int = MAX_COLOCATED_ROWS,
) -> dict[str, Any]:
    """``describe(pid)`` returns a short dict (comm, cmdline) for a pid."""
    w = max(s.t1 - s.t0, 1e-9)
    rows: dict[tuple[int, int], dict[str, Any]] = {}
    weights: dict[tuple[int, int], dict[int, float]] = {}
    for key, tr in s.tracks.items():
        rates = task_rates(tr, w)
        if rates is None:
            continue
        rows[key] = rates
        weights[key] = _cpu_weights(tr)
    targets = [k for k in rows if k in s.targets]
    others = [k for k in rows if k not in s.targets]

    per_cpu: dict[int, dict[str, Any]] = defaultdict(
        lambda: {
            "on_cpu_seconds_per_s": 0.0,
            "runqueue_wait_seconds_per_s": 0.0,
            "voluntary_switches_per_s": 0.0,
            "nonvoluntary_switches_per_s": 0.0,
            "runnable_samples": 0,
            "target_tasks": 0,
            "other_tasks": 0,
            "target_wakeups_per_s": 0.0,
            "colocated_wakeups_per_s": 0.0,
            "colocated_short_sleeper_wakeups_per_s": 0.0,
            "target_nonvoluntary_switches_per_s": 0.0,
            "colocated": [],
        }
    )
    for key, rates in rows.items():
        tr = s.tracks[key]
        is_t = key in s.targets
        home = _home(tr)
        busy = (rates["on_cpu_seconds_per_s"] or 0) > 0
        for cpu, share in weights[key].items():
            c = per_cpu[cpu]
            for k in (
                "on_cpu_seconds_per_s",
                "runqueue_wait_seconds_per_s",
                "voluntary_switches_per_s",
                "nonvoluntary_switches_per_s",
            ):
                c[k] += (rates[k] or 0.0) * share
            wake = (rates["voluntary_switches_per_s"] or 0.0) * share
            if is_t:
                c["target_wakeups_per_s"] += wake
                c["target_nonvoluntary_switches_per_s"] += (
                    rates["nonvoluntary_switches_per_s"] or 0.0
                ) * share
            else:
                c["colocated_wakeups_per_s"] += wake
                if rates["short_sleeper"]:
                    c["colocated_short_sleeper_wakeups_per_s"] += wake
                if share >= 0.05 and busy:
                    c["colocated"].append((key, share))
        for cpu, n in tr.runnable_samples.items():
            per_cpu[cpu]["runnable_samples"] += n
        if home is not None and busy:
            per_cpu[home]["target_tasks" if is_t else "other_tasks"] += 1

    def task_row(key: tuple[int, int], share: float | None = None) -> dict[str, Any]:
        tr = s.tracks[key]
        last = tr.last or tr.first
        out = {
            "pid": key[0],
            "tid": key[1],
            "comm": last.comm,
            **describe(key[0]),
            "home_cpu": _home(tr),
            "samples_by_cpu": dict(sorted(tr.cpu_samples.items())),
            "runnable_samples_by_cpu": dict(sorted(tr.runnable_samples.items())),
            "cpus_allowed": last.cpus_allowed,
            **rows[key],
        }
        if share is not None:
            out["share_of_samples_on_this_cpu"] = round(share, 3)
        return out

    target_cpus = sorted({c for k in targets for c in s.tracks[k].cpu_samples} or set())
    allowed: set[int] = set()
    for k in targets:
        allowed.update(
            pf.parse_cpu_list((s.tracks[k].last or s.tracks[k].first).cpus_allowed) or []
        )
    cpus_rows = []
    for cpu in sorted(set(per_cpu) & (set(target_cpus) | allowed)):
        c = per_cpu[cpu]
        co = sorted(
            c["colocated"],
            key=lambda ks: -(rows[ks[0]]["on_cpu_seconds_per_s"] or 0) * ks[1],
        )
        wake = c["colocated_wakeups_per_s"]
        cpus_rows.append(
            {
                "cpu": cpu,
                "target_tasks_here": c["target_tasks"],
                "other_busy_tasks_here": c["other_tasks"],
                "mean_runnable_tasks": round(c["runnable_samples"] / max(s.ticks, 1), 2),
                "on_cpu_seconds_per_s": round(c["on_cpu_seconds_per_s"], 3),
                "runqueue_wait_seconds_per_s": round(c["runqueue_wait_seconds_per_s"], 3),
                "voluntary_switches_per_s": round(c["voluntary_switches_per_s"], 1),
                "nonvoluntary_switches_per_s": round(c["nonvoluntary_switches_per_s"], 1),
                "wakeups_per_s": round(c["voluntary_switches_per_s"], 1),
                "target_nonvoluntary_switches_per_s": round(
                    c["target_nonvoluntary_switches_per_s"], 1
                ),
                "colocated_wakeups_per_s": round(wake, 1),
                "target_preemptions_per_colocated_wakeup": round(
                    c["target_nonvoluntary_switches_per_s"] / wake, 3
                )
                if wake >= SHORT_SLEEPER_MIN_WAKEUPS_PER_S
                else None,
                "colocated_short_sleeper_wakeup_share": round(
                    c["colocated_short_sleeper_wakeups_per_s"] / wake, 3
                )
                if wake
                else None,
                "colocated_tasks": [task_row(k, sh) for k, sh in co[:max_colocated]],
                "colocated_tasks_total": len(co),
            }
        )
    by_cpu = {row["cpu"]: row for row in cpus_rows}

    # Placement over the CPUs the targets may use.
    place_cpus = sorted(allowed) if allowed else target_cpus
    runnable = [by_cpu[c]["mean_runnable_tasks"] if c in by_cpu else 0.0 for c in place_cpus]
    t_counts = [by_cpu[c]["target_tasks_here"] if c in by_cpu else 0 for c in place_cpus]
    o_counts = [by_cpu[c]["other_busy_tasks_here"] if c in by_cpu else 0 for c in place_cpus]
    placement: dict[str, Any] = {
        "cpus": place_cpus,
        "target_tasks_by_cpu": dict(zip(place_cpus, t_counts, strict=True)),
        "other_busy_tasks_by_cpu": dict(zip(place_cpus, o_counts, strict=True)),
        "mean_runnable_tasks_by_cpu": dict(zip(place_cpus, runnable, strict=True)),
        "definition": "a task counts on its home CPU (where most of its samples were); "
        "busy means it ran in the window",
    }
    if len(place_cpus) >= 2 and runnable:
        mean = sum(runnable) / len(runnable)
        sd = math.sqrt(sum((x - mean) ** 2 for x in runnable) / len(runnable))
        placement["runnable_max_minus_min"] = round(max(runnable) - min(runnable), 2)
        placement["runnable_max_to_min_ratio"] = (
            round(max(runnable) / min(runnable), 2) if min(runnable) > 0 else None
        )
        placement["runnable_cv"] = round(sd / mean, 3) if mean > 0 else None
        tot = [t + o for t, o in zip(t_counts, o_counts, strict=True)]
        placement["busy_tasks_max_minus_min"] = max(tot) - min(tot)

    # Wakeup-preemption attribution, as inference.
    trows = []
    total_nv = 0.0
    xs: list[float] = []
    ys: list[float] = []
    for k in targets:
        home = _home(s.tracks[k])
        c = by_cpu.get(home) if home is not None else None
        nv = rows[k]["nonvoluntary_switches_per_s"]
        on = rows[k]["on_cpu_seconds_per_s"]
        nv_per_cpu_s = round(nv / on, 1) if nv is not None and on else None
        wake = c["colocated_wakeups_per_s"] if c else None
        if nv is not None:
            total_nv += nv
        if nv_per_cpu_s is not None and wake is not None:
            xs.append(wake)
            ys.append(nv_per_cpu_s)
        trows.append(
            {
                "pid": k[0],
                "tid": k[1],
                "home_cpu": home,
                "nonvoluntary_switches_per_s": nv,
                "nonvoluntary_switches_per_on_cpu_second": nv_per_cpu_s,
                "avg_timeslice_us": rows[k]["avg_timeslice_us"],
                "colocated_wakeups_per_s_on_home_cpu": wake,
                "colocated_short_sleeper_wakeup_share": c["colocated_short_sleeper_wakeup_share"]
                if c
                else None,
            }
        )
    corr = pearson(xs, ys)
    total_wake = sum(per_cpu[c]["colocated_wakeups_per_s"] for c in target_cpus)
    short_wake = sum(per_cpu[c]["colocated_short_sleeper_wakeups_per_s"] for c in target_cpus)
    attribution = {
        "basis": "inference: rates of tasks on the same CPU over the same window. Wakeups "
        "are taken as voluntary switches. No trace of which wakeup preempted which task "
        "was taken.",
        "per_target_task": trows[:MAX_TARGET_ROWS],
        "target_nonvoluntary_switches_per_s_total": round(total_nv, 1),
        "colocated_wakeups_per_s_on_target_cpus": round(total_wake, 1),
        "colocated_short_sleeper_wakeup_share_on_target_cpus": round(short_wake / total_wake, 3)
        if total_wake
        else None,
        "correlation_target_nonvoluntary_vs_colocated_wakeups": _r(corr),
        "correlation_note": "Pearson r across target tasks between each task's "
        "non-voluntary switches per second on CPU and the co-located wakeups per second on "
        "its home CPU. Per second on CPU, because a wakeup can only preempt the task that is "
        "running: tasks sharing a CPU split its preemptions by their share of its time."
        + (" Null with fewer than 3 target tasks or no spread." if corr is None else ""),
        "target_preemptions_per_colocated_wakeup_note": "per CPU in cpus[]: the targets' "
        "non-voluntary switches there divided by the co-located wakeups there. Near the "
        "targets' share of that CPU's time when most co-located wakeups preempt whoever runs. "
        f"Null under {SHORT_SLEEPER_MIN_WAKEUPS_PER_S:g} co-located wakeups/s, where the "
        "targets' preemptions come from each other (tick and fairness), not from wakeups",
        "short_sleeper_definition": f"at least {SHORT_SLEEPER_MIN_WAKEUPS_PER_S:g} wakeups/s "
        f"and under {SHORT_SLEEP_US:g} us asleep per wakeup on average (sleep = window minus "
        "on-CPU minus run-queue wait)",
    }
    wakers: Counter[tuple[int, int]] = Counter()
    for c in target_cpus:
        for k, sh in per_cpu[c]["colocated"]:
            if rows[k]["short_sleeper"]:
                wakers[k] += (rows[k]["voluntary_switches_per_s"] or 0) * sh
    attribution["top_short_sleepers_on_target_cpus"] = [
        {
            "pid": k[0],
            "tid": k[1],
            "comm": (s.tracks[k].last or s.tracks[k].first).comm,
            **describe(k[0]),
            "wakeups_per_s_on_target_cpus": round(v, 1),
            "avg_sleep_us": rows[k]["avg_sleep_us"],
        }
        for k, v in wakers.most_common(5)
    ]

    t_slices = [
        rows[k]["avg_timeslice_us"] for k in targets if rows[k]["avg_timeslice_us"] is not None
    ]
    t_sched = sorted(rows[k]["sched_slice_us"] for k in targets if rows[k]["sched_slice_us"])
    targets_summary = {
        "tasks": len(targets),
        "nonvoluntary_switches_per_s": round(total_nv, 1),
        "voluntary_switches_per_s": round(
            sum(rows[k]["voluntary_switches_per_s"] or 0 for k in targets), 1
        ),
        "on_cpu_seconds_per_s": round(
            sum(rows[k]["on_cpu_seconds_per_s"] or 0 for k in targets), 3
        ),
        "avg_timeslice_us_median": _median(t_slices),
        "sched_slice_us_median": _median(t_sched),
    }
    on = sum(
        (s.tracks[k].last.run_ns or 0) - (s.tracks[k].first.run_ns or 0)
        for k in targets
        if s.tracks[k].last is not None
    )
    sl = sum(
        (s.tracks[k].last.slices or 0) - (s.tracks[k].first.slices or 0)
        for k in targets
        if s.tracks[k].last is not None
    )
    targets_summary["avg_timeslice_us_pooled"] = round(on / sl / 1000, 1) if sl else None
    return {
        "measurement": {
            "window_s": round(w, 3),
            "rate_hz": round(rate_hz, 2),
            "samples": s.ticks,
            "late_samples": s.late_ticks,
            **({"rate_note": rate_note} if rate_note else {}),
        },
        "targets": targets_summary,
        "target_tasks": [task_row(k) for k in targets[:MAX_TARGET_ROWS]],
        "target_tasks_truncated": len(targets) > MAX_TARGET_ROWS,
        "cpus": cpus_rows,
        "placement": placement,
        "wakeup_preemption_attribution": attribution,
        "cost": {
            "host_tasks_listed": s.host_tasks,
            "host_tasks_truncated": s.host_truncated,
            "tasks_tracked": len(s.tracks),
            "tracked_tasks_truncated": s.active_truncated,
            "rescans": s.rescans,
            "sampler_cpu_seconds": round(s.cpu_s, 4),
            "reads": "start: stat, status and schedstat of every task on the host (up to "
            f"{MAX_HOST_TASKS}); every {RESCAN_S:g} s: schedstat of tasks not yet tracked; "
            "each sample: stat of tracked tasks (tasks that ran, up to "
            f"{MAX_ACTIVE_TASKS}); end: stat, status, schedstat and sched of tracked tasks",
        },
        "others_tracked": len(others),
    }


def _median(xs: list[float]) -> float | None:
    if not xs:
        return None
    ys = sorted(xs)
    n = len(ys)
    return round(ys[n // 2] if n % 2 else (ys[n // 2 - 1] + ys[n // 2]) / 2, 1)
