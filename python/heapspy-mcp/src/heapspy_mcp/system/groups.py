"""CPU and scheduler rates for a group of processes (``group_cpu``).

The members are chosen with the ``find_processes`` filters. Each member is
measured over the same window as ``process_cpu`` measures one process
(start and end counters of every thread, plus in-window samples of thread
state and last CPU). Members are put in groups by a key, so two services
can be compared side by side: per-member rows, and per group the sum, mean,
median, 90th percentile, minimum, maximum and spread of every rate metric.

With ``work_rate`` (units of work per second for a group, from the caller's
own metrics) a group reports CPU seconds per unit of work and timeslices per
unit of work.
"""

from __future__ import annotations

import math
import os
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio

from . import cgroups as cg
from . import procfs as pf
from . import search as srch
from .redact import redact_args, redact_cmdline
from .sampling import ProcessGone, ProcessSample, list_tids, sample_process

MAX_GROUP_MEMBERS = 256
MAX_THREADS_PER_MEMBER = 64
DEFAULT_RATE_HZ = 20.0
MAX_THREAD_SAMPLES_PER_S = 5000.0
MAX_GROUPS = 32

GROUP_BY_FIXED = ("none", "comm", "exe", "parent", "cgroup", "pod", "container", "cmdline_regex")
GROUP_BY_HELP = (
    "none | comm | exe | parent | cgroup | pod | container | cmdline_arg:N (the Nth "
    "argument, 0 = program; redacted) | cmdline_regex (first capture group of group_regex "
    "searched in the redacted command line)"
)

# metric -> how a group combines it: "sum" for rates that add up across members,
# "pooled" for ratios recomputed from the members' summed numerators and denominators.
METRICS: dict[str, str] = {
    "cpu_cores_used": "sum",
    "on_cpu_seconds_per_s": "sum",
    "cpu_seconds_user_per_s": "sum",
    "cpu_seconds_system_per_s": "sum",
    "voluntary_switches_per_s": "sum",
    "nonvoluntary_switches_per_s": "sum",
    "voluntary_share": "pooled",
    "switches_per_cpu_second": "pooled",
    "runqueue_wait_seconds_per_s": "sum",
    "runqueue_wait_ratio": "pooled",
    "timeslices_per_s": "sum",
    "avg_timeslice_us": "pooled",
    "cpu_migrations_per_s": "sum",
    "major_faults_per_s": "sum",
    "minor_faults_per_s": "sum",
    "threads": "sum",
    "runnable_share": "pooled",
}


class GroupError(Exception):
    """An argument to a group tool is invalid."""


def _r(x: float | None, nd: int = 3) -> float | None:
    return None if x is None else round(x, nd)


# --- keys ---------------------------------------------------------------------------


@dataclass
class KeyFn:
    kind: str
    arg: int | None = None
    regex: re.Pattern[str] | None = None

    def __call__(self, s: srch.Static) -> str:
        if self.kind == "none":
            return "all"
        if self.kind == "comm":
            return s.comm
        if self.kind == "exe":
            return s.exe or f"(no exe) {s.comm}"
        if self.kind == "parent":
            return str(s.ppid)
        if self.kind == "cgroup":
            return s.cgroup_path or "(unknown)"
        if self.kind in ("pod", "container"):
            k8s = cg.parse_kubepods_path(s.cgroup_path or "") or {}
            v = k8s.get("pod_uid" if self.kind == "pod" else "container_id")
            return v or "(not in a pod)"
        args = redact_args(s.cmdline or [])
        if self.kind == "cmdline_arg":
            assert self.arg is not None
            return args[self.arg] if self.arg < len(args) else "(missing)"
        assert self.regex is not None
        m = self.regex.search(" ".join(args))
        if not m:
            return "(no match)"
        return m.group(1) if m.groups() else m.group(0)


def parse_group_by(group_by: str, group_regex: str | None) -> KeyFn:
    g = (group_by or "none").strip()
    if g.startswith("cmdline_arg:"):
        n = g.split(":", 1)[1]
        if not n.isdigit() or int(n) > 1000:
            raise GroupError("cmdline_arg:N needs a whole number N (0 = the program)")
        return KeyFn("cmdline_arg", arg=int(n))
    if g not in GROUP_BY_FIXED:
        raise GroupError(f"group_by must be one of: {GROUP_BY_HELP}")
    if g == "cmdline_regex":
        if not group_regex:
            raise GroupError("group_by=cmdline_regex needs group_regex")
        if len(group_regex) > 500:
            raise GroupError("group_regex is longer than 500 characters")
        try:
            return KeyFn(g, regex=re.compile(group_regex))
        except re.error as e:
            raise GroupError(f"group_regex does not compile: {e}") from e
    return KeyFn(g)


# --- sampling -----------------------------------------------------------------------


@dataclass
class StateTicks:
    """In-window samples of each member's threads: state and last CPU (stat field 39)."""

    proc_root: Path
    pids: list[int]
    ticks: int = 0
    late: int = 0
    runnable: Counter[int] = field(default_factory=Counter)
    thread_samples: Counter[int] = field(default_factory=Counter)
    cpu_samples: dict[int, Counter[int]] = field(default_factory=lambda: defaultdict(Counter))
    runnable_by_cpu: dict[int, Counter[int]] = field(default_factory=lambda: defaultdict(Counter))
    cpu_s: float = 0.0

    def tick(self) -> None:
        c0 = time.process_time()
        self.ticks += 1
        for pid in self.pids:
            base = self.proc_root / str(pid) / "task"
            for tid in list_tids(self.proc_root, pid)[:MAX_THREADS_PER_MEMBER]:
                text = pf.read_text(base / str(tid) / "stat")
                if text is None:
                    continue
                try:
                    st = pf.parse_pid_stat(text)
                except (ValueError, IndexError):
                    continue
                self.thread_samples[pid] += 1
                if st.processor is not None:
                    self.cpu_samples[pid][st.processor] += 1
                if st.state == "R":
                    self.runnable[pid] += 1
                    if st.processor is not None:
                        self.runnable_by_cpu[pid][st.processor] += 1
        self.cpu_s += time.process_time() - c0


def member_metrics(
    a: ProcessSample, b: ProcessSample, ticks: StateTicks | None = None
) -> dict[str, Any]:
    """The process_cpu rate metrics of one member between two samples, and the raw
    sums the group's pooled ratios are computed from."""
    w = max(b.t - a.t, 1e-9)
    hz = pf.USER_HZ
    user = (b.stat.utime_ticks - a.stat.utime_ticks) / hz
    system = (b.stat.stime_ticks - a.stat.stime_ticks) / hz
    # Threads that exited in the window drop out of the end sums; count only threads
    # present at both ends for the per-thread counters.
    common = set(a.threads) & set(b.threads)

    def delta(attr: str, sub: str | None = None) -> int | None:
        total = 0
        for tid in common:
            va, vb = getattr(a.threads[tid], attr), getattr(b.threads[tid], attr)
            if sub is not None:
                va = getattr(va, sub) if va is not None else None
                vb = getattr(vb, sub) if vb is not None else None
            if va is None or vb is None:
                return None
            total += vb - va
        return total

    vol, nonvol = delta("voluntary"), delta("nonvoluntary")
    run, wait, slices = (
        delta("sched", "run_ns"),
        delta("sched", "wait_ns"),
        delta("sched", "timeslices"),
    )
    mig = delta("migrations")
    cpu = user + system
    raw = {
        "window_s": w,
        "cpu_s": cpu,
        "run_ns": run,
        "wait_ns": wait,
        "slices": slices,
        "vol": vol,
        "nonvol": nonvol,
        "runnable_samples": ticks.runnable.get(b.pid, 0) if ticks else None,
        "thread_samples": ticks.thread_samples.get(b.pid, 0) if ticks else None,
    }
    on_cpu = run / 1e9 if run is not None else None
    m: dict[str, Any] = {
        "cpu_cores_used": _r(cpu / w),
        "on_cpu_seconds_per_s": _r(on_cpu / w, 4) if on_cpu is not None else None,
        "cpu_seconds_user_per_s": _r(user / w),
        "cpu_seconds_system_per_s": _r(system / w),
        "voluntary_switches_per_s": _r(vol / w, 1) if vol is not None else None,
        "nonvoluntary_switches_per_s": _r(nonvol / w, 1) if nonvol is not None else None,
        "voluntary_share": _r(vol / (vol + nonvol))
        if vol is not None and nonvol is not None and vol + nonvol
        else None,
        "switches_per_cpu_second": _r((vol + nonvol) / cpu, 1)
        if vol is not None and nonvol is not None and cpu > 0
        else None,
        "runqueue_wait_seconds_per_s": _r(wait / 1e9 / w, 4) if wait is not None else None,
        "runqueue_wait_ratio": _r(wait / run) if wait is not None and run else None,
        "timeslices_per_s": _r(slices / w, 1) if slices is not None else None,
        "avg_timeslice_us": _r(run / slices / 1000, 1) if run is not None and slices else None,
        "cpu_migrations_per_s": _r(mig / w, 1) if mig is not None else None,
        "major_faults_per_s": _r((b.stat.majflt - a.stat.majflt) / w, 1),
        "minor_faults_per_s": _r((b.stat.minflt - a.stat.minflt) / w, 1),
        "threads": b.threads_total,
        "runnable_share": _r(raw["runnable_samples"] / raw["thread_samples"])
        if ticks and raw["thread_samples"]
        else None,
    }
    return {"metrics": m, "raw": raw}


# --- aggregation --------------------------------------------------------------------


def percentile(sorted_xs: list[float], q: float) -> float:
    """Linear-interpolation percentile (``q`` in 0..1) of an already sorted list."""
    if len(sorted_xs) == 1:
        return sorted_xs[0]
    pos = q * (len(sorted_xs) - 1)
    lo = math.floor(pos)
    hi = min(lo + 1, len(sorted_xs) - 1)
    return sorted_xs[lo] + (sorted_xs[hi] - sorted_xs[lo]) * (pos - lo)


def describe(values: list[float | None], combine: str) -> dict[str, Any]:
    xs = sorted(v for v in values if v is not None)
    out: dict[str, Any] = {"members_with_value": len(xs)}
    if not xs:
        return {
            **out,
            "sum": None,
            "mean": None,
            "p50": None,
            "p90": None,
            "min": None,
            "max": None,
            "spread": None,
            "max_to_min_ratio": None,
            "cv": None,
        }
    mean = sum(xs) / len(xs)
    sd = math.sqrt(sum((x - mean) ** 2 for x in xs) / len(xs))
    out.update(
        {
            "sum": _r(sum(xs), 4) if combine == "sum" else None,
            "mean": _r(mean, 4),
            "p50": _r(percentile(xs, 0.5), 4),
            "p90": _r(percentile(xs, 0.9), 4),
            "min": _r(xs[0], 4),
            "max": _r(xs[-1], 4),
            "spread": _r(xs[-1] - xs[0], 4),
            "max_to_min_ratio": _r(xs[-1] / xs[0], 3) if xs[0] > 0 else None,
            "cv": _r(sd / mean, 3) if mean else None,
        }
    )
    return out


def pooled(raws: list[dict[str, Any]]) -> dict[str, float | None]:
    """Group-level ratios from the members' summed raw counts."""

    def total(k: str) -> float | None:
        vals = [x[k] for x in raws]
        return None if any(v is None for v in vals) else float(sum(vals))

    run, wait, slices = total("run_ns"), total("wait_ns"), total("slices")
    vol, nonvol, cpu = total("vol"), total("nonvol"), total("cpu_s")
    rs, ts = total("runnable_samples"), total("thread_samples")
    return {
        "voluntary_share": _r(vol / (vol + nonvol))
        if vol is not None and nonvol is not None and vol + nonvol
        else None,
        "switches_per_cpu_second": _r((vol + nonvol) / cpu, 1)
        if vol is not None and nonvol is not None and cpu
        else None,
        "runqueue_wait_ratio": _r(wait / run) if wait is not None and run else None,
        "avg_timeslice_us": _r(run / slices / 1000, 1) if run is not None and slices else None,
        "runnable_share": _r(rs / ts) if rs is not None and ts else None,
    }


def aggregate(members: list[dict[str, Any]]) -> dict[str, Any]:
    pool = pooled([m["raw"] for m in members])
    out: dict[str, Any] = {}
    for name, combine in METRICS.items():
        d = describe([m["metrics"].get(name) for m in members], combine)
        if combine == "pooled":
            d["pooled"] = pool.get(name)
        out[name] = d
    return out


def work_block(agg: dict[str, Any], work_rate: float | None) -> dict[str, Any] | None:
    if work_rate is None:
        return None
    on = agg["on_cpu_seconds_per_s"]["sum"]
    source = "schedstat on-CPU time"
    if on is None:
        on = agg["cpu_cores_used"]["sum"]
        source = "utime+stime clock ticks"
    slices = agg["timeslices_per_s"]["sum"]
    return {
        "work_rate": work_rate,
        "cpu_seconds_per_unit_work": _r(on / work_rate, 9) if on is not None else None,
        "cpu_source": source,
        "timeslices_per_unit_work": _r(slices / work_rate, 6) if slices is not None else None,
        "units_of_work_per_timeslice": _r(work_rate / slices, 3) if slices else None,
    }


def placement(members: list[dict[str, Any]], ticks: StateTicks) -> dict[str, Any]:
    """Member threads' home CPUs and mean runnable member threads per CPU."""
    home: Counter[int] = Counter()
    runnable: Counter[int] = Counter()
    for m in members:
        pid = m["pid"]
        cs = ticks.cpu_samples.get(pid)
        if cs:
            home[cs.most_common(1)[0][0]] += 1
        for cpu, n in ticks.runnable_by_cpu.get(pid, {}).items():
            runnable[cpu] += n
    cpus = sorted(set(home) | set(runnable))
    return {
        "members_by_home_cpu": {c: home.get(c, 0) for c in cpus},
        "mean_runnable_member_threads_by_cpu": {
            c: round(runnable.get(c, 0) / max(ticks.ticks, 1), 2) for c in cpus
        },
        "definition": "a member counts on the CPU where most of its thread samples were",
    }


async def group_cpu(
    proc_root: Path,
    filters: srch.Filters,
    *,
    group_by: str,
    group_regex: str | None,
    window_s: float,
    rate_hz: float,
    rate_cap_hz: float,
    work_rate: float | None = None,
    work_rates: dict[str, float] | None = None,
    cmdline_max_chars: int = srch.MAX_CMDLINE,
    include_members: bool = True,
) -> dict[str, Any]:
    keyfn = parse_group_by(group_by, group_regex)
    filters.prepare()
    for name, v in [
        ("work_rate", work_rate),
        *((f"work_rates[{k}]", x) for k, x in (work_rates or {}).items()),
    ]:
        if v is not None and v <= 0:
            raise GroupError(f"{name} must be positive")
    state = srch.collect_statics(proc_root)
    me = os.getpid()
    pids = [p for p in srch.apply_filters(state.statics, filters, proc_root) if p != me]
    if not pids:
        raise GroupError("no process matches the selector")
    matched = len(pids)
    truncated = matched > MAX_GROUP_MEMBERS
    pids = pids[:MAX_GROUP_MEMBERS]
    keys = {p: keyfn(state.statics[p]) for p in pids}
    if len(set(keys.values())) > MAX_GROUPS:
        raise GroupError(f"more than {MAX_GROUPS} groups; use a coarser group_by or filter")
    if work_rate is not None and len(set(keys.values())) > 1 and not work_rates:
        raise GroupError(
            "work_rate applies to a single group; with several groups pass work_rates "
            "(group key -> units/s)"
        )

    first: dict[int, ProcessSample] = {}
    for p in pids:
        try:
            first[p] = sample_process(proc_root, p, MAX_THREADS_PER_MEMBER)
        except ProcessGone:  # exited between listing and sampling
            continue
    threads = sum(min(len(s.threads), MAX_THREADS_PER_MEMBER) for s in first.values())
    rate = max(1.0, min(rate_hz, rate_cap_hz))
    note = (
        f"rate capped at the server's --max-stall-rate ({rate_cap_hz:g} Hz)"
        if rate < rate_hz
        else None
    )
    if threads and MAX_THREAD_SAMPLES_PER_S / threads < rate:
        rate = max(1.0, MAX_THREAD_SAMPLES_PER_S / threads)
        note = (
            f"rate lowered to {rate:.1f} Hz so that {threads} threads stay within "
            f"{MAX_THREAD_SAMPLES_PER_S:g} thread samples per second"
        )
    ticks = StateTicks(proc_root, list(first))
    n = max(2, int(window_s * rate))
    period = window_s / (n + 1)
    t0 = anyio.current_time()
    for k in range(n):
        delay = t0 + (k + 1) * period - anyio.current_time()
        if delay > 0:
            await anyio.sleep(delay)
        else:
            ticks.late += 1
        ticks.tick()
    delay = t0 + window_s - anyio.current_time()
    if delay > 0:
        await anyio.sleep(delay)
    members: list[dict[str, Any]] = []
    exited = 0
    for p, a in first.items():
        try:
            b = sample_process(proc_root, p, MAX_THREADS_PER_MEMBER)
        except ProcessGone:
            exited += 1
            continue
        mm = member_metrics(a, b, ticks)
        s = state.statics[p]
        cs = ticks.cpu_samples.get(p)
        members.append(
            {
                "pid": p,
                "group": keys[p],
                "comm": s.comm,
                "cmdline": redact_cmdline(s.cmdline, cmdline_max_chars),
                "cgroup": s.cgroup_path,
                "home_cpu": cs.most_common(1)[0][0] if cs else None,
                "samples_by_cpu": dict(sorted(cs.items())) if cs else {},
                "cpus_allowed": next(
                    (t.cpus_allowed for t in b.threads.values() if t.cpus_allowed), None
                ),
                **mm,
            }
        )
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for m in members:
        by_group[m["group"]].append(m)
    groups = []
    for key in sorted(by_group):
        ms = by_group[key]
        agg = aggregate(ms)
        rate_for = (work_rates or {}).get(key, work_rate if len(by_group) == 1 else None)
        groups.append(
            {
                "key": key,
                "members": len(ms),
                "pids": sorted(m["pid"] for m in ms)[:64],
                "metrics": agg,
                "work": work_block(agg, rate_for),
                "placement": placement(ms, ticks),
            }
        )
    unknown_rates = sorted(set(work_rates or {}) - set(by_group))
    out: dict[str, Any] = {
        "measurement": {
            "window_s": round(window_s, 3),
            "state_samples": ticks.ticks,
            "state_rate_hz": round(rate, 2),
            "late_samples": ticks.late,
            **({"rate_note": note} if note else {}),
        },
        "group_by": group_by,
        "matched": matched,
        "members_measured": len(members),
        "members_truncated": truncated,
        "members_exited_in_window": exited,
        "groups": groups,
        "comparison": compare_groups(groups) if len(groups) >= 2 else None,
        "metric_notes": {
            "sum": "for rates that add up across members; null for ratios",
            "pooled": "ratios recomputed from the members' summed counts (for example "
            "avg_timeslice_us = total on-CPU time / total timeslices)",
            "spread": "max minus min across members; cv is the standard deviation over the mean",
            "runnable_share": "share of in-window thread samples in state R (running or "
            "waiting for a CPU)",
        },
        "cost": {
            "sampler_cpu_seconds": round(ticks.cpu_s, 4),
            "reads": "start and end: stat, status, schedstat and sched of up to "
            f"{MAX_THREADS_PER_MEMBER} threads per member; each sample: stat of those threads",
        },
    }
    if unknown_rates:
        out["work_rates_unmatched_keys"] = unknown_rates
    out["member_rows"] = (
        [
            {k: v for k, v in m.items() if k != "raw"}
            for m in sorted(members, key=lambda m: (m["group"], m["pid"]))
        ]
        if include_members
        else None
    )
    return out


COMPARE_KEYS = (
    "cpu_cores_used",
    "nonvoluntary_switches_per_s",
    "voluntary_switches_per_s",
    "voluntary_share",
    "runqueue_wait_ratio",
    "avg_timeslice_us",
    "timeslices_per_s",
    "runnable_share",
)


def compare_groups(groups: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-member means and pooled ratios of each group side by side."""
    rows = {}
    for name in COMPARE_KEYS:
        combine = METRICS[name]
        rows[name] = {
            g["key"]: (
                g["metrics"][name]["pooled"] if combine == "pooled" else g["metrics"][name]["mean"]
            )
            for g in groups
        }
    return {
        "per_member_mean_or_pooled": rows,
        "note": "rates are per-member means; ratios (voluntary_share, runqueue_wait_ratio, "
        "avg_timeslice_us, runnable_share) are pooled over the group's members",
    }
