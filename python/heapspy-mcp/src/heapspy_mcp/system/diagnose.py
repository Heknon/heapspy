"""Weigh competing explanations for a process's CPU use, CPU wait or slowness.

Each hypothesis is scored from the measurements of one window. Every
judgement lists the raw value, the threshold it was compared with, and its
weight. A signal that could not be measured is listed under ``unknown`` and
contributes nothing. The output is a ranking of how well each explanation
fits these numbers; it is not a finding, and several can hold at once.

All thresholds are in :data:`THRESHOLDS`, in one place, for review.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# name -> (value, unit, why this value). Reviewed as a table; change here only.
THRESHOLDS: dict[str, tuple[float, str, str]] = {
    "runqueue_wait_ratio_high": (
        0.20,
        "ratio",
        "runnable-but-waiting time is at least a fifth of on-CPU time",
    ),
    "runqueue_wait_ratio_very_high": (0.50, "ratio", "waiting half as long as running"),
    "runqueue_wait_ratio_low": (0.05, "ratio", "wait under 5% of run time: CPUs were available"),
    "nonvoluntary_switches_per_s_high": (100.0, "1/s", "frequent preemption"),
    "procs_running_per_core_high": (1.0, "ratio", "more runnable tasks than online cores"),
    "procs_running_per_core_low": (0.7, "ratio", "host has idle cores on average"),
    "psi_cpu_some_window_pct_high": (20.0, "%", "tasks were waiting for CPU 20% of the window"),
    "ipc_low": (0.8, "instructions/cycle", "low for general-purpose server code"),
    "ipc_normal": (1.5, "instructions/cycle", "typical of code not bound on memory"),
    "llc_mpki_high": (10.0, "misses per 1000 instructions", "heavy last-level cache missing"),
    "llc_mpki_low": (2.0, "misses per 1000 instructions", "the working set mostly hits LLC"),
    "cfs_throttled_ratio_high": (0.20, "ratio", "a fifth of CFS periods hit the quota"),
    "cfs_throttled_ratio_some": (0.05, "ratio", "some CFS periods hit the quota"),
    "cfs_throttled_ratio_none": (0.01, "ratio", "throttling is rare"),
    "throttled_seconds_per_s_high": (0.10, "s/s", "100 ms of throttling per second"),
    "usage_to_limit_ratio_high": (0.90, "ratio", "usage within 10% of the quota"),
    "voluntary_share_high": (0.70, "ratio", "most switches are the thread blocking itself"),
    "voluntary_share_low": (0.30, "ratio", "most switches are preemptions"),
    "voluntary_switches_per_s_high": (500.0, "1/s", "frequent blocking and waking"),
    "voluntary_switches_per_s_low": (50.0, "1/s", "little blocking"),
    "futex_wait_share_high": (0.50, "ratio", "half of sleeping-thread samples are in futex"),
    "switches_per_cpu_second_high": (2000.0, "1/cpu-s", "short bursts of CPU between switches"),
    "switches_per_cpu_second_low": (50.0, "1/cpu-s", "long uninterrupted runs on CPU"),
    "cpu_cores_used_busy": (0.5, "cores", "at least half a core busy"),
    "cpu_cores_used_idle": (0.2, "cores", "mostly idle"),
    "user_share_high": (0.90, "ratio", "time is in user space"),
    "gil_cores_ceiling": (1.3, "cores", "a GIL-bound process stays near one core"),
    "gil_cores_exceeded": (1.5, "cores", "well above one core: threads run in parallel"),
    "active_threads_min": (2.0, "threads", "at least two threads runnable or waiting on futex"),
    "voluntary_switches_per_s_gil": (200.0, "1/s", "frequent hand-offs between threads"),
    "steal_pct_high": (5.0, "%", "hypervisor took 5% of host CPU time"),
    "steal_pct_very_high": (10.0, "%", "hypervisor took 10% of host CPU time"),
    "steal_pct_low": (1.0, "%", "little steal"),
    "psi_memory_some_window_pct_high": (5.0, "%", "tasks stalled on memory 5% of the window"),
    "psi_memory_full_window_pct_high": (1.0, "%", "all tasks stalled on memory 1% of the time"),
    "psi_memory_some_window_pct_low": (0.5, "%", "negligible memory stall"),
    "major_faults_per_s_high": (100.0, "1/s", "frequent reads of pages from storage"),
    "major_faults_per_s_low": (5.0, "1/s", "few major faults"),
    "psi_io_some_window_pct_high": (10.0, "%", "tasks stalled on I/O 10% of the window"),
    "psi_io_some_window_pct_low": (1.0, "%", "negligible I/O stall"),
    "iowait_seconds_per_s_high": (0.10, "s/s", "threads waited on block I/O 10% of the time"),
    "disk_wait_share_high": (0.20, "ratio", "a fifth of thread samples in D state or block I/O"),
}

ASSESSMENTS = (
    "consistent_with_measurements",  # score >= 3
    "partly_consistent",  # 1..2
    "not_indicated",  # <= 0 with evidence
    "insufficient_signals",  # nothing measured
)


def T(name: str) -> float:
    return THRESHOLDS[name][0]


@dataclass
class Hyp:
    id: str
    title: str
    for_: list[dict[str, Any]]
    against: list[dict[str, Any]]
    unknown: list[dict[str, Any]]
    next_steps: list[str]
    caveat: str | None = None

    def add(
        self, side: str, signal: str, value: Any, threshold: str, weight: int, note: str = ""
    ) -> None:
        val, unit, why = THRESHOLDS[threshold]
        item = {
            "signal": signal,
            "value": value,
            "threshold_name": threshold,
            "threshold": val,
            "unit": unit,
            "weight": weight,
            "threshold_meaning": why,
        }
        if note:
            item["note"] = note
        (self.for_ if side == "for" else self.against).append(item)

    def missing(self, signal: str, reason: str) -> None:
        self.unknown.append({"signal": signal, "reason": reason})

    def result(self) -> dict[str, Any]:
        score = sum(e["weight"] for e in self.for_) - sum(e["weight"] for e in self.against)
        if not self.for_ and not self.against:
            assessment = "insufficient_signals"
        elif score >= 3:
            assessment = "consistent_with_measurements"
        elif score >= 1:
            assessment = "partly_consistent"
        else:
            assessment = "not_indicated"
        out = {
            "id": self.id,
            "title": self.title,
            "score": score,
            "assessment": assessment,
            "evidence_for": self.for_,
            "evidence_against": self.against,
            "unknown": self.unknown,
            "next_measurements": self.next_steps,
        }
        if self.caveat:
            out["caveat"] = self.caveat
        return out


def _get(d: dict[str, Any] | None, *path: str) -> Any:
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def extract_signals(view: dict[str, Any], hw: dict[str, Any] | None, python: dict[str, Any]):
    """The flat set of numbers the hypotheses read, with a reason for each missing one."""
    env = view.get("environment") or {}
    host = env.get("host")
    cgv = env.get("cgroup") or {}
    window = _get(view, "measurement", "window_s") or 1.0
    states = _get(view, "threads", "state_share_over_window") or {}
    threads = _get(view, "threads", "count") or 0
    sites = _get(view, "wait_sites", "share_by_site") or {}
    sleeping = _get(view, "wait_sites", "sleeping_thread_samples") or 0
    ticks = _get(view, "wait_sites", "samples") or 0
    counts = _get(view, "wait_sites", "samples_by_site") or {}
    thread_samples = _get(view, "wait_sites", "thread_samples") or 0
    reasons: dict[str, str] = {}
    unavailable = view.get("unavailable") or {}

    def pick(name: str, value: Any, reason: str | None) -> Any:
        if value is None:
            reasons[name] = reason or "not measured"
        return value

    def psi(src: dict[str, Any] | None, res: str, kind: str) -> float | None:
        return _get(src, res, kind, "window_pct")

    host_reason = (
        env.get("host_unavailable_reason") if host is None else None
    ) or "host context unavailable"
    cg_reason = cgv.get("reason") if not cgv.get("available") else None
    psi_cg = cgv.get("pressure") if cgv.get("available") else None
    psi_host = host.get("psi") if host else None

    def max_psi(res: str, kind: str) -> float | None:
        vals = [v for v in (psi(psi_cg, res, kind), psi(psi_host, res, kind)) if v is not None]
        return max(vals) if vals else None

    iowait = view.get("iowait_seconds")
    s: dict[str, Any] = {
        "cpu_cores_used": _get(view, "cpu", "cpu_cores_used"),
        "user_share": _get(view, "cpu", "user_share"),
        "threads": threads,
        "voluntary_switches_per_s": _get(view, "context_switches", "voluntary_switches_per_s"),
        "nonvoluntary_switches_per_s": _get(
            view, "context_switches", "nonvoluntary_switches_per_s"
        ),
        "voluntary_share": _get(view, "context_switches", "voluntary_share"),
        "switches_per_cpu_second": _get(view, "context_switches", "switches_per_cpu_second"),
        "runqueue_wait_ratio": pick(
            "runqueue_wait_ratio",
            _get(view, "scheduler", "runqueue_wait_ratio"),
            unavailable.get("runqueue_wait_ratio"),
        ),
        "mean_runnable_threads": round(states.get("running_or_runnable", 0) * threads, 2)
        if states
        else None,
        "futex_wait_share": sites.get("futex", 0.0) if sleeping else None,
        "mean_futex_waiting_threads": round(counts.get("futex", 0) / ticks, 2) if ticks else None,
        "disk_wait_share": round(counts.get("block_io", 0) / thread_samples, 3)
        if thread_samples
        else None,
        "major_faults_per_s": _get(view, "page_faults", "major_faults_per_s"),
        "iowait_seconds_per_s": pick(
            "iowait_seconds_per_s",
            round(iowait / window, 4) if iowait is not None else None,
            unavailable.get("iowait_seconds"),
        ),
        "procs_running_per_core": pick(
            "procs_running_per_core",
            _get(host, "procs_running_per_core"),
            host_reason,
        ),
        "steal_pct": pick(
            "steal_pct",
            _get(host, "cpu_time_pct", "steal_pct"),
            host_reason if host is None else _get(host, "unavailable", "steal_pct"),
        ),
        "psi_cpu_some_window_pct": pick(
            "psi_cpu_some_window_pct", max_psi("cpu", "some"), "no PSI from cgroup or host"
        ),
        "psi_memory_some_window_pct": pick(
            "psi_memory_some_window_pct", max_psi("memory", "some"), "no PSI from cgroup or host"
        ),
        "psi_memory_full_window_pct": pick(
            "psi_memory_full_window_pct", max_psi("memory", "full"), "no PSI from cgroup or host"
        ),
        "psi_io_some_window_pct": pick(
            "psi_io_some_window_pct", max_psi("io", "some"), "no PSI from cgroup or host"
        ),
        "cgroup_available": bool(cgv.get("available")),
        "cgroup_reason": cg_reason,
        "cfs_throttled_ratio": cgv.get("max_cfs_throttled_ratio"),
        "tightest_limit_cores": cgv.get("tightest_limit_cores"),
        "process_cpu_cores_to_tightest_limit_ratio": cgv.get(
            "process_cpu_cores_to_tightest_limit_ratio"
        ),
        "throttled_seconds_per_s": max(
            (
                lv.get("throttled_seconds_per_s") or 0
                for lv in [cgv.get("own") or {}, *(cgv.get("ancestors_with_quota") or [])]
            ),
            default=None,
        )
        if cgv.get("available")
        else None,
        "ipc": None,
        "llc_mpki": None,
        "is_python": python.get("is_python"),
        "python_free_threaded": python.get("free_threaded"),
    }
    if hw is not None:
        s["ipc"] = hw.get("ipc")
        s["llc_mpki"] = hw.get("llc_mpki")
        for k in ("ipc", "llc_mpki"):
            if s[k] is None:
                reasons[k] = (hw.get("unavailable") or {}).get(k, "not measured")
    else:
        reasons["ipc"] = reasons["llc_mpki"] = "hardware counters not collected"
    return s, reasons


def _ge(h: Hyp, side: str, s: dict, key: str, thr: str, w: int, note: str = "") -> bool:
    v = s.get(key)
    if v is not None and v >= T(thr):
        h.add(side, key, v, thr, w, note)
        return True
    return False


def _lt(h: Hyp, side: str, s: dict, key: str, thr: str, w: int, note: str = "") -> bool:
    v = s.get(key)
    if v is not None and v < T(thr):
        h.add(side, key, v, thr, w, note)
        return True
    return False


def _need(h: Hyp, s: dict, reasons: dict, *keys: str) -> None:
    for k in keys:
        if s.get(k) is None:
            h.missing(k, reasons.get(k, "not measured"))


def evaluate(s: dict[str, Any], reasons: dict[str, str]) -> list[dict[str, Any]]:
    hyps: list[Hyp] = []

    h = Hyp(
        "runqueue_contention",
        "Threads are runnable but wait for a CPU (more runnable work than CPUs it may use)",
        [],
        [],
        [],
        [
            "Measure the same pid at two load levels with snapshot_process_metrics and "
            "compare runqueue_wait_ratio and cpu_seconds_per_unit_work",
            "Reduce threads per process, or processes per host, and re-measure",
            "Give the workload dedicated CPUs (Kubernetes static CPU manager policy with a "
            "Guaranteed pod and integer CPU requests) and compare",
        ],
    )
    if not _ge(h, "for", s, "runqueue_wait_ratio", "runqueue_wait_ratio_very_high", 3):
        _ge(h, "for", s, "runqueue_wait_ratio", "runqueue_wait_ratio_high", 2)
    _lt(h, "against", s, "runqueue_wait_ratio", "runqueue_wait_ratio_low", 2)
    if (s.get("voluntary_share") is not None and s["voluntary_share"] < 0.5) or (
        s.get("voluntary_share") is None
    ):
        _ge(h, "for", s, "nonvoluntary_switches_per_s", "nonvoluntary_switches_per_s_high", 1)
    _ge(h, "for", s, "procs_running_per_core", "procs_running_per_core_high", 1)
    _lt(h, "against", s, "procs_running_per_core", "procs_running_per_core_low", 1)
    _ge(h, "for", s, "psi_cpu_some_window_pct", "psi_cpu_some_window_pct_high", 1)
    ratio = s.get("cfs_throttled_ratio")
    prc = s.get("procs_running_per_core")
    if (
        ratio is not None
        and ratio >= T("cfs_throttled_ratio_high")
        and prc is not None
        and prc < T("procs_running_per_core_high")
    ):
        h.add(
            "against",
            "cfs_throttled_ratio",
            ratio,
            "cfs_throttled_ratio_high",
            1,
            "the cgroup was throttled while the host had fewer runnable tasks than cores; "
            "throttled time can show up as run-queue wait",
        )
    _need(h, s, reasons, "runqueue_wait_ratio", "procs_running_per_core", "psi_cpu_some_window_pct")
    hyps.append(h)

    h = Hyp(
        "cache_or_memory_bound_contention",
        "Instructions per cycle are low and last-level cache misses are high "
        "(shared-cache or memory-bandwidth contention, or a memory-bound workload)",
        [],
        [],
        [],
        [
            "Measure ipc and llc_mpki with hw_counters at two densities (e.g. half the "
            "processes or pods on the host); a fall in IPC as density rises points at shared "
            "resources rather than the code itself",
            "Run on a host that exposes a PMU (bare metal, or a VM with a virtual PMU) if "
            "hw_counters reports no PMU",
            "If /sys/fs/resctrl is available, compare L3 occupancy and memory bandwidth",
        ],
        caveat="One window cannot separate contention from a workload that is memory-bound "
        "on its own; compare densities.",
    )
    _lt(h, "for", s, "ipc", "ipc_low", 2)
    _ge(h, "for", s, "llc_mpki", "llc_mpki_high", 2)
    _ge(h, "against", s, "ipc", "ipc_normal", 2)
    _lt(h, "against", s, "llc_mpki", "llc_mpki_low", 1)
    _need(h, s, reasons, "ipc", "llc_mpki")
    hyps.append(h)

    h = Hyp(
        "cfs_throttling",
        "The process's cgroup (or an ancestor) hits its CPU quota (cpu.max / cfs_quota_us)",
        [],
        [],
        [],
        [
            "Raise or remove the CPU limit on one instance and compare throttling and latency",
            "Compare usage with the quota over a shorter CFS period, since bursts within a "
            "period can be throttled even when the average is under the limit",
        ],
    )
    if s["cgroup_available"]:
        if s.get("tightest_limit_cores") is None:
            h.against.append(
                {
                    "signal": "tightest_limit_cores",
                    "value": None,
                    "note": "no CPU quota on the process's cgroup or its ancestors",
                    "weight": 3,
                }
            )
        else:
            if not _ge(h, "for", s, "cfs_throttled_ratio", "cfs_throttled_ratio_high", 3):
                _ge(h, "for", s, "cfs_throttled_ratio", "cfs_throttled_ratio_some", 1)
            _lt(h, "against", s, "cfs_throttled_ratio", "cfs_throttled_ratio_none", 2)
            _ge(h, "for", s, "throttled_seconds_per_s", "throttled_seconds_per_s_high", 1)
            _ge(
                h,
                "for",
                s,
                "process_cpu_cores_to_tightest_limit_ratio",
                "usage_to_limit_ratio_high",
                1,
            )
            if s.get("cfs_throttled_ratio") is None:
                h.missing("cfs_throttled_ratio", "no CFS periods were counted in the window")
    else:
        h.missing("cgroup", s.get("cgroup_reason") or "cgroup not found")
    hyps.append(h)

    h = Hyp(
        "lock_contention",
        "Threads block and wake often, mostly in futex (locks, condition variables)",
        [],
        [],
        [],
        [
            "Take stacks of the threads waiting in futex (cpu_stacks / py-spy dump for Python; "
            "gdb, or eBPF offcputime for native code)",
            "Re-measure with fewer threads; contention falls faster than throughput if a lock "
            "is shared",
        ],
    )
    vs = s.get("voluntary_share")
    vps = s.get("voluntary_switches_per_s")
    if (
        vs is not None
        and vps is not None
        and vs >= T("voluntary_share_high")
        and vps >= T("voluntary_switches_per_s_high")
    ):
        h.add(
            "for",
            "voluntary_switches_per_s",
            vps,
            "voluntary_switches_per_s_high",
            2,
            f"voluntary_share={vs}",
        )
    if (s.get("threads") or 0) >= 2:
        _ge(h, "for", s, "futex_wait_share", "futex_wait_share_high", 1)
    _ge(h, "for", s, "switches_per_cpu_second", "switches_per_cpu_second_high", 1)
    _lt(h, "against", s, "voluntary_switches_per_s", "voluntary_switches_per_s_low", 2)
    _lt(h, "against", s, "voluntary_share", "voluntary_share_low", 1)
    if (s.get("threads") or 0) < 2:
        h.against.append(
            {
                "signal": "threads",
                "value": s.get("threads"),
                "note": "single-threaded: no lock contention inside the process "
                "(cross-process locks remain possible)",
                "weight": 1,
            }
        )
    if s.get("futex_wait_share") is None:
        h.missing("futex_wait_share", "no sleeping threads were sampled")
    hyps.append(h)

    h = Hyp(
        "spin_waiting_or_compute",
        "Threads stay on CPU with few switches and normal IPC: busy-waiting or plain computation",
        [],
        [],
        [],
        [
            "Take on-CPU stacks (cpu_stacks / py-spy top, or perf record) and look for loops "
            "around atomics, polling or sched_yield",
            "Compare cpu_seconds_per_unit_work at two load levels: spinning grows CPU without "
            "growing work",
        ],
        caveat="Counters cannot tell spin-waiting from useful computation; stacks can.",
    )
    _ge(h, "for", s, "cpu_cores_used", "cpu_cores_used_busy", 1)
    _lt(h, "for", s, "switches_per_cpu_second", "switches_per_cpu_second_low", 1)
    _ge(h, "for", s, "user_share", "user_share_high", 1)
    if s.get("ipc") is not None and s["ipc"] >= T("ipc_low"):
        h.add("for", "ipc", s["ipc"], "ipc_low", 1, "IPC is not low")
    _lt(h, "against", s, "cpu_cores_used", "cpu_cores_used_idle", 2)
    if s.get("ipc") is not None and s["ipc"] < T("ipc_low"):
        h.add("against", "ipc", s["ipc"], "ipc_low", 1)
    _ge(h, "against", s, "switches_per_cpu_second", "switches_per_cpu_second_high", 1)
    _need(h, s, reasons, "ipc")
    hyps.append(h)

    h = Hyp(
        "gil_convoy",
        "Several Python threads take turns on the GIL: CPU stays near one core while threads "
        "hand off often",
        [],
        [],
        [],
        [
            "Take Python stacks with GIL information (cpu_stacks, or py-spy dump / "
            "py-spy top --gil) to see which threads hold and wait for the GIL",
            "Compare with the work split across processes instead of threads",
        ],
    )
    if s.get("is_python") is False:
        h.against.append(
            {"signal": "is_python", "value": False, "note": "not a Python process", "weight": 3}
        )
    elif s.get("is_python") is None:
        h.missing("is_python", "could not tell whether this is a CPython process")
    else:
        if s.get("python_free_threaded"):
            h.against.append(
                {
                    "signal": "python_free_threaded",
                    "value": True,
                    "note": "free-threaded build: no GIL by default",
                    "weight": 2,
                }
            )
        active = (s.get("mean_runnable_threads") or 0) + (s.get("mean_futex_waiting_threads") or 0)
        cores = s.get("cpu_cores_used")
        if (
            active >= T("active_threads_min")
            and cores is not None
            and cores <= T("gil_cores_ceiling")
        ):
            h.add(
                "for",
                "mean_active_threads",
                round(active, 2),
                "active_threads_min",
                2,
                f"while cpu_cores_used={cores} stays at or under {T('gil_cores_ceiling')} cores",
            )
        _ge(h, "for", s, "voluntary_switches_per_s", "voluntary_switches_per_s_gil", 1)
        _ge(h, "for", s, "futex_wait_share", "futex_wait_share_high", 1)
        _ge(h, "against", s, "cpu_cores_used", "gil_cores_exceeded", 2)
        if (s.get("threads") or 0) < 2:
            h.against.append(
                {"signal": "threads", "value": s.get("threads"), "note": "one thread", "weight": 2}
            )
    hyps.append(h)

    h = Hyp(
        "steal",
        "The hypervisor runs other guests on this VM's CPUs (steal time)",
        [],
        [],
        [],
        [
            "Compare steal over time with the cloud provider's metrics; try a dedicated or "
            "different instance type",
        ],
    )
    if not _ge(h, "for", s, "steal_pct", "steal_pct_very_high", 3):
        _ge(h, "for", s, "steal_pct", "steal_pct_high", 2)
    _lt(h, "against", s, "steal_pct", "steal_pct_low", 2)
    _need(h, s, reasons, "steal_pct")
    hyps.append(h)

    h = Hyp(
        "memory_pressure",
        "Tasks stall on memory (reclaim, swap-in, refaults)",
        [],
        [],
        [],
        [
            "Read memory.events and memory.stat of the cgroup; check for swap and reclaim",
            "For Python, heap_summary shows what is retained",
        ],
    )
    _ge(h, "for", s, "psi_memory_some_window_pct", "psi_memory_some_window_pct_high", 2)
    _ge(h, "for", s, "psi_memory_full_window_pct", "psi_memory_full_window_pct_high", 1)
    _ge(h, "for", s, "major_faults_per_s", "major_faults_per_s_high", 1)
    _lt(h, "against", s, "psi_memory_some_window_pct", "psi_memory_some_window_pct_low", 2)
    _lt(h, "against", s, "major_faults_per_s", "major_faults_per_s_low", 1)
    _need(h, s, reasons, "psi_memory_some_window_pct")
    hyps.append(h)

    h = Hyp(
        "io_pressure",
        "Threads wait on block I/O",
        [],
        [],
        [],
        [
            "Check /proc/<pid>/io rates (find_processes sort_by=read_bytes_per_s) and the "
            "block device's utilisation; look at the block_io wait channels",
        ],
    )
    _ge(h, "for", s, "psi_io_some_window_pct", "psi_io_some_window_pct_high", 2)
    _ge(h, "for", s, "iowait_seconds_per_s", "iowait_seconds_per_s_high", 2)
    _ge(h, "for", s, "disk_wait_share", "disk_wait_share_high", 1)
    _lt(h, "against", s, "psi_io_some_window_pct", "psi_io_some_window_pct_low", 1)
    if s.get("disk_wait_share") is not None and s["disk_wait_share"] == 0:
        h.against.append(
            {
                "signal": "disk_wait_share",
                "value": 0,
                "note": "no thread was sampled in D state or a block-I/O wait",
                "weight": 1,
            }
        )
    _need(h, s, reasons, "psi_io_some_window_pct", "iowait_seconds_per_s")
    hyps.append(h)

    results = [x.result() for x in hyps]
    order = {a: i for i, a in enumerate(ASSESSMENTS)}
    results.sort(key=lambda x: (-x["score"], order[x["assessment"]], len(x["unknown"])))
    for i, x in enumerate(results, 1):
        x["rank"] = i
    return results


def threshold_table() -> list[dict[str, Any]]:
    return [{"name": k, "value": v, "unit": u, "meaning": m} for k, (v, u, m) in THRESHOLDS.items()]
