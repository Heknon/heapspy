"""Turn start/end samples into the ``process_cpu`` view and its ``environment`` block.

Field names carry their unit (``_seconds``, ``_per_s``, ``_pct``, ``_ratio``,
``_bytes``). A signal that could not be measured is ``null`` and has an entry
in the enclosing ``unavailable`` map saying why; it is never reported as 0.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio

from . import cgroups as cg
from . import procfs as pf
from .sampling import (
    CgroupSample,
    HostSample,
    ProcessSample,
    TickAccumulator,
    locate_cgroup,
    sample_cgroup,
    sample_host,
    sample_process,
)

TICKS = 4  # host samples (runnable count) inside the window
DEFAULT_WAIT_RATE_HZ = 50.0
# Thread samples per second the wait-site sampler may take (threads x rate); with
# more threads the rate is lowered to stay under it, and the result says so.
MAX_THREAD_SAMPLES_PER_S = 5000.0
MAX_TOP_THREADS = 20
MAX_CPU_ROWS = 64


def r(x: float | None, nd: int = 3) -> float | None:
    return None if x is None else round(x, nd)


def compress_cpus(cpus: list[int]) -> str:
    out: list[str] = []
    i = 0
    while i < len(cpus):
        j = i
        while j + 1 < len(cpus) and cpus[j + 1] == cpus[j] + 1:
            j += 1
        out.append(str(cpus[i]) if i == j else f"{cpus[i]}-{cpus[j]}")
        i = j + 1
    return ",".join(out)


# --- measurement --------------------------------------------------------------


@dataclass
class Measurement:
    pid: int
    window_requested_s: float
    a: ProcessSample
    b: ProcessSample
    ticks: TickAccumulator
    host_a: HostSample | None
    host_b: HostSample | None
    cg_a: CgroupSample | None
    cg_b: CgroupSample | None
    cg_reason: str | None
    delayacct: bool | None
    hw: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    sampling: dict[str, Any] = field(default_factory=dict)
    proc_root: Path = Path("/proc")

    @property
    def window_s(self) -> float:
        return max(self.b.t - self.a.t, 1e-9)


def effective_rate(rate_hz: float, cap_hz: float, threads: int) -> tuple[float, str | None]:
    """The wait-site sampling rate after the server cap and the thread-sample budget."""
    rate = max(1.0, min(rate_hz, cap_hz))
    note = None
    if rate < rate_hz:
        note = f"rate capped at the server's --max-stall-rate ({cap_hz:g} Hz)"
    budget = MAX_THREAD_SAMPLES_PER_S / max(threads, 1)
    if budget < rate:
        rate = max(1.0, budget)
        note = (
            f"rate lowered to {rate:g} Hz so that {threads} threads stay within "
            f"{MAX_THREAD_SAMPLES_PER_S:g} thread samples per second"
        )
    return rate, note


async def measure(
    proc_root: Path,
    pid: int,
    window_s: float,
    *,
    host: bool,
    cgroup_root: Path | None,
    hw_session: Any | None = None,
    wait_rate_hz: float = DEFAULT_WAIT_RATE_HZ,
    rate_cap_hz: float = 100.0,
) -> Measurement:
    """Sample at the start and the end of the window, and inside it: thread states and
    wait sites at ``wait_rate_hz`` (capped), the host's runnable count ``TICKS`` times."""
    loc, cg_reason = locate_cgroup(proc_root, pid, cgroup_root)
    host_a = sample_host(proc_root) if host else None
    cg_a = sample_cgroup(loc) if loc else None
    if hw_session is not None:
        hw_session.start()
    a = sample_process(proc_root, pid)
    ticks = TickAccumulator(proc_root, pid)
    rate, note = effective_rate(wait_rate_hz, rate_cap_hz, min(len(a.threads), 256))
    n = max(TICKS, int(window_s * rate))
    period = window_s / (n + 1)
    host_at = {round((i + 1) * (n + 1) / (TICKS + 1)) - 1 for i in range(TICKS)}
    t0 = anyio.current_time()
    late = 0
    for k in range(n):
        delay = t0 + (k + 1) * period - anyio.current_time()
        if delay > 0:
            await anyio.sleep(delay)
        else:
            late += 1
        ticks.tick(host and k in host_at)
    delay = t0 + window_s - anyio.current_time()
    if delay > 0:
        await anyio.sleep(delay)
    b = sample_process(proc_root, pid)
    hw = hw_session.stop() if hw_session is not None else None
    host_b = sample_host(proc_root) if host else None
    cg_b = sample_cgroup(loc) if loc else None
    return Measurement(
        pid=pid,
        window_requested_s=window_s,
        a=a,
        b=b,
        ticks=ticks,
        host_a=host_a,
        host_b=host_b,
        cg_a=cg_a,
        cg_b=cg_b,
        cg_reason=cg_reason,
        delayacct=pf.read_task_delayacct(proc_root),
        hw=hw,
        proc_root=proc_root,
        sampling={
            "rate_hz_requested": wait_rate_hz,
            "rate_hz": round(rate, 2),
            "samples": ticks.ticks,
            "late_samples": late,
            "sampler_cpu_seconds": round(ticks.cpu_s, 4),
            **({"rate_note": note} if note else {}),
        },
    )


# --- process ------------------------------------------------------------------


def _thread_deltas(m: Measurement) -> list[dict[str, Any]]:
    rows = []
    hz = pf.USER_HZ
    for tid, tb in m.b.threads.items():
        ta = m.a.threads.get(tid)
        new = ta is None

        def d(attr: str, ta=ta, tb=tb) -> int | None:
            vb = getattr(tb, attr)
            va = 0 if ta is None else getattr(ta, attr)
            return None if vb is None or va is None else vb - va

        run = wait = slices = None
        if tb.sched is not None:
            sa = ta.sched if ta is not None else pf.SchedStat(0, 0, 0)
            if sa is not None:
                run = tb.sched.run_ns - sa.run_ns
                wait = tb.sched.wait_ns - sa.wait_ns
                slices = tb.sched.timeslices - sa.timeslices
        cpu_ticks = (d("utime_ticks") or 0) + (d("stime_ticks") or 0)
        rows.append(
            {
                "tid": tid,
                "comm": tb.comm,
                "state": tb.state,
                "started_in_window": new,
                "cpu_seconds": cpu_ticks / hz,
                "voluntary": d("voluntary"),
                "nonvoluntary": d("nonvoluntary"),
                "run_ns": run,
                "wait_ns": wait,
                "timeslices": slices,
                "migrations": d("migrations"),
                "blkio_ticks": d("blkio_ticks"),
                "last_cpu": tb.processor,
            }
        )
    return rows


def _sum(rows: list[dict[str, Any]], key: str) -> int | None:
    vals = [row[key] for row in rows]
    if not vals or any(v is None for v in vals):
        return None
    return sum(vals)


def process_view(m: Measurement, top_n: int = 5) -> dict[str, Any]:
    w = m.window_s
    hz = pf.USER_HZ
    unavailable: dict[str, str] = {}
    rows = _thread_deltas(m)
    user_s = (m.b.stat.utime_ticks - m.a.stat.utime_ticks) / hz
    sys_s = (m.b.stat.stime_ticks - m.a.stat.stime_ticks) / hz
    vol = _sum(rows, "voluntary")
    nonvol = _sum(rows, "nonvoluntary")
    run = _sum(rows, "run_ns")
    wait = _sum(rows, "wait_ns")
    slices = _sum(rows, "timeslices")
    mig = _sum(rows, "migrations")
    blkio = _sum(rows, "blkio_ticks")

    switches: dict[str, Any] = {
        "voluntary_switches_per_s": r(vol / w, 1) if vol is not None else None,
        "nonvoluntary_switches_per_s": r(nonvol / w, 1) if nonvol is not None else None,
    }
    if vol is None or nonvol is None:
        unavailable["context_switches"] = "voluntary_ctxt_switches missing from /proc/<tid>/status"
        switches["voluntary_share"] = None
        switches["switches_per_cpu_second"] = None
    else:
        total = vol + nonvol
        switches["voluntary_share"] = r(vol / total) if total else None
        if not total:
            unavailable["voluntary_share"] = "no context switches in the window"
        cpu = user_s + sys_s
        switches["switches_per_cpu_second"] = r(total / cpu, 1) if cpu > 0 else None
        if cpu <= 0:
            unavailable["switches_per_cpu_second"] = "no CPU time in the window"

    sched: dict[str, Any] = {}
    if run is None or wait is None:
        reason = "/proc/<tid>/schedstat missing (kernel without CONFIG_SCHED_INFO)"
        for k in (
            "on_cpu_seconds",
            "runqueue_wait_seconds",
            "runqueue_wait_ratio",
            "runqueue_wait_seconds_per_s",
            "on_cpu_seconds_per_s",
            "timeslices_per_s",
        ):
            sched[k] = None
            unavailable[k] = reason
    else:
        sched["on_cpu_seconds"] = r(run / 1e9, 4)
        sched["runqueue_wait_seconds"] = r(wait / 1e9, 4)
        sched["runqueue_wait_ratio"] = r(wait / run) if run > 0 else None
        if run <= 0:
            unavailable["runqueue_wait_ratio"] = "no on-CPU time in the window"
        sched["runqueue_wait_seconds_per_s"] = r(wait / 1e9 / w)
        sched["on_cpu_seconds_per_s"] = r(run / 1e9 / w)
        sched["timeslices_per_s"] = r(slices / w, 1) if slices is not None else None
    sched.update(_slice_fields(m, run, slices, vol, nonvol, unavailable))
    if mig is None:
        sched["cpu_migrations_per_s"] = None
        unavailable["cpu_migrations_per_s"] = (
            "se.nr_migrations missing from /proc/<tid>/sched (needs CONFIG_SCHED_DEBUG); "
            "hw_counters reports migrations from the perf software event"
        )
    else:
        sched["cpu_migrations_per_s"] = r(mig / w, 1)

    if m.delayacct is False:
        iowait = None
        unavailable["iowait_seconds"] = (
            "delay accounting is off (kernel.task_delayacct=0); enable it with "
            "sysctl kernel.task_delayacct=1 or boot with delayacct"
        )
    elif blkio is None:
        iowait = None
        unavailable["iowait_seconds"] = "delayacct_blkio_ticks missing from /proc/<tid>/stat"
    else:
        iowait = r(blkio / hz, 3)

    states = pf.empty_state_counts()
    for row in rows:
        states[pf.state_bucket(row["state"])] += 1
    tick_total = sum(m.ticks.states.values())
    wait_total = sum(m.ticks.wait_sites.values())

    def top(key: str) -> list[dict[str, Any]]:
        ranked = sorted(
            (row for row in rows if row.get(key) is not None),
            key=lambda row: row[key],
            reverse=True,
        )
        return [_thread_row(row, w) for row in ranked[:top_n] if row[key]]

    cpu_s = user_s + sys_s
    return {
        "pid": m.pid,
        "comm": m.b.stat.comm,
        "cpu": {
            "cpu_seconds_user": r(user_s),
            "cpu_seconds_system": r(sys_s),
            "cpu_cores_used": r(cpu_s / w),
            "cpu_percent_on_cpu": r(cpu_s / w * 100, 1),
            "user_share": r(user_s / cpu_s) if cpu_s > 0 else None,
        },
        "iowait_seconds": iowait,
        "page_faults": {
            "major_faults_per_s": r((m.b.stat.majflt - m.a.stat.majflt) / w, 1),
            "minor_faults_per_s": r((m.b.stat.minflt - m.a.stat.minflt) / w, 1),
        },
        "context_switches": switches,
        "scheduler": sched,
        "threads": {
            "count": m.b.threads_total,
            "sampled": len(m.b.threads),
            "truncated": m.b.threads_truncated,
            "started_in_window": sum(1 for row in rows if row["started_in_window"]),
            "exited_in_window": len(set(m.a.threads) - set(m.b.threads)),
            "threads_by_state": states,
            "state_share_over_window": {
                k: r(v / tick_total) for k, v in sorted(m.ticks.states.items())
            }
            if tick_total
            else None,
        },
        "wait_sites": {
            "samples": m.ticks.ticks,
            "rate_hz": m.sampling.get("rate_hz"),
            "thread_samples": tick_total,
            "sleeping_thread_samples": wait_total,
            "samples_by_site": dict(m.ticks.wait_sites.most_common()),
            "share_by_site": {k: r(v / wait_total) for k, v in m.ticks.wait_sites.most_common()}
            if wait_total
            else {},
            "top_wait_channels": [
                {"wchan": k, "samples": v} for k, v in m.ticks.wchans.most_common(5)
            ],
            "note": "kernel functions sleeping threads were blocked in, sampled "
            f"{m.ticks.ticks} times at {m.sampling.get('rate_hz')} Hz; futex covers locks, "
            "condition variables and the GIL",
        },
        "top_threads": {
            "by_cpu_seconds": top("cpu_seconds"),
            "by_nonvoluntary_switches": top("nonvoluntary"),
            "by_voluntary_switches": top("voluntary"),
            "by_runqueue_wait": top("wait_ns"),
        },
        "unavailable": unavailable,
    }


def _slice_fields(
    m: Measurement,
    run: int | None,
    slices: int | None,
    vol: int | None,
    nonvol: int | None,
    unavailable: dict[str, str],
) -> dict[str, Any]:
    """Average timeslice over the window and the scheduler's slice for these threads."""
    out: dict[str, Any] = {}
    if run is not None and slices:
        out["avg_timeslice_us"] = r(run / slices / 1000, 1)
        out["avg_timeslice_source"] = "schedstat on-CPU time / timeslices (pcount)"
    elif run is not None and vol is not None and nonvol is not None and vol + nonvol:
        out["avg_timeslice_us"] = r(run / (vol + nonvol) / 1000, 1)
        out["avg_timeslice_source"] = (
            "schedstat on-CPU time / (voluntary + non-voluntary switches): no timeslice count"
        )
    else:
        out["avg_timeslice_us"] = None
        unavailable["avg_timeslice_us"] = (
            "no timeslices in the window" if run is not None else "schedstat missing"
        )
    slices_ns = sorted(t.slice_ns for t in m.b.threads.values() if t.slice_ns)
    if slices_ns:
        out["sched_slice_us"] = r(slices_ns[len(slices_ns) // 2] / 1000, 1)
        out["sched_slice_source"] = "se.slice from /proc/<tid>/sched (median over threads)"
    else:
        base = pf.default_base_slice(m.proc_root, Path("/sys"), os.cpu_count() or 1)
        out["sched_slice_us"] = r(base["slice_ns"] / 1000, 1)
        out["sched_slice_source"] = base["source"]
    if out["avg_timeslice_us"] is not None and out["sched_slice_us"]:
        out["avg_timeslice_to_sched_slice_ratio"] = r(
            out["avg_timeslice_us"] / out["sched_slice_us"]
        )
    else:
        out["avg_timeslice_to_sched_slice_ratio"] = None
    return out


def _thread_row(row: dict[str, Any], w: float) -> dict[str, Any]:
    run, wait = row["run_ns"], row["wait_ns"]
    return {
        "tid": row["tid"],
        "comm": row["comm"],
        "state": row["state"],
        "cpu_seconds": r(row["cpu_seconds"]),
        "voluntary_switches_per_s": r(row["voluntary"] / w, 1)
        if row["voluntary"] is not None
        else None,
        "nonvoluntary_switches_per_s": r(row["nonvoluntary"] / w, 1)
        if row["nonvoluntary"] is not None
        else None,
        "runqueue_wait_ratio": r(wait / run) if run else None,
        "runqueue_wait_seconds": r(wait / 1e9, 4) if wait is not None else None,
        "last_cpu": row["last_cpu"],
    }


# --- environment --------------------------------------------------------------


def _psi_block(
    a: dict[str, dict[str, float]] | None, b: dict[str, dict[str, float]] | None, w: float
) -> dict[str, Any] | None:
    if b is None:
        return None
    out: dict[str, Any] = {}
    for kind in ("some", "full"):
        row = b.get(kind)
        if row is None:
            continue
        before = (a or {}).get(kind, {}).get("total_us")
        after = row.get("total_us")
        out[kind] = {
            "avg10_pct": row.get("avg10"),
            "avg60_pct": row.get("avg60"),
            "window_pct": r((after - before) / (w * 1e6) * 100, 2)
            if before is not None and after is not None
            else None,
        }
    return out


def host_view(m: Measurement) -> dict[str, Any]:
    ha, hb = m.host_a, m.host_b
    assert ha is not None and hb is not None
    w = max(hb.t - ha.t, 1e-9)
    unavailable: dict[str, str] = {}
    cores = os.cpu_count() or (hb.stat.per_cpu_count if hb.stat else None)
    out: dict[str, Any] = {"cores_online": cores}
    if ha.stat and hb.stat:
        sa, sb = ha.stat, hb.stat
        keys = [k for k in pf.STAT_CPU_FIELDS[:8] if k in sa.cpu_ticks and k in sb.cpu_ticks]
        deltas = {k: sb.cpu_ticks[k] - sa.cpu_ticks[k] for k in keys}
        total = sum(deltas.values())
        out["cpu_time_pct"] = {
            f"{k}_pct": r(v / total * 100, 2) if total else None for k, v in deltas.items()
        }
        if "steal" not in keys:
            unavailable["steal_pct"] = "this kernel's /proc/stat has no steal column"
        out["context_switches_per_s"] = (
            r((sb.ctxt - sa.ctxt) / w, 1) if sa.ctxt is not None and sb.ctxt is not None else None
        )
    else:
        out["cpu_time_pct"] = None
        unavailable["cpu_time_pct"] = "/proc/stat unreadable"
    pr = m.ticks.procs_running
    if pr:
        mean = sum(pr) / len(pr)
        out["procs_running_mean"] = r(mean, 2)
        out["procs_running_max"] = max(pr)
        out["procs_running_per_core"] = r(mean / cores, 3) if cores else None
        out["procs_running_note"] = (
            f"sampled {len(pr)} times; includes the thread doing the sampling"
        )
    else:
        out["procs_running_mean"] = None
        unavailable["procs_running_mean"] = "no in-window samples of /proc/stat"
    out["load_average"] = hb.loadavg
    out["psi"] = {res: _psi_block(ha.psi.get(res), hb.psi.get(res), w) for res in hb.psi}
    for res, val in out["psi"].items():
        if val is None:
            unavailable[f"psi.{res}"] = f"/proc/pressure/{res} missing (CONFIG_PSI off or psi=0)"
    if ha.schedstat and hb.schedstat:
        before = {c.cpu: c for c in ha.schedstat.cpus}
        rows = []
        for c in hb.schedstat.cpus:
            p = before.get(c.cpu)
            if p is None:
                continue
            rows.append(
                {
                    "cpu": c.cpu,
                    "runqueue_wait_seconds_per_s": r((c.waiting_ns - p.waiting_ns) / 1e9 / w),
                    "busy_seconds_per_s": r((c.running_ns - p.running_ns) / 1e9 / w),
                }
            )
        out["runqueue_wait_per_cpu"] = rows[:MAX_CPU_ROWS]
        out["runqueue_wait_seconds_per_s_all_cpus"] = r(
            sum(x["runqueue_wait_seconds_per_s"] or 0 for x in rows)
        )
    else:
        out["runqueue_wait_per_cpu"] = None
        unavailable["runqueue_wait_per_cpu"] = hb.schedstat_reason or "unreadable"
    out["window_s"] = r(w)
    out["unavailable"] = unavailable
    return out


def cgroup_view(m: Measurement, process_cores: float | None) -> dict[str, Any]:
    if m.cg_a is None or m.cg_b is None:
        return {"available": False, "reason": m.cg_reason}
    a, b = m.cg_a, m.cg_b
    loc = b.location
    w = max(b.t - a.t, 1e-9)
    unavailable: dict[str, str] = {}
    pod = cg.parse_kubepods_path(loc.path)
    root = loc.cpu_root

    def rel(d: str) -> str:
        try:
            return "/" + Path(d).relative_to(root).as_posix() if root else d
        except ValueError:
            return d

    levels = []
    for d, sb in b.stats.items():
        sa = a.stats.get(d, {})

        def delta(k: str, sa=sa, sb=sb) -> int | None:
            x, y = sa.get(k), sb.get(k)
            return None if x is None or y is None else y - x

        usage = delta("usage_usec")
        periods = delta("nr_periods")
        throttled = delta("nr_throttled")
        tus = delta("throttled_usec")
        lim = b.limits.get(d)
        limit_cores = lim.get("limit_cores") if lim else None
        level: dict[str, Any] = {
            "path": rel(d) if rel(d) != "/." else "/",
            "cpu_cores_used": r(usage / 1e6 / w) if usage is not None else None,
            "cpu_seconds_user": r(delta("user_usec") / 1e6)
            if delta("user_usec") is not None
            else None,
            "cpu_seconds_system": r(delta("system_usec") / 1e6)
            if delta("system_usec") is not None
            else None,
            "limit": lim,
            "usage_to_limit_ratio": r(usage / 1e6 / w / limit_cores)
            if usage is not None and limit_cores
            else None,
            "nr_periods": periods,
            "nr_throttled": throttled,
            "throttled_seconds": r(tus / 1e6, 4) if tus is not None else None,
            "throttled_seconds_per_s": r(tus / 1e6 / w, 4) if tus is not None else None,
            "cfs_throttled_ratio": r(throttled / periods)
            if periods and throttled is not None
            else None,
        }
        if not periods:
            level["cfs_throttled_ratio_unavailable_reason"] = (
                "no CFS enforcement periods in the window (no quota on this cgroup, or idle)"
                if lim is None or lim.get("quota_usec") is None or periods == 0
                else "nr_periods not reported"
            )
        levels.append(level)
    own = levels[0] if levels else {}
    with_quota = [lv for lv in levels if lv.get("limit") and lv["limit"].get("quota_usec")]
    ratios = [lv for lv in levels if lv.get("cfs_throttled_ratio") is not None]
    worst = max(ratios, key=lambda lv: lv["cfs_throttled_ratio"], default=None)
    pressure = {res: _psi_block(a.pressure.get(res), b.pressure.get(res), w) for res in b.pressure}
    for res, val in pressure.items():
        if val is None:
            unavailable[f"pressure.{res}"] = (
                f"{res}.pressure not found in the process's cgroup v2 directory"
            )
    if not loc.cpuacct_matches:
        unavailable["cpu_cores_used"] = (
            "cgroup v1: the process's cpuacct cgroup is not the same path as its cpu cgroup, "
            "so CPU usage of the cpu cgroup cannot be read"
        )
    cpus = cg.read_cpuset(loc)
    if cpus is None:
        unavailable["cpuset_cpus_effective"] = "cpuset file not readable"
    tightest = min((lv["limit"]["limit_cores"] for lv in with_quota), default=None)
    return {
        "available": True,
        "cgroup_version": loc.version,
        "path": loc.path,
        "kubernetes": pod,
        "own": own,
        "ancestors_with_quota": [lv for lv in levels[1:]],
        "tightest_limit_cores": tightest,
        "process_cpu_cores_to_tightest_limit_ratio": r(process_cores / tightest)
        if process_cores is not None and tightest
        else None,
        "max_cfs_throttled_ratio": worst["cfs_throttled_ratio"] if worst else None,
        "max_cfs_throttled_ratio_path": worst["path"] if worst else None,
        "pressure": pressure,
        "pressure_dir": str(loc.pressure_dir) if loc.pressure_dir else None,
        "cpuset_cpus_effective": compress_cpus(cpus) if cpus else None,
        "cpuset_cpu_count": len(cpus) if cpus else None,
        "notes": loc.notes,
        "unavailable": unavailable,
    }


def environment_view(m: Measurement, process_cores: float | None) -> dict[str, Any]:
    env: dict[str, Any] = {
        "description": "what this process is subject to: its cgroup and, unless disabled, "
        "host-wide CPU, steal and pressure over the same window",
        "cgroup": cgroup_view(m, process_cores),
    }
    if m.host_a is not None:
        env["host"] = host_view(m)
    else:
        env["host"] = None
        env["host_unavailable_reason"] = "host context disabled by the server (--no-host-context)"
    return env


def full_view(m: Measurement, top_n: int = 5) -> dict[str, Any]:
    pv = process_view(m, top_n)
    return {
        "measurement": {
            "window_s": r(m.window_s),
            "window_requested_s": m.window_requested_s,
            "in_window_samples": m.ticks.ticks,
            "wait_site_sampling": m.sampling,
            "started_at_unix": round(m.a.wall, 3),
        },
        **pv,
        "environment": environment_view(m, pv["cpu"]["cpu_cores_used"]),
    }
