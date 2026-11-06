"""Process CPU, scheduler and environment diagnostics for heapspy-mcp.

Every tool here is keyed on a process. Host and cgroup figures appear only as
the ``environment`` of that process: what it is subject to. ``register`` adds
the tools to an :class:`MCPServer`.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Any, TypeVar

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import DEFAULT_WINDOW, Config
from ..processes import matches_allowlist, version_from_exe, version_from_maps_text
from . import colocation as co
from . import diagnose as dg
from . import groups as grp
from . import perf, probe, stalls, views, windows
from . import procfs as pf
from . import search as srch
from .redact import redact_cmdline
from .sampling import ProcessGone, identify, list_tids, sample_process

T = TypeVar("T")

if sys.version_info < (3, 11):  # pragma: no cover
    from exceptiongroup import BaseExceptionGroup

PROCESS_WORKFLOW = """\
Process diagnostics (any process, not only Python):

1. If you do not know the pid: scan_processes (outliers by metric over one window, plus
   factual conditions such as threads in disk wait, zombies, fd use near the limit, RSS that
   grew on every sample, throttled cgroups, sustained major faults, memory pressure, threads
   in D in a memory wait, frozen cgroups and stopped processes, OOM kills), or find_processes
   (filters such as name, cmdline, user, parent, cgroup, container id, pod UID, state; sort_by
   one metric).
2. process_cpu(pid): CPU split, context switches (voluntary vs non-voluntary), run-queue wait,
   migrations, thread states, wait sites, top threads, and the process's environment: its
   cgroup (quota, throttling, pressure, cpuset, pod/container) and host CPU, steal and PSI.
3. Process hangs or is intermittently slow: watch_process_stalls(pid), then diagnose_process.
   It samples every thread at 20 Hz: the share of time in each kernel wait category
   (page-fault I/O, direct reclaim, memory.high throttling, compaction, futex, poll, block
   I/O, stopped or frozen, ...), fault rates, and the longest stretches with no CPU progress
   with example kernel stacks; plus the memory cgroup's limits, events, refaults and pressure,
   and whether the process is frozen or stopped on purpose.
4. Many processes compete for few CPUs, or sibling workers behave differently:
   cpu_colocation(pid | pids | name) shows which tasks shared each CPU the target ran on,
   their switches, wakeups, sleep lengths and timeslices, how tasks are placed across CPUs,
   and which co-located short sleepers are the likely source of the target's preemptions
   (an inference from rates, labelled as such). group_cpu(selector, group_by) measures a
   set of processes at once: per-member rows and per-group sum, mean, p50, p90, max and
   spread, so two services can be compared.
5. hw_counters(pid): IPC and last-level cache misses per 1000 instructions, when the host
   exposes a PMU; software events and schedstat timeslices otherwise. Without a PMU,
   cache_sensitivity_probe (opt-in, adds load) measures how much a synthetic working set of
   a given size slows down on this host when its CPU is time-sliced.
6. diagnose_process(pid, focus?): all of the above in one window, with each competing
   explanation scored against the numbers (evidence for, against, and unknown), plus next
   measurements, after a check for a deliberately frozen or stopped process.
   diagnose_process_cpu is the same tool under its earlier name. It ranks fits; it does not
   establish a cause.
7. snapshot_process_metrics(pid, work_rate?) or snapshot_group_metrics(selector,
   work_rate?) before and after a change, then compare_process_snapshots: CPU per unit of
   work and how each metric moved. With three or more snapshots at different settings,
   fit_per_slice_cost fits CPU per unit of work against timeslices per unit of work and
   returns the fixed CPU cost per timeslice.
8. For Python processes, go deeper with the heap tools (capture_snapshot, heap_summary) or
   stack tools where available.

Search, scan, cpu_colocation and group_cpu are open to any process the server can see: they
read the same per-task files as ps and top. Per-pid tools that read wait sites, stacks or
counters need the pid on the server's allowlist (--allow). Every rate states its window; a
signal that could not be measured is null with a reason, never 0.
"""


PidArg = Annotated[int, Field(description="Process id (must be on the server's allowlist).")]
WindowArg = Annotated[
    float,
    Field(
        description=f"Measurement window in seconds (default {DEFAULT_WINDOW:g}; the server caps "
        "it at its --max-window, default 10)."
    ),
]


class DiagnosticsRefused(Exception):
    def __init__(self, reason: str, message: str, **details: Any) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason = reason
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": "diagnostics_refused",
            "reason": self.reason,
            "message": self.message,
            **self.details,
        }


def _tool_error(payload: dict[str, Any]) -> ToolError:
    return ToolError(json.dumps({"error": payload}, ensure_ascii=False))


async def _guard(fn: Callable[[], Awaitable[T]]) -> T:
    try:
        return await fn()
    except DiagnosticsRefused as e:
        raise _tool_error(e.to_dict()) from e
    except ProcessGone as e:
        raise _tool_error({"code": "no_such_process", "message": str(e)}) from e
    except (srch.SearchError, windows.SnapshotError, grp.GroupError) as e:
        raise _tool_error({"code": "invalid_argument", "message": str(e)}) from e
    except probe.ProbeError as e:
        raise _tool_error({"code": "probe_failed", "message": str(e)}) from e


def check_pid(config: Config, pid: int) -> dict[str, Any]:
    """The allowlist gate shared by every per-pid tool."""
    proc_root = config.diagnostics.proc_root
    if pid <= 0:
        raise DiagnosticsRefused("invalid_argument", f"pid must be positive, got {pid}")
    try:
        ident = identify(proc_root, pid)
    except ProcessGone as e:
        raise DiagnosticsRefused("no_such_process", f"no process with pid {pid}") from e
    if not config.allow:
        raise DiagnosticsRefused(
            "allowlist_empty",
            "per-process tools are disabled: the server has an empty process allowlist. The "
            "user must start heapspy-mcp with --allow PATTERN (or HEAPSPY_MCP_ALLOW). "
            "find_processes and scan_processes work without it.",
            pid=pid,
            name=ident["name"],
        )
    entry = matches_allowlist(config.allow, pid=pid, **ident)
    if entry is None:
        raise DiagnosticsRefused(
            "not_allowlisted",
            f"pid {pid} ({ident['name']}) does not match the server's process allowlist. Only "
            "the user can change it (--allow / HEAPSPY_MCP_ALLOW).",
            pid=pid,
            name=ident["name"],
        )
    return {"allowlist_entry": entry, **ident}


def python_info(proc_root: Path, pid: int, exe: str | None, name: str | None) -> dict[str, Any]:
    version = version_from_exe(exe) or version_from_exe(name)
    free = bool(exe and re.search(r"python3\.\d+t$", Path(exe).name))
    maps = None
    if not version:
        maps = pf.read_text(proc_root / str(pid) / "maps") or ""
        version = version_from_maps_text(maps)
        free = free or bool(re.search(r"libpython3\.\d+t\.so", maps))
    by_name = bool(re.match(r"^python", Path(exe).name if exe else (name or "")))
    return {
        "is_python": bool(version) or by_name,
        "python_version": version,
        "free_threaded": free,
    }


FOCUS_CHOICES = ("all", "cpu", "memory", "io")
DIAGNOSE_STALL_RATE_HZ = 10.0
DIAGNOSE_COLOCATION_RATE_HZ = 20.0


def _colocation_digest(cov: dict[str, Any]) -> dict[str, Any]:
    """The co-location numbers diagnose_process read, without per-task detail."""
    att = cov["wakeup_preemption_attribution"]
    return {
        "targets": cov["targets"],
        "cpus": [
            {k: v for k, v in c.items() if k != "colocated_tasks"}
            | {
                "top_colocated": [
                    {
                        k: t.get(k)
                        for k in (
                            "pid",
                            "tid",
                            "comm",
                            "on_cpu_seconds_per_s",
                            "voluntary_switches_per_s",
                            "avg_sleep_us",
                            "short_sleeper",
                        )
                    }
                    for t in c["colocated_tasks"][:3]
                ]
            }
            for c in cov["cpus"]
        ],
        "placement": cov["placement"],
        "wakeup_preemption_attribution": {k: v for k, v in att.items() if k != "per_target_task"},
        "measurement": cov["measurement"],
        "note": "cpu_colocation gives every co-located task and per-target rows",
    }


def _stall_digest(st: dict[str, Any] | None) -> dict[str, Any] | None:
    """The stall numbers diagnose_process scored, without per-thread rows."""
    if st is None:
        return None
    pr = st["process"]
    keys = (
        "major_faults_per_s",
        "minor_faults_per_s",
        "system_share",
        "category_share",
        "category_share_of_active",
        "memory_stall_share_of_active",
        "memory_stall_no_progress_seconds_per_s",
        "no_progress_seconds_by_category",
        "memory",
        "delay_accounting",
    )
    return {
        **{k: pr.get(k) for k in keys},
        "longest_no_progress_intervals": pr["longest_no_progress_intervals"][:3],
        "frozen_or_stopped": st["frozen_or_stopped"],
        "note": "watch_process_stalls gives per-thread rows, more intervals and example stacks",
    }


def _window(config: Config, window_s: float) -> float:
    if window_s <= 0:
        raise DiagnosticsRefused("invalid_argument", "window_s must be positive")
    return min(window_s, config.diagnostics.max_window_s)


CmdlineCharsArg = Annotated[
    int,
    Field(
        description="Characters of each (redacted) command line to return, keeping the "
        f"start (default {srch.MAX_CMDLINE}; capped by the server's --max-cmdline-chars)."
    ),
]


GroupBy = Annotated[str, Field(description=grp.GROUP_BY_HELP)]
GroupRegex = Annotated[
    str | None,
    Field(description="With group_by=cmdline_regex: regex whose first group is the key."),
]
GroupRate = Annotated[
    float,
    Field(description=f"In-window state samples per second (default {grp.DEFAULT_RATE_HZ:g})."),
]
WorkRate = Annotated[
    float | None, Field(description="Units of work per second for the selection (one group).")
]
WorkRates = Annotated[
    dict[str, float] | None, Field(description="Group key -> units of work per second.")
]


def _selector(
    *,
    pid: int | None = None,
    pids: list[int] | None = None,
    name: str | None = None,
    cmdline: str | None = None,
    cmdline_regex: str | None = None,
    user: str | None = None,
    parent_pid: int | None = None,
    include_descendants: bool = True,
    cgroup: str | None = None,
    container_id: str | None = None,
    pod_uid: str | None = None,
) -> tuple[srch.Filters, dict[str, Any]]:
    all_pids = sorted({*(pids or []), *([pid] if pid is not None else [])}) or None
    given = {
        "pids": all_pids,
        "name": name,
        "cmdline": cmdline,
        "cmdline_regex": cmdline_regex,
        "user": user,
        "parent_pid": parent_pid,
        "cgroup": cgroup,
        "container_id": container_id,
        "pod_uid": pod_uid,
    }
    given = {k: v for k, v in given.items() if v is not None}
    if not given:
        raise DiagnosticsRefused(
            "invalid_argument",
            "give a selector: pid, pids, name, cmdline, cmdline_regex, user, parent_pid, "
            "cgroup, container_id or pod_uid",
        )
    f = srch.Filters(
        name=name,
        cmdline=cmdline,
        cmdline_regex=cmdline_regex,
        user=user,
        pids=all_pids,
        parent_pid=parent_pid,
        include_descendants=include_descendants,
        cgroup=cgroup,
        container_id=container_id,
        pod_uid=pod_uid,
    )
    return f, given


def register(server: MCPServer, config: Config) -> None:
    d = config.diagnostics
    store = windows.WindowStore()
    read_only = ToolAnnotations(read_only_hint=True, open_world_hint=False)
    low = getattr(server, "_lowlevel_server", None)
    if low is not None and getattr(low, "instructions", None):
        low.instructions = f"{low.instructions}\n{PROCESS_WORKFLOW}"

    async def measure(
        pid: int, window_s: float, hw: bool, rate_hz: float = views.DEFAULT_WAIT_RATE_HZ
    ) -> views.Measurement:
        session = perf.CounterSession(pid, proc_root=d.proc_root) if hw else None
        if rate_hz <= 0:
            raise DiagnosticsRefused("invalid_argument", "wait_sample_rate_hz must be positive")
        return await views.measure(
            d.proc_root,
            pid,
            _window(config, window_s),
            host=d.host_context,
            cgroup_root=d.cgroup_root,
            hw_session=session,
            wait_rate_hz=rate_hz,
            rate_cap_hz=d.max_stall_rate_hz,
        )

    def cmd_chars(n: int) -> int:
        if n < 16:
            raise DiagnosticsRefused("invalid_argument", "cmdline_max_chars must be at least 16")
        return min(n, d.max_cmdline_chars)

    async def colocate(
        target_pids: list[int], window_s: float, rate_hz: float, chars: int, max_rows: int
    ) -> dict[str, Any]:
        if rate_hz <= 0:
            raise DiagnosticsRefused("invalid_argument", "rate_hz must be positive")
        targets = {
            (p, t) for p in target_pids for t in list_tids(d.proc_root, p)[: co.MAX_TARGET_ROWS]
        }
        if not targets:
            raise DiagnosticsRefused("no_such_process", "no threads found for the target")
        statics = srch.collect_statics(d.proc_root).statics
        sampler = co.CoSampler(d.proc_root, targets, exclude_pids={os.getpid()})
        rate, note = await sampler.run(window_s, rate_hz, d.max_stall_rate_hz)

        def describe(p: int) -> dict[str, Any]:
            st = statics.get(p)
            return {"cmdline": redact_cmdline(st.cmdline, chars) if st else None}

        view = co.build_view(
            sampler, rate_hz=rate, rate_note=note, describe=describe, max_colocated=max_rows
        )
        view["target_pids"] = target_pids
        return view

    def hw_block(m: views.Measurement) -> dict[str, Any] | None:
        if m.hw is None:
            return None
        return {**perf.derived(m.hw, m.window_s), "counters": m.hw}

    @server.tool(
        annotations=read_only,
        description=(
            "Rank every process this server can see (any language) by one measured metric, "
            "with optional filters: name/exe glob, cmdline substring or regex, user, pids, "
            "parent_pid (with descendants), cgroup path substring, container_id prefix, pod_uid, "
            "/proc state letters, is_python. Rates are measured over window_s in one pass over "
            "all candidates. Each row has its metrics, cgroup, pod and container; command lines "
            "are redacted and truncated. Processes that exit or cannot be read are skipped and "
            "counted. Read-only; no allowlist needed."
        ),
    )
    async def find_processes(
        sort_by: Annotated[
            str | None,
            Field(description=f"One of: {', '.join(srch.METRICS)}. Default cpu_percent_on_cpu."),
        ] = None,
        name: Annotated[str | None, Field(description="Glob on process name or exe.")] = None,
        cmdline: Annotated[str | None, Field(description="Case-insensitive substring.")] = None,
        cmdline_regex: Annotated[str | None, Field(description="Python regex.")] = None,
        user: Annotated[str | None, Field(description="User name or numeric uid.")] = None,
        pids: Annotated[list[int] | None, Field(description="Only these pids.")] = None,
        parent_pid: Annotated[int | None, Field(description="Children of this pid.")] = None,
        include_descendants: Annotated[
            bool, Field(description="With parent_pid: all descendants, not only children.")
        ] = True,
        cgroup: Annotated[str | None, Field(description="Substring of the cgroup path.")] = None,
        container_id: Annotated[str | None, Field(description="Container id prefix.")] = None,
        pod_uid: Annotated[str | None, Field(description="Kubernetes pod UID.")] = None,
        state: Annotated[
            str | None, Field(description="/proc state letters to keep, e.g. D or RD.")
        ] = None,
        is_python: Annotated[bool | None, Field(description="Keep only (non-)Python.")] = None,
        include_kernel_threads: bool = False,
        descending: bool = True,
        limit: Annotated[int, Field(description=f"Rows (1 to {srch.MAX_LIMIT}).")] = 20,
        window_s: Annotated[
            float, Field(description="Window for rate metrics; 0 for an instant listing.")
        ] = 1.0,
        cmdline_max_chars: CmdlineCharsArg = srch.MAX_CMDLINE,
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            f = srch.Filters(
                name=name,
                cmdline=cmdline,
                cmdline_regex=cmdline_regex,
                user=user,
                pids=pids,
                parent_pid=parent_pid,
                include_descendants=include_descendants,
                cgroup=cgroup,
                container_id=container_id,
                pod_uid=pod_uid,
                state=state,
                is_python=is_python,
                include_kernel_threads=include_kernel_threads,
            )
            return await srch.find_processes(
                d.proc_root,
                f,
                sort_by=sort_by,
                descending=descending,
                limit=max(1, min(limit, srch.MAX_LIMIT)),
                window_s=window_s,
                window_cap=d.max_window_s,
                cgroup_root=d.cgroup_root,
                cmdline_max_chars=cmd_chars(cmdline_max_chars),
            )

        return await _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "One pass over every process: the top processes for each metric (outliers by "
            "metric: CPU, RSS and its growth, threads, context switches, run-queue wait, "
            "iowait, open fds and fd limit use, read/write bytes, uptime, cgroup throttling, "
            "major faults), and factual conditions with raw values: threads in disk wait for "
            "the whole window, zombies by parent, fd use above a stated share of "
            "RLIMIT_NOFILE, RSS that grew on every sample, cgroups throttled in the window, "
            "major faults above a stated rate for the whole window, cgroups with memory "
            "pressure 'full' in the window, threads in D in a memory-management wait (with "
            "other D threads as candidates for watch_process_stalls), frozen cgroups and "
            "stopped processes, OOM-kill counters. Use it when you do not yet know which "
            "process to look at. Read-only; no allowlist needed."
        ),
    )
    async def scan_processes(
        window_s: WindowArg = DEFAULT_WINDOW,
        limit_per_metric: Annotated[
            int, Field(description=f"Rows per metric (1 to {srch.MAX_PER_METRIC}).")
        ] = 5,
        fd_threshold_pct: Annotated[
            float, Field(description="Report fd use above this % of the soft limit.")
        ] = srch.DEFAULT_FD_THRESHOLD_PCT,
        major_fault_threshold_per_s: Annotated[
            float,
            Field(
                description="Report processes with at least this many major faults per "
                "second in every interval of the window."
            ),
        ] = srch.DEFAULT_MAJOR_FAULT_THRESHOLD_PER_S,
        include_kernel_threads: bool = False,
        cmdline_max_chars: CmdlineCharsArg = srch.MAX_CMDLINE,
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            return await srch.scan_processes(
                d.proc_root,
                window_s=window_s,
                window_cap=d.max_window_s,
                limit_per_metric=max(1, min(limit_per_metric, srch.MAX_PER_METRIC)),
                fd_threshold_pct=fd_threshold_pct,
                include_kernel_threads=include_kernel_threads,
                cgroup_root=d.cgroup_root,
                major_fault_threshold_per_s=major_fault_threshold_per_s,
                cmdline_max_chars=cmd_chars(cmdline_max_chars),
            )

        return await _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Measure one process over a window: CPU seconds (user, system), iowait seconds "
            "(delay accounting), voluntary and non-voluntary context switches per second "
            "summed over threads, run-queue wait (time runnable but not running) and its ratio "
            "to on-CPU time, timeslices and the average timeslice against the scheduler slice "
            "(se.slice), CPU migrations, page faults, thread states, where sleeping threads "
            "wait (futex, poll, timers, block I/O; sampled at wait_sample_rate_hz, default "
            "50 Hz), the top threads, and an environment block: "
            "the process's cgroup (quota, throttling, pressure, cpuset, Kubernetes pod and "
            "container) and the host's runnable count per core, CPU time split including "
            "steal, and PSI. Unmeasurable signals are null with a reason."
        ),
    )
    async def process_cpu(
        pid: PidArg,
        window_s: WindowArg = DEFAULT_WINDOW,
        top_threads: Annotated[
            int, Field(description=f"Threads per top list (0 to {views.MAX_TOP_THREADS}).")
        ] = 5,
        wait_sample_rate_hz: Annotated[
            float,
            Field(
                description="Rate of the in-window thread-state and wait-site samples (default "
                f"{views.DEFAULT_WAIT_RATE_HZ:g}; capped by --max-stall-rate and by "
                f"{views.MAX_THREAD_SAMPLES_PER_S:g} thread samples per second)."
            ),
        ] = views.DEFAULT_WAIT_RATE_HZ,
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            check_pid(config, pid)
            m = await measure(pid, window_s, hw=False, rate_hz=wait_sample_rate_hz)
            return views.full_view(m, max(0, min(top_threads, views.MAX_TOP_THREADS)))

        return await _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Hardware and software performance counters for every thread of one process over "
            "a window, through perf_event_open: cycles, instructions, last-level cache "
            "references and misses, context switches, CPU migrations and task clock. Returns "
            "ipc, llc_mpki (LLC misses per 1000 instructions) and llc_miss_ratio. Counts are "
            "scaled when the kernel multiplexes counters, and the scaling is reported. Where "
            "the host exposes no PMU (common in VMs) or permissions block it, the hardware "
            "fields are null with the exact reason, and software_fallback lists what can "
            "be measured instead: context switches per CPU-second, CPU migrations, "
            "timeslices and the average timeslice from schedstat, and the tools that look "
            "further (cpu_colocation, and cache_sensitivity_probe when the server enables it)."
        ),
    )
    async def hw_counters(pid: PidArg, window_s: WindowArg = DEFAULT_WINDOW) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            check_pid(config, pid)
            w = _window(config, window_s)
            session = perf.CounterSession(pid, proc_root=d.proc_root)
            before = sample_or_none(pid)
            session.start()
            try:
                t0 = anyio.current_time()
                await anyio.sleep(w)
                elapsed = anyio.current_time() - t0
            finally:
                counters = session.stop()
            after = sample_or_none(pid)
            derived = perf.derived(counters, elapsed)
            fallback = None
            if derived.get("ipc") is None or derived.get("llc_mpki") is None:
                fallback = software_fallback(derived, before, after)
            return {
                "pid": pid,
                "measurement": {"window_s": round(elapsed, 3), "window_requested_s": window_s},
                "threads_counted": len(session.tids),
                "threads_total": session.threads_total,
                "threads_truncated": session.threads_total > len(session.tids),
                **derived,
                "counters": counters,
                "resctrl": perf.resctrl_for_pid(pid),
                "software_fallback": fallback,
            }

        return await _guard(body)

    def sample_or_none(pid: int) -> Any:
        try:
            return sample_process(d.proc_root, pid, grp.MAX_THREADS_PER_MEMBER)
        except ProcessGone:
            return None

    def software_fallback(derived: dict[str, Any], a: Any, b: Any) -> dict[str, Any]:
        out: dict[str, Any] = {
            "why": "hardware counters are unavailable; these software measurements cover "
            "part of the same question",
            "context_switches_per_s": derived.get("context_switches_per_s"),
            "cpu_migrations_per_s": derived.get("cpu_migrations_per_s"),
        }
        tc = derived.get("task_clock_seconds")
        cs = derived.get("context_switches_per_s")
        out["context_switches_per_cpu_second"] = (
            round(cs * (b.t - a.t) / tc, 1) if cs is not None and tc and a and b else None
        )
        if a is not None and b is not None:
            mm = grp.member_metrics(a, b)["metrics"]
            for k in (
                "on_cpu_seconds_per_s",
                "timeslices_per_s",
                "avg_timeslice_us",
                "switches_per_cpu_second",
                "voluntary_share",
                "runqueue_wait_ratio",
            ):
                out[k] = mm.get(k)
            out["schedstat_source"] = "/proc/<tid>/schedstat over the same window"
        out["see_also"] = [
            "cpu_colocation(pid): which tasks share the process's CPUs, their wakeups and "
            "timeslices",
            "fit_per_slice_cost over snapshots at several settings: CPU cost per timeslice",
            "cache_sensitivity_probe: "
            + (
                "available (needs confirm=true; adds load)"
                if d.allow_load_probes
                else "disabled on this server (start it with --allow-load-probes)"
            )
            + "; measures a synthetic workload's sensitivity to cache sharing on this host, "
            "not this process's misses",
        ]
        return out

    @server.tool(
        annotations=read_only,
        description=(
            "Measure one process over a window (as process_cpu, plus hardware counters when "
            "available) and keep the key numbers in server memory under a token. Take one "
            "before and one after a change, then call compare_process_snapshots. work_rate is "
            "an optional number from your own metrics (requests/s, jobs/s); with it the "
            "snapshot records cpu_seconds_per_unit_work."
        ),
    )
    async def snapshot_process_metrics(
        pid: PidArg,
        window_s: WindowArg = DEFAULT_WINDOW,
        work_rate: Annotated[
            float | None, Field(description="Units of work per second during the window.")
        ] = None,
        label: Annotated[str | None, Field(description="Free text, e.g. 'before'.")] = None,
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            check_pid(config, pid)
            if work_rate is not None and work_rate <= 0:
                raise DiagnosticsRefused("invalid_argument", "work_rate must be positive")
            m = await measure(pid, window_s, hw=True)
            view = views.full_view(m)
            view["hw"] = hw_block(m)
            return store.put(pid, view, work_rate, (label or "")[:80] or None)

        return await _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Compare two snapshots from snapshot_process_metrics (pm-...) or two from "
            "snapshot_group_metrics (pg-...): each metric before, after, change and ratio; "
            "for groups, per group key. When both have a work rate: CPU seconds per unit of "
            "work before and after, and cpu_per_unit_work_ratio (above 1 means CPU grew "
            "faster than work). For three or more snapshots use fit_per_slice_cost."
        ),
    )
    async def compare_process_snapshots(
        before: Annotated[str, Field(description="Token of the earlier snapshot (pm-...).")],
        after: Annotated[str, Field(description="Token of the later snapshot.")],
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            return windows.compare(store.get(before), store.get(after))

        return await _guard(body)

    selector_doc = (
        "Selector (any combination, as in find_processes): pid, pids, name (glob on name or "
        "exe), cmdline (substring), cmdline_regex, user, parent_pid (with descendants unless "
        "include_descendants=false), cgroup (substring), container_id (prefix), pod_uid."
    )

    @server.tool(
        annotations=read_only,
        description=(
            "Which tasks shared CPUs with a target over a window. Every running task on the "
            "host is sampled at rate_hz for its state and last CPU (/proc/<pid>/task/<tid>/stat "
            "field 39); counters come from status and schedstat at the start and end. For each "
            "CPU the target ran on: the target's tasks and the co-located tasks, their "
            "voluntary and non-voluntary switches, wakeups per second (voluntary switches), "
            "mean runnable tasks, and per task the average timeslice (on-CPU time / schedstat "
            "timeslices), average sleep per wakeup and whether it is a short sleeper. "
            "placement: target and other busy tasks per CPU and runnable imbalance. "
            "wakeup_preemption_attribution: the target's non-voluntary switches next to the "
            "co-located wakeups on the same CPU, the share from short sleepers, and their "
            "correlation across target tasks; this is an inference from rates, not a trace. "
            + selector_doc
            + " Reads the same per-task files as ps; no allowlist needed."
        ),
    )
    async def cpu_colocation(
        pid: Annotated[int | None, Field(description="Target process id.")] = None,
        pids: Annotated[list[int] | None, Field(description="Several target pids.")] = None,
        name: Annotated[str | None, Field(description="Glob on process name or exe.")] = None,
        cmdline: Annotated[str | None, Field(description="Case-insensitive substring.")] = None,
        cmdline_regex: Annotated[str | None, Field(description="Python regex.")] = None,
        parent_pid: int | None = None,
        cgroup: Annotated[str | None, Field(description="Substring of the cgroup path.")] = None,
        pod_uid: str | None = None,
        container_id: str | None = None,
        window_s: WindowArg = DEFAULT_WINDOW,
        rate_hz: Annotated[
            float,
            Field(
                description=f"Samples per second (default {co.DEFAULT_RATE_HZ:g}; capped by "
                f"--max-stall-rate and by {co.MAX_TASK_SAMPLES_PER_S:g} task samples per "
                "second)."
            ),
        ] = co.DEFAULT_RATE_HZ,
        colocated_per_cpu: Annotated[
            int, Field(description="Co-located task rows per CPU (0 to 50).")
        ] = co.MAX_COLOCATED_ROWS,
        cmdline_max_chars: CmdlineCharsArg = srch.MAX_CMDLINE,
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            f, given = _selector(
                pid=pid,
                pids=pids,
                name=name,
                cmdline=cmdline,
                cmdline_regex=cmdline_regex,
                parent_pid=parent_pid,
                cgroup=cgroup,
                pod_uid=pod_uid,
                container_id=container_id,
            )
            f.prepare()
            statics = srch.collect_statics(d.proc_root).statics
            me = os.getpid()
            matched = [p for p in srch.apply_filters(statics, f, d.proc_root) if p != me]
            if not matched:
                raise DiagnosticsRefused("no_such_process", "no process matches the selector")
            view = await colocate(
                matched[: co.MAX_TARGET_ROWS],
                _window(config, window_s),
                rate_hz,
                cmd_chars(cmdline_max_chars),
                max(0, min(colocated_per_cpu, 50)),
            )
            view["selector"] = given
            view["targets_matched"] = len(matched)
            view["targets_truncated"] = len(matched) > co.MAX_TARGET_ROWS
            return view

        return await _guard(body)

    group_args_doc = (
        "group_by: "
        + grp.GROUP_BY_HELP
        + ". work_rate: units of work per second for the selection (one group), or "
        "work_rates: group key -> units/s; with it each group reports "
        "cpu_seconds_per_unit_work and timeslices_per_unit_work."
    )

    async def run_group(
        f: srch.Filters,
        group_by: str,
        group_regex: str | None,
        window_s: float,
        rate_hz: float,
        work_rate: float | None,
        work_rates: dict[str, float] | None,
        chars: int,
        include_members: bool,
    ) -> dict[str, Any]:
        if rate_hz <= 0:
            raise DiagnosticsRefused("invalid_argument", "rate_hz must be positive")
        return await grp.group_cpu(
            d.proc_root,
            f,
            group_by=group_by,
            group_regex=group_regex,
            window_s=_window(config, window_s),
            rate_hz=rate_hz,
            rate_cap_hz=d.max_stall_rate_hz,
            work_rate=work_rate,
            work_rates=work_rates,
            cmdline_max_chars=chars,
            include_members=include_members,
        )

    @server.tool(
        annotations=read_only,
        description=(
            "Measure a group of processes over one window, as process_cpu measures one: per "
            "member CPU, on-CPU time, voluntary and non-voluntary switches, run-queue wait, "
            "timeslices and average timeslice, migrations, faults, threads and runnable share; "
            "per group the sum, mean, p50, p90, min, max, spread (max minus min), max/min and "
            "cv of each metric, pooled ratios, and placement of members across CPUs. Groups "
            "are formed by group_by so services can be compared (a comparison block is added "
            "when there are two or more). "
            + selector_doc
            + " "
            + group_args_doc
            + " Reads the same per-task files as find_processes; no allowlist needed."
        ),
    )
    async def group_cpu(
        name: Annotated[str | None, Field(description="Glob on process name or exe.")] = None,
        cmdline: Annotated[str | None, Field(description="Case-insensitive substring.")] = None,
        cmdline_regex: Annotated[str | None, Field(description="Python regex.")] = None,
        pids: list[int] | None = None,
        user: str | None = None,
        parent_pid: int | None = None,
        include_descendants: bool = True,
        cgroup: Annotated[str | None, Field(description="Substring of the cgroup path.")] = None,
        container_id: str | None = None,
        pod_uid: str | None = None,
        group_by: GroupBy = "none",
        group_regex: GroupRegex = None,
        window_s: WindowArg = DEFAULT_WINDOW,
        rate_hz: GroupRate = grp.DEFAULT_RATE_HZ,
        work_rate: WorkRate = None,
        work_rates: WorkRates = None,
        include_members: Annotated[bool, Field(description="Return per-member rows.")] = True,
        cmdline_max_chars: CmdlineCharsArg = srch.MAX_CMDLINE,
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            f, given = _selector(
                pids=pids,
                name=name,
                cmdline=cmdline,
                cmdline_regex=cmdline_regex,
                user=user,
                parent_pid=parent_pid,
                include_descendants=include_descendants,
                cgroup=cgroup,
                container_id=container_id,
                pod_uid=pod_uid,
            )
            out = await run_group(
                f,
                group_by,
                group_regex,
                window_s,
                rate_hz,
                work_rate,
                work_rates,
                cmd_chars(cmdline_max_chars),
                include_members,
            )
            out["selector"] = given
            return out

        return await _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Measure a group of processes as group_cpu does and keep the per-group numbers in "
            "server memory under a token (pg-...). Take snapshots before and after a change "
            "and compare them with compare_process_snapshots, or take three or more at "
            "different settings and fit them with fit_per_slice_cost. "
            + selector_doc
            + " "
            + group_args_doc
        ),
    )
    async def snapshot_group_metrics(
        name: Annotated[str | None, Field(description="Glob on process name or exe.")] = None,
        cmdline: Annotated[str | None, Field(description="Case-insensitive substring.")] = None,
        cmdline_regex: Annotated[str | None, Field(description="Python regex.")] = None,
        pids: list[int] | None = None,
        user: str | None = None,
        parent_pid: int | None = None,
        include_descendants: bool = True,
        cgroup: Annotated[str | None, Field(description="Substring of the cgroup path.")] = None,
        container_id: str | None = None,
        pod_uid: str | None = None,
        group_by: GroupBy = "none",
        group_regex: GroupRegex = None,
        window_s: WindowArg = DEFAULT_WINDOW,
        rate_hz: GroupRate = grp.DEFAULT_RATE_HZ,
        work_rate: WorkRate = None,
        work_rates: WorkRates = None,
        label: Annotated[str | None, Field(description="Free text, e.g. '2 cores'.")] = None,
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            f, given = _selector(
                pids=pids,
                name=name,
                cmdline=cmdline,
                cmdline_regex=cmdline_regex,
                user=user,
                parent_pid=parent_pid,
                include_descendants=include_descendants,
                cgroup=cgroup,
                container_id=container_id,
                pod_uid=pod_uid,
            )
            view = await run_group(
                f,
                group_by,
                group_regex,
                window_s,
                rate_hz,
                work_rate,
                work_rates,
                srch.MAX_CMDLINE,
                False,
            )
            return store.put_group(view, (label or "")[:80] or None, given)

        return await _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Fit CPU seconds per unit of work against timeslices per unit of work across three "
            "or more snapshots (all pm-... of one process, or all pg-... of one group) taken at "
            "different settings, such as different CPU counts or co-location: y = a + b x, "
            "equivalently a + b / units_of_work_per_timeslice. Returns "
            "fixed_cost_per_timeslice_us (b, the CPU each timeslice costs on top of the work in "
            "it, such as refilling caches), cost_per_unit_work_without_slicing_us (a), their "
            "standard errors, R squared and residuals, and each point with its average "
            "timeslice and timeslices per second. Warns when fewer than 3 points are usable. "
            "work_rates (token -> units/s) supplies or overrides the work rate of a snapshot, "
            "for rates known only after the window."
        ),
    )
    async def fit_per_slice_cost(
        tokens: Annotated[list[str], Field(description="Snapshot tokens, 2 to 32.")],
        group: Annotated[
            str | None, Field(description="Group key, when the group snapshots have several.")
        ] = None,
        work_rates: Annotated[
            dict[str, float] | None, Field(description="Snapshot token -> units of work per s.")
        ] = None,
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            for k, v in (work_rates or {}).items():
                if v <= 0:
                    raise DiagnosticsRefused(
                        "invalid_argument", f"work_rates[{k}] must be positive"
                    )
            entries = [store.get(t) for t in tokens]
            return windows.fit_per_slice_cost(entries, group=group, work_rates=work_rates)

        return await _guard(body)

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=False, open_world_hint=False),
        description=(
            "Opt-in benchmark for hosts without hardware counters: how much a synthetic working "
            "set of each size slows down on this host when its CPU is time-sliced. It runs in "
            "separate processes and never attaches to, reads or signals the target. Per size "
            "it walks a random linked list pinned to one CPU, alone and then shared: with "
            "mode=synthetic against two neighbours on the same CPU (one walking a large buffer, "
            "one waking every ~50 us), or with mode=colocated on the CPU where pid ran most, "
            "against the target's co-located tasks. Reports ns per access alone and shared, "
            "the slowdown, the probe's timeslices, and extra CPU microseconds per timeslice. "
            "Sizes default to the host's L1d/L2/L3 from sysfs. It measures cache sensitivity "
            "of a synthetic workload on this host, not the target's misses. It adds up to one "
            "CPU of load for up to 2 x sizes x phase_s seconds, so it needs confirm=true and "
            "a server started with --allow-load-probes."
        ),
    )
    async def cache_sensitivity_probe(
        confirm: Annotated[
            bool, Field(description="Must be true: the probe adds CPU load to the chosen CPU.")
        ] = False,
        mode: Annotated[str, Field(description="synthetic (default) or colocated.")] = "synthetic",
        pid: Annotated[
            int | None, Field(description="With mode=colocated: the target (allowlisted).")
        ] = None,
        cpu: Annotated[
            int | None,
            Field(
                description="CPU for the alone phase (and, for synthetic, the shared phase). "
                "Default: the highest CPU this server may use (for colocated, one other than "
                "the target's)."
            ),
        ] = None,
        sizes_bytes: Annotated[
            list[int] | None,
            Field(description=f"Working-set sizes, up to {probe.MAX_SIZES}; default from sysfs."),
        ] = None,
        phase_s: Annotated[
            float,
            Field(
                description=f"Seconds per phase (default {probe.DEFAULT_PHASE_S:g}, max "
                f"{probe.MAX_PHASE_S:g})."
            ),
        ] = probe.DEFAULT_PHASE_S,
        neighbour_bytes: Annotated[
            int | None,
            Field(description="Synthetic big neighbour's buffer (default 4 x L2, at least 8 MiB)."),
        ] = None,
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            if not d.allow_load_probes:
                raise DiagnosticsRefused(
                    "load_probes_disabled",
                    "cache_sensitivity_probe is off on this server; it adds CPU load. The user "
                    "can enable it with --allow-load-probes (or HEAPSPY_MCP_ALLOW_LOAD_PROBES=1).",
                )
            if mode not in ("synthetic", "colocated"):
                raise DiagnosticsRefused("invalid_argument", "mode must be synthetic or colocated")
            if not 0.1 <= phase_s <= probe.MAX_PHASE_S:
                raise DiagnosticsRefused(
                    "invalid_argument", f"phase_s must be 0.1 to {probe.MAX_PHASE_S:g}"
                )
            topo = pf.read_cache_topology()
            if sizes_bytes:
                if len(sizes_bytes) > probe.MAX_SIZES:
                    raise DiagnosticsRefused("invalid_argument", f"at most {probe.MAX_SIZES} sizes")
                bad = [
                    x
                    for x in sizes_bytes
                    if not probe.MIN_WORKING_SET <= x <= probe.MAX_WORKING_SET
                ]
                if bad:
                    raise DiagnosticsRefused(
                        "invalid_argument",
                        f"sizes must be {probe.MIN_WORKING_SET} to {probe.MAX_WORKING_SET} bytes",
                    )
                sizes, basis = sorted(set(sizes_bytes)), "given"
            else:
                sizes, basis = probe.default_sizes(topo)
            l2 = pf.cache_size(topo, 2) or 2 * 1024 * 1024
            nb = neighbour_bytes or max(4 * l2, 8 * 1024 * 1024)
            if not probe.MIN_WORKING_SET <= nb <= probe.MAX_WORKING_SET:
                raise DiagnosticsRefused("invalid_argument", "neighbour_bytes out of range")
            usable = sorted(os.sched_getaffinity(0))
            shared_cpu = None
            if mode == "colocated":
                if pid is None:
                    raise DiagnosticsRefused("invalid_argument", "mode=colocated needs pid")
                check_pid(config, pid)
                shared_cpu = probe.target_home_cpu(d.proc_root, pid)
                if shared_cpu is None or shared_cpu not in usable:
                    raise DiagnosticsRefused(
                        "invalid_argument",
                        f"the target's CPU ({shared_cpu}) is not one this server may run on",
                    )
            alone_cpu = cpu
            if alone_cpu is None:
                others = [c for c in usable if c != shared_cpu]
                alone_cpu = (others or usable)[-1]
            if alone_cpu not in usable:
                raise DiagnosticsRefused(
                    "invalid_argument", f"cpu {alone_cpu} is not in this server's affinity {usable}"
                )
            if shared_cpu is None:
                shared_cpu = alone_cpu
            plan = {
                "mode": mode,
                "alone_cpu": alone_cpu,
                "shared_cpu": shared_cpu,
                "working_set_bytes": sizes,
                "sizes_basis": basis,
                "phase_s": phase_s,
                "max_duration_s": round(2 * len(sizes) * phase_s + len(sizes) * 0.2, 1),
                "neighbour_bytes": nb if mode == "synthetic" else None,
            }
            if not confirm:
                raise DiagnosticsRefused(
                    "confirmation_required",
                    "this probe adds CPU load; call again with confirm=true to run it",
                    plan=plan,
                )
            res = await probe.run_probe(
                cpu=alone_cpu,
                shared_cpu=shared_cpu,
                sizes=sizes,
                phase_s=phase_s,
                mode=mode,
                neighbour_bytes=nb,
            )
            return {
                "plan": plan,
                "cache_topology": topo,
                **res,
                "what_this_measures": "how much a synthetic pointer-chasing working set of each "
                "size slows down, per second of its own CPU time, when its CPU is shared; on "
                "this host. It is not a measurement of the target's cache misses.",
                "reading": "slowdown_ratio near 1: the size fits regardless of sharing, or "
                "misses either way. Well above 1: data that fits in the per-core cache when "
                "alone is evicted while the CPU runs other tasks, and refilled every slice. "
                "extra_cpu_us_per_timeslice estimates that refill per slice; compare it with "
                "fixed_cost_per_timeslice_us from fit_per_slice_cost.",
                "caveats": [
                    "the alone phase shares its CPU with whatever else the host runs there",
                    "the Python fallback adds interpreter overhead per access, which hides "
                    "much of the difference; build tools on the host give the C version",
                ],
            }

        return await _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Sample every thread of one process at a fixed rate over a window (default 5 s at "
            "20 Hz) to see whether it keeps leaving its hot path for the kernel: per thread, the "
            "share of samples in each state and kernel wait category (page_fault_io, "
            "direct_reclaim, memcg_high_throttle, dirty_throttle, compaction, oom, futex, poll, "
            "nanosleep, ipc_wait, block_io, stopped_or_frozen, running, other), major and minor "
            "faults per second, and the longest intervals in which its CPU time did not advance "
            "while it was not voluntarily idle, each with its dominant category and an example "
            "kernel stack. Per process: fault totals, RSS and swap, delay accounting when "
            "enabled, and whether the process is frozen by a cgroup freezer or stopped. "
            "environment: the memory cgroup (usage against memory.max/memory.high, "
            "memory.events and memory.stat deltas, memory.pressure over the window) and host "
            "memory PSI and /proc/vmstat reclaim and refault counters. Use it when a process "
            "hangs or is intermittently slow; then diagnose_process. Kernel stacks need root; "
            "without them categories come from wchan."
        ),
    )
    async def watch_process_stalls(
        pid: PidArg,
        window_s: Annotated[
            float,
            Field(
                description=f"Seconds to sample (default {stalls.DEFAULT_STALL_WINDOW:g}; capped "
                "at the server's --max-window)."
            ),
        ] = stalls.DEFAULT_STALL_WINDOW,
        rate_hz: Annotated[
            float,
            Field(
                description=f"Samples per second per thread (default {stalls.DEFAULT_RATE_HZ:g}; "
                "capped at the server's --max-stall-rate, default 100)."
            ),
        ] = stalls.DEFAULT_RATE_HZ,
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            check_pid(config, pid)
            if rate_hz <= 0:
                raise DiagnosticsRefused("invalid_argument", "rate_hz must be positive")
            return await stalls.watch(
                d.proc_root,
                pid,
                _window(config, window_s),
                rate_hz,
                host=d.host_context,
                cgroup_root=d.cgroup_root,
                rate_cap_hz=d.max_stall_rate_hz,
            )

        return await _guard(body)

    async def diagnose(pid: int, window_s: float, focus: str) -> dict[str, Any]:
        if focus not in FOCUS_CHOICES:
            raise DiagnosticsRefused(
                "invalid_argument", f"focus must be one of {', '.join(FOCUS_CHOICES)}"
            )
        ident = check_pid(config, pid)
        w = _window(config, window_s)
        got: dict[str, Any] = {}

        async def run_measure() -> None:
            got["m"] = await measure(pid, w, hw=True)

        async def run_colocation() -> None:
            try:
                got["co"] = await colocate([pid], w, DIAGNOSE_COLOCATION_RATE_HZ, 120, 3)
            except (ProcessGone, DiagnosticsRefused) as e:
                got["co_reason"] = str(e)

        async def run_stalls() -> None:
            try:
                got["stalls"] = await stalls.watch(
                    d.proc_root,
                    pid,
                    w,
                    min(DIAGNOSE_STALL_RATE_HZ, d.max_stall_rate_hz),
                    host=d.host_context,
                    cgroup_root=d.cgroup_root,
                    rate_cap_hz=d.max_stall_rate_hz,
                )
            except ProcessGone as e:
                got["stalls_reason"] = str(e)

        # Both sample the same window side by side.
        try:
            async with anyio.create_task_group() as tg:
                tg.start_soon(run_measure)
                tg.start_soon(run_stalls)
                tg.start_soon(run_colocation)
        except BaseExceptionGroup as eg:
            raise eg.exceptions[0] from eg
        m = got["m"]
        st = got.get("stalls")
        view = views.full_view(m)
        hw = hw_block(m)
        py = python_info(d.proc_root, pid, ident.get("exe"), ident.get("name"))
        cov = got.get("co")
        signals, reasons = dg.extract_signals(
            view, hw, py, st, got.get("stalls_reason"), cov, got.get("co_reason")
        )
        ranked = dg.evaluate(signals, reasons)
        facts = dg.fact_checks(signals, reasons)
        if focus != "all":
            ranked = [h for h in ranked if h["id"] in dg.FOCUS[focus]]
        caveats = [
            "Scores compare these numbers with fixed thresholds from one window; they "
            "rank how well each explanation fits, they do not prove one.",
            "Several explanations can hold at once, and an unmeasured signal "
            "(listed under unknown) can change the ranking.",
        ]
        if signals.get("deliberately_frozen"):
            caveats.insert(0, facts[0]["consequence"])
        return {
            "pid": pid,
            "comm": view["comm"],
            "focus": focus,
            "measurement": {
                **view["measurement"],
                "stall_sampling": st["measurement"] if st else None,
            },
            "python": py,
            "fact_checks": facts,
            "hypotheses": ranked,
            "signals": signals,
            "signal_unavailable_reasons": reasons,
            "thresholds": dg.threshold_table(),
            "caveats": caveats,
            "process": {k: view[k] for k in ("cpu", "context_switches", "scheduler")},
            "memory_stalls": _stall_digest(st),
            "colocation": _colocation_digest(cov) if cov else None,
            "environment": {
                **view["environment"],
                "cgroup_memory": st["environment"]["cgroup_memory"] if st else None,
                "host_memory": st["environment"]["host"] if st else None,
            },
            "hw": hw,
        }

    @server.tool(
        annotations=read_only,
        description=(
            "Measure one process and its environment over a window (process_cpu plus hardware "
            "counters, per-thread stall sampling as in watch_process_stalls at 10 Hz, and "
            "cpu_colocation at 20 Hz) and score competing explanations for its CPU use, CPU "
            "wait, slowness or stalls: run-queue contention, short timeslices from co-located "
            "wakeups, cache or memory-bound contention, CFS throttling, lock contention, "
            "spin-waiting or compute (a runnable thread that gets no CPU counts as starved, "
            "not idle), GIL convoy, steal, memory thrashing, I/O pressure. Each has evidence "
            "for, evidence against (raw value, threshold, weight) "
            "and unknown signals, and next measurements to tell them apart. A fact check "
            "first reports whether the process is deliberately frozen (cgroup freezer) or "
            "stopped (signal, ptrace); if so the explanations are moot. focus lists only the "
            "cpu, memory or io explanations (all are still measured). The ranking says how "
            "well each fits these numbers; it does not establish a cause, and several can "
            "apply at once."
        ),
    )
    async def diagnose_process(
        pid: PidArg,
        window_s: WindowArg = DEFAULT_WINDOW,
        focus: Annotated[
            str, Field(description=f"One of: {', '.join(FOCUS_CHOICES)}. Default all.")
        ] = "all",
    ) -> dict[str, Any]:
        return await _guard(lambda: diagnose(pid, window_s, focus))

    @server.tool(
        annotations=read_only,
        description=(
            "Same as diagnose_process(pid, window_s, focus='all'); kept under its earlier "
            "name. Scores explanations for a process's CPU use, CPU wait, slowness or "
            "stalls, after checking whether it is deliberately frozen or stopped."
        ),
    )
    async def diagnose_process_cpu(
        pid: PidArg, window_s: WindowArg = DEFAULT_WINDOW
    ) -> dict[str, Any]:
        return await _guard(lambda: diagnose(pid, window_s, "all"))

    @server.resource(
        "heapspy://process-workflow",
        name="process-workflow",
        description="How to find and diagnose a process's CPU use and stalls with these tools.",
        mime_type="text/markdown",
    )
    def process_workflow() -> str:
        return PROCESS_WORKFLOW

    @server.prompt(
        name="investigate_process_cpu",
        description="Walk through finding a process and explaining its CPU use or slowness.",
    )
    def investigate_process_cpu(target: str = "") -> str:
        lead = f"Investigate the CPU behaviour of {target}.\n\n" if target else ""
        return lead + PROCESS_WORKFLOW
