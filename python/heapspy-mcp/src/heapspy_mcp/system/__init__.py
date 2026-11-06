"""Process CPU, scheduler and environment diagnostics for heapspy-mcp.

Every tool here is keyed on a process. Host and cgroup figures appear only as
the ``environment`` of that process: what it is subject to. ``register`` adds
the tools to an :class:`MCPServer`.
"""

from __future__ import annotations

import json
import re
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
from . import diagnose as dg
from . import perf, stalls, views, windows
from . import procfs as pf
from . import search as srch
from .sampling import ProcessGone, identify

T = TypeVar("T")

PROCESS_WORKFLOW = """\
Process diagnostics (any process, not only Python):

1. If you do not know the pid: scan_processes (outliers by metric over one window, plus
   factual conditions such as threads in disk wait, zombies, fd use near the limit, RSS that
   grew on every sample, throttled cgroups, OOM kills), or find_processes (filters such as
   name, cmdline, user, parent, cgroup, container id, pod UID, state; sort_by one metric).
2. process_cpu(pid): CPU split, context switches (voluntary vs non-voluntary), run-queue wait,
   migrations, thread states, wait sites, top threads, and the process's environment: its
   cgroup (quota, throttling, pressure, cpuset, pod/container) and host CPU, steal and PSI.
3. hw_counters(pid): IPC and last-level cache misses per 1000 instructions, when the host
   exposes a PMU; software events otherwise.
4. diagnose_process_cpu(pid): all of the above in one window, with each competing explanation
   scored against the numbers (evidence for, against, and unknown), plus next measurements.
   It ranks fits; it does not establish a cause.
5. snapshot_process_metrics(pid, work_rate?) before and after a change, then
   compare_process_snapshots: CPU per unit of work and how each metric moved.
6. For Python processes, go deeper with the heap tools (capture_snapshot, heap_summary) or
   stack tools where available.

Search and scan are open to any process the server can see. Per-pid tools need the pid on the
server's allowlist (--allow). Every rate states its window; a signal that could not be
measured is null with a reason, never 0.
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
    except (srch.SearchError, windows.SnapshotError) as e:
        raise _tool_error({"code": "invalid_argument", "message": str(e)}) from e


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


def _window(config: Config, window_s: float) -> float:
    if window_s <= 0:
        raise DiagnosticsRefused("invalid_argument", "window_s must be positive")
    return min(window_s, config.diagnostics.max_window_s)


def register(server: MCPServer, config: Config) -> None:
    d = config.diagnostics
    store = windows.WindowStore()
    read_only = ToolAnnotations(read_only_hint=True, open_world_hint=False)
    low = getattr(server, "_lowlevel_server", None)
    if low is not None and getattr(low, "instructions", None):
        low.instructions = f"{low.instructions}\n{PROCESS_WORKFLOW}"

    async def measure(pid: int, window_s: float, hw: bool) -> views.Measurement:
        session = perf.CounterSession(pid, proc_root=d.proc_root) if hw else None
        return await views.measure(
            d.proc_root,
            pid,
            _window(config, window_s),
            host=d.host_context,
            cgroup_root=d.cgroup_root,
            hw_session=session,
        )

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
            )

        return await _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "One pass over every process: the top processes for each metric (outliers by "
            "metric: CPU, RSS and its growth, threads, context switches, run-queue wait, "
            "iowait, open fds and fd limit use, read/write bytes, uptime, cgroup throttling), "
            "and factual conditions with raw values: threads in disk wait for the whole "
            "window, zombies by parent, fd use above a stated share of RLIMIT_NOFILE, RSS that "
            "grew on every sample, cgroups throttled in the window, OOM-kill counters. Use it "
            "when you do not yet know which process to look at. Read-only; no allowlist needed."
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
        include_kernel_threads: bool = False,
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
            )

        return await _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Measure one process over a window: CPU seconds (user, system), iowait seconds "
            "(delay accounting), voluntary and non-voluntary context switches per second "
            "summed over threads, run-queue wait (time runnable but not running) and its ratio "
            "to on-CPU time, CPU migrations, page faults, thread states, where sleeping threads "
            "wait (futex, poll, timers, block I/O), the top threads, and an environment block: "
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
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            check_pid(config, pid)
            m = await measure(pid, window_s, hw=False)
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
            "fields are null with the exact reason."
        ),
    )
    async def hw_counters(pid: PidArg, window_s: WindowArg = DEFAULT_WINDOW) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            check_pid(config, pid)
            w = _window(config, window_s)
            session = perf.CounterSession(pid, proc_root=d.proc_root)
            session.start()
            try:
                t0 = anyio.current_time()
                await anyio.sleep(w)
                elapsed = anyio.current_time() - t0
            finally:
                counters = session.stop()
            return {
                "pid": pid,
                "measurement": {"window_s": round(elapsed, 3), "window_requested_s": window_s},
                "threads_counted": len(session.tids),
                "threads_total": session.threads_total,
                "threads_truncated": session.threads_total > len(session.tids),
                **perf.derived(counters, elapsed),
                "counters": counters,
                "resctrl": perf.resctrl_for_pid(pid),
            }

        return await _guard(body)

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
            "Compare two snapshots from snapshot_process_metrics: each metric before, after, "
            "change and ratio. When both have work_rate: CPU seconds per unit of work before "
            "and after, and cpu_per_unit_work_ratio (above 1 means CPU grew faster than work)."
        ),
    )
    async def compare_process_snapshots(
        before: Annotated[str, Field(description="Token of the earlier snapshot (pm-...).")],
        after: Annotated[str, Field(description="Token of the later snapshot.")],
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            return windows.compare(store.get(before), store.get(after))

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

    @server.tool(
        annotations=read_only,
        description=(
            "Measure one process and its environment over a window (process_cpu plus hardware "
            "counters) and score competing explanations for its CPU use, CPU wait or slowness: "
            "run-queue contention, cache or memory-bound contention, CFS throttling, lock "
            "contention, spin-waiting or compute, GIL convoy, steal, memory pressure, I/O "
            "pressure. Each has evidence for, evidence against (raw value, threshold, weight) "
            "and unknown signals, and next measurements to tell them apart. The ranking says "
            "how well each fits these numbers; it does not establish a cause, and several can "
            "apply at once."
        ),
    )
    async def diagnose_process_cpu(
        pid: PidArg, window_s: WindowArg = DEFAULT_WINDOW
    ) -> dict[str, Any]:
        async def body() -> dict[str, Any]:
            ident = check_pid(config, pid)
            m = await measure(pid, window_s, hw=True)
            view = views.full_view(m)
            hw = hw_block(m)
            py = python_info(d.proc_root, pid, ident.get("exe"), ident.get("name"))
            signals, reasons = dg.extract_signals(view, hw, py)
            return {
                "pid": pid,
                "comm": view["comm"],
                "measurement": view["measurement"],
                "python": py,
                "hypotheses": dg.evaluate(signals, reasons),
                "signals": signals,
                "signal_unavailable_reasons": reasons,
                "thresholds": dg.threshold_table(),
                "caveats": [
                    "Scores compare these numbers with fixed thresholds from one window; they "
                    "rank how well each explanation fits, they do not prove one.",
                    "Several explanations can hold at once, and an unmeasured signal "
                    "(listed under unknown) can change the ranking.",
                ],
                "process": {k: view[k] for k in ("cpu", "context_switches", "scheduler")},
                "environment": view["environment"],
                "hw": hw,
            }

        return await _guard(body)

    @server.resource(
        "heapspy://process-workflow",
        name="process-workflow",
        description="How to find and diagnose a process's CPU behaviour with these tools.",
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
