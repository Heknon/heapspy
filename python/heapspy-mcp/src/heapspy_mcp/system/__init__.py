"""Process CPU, scheduler and environment diagnostics for heapspy-mcp.

Every tool here is keyed on a process. Host and cgroup figures appear only as
the ``environment`` of that process: what it is subject to. ``register`` adds
the tools to an :class:`MCPServer`.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, TypeVar

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import DEFAULT_WINDOW, Config
from ..processes import matches_allowlist
from . import perf, views
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


def _window(config: Config, window_s: float) -> float:
    if window_s <= 0:
        raise DiagnosticsRefused("invalid_argument", "window_s must be positive")
    return min(window_s, config.diagnostics.max_window_s)


def register(server: MCPServer, config: Config) -> None:
    d = config.diagnostics
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
