"""CPU tools backed by py-spy: what a process is doing, and where its time goes.

``register(server, config)`` adds ``cpu_stacks`` to the server.

Every tool attaches to a live process, so every tool goes through
:func:`check_target`: the pid must be on the server's allowlist (the same
``--allow`` / ``HEAPSPY_MCP_ALLOW`` list that gates ``capture_snapshot``), it
may not be the server itself, and each attach is logged to stderr. There is no
``confirm`` argument: sampling only reads memory and, in the default
non-blocking mode, does not pause the target. The allowlist is the user's
consent.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections import Counter
from collections.abc import Callable
from typing import Annotated, Any, TypeVar

import psutil
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from .config import Config
from .processes import describe_cmdline, matches_allowlist
from .pyspy import PySpy, PySpyError, frame_from_dump, thread_state
from .summarize import clamp, clip

log = logging.getLogger("heapspy_mcp.cpu")

MAX_THREADS = 200
MAX_FRAMES = 100

T = TypeVar("T")

# -- errors and gates --------------------------------------------------------------


class AttachRefused(Exception):
    """A safety gate refused to attach py-spy. ``reason`` is a stable code."""

    def __init__(self, reason: str, message: str, **details: Any) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason = reason
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": "attach_refused",
            "reason": self.reason,
            "message": self.message,
            **self.details,
        }


def _tool_error(payload: dict[str, Any]) -> ToolError:
    return ToolError(json.dumps({"error": payload}, ensure_ascii=False))


def _guard(fn: Callable[[], T]) -> T:
    try:
        return fn()
    except (PySpyError, AttachRefused) as e:
        raise _tool_error(e.to_dict()) from e


def check_target(config: Config, pid: int) -> dict[str, Any]:
    """Apply the attach gates to ``pid``; return what is known about the target."""
    if pid <= 0:
        raise AttachRefused("invalid_argument", f"pid must be positive, got {pid}")
    if pid == os.getpid():
        raise AttachRefused("invalid_argument", "refusing to attach to the heapspy-mcp server")
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            name = proc.name()
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                exe = None
            try:
                cmdline = proc.cmdline()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                cmdline = None
    except psutil.NoSuchProcess as e:
        raise AttachRefused("no_such_process", f"no process with pid {pid}") from e
    except psutil.AccessDenied as e:
        raise AttachRefused(
            "process_inaccessible", f"cannot inspect pid {pid} to check the allowlist"
        ) from e
    if not config.allow:
        raise AttachRefused(
            "attach_disabled",
            "CPU sampling is disabled: the server has an empty process allowlist. The user "
            "must start heapspy-mcp with --allow PATTERN (or HEAPSPY_MCP_ALLOW) to enable it.",
            pid=pid,
            name=name,
        )
    entry = matches_allowlist(config.allow, pid=pid, name=name, exe=exe, cmdline=cmdline)
    if entry is None:
        raise AttachRefused(
            "not_allowlisted",
            f"pid {pid} ({name}) does not match any entry of the server's process allowlist. "
            "Only the user can change the allowlist (--allow / HEAPSPY_MCP_ALLOW).",
            pid=pid,
            name=name,
        )
    return {
        "pid": pid,
        "name": name,
        "exe": exe,
        "cmdline": describe_cmdline(cmdline),
        "allowlist_entry": entry,
    }


def _log_attach(tool: str, target: dict[str, Any], **details: Any) -> None:
    log.warning(
        "py-spy attach: tool=%s pid=%s name=%s allowlist_entry=%s %s",
        tool,
        target["pid"],
        target["name"],
        target["allowlist_entry"],
        " ".join(f"{k}={v}" for k, v in details.items()),
    )


def _spy(config: Config) -> PySpy:
    return PySpy(config.py_spy_bin)


def _pct(part: float, whole: float) -> float | None:
    return round(100.0 * part / whole, 1) if whole else None


# -- cpu_stacks --------------------------------------------------------------------


def _dump_thread(raw: dict[str, Any], pid: int, max_frames: int) -> dict[str, Any]:
    frames = [frame_from_dump(f) for f in raw.get("frames") or [] if isinstance(f, dict)]
    os_tid = raw.get("os_thread_id")
    tid = raw.get("thread_id")
    out: dict[str, Any] = {
        "thread_id": os_tid,
        "python_thread_id": hex(tid) if isinstance(tid, int) else tid,
        "name": clip(raw.get("thread_name")),
        "active": bool(raw.get("active")),
        "owns_gil": bool(raw.get("owns_gil")),
        "os_state": thread_state(raw.get("pid") or pid, os_tid)
        if isinstance(os_tid, int)
        else None,
        "frames": frames[:max_frames],
        "frames_total": len(frames),
    }
    if len(frames) > max_frames:
        out["frames_truncated"] = True
    return out


def take_stacks(
    config: Config,
    *,
    pid: int,
    include_idle: bool,
    native: bool,
    nonblocking: bool,
    max_threads: int,
    max_frames: int,
) -> dict[str, Any]:
    _spy(config).require()
    target = check_target(config, pid)
    if native and nonblocking:
        nonblocking = False
        native_note = "native=true needs a blocking read, so nonblocking was turned off."
    else:
        native_note = None
    _log_attach("cpu_stacks", target, native=native, nonblocking=nonblocking)
    raw_threads = _spy(config).dump(pid, native=native, nonblocking=nonblocking)
    n_threads = clamp(max_threads, 1, MAX_THREADS)
    n_frames = clamp(max_frames, 1, MAX_FRAMES)
    threads = [_dump_thread(t, pid, n_frames) for t in raw_threads if isinstance(t, dict)]
    # Active threads first, the GIL holder before the rest; then by name.
    threads.sort(key=lambda t: (not t["owns_gil"], not t["active"], str(t["name"] or "")))
    shown = threads if include_idle else [t for t in threads if t["active"]]
    states = Counter(t["os_state"]["label"] for t in threads if t["os_state"])
    notes = [
        "frames are innermost first. module is derived from the shortened file path py-spy "
        "reports (app/cache.py gives app.cache); for a script run by path it is a guess.",
        "os_state is read from /proc right after py-spy's sample, not atomically with it.",
    ]
    if nonblocking:
        notes.append(
            "Read with --nonblocking: the process was not paused, so a stack can be torn if "
            "the thread moved while it was read."
        )
    if native_note:
        notes.append(native_note)
    if not sys.platform.startswith("linux"):
        notes.append("OS thread state is only available on Linux.")
    return {
        "target": target,
        "nonblocking": nonblocking,
        "native": native,
        "summary": {
            "threads": len(threads),
            "active": sum(1 for t in threads if t["active"]),
            "idle": sum(1 for t in threads if not t["active"]),
            "gil_holder": next(
                (t["name"] or t["thread_id"] for t in threads if t["owns_gil"]), None
            ),
            "os_states": dict(states),
        },
        "threads": shown[:n_threads],
        "threads_omitted": max(0, len(shown) - n_threads),
        "idle_threads_hidden": 0 if include_idle else len(threads) - len(shown),
        "notes": notes,
    }


# -- registration ------------------------------------------------------------------

PidArg = Annotated[int, Field(description="PID of a live CPython process on the allowlist.")]
NativeArg = Annotated[
    bool,
    Field(
        description=(
            "Also unwind C/C++/Cython frames. Needs a blocking read (the process is paused for "
            "each sample) and is slower."
        )
    ),
]


def register(server: MCPServer, config: Config) -> None:
    """Add the CPU tools to ``server``. Each tool calls :func:`check_target` first."""
    sampling = ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=False, open_world_hint=False
    )

    @server.tool(
        annotations=sampling,
        description=(
            "What every thread of a Python process is doing right now (py-spy dump). Per "
            "thread: OS thread id and name, py-spy's active/idle flag, whether it holds the "
            "GIL, the OS thread state from /proc (running/runnable, sleeping in a syscall with "
            "the kernel wait channel and syscall name, disk wait, stopped, zombie), and the top "
            "frames as function, file:line and module, innermost first. Use it for a hung or "
            "slow process, and to see where waiting threads wait. nonblocking=true (default) "
            "reads the stacks without pausing the process: no impact on the target, but a "
            "stack can be torn if the thread moved while it was read. nonblocking=false pauses "
            "the process for the few milliseconds of the read and gives a consistent snapshot. "
            "Attaches with ptrace; the pid must be on the server's allowlist. Local variable "
            "values are never read."
        ),
    )
    def cpu_stacks(
        pid: PidArg,
        include_idle: Annotated[
            bool, Field(description="Include threads py-spy classes as idle.")
        ] = True,
        native: NativeArg = False,
        nonblocking: Annotated[
            bool, Field(description="Read without pausing the process (see description).")
        ] = True,
        max_threads: Annotated[
            int, Field(description=f"Threads to return (1 to {MAX_THREADS}).")
        ] = 50,
        max_frames: Annotated[
            int, Field(description=f"Frames per thread, innermost first (1 to {MAX_FRAMES}).")
        ] = 20,
    ) -> dict[str, Any]:
        return _guard(
            lambda: take_stacks(
                config,
                pid=pid,
                include_idle=include_idle,
                native=native,
                nonblocking=nonblocking,
                max_threads=max_threads,
                max_frames=max_frames,
            )
        )
