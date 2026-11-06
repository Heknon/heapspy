"""CPU tools backed by py-spy: what a process is doing, and where its time goes.

``register(server, config)`` adds ``cpu_stacks``, ``cpu_profile``, ``cpu_top``
and ``cpu_flamegraph`` to the server, plus a CPU workflow resource and prompt.

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
import secrets
import shutil
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Annotated, Any, TypeVar

import psutil
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from .config import Config
from .processes import describe_cmdline, matches_allowlist
from .pyspy import (
    FoldedStack,
    PySpy,
    PySpyError,
    RecordSpec,
    frame_from_dump,
    module_from_filename,
    read_folded,
    sample_task_states,
    thread_state,
)
from .snapshots import SnapshotStore
from .summarize import clamp, clip, human_bytes

log = logging.getLogger("heapspy_mcp.cpu")

MAX_THREADS = 200
MAX_FRAMES = 100
MAX_TOP = 50
MAX_STACK_FRAMES = 30
MAX_RATE = 1000
OS_SAMPLE_INTERVAL = 0.05  # 20 Hz; reading /proc for every thread is not free

T = TypeVar("T")

CPU_WORKFLOW = """\
CPU tools (py-spy) answer "where is the time going, and is the process running, blocked,
waiting for the GIL, or idle?". Heap tools (heapspy) answer "what is keeping memory alive?".

Which to use:
- Memory grows or RSS is high: heap tools (capture_snapshot, heap_summary, ...).
- Process is slow, hot, hung, or a request takes too long: CPU tools.
- Both: start with cpu_top (cheap, 5 s); look at the heap only if the time is in allocation
  or garbage collection, or memory grows as well.

The loop:
1. list_python_processes: find the PID. capture_allowed must be true; the CPU tools use the
   same allowlist.
2. cpu_stacks(pid): what every thread is doing right now, with py-spy's active/idle flag, GIL
   ownership and the OS thread state. A hung process usually shows here: a thread blocked in
   a syscall, or every thread waiting on locks.
3. cpu_top(pid): a 5 s profile next to the CPU seconds the process actually used. If
   cpu_seconds_user + cpu_seconds_system is far below wall_seconds, the process is mostly
   waiting, not computing.
4. cpu_profile(pid, duration_s): longer profile with top functions by self and total samples,
   top stacks, the on-CPU / idle / GIL split and per-thread OS states. include_idle=true to
   see where waiting threads wait.
5. map_to_source(module.function, repo_path) to open the hot code.
6. cpu_flamegraph(pid, duration_s) writes a speedscope or SVG file for the user to open.

What the numbers mean:
- A sample is one thread at one sampling tick. pct_of_samples is a share of the samples in the
  stated sampling mode, not a share of machine CPU. 50% of on-CPU samples in f() means f() was
  on the stack in half of the times a thread was seen running, nothing more.
- py-spy's "active" flag: the OS thread was running, or it held the GIL. A thread waiting for
  the GIL sleeps on a futex, so py-spy counts it as idle. The gil section of cpu_profile and the
  OS thread states (sleeping_futex) are how contention shows up.
- OS thread state comes from /proc/<pid>/task/<tid>/stat (Linux only): running/runnable,
  sleeping (blocked in a syscall; kernel_wait and syscall say which), disk wait, stopped, zombie.
- CPU seconds come from the kernel (psutil cpu_times) and are exact. iowait_seconds needs
  kernel delay accounting (sysctl kernel.task_delayacct=1); it is null when that is off.
"""

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


# -- profile aggregation -----------------------------------------------------------

_MODES = {
    (False, False): (
        "on_cpu",
        "on-CPU samples only: threads py-spy classed as active (OS thread running, or holding "
        "the GIL) at each tick. Idle threads are not counted.",
    ),
    (True, False): (
        "all",
        "all samples including idle: every Python thread at every tick, whether running, "
        "sleeping, blocked on I/O or waiting for the GIL.",
    ),
    (False, True): (
        "gil_on_cpu",
        "GIL-holding samples only, active threads only: at most one sample per tick.",
    ),
    (True, True): (
        "gil",
        "GIL-holding samples only: the thread that held the GIL at each tick, at most one "
        "sample per tick.",
    ),
}


def _fn_key(function: str, file: str | None) -> tuple[str, str | None]:
    return (function, file)


def _fn_row(key: tuple[str, str | None], samples: int, total: int, lines: Counter) -> dict:
    function, file = key
    line = lines.most_common(1)[0][0] if lines else None
    location = (f"{file}:{line}" if line is not None else file) if file else None
    return {
        "function": clip(function),
        "module": module_from_filename(file),
        "location": location,
        "samples": samples,
        "pct_of_samples": _pct(samples, total),
    }


def _thread_key(s: FoldedStack) -> tuple[tuple[int, ...], str | None]:
    return (s.pids, s.thread_id)


def aggregate(stacks: Iterable[FoldedStack], *, top: int, top_stacks: int) -> dict[str, Any]:
    """Rank functions by self and total samples, and whole stacks, from folded output."""
    stacks = list(stacks)
    total = sum(s.count for s in stacks)
    self_c: Counter = Counter()
    total_c: Counter = Counter()
    self_lines: dict[tuple, Counter] = defaultdict(Counter)
    any_lines: dict[tuple, Counter] = defaultdict(Counter)
    by_stack: Counter = Counter()
    stack_threads: dict[tuple, Counter] = defaultdict(Counter)
    no_frames = 0
    for s in stacks:
        if not s.frames:
            no_frames += s.count
            continue
        leaf = s.frames[-1]
        key = _fn_key(leaf.function, leaf.file)
        self_c[key] += s.count
        self_lines[key][leaf.line] += s.count
        seen = set()
        for f in s.frames:
            k = _fn_key(f.function, f.file)
            any_lines[k][f.line] += s.count
            if k not in seen:
                seen.add(k)
                total_c[k] += s.count
        by_stack[s.frames] += s.count
        stack_threads[s.frames][s.thread_name or s.thread_id or "?"] += s.count

    top_stack_rows = []
    for frames, count in by_stack.most_common(top_stacks):
        leaf_first = [f.render() for f in reversed(frames)]
        row: dict[str, Any] = {
            "samples": count,
            "pct_of_samples": _pct(count, total),
            "threads": [clip(name) for name, _ in stack_threads[frames].most_common(3)],
            "frames": [clip(f) for f in leaf_first[:MAX_STACK_FRAMES]],
        }
        if len(leaf_first) > MAX_STACK_FRAMES:
            row["frames_elided"] = len(leaf_first) - MAX_STACK_FRAMES
        top_stack_rows.append(row)

    return {
        "samples_total": total,
        "samples_without_python_frames": no_frames,
        "top_self": [_fn_row(k, n, total, self_lines[k]) for k, n in self_c.most_common(top)],
        "top_total": [_fn_row(k, n, total, any_lines[k]) for k, n in total_c.most_common(top)],
        "top_stacks": top_stack_rows,
    }


def per_thread_counts(stacks: Iterable[FoldedStack]) -> dict[tuple, dict[str, Any]]:
    out: dict[tuple, dict[str, Any]] = {}
    for s in stacks:
        row = out.setdefault(_thread_key(s), {"name": s.thread_name, "samples": 0})
        row["samples"] += s.count
    return out


class _StateSampler(threading.Thread):
    """Samples /proc thread states of one process while py-spy records."""

    def __init__(self, pid: int, interval: float = OS_SAMPLE_INTERVAL) -> None:
        super().__init__(name="heapspy-mcp-os-states", daemon=True)
        self.pid = pid
        self.interval = interval
        self.stop_event = threading.Event()
        self.ticks = 0
        self.counts: Counter = Counter()
        self.per_thread: dict[int, Counter] = defaultdict(Counter)

    def run(self) -> None:
        while not self.stop_event.wait(self.interval):
            snap = sample_task_states(self.pid)
            if not snap:
                continue
            self.ticks += 1
            for tid, bucket in snap.items():
                self.counts[bucket] += 1
                self.per_thread[tid][bucket] += 1

    def stop(self) -> None:
        self.stop_event.set()
        self.join(timeout=5)


_BUCKET_ORDER = ("running", "sleeping_futex", "sleeping_other", "disk_wait", "stopped", "other")


def _bucket_pcts(counts: Counter) -> dict[str, float | None]:
    total = sum(counts.values())
    return {b: _pct(counts.get(b, 0), total) for b in _BUCKET_ORDER if counts.get(b)}


def _gil_assessment(
    held_pct: float | None, holders: int, futex_avg: float | None
) -> tuple[str, str]:
    if held_pct is None:
        return "unknown", "no GIL samples were collected"
    if held_pct < 80:
        return (
            "unlikely",
            f"The GIL was free in {100 - held_pct:.0f}% of ticks, so threads that want it "
            "rarely have to wait.",
        )
    if holders < 2:
        return (
            "unlikely",
            f"The GIL was held in {held_pct:.0f}% of ticks, but by one thread only; no other "
            "thread competed for it.",
        )
    if futex_avg is None:
        return (
            "possible",
            f"The GIL was held in {held_pct:.0f}% of ticks and {holders} threads took turns "
            "holding it. OS thread states are not available here to confirm that the others "
            "were waiting.",
        )
    if futex_avg >= 0.5:
        return (
            "likely",
            f"The GIL was held in {held_pct:.0f}% of ticks, {holders} threads took turns "
            f"holding it, and on average {futex_avg:.1f} threads were asleep on a futex, which "
            "is how CPython threads wait for the GIL. Futex waits also include locks, queues "
            "and conditions: use cpu_stacks to check that the waiting threads are in plain "
            "Python code rather than in Lock.acquire, Queue.get or Condition.wait.",
        )
    return (
        "possible",
        f"The GIL was held in {held_pct:.0f}% of ticks by {holders} threads in turn, but few "
        "threads were seen waiting on a futex.",
    )


def run_profile(
    config: Config,
    *,
    tool: str,
    pid: int,
    duration_s: int,
    rate_hz: int,
    include_idle: bool,
    gil_only: bool,
    subprocesses: bool,
    native: bool,
    top: int,
    top_stacks: int,
    save_folded: bool,
    measure_cpu: bool = False,
) -> dict[str, Any]:
    spy = _spy(config)
    spy.require()
    target = check_target(config, pid)
    notes: list[str] = []
    max_d = config.cpu_max_duration
    duration = clamp(duration_s, 1, max_d)
    if duration != duration_s:
        notes.append(
            f"duration_s={duration_s} was clamped to {duration} (server limit {max_d} s, "
            "set with --cpu-max-duration)."
        )
    rate = clamp(rate_hz, 1, MAX_RATE)
    if rate != rate_hz:
        notes.append(f"rate_hz={rate_hz} was clamped to {rate}.")

    mode, mode_text = _MODES[(include_idle, gil_only)]
    tmp = Path(tempfile.mkdtemp(prefix="heapspy-mcp-cpu-"))
    common = {
        "duration_s": duration,
        "rate_hz": rate,
        "threads": True,
        "subprocesses": subprocesses,
        "native": native,
        "nonblocking": not native,
    }
    main = RecordSpec(output=tmp / "main.folded", idle=include_idle, gil=gil_only, **common)
    specs = [main]
    split_specs: dict[str, RecordSpec] = {}
    if not native:
        for key, (idle, gil) in {"all": (True, False), "on_cpu": (False, False)}.items():
            split_specs[key] = main
            if (idle, gil) != (main.idle, main.gil):
                split_specs[key] = RecordSpec(
                    output=tmp / f"{key}.folded", idle=idle, gil=gil, **common
                )
                specs.append(split_specs[key])
        # The GIL pass includes idle threads so a GIL holder blocked in C is still counted.
        if (main.idle, main.gil) == (True, True):
            split_specs["gil"] = main
        else:
            split_specs["gil"] = RecordSpec(
                output=tmp / "gil.folded", idle=True, gil=True, **common
            )
            specs.append(split_specs["gil"])

    _log_attach(
        tool,
        target,
        duration_s=duration,
        rate_hz=rate,
        mode=mode,
        passes=len(specs),
        subprocesses=subprocesses,
        native=native,
        nonblocking=not native,
    )
    sampler = _StateSampler(pid) if sys.platform.startswith("linux") else None
    cpu_before = cpu_after = None
    folded_path: Path | None = None
    try:
        if measure_cpu:
            try:
                proc = psutil.Process(pid)
                cpu_before = (time.monotonic(), proc.cpu_times())
            except psutil.Error as e:
                raise AttachRefused("no_such_process", f"cannot read CPU times of pid {pid}") from e
        if sampler:
            sampler.start()
        try:
            results = spy.record(pid, specs)
        finally:
            if sampler:
                sampler.stop()
            if measure_cpu:
                try:
                    cpu_after = (time.monotonic(), proc.cpu_times())
                except psutil.Error:
                    cpu_after = None
        parsed = {spec.output: read_folded(spec.output) for spec in specs}
        if save_folded:
            store = SnapshotStore(config.snapshot_dir)
            directory = store.ensure_dir()
            folded_path = directory / f"cpu-{secrets.token_hex(4)}.folded"
            if main.output.exists():
                shutil.move(str(main.output), folded_path)
            else:
                folded_path.write_text("")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    stacks = parsed[main.output]
    agg = aggregate(stacks, top=clamp(top, 1, MAX_TOP), top_stacks=clamp(top_stacks, 1, MAX_TOP))
    errors = sum(r.errors or 0 for r in results)

    # Ticks: in the all-threads pass every thread is sampled at every tick, so the thread
    # with the most samples was present for (nearly) every tick.
    all_stacks = parsed[split_specs["all"].output] if "all" in split_specs else None
    threads_all = per_thread_counts(all_stacks if all_stacks is not None else stacks)
    if all_stacks is not None and threads_all:
        ticks = max(r["samples"] for r in threads_all.values())
        ticks_basis = "most samples of any one thread in the all-threads pass"
    elif mode == "all" and threads_all:
        ticks = max(r["samples"] for r in threads_all.values())
        ticks_basis = "most samples of any one thread"
    else:
        ticks = duration * rate
        ticks_basis = "nominal: duration_s * rate_hz"

    out: dict[str, Any] = {
        "target": target,
        "duration_s": duration,
        "rate_hz": rate,
        "sampling": {
            "mode": mode,
            "description": mode_text,
            "unit": "thread-samples: one per thread per sampling tick",
            "nonblocking": not native,
            "native": native,
            "subprocesses": subprocesses,
            "passes": len(specs),
        },
        "samples": {
            "total": agg["samples_total"],
            "ticks_estimate": ticks,
            "ticks_basis": ticks_basis,
            "without_python_frames": agg["samples_without_python_frames"],
            "py_spy_errors": errors,
        },
        "top_self": agg["top_self"],
        "top_total": agg["top_total"],
        "top_stacks": agg["top_stacks"],
    }

    on_cpu_threads: dict[tuple, dict[str, Any]] = {}
    gil_threads: dict[tuple, dict[str, Any]] = {}
    if split_specs:
        all_n = sum(s.count for s in parsed[split_specs["all"].output])
        on_stacks = parsed[split_specs["on_cpu"].output]
        gil_stacks = parsed[split_specs["gil"].output]
        on_n = sum(s.count for s in on_stacks)
        gil_n = sum(s.count for s in gil_stacks)
        on_cpu_threads = per_thread_counts(on_stacks)
        gil_threads = per_thread_counts(gil_stacks)
        on_n_c = min(on_n, all_n)

        def part(n: int) -> dict[str, Any]:
            return {"samples": n, "pct_of_samples": _pct(n, all_n)}

        out["split"] = {
            "basis": (
                "Separate py-spy passes over the same window, run at the same time: all "
                "threads (--idle), active threads only, and the GIL holder (--gil). Percentages "
                "are of the all-threads samples. The passes sample independently, so the parts "
                "are estimates and need not add up exactly."
            ),
            "samples_all_threads": all_n,
            "on_cpu": part(on_n_c),
            "idle": part(max(all_n - on_n, 0)),
            "gil_held": part(gil_n),
            "on_cpu_without_gil": part(max(on_n_c - gil_n, 0)),
            "meaning": {
                "on_cpu": "py-spy's active flag: OS thread running, or holding the GIL.",
                "idle": (
                    "everything else: sleeping, blocked on I/O or a lock, and waiting for the "
                    "GIL. py-spy cannot tell these apart; see os_thread_states and gil."
                ),
                "gil_held": "samples of the thread holding the GIL.",
                "on_cpu_without_gil": (
                    "running without the GIL: C code that released it (I/O, compression, "
                    "numpy), or a thread spinning before it takes the GIL."
                ),
            },
        }
    else:
        out["split"] = None
        notes.append(
            "No on-CPU/idle/GIL split: native=true needs blocking reads, and blocking py-spy "
            "passes cannot run side by side. Run again with native=false for the split."
        )

    futex_avg = None
    if sampler is not None and sampler.ticks:
        futex_avg = round(sampler.counts.get("sleeping_futex", 0) / sampler.ticks, 2)
        out["os_thread_states"] = {
            "basis": (
                f"/proc/<pid>/task/*/stat sampled by the server at {1 / OS_SAMPLE_INTERVAL:g} Hz "
                "during the profile, all threads of the process (including threads without "
                "Python frames). Percentages are of those thread-state samples."
            ),
            "ticks": sampler.ticks,
            "pct_of_samples": _bucket_pcts(sampler.counts),
            "meaning": {
                "running": "running or runnable (R)",
                "sleeping_futex": (
                    "asleep in futex(): waiting for the GIL, a lock, a queue or a condition"
                ),
                "sleeping_other": "asleep in another syscall: sleep, socket read, select/poll",
                "disk_wait": "uninterruptible wait (D), usually disk or network file system I/O",
                "stopped": "stopped (T/t); with native=true py-spy itself stops threads",
            },
        }
    else:
        out["os_thread_states"] = None

    if split_specs:
        gil_n = out["split"]["gil_held"]["samples"]
        held_pct = _pct(gil_n, ticks) if gil_n else 0.0
        if held_pct is not None:
            held_pct = min(held_pct, 100.0)
        holders = sum(1 for r in gil_threads.values() if r["samples"] > 0)
        verdict, why = _gil_assessment(held_pct, holders, futex_avg)
        out["gil"] = {
            "held_pct_of_ticks": held_pct,
            "threads_that_held_gil": holders,
            "python_threads_seen": len(threads_all),
            "futex_waiters_avg": futex_avg,
            "contention": verdict,
            "explanation": why,
        }
    else:
        out["gil"] = None

    # Per-thread table: samples in each pass and OS states.
    rows = []
    for key, row in sorted(threads_all.items(), key=lambda kv: -kv[1]["samples"])[:MAX_TOP]:
        _, tid = key
        r: dict[str, Any] = {
            "thread_id": int(tid) if tid and tid.isdigit() else tid,
            "name": clip(row["name"]),
            "samples": row["samples"],
        }
        if split_specs:
            r["on_cpu_samples"] = on_cpu_threads.get(key, {}).get("samples", 0)
            r["gil_samples"] = gil_threads.get(key, {}).get("samples", 0)
            r["on_cpu_pct_of_thread_samples"] = _pct(r["on_cpu_samples"], row["samples"])
        if sampler is not None and tid and tid.isdigit() and int(tid) in sampler.per_thread:
            r["os_states_pct"] = _bucket_pcts(sampler.per_thread[int(tid)])
        rows.append(r)
    out["threads"] = rows

    if measure_cpu and cpu_before and cpu_after:
        (t0, c0), (t1, c1) = cpu_before, cpu_after
        out["cpu_usage"] = _cpu_delta(t1 - t0, c0, c1)
    elif measure_cpu:
        out["cpu_usage"] = None
        notes.append("CPU times could not be read after the profile (did the process exit?).")

    out["folded_path"] = str(folded_path) if folded_path else None
    if folded_path:
        notes.append(
            "folded_path is py-spy's folded stack file (one 'frames count' line per stack, "
            "with a thread frame first). Open it in speedscope, or pass it to flamegraph.pl or "
            "inferno-flamegraph."
        )
    for warning in sorted({w for r in results for w in r.warnings}):
        notes.append(f"py-spy: {warning}")
    if errors:
        notes.append(
            f"py-spy reported {errors} failed samples: usually stacks that changed while they "
            "were read without pausing the process."
        )
    if agg["samples_total"] == 0:
        notes.append(
            "No samples in this mode. With the default on-CPU mode this means no Python thread "
            "was running; try include_idle=true to see where the threads wait."
        )
    out["notes"] = notes
    log.warning(
        "py-spy done: tool=%s pid=%s samples=%s errors=%s", tool, pid, agg["samples_total"], errors
    )
    return out


def _delay_accounting() -> bool | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        return Path("/proc/sys/kernel/task_delayacct").read_text().strip() == "1"
    except OSError:
        return None


def _cpu_delta(wall: float, c0: Any, c1: Any) -> dict[str, Any]:
    user = max(0.0, c1.user - c0.user)
    system = max(0.0, c1.system - c0.system)
    delayacct = _delay_accounting()
    iowait = None
    if hasattr(c1, "iowait") and delayacct:
        iowait = round(max(0.0, c1.iowait - c0.iowait), 3)
    out = {
        "wall_seconds": round(wall, 3),
        "cpu_seconds_user": round(user, 3),
        "cpu_seconds_system": round(system, 3),
        "iowait_seconds": iowait,
        "cpu_pct_of_one_core": _pct(user + system, wall),
        "delay_accounting_enabled": delayacct,
        "basis": (
            "psutil cpu_times() of the target process before and after the profile; the "
            "kernel's own accounting, independent of sampling. cpu_pct_of_one_core can exceed "
            "100 for a process running on several cores. py-spy runs in its own process, so its "
            "CPU is not included."
        ),
    }
    if iowait is None:
        out["iowait_note"] = (
            "iowait_seconds needs Linux delay accounting; it is off here "
            "(enable with sysctl kernel.task_delayacct=1, or boot with 'delayacct')."
            if delayacct is False
            else "iowait_seconds is only available on Linux."
        )
    return out


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
DurationArg = Annotated[
    int, Field(description="Seconds to sample, whole number. Capped by the server's limit.")
]


def register(server: MCPServer, config: Config) -> None:
    """Add the CPU tools, the CPU workflow resource and prompt to ``server``."""
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

    @server.tool(
        annotations=sampling,
        description=(
            "Sample a Python process with py-spy for duration_s seconds and rank where the "
            "time goes: top functions by self samples (the function itself was running) and by "
            "total samples (it was anywhere on the stack), top stacks, a per-thread table, the "
            "on-CPU / idle / GIL split, OS thread states sampled from /proc, and a GIL "
            "contention assessment. Every percentage is pct_of_samples: a share of the samples "
            "in the stated sampling mode, NOT a share of machine or core CPU; use cpu_top for "
            "real CPU seconds. Default mode counts on-CPU samples only; include_idle=true counts "
            "every thread at every tick (shows where threads wait); gil_only=true counts the "
            "GIL holder only. Never pauses the target unless native=true. save_folded=true "
            "keeps the folded stacks in the server's snapshot directory for a flame graph tool. "
            "The pid must be on the server's allowlist."
        ),
    )
    def cpu_profile(
        pid: PidArg,
        duration_s: DurationArg = 10,
        rate_hz: Annotated[
            int, Field(description=f"Samples per second per thread (1 to {MAX_RATE}).")
        ] = 100,
        include_idle: Annotated[
            bool, Field(description="Count idle threads too (sampling mode 'all').")
        ] = False,
        gil_only: Annotated[
            bool, Field(description="Count only the thread holding the GIL.")
        ] = False,
        subprocesses: Annotated[
            bool, Field(description="Also sample child processes of the target.")
        ] = False,
        native: NativeArg = False,
        top: Annotated[int, Field(description=f"Rows per ranked list (1 to {MAX_TOP}).")] = 15,
        top_stacks: Annotated[int, Field(description=f"Stacks to return (1 to {MAX_TOP}).")] = 5,
        save_folded: Annotated[
            bool, Field(description="Keep the folded stack file and return its path.")
        ] = False,
    ) -> dict[str, Any]:
        return _guard(
            lambda: run_profile(
                config,
                tool="cpu_profile",
                pid=pid,
                duration_s=duration_s,
                rate_hz=rate_hz,
                include_idle=include_idle,
                gil_only=gil_only,
                subprocesses=subprocesses,
                native=native,
                top=top,
                top_stacks=top_stacks,
                save_folded=save_folded,
            )
        )

    @server.tool(
        annotations=sampling,
        description=(
            "Short on-CPU profile (default 5 s) summarised as the top functions, next to the "
            "CPU time the process really used over the same window: cpu_seconds_user, "
            "cpu_seconds_system and, on Linux with delay accounting, iowait_seconds (from "
            "psutil, the kernel's accounting). Compare the two: pct_of_samples says where the "
            "running threads were, cpu_seconds says how much running there was. If CPU seconds "
            "are near zero the process is waiting, not computing; look at the split and "
            "cpu_stacks. The pid must be on the server's allowlist."
        ),
    )
    def cpu_top(
        pid: PidArg,
        duration_s: DurationArg = 5,
        top: Annotated[int, Field(description=f"Functions to return (1 to {MAX_TOP}).")] = 10,
    ) -> dict[str, Any]:
        def body() -> dict[str, Any]:
            full = run_profile(
                config,
                tool="cpu_top",
                pid=pid,
                duration_s=duration_s,
                rate_hz=100,
                include_idle=False,
                gil_only=False,
                subprocesses=False,
                native=False,
                top=top,
                top_stacks=1,
                save_folded=False,
                measure_cpu=True,
            )
            usage = full.get("cpu_usage") or {}
            return {
                "target": full["target"],
                "duration_s": full["duration_s"],
                "sampling": full["sampling"],
                "samples": full["samples"],
                "top_functions": full["top_self"],
                "wall_seconds": usage.get("wall_seconds"),
                "cpu_seconds_user": usage.get("cpu_seconds_user"),
                "cpu_seconds_system": usage.get("cpu_seconds_system"),
                "iowait_seconds": usage.get("iowait_seconds"),
                "cpu_pct_of_one_core": usage.get("cpu_pct_of_one_core"),
                "cpu_usage": usage or None,
                "split": full["split"],
                "gil": full["gil"],
                "os_thread_states": (full["os_thread_states"] or {}).get("pct_of_samples"),
                "notes": full["notes"],
            }

        return _guard(body)

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
        description=(
            "Record a flame graph of a Python process with py-spy and write it to the server's "
            "snapshot directory. Returns the file path, never the contents: give the path to "
            "the user to open (speedscope: https://www.speedscope.app, or the SVG in a "
            "browser). format is 'speedscope' (default) or 'flamegraph' (SVG). Samples on-CPU "
            "threads unless include_idle=true. Does not pause the target. The pid must be on "
            "the server's allowlist."
        ),
    )
    def cpu_flamegraph(
        pid: PidArg,
        duration_s: DurationArg = 10,
        format: Annotated[
            str, Field(description="'speedscope' (JSON for speedscope.app) or 'flamegraph' (SVG).")
        ] = "speedscope",
        include_idle: Annotated[bool, Field(description="Include idle threads.")] = False,
        rate_hz: Annotated[
            int, Field(description=f"Samples per second per thread (1 to {MAX_RATE}).")
        ] = 100,
    ) -> dict[str, Any]:
        return _guard(
            lambda: _cpu_flamegraph(
                config,
                pid=pid,
                duration_s=duration_s,
                fmt=format,
                include_idle=include_idle,
                rate_hz=rate_hz,
            )
        )

    @server.resource(
        "heapspy://workflow/cpu",
        name="cpu_workflow",
        description="How to investigate Python CPU use with the py-spy tools, and when to use "
        "heap tools instead.",
        mime_type="text/markdown",
    )
    def cpu_workflow_resource() -> str:
        return CPU_WORKFLOW

    @server.prompt(
        name="investigate_cpu",
        description="Walk through finding where a Python process spends its time, or why it "
        "is stuck.",
    )
    def investigate_cpu(target: str = "") -> str:
        lead = (
            f"Investigate where {target} spends its time, or what it is waiting on.\n\n"
            if target
            else "Investigate where a Python process spends its time, or what it waits on.\n\n"
        )
        return lead + CPU_WORKFLOW

    # Tell clients about the CPU tools in the server instructions as well.
    lowlevel = getattr(server, "_lowlevel_server", None)
    if lowlevel is not None and isinstance(getattr(lowlevel, "instructions", None), str):
        lowlevel.instructions = lowlevel.instructions.rstrip() + "\n\n" + CPU_WORKFLOW


_FLAME_FORMATS = {"speedscope": ".speedscope.json", "flamegraph": ".svg"}


def _cpu_flamegraph(
    config: Config, *, pid: int, duration_s: int, fmt: str, include_idle: bool, rate_hz: int
) -> dict[str, Any]:
    if fmt not in _FLAME_FORMATS:
        raise PySpyError("invalid_argument", "format must be 'speedscope' or 'flamegraph'")
    spy = _spy(config)
    spy.require()
    target = check_target(config, pid)
    notes = []
    duration = clamp(duration_s, 1, config.cpu_max_duration)
    if duration != duration_s:
        notes.append(f"duration_s={duration_s} was clamped to {duration} (server limit).")
    rate = clamp(rate_hz, 1, MAX_RATE)
    directory = SnapshotStore(config.snapshot_dir).ensure_dir()
    path = directory / f"cpu-{secrets.token_hex(4)}{_FLAME_FORMATS[fmt]}"
    spec = RecordSpec(
        output=path, duration_s=duration, rate_hz=rate, fmt=fmt, idle=include_idle, threads=True
    )
    _log_attach("cpu_flamegraph", target, duration_s=duration, rate_hz=rate, format=fmt)
    (result,) = spy.record(pid, [spec])
    if not path.is_file():
        raise PySpyError("bad_output", f"py-spy record exited 0 but did not write {path}")
    size = path.stat().st_size
    log.warning("py-spy done: tool=cpu_flamegraph pid=%s file=%s size=%s", pid, path, size)
    return {
        "target": target,
        "path": str(path),
        "format": fmt,
        "file_bytes": size,
        "file_human": human_bytes(size),
        "samples": result.samples,
        "py_spy_errors": result.errors,
        "sampling_mode": "all" if include_idle else "on_cpu",
        "open_with": (
            "https://www.speedscope.app (drag the file in)"
            if fmt == "speedscope"
            else "a web browser (the SVG is interactive)"
        ),
        "notes": notes,
    }
