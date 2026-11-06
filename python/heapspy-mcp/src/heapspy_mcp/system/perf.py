"""Per-thread performance counters through ``perf_event_open(2)`` and ctypes.

No ``perf`` binary is needed. Each thread of the target process gets one
counter per event (``pid=tid, cpu=-1``, ``inherit=1`` so threads it starts
during the window are folded in when they exit). Counts are read with
``PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING``. When the
kernel multiplexes hardware counters, a count is scaled by
``time_enabled / time_running`` and the scaling is reported.

The syscall goes through a :class:`PerfBackend` so tests can replace it.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import os
import platform
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import procfs as pf

PERF_TYPE_HARDWARE = 0
PERF_TYPE_SOFTWARE = 1
PERF_TYPE_HW_CACHE = 3

PERF_COUNT_HW_CPU_CYCLES = 0
PERF_COUNT_HW_INSTRUCTIONS = 1
PERF_COUNT_HW_CACHE_REFERENCES = 2
PERF_COUNT_HW_CACHE_MISSES = 3
PERF_COUNT_SW_TASK_CLOCK = 1
PERF_COUNT_SW_CONTEXT_SWITCHES = 3
PERF_COUNT_SW_CPU_MIGRATIONS = 4

# PERF_TYPE_HW_CACHE config: cache id | (op << 8) | (result << 16)
PERF_COUNT_HW_CACHE_LL = 2
PERF_COUNT_HW_CACHE_OP_READ = 0
PERF_COUNT_HW_CACHE_RESULT_ACCESS = 0
PERF_COUNT_HW_CACHE_RESULT_MISS = 1

PERF_FORMAT_TOTAL_TIME_ENABLED = 1 << 0
PERF_FORMAT_TOTAL_TIME_RUNNING = 1 << 1
ATTR_FLAG_INHERIT = 1 << 1

PERF_FLAG_FD_CLOEXEC = 1 << 3

SYS_PERF_EVENT_OPEN = {"x86_64": 298, "aarch64": 241, "arm64": 241, "i686": 336, "i386": 336}

MAX_PERF_THREADS = 128

PMU_MISSING_REASON = "unavailable: no PMU exposed (common in VMs)"


class PerfEventAttr(ctypes.Structure):
    """``struct perf_event_attr`` up to ``config2`` (PERF_ATTR_SIZE_VER1, 72 bytes)."""

    _fields_ = [
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("sample_period", ctypes.c_uint64),
        ("sample_type", ctypes.c_uint64),
        ("read_format", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("wakeup_events", ctypes.c_uint32),
        ("bp_type", ctypes.c_uint32),
        ("config1", ctypes.c_uint64),
        ("config2", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class EventSpec:
    name: str
    type: int
    config: int
    hardware: bool
    description: str


def _cache_config(result: int) -> int:
    return PERF_COUNT_HW_CACHE_LL | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (result << 16)


EVENTS: tuple[EventSpec, ...] = (
    EventSpec("cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, True, "CPU cycles"),
    EventSpec(
        "instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, True, "retired instructions"
    ),
    EventSpec(
        "llc_references",
        PERF_TYPE_HW_CACHE,
        _cache_config(PERF_COUNT_HW_CACHE_RESULT_ACCESS),
        True,
        "last-level cache read accesses (PERF_TYPE_HW_CACHE LL/READ/ACCESS)",
    ),
    EventSpec(
        "llc_misses",
        PERF_TYPE_HW_CACHE,
        _cache_config(PERF_COUNT_HW_CACHE_RESULT_MISS),
        True,
        "last-level cache read misses (PERF_TYPE_HW_CACHE LL/READ/MISS)",
    ),
    EventSpec(
        "context_switches",
        PERF_TYPE_SOFTWARE,
        PERF_COUNT_SW_CONTEXT_SWITCHES,
        False,
        "context switches (software event)",
    ),
    EventSpec(
        "cpu_migrations",
        PERF_TYPE_SOFTWARE,
        PERF_COUNT_SW_CPU_MIGRATIONS,
        False,
        "CPU migrations (software event)",
    ),
    EventSpec("task_clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK, False, "on-CPU time, ns"),
)

# Generic cache events, tried when the PMU has no LL entry in its cache table.
LLC_FALLBACK = {
    "llc_references": EventSpec(
        "llc_references",
        PERF_TYPE_HARDWARE,
        PERF_COUNT_HW_CACHE_REFERENCES,
        True,
        "PERF_COUNT_HW_CACHE_REFERENCES (usually last-level cache)",
    ),
    "llc_misses": EventSpec(
        "llc_misses",
        PERF_TYPE_HARDWARE,
        PERF_COUNT_HW_CACHE_MISSES,
        True,
        "PERF_COUNT_HW_CACHE_MISSES (usually last-level cache)",
    ),
}


class PerfBackend:
    """The real syscall. Tests substitute an object with the same three methods."""

    def __init__(self) -> None:
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._nr = SYS_PERF_EVENT_OPEN.get(platform.machine())

    def open(self, spec: EventSpec, tid: int) -> int:
        """Return an fd, or raise OSError with the errno."""
        if self._nr is None:
            raise OSError(errno.ENOSYS, f"perf_event_open number unknown for {platform.machine()}")
        attr = PerfEventAttr()
        attr.type = spec.type
        attr.size = ctypes.sizeof(PerfEventAttr)
        attr.config = spec.config
        attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING
        attr.flags = ATTR_FLAG_INHERIT
        fd = self._libc.syscall(
            self._nr, ctypes.byref(attr), tid, -1, -1, ctypes.c_ulong(PERF_FLAG_FD_CLOEXEC)
        )
        if fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return int(fd)

    def read(self, fd: int) -> tuple[int, int, int]:
        """(value, time_enabled_ns, time_running_ns)."""
        data = os.read(fd, 24)
        return struct.unpack("QQQ", data)  # type: ignore[return-value]

    def close(self, fd: int) -> None:
        os.close(fd)


def pmu_devices(sys_root: Path = Path("/sys")) -> list[str]:
    try:
        return sorted(os.listdir(sys_root / "bus" / "event_source" / "devices"))
    except OSError:
        return []


def has_cpu_pmu(devices: list[str]) -> bool:
    """A core PMU: ``cpu`` (x86), ``cpu_core``/``cpu_atom`` (hybrid Intel), ``armv8_*``."""
    return any(d == "cpu" or d.startswith(("cpu_", "armv8", "armv7", "arm_")) for d in devices)


def explain_errno(err: int, *, hardware: bool, devices: list[str], paranoid: str | None) -> str:
    if err == errno.ENOENT:
        if hardware and not has_cpu_pmu(devices):
            return f"{PMU_MISSING_REASON}; event_source devices: {', '.join(devices) or 'none'}"
        return "ENOENT: the PMU does not support this event"
    if err in (errno.EACCES, errno.EPERM):
        return (
            f"{errno.errorcode.get(err, err)}: permission denied "
            f"(kernel.perf_event_paranoid={paranoid}); counting another process needs "
            "CAP_PERFMON (Linux 5.8+) or CAP_SYS_ADMIN on older kernels, or ptrace access"
        )
    if err == errno.EOPNOTSUPP:
        return "EOPNOTSUPP: the PMU does not support this event or its flags"
    if err == errno.EMFILE:
        return "EMFILE: out of file descriptors"
    if err == errno.ESRCH:
        return "ESRCH: the thread exited"
    if err == errno.ENODEV:
        return "ENODEV: event not supported on this CPU"
    if err == errno.ENOSYS:
        return "ENOSYS: perf_event_open is not available"
    return f"{errno.errorcode.get(err, err)}: {os.strerror(err)}"


@dataclass
class _Open:
    spec: EventSpec
    fds: dict[int, int]
    start: dict[int, tuple[int, int, int]]
    error: str | None = None


class CounterSession:
    """Open counters on every thread of ``pid`` at :meth:`start`, read them at :meth:`stop`."""

    def __init__(
        self,
        pid: int,
        *,
        proc_root: Path = Path("/proc"),
        sys_root: Path = Path("/sys"),
        backend: Any | None = None,
        max_threads: int = MAX_PERF_THREADS,
    ) -> None:
        self.pid = pid
        self.proc_root = proc_root
        self.sys_root = sys_root
        self.backend = backend if backend is not None else PerfBackend()
        self.max_threads = max_threads
        self.events: dict[str, _Open] = {}
        self.tids: list[int] = []
        self.threads_total = 0

    def start(self) -> None:
        from .sampling import list_tids

        tids = list_tids(self.proc_root, self.pid) or [self.pid]
        self.threads_total = len(tids)
        self.tids = tids[: self.max_threads]
        devices = pmu_devices(self.sys_root)
        paranoid = (pf.read_text(self.proc_root / "sys/kernel/perf_event_paranoid") or "").strip()
        for spec in EVENTS:
            opened = self._open_all(spec, devices, paranoid or None)
            if opened.error and not opened.fds and spec.name in LLC_FALLBACK:
                fallback = self._open_all(LLC_FALLBACK[spec.name], devices, paranoid or None)
                if fallback.fds:
                    opened = fallback
            self.events[spec.name] = opened

    def _open_all(self, spec: EventSpec, devices: list[str], paranoid: str | None) -> _Open:
        result = _Open(spec, {}, {})
        last_err: int | None = None
        for tid in self.tids:
            try:
                fd = self.backend.open(spec, tid)
            except OSError as e:
                last_err = e.errno
                if e.errno == errno.ESRCH:
                    continue
                break
            result.fds[tid] = fd
            result.start[tid] = self.backend.read(fd)
        if not result.fds:
            err = last_err if last_err is not None else errno.ESRCH
            result.error = explain_errno(
                err, hardware=spec.hardware, devices=devices, paranoid=paranoid
            )
        return result

    def stop(self) -> dict[str, Any]:
        counters: dict[str, Any] = {}
        for name, opened in self.events.items():
            if opened.error:
                counters[name] = {"value": None, "unavailable_reason": opened.error}
                continue
            raw = enabled = running = 0
            for tid, fd in opened.fds.items():
                try:
                    v, e, r = self.backend.read(fd)
                except OSError:
                    continue
                v0, e0, r0 = opened.start[tid]
                dv, de, dr = v - v0, e - e0, r - r0
                raw += dv
                # Scale each thread on its own: threads can be multiplexed differently.
                enabled += de
                running += dr
            scaled: float | None
            if running > 0:
                scaled = raw * (enabled / running)
            elif raw == 0 and enabled == 0:
                scaled = 0.0
            else:
                scaled = None
            fraction = round(running / enabled, 4) if enabled else None
            counters[name] = {
                "value": round(scaled) if scaled is not None else None,
                "raw_value": raw,
                "time_enabled_ns": enabled,
                "time_running_ns": running,
                "running_fraction": fraction,
                "multiplexed": fraction is not None and fraction < 0.999,
                "event": opened.spec.description,
            }
            if scaled is None:
                counters[name]["unavailable_reason"] = (
                    "counter never ran on the PMU during the window (time_running=0)"
                )
        self.close()
        return counters

    def close(self) -> None:
        for opened in self.events.values():
            for fd in opened.fds.values():
                with contextlib.suppress(OSError):
                    self.backend.close(fd)
            opened.fds.clear()


def derived(counters: dict[str, Any], window_s: float) -> dict[str, Any]:
    """``ipc``, ``llc_mpki``, ``llc_miss_ratio`` and software-event rates."""

    def val(name: str) -> float | None:
        c = counters.get(name) or {}
        return c.get("value")

    def reason(*names: str) -> str:
        for n in names:
            c = counters.get(n) or {}
            if c.get("value") is None:
                return f"{n}: {c.get('unavailable_reason', 'not measured')}"
        return "denominator is zero in this window"

    out: dict[str, Any] = {}
    unavailable: dict[str, str] = {}
    cyc, ins = val("cycles"), val("instructions")
    refs, miss = val("llc_references"), val("llc_misses")
    if cyc and ins is not None:
        out["ipc"] = round(ins / cyc, 3)
    else:
        out["ipc"] = None
        unavailable["ipc"] = reason("cycles", "instructions")
    if ins and miss is not None:
        out["llc_mpki"] = round(miss * 1000 / ins, 3)
    else:
        out["llc_mpki"] = None
        unavailable["llc_mpki"] = reason("llc_misses", "instructions")
    if refs and miss is not None:
        out["llc_miss_ratio"] = round(miss / refs, 4)
    else:
        out["llc_miss_ratio"] = None
        unavailable["llc_miss_ratio"] = reason("llc_misses", "llc_references")
    for name, key in (
        ("context_switches", "context_switches_per_s"),
        ("cpu_migrations", "cpu_migrations_per_s"),
    ):
        v = val(name)
        out[key] = round(v / window_s, 2) if v is not None and window_s > 0 else None
        if v is None:
            unavailable[key] = reason(name)
    tc = val("task_clock")
    out["task_clock_seconds"] = round(tc / 1e9, 4) if tc is not None else None
    if tc is None:
        unavailable["task_clock_seconds"] = reason("task_clock")
    out["unavailable"] = unavailable
    return out


# --- resctrl ------------------------------------------------------------------


def resctrl_for_pid(pid: int, resctrl_root: Path = Path("/sys/fs/resctrl")) -> dict[str, Any]:
    """Find the resctrl group holding ``pid`` and read its L3 monitoring counters.

    Only reads existing groups; never creates one. The counters cover every task
    in the group, which may be more than this process.
    """
    if not (resctrl_root / "tasks").is_file():
        return {"available": False, "reason": f"{resctrl_root} is not mounted"}
    group = None
    candidates = [resctrl_root]
    for sub in ("mon_groups",):
        candidates.extend(p for p in (resctrl_root / sub).glob("*") if p.is_dir())
    for d in sorted(resctrl_root.glob("*")):
        if d.is_dir() and (d / "tasks").is_file():
            candidates.append(d)
            candidates.extend(p for p in (d / "mon_groups").glob("*") if p.is_dir())
    for d in reversed(candidates):  # most specific first
        text = pf.read_text(d / "tasks") or ""
        if str(pid) in text.split():
            group = d
            break
    if group is None:
        return {"available": False, "reason": f"pid {pid} not found in any resctrl group"}
    occupancy = 0
    mbm = 0
    domains = 0
    for dom in sorted((group / "mon_data").glob("mon_L3_*")):
        o = pf.read_text(dom / "llc_occupancy")
        m = pf.read_text(dom / "mbm_total_bytes")
        if o and o.strip().isdigit():
            occupancy += int(o)
        if m and m.strip().isdigit():
            mbm += int(m)
        domains += 1
    if domains == 0:
        return {"available": False, "reason": f"{group} has no mon_data/mon_L3_* domains"}
    return {
        "available": True,
        "group": str(group),
        "l3_domains": domains,
        "llc_occupancy_bytes": occupancy,
        "mbm_total_bytes_cumulative": mbm,
        "note": "group-wide counters: they include every task in the resctrl group",
    }
