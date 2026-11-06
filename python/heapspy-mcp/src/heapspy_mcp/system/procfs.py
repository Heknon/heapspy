"""Parsers and readers for the Linux ``/proc`` files the process tools use.

Every ``parse_*`` function takes the file's text and returns plain values, so
it can be tested against fixtures from different kernels. Readers take a
``proc_root`` so tests (and containers with the host's ``/proc`` mounted
elsewhere) can point them at another directory. A reader returns ``None``
when the file is missing or unreadable; callers turn that into a ``null``
field with a reason.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

USER_HZ = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

# Field order of the aggregate "cpu" line in /proc/stat (proc(5)). Older kernels
# have fewer columns; missing ones are left out, not set to 0.
STAT_CPU_FIELDS = (
    "user",
    "nice",
    "system",
    "idle",
    "iowait",
    "irq",
    "softirq",
    "steal",
    "guest",
    "guest_nice",
)

# futex(2) syscall number per machine, for /proc/<tid>/syscall.
FUTEX_SYSCALL = {"x86_64": 202, "aarch64": 98, "arm64": 98, "i686": 240, "i386": 240}


def read_text(path: Path) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


# --- /proc/<pid>/status -------------------------------------------------------


def parse_pid_status(text: str) -> dict[str, Any]:
    """``State``, ``Threads``, ``voluntary_ctxt_switches``, ``nonvoluntary_ctxt_switches``,
    ``Cpus_allowed_list``, ``Name``, ``Tgid``, ``NSpid`` and the real ``Uid``."""
    out: dict[str, Any] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        value = value.strip()
        if key in ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches", "Threads", "Tgid"):
            try:
                out[key] = int(value)
            except ValueError:
                continue
        elif key == "State":
            out["State"] = value[:1]
        elif key in ("Name", "Cpus_allowed_list"):
            out[key] = value
        elif key == "Uid":
            uids = value.split()
            if uids and uids[0].isdigit():
                out["Uid"] = int(uids[0])
        elif key == "NSpid":
            out[key] = [int(x) for x in value.split() if x.isdigit()]
    return out


# --- /proc/<pid>/stat ---------------------------------------------------------


@dataclass
class PidStat:
    comm: str
    state: str
    ppid: int
    minflt: int
    majflt: int
    utime_ticks: int
    stime_ticks: int
    num_threads: int
    starttime_ticks: int
    rss_pages: int
    processor: int | None
    delayacct_blkio_ticks: int | None


def parse_pid_stat(text: str) -> PidStat:
    """Parse ``/proc/<pid>/stat``. ``comm`` may contain spaces and parentheses, so
    the fields are split after the last ``)``."""
    open_paren = text.index("(")
    close_paren = text.rindex(")")
    comm = text[open_paren + 1 : close_paren]
    rest = text[close_paren + 2 :].split()
    # rest[0] is field 3 (state); field N is rest[N - 3].

    def field_(n: int) -> int | None:
        i = n - 3
        return int(rest[i]) if i < len(rest) else None

    return PidStat(
        comm=comm,
        state=rest[0],
        ppid=field_(4) or 0,
        minflt=field_(10) or 0,
        majflt=field_(12) or 0,
        utime_ticks=field_(14) or 0,
        stime_ticks=field_(15) or 0,
        num_threads=field_(20) or 0,
        starttime_ticks=field_(22) or 0,
        rss_pages=field_(24) or 0,
        processor=field_(39),
        delayacct_blkio_ticks=field_(42),
    )


# --- /proc/<pid>/schedstat ----------------------------------------------------


@dataclass
class SchedStat:
    run_ns: int
    wait_ns: int
    timeslices: int


def parse_pid_schedstat(text: str) -> SchedStat | None:
    """``/proc/<pid>/schedstat``: time on CPU (ns), time runnable but waiting on a
    run queue (ns), and the number of timeslices run."""
    parts = text.split()
    if len(parts) < 3:
        return None
    try:
        return SchedStat(int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


# --- /proc/<pid>/sched --------------------------------------------------------


def parse_pid_sched_migrations(text: str) -> int | None:
    """``se.nr_migrations`` from ``/proc/<pid>/sched`` (needs CONFIG_SCHED_DEBUG)."""
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() == "se.nr_migrations":
            try:
                return int(value.strip())
            except ValueError:
                return None
    return None


def parse_pid_sched(text: str) -> dict[str, float]:
    """Every numeric ``name : value`` line of ``/proc/<pid>/sched`` (CONFIG_SCHED_DEBUG).

    Times are as the kernel prints them: ``se.slice`` in nanoseconds, the
    ``se.sum_exec_runtime`` and ``se.statistics.*`` / ``sum_sleep_runtime`` style
    fields in milliseconds. Fields differ between kernels; callers look up the
    ones they need and treat a missing one as unavailable.
    """
    out: dict[str, float] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip()
        if not key or " " in key:
            continue
        try:
            out[key] = float(value.strip())
        except ValueError:
            continue
    return out


def sched_slice_ns(fields: dict[str, float]) -> int | None:
    """``se.slice`` (EEVDF, kernels 6.6+): the task's requested slice in nanoseconds."""
    v = fields.get("se.slice")
    return int(v) if v is not None and v > 0 else None


def parse_cpu_list(text: str | None) -> list[int] | None:
    """A kernel CPU list such as ``0-3,8,10-11`` (``Cpus_allowed_list``, sysfs
    ``shared_cpu_list``, ``cpuset.cpus``) to sorted CPU numbers; None if malformed."""
    if text is None:
        return None
    out: set[int] = set()
    for part in text.strip().split(","):
        part = part.strip()
        if not part:
            continue
        lo, sep, hi = part.partition("-")
        try:
            if sep:
                a, b = int(lo), int(hi)
                if b < a or b - a > 65536:
                    return None
                out.update(range(a, b + 1))
            else:
                out.add(int(lo))
        except ValueError:
            return None
    return sorted(out)


# --- CPU cache topology (sysfs) ---------------------------------------------------

_SIZE_SUFFIX = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}


def parse_cache_size(text: str | None) -> int | None:
    """sysfs cache ``size`` (``48K``, ``2048K``, ``32M``) to bytes."""
    if not text:
        return None
    t = text.strip().upper()
    unit = t[-1] if t and t[-1] in "KMG" else ""
    num = t[:-1] if unit else t
    try:
        return int(num) * _SIZE_SUFFIX[unit]
    except ValueError:
        return None


def read_cache_topology(sys_root: Path = Path("/sys"), cpu: int = 0) -> list[dict[str, Any]]:
    """Caches of one CPU from ``/sys/devices/system/cpu/cpu<N>/cache/index*``: level,
    type (Data, Instruction, Unified), size, line size and the CPUs sharing it.
    Empty when sysfs does not expose them."""
    base = sys_root / "devices" / "system" / "cpu" / f"cpu{cpu}" / "cache"
    try:
        dirs = sorted(d for d in base.iterdir() if d.name.startswith("index"))
    except OSError:
        return []
    out = []
    for d in dirs:
        level = (read_text(d / "level") or "").strip()
        if not level.isdigit():
            continue
        line = (read_text(d / "coherency_line_size") or "").strip()
        shared = (read_text(d / "shared_cpu_list") or "").strip()
        out.append(
            {
                "level": int(level),
                "type": (read_text(d / "type") or "").strip() or None,
                "size_bytes": parse_cache_size(read_text(d / "size")),
                "line_size_bytes": int(line) if line.isdigit() else None,
                "shared_cpu_list": shared or None,
                "shared_cpu_count": len(parse_cpu_list(shared) or []) or None,
            }
        )
    return out


def cache_size(topology: list[dict[str, Any]], level: int) -> int | None:
    """Size of the data or unified cache at ``level``, or None."""
    for c in topology:
        if c["level"] == level and c["type"] in ("Data", "Unified"):
            return c["size_bytes"]
    return None


# --- scheduler slice default ------------------------------------------------------

EEVDF_BASE_SLICE_NS = 750_000
EEVDF_BASE_SLICE_NS_6_12 = 700_000  # lowered in Linux 6.12


def _kernel_at_least(release: str, major: int, minor: int) -> bool:
    parts = release.split(".")
    try:
        return (int(parts[0]), int("".join(c for c in parts[1] if c.isdigit()) or 0)) >= (
            major,
            minor,
        )
    except (IndexError, ValueError):
        return False


def default_base_slice(
    proc_root: Path, sys_root: Path, ncpus: int, release: str | None = None
) -> dict[str, Any]:
    """The scheduler's base slice, from the first source that exists:

    1. ``/sys/kernel/debug/sched/base_slice_ns`` (EEVDF, 6.6+, debugfs mounted)
    2. ``/proc/sys/kernel/sched_base_slice_ns`` (some distribution kernels)
    3. ``/sys/kernel/debug/sched/min_granularity_ns`` or
       ``/proc/sys/kernel/sched_min_granularity_ns`` (CFS before 6.6)
    4. the EEVDF default, 0.7 ms (0.75 ms before 6.12) x (1 + log2(min(CPUs, 8))),
       marked as an estimate
    """
    for path, kind in (
        (sys_root / "kernel" / "debug" / "sched" / "base_slice_ns", "base_slice_ns"),
        (proc_root / "sys" / "kernel" / "sched_base_slice_ns", "base_slice_ns"),
        (sys_root / "kernel" / "debug" / "sched" / "min_granularity_ns", "min_granularity_ns"),
        (proc_root / "sys" / "kernel" / "sched_min_granularity_ns", "min_granularity_ns"),
    ):
        text = (read_text(path) or "").strip()
        if text.isdigit() and int(text) > 0:
            return {"slice_ns": int(text), "source": str(path), "kind": kind, "estimate": False}
    factor = max(min(ncpus, 8), 1).bit_length()  # 1 + floor(log2(n))
    rel = release if release is not None else platform.release()
    base = EEVDF_BASE_SLICE_NS_6_12 if _kernel_at_least(rel, 6, 12) else EEVDF_BASE_SLICE_NS
    return {
        "slice_ns": base * factor,
        "source": f"EEVDF default {base / 1e6:g} ms x (1 + log2(min(CPUs, 8))) for kernel "
        f"{rel}; no sysctl or debugfs value was readable",
        "kind": "base_slice_ns",
        "estimate": True,
    }


# --- /proc/stat ---------------------------------------------------------------


@dataclass
class ProcStat:
    cpu_ticks: dict[str, int]
    per_cpu_count: int
    ctxt: int | None
    procs_running: int | None
    procs_blocked: int | None
    btime: int | None


def parse_proc_stat(text: str) -> ProcStat:
    cpu_ticks: dict[str, int] = {}
    per_cpu = 0
    values: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "cpu":
            for name, raw in zip(STAT_CPU_FIELDS, parts[1:], strict=False):
                cpu_ticks[name] = int(raw)
        elif parts[0].startswith("cpu") and parts[0][3:].isdigit():
            per_cpu += 1
        elif parts[0] in ("ctxt", "procs_running", "procs_blocked", "btime") and len(parts) > 1:
            values[parts[0]] = int(parts[1])
    return ProcStat(
        cpu_ticks=cpu_ticks,
        per_cpu_count=per_cpu,
        ctxt=values.get("ctxt"),
        procs_running=values.get("procs_running"),
        procs_blocked=values.get("procs_blocked"),
        btime=values.get("btime"),
    )


# --- /proc/schedstat ----------------------------------------------------------


@dataclass
class CpuSchedStat:
    cpu: int
    running_ns: int
    waiting_ns: int
    timeslices: int


@dataclass
class ProcSchedStat:
    version: int | None
    cpus: list[CpuSchedStat] = field(default_factory=list)
    note: str | None = None


KNOWN_SCHEDSTAT_VERSIONS = (15, 16, 17)


def parse_proc_schedstat(text: str) -> ProcSchedStat:
    """Per-CPU lines of ``/proc/schedstat``.

    Versions 15 to 17 (kernels 4.x to 6.x) share the ``cpuN`` line layout:
    nine counters, of which the 7th is time spent running tasks (ns), the 8th
    time tasks spent waiting to run (ns) and the 9th the number of timeslices.
    Other versions are reported as unreadable rather than guessed at.
    """
    version: int | None = None
    cpus: list[CpuSchedStat] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "version" and len(parts) > 1 and parts[1].isdigit():
            version = int(parts[1])
        elif parts[0].startswith("cpu") and parts[0][3:].isdigit() and len(parts) >= 10:
            try:
                cpus.append(
                    CpuSchedStat(int(parts[0][3:]), int(parts[7]), int(parts[8]), int(parts[9]))
                )
            except ValueError:
                continue
    if version not in KNOWN_SCHEDSTAT_VERSIONS:
        return ProcSchedStat(version, [], f"unrecognised /proc/schedstat version {version}")
    return ProcSchedStat(version, cpus)


# --- PSI ----------------------------------------------------------------------


def parse_psi(text: str) -> dict[str, dict[str, float]]:
    """``some``/``full`` lines of a pressure file to ``{"some": {"avg10": ..,
    "avg60": .., "avg300": .., "total_us": ..}}``. The ``full`` line is absent for
    host ``cpu`` on kernels before 5.13, and is all zeros there on later ones."""
    out: dict[str, dict[str, float]] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] not in ("some", "full"):
            continue
        row: dict[str, float] = {}
        for item in parts[1:]:
            key, sep, value = item.partition("=")
            if not sep:
                continue
            if key == "total":
                row["total_us"] = int(value)
            else:
                row[key] = float(value)
        out[parts[0]] = row
    return out


def parse_loadavg(text: str) -> dict[str, Any]:
    parts = text.split()
    running, _, total = parts[3].partition("/")
    return {
        "load1": float(parts[0]),
        "load5": float(parts[1]),
        "load15": float(parts[2]),
        "runnable_entities": int(running),
        "total_entities": int(total),
    }


# --- wait sites ---------------------------------------------------------------

WAIT_SITE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("futex", ("futex",)),
    ("poll_epoll_select", ("epoll", "ep_poll", "do_sys_poll", "do_select", "poll_schedule")),
    ("timer_sleep", ("nanosleep", "hrtimer", "schedule_timeout", "clock_nanosleep")),
    (
        "block_io",
        ("io_schedule", "folio_wait", "wait_on_page", "blk_", "bit_wait_io", "jbd2", "xfs_"),
    ),
    (
        "pipe_socket",
        ("pipe_", "sk_wait", "unix_stream", "inet_csk", "wait_woken", "tcp_", "udp_"),
    ),
)


def classify_wait_site(wchan: str | None, syscall_nr: int | None, futex_nr: int | None) -> str:
    """Group a sleeping thread's kernel wait site (``wchan``) into a coarse bucket.

    The bucket names describe where the thread sleeps, not why.
    """
    if syscall_nr is not None and futex_nr is not None and syscall_nr == futex_nr:
        return "futex"
    if not wchan or wchan == "0":
        return "unknown"
    for group, needles in WAIT_SITE_GROUPS:
        if any(n in wchan for n in needles):
            return group
    return "other"


def parse_syscall_nr(text: str | None) -> int | None:
    """First field of ``/proc/<tid>/syscall``; ``running`` or ``-1`` give None."""
    if not text:
        return None
    first = text.split(maxsplit=1)[0] if text.split() else ""
    try:
        nr = int(first)
    except ValueError:
        return None
    return nr if nr >= 0 else None


def futex_syscall_nr() -> int | None:
    return FUTEX_SYSCALL.get(platform.machine())


# --- thread state -------------------------------------------------------------


def state_bucket(state: str) -> str:
    """Map a ``/proc`` state letter to running_or_runnable, sleeping, disk_wait or other."""
    if state == "R":
        return "running_or_runnable"
    if state in ("S", "I"):
        return "sleeping"
    if state == "D":
        return "disk_wait"
    return "other"


def empty_state_counts() -> dict[str, int]:
    return {"running_or_runnable": 0, "sleeping": 0, "disk_wait": 0, "other": 0}


def read_task_delayacct(proc_root: Path) -> bool | None:
    """``kernel.task_delayacct``: None if the sysctl does not exist (kernels before 5.14,
    where delay accounting is on unless booted with ``nodelayacct``)."""
    text = read_text(proc_root / "sys" / "kernel" / "task_delayacct")
    if text is None:
        return None
    return text.strip() == "1"


def parse_pid_io(text: str) -> dict[str, int]:
    """``/proc/<pid>/io``: ``read_bytes``/``write_bytes`` are storage-layer bytes;
    ``rchar``/``wchar`` count every read/write call, including pipes and sockets."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and value.strip().isdigit():
            out[key.strip()] = int(value.strip())
    return out


def parse_nofile_limit(text: str) -> int | None:
    """Soft ``Max open files`` from ``/proc/<pid>/limits``; None if unlimited."""
    for line in text.splitlines():
        if line.startswith("Max open files"):
            parts = line[len("Max open files") :].split()
            if parts and parts[0].isdigit():
                return int(parts[0])
            return None
    return None


def parse_uptime(text: str) -> float:
    return float(text.split()[0])


# --- memory -------------------------------------------------------------------


def parse_kb_fields(text: str, keys: tuple[str, ...] | None = None) -> dict[str, int]:
    """``Key:   123 kB`` lines (``status``, ``smaps_rollup``, ``meminfo``) to bytes.

    Lines without a ``kB`` unit (``HugePages_Total: 0``) are kept as plain counts.
    ``keys`` limits the result to those names.
    """
    out: dict[str, int] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep or (keys is not None and key not in keys):
            continue
        parts = value.split()
        if not parts or not parts[0].isdigit():
            continue
        n = int(parts[0])
        out[key] = n * 1024 if len(parts) > 1 and parts[1] == "kB" else n
    return out


STATUS_MEMORY_KEYS = ("VmRSS", "VmHWM", "VmSwap", "RssAnon", "RssFile", "RssShmem")
SMAPS_ROLLUP_KEYS = ("Rss", "Pss", "Swap", "SwapPss", "Anonymous", "Pss_Anon", "Pss_File")
MEMINFO_KEYS = ("MemTotal", "MemFree", "MemAvailable", "SwapTotal", "SwapFree", "Dirty")


def parse_status_memory(text: str) -> dict[str, int]:
    """Memory lines of ``/proc/<pid>/status`` in bytes (``VmSwap`` and ``Rss*`` need 4.5+)."""
    return parse_kb_fields(text, STATUS_MEMORY_KEYS)


def parse_smaps_rollup(text: str) -> dict[str, int]:
    """``/proc/<pid>/smaps_rollup`` (4.14+) totals in bytes; the header line is skipped."""
    return parse_kb_fields(text, SMAPS_ROLLUP_KEYS)


def parse_vmstat(text: str) -> dict[str, int]:
    """``/proc/vmstat``: one ``name value`` counter per line."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                continue
    return out


def _bare_function(name: str) -> str:
    """``shrink_node.isra.0`` -> ``shrink_node``; a leading ``.`` (ppc64) is kept."""
    head, dot, _ = name[1:].partition(".")
    return name[0] + head if dot else name


def parse_stack(text: str | None) -> list[str]:
    """Function names of ``/proc/<tid>/stack``, innermost first, without offsets.

    Lines look like ``[<0>] folio_wait_bit_common+0x110/0x310`` (addresses are
    hidden unless ``kptr_restrict`` allows them) and may end with a module name
    in brackets. Compiler suffixes such as ``.isra.0`` or ``.constprop.0`` are
    removed so names match across builds.
    """
    if not text:
        return []
    frames: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            _, _, line = line.partition("] ")
        name = line.split("+", 1)[0].split(" ", 1)[0].strip()
        if not name or name.startswith("0x"):
            continue
        frames.append(_bare_function(name))
    return frames


def parse_wchan(text: str | None) -> str | None:
    """``/proc/<tid>/wchan``: a function name, or None for ``0`` (running) and empty."""
    if text is None:
        return None
    value = text.strip()
    return None if value in ("", "0") else _bare_function(value)
