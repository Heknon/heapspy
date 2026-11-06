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
