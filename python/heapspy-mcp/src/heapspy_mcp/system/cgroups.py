"""Find and read the cgroup a process is in (cgroup v2, with a v1 fallback).

The cgroup is resolved from ``/proc/<pid>/cgroup`` and the cgroup mounts in
``/proc/self/mountinfo``. On a v2-only host everything comes from the unified
hierarchy. On a hybrid host where the ``cpu`` controller is still bound to a
v1 hierarchy, CPU accounting and throttling come from the v1 ``cpu`` and
``cpuacct`` hierarchies and pressure files from the v2 one; the result says
which.

Kubernetes pod identity is parsed from the cgroup path only (systemd and
cgroupfs driver layouts). Pod names are not looked up.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .procfs import USER_HZ, parse_psi, read_text

MAX_ANCESTORS = 8


# --- mounts -------------------------------------------------------------------


@dataclass
class CgroupMounts:
    v2: Path | None = None
    v1: dict[str, Path] = field(default_factory=dict)  # controller -> mount point
    v1_roots: dict[str, str] = field(default_factory=dict)  # controller -> mount root
    v2_root: str = "/"


def parse_mountinfo(text: str) -> CgroupMounts:
    """Cgroup mounts from ``/proc/self/mountinfo`` (proc(5) format)."""
    mounts = CgroupMounts()
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        lf = left.split()
        rf = right.split()
        if len(lf) < 5 or len(rf) < 3:
            continue
        root, mount_point, fstype = lf[3], Path(lf[4].replace("\\040", " ")), rf[0]
        if fstype == "cgroup2":
            # Prefer /sys/fs/cgroup over other mounts of the same hierarchy.
            if mounts.v2 is None or str(mount_point) == "/sys/fs/cgroup":
                mounts.v2 = mount_point
                mounts.v2_root = root
        elif fstype == "cgroup":
            for opt in rf[2].split(","):
                if opt in ("rw", "ro") or "=" in opt or opt.startswith("name"):
                    continue
                mounts.v1.setdefault(opt, mount_point)
                mounts.v1_roots.setdefault(opt, root)
    return mounts


def discover_mounts(proc_root: Path, cgroup_root: Path | None) -> CgroupMounts:
    """Mounts as seen by this server, or a configured v2 root (``--cgroup-root``)."""
    if cgroup_root is not None:
        return CgroupMounts(v2=cgroup_root)
    text = read_text(proc_root / "self" / "mountinfo")
    return parse_mountinfo(text or "")


# --- /proc/<pid>/cgroup -------------------------------------------------------


@dataclass
class PidCgroups:
    v2_path: str | None = None
    v1_paths: dict[str, str] = field(default_factory=dict)


def parse_pid_cgroup(text: str) -> PidCgroups:
    out = PidCgroups()
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        hier, controllers, path = parts
        if hier == "0" and controllers == "":
            out.v2_path = path
        else:
            for c in controllers.split(","):
                if c and not c.startswith("name="):
                    out.v1_paths[c] = path
    return out


def _join(mount: Path, mount_root: str, path: str) -> tuple[Path, str | None]:
    """Turn a ``/proc/<pid>/cgroup`` path into a directory under ``mount``.

    Inside a private cgroup namespace, paths of processes outside it start
    with ``/..``. Those segments are dropped and the rest is looked up from the
    mount's top, which matches a host cgroupfs mounted with ``--cgroup-root``.
    """
    note = None
    rel = path
    if mount_root not in ("/", "") and rel.startswith(mount_root):
        rel = rel[len(mount_root) :]
    parts = [p for p in rel.split("/") if p]
    if parts and parts[0] == "..":
        parts = [p for p in parts if p != ".."]
        note = "cgroup path is outside this server's cgroup namespace; resolved from the mount top"
    return mount.joinpath(*parts) if parts else mount, note


# --- file parsers -------------------------------------------------------------


def parse_flat_keyed(text: str) -> dict[str, int]:
    """``key value`` lines (``cpu.stat``, ``cpuacct.stat``)."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                continue
    return out


def parse_cpu_max(text: str) -> dict[str, Any]:
    """v2 ``cpu.max``: ``max 100000`` or ``50000 100000``."""
    parts = text.split()
    quota = None if parts[0] == "max" else int(parts[0])
    period = int(parts[1]) if len(parts) > 1 else 100000
    return {
        "quota_usec": quota,
        "period_usec": period,
        "limit_cores": round(quota / period, 3) if quota is not None and period else None,
    }


def parse_v1_quota(quota_text: str, period_text: str) -> dict[str, Any]:
    quota = int(quota_text.strip())
    period = int(period_text.strip())
    q = None if quota < 0 else quota
    return {
        "quota_usec": q,
        "period_usec": period,
        "limit_cores": round(q / period, 3) if q is not None and period else None,
    }


def parse_cpu_list(text: str) -> list[int]:
    """``0-3,8,10-11`` -> ``[0, 1, 2, 3, 8, 10, 11]``."""
    cpus: list[int] = []
    for part in text.strip().split(","):
        if not part:
            continue
        lo, sep, hi = part.partition("-")
        if sep:
            cpus.extend(range(int(lo), int(hi) + 1))
        else:
            cpus.append(int(lo))
    return cpus


# --- Kubernetes pod identity ---------------------------------------------------

_QOS = {"burstable": "Burstable", "besteffort": "BestEffort"}
_POD_SYSTEMD = re.compile(
    r"^kubepods(?:-(?P<qos>burstable|besteffort))?-pod(?P<uid>[0-9a-f_]{36})\.slice$"
)
_POD_CGROUPFS = re.compile(r"^pod(?P<uid>[0-9a-f-]{36})$")
_CONTAINER_SCOPE = re.compile(
    r"^(?P<runtime>cri-containerd|crio|docker|containerd)-(?P<id>[0-9a-f]{12,64})\.scope$"
)
_CONTAINER_ID = re.compile(r"^(?P<id>[0-9a-f]{64})$")


def parse_kubepods_path(path: str) -> dict[str, Any] | None:
    """Pod UID, QoS class and container id from a cgroup path, or None.

    Handles the systemd driver layout
    (``/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/
    cri-containerd-<id>.scope``, with ``_`` in place of ``-`` in the UID) and the
    cgroupfs driver layout (``/kubepods/burstable/pod<uid>/<id>``). Pods with no
    QoS segment are Guaranteed.
    """
    parts = [p for p in path.split("/") if p and p != ".."]
    try:
        start = next(i for i, p in enumerate(parts) if p in ("kubepods", "kubepods.slice"))
    except StopIteration:
        return None
    rest = parts[start + 1 :]
    qos = "Guaranteed"
    uid = None
    container_id = None
    runtime = None
    for seg in rest:
        if seg in ("burstable", "besteffort"):
            qos = _QOS[seg]
            continue
        m = re.match(r"^kubepods-(burstable|besteffort)\.slice$", seg)
        if m:
            qos = _QOS[m.group(1)]
            continue
        m = _POD_SYSTEMD.match(seg)
        if m:
            uid = m.group("uid").replace("_", "-")
            if m.group("qos"):
                qos = _QOS[m.group("qos")]
            continue
        m = _POD_CGROUPFS.match(seg)
        if m:
            uid = m.group("uid")
            continue
        if uid is not None:
            m = _CONTAINER_SCOPE.match(seg)
            if m:
                container_id, runtime = m.group("id"), m.group("runtime")
                continue
            m = _CONTAINER_ID.match(seg)
            if m:
                container_id = m.group("id")
    if uid is None:
        return {
            "pod_uid": None,
            "qos_class": qos,
            "container_id": None,
            "note": "kubepods cgroup above pod level",
        }
    return {
        "pod_uid": uid,
        "qos_class": qos,
        "container_id": container_id,
        "container_runtime": runtime,
    }


# --- reading a cgroup ---------------------------------------------------------


@dataclass
class CgroupLocation:
    """Where a process's CPU, pressure and cpuset files are."""

    version: str  # "v2" or "v1+v2" (hybrid) or "v1"
    path: str  # the path from /proc/<pid>/cgroup used for identity
    cpu_dir: Path | None  # cpu.stat / cpu.max (v2) or cpu.cfs_* (v1)
    cpuacct_dir: Path | None  # v1 only
    pressure_dir: Path | None  # v2 directory with *.pressure
    cpuset_dir: Path | None
    cpuset_v1: bool
    cpu_root: Path | None  # walk limit for ancestors
    notes: list[str] = field(default_factory=list)
    cpuacct_matches: bool = True  # v1: the cpuacct cgroup is the same path as the cpu one


def locate(pid_cgroup: PidCgroups, mounts: CgroupMounts) -> CgroupLocation | None:
    notes: list[str] = []
    v2_dir = None
    if mounts.v2 is not None and pid_cgroup.v2_path is not None:
        v2_dir, note = _join(mounts.v2, mounts.v2_root, pid_cgroup.v2_path)
        if note:
            notes.append(note)

    def v1_dir(ctrl: str) -> Path | None:
        if ctrl not in mounts.v1 or ctrl not in pid_cgroup.v1_paths:
            return None
        d, note = _join(mounts.v1[ctrl], mounts.v1_roots.get(ctrl, "/"), pid_cgroup.v1_paths[ctrl])
        if note and note not in notes:
            notes.append(note)
        return d

    cpu_v1 = v1_dir("cpu")
    if cpu_v1 is not None:
        notes.append(
            "the cpu controller is on a cgroup v1 hierarchy; CPU accounting and throttling "
            "come from cgroup v1 files"
        )
        cpuset_v1 = v1_dir("cpuset")
        return CgroupLocation(
            version="v1+v2" if v2_dir is not None else "v1",
            path=pid_cgroup.v1_paths["cpu"],
            cpu_dir=cpu_v1,
            cpuacct_dir=v1_dir("cpuacct"),
            pressure_dir=v2_dir,
            cpuset_dir=cpuset_v1 if cpuset_v1 is not None else v2_dir,
            cpuset_v1=cpuset_v1 is not None,
            cpu_root=mounts.v1["cpu"],
            notes=notes,
            cpuacct_matches=pid_cgroup.v1_paths.get("cpuacct") == pid_cgroup.v1_paths["cpu"],
        )
    if v2_dir is None:
        return None
    return CgroupLocation(
        version="v2",
        path=pid_cgroup.v2_path or "/",
        cpu_dir=v2_dir,
        cpuacct_dir=None,
        pressure_dir=v2_dir,
        cpuset_dir=v2_dir,
        cpuset_v1=False,
        cpu_root=mounts.v2,
        notes=notes,
    )


def is_v1_cpu(loc: CgroupLocation) -> bool:
    return loc.version != "v2"


def read_cpu_stat(loc: CgroupLocation, directory: Path | None = None) -> dict[str, int | None]:
    """CPU usage and throttling counters of ``directory`` (default: the process's cgroup),
    in microseconds whatever the cgroup version."""
    d = directory or loc.cpu_dir
    keys = (
        "usage_usec",
        "user_usec",
        "system_usec",
        "nr_periods",
        "nr_throttled",
        "throttled_usec",
    )
    if d is None:
        return dict.fromkeys(keys)
    raw = parse_flat_keyed(read_text(d / "cpu.stat") or "")
    if not is_v1_cpu(loc):
        return {k: raw.get(k) for k in keys}
    out: dict[str, int | None] = {
        "nr_periods": raw.get("nr_periods"),
        "nr_throttled": raw.get("nr_throttled"),
        "throttled_usec": raw["throttled_time"] // 1000 if "throttled_time" in raw else None,
    }
    if not loc.cpuacct_matches:
        # Separate cpu and cpuacct hierarchies with different paths: no usage for this cgroup.
        out.update(usage_usec=None, user_usec=None, system_usec=None)
        return out
    acct = d if loc.cpuacct_dir is None else _sibling(loc, d)

    def ns_file(name: str) -> int | None:
        text = read_text(acct / name) if acct else None
        return int(text) // 1000 if text and text.strip().isdigit() else None

    out["usage_usec"] = ns_file("cpuacct.usage")
    out["user_usec"] = ns_file("cpuacct.usage_user")
    out["system_usec"] = ns_file("cpuacct.usage_sys")
    if out["user_usec"] is None and acct is not None:
        stat = parse_flat_keyed(read_text(acct / "cpuacct.stat") or "")
        if "user" in stat:
            out["user_usec"] = stat["user"] * 1_000_000 // USER_HZ
        if "system" in stat:
            out["system_usec"] = stat["system"] * 1_000_000 // USER_HZ
    return out


def _sibling(loc: CgroupLocation, cpu_ancestor: Path) -> Path | None:
    """The cpuacct directory at the same position as ``cpu_ancestor`` in the cpu tree."""
    assert loc.cpu_dir is not None and loc.cpuacct_dir is not None
    depth = len(loc.cpu_dir.parts) - len(cpu_ancestor.parts)
    if depth < 0:
        return None
    d = loc.cpuacct_dir
    for _ in range(depth):
        d = d.parent
    return d


def read_limit(loc: CgroupLocation, directory: Path) -> dict[str, Any] | None:
    if not is_v1_cpu(loc):
        text = read_text(directory / "cpu.max")
        return parse_cpu_max(text) if text else None
    quota = read_text(directory / "cpu.cfs_quota_us")
    period = read_text(directory / "cpu.cfs_period_us")
    if quota is None or period is None:
        return None
    return parse_v1_quota(quota, period)


def read_pressure(loc: CgroupLocation) -> dict[str, dict[str, dict[str, float]] | None]:
    out: dict[str, dict[str, dict[str, float]] | None] = {}
    for res in ("cpu", "memory", "io"):
        text = read_text(loc.pressure_dir / f"{res}.pressure") if loc.pressure_dir else None
        out[res] = parse_psi(text) if text else None
    return out


def read_cpuset(loc: CgroupLocation) -> list[int] | None:
    if loc.cpuset_dir is None:
        return None
    name = "cpuset.effective_cpus" if loc.cpuset_v1 else "cpuset.cpus.effective"
    d: Path | None = loc.cpuset_dir
    text = read_text(d / name)
    if text is None and loc.cpuset_v1:
        text = read_text(d / "cpuset.cpus")
    if text is None or not text.strip():
        return None
    return parse_cpu_list(text)


def limited_ancestors(loc: CgroupLocation) -> list[Path]:
    """The process's cgroup and every ancestor that has a CPU quota, nearest first."""
    if loc.cpu_dir is None or loc.cpu_root is None:
        return []
    found: list[Path] = []
    d = loc.cpu_dir
    for _ in range(64):
        lim = read_limit(loc, d)
        if d == loc.cpu_dir or (lim and lim.get("quota_usec") is not None):
            found.append(d)
        if d == loc.cpu_root or d.parent == d or len(found) > MAX_ANCESTORS:
            break
        d = d.parent
    return found[: MAX_ANCESTORS + 1]


# --- memory controller ----------------------------------------------------------

# A v1 limit at or above this is "no limit" (the kernel reports PAGE_COUNTER_MAX pages).
V1_UNLIMITED = 1 << 62

# memory.stat counters reported as deltas. v1 names them with a total_ prefix for the
# hierarchical value; v1 before 5.9 has a single workingset_refault.
MEMORY_STAT_KEYS = (
    "workingset_refault_anon",
    "workingset_refault_file",
    "workingset_refault",
    "pgmajfault",
    "pgfault",
    "pgscan",
    "pgsteal",
    "pgscan_direct",
    "pgscan_kswapd",
)
MEMORY_STAT_LEVELS = ("anon", "file", "swap", "rss", "cache")
MEMORY_EVENT_KEYS = ("low", "high", "max", "oom", "oom_kill", "oom_group_kill")


@dataclass
class MemoryLocation:
    """Where a process's memory controller files are.

    ``pressure_dir`` is the process's v2 directory: PSI follows the v2 hierarchy
    even when the memory controller is bound to v1 (hybrid hosts).
    """

    version: str  # "v2" or "v1"
    path: str
    dir: Path
    root: Path
    pressure_dir: Path | None
    notes: list[str] = field(default_factory=list)


def locate_memory(pid_cgroup: PidCgroups, mounts: CgroupMounts) -> MemoryLocation | None:
    notes: list[str] = []
    v2_dir = None
    if mounts.v2 is not None and pid_cgroup.v2_path is not None:
        v2_dir, note = _join(mounts.v2, mounts.v2_root, pid_cgroup.v2_path)
        if note:
            notes.append(note)
    if "memory" in mounts.v1 and "memory" in pid_cgroup.v1_paths:
        d, note = _join(
            mounts.v1["memory"], mounts.v1_roots.get("memory", "/"), pid_cgroup.v1_paths["memory"]
        )
        if note and note not in notes:
            notes.append(note)
        notes.append(
            "the memory controller is on a cgroup v1 hierarchy; usage, limit and memory.stat "
            "come from cgroup v1 files, pressure from the v2 directory"
        )
        return MemoryLocation(
            "v1", pid_cgroup.v1_paths["memory"], d, mounts.v1["memory"], v2_dir, notes
        )
    if v2_dir is None or mounts.v2 is None:
        return None
    return MemoryLocation("v2", pid_cgroup.v2_path or "/", v2_dir, mounts.v2, v2_dir, notes)


def parse_memory_value(text: str | None) -> int | None:
    """``memory.max``-style value: ``max`` (or a huge v1 limit) is None."""
    if text is None:
        return None
    value = text.strip()
    if not value.isdigit():
        return None
    n = int(value)
    return None if n >= V1_UNLIMITED else n


def _int_file(path: Path) -> int | None:
    text = read_text(path)
    return int(text.strip()) if text and text.strip().isdigit() else None


def _v1_stat(raw: dict[str, int]) -> dict[str, int]:
    """Hierarchical (``total_``) values where v1 has them, under the v2 names."""
    out: dict[str, int] = {}
    for key in (*MEMORY_STAT_KEYS, *MEMORY_STAT_LEVELS, "hierarchical_memory_limit"):
        if f"total_{key}" in raw:
            out[key] = raw[f"total_{key}"]
        elif key in raw:
            out[key] = raw[key]
    return out


def read_memory(loc: MemoryLocation) -> dict[str, Any]:
    """Cumulative memory counters and current levels of the process's memory cgroup.

    Keys are the same for v1 and v2; a value the version does not have is None and
    named in ``unavailable`` with the reason.
    """
    d = loc.dir
    unavailable: dict[str, str] = {}
    out: dict[str, Any] = {"version": loc.version}
    if loc.version == "v2":
        out["usage_bytes"] = _int_file(d / "memory.current")
        out["max_bytes"] = parse_memory_value(read_text(d / "memory.max"))
        out["high_bytes"] = parse_memory_value(read_text(d / "memory.high"))
        out["swap_usage_bytes"] = _int_file(d / "memory.swap.current")
        if out["usage_bytes"] is None:
            unavailable["usage_bytes"] = (
                "no memory.current (the root cgroup, or the memory controller is not enabled "
                "for this cgroup)"
            )
        events = parse_flat_keyed(read_text(d / "memory.events") or "")
        out["events"] = {k: events.get(k) for k in MEMORY_EVENT_KEYS}
        if not events:
            unavailable["events"] = "memory.events not readable"
        raw = parse_flat_keyed(read_text(d / "memory.stat") or "")
        out["stat"] = {k: raw[k] for k in (*MEMORY_STAT_KEYS, *MEMORY_STAT_LEVELS) if k in raw}
        if not raw:
            unavailable["stat"] = "memory.stat not readable"
    else:
        raw = _v1_stat(parse_flat_keyed(read_text(d / "memory.stat") or ""))
        out["usage_bytes"] = _int_file(d / "memory.usage_in_bytes")
        own = parse_memory_value(read_text(d / "memory.limit_in_bytes"))
        # hierarchical_memory_limit is the tightest limit of this cgroup and its ancestors.
        hier = parse_memory_value(str(raw.pop("hierarchical_memory_limit", "")))
        limits = [v for v in (own, hier) if v is not None]
        out["max_bytes"] = min(limits) if limits else None
        out["high_bytes"] = None
        unavailable["high_bytes"] = "cgroup v1 has no memory.high"
        memsw = _int_file(d / "memory.memsw.usage_in_bytes")
        out["swap_usage_bytes"] = (
            memsw - out["usage_bytes"]
            if memsw is not None and out["usage_bytes"] is not None
            else None
        )
        if memsw is None:
            unavailable["swap_usage_bytes"] = "memory.memsw.* not present (swap accounting off)"
        oom = parse_flat_keyed(read_text(d / "memory.oom_control") or "")
        out["events"] = {
            "low": None,
            "high": None,
            # failcnt counts the times usage hit the limit: the v1 counterpart of "max".
            "max": _int_file(d / "memory.failcnt"),
            "oom": None,
            "oom_kill": oom.get("oom_kill"),
            "oom_group_kill": None,
        }
        out["under_oom"] = bool(oom.get("under_oom")) if "under_oom" in oom else None
        unavailable["events.high"] = "cgroup v1 has no memory.high"
        unavailable["events.oom"] = "cgroup v1 has no oom event counter; see under_oom"
        unavailable["events.max"] = "cgroup v1: memory.failcnt stands in for max events"
        out["stat"] = raw
        unavailable["pressure_level"] = (
            "cgroup v1 memory.pressure_level is a notification interface (eventfd through "
            "cgroup.event_control) and cannot be read; pressure comes from the v2 directory"
        )
    for key in ("pgscan", "pgsteal"):
        if key not in out["stat"]:
            unavailable[f"stat.{key}"] = (
                f"{key} is not in this memory.stat (cgroup v1 reports no scan or steal counters)"
                if loc.version == "v1"
                else f"{key} is not in this memory.stat (kernel before 4.13)"
            )
    pressure = read_text(loc.pressure_dir / "memory.pressure") if loc.pressure_dir else None
    out["pressure"] = parse_psi(pressure) if pressure else None
    if out["pressure"] is None:
        unavailable["pressure"] = (
            "no memory.pressure in the process's cgroup v2 directory (no v2 mount, or PSI off)"
        )
    out["unavailable"] = unavailable
    return out


def memory_limits(loc: MemoryLocation) -> list[dict[str, Any]]:
    """The process's memory cgroup and each ancestor with a ``memory.max`` or
    ``memory.high`` (v2), nearest first. v1 hierarchies give the effective limit in
    ``hierarchical_memory_limit`` instead, so only the own level is listed."""
    out: list[dict[str, Any]] = []
    d = loc.dir
    for _ in range(64):
        if loc.version == "v2":
            mx = parse_memory_value(read_text(d / "memory.max"))
            hi = parse_memory_value(read_text(d / "memory.high"))
        else:
            mx = parse_memory_value(read_text(d / "memory.limit_in_bytes"))
            hi = None
        if d == loc.dir or mx is not None or hi is not None:
            try:
                rel = "/" + d.relative_to(loc.root).as_posix() if d != loc.root else "/"
            except ValueError:
                rel = str(d)
            out.append({"path": rel, "max_bytes": mx, "high_bytes": hi})
        if loc.version == "v1" or d == loc.root or d.parent == d or len(out) > MAX_ANCESTORS:
            break
        d = d.parent
    return out[: MAX_ANCESTORS + 1]


# --- freezer --------------------------------------------------------------------


def read_freezer(pid_cgroup: PidCgroups, mounts: CgroupMounts) -> dict[str, Any]:
    """Freezer state of the process's cgroups.

    cgroup v2: ``cgroup.events`` ``frozen`` (1 once every task in the cgroup is
    frozen) and the requested ``cgroup.freeze``. cgroup v1: ``freezer.state``
    (``THAWED``, ``FREEZING``, ``FROZEN``) and ``self_freezing`` / ``parent_freezing``.
    ``frozen`` is True when either says the cgroup is frozen or freezing.
    """
    out: dict[str, Any] = {"frozen": None, "v2": None, "v1": None}
    reasons: list[str] = []
    if mounts.v2 is not None and pid_cgroup.v2_path is not None:
        d, _ = _join(mounts.v2, mounts.v2_root, pid_cgroup.v2_path)
        events = read_text(d / "cgroup.events")
        if events is not None:
            ev = parse_flat_keyed(events)
            out["v2"] = {
                "frozen": bool(ev.get("frozen")) if "frozen" in ev else None,
                "freeze_requested": _int_file(d / "cgroup.freeze") == 1,
                "path": pid_cgroup.v2_path,
            }
        else:
            reasons.append("no v2 cgroup.events (root cgroup, which cannot be frozen)")
    if "freezer" in mounts.v1 and "freezer" in pid_cgroup.v1_paths:
        d, _ = _join(
            mounts.v1["freezer"],
            mounts.v1_roots.get("freezer", "/"),
            pid_cgroup.v1_paths["freezer"],
        )
        state = read_text(d / "freezer.state")
        if state is not None:
            out["v1"] = {
                "state": state.strip(),
                "self_freezing": _int_file(d / "freezer.self_freezing") == 1,
                "parent_freezing": _int_file(d / "freezer.parent_freezing") == 1,
                "path": pid_cgroup.v1_paths["freezer"],
            }
        else:
            reasons.append("no v1 freezer.state (root freezer cgroup, which cannot be frozen)")
    flags = []
    if out["v2"] is not None and out["v2"]["frozen"] is not None:
        flags.append(out["v2"]["frozen"] or out["v2"]["freeze_requested"])
    if out["v1"] is not None:
        flags.append(out["v1"]["state"] in ("FROZEN", "FREEZING"))
    if flags:
        out["frozen"] = any(flags)
    elif reasons:
        # The root cgroups cannot be frozen, so "not frozen" is known here.
        out["frozen"] = False
        out["note"] = "; ".join(reasons)
    else:
        out["unavailable_reason"] = "no cgroup v2 mount and no v1 freezer hierarchy"
    return out
