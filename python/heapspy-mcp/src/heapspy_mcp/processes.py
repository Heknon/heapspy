"""Find Python processes on this machine (read-only)."""

from __future__ import annotations

import os
import re
import sys
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import psutil

MAX_CMDLINE = 200
MAX_PROCESSES = 200

# python, python3, python3.12, python3.13t, python3.12d, pythonw.exe, python312.exe
_EXE_RE = re.compile(r"^python(?:w)?(?P<ver>\d(?:\.?\d+)?)?[dmt]*(?:\.exe)?$", re.IGNORECASE)
# libpython3.12.so.1.0, libpython3.13t.so, python312.dll, python3.dll is the stable ABI shim
_LIB_RE = re.compile(
    r"(?:^|[/\\])(?:lib)?python(?P<major>\d)\.?(?P<minor>\d{1,2})[dmt]*\.(?:so|dll|dylib)",
    re.IGNORECASE,
)


def version_from_exe(name: str | None) -> str | None:
    """``python3.12`` -> ``3.12``; ``python312.exe`` -> ``3.12``; ``python3`` -> None."""
    if not name:
        return None
    m = _EXE_RE.match(Path(name).name)
    if not m or not m.group("ver"):
        return None
    ver = m.group("ver")
    if "." in ver:
        return ver
    if len(ver) >= 3:
        return f"{ver[0]}.{ver[1:]}"
    return None


def version_from_maps_text(text: str) -> str | None:
    m = _LIB_RE.search(text)
    return f"{m.group('major')}.{m.group('minor')}" if m else None


def _version_from_mappings(proc: psutil.Process) -> str | None:
    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{proc.pid}/maps", encoding="utf-8", errors="replace") as f:
                return version_from_maps_text(f.read())
        except OSError:
            return None
    if sys.platform == "win32":
        try:
            for mapping in proc.memory_maps(grouped=True):
                ver = version_from_maps_text(mapping.path)
                if ver:
                    return ver
        except (psutil.Error, OSError):
            return None
    return None


def _looks_like_python(name: str | None, exe: str | None) -> bool:
    for candidate in (name, Path(exe).name if exe else None):
        if candidate and _EXE_RE.match(candidate):
            return True
    return False


def describe_cmdline(cmdline: list[str] | None) -> str:
    text = " ".join(cmdline or [])
    return text if len(text) <= MAX_CMDLINE else text[: MAX_CMDLINE - 3] + "..."


def matches_allowlist(
    patterns: list[str], *, pid: int, name: str | None, exe: str | None, cmdline: list[str] | None
) -> str | None:
    """The first allowlist entry that admits this process, or None.

    An entry is either ``pid:N`` / ``N`` (exact PID) or a glob pattern
    (``fnmatch``, case-sensitive) tried against the process name, the
    executable's file name, and the full command line joined by spaces.
    """
    targets = [t for t in (name, Path(exe).name if exe else None, " ".join(cmdline or [])) if t]
    for pattern in patterns:
        spec = pattern.removeprefix("pid:")
        if spec.isdigit():
            if int(spec) == pid:
                return pattern
            continue
        if any(fnmatchcase(t, pattern) for t in targets):
            return pattern
    return None


def list_python_processes(
    name_filter: str | None, *, limit: int, allow: list[str], measure_s: float = 0.0
) -> dict[str, Any]:
    me = os.getpid()
    found: list[dict[str, Any]] = []
    inaccessible = 0
    needle = (name_filter or "").lower()
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "memory_info", "username"]):
        info = proc.info
        name, exe, cmdline = info.get("name"), info.get("exe"), info.get("cmdline")
        version = version_from_exe(exe) or version_from_exe(name)
        source = "exe_name" if version else None
        by_name = _looks_like_python(name, exe)
        if not version:
            mapped = _version_from_mappings(proc)
            if mapped:
                version, source = mapped, "libpython_mapping"
        if not (by_name or version):
            continue
        cmd_text = " ".join(cmdline or [])
        if needle and needle not in (name or "").lower() and needle not in cmd_text.lower():
            continue
        mem = info.get("memory_info")
        if mem is None and cmdline is None:
            inaccessible += 1
        rss = getattr(mem, "rss", None)
        found.append(
            {
                "pid": info["pid"],
                "name": name,
                "exe": exe,
                "cmdline": describe_cmdline(cmdline),
                "rss_bytes": rss,
                "python_version": version,
                "version_source": source,
                "username": info.get("username"),
                "is_this_server": info["pid"] == me,
                "capture_allowed": matches_allowlist(
                    allow, pid=info["pid"], name=name, exe=exe, cmdline=cmdline
                )
                is not None,
            }
        )
    found.sort(key=lambda p: p["rss_bytes"] or 0, reverse=True)
    from .system.listing import annotate  # threads, threads_by_state, cpu_percent_on_cpu

    measured = annotate(found[:limit], measure_s)
    return {
        **measured,
        "processes": found[:limit],
        "total_found": len(found),
        "partially_inaccessible": inaccessible,
        "capture_allowlist_configured": bool(allow),
    }
