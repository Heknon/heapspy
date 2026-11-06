"""Server configuration: command-line flags, environment variables, defaults."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

ENV_BIN = "HEAPSPY_BIN"
ENV_ALLOW = "HEAPSPY_MCP_ALLOW"
ENV_ALLOW_CONTENTS = "HEAPSPY_MCP_ALLOW_CONTENTS"
ENV_MAX_RSS = "HEAPSPY_MCP_MAX_RSS"
ENV_SNAPSHOT_DIR = "HEAPSPY_MCP_SNAPSHOT_DIR"
ENV_TIMEOUT = "HEAPSPY_MCP_TIMEOUT"
ENV_CAPTURE_TIMEOUT = "HEAPSPY_MCP_CAPTURE_TIMEOUT"

GIB = 1024**3
DEFAULT_MAX_RSS = 8 * GIB
DEFAULT_TIMEOUT = 120.0
DEFAULT_CAPTURE_TIMEOUT = 900.0

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b?)?\s*$", re.IGNORECASE)
_SIZE_UNITS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


class ConfigError(Exception):
    """The server cannot start with the given configuration."""


def parse_size(text: str) -> int:
    """Parse a byte count such as ``8589934592``, ``8G``, ``8GiB`` or ``512M``.

    Suffixes are binary (``K`` = 1024).
    """
    m = _SIZE_RE.match(text)
    if not m:
        raise ConfigError(f"not a byte size: {text!r} (examples: 8G, 512MiB, 1073741824)")
    unit = (m.group(2) or "").lower().rstrip("b").rstrip("i")
    if unit not in _SIZE_UNITS:
        raise ConfigError(f"unknown size unit in {text!r}")
    return int(float(m.group(1)) * _SIZE_UNITS[unit])


def parse_bool(text: str | None) -> bool:
    return (text or "").strip().lower() in {"1", "true", "yes", "on"}


def split_allow(text: str | None) -> list[str]:
    """Split an allowlist value on commas; empty entries are dropped."""
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def default_snapshot_dir() -> Path:
    """Per-user cache directory for managed snapshots."""
    home = Path.home()
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
        return base / "heapspy-mcp" / "Cache" / "snapshots"
    if sys.platform == "darwin":
        return home / "Library" / "Caches" / "heapspy-mcp" / "snapshots"
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else home / ".cache"
    return base / "heapspy-mcp" / "snapshots"


def resolve_binary(flag_value: str | None, env: dict[str, str] | None = None) -> Path | None:
    """Find the heapspy executable.

    Order: ``--heapspy-bin``, then ``$HEAPSPY_BIN``, then ``heapspy`` on PATH.
    An explicitly configured value that does not point at an executable is a
    :class:`ConfigError`. ``None`` means nothing was configured and ``heapspy``
    is not on PATH.
    """
    env = os.environ if env is None else env
    for origin, value in (("--heapspy-bin", flag_value), (ENV_BIN, env.get(ENV_BIN))):
        if not value:
            continue
        candidate = Path(value).expanduser()
        if candidate.parent == Path(".") and not candidate.exists():
            found = shutil.which(value)
            if found:
                return Path(found).resolve()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
        raise ConfigError(f"{origin}={value!r} is not an executable file")
    found = shutil.which("heapspy")
    return Path(found).resolve() if found else None


@dataclass
class Config:
    heapspy_bin: Path | None
    snapshot_dir: Path = field(default_factory=default_snapshot_dir)
    allow: list[str] = field(default_factory=list)
    allow_contents: bool = False
    max_rss_bytes: int = DEFAULT_MAX_RSS
    timeout: float = DEFAULT_TIMEOUT
    capture_timeout: float = DEFAULT_CAPTURE_TIMEOUT
    # process diagnostics (heapspy_mcp.system)
    diagnostics: DiagnosticsConfig = field(default_factory=lambda: DiagnosticsConfig())

    @classmethod
    def from_sources(
        cls,
        *,
        heapspy_bin: str | None = None,
        snapshot_dir: str | None = None,
        allow: list[str] | None = None,
        allow_contents: bool = False,
        max_rss: str | None = None,
        timeout: float | None = None,
        capture_timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> Config:
        """Merge flags (given as arguments) over environment variables."""
        env = dict(os.environ) if env is None else env
        allow_list = split_allow(env.get(ENV_ALLOW))
        for entry in allow or []:
            allow_list.extend(split_allow(entry))
        snap_dir = snapshot_dir or env.get(ENV_SNAPSHOT_DIR)
        rss_text = max_rss or env.get(ENV_MAX_RSS)
        return cls(
            heapspy_bin=resolve_binary(heapspy_bin, env),
            snapshot_dir=Path(snap_dir).expanduser() if snap_dir else default_snapshot_dir(),
            allow=allow_list,
            allow_contents=allow_contents or parse_bool(env.get(ENV_ALLOW_CONTENTS)),
            max_rss_bytes=parse_size(rss_text) if rss_text else DEFAULT_MAX_RSS,
            timeout=timeout or _float_env(env, ENV_TIMEOUT, DEFAULT_TIMEOUT),
            capture_timeout=capture_timeout
            or _float_env(env, ENV_CAPTURE_TIMEOUT, DEFAULT_CAPTURE_TIMEOUT),
        )


def _float_env(env: dict[str, str], name: str, default: float) -> float:
    value = env.get(name)
    if not value:
        return default
    try:
        result = float(value)
    except ValueError as e:
        raise ConfigError(f"{name}={value!r} is not a number of seconds") from e
    if result <= 0:
        raise ConfigError(f"{name} must be positive")
    return result


# --- process diagnostics (heapspy_mcp.system) ---------------------------------
# Settings for the process CPU and scheduler tools, kept in one block so it
# merges cleanly with other tool families.

ENV_MAX_WINDOW = "HEAPSPY_MCP_MAX_WINDOW"
ENV_NO_HOST_CONTEXT = "HEAPSPY_MCP_NO_HOST_CONTEXT"
ENV_PROC_ROOT = "HEAPSPY_MCP_PROC_ROOT"
ENV_CGROUP_ROOT = "HEAPSPY_MCP_CGROUP_ROOT"
DEFAULT_WINDOW = 2.0
DEFAULT_MAX_WINDOW = 10.0


@dataclass
class DiagnosticsConfig:
    """``max_window_s`` caps every measurement window. ``host_context=False`` leaves
    host-wide figures (load, steal, host PSI) out of the process tools. ``proc_root``
    and ``cgroup_root`` point at a host ``/proc`` or cgroup v2 mount when the server
    sees them somewhere other than the usual place."""

    max_window_s: float = DEFAULT_MAX_WINDOW
    host_context: bool = True
    proc_root: Path = Path("/proc")
    cgroup_root: Path | None = None

    @classmethod
    def from_sources(
        cls,
        *,
        max_window: float | None = None,
        no_host_context: bool = False,
        proc_root: str | None = None,
        cgroup_root: str | None = None,
        env: dict[str, str] | None = None,
    ) -> DiagnosticsConfig:
        env = dict(os.environ) if env is None else env
        proc = proc_root or env.get(ENV_PROC_ROOT)
        cgroup = cgroup_root or env.get(ENV_CGROUP_ROOT)
        for name, value in (("--proc-root", proc), ("--cgroup-root", cgroup)):
            if value and not Path(value).is_dir():
                raise ConfigError(f"{name}={value!r} is not a directory")
        if max_window is not None and max_window <= 0:
            raise ConfigError("--max-window must be positive")
        return cls(
            max_window_s=max_window or _float_env(env, ENV_MAX_WINDOW, DEFAULT_MAX_WINDOW),
            host_context=not (no_host_context or parse_bool(env.get(ENV_NO_HOST_CONTEXT))),
            proc_root=Path(proc) if proc else Path("/proc"),
            cgroup_root=Path(cgroup) if cgroup else None,
        )


def add_diagnostics_arguments(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group("process diagnostics")
    g.add_argument(
        "--max-window",
        type=float,
        metavar="SECONDS",
        help=f"cap on measurement windows (also ${ENV_MAX_WINDOW}; default {DEFAULT_MAX_WINDOW:g})",
    )
    g.add_argument(
        "--no-host-context",
        action="store_true",
        help=f"leave host-wide load, steal and PSI out of the process tools "
        f"(also ${ENV_NO_HOST_CONTEXT}=1)",
    )
    g.add_argument("--proc-root", metavar="DIR", help=f"procfs to read (also ${ENV_PROC_ROOT})")
    g.add_argument(
        "--cgroup-root",
        metavar="DIR",
        help=f"cgroup v2 mount to read instead of the one in /proc/self/mountinfo "
        f"(also ${ENV_CGROUP_ROOT})",
    )


def diagnostics_from_args(args: argparse.Namespace) -> DiagnosticsConfig:
    return DiagnosticsConfig.from_sources(
        max_window=args.max_window,
        no_host_context=args.no_host_context,
        proc_root=args.proc_root,
        cgroup_root=args.cgroup_root,
    )
