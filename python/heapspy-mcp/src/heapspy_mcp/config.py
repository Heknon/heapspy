"""Server configuration: command-line flags, environment variables, defaults."""

from __future__ import annotations

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


# --- CPU profiling (py-spy) ------------------------------------------------------
# Kept in one block so it merges cleanly with other additions to this module.

ENV_PY_SPY_BIN = "PY_SPY_BIN"
ENV_CPU_MAX_DURATION = "HEAPSPY_MCP_CPU_MAX_DURATION"
DEFAULT_CPU_MAX_DURATION = 30
CPU_MAX_DURATION_LIMIT = 3600


def resolve_py_spy(flag_value: str | None, env: dict[str, str] | None = None) -> Path | None:
    """Find the py-spy executable.

    Order: ``--py-spy-bin``, then ``$PY_SPY_BIN``, then ``py-spy`` on PATH, then
    ``py-spy`` next to the running interpreter (where ``pip install
    heapspy-mcp[pyspy]`` puts it, even when that directory is not on PATH).
    An explicitly configured value that is not executable is a
    :class:`ConfigError`; ``None`` means py-spy is not available, and the CPU
    tools return ``py_spy_not_found``.
    """
    env = os.environ if env is None else env
    for origin, value in (("--py-spy-bin", flag_value), (ENV_PY_SPY_BIN, env.get(ENV_PY_SPY_BIN))):
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
    found = shutil.which("py-spy")
    if found:
        return Path(found).resolve()
    beside = Path(sys.executable).parent / ("py-spy.exe" if sys.platform == "win32" else "py-spy")
    if beside.is_file() and os.access(beside, os.X_OK):
        return beside.resolve()
    return None


def load_cpu_settings(
    config: Config,
    *,
    py_spy_bin: str | None = None,
    cpu_max_duration: int | None = None,
    env: dict[str, str] | None = None,
) -> Config:
    """Fill the CPU profiling fields of ``config`` from flags and environment."""
    env = dict(os.environ) if env is None else env
    config.py_spy_bin = resolve_py_spy(py_spy_bin, env)
    if cpu_max_duration is None:
        text = env.get(ENV_CPU_MAX_DURATION)
        if text:
            try:
                cpu_max_duration = int(text)
            except ValueError as e:
                raise ConfigError(
                    f"{ENV_CPU_MAX_DURATION}={text!r} is not a whole number of seconds"
                ) from e
    if cpu_max_duration is not None:
        if not 1 <= cpu_max_duration <= CPU_MAX_DURATION_LIMIT:
            raise ConfigError(
                f"the CPU profile duration limit must be 1 to {CPU_MAX_DURATION_LIMIT} seconds"
            )
        config.cpu_max_duration = cpu_max_duration
    return config


# --- end CPU profiling -----------------------------------------------------------


@dataclass
class Config:
    heapspy_bin: Path | None
    snapshot_dir: Path = field(default_factory=default_snapshot_dir)
    allow: list[str] = field(default_factory=list)
    allow_contents: bool = False
    max_rss_bytes: int = DEFAULT_MAX_RSS
    timeout: float = DEFAULT_TIMEOUT
    capture_timeout: float = DEFAULT_CAPTURE_TIMEOUT

    # --- CPU profiling (py-spy); set by load_cpu_settings() above ---
    py_spy_bin: Path | None = None
    cpu_max_duration: int = DEFAULT_CPU_MAX_DURATION
    # --- end CPU profiling ---

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
