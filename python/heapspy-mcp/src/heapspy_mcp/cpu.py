"""CPU tools backed by py-spy.

``register(server, config)`` adds the CPU tools to the server.

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
from collections.abc import Callable
from typing import Any, TypeVar

import psutil
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .config import Config
from .processes import describe_cmdline, matches_allowlist
from .pyspy import PySpy, PySpyError

log = logging.getLogger("heapspy_mcp.cpu")

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


# -- registration ------------------------------------------------------------------


def register(server: MCPServer, config: Config) -> None:
    """Add the CPU tools to ``server``. Each tool calls :func:`check_target` first."""
