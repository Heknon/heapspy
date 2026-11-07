"""``capture_snapshot``: the one tool that touches a process, and its gates."""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any

import psutil

from . import summarize as S
from .cli import HeapspyCLI, HeapspyError
from .config import MAX_STR_LIMIT, Config
from .processes import describe_cmdline, matches_allowlist
from .snapshots import SnapshotStore
from .summarize import human_bytes

log = logging.getLogger("heapspy_mcp.capture")


class CaptureRefused(Exception):
    """A safety gate refused the capture. ``reason`` is a stable code."""

    def __init__(self, reason: str, message: str, **details: Any) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason = reason
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": "capture_refused",
            "reason": self.reason,
            "message": self.message,
            **self.details,
        }


def _check_file(path_text: str, what: str) -> Path:
    path = Path(path_text).expanduser()
    if not path.is_file():
        raise CaptureRefused("invalid_argument", f"{what} {path_text!r} is not a file")
    return Path(os.path.abspath(path))


def _check_process(config: Config, pid: int) -> dict[str, Any]:
    if pid <= 0:
        raise CaptureRefused("invalid_argument", f"pid must be positive, got {pid}")
    if pid == os.getpid():
        raise CaptureRefused("invalid_argument", "refusing to dump the heapspy-mcp server itself")
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
            try:
                rss = proc.memory_info().rss
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                rss = None
    except psutil.NoSuchProcess as e:
        raise CaptureRefused("no_such_process", f"no process with pid {pid}") from e
    except psutil.AccessDenied as e:
        raise CaptureRefused(
            "process_inaccessible", f"cannot inspect pid {pid} to check the allowlist"
        ) from e

    if not config.allow:
        raise CaptureRefused(
            "capture_disabled",
            "live capture is disabled: the server has an empty process allowlist. The user "
            "must start heapspy-mcp with --allow PATTERN (or HEAPSPY_MCP_ALLOW) to enable it.",
            pid=pid,
            name=name,
        )
    entry = matches_allowlist(config.allow, pid=pid, name=name, exe=exe, cmdline=cmdline)
    if entry is None:
        raise CaptureRefused(
            "not_allowlisted",
            f"pid {pid} ({name}) does not match any entry of the server's process allowlist. "
            "Only the user can change the allowlist (--allow / HEAPSPY_MCP_ALLOW).",
            pid=pid,
            name=name,
        )
    if rss is None:
        raise CaptureRefused(
            "rss_unknown", f"cannot read the RSS of pid {pid}, so the size guard cannot be checked"
        )
    if rss > config.max_rss_bytes:
        raise CaptureRefused(
            "rss_limit",
            f"pid {pid} has RSS {human_bytes(rss)}, over the server's limit of "
            f"{human_bytes(config.max_rss_bytes)}. Dumping pauses the target and writes an image "
            "about that size. The user can raise the limit with --max-rss.",
            pid=pid,
            rss_bytes=rss,
            max_rss_bytes=config.max_rss_bytes,
        )
    return {
        "pid": pid,
        "name": name,
        "exe": exe,
        "cmdline": describe_cmdline(cmdline),
        "rss_bytes": rss,
        "allowlist_entry": entry,
    }


def capture_snapshot(
    config: Config,
    cli: HeapspyCLI,
    store: SnapshotStore,
    *,
    pid: int | None,
    core_path: str | None,
    minidump_path: str | None,
    confirm: bool,
    capture_contents: bool,
    max_str: int | None,
) -> dict[str, Any]:
    if confirm is not True:
        raise CaptureRefused(
            "confirmation_required",
            "capture_snapshot needs confirm=true. Ask the user first: a live dump pauses the "
            "target process and writes a memory image to disk.",
        )
    given = [x for x in (pid, core_path, minidump_path) if x is not None]
    if len(given) != 1:
        raise CaptureRefused(
            "invalid_argument", "give exactly one of pid, core_path or minidump_path"
        )
    if max_str is not None and not capture_contents:
        raise CaptureRefused("invalid_argument", "max_str only applies with capture_contents=true")
    if max_str is not None and not 1 <= max_str <= MAX_STR_LIMIT:
        raise CaptureRefused("invalid_argument", f"max_str must be between 1 and {MAX_STR_LIMIT}")
    if capture_contents and max_str is None:
        max_str = config.max_str

    target: dict[str, Any]
    core = minidump = None
    if pid is not None:
        target = {"kind": "pid", **_check_process(config, pid)}
    elif core_path is not None:
        core = _check_file(core_path, "core_path")
        target = {"kind": "core", "path": str(core)}
    else:
        assert minidump_path is not None
        minidump = _check_file(minidump_path, "minidump_path")
        target = {"kind": "minidump", "path": str(minidump)}

    handle, out = store.new_handle()
    log.warning(
        "capture start: handle=%s target=%s contents=%s max_str=%s output=%s",
        handle,
        {k: v for k, v in target.items() if k != "cmdline"},
        capture_contents,
        max_str,
        out,
    )
    if capture_contents:
        log.warning("capture %s records string and bytes CONTENTS (--capture-contents)", handle)
    # heapspy writes the snapshot through a temporary file next to its output
    # (.tmpXXXXXX) and renames it into place. If it is killed, by the capture
    # timeout for example, that file stays behind, and it can be as large as
    # the target's heap. So heapspy writes into a private staging directory,
    # which is removed on every path; only a finished snapshot is moved out.
    stage = out.parent / f".{handle}.partial"
    stage.mkdir(mode=0o700)
    staged = stage / out.name
    try:
        try:
            result = cli.dump(
                output=staged,
                pid=pid,
                core=core,
                minidump=minidump,
                capture_contents=capture_contents,
                max_str=max_str,
            )
        except Exception as e:
            log.warning("capture failed: handle=%s error=%s", handle, e)
            raise
        if not staged.is_file():
            log.warning("capture failed: handle=%s error=no snapshot file written", handle)
            raise HeapspyError(
                "cli_failed",
                f"heapspy dump exited 0 but did not write {staged}",
                stderr=result.stderr,
            )
        os.replace(staged, out)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    size = out.stat().st_size
    log.warning(
        "capture done: handle=%s file=%s size=%s report=%s pause_ms=%s",
        handle,
        out,
        size,
        result.report,
        result.pause_ms,
    )
    stats: dict[str, Any] = {
        "objects": result.objects,
        "edges": result.edges,
        "types": result.types,
        "roots": result.roots,
        "file_bytes": size,
        "file_human": human_bytes(size),
        "truncated": result.truncated,
        "missing_bytes": result.missing_bytes,
        "read_errors": result.read_errors,
        "pause_ms": result.pause_ms,
    }
    out_doc: dict[str, Any] = {
        "snapshot": handle,
        "path": str(out),
        "target": target,
        "python_version": result.python_version,
        "contents_captured": capture_contents,
        "max_str": max_str if capture_contents else None,
        "stats": stats,
        "notes": S.notes(list(result.notes)),
        # "json": the dump report; "stderr_line": an older heapspy without
        # `dump --json`, so types, read_errors, missing_bytes, pause_ms and
        # python_version are null.
        "report": result.report,
        "next_step": f"Call heap_summary(snapshot={handle!r}) to see the top retainers.",
    }
    if result.truncated:
        out_doc["warning"] = (
            "The snapshot is marked truncated (the walk did not finish, or the image is "
            "incomplete). Sizes and counts from it are lower bounds."
        )
    return out_doc
