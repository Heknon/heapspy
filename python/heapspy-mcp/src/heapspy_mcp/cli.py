"""Thin, typed wrapper around the ``heapspy`` command-line tool.

Runs the binary without a shell and with a timeout, parses the ``--json``
document (schema version 1, see ``docs/json-schema.md``) and turns every kind
of failure into a :class:`HeapspyError` with a stable ``code``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

# Codes the CLI itself puts in its error document. The dump codes
# (no_such_process to unsupported) and invalid_allocations were added within
# schema version 1. A code not listed here is reported as ``internal``, with
# the original in ``cli_code``, as docs/json-schema.md asks.
CLI_ERROR_CODES = frozenset(
    {
        "unimplemented",
        "invalid_argument",
        "not_found",
        "invalid_snapshot",
        "invalid_allocations",
        "io",
        "permission_denied",
        "no_such_process",
        "not_python",
        "unsupported_python",
        "invalid_image",
        "truncated_image",
        "unsupported",
        "internal",
    }
)

_HINTS = {
    "binary_not_found": (
        "Install heapspy, or point the server at it with --heapspy-bin or the HEAPSPY_BIN "
        "environment variable."
    ),
    "unimplemented": "This heapspy build does not implement the command yet.",
    "permission_denied": (
        "Dumping another process needs CAP_SYS_PTRACE (or a permissive "
        "kernel.yama.ptrace_scope) on Linux, or SeDebugPrivilege on Windows. "
        "The user has to grant this; the agent cannot."
    ),
    "invalid_snapshot": "The file is not a heapspy snapshot, or it is truncated or corrupt.",
    "timeout": "The command took longer than the configured timeout (--timeout).",
    "schema_mismatch": "The heapspy binary and heapspy-mcp disagree on the JSON schema version.",
    "not_found": "Check the address or type name against heap_summary or type_detail output.",
    "no_such_process": (
        "No process has that PID, or it exited before it could be stopped. Look it up again "
        "with list_python_processes."
    ),
    "not_python": (
        "No CPython runtime was found in the target (no module exports _PyRuntime). Check the "
        "PID with list_python_processes: a shell, launcher or supervisor may be the parent of "
        "the real Python process."
    ),
    "unsupported_python": (
        "heapspy reads CPython 3.12 to 3.14 release builds. Free-threaded and debug builds, "
        "and other versions, are refused."
    ),
    "invalid_image": (
        "The core or minidump is not one heapspy reads: it must be an ELF core or a "
        "full-memory minidump of a 64-bit little-endian x86_64 or aarch64 process, and hold "
        "the memory the Python runtime points to."
    ),
    "truncated_image": (
        "The image file ends before data its own headers describe (cut short by a core size "
        "limit such as ulimit -c, or by a full disk). Take the core or minidump again."
    ),
    "unsupported": (
        "heapspy cannot do this here: e.g. dump itself, dump a live process on a platform "
        "without a live backend, or stop a target that keeps creating threads."
    ),
    "invalid_allocations": (
        "The allocations file is not a heapspy allocation profile (.hpya), or it is truncated "
        "or corrupt."
    ),
    "io": (
        "A file could not be read or written: check that the path exists and is readable, "
        "and that the snapshot directory has free space."
    ),
    "allocations_unsupported": (
        "Allocation profiles need a heapspy with the allocation join (analyze and query "
        "--allocations, flamegraph --allocations). Upgrade heapspy, or leave out the "
        "allocations argument."
    ),
    "internal": "A bug in heapspy. The message and stderr say where it failed.",
}

_STDERR_LIMIT = 2000

_DUMP_STATS_RE = re.compile(
    r"wrote (?P<path>.+?): (?P<objects>\d+) objects, (?P<edges>\d+) edges, "
    r"(?P<roots>\d+) roots, (?P<bytes>\d+) bytes(?P<truncated> \(truncated\))?"
)


class HeapspyError(Exception):
    """A heapspy invocation failed.

    ``code`` is one of the CLI's error codes (see :data:`CLI_ERROR_CODES`) or
    one added by this wrapper: ``binary_not_found``, ``timeout``,
    ``usage_error`` (exit status 2), ``bad_output`` (stdout is not JSON),
    ``schema_mismatch``, ``unexpected_kind``, ``cli_failed`` (non-zero exit
    without an error document), ``allocations_unsupported`` (a heapspy
    without ``--allocations``). ``cli_code`` holds a CLI code this server does
    not know; ``code`` is then ``internal``.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_status: int | None = None,
        stderr: str | None = None,
        cli_code: str | None = None,
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.exit_status = exit_status
        self.stderr = _tail(stderr) if stderr else None
        self.cli_code = cli_code

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.cli_code is not None:
            out["cli_code"] = self.cli_code
        if self.exit_status is not None:
            out["exit_status"] = self.exit_status
        if self.stderr:
            out["stderr"] = self.stderr
        hint = _HINTS.get(self.code)
        if hint:
            out["hint"] = hint
        return out


def _tail(text: str, limit: int = _STDERR_LIMIT) -> str:
    text = text.strip()
    return text if len(text) <= limit else "..." + text[-limit:]


# clap's message when `dump` does not know `--json` (heapspy before dump --json).
_UNKNOWN_JSON_FLAG_RE = re.compile(r"unexpected argument '--json'")
# clap's messages from a heapspy without the allocation join.
_ALLOCATIONS_UNKNOWN_RE = re.compile(
    r"unexpected argument '--allocations'|unrecognized subcommand 'flamegraph'"
)


@dataclass(frozen=True)
class DumpResult:
    """What ``heapspy dump`` reported.

    ``report`` is ``"json"`` when the fields come from the ``kind: "dump"``
    document, and ``"stderr_line"`` when they were parsed from the
    ``wrote ...`` line (a heapspy without ``dump --json``). The fields that
    line does not carry are then ``None``.
    """

    path: Path
    objects: int | None
    edges: int | None
    roots: int | None
    bytes_written: int | None
    truncated: bool | None
    stderr: str
    report: str = "stderr_line"
    types: int | None = None
    read_errors: int | None = None
    missing_bytes: int | None = None
    pause_ms: float | None = None
    python_version: str | None = None
    notes: tuple[dict[str, Any], ...] = ()


class HeapspyCLI:
    """Runs ``heapspy`` subcommands and returns parsed JSON documents."""

    def __init__(self, binary: Path | None, *, timeout: float, capture_timeout: float) -> None:
        self.binary = Path(os.path.abspath(binary)) if binary is not None else None
        self.timeout = timeout
        self.capture_timeout = capture_timeout
        # None until a dump shows whether this heapspy has `dump --json`.
        self.dump_json: bool | None = None

    # -- analysis commands (JSON) -------------------------------------------------

    def analyze(
        self, snapshot: Path, *, top: int, allocations: Path | None = None
    ) -> dict[str, Any]:
        args = ["analyze", str(snapshot), "--json", f"--top={top}"]
        if allocations is None:
            return self.run_json(args, "analyze")
        args.append(f"--allocations={allocations}")
        return _require_join(self.run_json(args, "analyze"))

    def query_type(
        self, snapshot: Path, type_name: str, *, allocations: Path | None = None
    ) -> dict[str, Any]:
        # `--type=VALUE` so a value starting with '-' is not read as a flag.
        args = ["query", str(snapshot), f"--type={type_name}", "--json"]
        if allocations is None:
            return self.run_json(args, "type_query")
        args.append(f"--allocations={allocations}")
        return _require_join(self.run_json(args, "type_query"))

    def retaining_path(self, snapshot: Path, address: str) -> dict[str, Any]:
        return self.run_json(
            ["query", str(snapshot), f"--retaining-path={address}", "--json"], "retaining_path"
        )

    def diff(self, before: Path, after: Path) -> dict[str, Any]:
        return self.run_json(["diff", str(before), str(after), "--json"], "diff")

    # -- dump -----------------------------------------------------------------------

    def dump(
        self,
        *,
        output: Path,
        pid: int | None = None,
        core: Path | None = None,
        minidump: Path | None = None,
        capture_contents: bool = False,
        max_str: int | None = None,
    ) -> DumpResult:
        args = ["dump"]
        if pid is not None:
            args.append(f"--pid={pid}")
        elif core is not None:
            args.append(f"--core={core}")
        elif minidump is not None:
            args.append(f"--minidump={minidump}")
        else:
            raise ValueError("dump needs a pid, core or minidump")
        args.append(f"--output={output}")
        if capture_contents:
            args.append("--capture-contents")
            if max_str is not None:
                args.append(f"--max-str={max_str}")
        if self.dump_json is not False:
            proc = self._run([*args, "--json"], timeout=self.capture_timeout)
            if not (proc.returncode == 2 and _rejects_json_flag(proc.stderr)):
                if proc.returncode != 0:
                    raise self._failure(proc, json_expected=True)
                result = _dump_from_json(output, proc)
                if result is None:
                    # Exit 0 without a dump document: fall back to the stderr line.
                    return _dump_from_stderr(output, proc)
                self.dump_json = True
                return result
            # This heapspy has no `dump --json`. It rejected the flag while
            # parsing arguments, before it touched the target, so the same dump
            # is run again without it.
            self.dump_json = False
        proc = self._run(args, timeout=self.capture_timeout)
        if proc.returncode != 0:
            raise self._failure(proc, json_expected=False)
        return _dump_from_stderr(output, proc)

    # -- allocation profile without a snapshot -------------------------------------

    def allocation_folded(self, profile: Path) -> str:
        """``heapspy flamegraph --allocations PROFILE --folded`` on stdout.

        heapspy has no JSON report for a profile on its own; the folded
        stacks (``outer;...;inner bytes``, weighted by estimated bytes) are
        the only profile-only output. ``--min-bytes=0`` turns off the
        ``[other]`` folding so every stack is its own line.
        """
        proc = self._run(
            ["flamegraph", f"--allocations={profile}", "--folded", "--min-bytes=0"],
            timeout=self.timeout,
        )
        if proc.returncode != 0:
            raise self._failure(proc, json_expected=False)
        return proc.stdout

    # -- plumbing -----------------------------------------------------------------

    def run_json(self, args: list[str], expected_kind: str) -> dict[str, Any]:
        proc = self._run(args, timeout=self.timeout)
        if proc.returncode != 0:
            raise self._failure(proc, json_expected=True)
        doc = _parse_document(proc.stdout, proc.stderr, proc.returncode)
        kind = doc.get("kind")
        if kind == "error":
            # An error document with exit status 0 is a CLI bug, but report it as what it says.
            raise _error_from_document(doc, proc.returncode, proc.stderr)
        if kind != expected_kind:
            raise HeapspyError(
                "unexpected_kind",
                f"expected a {expected_kind!r} document, got kind={kind!r}",
                exit_status=proc.returncode,
            )
        return doc

    def _run(self, args: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        if self.binary is None:
            raise HeapspyError(
                "binary_not_found",
                "the heapspy executable was not found (no --heapspy-bin, no HEAPSPY_BIN, "
                "and no 'heapspy' on PATH)",
            )
        try:
            return subprocess.run(
                [str(self.binary), *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            stderr = e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, bytes) else None
            raise HeapspyError(
                "timeout", f"heapspy {args[0]} did not finish within {timeout:g} s", stderr=stderr
            ) from e
        except FileNotFoundError as e:
            raise HeapspyError("binary_not_found", f"cannot run {self.binary}: {e}") from e
        except PermissionError as e:
            raise HeapspyError("binary_not_found", f"cannot execute {self.binary}: {e}") from e

    def _failure(
        self, proc: subprocess.CompletedProcess[str], *, json_expected: bool
    ) -> HeapspyError:
        if proc.returncode == 2 and _ALLOCATIONS_UNKNOWN_RE.search(proc.stderr or ""):
            return HeapspyError(
                "allocations_unsupported",
                "this heapspy does not read allocation profiles (no --allocations or no "
                "flamegraph command)",
                exit_status=2,
                stderr=proc.stderr,
            )
        if proc.returncode == 2:
            return HeapspyError(
                "usage_error",
                "heapspy rejected the command line (this heapspy-mcp may not match the "
                "installed heapspy version)",
                exit_status=2,
                stderr=proc.stderr,
            )
        if json_expected and proc.stdout.strip():
            try:
                doc = _parse_document(proc.stdout, proc.stderr, proc.returncode)
            except HeapspyError as e:
                return e
            if doc.get("kind") == "error":
                return _error_from_document(doc, proc.returncode, proc.stderr)
        message = _tail(proc.stderr or "", 500) or f"heapspy exited with status {proc.returncode}"
        return HeapspyError("cli_failed", message, exit_status=proc.returncode, stderr=proc.stderr)


def _rejects_json_flag(stderr: str | None) -> bool:
    """Whether a usage error says that ``--json`` is unknown.

    A heapspy that has ``dump --json`` also prints ``--json`` in the
    ``Usage:`` line of its other usage errors, so that line does not count.
    """
    text = stderr or ""
    if _UNKNOWN_JSON_FLAG_RE.search(text):
        return True
    return any(
        "--json" in line and not line.lstrip().lower().startswith("usage:")
        for line in text.splitlines()
    )


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _dump_from_json(output: Path, proc: subprocess.CompletedProcess[str]) -> DumpResult | None:
    """The ``kind: "dump"`` document on stdout, or ``None`` if there is none."""
    if not (proc.stdout or "").strip():
        return None
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return None
    if doc.get("kind") == "error":
        raise _error_from_document(doc, proc.returncode, proc.stderr)
    if doc.get("kind") != "dump":
        return None
    version = doc.get("schema_version")
    if version != SCHEMA_VERSION:
        raise HeapspyError(
            "schema_mismatch",
            f"heapspy printed schema_version={version!r}; this server understands "
            f"version {SCHEMA_VERSION}",
            exit_status=proc.returncode,
        )
    image = doc.get("image") if isinstance(doc.get("image"), dict) else {}
    pause = doc.get("pause_ms")
    truncated = doc.get("truncated")
    python_version = doc.get("python_version")
    return DumpResult(
        path=output,
        objects=_int(doc.get("objects")),
        edges=_int(doc.get("edges")),
        roots=_int(doc.get("roots")),
        bytes_written=_int(doc.get("bytes_written")),
        truncated=truncated if isinstance(truncated, bool) else None,
        stderr=_tail(proc.stderr or ""),
        report="json",
        types=_int(doc.get("types")),
        read_errors=_int(doc.get("read_errors")),
        missing_bytes=_int(image.get("missing_bytes")),
        pause_ms=float(pause) if isinstance(pause, (int, float)) else None,
        python_version=python_version if isinstance(python_version, str) else None,
        notes=tuple(n for n in doc.get("notes") or [] if isinstance(n, dict)),
    )


def _dump_from_stderr(output: Path, proc: subprocess.CompletedProcess[str]) -> DumpResult:
    stats = _DUMP_STATS_RE.search(proc.stderr or "")

    def num(name: str) -> int | None:
        return int(stats.group(name)) if stats else None

    return DumpResult(
        path=output,
        objects=num("objects"),
        edges=num("edges"),
        roots=num("roots"),
        bytes_written=num("bytes"),
        truncated=bool(stats.group("truncated")) if stats else None,
        stderr=_tail(proc.stderr or ""),
    )


def _require_join(doc: dict[str, Any]) -> dict[str, Any]:
    """Refuse a report from a heapspy that takes ``--allocations`` but has no join.

    Such a heapspy (``feature/alloc-format``, PR #16, without PR #19) checks the
    profile against the snapshot, then reports ``allocations`` and every
    ``allocated_at`` as null with the note ``allocations_not_joined``.
    """
    notes = doc.get("notes")
    if isinstance(notes, list) and any(
        isinstance(n, dict) and n.get("code") == "allocations_not_joined" for n in notes
    ):
        raise HeapspyError(
            "allocations_unsupported",
            "this heapspy checks allocation profiles but does not join them with snapshots "
            "(note allocations_not_joined)",
            exit_status=0,
        )
    return doc


def _parse_document(stdout: str, stderr: str | None, status: int) -> dict[str, Any]:
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise HeapspyError(
            "bad_output",
            f"heapspy printed something that is not JSON ({e.msg} at line {e.lineno})",
            exit_status=status,
            stderr=stderr,
        ) from e
    if not isinstance(doc, dict):
        raise HeapspyError("bad_output", "heapspy JSON output is not an object", exit_status=status)
    version = doc.get("schema_version")
    if version != SCHEMA_VERSION:
        raise HeapspyError(
            "schema_mismatch",
            f"heapspy printed schema_version={version!r}; this server understands "
            f"version {SCHEMA_VERSION}",
            exit_status=status,
        )
    return doc


def _error_from_document(doc: dict[str, Any], status: int, stderr: str | None) -> HeapspyError:
    err = doc.get("error") if isinstance(doc.get("error"), dict) else {}
    code = err.get("code") if isinstance(err.get("code"), str) else "internal"
    message = err.get("message") if isinstance(err.get("message"), str) else "unknown error"
    if code not in CLI_ERROR_CODES:
        # Codes may be added within schema v1, and the schema says to treat an
        # unknown one like `internal`. The original is kept in cli_code.
        return HeapspyError("internal", message, exit_status=status, stderr=stderr, cli_code=code)
    return HeapspyError(code, message, exit_status=status, stderr=stderr)
