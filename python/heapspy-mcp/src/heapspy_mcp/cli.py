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

# Codes the CLI itself puts in its error document.
CLI_ERROR_CODES = frozenset(
    {
        "unimplemented",
        "invalid_argument",
        "not_found",
        "invalid_snapshot",
        "io",
        "permission_denied",
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
    without an error document).
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_status: int | None = None,
        stderr: str | None = None,
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.exit_status = exit_status
        self.stderr = _tail(stderr) if stderr else None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
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


@dataclass(frozen=True)
class DumpResult:
    path: Path
    objects: int | None
    edges: int | None
    roots: int | None
    bytes_written: int | None
    truncated: bool | None
    stderr: str


class HeapspyCLI:
    """Runs ``heapspy`` subcommands and returns parsed JSON documents."""

    def __init__(self, binary: Path | None, *, timeout: float, capture_timeout: float) -> None:
        self.binary = Path(os.path.abspath(binary)) if binary is not None else None
        self.timeout = timeout
        self.capture_timeout = capture_timeout

    # -- analysis commands (JSON) -------------------------------------------------

    def analyze(self, snapshot: Path, *, top: int) -> dict[str, Any]:
        return self.run_json(["analyze", str(snapshot), "--json", f"--top={top}"], "analyze")

    def query_type(self, snapshot: Path, type_name: str) -> dict[str, Any]:
        # `--type=VALUE` so a value starting with '-' is not read as a flag.
        return self.run_json(
            ["query", str(snapshot), f"--type={type_name}", "--json"], "type_query"
        )

    def retaining_path(self, snapshot: Path, address: str) -> dict[str, Any]:
        return self.run_json(
            ["query", str(snapshot), f"--retaining-path={address}", "--json"], "retaining_path"
        )

    def diff(self, before: Path, after: Path) -> dict[str, Any]:
        return self.run_json(["diff", str(before), str(after), "--json"], "diff")

    # -- dump (text output) -------------------------------------------------------

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
        proc = self._run(args, timeout=self.capture_timeout)
        if proc.returncode != 0:
            raise self._failure(proc, json_expected=False)
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
    # Codes outside CLI_ERROR_CODES may be added within schema v1; they pass through.
    return HeapspyError(code, message, exit_status=status, stderr=stderr)
