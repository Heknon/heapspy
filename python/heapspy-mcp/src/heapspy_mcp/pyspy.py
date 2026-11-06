"""Thin, typed wrapper around ``py-spy``, plus parsers for its output.

Runs the binary without a shell and with a timeout, kills it when the
timeout expires, and turns every kind of failure into a :class:`PySpyError`
with a stable ``code``. Parsers cover ``py-spy dump --json`` and the folded
stacks that ``py-spy record --format raw`` writes.

``--locals`` is never passed: local variable values can hold credentials and
user data, the same reason heapspy does not record string contents by default.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_STDERR_LIMIT = 2000

_HINTS = {
    "py_spy_not_found": (
        "Install py-spy (pip install 'heapspy-mcp[pyspy]' or pip install py-spy), or point the "
        "server at it with --py-spy-bin or the PY_SPY_BIN environment variable."
    ),
    "permission_denied": (
        "py-spy reads the target's memory through ptrace. On Linux, run the server as the "
        "target's user with kernel.yama.ptrace_scope=0 (sysctl kernel.yama.ptrace_scope=0), "
        "or give py-spy CAP_SYS_PTRACE (sudo setcap cap_sys_ptrace+ep $(which py-spy)), or run "
        "it as root. In Docker start the container with --cap-add SYS_PTRACE; in Kubernetes "
        "add SYS_PTRACE to securityContext.capabilities.add. On macOS py-spy needs root. The "
        "user has to grant this; the agent cannot."
    ),
    "not_python": (
        "py-spy did not find a CPython interpreter in that process. Check the PID with "
        "list_python_processes; a launcher or shell wrapper may be the parent of the real "
        "Python process."
    ),
    "no_such_process": "The process exited, or the PID is wrong.",
    "timeout": "py-spy did not finish in time and was killed. Try a shorter duration.",
}

# (substring of stderr, code); first match wins. Checked case-insensitively.
_STDERR_CODES: tuple[tuple[str, str], ...] = (
    ("permission denied", "permission_denied"),
    ("operation not permitted", "permission_denied"),
    ("os error 13", "permission_denied"),
    ("os error 1)", "permission_denied"),
    ("failed to get process executable name", "no_such_process"),
    ("no such process", "no_such_process"),
    ("os error 3)", "no_such_process"),
    ("failed to find python version", "not_python"),
    ("failed to find a python interpreter", "not_python"),
    ("couldn't find python", "not_python"),
)

_RECORD_STATS_RE = re.compile(r"Samples: (?P<samples>\d+) Errors: (?P<errors>\d+)")


class PySpyError(Exception):
    """A py-spy invocation failed.

    ``code`` is one of ``py_spy_not_found``, ``permission_denied``,
    ``no_such_process``, ``not_python``, ``timeout``, ``bad_output`` (stdout
    or the output file could not be parsed), ``invalid_argument`` or
    ``py_spy_failed`` (any other non-zero exit).
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
        self.stderr = clean_stderr(stderr) if stderr else None

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


def clean_stderr(text: str, limit: int = _STDERR_LIMIT) -> str:
    """Drop Rust backtraces and py-spy's progress lines; keep the tail."""
    lines = []
    for line in text.splitlines():
        if line.strip() == "Stack backtrace:":
            break
        if line.startswith("py-spy> ") or not line.strip():
            continue
        lines.append(line.rstrip())
    out = "\n".join(lines).strip()
    return out if len(out) <= limit else "..." + out[-limit:]


def clip_line(line: str, limit: int = 300) -> str:
    line = line.removeprefix("py-spy> ").strip()
    return line if len(line) <= limit else line[: limit - 3] + "..."


def classify_failure(stderr: str, status: int | None) -> PySpyError:
    text = clean_stderr(stderr or "")
    low = text.lower()
    for needle, code in _STDERR_CODES:
        if needle in low:
            return PySpyError(code, text or code, exit_status=status, stderr=stderr)
    message = text[:500] or f"py-spy exited with status {status}"
    return PySpyError("py_spy_failed", message, exit_status=status, stderr=stderr)


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    # anyhow prints a backtrace on error when these are set; it only adds noise.
    env["RUST_BACKTRACE"] = "0"
    env["RUST_LIB_BACKTRACE"] = "0"
    return env


# -- records ----------------------------------------------------------------------


@dataclass(frozen=True)
class RecordSpec:
    """One ``py-spy record`` run."""

    output: Path
    duration_s: int
    rate_hz: int
    fmt: str = "raw"
    idle: bool = False
    gil: bool = False
    threads: bool = True
    subprocesses: bool = False
    native: bool = False
    nonblocking: bool = True

    def args(self, pid: int) -> list[str]:
        args = [
            "record",
            f"--pid={pid}",
            f"--output={self.output}",
            f"--format={self.fmt}",
            f"--duration={self.duration_s}",
            f"--rate={self.rate_hz}",
        ]
        for flag, on in (
            ("--idle", self.idle),
            ("--gil", self.gil),
            ("--threads", self.threads),
            ("--subprocesses", self.subprocesses),
            ("--native", self.native),
            ("--nonblocking", self.nonblocking),
        ):
            if on:
                args.append(flag)
        return args


@dataclass
class RecordResult:
    spec: RecordSpec
    samples: int | None
    errors: int | None
    stderr: str
    wall_s: float
    warnings: list[str] = field(default_factory=list)


@dataclass
class PySpy:
    """Runs ``py-spy dump`` and ``py-spy record``."""

    binary: Path | None
    dump_timeout: float = 30.0
    record_grace: float = 30.0

    def require(self) -> Path:
        """The binary, or :class:`PySpyError` ``py_spy_not_found``."""
        if self.binary is None:
            raise PySpyError(
                "py_spy_not_found",
                "the py-spy executable was not found (no --py-spy-bin, no PY_SPY_BIN, no "
                "'py-spy' on PATH or next to the server's Python)",
            )
        return self.binary

    def _argv(self, args: list[str]) -> list[str]:
        return [str(self.require()), *args]

    def dump(self, pid: int, *, native: bool = False, nonblocking: bool = True) -> list[Any]:
        if native and nonblocking:
            raise PySpyError(
                "invalid_argument", "py-spy cannot read native stacks with --nonblocking"
            )
        args = ["dump", f"--pid={pid}", "--json"]
        if native:
            args.append("--native")
        if nonblocking:
            args.append("--nonblocking")
        argv = self._argv(args)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.dump_timeout,
                stdin=subprocess.DEVNULL,
                shell=False,
                check=False,
                env=_child_env(),
            )
        except subprocess.TimeoutExpired as e:
            raise PySpyError(
                "timeout", f"py-spy dump did not finish within {self.dump_timeout:g} s"
            ) from e
        except OSError as e:
            raise PySpyError("py_spy_not_found", f"cannot run {self.binary}: {e}") from e
        if proc.returncode != 0:
            raise classify_failure(proc.stderr, proc.returncode)
        try:
            doc = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise PySpyError(
                "bad_output",
                f"py-spy dump --json printed something that is not JSON ({e.msg})",
                stderr=proc.stderr,
            ) from e
        if not isinstance(doc, list):
            raise PySpyError("bad_output", "py-spy dump --json output is not a list of threads")
        return doc

    def record(self, pid: int, specs: Sequence[RecordSpec]) -> list[RecordResult]:
        """Run one or more recorders against ``pid`` at the same time.

        All of them must succeed. On a timeout or failure every recorder still
        running is killed and every output file is removed.
        """
        if not specs:
            return []
        deadline_s = max(s.duration_s for s in specs) + self.record_grace
        procs: list[subprocess.Popen[str]] = []
        start = time.monotonic()
        try:
            for spec in specs:
                procs.append(
                    subprocess.Popen(
                        self._argv(spec.args(pid)),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        shell=False,
                        env=_child_env(),
                    )
                )
            results: list[RecordResult] = []
            failure: PySpyError | None = None
            for spec, proc in zip(specs, procs, strict=True):
                remaining = max(0.1, deadline_s - (time.monotonic() - start))
                try:
                    stdout, stderr = proc.communicate(timeout=remaining)
                except subprocess.TimeoutExpired as e:
                    raise PySpyError(
                        "timeout",
                        f"py-spy record did not finish within {deadline_s:g} s "
                        f"({spec.duration_s} s of sampling plus {self.record_grace:g} s)",
                    ) from e
                # py-spy prints its progress and summary lines on stdout, errors on stderr.
                output = f"{stdout or ''}\n{stderr or ''}"
                if proc.returncode != 0 and failure is None:
                    failure = classify_failure(output, proc.returncode)
                stats = _RECORD_STATS_RE.search(output)
                results.append(
                    RecordResult(
                        spec=spec,
                        samples=int(stats.group("samples")) if stats else None,
                        errors=int(stats.group("errors")) if stats else None,
                        stderr=clean_stderr(stderr or ""),
                        wall_s=time.monotonic() - start,
                        warnings=[
                            clip_line(line)
                            for line in output.splitlines()
                            if "behind in sampling" in line
                        ][:3],
                    )
                )
            if failure is not None:
                raise failure
            return results
        except OSError as e:
            _cleanup(procs, specs)
            raise PySpyError("py_spy_not_found", f"cannot run {self.binary}: {e}") from e
        except BaseException:
            _cleanup(procs, specs)
            raise


def _cleanup(procs: list[subprocess.Popen[str]], specs: Sequence[RecordSpec]) -> None:
    for proc in procs:
        if proc.poll() is None:
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired, ValueError, OSError):
            proc.communicate(timeout=5)
    for spec in specs:
        spec.output.unlink(missing_ok=True)


# -- parsing: py-spy dump --json ---------------------------------------------------


def module_from_filename(short_filename: str | None) -> str | None:
    """``app/cache.py`` -> ``app.cache``. py-spy shortens filenames to the part
    below the ``sys.path`` entry they were found in, so this is usually the
    importable module name. Returns None for ``<string>``, absolute paths and
    anything that is not a ``.py`` path."""
    if not short_filename or short_filename.startswith(("<", "/")) or "\\" in short_filename:
        return None
    if not short_filename.endswith(".py"):
        return None
    parts = short_filename[:-3].split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts or not all(p.isidentifier() for p in parts):
        return None
    return ".".join(parts)


def frame_from_dump(frame: dict[str, Any]) -> dict[str, Any]:
    """Keep only what describes the code location. ``locals`` is always dropped."""
    short = frame.get("short_filename") or frame.get("filename")
    line = frame.get("line")
    module = frame.get("module")
    return {
        "function": frame.get("name"),
        "location": f"{short}:{line}" if line else short,
        "file": frame.get("filename"),
        "line": line or None,
        "module": module if module else module_from_filename(short),
        "native": bool(module),
    }


# -- parsing: folded stacks (py-spy record --format raw) ---------------------------

_PROCESS_RE = re.compile(r'^process (?P<pid>\d+):"(?P<cmd>.*?)";(?=process |thread \()')
_THREAD_RE = re.compile(r"^thread \((?P<tid>0x[0-9a-fA-F]+|\d+)\)(?:: (?P<name>.*))?$")
_FRAME_RE = re.compile(r"^(?P<name>.*?) \((?P<loc>[^()]*)\)$")


@dataclass(frozen=True)
class Frame:
    function: str
    file: str | None
    line: int | None

    @property
    def location(self) -> str | None:
        if self.file is None:
            return None
        return f"{self.file}:{self.line}" if self.line is not None else self.file

    def render(self) -> str:
        return f"{self.function} ({self.location})" if self.location else self.function


@dataclass(frozen=True)
class FoldedStack:
    """One line of folded output: a root-first stack and its sample count."""

    frames: tuple[Frame, ...]
    count: int
    pids: tuple[int, ...] = ()
    thread_id: str | None = None
    thread_name: str | None = None


class FoldedParseError(ValueError):
    pass


def parse_frame(text: str) -> Frame:
    m = _FRAME_RE.match(text)
    if not m:
        return Frame(function=text, file=None, line=None)
    loc = m.group("loc")
    file, sep, line = loc.rpartition(":")
    if sep and line.isdigit():
        return Frame(function=m.group("name"), file=file, line=int(line))
    return Frame(function=m.group("name"), file=loc or None, line=None)


def parse_folded_line(line: str) -> FoldedStack | None:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    body, sep, count_text = line.rpartition(" ")
    if not sep or not count_text.isdigit():
        raise FoldedParseError(f"folded line does not end with a sample count: {line[:200]!r}")
    pids: list[int] = []
    while body.startswith("process "):
        m = _PROCESS_RE.match(body)
        if not m:
            break
        pids.append(int(m.group("pid")))
        body = body[m.end() :]
    parts = body.split(";") if body else []
    thread_id = thread_name = None
    if parts:
        m = _THREAD_RE.match(parts[0])
        if m:
            thread_id, thread_name = m.group("tid"), m.group("name")
            parts = parts[1:]
    frames = tuple(parse_frame(p) for p in parts if p)
    return FoldedStack(
        frames=frames,
        count=int(count_text),
        pids=tuple(pids),
        thread_id=thread_id,
        thread_name=thread_name,
    )


def parse_folded(text: str) -> list[FoldedStack]:
    out = []
    for line in text.splitlines():
        stack = parse_folded_line(line)
        if stack is not None:
            out.append(stack)
    return out


def read_folded(path: Path) -> list[FoldedStack]:
    """Parse a folded file; a missing file means py-spy collected no samples."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []
    try:
        return parse_folded(text)
    except FoldedParseError as e:
        raise PySpyError("bad_output", str(e)) from e


# -- /proc thread state (Linux) ----------------------------------------------------

STATE_LABELS = {
    "R": "running/runnable",
    "S": "sleeping (blocked in a syscall)",
    "D": "disk wait (uninterruptible)",
    "T": "stopped",
    "t": "stopped",
    "Z": "zombie",
    "X": "dead",
    "I": "idle (kernel)",
    "P": "parked",
}

# Syscalls a blocked Python thread is typically in, by number.
_SYSCALLS_X86_64 = {
    0: "read",
    1: "write",
    7: "poll",
    17: "pread64",
    18: "pwrite64",
    23: "select",
    35: "nanosleep",
    43: "accept",
    45: "recvfrom",
    47: "recvmsg",
    61: "wait4",
    74: "fsync",
    75: "fdatasync",
    202: "futex",
    230: "clock_nanosleep",
    232: "epoll_wait",
    270: "pselect6",
    271: "ppoll",
    281: "epoll_pwait",
    288: "accept4",
    441: "epoll_pwait2",
}
_SYSCALLS_AARCH64 = {
    22: "epoll_pwait",
    63: "read",
    64: "write",
    67: "pread64",
    68: "pwrite64",
    72: "pselect6",
    73: "ppoll",
    82: "fsync",
    83: "fdatasync",
    98: "futex",
    101: "nanosleep",
    115: "clock_nanosleep",
    202: "accept",
    207: "recvfrom",
    212: "recvmsg",
    242: "accept4",
    260: "wait4",
    441: "epoll_pwait2",
}


def _syscall_table() -> dict[int, str]:
    machine = os.uname().machine if hasattr(os, "uname") else ""
    if machine in ("x86_64", "amd64"):
        return _SYSCALLS_X86_64
    if machine in ("aarch64", "arm64"):
        return _SYSCALLS_AARCH64
    return {}


_SYSCALLS = _syscall_table()


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def parse_stat_state(stat_text: str) -> str | None:
    """The one-letter state from a ``/proc/.../stat`` line (after the comm field)."""
    end = stat_text.rfind(")")
    if end < 0:
        return None
    rest = stat_text[end + 1 :].split()
    return rest[0] if rest else None


def parse_syscall(text: str | None) -> str | None:
    if not text:
        return None
    first = text.split()[0] if text.split() else ""
    if first == "running":
        return None
    if first.lstrip("-").isdigit():
        number = int(first)
        if number < 0:
            return None
        return _SYSCALLS.get(number, f"syscall {number}")
    return None


def thread_state(pid: int, tid: int) -> dict[str, Any] | None:
    """OS state of one thread from ``/proc/<pid>/task/<tid>``; None off Linux or if gone."""
    if not sys.platform.startswith("linux"):
        return None
    base = f"/proc/{pid}/task/{tid}"
    stat = _read(f"{base}/stat")
    if stat is None:
        return None
    code = parse_stat_state(stat)
    wchan = (_read(f"{base}/wchan") or "").strip()
    syscall = parse_syscall(_read(f"{base}/syscall"))
    out: dict[str, Any] = {
        "code": code,
        "label": STATE_LABELS.get(code or "", "unknown"),
    }
    if code != "R":
        out["kernel_wait"] = wchan if wchan and wchan != "0" else None
        out["syscall"] = syscall
    return out


def task_ids(pid: int) -> list[int]:
    try:
        return sorted(int(t) for t in os.listdir(f"/proc/{pid}/task") if t.isdigit())
    except OSError:
        return []


def state_bucket(code: str | None, syscall: str | None, wchan: str | None) -> str:
    """Coarse class used to aggregate OS state samples."""
    if code == "R":
        return "running"
    if code == "D":
        return "disk_wait"
    if code == "S":
        if syscall == "futex" or (wchan and "futex" in wchan):
            return "sleeping_futex"
        return "sleeping_other"
    if code in ("T", "t"):
        return "stopped"
    return "other"


def sample_task_states(pid: int) -> dict[int, str]:
    """One sample: thread id -> :func:`state_bucket` for every thread of ``pid``."""
    out: dict[int, str] = {}
    for tid in task_ids(pid):
        base = f"/proc/{pid}/task/{tid}"
        stat = _read(f"{base}/stat")
        if stat is None:
            continue
        code = parse_stat_state(stat)
        syscall = wchan = None
        if code == "S":
            syscall = parse_syscall(_read(f"{base}/syscall"))
            if syscall is None:
                wchan = (_read(f"{base}/wchan") or "").strip()
        out[tid] = state_bucket(code, syscall, wchan)
    return out
