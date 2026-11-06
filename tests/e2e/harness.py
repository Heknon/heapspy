"""Helpers for driving the heapspy binary against victim processes.

Everything platform-specific is in this file and kept to a few functions:
``gcore`` and the ELF rewrite (Linux), ``procdump`` (Windows),
``acquisition_methods`` and ``SLEEPER``.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
VICTIMS = HERE / "victims"

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

# How long one heapspy invocation may take before the test fails.
TIMEOUT = float(os.environ.get("HEAPSPY_E2E_TIMEOUT", "300"))
# How long a victim may take to build its heap and write ready.json.
READY_TIMEOUT = float(os.environ.get("HEAPSPY_E2E_READY_TIMEOUT", "180"))

# A long-running process that is not Python.
SLEEPER = ["ping", "-n", "600", "127.0.0.1"] if IS_WINDOWS else ["sleep", "600"]


def acquisition_methods() -> list[str]:
    """How snapshots are taken on this platform.

    - ``pid``: ``heapspy dump --pid`` (ptrace on Linux; on Windows heapspy
      writes a temporary minidump itself).
    - ``core``: ``gcore`` then ``heapspy dump --core`` (Linux).
    - ``minidump``: ``procdump -ma`` then ``heapspy dump --minidump`` (Windows).
    """
    if IS_LINUX:
        return ["pid", "core"]
    if IS_WINDOWS:
        return ["pid", "minidump"]
    return ["pid"]


# -- timings ------------------------------------------------------------------


@dataclass
class Timing:
    test: str
    step: str
    seconds: float


TIMINGS: list[Timing] = []
CURRENT_TEST = ["?"]


def record(step: str, seconds: float) -> None:
    TIMINGS.append(Timing(CURRENT_TEST[0], step, seconds))


# -- processes ----------------------------------------------------------------


@dataclass
class Result:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    seconds: float

    def describe(self) -> str:
        return (
            f"$ {' '.join(self.args)}\nexit status {self.returncode} after {self.seconds:.1f} s\n"
            f"--- stderr ---\n{self.stderr[-4000:]}\n--- stdout ---\n{self.stdout[-4000:]}"
        )


def run(args: list[str], *, timeout: float = TIMEOUT, step: str | None = None) -> Result:
    """Run a command with a hard timeout. A timeout is a test failure, not a hang."""
    start = time.monotonic()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise AssertionError(f"timed out after {timeout:g} s: {' '.join(args)}") from e
    seconds = time.monotonic() - start
    if step:
        record(step, seconds)
    return Result(list(args), proc.returncode, proc.stdout, proc.stderr, seconds)


def is_crash(r: Result) -> bool:
    """A panic, a signal, or any exit status heapspy does not document."""
    return r.returncode not in (0, 1, 2) or "panicked at" in r.stderr


class Victim:
    """A victim script running under one interpreter. Always call ``kill``."""

    def __init__(self, python: Path, script: str, workdir: Path, *, args: list[str] = ()):
        self.workdir = workdir
        self.script = VICTIMS / script
        workdir.mkdir(parents=True, exist_ok=True)
        self._out = open(workdir / "victim.out", "w")  # noqa: SIM115 - closed in kill()
        # -E: ignore PYTHON* variables from the test environment. -s: no user
        # site-packages. Not -I, which would also drop the script directory
        # from sys.path and break `import _victim`.
        self.proc = subprocess.Popen(
            [str(python), "-E", "-s", str(self.script), str(workdir), *args],
            stdout=self._out,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        self.pid = self.proc.pid
        self.info: dict[str, Any] = {}

    def wait_ready(self, timeout: float = READY_TIMEOUT) -> dict[str, Any]:
        start = time.monotonic()
        path = self.workdir / "ready.json"
        self.info = self._wait_file(path, start, timeout)
        record("victim ready", time.monotonic() - start)
        return self.info

    def trigger(self, step: int, timeout: float = READY_TIMEOUT) -> dict[str, Any]:
        """Ask the victim to run its step ``step`` and wait for the result."""
        (self.workdir / f"trigger-{step}").write_text("")
        return self._wait_file(self.workdir / f"done-{step}.json", time.monotonic(), timeout)

    def _wait_file(self, path: Path, start: float, timeout: float) -> dict[str, Any]:
        while not path.exists():
            if self.proc.poll() is not None:
                raise AssertionError(
                    f"victim {self.script.name} exited with {self.proc.returncode}:\n"
                    + self.output()
                )
            if time.monotonic() - start > timeout:
                raise AssertionError(f"victim {self.script.name} did not write {path.name}")
            time.sleep(0.05)
        return json.loads(path.read_text())

    def output(self) -> str:
        self._out.flush()
        try:
            return (self.workdir / "victim.out").read_text(errors="replace")[-4000:]
        except OSError:
            return ""

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.proc.wait(timeout=30)
        self._out.close()


# -- heapspy ------------------------------------------------------------------


class Heapspy:
    def __init__(self, binary: Path):
        self.binary = binary

    def run(self, *args: str, timeout: float = TIMEOUT, step: str | None = None) -> Result:
        return run([str(self.binary), *args], timeout=timeout, step=step)

    def dump(self, source: list[str], out: Path, *, step: str = "dump") -> Result:
        r = self.run("dump", *source, "-o", str(out), step=step)
        assert not is_crash(r), r.describe()
        assert r.returncode == 0, r.describe()
        assert out.is_file(), r.describe()
        assert r.stderr.strip().splitlines()[-1].startswith(f"wrote {out}: "), r.describe()
        return r

    def error_code(self, *args: str, step: str | None = None) -> str:
        """Run a command that must fail with ``--json``; return ``error.code``."""
        r = self.run(*args, "--json", step=step)
        assert not is_crash(r), r.describe()
        assert r.returncode == 1, r.describe()
        assert "heapspy: error:" in r.stderr, r.describe()
        doc = json.loads(r.stdout)
        assert doc["schema_version"] == 1 and doc["kind"] == "error", doc
        return doc["error"]["code"]

    def json(self, *args: str, kind: str, step: str | None = None) -> dict[str, Any]:
        r = self.run(*args, "--json", step=step)
        assert not is_crash(r), r.describe()
        assert r.returncode == 0, r.describe()
        doc = json.loads(r.stdout)
        assert doc["schema_version"] == 1, doc
        assert doc["kind"] == kind, doc
        return doc

    def analyze(self, snap: Path, top: int = 20) -> dict[str, Any]:
        return self.json("analyze", str(snap), "--top", str(top), kind="analyze", step="analyze")

    def query_type(self, snap: Path, type_name: str) -> dict[str, Any]:
        return self.json("query", str(snap), f"--type={type_name}", kind="type_query", step="query")

    def path_to(self, snap: Path, address: str) -> dict[str, Any]:
        return self.json(
            "query", str(snap), "--retaining-path", address, kind="retaining_path", step="query"
        )

    def path_to_type(self, snap: Path, type_name: str, top: int = 3) -> dict[str, Any]:
        return self.json(
            "query",
            str(snap),
            f"--retaining-path-type={type_name}",
            "--top",
            str(top),
            kind="retaining_path",
            step="query",
        )

    def diff(self, before: Path, after: Path) -> dict[str, Any]:
        return self.json("diff", str(before), str(after), kind="diff", step="diff")


# -- acquisition --------------------------------------------------------------


def gcore(pid: int, workdir: Path, *, step: str = "gcore") -> Path:
    """Write an ELF core of a live process with gdb's gcore (Linux)."""
    if shutil.which("gcore") is None:
        raise AssertionError("gcore (from gdb) is not installed")
    prefix = workdir / "core"
    r = run(["gcore", "-o", str(prefix), str(pid)], step=step)
    core = Path(f"{prefix}.{pid}")
    assert r.returncode == 0 and core.is_file(), r.describe()
    return core


def procdump_binary() -> str | None:
    """Sysinternals procdump: ``$HEAPSPY_PROCDUMP``, else on PATH."""
    configured = os.environ.get("HEAPSPY_PROCDUMP")
    if configured:
        return configured
    for name in ("procdump64.exe", "procdump.exe", "procdump"):
        found = shutil.which(name)
        if found:
            return found
    return None


def procdump(pid: int, workdir: Path, *, step: str = "procdump") -> Path:
    """Write a full-memory minidump with ``procdump -ma`` (Windows)."""
    exe = procdump_binary()
    if exe is None:
        raise AssertionError("procdump not found; set HEAPSPY_PROCDUMP")
    out = workdir / f"victim-{pid}.dmp"
    r = run([exe, "-accepteula", "-ma", str(pid), str(out)], step=step)
    # procdump exits with a non-zero status even on success on some versions;
    # the file is what counts.
    assert out.is_file(), r.describe()
    return out


def image_file(method: str, pid: int, workdir: Path) -> tuple[list[str], Path]:
    """Capture a memory image file of ``pid``; returns the dump args and the file."""
    if method == "core":
        core = gcore(pid, workdir)
        return ["--core", str(core)], core
    if method == "minidump":
        dmp = procdump(pid, workdir)
        return ["--minidump", str(dmp)], dmp
    raise ValueError(method)


def acquire(
    heapspy: Heapspy, method: str, victim: Victim, workdir: Path, name: str = "snap"
) -> Path:
    """Take a snapshot of a running victim with ``method``."""
    out = workdir / f"{name}.hpy"
    if method == "pid":
        heapspy.dump(["--pid", str(victim.pid)], out, step="dump --pid")
        return out
    args, image = image_file(method, victim.pid, workdir)
    heapspy.dump(args, out, step=f"dump --{method}")
    image.unlink()  # cores of large heaps are big; nothing reads it again
    return out


# -- reports ------------------------------------------------------------------


def render_path(hops: list[dict[str, Any]]) -> str:
    """Join a root-first path as docs/json-schema.md describes (the diff site key)."""
    out = hops[0]["root_label"] or f"<{hops[0]['type']}>"
    for hop in hops[1:]:
        edge = hop["edge"] or "<?>"
        out += f" {edge}" if edge[0].isalpha() or edge[0] == "<" else edge
    return out


def edges(hops: list[dict[str, Any]]) -> list[str]:
    return [h["edge"] for h in hops[1:]]


def is_subsequence(needles: list[str], haystack: list[str]) -> bool:
    it = iter(haystack)
    return all(any(n == h for h in it) for n in needles)


# -- core file surgery (Linux) ------------------------------------------------


@dataclass
class _Phdr:
    raw: bytearray
    p_type: int
    offset: int
    filesz: int
    data: bytes = field(default=b"", repr=False)


def kernel_layout_core(src: Path, dst: Path) -> list[tuple[int, int, int]]:
    """Rewrite a gcore core so the PT_NOTE segment comes first, as in kernel cores.

    gdb's gcore writes the notes after all memory segments, so cutting the
    file anywhere removes them and heapspy stops with "image cut short: ... PT_NOTE
    ... is past the end of the file" (error code ``truncated_image``).
    A core the kernel writes (and truncates at RLIMIT_CORE or a full disk) has
    the notes first and loses memory segments instead. This produces that
    layout from a gcore file. Returns ``(vaddr, file_offset, filesz)`` of each
    PT_LOAD in the new file.
    """
    data = src.read_bytes()
    assert data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1, "64-bit LE ELF only"
    (e_phoff,) = struct.unpack_from("<Q", data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        raw = bytearray(data[off : off + e_phentsize])
        (p_type,) = struct.unpack_from("<I", raw, 0)
        (p_offset,) = struct.unpack_from("<Q", raw, 8)
        (p_filesz,) = struct.unpack_from("<Q", raw, 32)
        phdrs.append(_Phdr(raw, p_type, p_offset, p_filesz, data[p_offset : p_offset + p_filesz]))
    header_end = e_phoff + e_phnum * e_phentsize
    ordered = [p for p in phdrs if p.p_type == 4] + [p for p in phdrs if p.p_type != 4]
    pos = (header_end + 15) & ~15
    body = bytearray()
    loads = []
    for p in ordered:
        struct.pack_into("<Q", p.raw, 8, pos if p.filesz else 0)
        if p.p_type == 1:
            (vaddr,) = struct.unpack_from("<Q", p.raw, 16)
            loads.append((vaddr, pos, p.filesz))
        body += p.data
        pos += p.filesz
    out = bytearray(data[:header_end])
    # Drop section headers (gcore writes a few); their offsets would be stale.
    struct.pack_into("<Q", out, 0x28, 0)  # e_shoff
    struct.pack_into("<HHH", out, 0x3A, 0, 0, 0)  # e_shentsize, e_shnum, e_shstrndx
    for i, p in enumerate(phdrs):
        off = e_phoff + i * e_phentsize
        out[off : off + e_phentsize] = p.raw
    out += b"\0" * (((header_end + 15) & ~15) - header_end)
    out += body
    dst.write_bytes(out)
    return loads
