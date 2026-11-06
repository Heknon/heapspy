"""Inputs heapspy must survive: truncated images, non-Python processes, a
target that is busy allocating while it is dumped, and a PID that is gone.

"Survive" means: exit status 0 or 1 within the timeout, never a panic or a
signal. A failure must say why on stderr and, with ``--json``, carry the
specific error code from docs/json-schema.md; a snapshot that was written
from an incomplete image must be marked ``truncated``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from expectations import MAIN, RETAINED_HI, RETAINED_LO
from harness import (
    IS_LINUX,
    SLEEPER,
    acquire,
    image_file,
    is_crash,
    kernel_layout_core,
    procdump_binary,
    render_path,
)

# -- truncated images ---------------------------------------------------------

IMAGE_METHOD = "core" if IS_LINUX else "minidump"


def check_truncated_dump(heapspy, image, tmp_path, flag: str, what: str) -> str:
    """Dump a cut image with ``--json``; return the error code, or "truncated"
    if a snapshot was written. Anything else fails."""
    out = tmp_path / "cut.hpy"
    out.unlink(missing_ok=True)
    r = heapspy.run("dump", flag, str(image), "-o", str(out), "--json", step=f"dump {what}")
    assert not is_crash(r), r.describe()
    if r.returncode == 1:
        assert "heapspy: error:" in r.stderr, r.describe()
        assert not out.exists(), "a failed dump left a snapshot behind"
        doc = json.loads(r.stdout)
        assert doc["kind"] == "error", doc
        code = doc["error"]["code"]
        assert code in ("truncated_image", "invalid_image"), f"{what}: {doc}"
        return code
    assert r.returncode == 0, r.describe()
    assert r.stderr.strip().endswith("(truncated)"), (
        f"{what}: dump succeeded on a cut image without marking it truncated\n" + r.describe()
    )
    report = json.loads(r.stdout)
    assert report["kind"] == "dump" and report["truncated"] is True, report
    assert "truncated_snapshot" in [n["code"] for n in report["notes"]], report
    doc = heapspy.analyze(out)
    assert doc["snapshot"]["truncated"] is True, doc["snapshot"]
    assert "truncated_snapshot" in [n["code"] for n in doc["notes"]]
    return "truncated"


@pytest.fixture
def cache_image(heapspy, start_victim, tmp_path, python):
    """A memory image file of the unbounded-cache victim, and its dump flag."""
    victim = start_victim(python, "unbounded_cache.py")
    if IMAGE_METHOD == "minidump" and procdump_binary() is None:
        pytest.skip("procdump not found; set HEAPSPY_PROCDUMP")
    args, image = image_file(IMAGE_METHOD, victim.pid, tmp_path)
    victim.kill()
    return args[0], image


@pytest.mark.parametrize("keep", [0, 64, 4096, 0.25, 0.5, 0.9, 0.999])
def test_cut_image(heapspy, cache_image, tmp_path, keep) -> None:
    """Cut the image file as written (gcore puts the ELF notes last)."""
    flag, image = cache_image
    size = image.stat().st_size
    cut = tmp_path / f"cut{image.suffix}"
    data = image.read_bytes()
    n = keep if isinstance(keep, int) else int(size * keep)
    cut.write_bytes(data[:n])
    result = check_truncated_dump(heapspy, cut, tmp_path, flag, f"cut to {n} of {size} bytes")
    if n < 32:
        # Shorter than an ELF or minidump header: not recognisable at all.
        assert result == "invalid_image", result
    elif flag == "--core":
        # gcore writes the notes last, so any cut loses them or the
        # program headers.
        assert result == "truncated_image", result


@pytest.mark.skipif(not IS_LINUX, reason="ELF cores only")
@pytest.mark.parametrize("keep", [0.1, 0.3, 0.5, 0.7, 0.9, 0.99])
def test_cut_kernel_layout_core(heapspy, cache_image, tmp_path, keep) -> None:
    """Notes first, as the kernel writes cores, then cut inside memory segments.

    This is what a core cut short by RLIMIT_CORE or a full disk looks like:
    the process metadata is intact and some memory is missing. heapspy may
    still fail (e.g. if _PyRuntime's page is gone), but if it writes a
    snapshot, the snapshot must say it is incomplete.
    """
    _, image = cache_image
    full = tmp_path / "kernel-layout.core"
    loads = kernel_layout_core(image, full)
    # The rewritten core is still a valid, complete image.
    out = tmp_path / "full.hpy"
    heapspy.dump(["--core", str(full)], out)
    doc = heapspy.analyze(out)
    assert doc["snapshot"]["truncated"] is False
    assert render_path(doc["top_retainers"][0]["path"]) == f"{MAIN}['CACHE']"

    data = full.read_bytes()
    n = int(len(data) * keep)
    assert any(off <= n < off + size for _, off, size in loads), "cut is inside a segment"
    cut = tmp_path / "cut.core"
    cut.write_bytes(data[:n])
    result = check_truncated_dump(
        heapspy, cut, tmp_path, "--core", f"kernel-layout core cut at {keep}"
    )
    # Metadata is intact: either a truncated snapshot or a refusal that
    # blames the cut, never "not a CPython process".
    assert result in ("truncated", "truncated_image"), result


# -- not a Python process -----------------------------------------------------


@pytest.fixture
def sleeper():
    proc = subprocess.Popen(SLEEPER, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        yield proc
    finally:
        proc.kill()
        proc.wait(timeout=30)


def check_not_python(r) -> None:
    assert not is_crash(r), r.describe()
    assert r.returncode == 1, r.describe()
    assert "not a CPython process" in r.stderr, r.describe()
    doc = json.loads(r.stdout)
    assert doc["kind"] == "error" and doc["error"]["code"] == "not_python", doc


def test_not_python_pid(heapspy, sleeper, tmp_path) -> None:
    out = tmp_path / "x.hpy"
    r = heapspy.run("dump", "--pid", str(sleeper.pid), "-o", str(out), "--json", step="dump --pid")
    check_not_python(r)
    assert not out.exists()


@pytest.mark.skipif(not IS_LINUX, reason="gcore is Linux only")
def test_not_python_core(heapspy, sleeper, tmp_path) -> None:
    args, _ = image_file("core", sleeper.pid, tmp_path)
    r = heapspy.run("dump", *args, "-o", str(tmp_path / "x.hpy"), "--json", step="dump --core")
    check_not_python(r)


def test_pid_that_has_exited(heapspy, tmp_path) -> None:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(timeout=60)
    pid = proc.pid
    del proc  # on Windows, release the process handle
    code = heapspy.error_code("dump", "--pid", str(pid), "-o", str(tmp_path / "x.hpy"))
    if IS_LINUX:
        assert code == "no_such_process", code
    else:
        # A process object can outlive the process while a handle to it is
        # open somewhere; dumping it then fails some other way.
        assert code in ("no_such_process", "io", "not_python"), code


def test_pid_that_never_existed(heapspy, tmp_path) -> None:
    # Above Linux's largest pid_max (2^22); Windows process ids are multiples of 4.
    code = heapspy.error_code("dump", "--pid", "1073741823", "-o", str(tmp_path / "x.hpy"))
    assert code == "no_such_process", code


@pytest.mark.skipif(
    not IS_LINUX or os.geteuid() != 0, reason="needs root on Linux to run heapspy as nobody"
)
def test_permission_denied(heapspy, sleeper, tmp_path) -> None:
    """heapspy as ``nobody`` cannot ptrace a root process."""
    args = [str(heapspy.binary), "dump", f"--pid={sleeper.pid}", "-o", "/nonexistent/x.hpy"]
    r = subprocess.run(
        [*args, "--json"],
        capture_output=True,
        text=True,
        timeout=60,
        user=65534,
        group=65534,
        check=False,
    )
    assert r.returncode == 1, (r.returncode, r.stderr)
    doc = json.loads(r.stdout)
    assert doc["error"]["code"] == "permission_denied", doc
    assert "CAP_SYS_PTRACE" in r.stderr, r.stderr


@pytest.mark.parametrize("flag", ["--core", "--minidump"])
def test_junk_image(heapspy, tmp_path, flag) -> None:
    junk = tmp_path / "junk.img"
    junk.write_bytes(b"neither an ELF core nor a minidump\n" * 100)
    code = heapspy.error_code("dump", flag, str(junk), "-o", str(tmp_path / "x.hpy"))
    assert code == "invalid_image", code


def test_analyze_non_snapshot_file(heapspy, tmp_path) -> None:
    junk = tmp_path / "junk.hpy"
    junk.write_bytes(b"not a snapshot at all\n" * 100)
    r = heapspy.run("analyze", str(junk), "--json")
    assert not is_crash(r), r.describe()
    assert r.returncode == 1
    doc = json.loads(r.stdout)
    assert doc["kind"] == "error" and doc["error"]["code"] == "invalid_snapshot", doc


# -- dumping a busy process ---------------------------------------------------


def test_busy_process(heapspy, start_victim, tmp_path, python, method) -> None:
    """Dump three times while two threads allocate, free and collect."""
    victim = start_victim(python, "busy_allocator.py")
    info = victim.info
    for i in range(3):
        snap = acquire(heapspy, method, victim, tmp_path, f"busy-{i}")
        assert victim.proc.poll() is None, "the victim died during the dump:\n" + victim.output()
        doc = heapspy.analyze(snap)
        assert doc["snapshot"]["truncated"] is False, doc["snapshot"]
        totals = doc["totals"]
        assert totals["objects"] > 10_000 and totals["reachable_objects"] > 0, totals
        # The fixed structure is found whole, however the rest of the heap moved.
        stable = [t for t in doc["top_retainers"] if render_path(t["path"]) == f"{MAIN}['STABLE']"]
        assert stable, [render_path(t["path"]) for t in doc["top_retainers"]]
        expected = info["expected_stable"]
        assert expected * RETAINED_LO <= stable[0]["retained_bytes"] <= expected * RETAINED_HI
        # And the snapshot answers queries.
        q = heapspy.query_type(snap, "builtins.dict")
        assert q["instances"] > 0
        heapspy.path_to(snap, stable[0]["address"])
