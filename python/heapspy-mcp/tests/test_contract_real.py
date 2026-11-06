"""Contract tests against a real heapspy binary. Off by default.

    HEAPSPY_MCP_REAL_BIN=/path/to/heapspy uv run pytest tests/test_contract_real.py

What runs depends on what the binary has (checked with --help):

- ``dump --json`` (feature/dump-json-errors): captures are parsed from the dump
  report, and failures carry specific codes. Without it, the server must fall
  back to the stderr line and report failures as ``cli_failed``.
- the allocation join (feature/alloc-join, which adds ``flamegraph --allocations``):
  the allocation tools run against ``tests/fixtures/heapspy/contract.snapshot`` (a
  ``.hpy``) and ``contract.hpya`` (see the README there). Without it, they must fail
  with ``allocations_unsupported``. A heapspy with ``analyze --allocations`` but no
  join (feature/alloc-format alone) still checks the profile, so a corrupt one is
  ``invalid_allocations`` there.

The live tests start ``/usr/bin/python3.12`` (``HEAPSPY_MCP_REAL_PYTHON``
overrides it) and ``sleep``, and need ptrace rights on them; they are skipped
when the capture is refused for lack of them. Every child is killed and
waited for on every path, and snapshots go to pytest's temporary directory.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from heapspy_mcp.cli import HeapspyCLI, HeapspyError

from .conftest import CLI_FIXTURES

REAL_BIN = os.environ.get("HEAPSPY_MCP_REAL_BIN")
PYTHON = Path(os.environ.get("HEAPSPY_MCP_REAL_PYTHON", "/usr/bin/python3.12"))

pytestmark = [
    pytest.mark.real_heapspy,
    pytest.mark.skipif(not REAL_BIN, reason="set HEAPSPY_MCP_REAL_BIN to a heapspy binary"),
]

VICTIM = textwrap.dedent(
    """
    import time


    class ContractHolder:
        def __init__(self, i):
            self.payload = bytearray(2048)
            self.i = i


    HELD = [ContractHolder(i) for i in range(500)]
    print("ready", flush=True)
    time.sleep(120)
    """
).lstrip()


def _help(*args: str) -> str:
    assert REAL_BIN
    proc = subprocess.run(
        [REAL_BIN, *args, "--help"], capture_output=True, text=True, timeout=30, check=False
    )
    return proc.stdout + proc.stderr


@pytest.fixture(scope="module")
def features() -> dict[str, bool]:
    return {
        "dump_json": "--json" in _help("dump"),
        "allocations_flag": "--allocations" in _help("analyze"),
        "allocations": "--allocations" in _help("analyze")
        and "--allocations" in _help("flamegraph"),
    }


@pytest.fixture
def real_bin() -> Path:
    assert REAL_BIN
    path = Path(REAL_BIN)
    if not (path.is_file() and os.access(path, os.X_OK)):
        pytest.fail(f"HEAPSPY_MCP_REAL_BIN={REAL_BIN} is not an executable file")
    return path.resolve()


@pytest.fixture
def real_cli(real_bin: Path) -> HeapspyCLI:
    return HeapspyCLI(real_bin, timeout=60, capture_timeout=120)


def _start(argv: list[str], **kw) -> subprocess.Popen[str]:
    return subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        **kw,
    )


def _stop(proc: subprocess.Popen[str]) -> None:
    proc.kill()
    proc.wait(timeout=30)
    if proc.stdout:
        proc.stdout.close()


@pytest.fixture
def victim(tmp_path: Path) -> Iterator[tuple[subprocess.Popen[str], Path]]:
    """A python3.12 running a plain script (no main guard) that holds 500 objects."""
    if not PYTHON.is_file():
        pytest.skip(f"{PYTHON} is not installed")
    repo = tmp_path / "victim-repo"
    repo.mkdir()
    script = repo / "contract_victim.py"
    script.write_text(VICTIM)
    proc = _start([str(PYTHON), str(script)], cwd=repo)
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "ready"
        yield proc, repo
    finally:
        _stop(proc)


@pytest.fixture
def sleeper() -> Iterator[subprocess.Popen[str]]:
    sleep = shutil.which("sleep")
    if sleep is None:
        pytest.skip("no sleep binary")
    proc = _start([sleep, "120"])
    try:
        yield proc
    finally:
        _stop(proc)


def _skip_if_no_ptrace(err: bool, out) -> None:
    if err and isinstance(out, dict) and out["error"].get("code") == "permission_denied":
        pytest.skip("no ptrace rights on the child process")
    text = json.dumps(out)
    if err and "permission denied" in text.lower():
        pytest.skip("no ptrace rights on the child process")


def _keys(obj, prefix: str = "") -> set[str]:
    """Dotted key paths of a JSON document (lists: their first element)."""
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(prefix + k)
            out |= _keys(v, f"{prefix}{k}.")
    elif isinstance(obj, list) and obj:
        out |= _keys(obj[0], f"{prefix}[].")
    return out


# -- capture -------------------------------------------------------------------------


async def test_capture_live_python(call, real_bin, features, victim, snapshot_dir) -> None:
    proc, repo = victim
    err, out = await call(
        "capture_snapshot",
        {"pid": proc.pid, "confirm": True},
        heapspy_bin=real_bin,
        allow=[f"pid:{proc.pid}"],
    )
    _skip_if_no_ptrace(err, out)
    assert not err, out
    stats = out["stats"]
    assert stats["objects"] > 1000 and stats["edges"] > stats["objects"] and stats["roots"] > 0
    assert stats["file_bytes"] > 0 and stats["truncated"] is False
    if features["dump_json"]:
        assert out["report"] == "json"
        assert out["python_version"].startswith("3.12")
        assert isinstance(stats["pause_ms"], float) and stats["pause_ms"] >= 0
        assert stats["types"] > 0 and stats["read_errors"] == 0 and stats["missing_bytes"] == 0
    else:
        assert out["report"] == "stderr_line"
        assert stats["pause_ms"] is None and out["python_version"] is None
    handle = out["snapshot"]

    err, summary = await call("heap_summary", {"snapshot": handle}, heapspy_bin=real_bin)
    assert not err, summary
    assert summary["snapshot"]["python_version"].startswith("3.12")
    assert summary["snapshot"]["source"]["kind"] == "pid"

    err, detail = await call(
        "type_detail", {"snapshot": handle, "type": "ContractHolder"}, heapspy_bin=real_bin
    )
    assert not err, detail
    assert detail["matched_types"] == ["__main__.ContractHolder"]
    assert detail["instances"] == 500

    # The script has no main guard; map_to_source finds __main__ names in it anyway.
    err, src = await call(
        "map_to_source", {"qualname": "__main__.ContractHolder.payload", "repo_path": str(repo)}
    )
    assert not err, src
    assert src["heuristic"] is True
    assert src["candidates"][0]["location"] == "contract_victim.py:6"
    assert src["candidates"][0]["kind"] == "instance_attribute"

    if features["allocations"]:
        # A profile from another pid: nothing links, the stacks are still listed.
        profile = CLI_FIXTURES / "contract.hpya"
        err, sites = await call(
            "allocation_sites",
            {"profile": str(profile), "snapshot": handle},
            heapspy_bin=real_bin,
        )
        assert not err, sites
        codes = {n["code"] for n in sites["notes"]}
        assert {"allocations_pid_mismatch", "allocations_not_linked"} <= codes
        assert "No object was linked" in sites["warning"]
        assert all(s["linked_bytes"] == 0 for s in sites["top_stacks"])
    assert sorted(p.name for p in snapshot_dir.iterdir()) == [f"{handle}.hpy"]


async def test_capture_not_python(call, real_bin, features, sleeper, snapshot_dir) -> None:
    err, out = await call(
        "capture_snapshot",
        {"pid": sleeper.pid, "confirm": True},
        heapspy_bin=real_bin,
        allow=[f"pid:{sleeper.pid}"],
    )
    _skip_if_no_ptrace(err, out)
    assert err
    if features["dump_json"]:
        assert out["error"]["code"] == "not_python"
        assert "_PyRuntime" in out["error"]["hint"]
    else:
        assert out["error"]["code"] == "cli_failed"
        assert "not a CPython process" in out["error"]["message"]
    assert list(snapshot_dir.iterdir()) == []


def test_dump_error_codes(real_cli: HeapspyCLI, features, tmp_path: Path) -> None:
    bad_core = tmp_path / "bad.core"
    bad_core.write_bytes(b"not an ELF file")
    cases = [
        ({"pid": 2**22 + 4321}, "no_such_process"),
        ({"core": bad_core}, "invalid_image"),
        ({"core": tmp_path / "missing.core"}, "io"),
    ]
    for kwargs, code in cases:
        with pytest.raises(HeapspyError) as e:
            real_cli.dump(output=tmp_path / "x.hpy", **kwargs)
        expected = code if features["dump_json"] else "cli_failed"
        assert e.value.code == expected, (kwargs, e.value.to_dict())
        assert e.value.exit_status == 1
    assert real_cli.dump_json is (None if features["dump_json"] else False)
    assert not (tmp_path / "x.hpy").exists()


def test_dump_report_matches_fixture_fields(real_cli: HeapspyCLI, features, victim, tmp_path):
    """The dump report has every field of the copied docs/examples/dump.json."""
    if not features["dump_json"]:
        pytest.skip("this heapspy has no dump --json")
    proc, _ = victim
    out = tmp_path / "v.hpy"
    run = subprocess.run(
        [str(real_cli.binary), "dump", f"--pid={proc.pid}", f"--output={out}", "--json"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if run.returncode == 1 and "permission_denied" in run.stdout:
        pytest.skip("no ptrace rights on the child process")
    assert run.returncode == 0, run.stderr
    real = json.loads(run.stdout)
    fixture = json.loads((CLI_FIXTURES / "dump.json").read_text())
    assert _keys(real) >= _keys(fixture) - {"notes.[].code", "notes.[].message"}
    assert "wrote " in run.stderr  # the stderr line older parsers use is still there


# -- allocations ---------------------------------------------------------------------


@pytest.fixture
def contract_files(tmp_path: Path) -> tuple[Path, Path]:
    snap = tmp_path / "contract.hpy"
    prof = tmp_path / "contract.hpya"
    # Stored as contract.snapshot: *.hpy is git-ignored repository-wide.
    shutil.copyfile(CLI_FIXTURES / "contract.snapshot", snap)
    shutil.copyfile(CLI_FIXTURES / "contract.hpya", prof)
    return snap, prof


async def test_allocation_sites_joined(call, real_bin, features, contract_files) -> None:
    snap, prof = contract_files
    err, out = await call(
        "allocation_sites", {"profile": str(prof), "snapshot": str(snap)}, heapspy_bin=real_bin
    )
    if not features["allocations"]:
        assert err and out["error"]["code"] == "allocations_unsupported"
        return
    assert not err, out
    rec = out["recording"]
    assert (rec["pid"], rec["python_version"], rec["duration_ms"]) == (4242, "3.12.0", 60000)
    assert rec["samples"] == 5 and rec["mechanisms"] == ["ebpf"]
    assert rec["sampling"]["events"] == ["arena", "large_object"]
    cov = out["coverage"]
    assert (cov["linked_objects"], cov["linked_bytes"]) == (203, 401408)
    assert (cov["exact_linked_objects"], cov["exact_linked_bytes"]) == (3, 196608)
    by_site = {s["allocated_in"]: s for s in out["top_stacks"]}
    report = by_site["app/reports.py:57"]
    assert (report["rank"], report["estimated_bytes"], report["linked_bytes"]) == (1, 2 << 20, 0)
    session = by_site["app/session.py:41"]
    assert session["events"] == ["arena"]
    assert (session["linked_bytes"], session["exact_linked_bytes"]) == (204800, 0)
    assert [f["function"] for f in session["frames"]] == [
        "Session.__init__",
        "SessionStore.create",
        "handle_login",
    ]
    assert session["source_hints"][0]["qualname_guess"] == "app.session.Session.__init__"
    cache = by_site["app/cache.py:12"]
    assert cache["samples"] == 3
    assert cache["linked_bytes"] == cache["exact_linked_bytes"] == 196608
    assert [n["code"] for n in out["notes"]] == ["allocations_sampled"]
    assert "warning" not in out


async def test_allocation_sites_profile_only(call, real_bin, features, contract_files) -> None:
    _, prof = contract_files
    err, out = await call("allocation_sites", {"profile": str(prof)}, heapspy_bin=real_bin)
    if not features["allocations"]:
        assert err and out["error"]["code"] == "allocations_unsupported"
        return
    assert not err, out
    assert out["mode"] == "profile_only"
    assert out["stacks_total"] == 3
    assert out["estimated_bytes"] == (2 << 20) + (1 << 20) + 3 * 65536
    assert [s["allocated_in"] for s in out["top_stacks"]] == [
        "app/reports.py:57",
        "app/session.py:41",
        "app/cache.py:12",
    ]
    assert out["top_stacks"][1]["frames"][2] == {
        "function": "handle_login",
        "file": "app/views.py",
        "line": 120,
        "location": "app/views.py:120",
        "approximate": None,
    }


async def test_heap_summary_and_type_detail_with_allocations(
    call, real_bin, features, contract_files
) -> None:
    snap, prof = contract_files
    err, out = await call(
        "heap_summary", {"snapshot": str(snap), "allocations": str(prof)}, heapspy_bin=real_bin
    )
    if not features["allocations"]:
        assert err and out["error"]["code"] == "allocations_unsupported"
        return
    assert not err, out
    by_type = {r["type"]: r for r in out["top_retainers"]}
    sessions = by_type["builtins.list"]["allocated_at"]
    assert sessions["linked_objects"] == 200 and sessions["exact_linked_bytes"] == 0
    assert sessions["stacks"][0]["allocated_in"] == "app/session.py:41"
    assert sessions["stacks"][0]["top_stack_rank"] == 2
    cache = by_type["builtins.dict"]["allocated_at"]
    assert cache["exact_linked_bytes"] == 196608
    assert out["allocations"]["coverage"]["linked_pct"] > 90

    err, detail = await call(
        "type_detail",
        {"snapshot": str(snap), "type": "Session", "allocations": str(prof), "top": 2},
        heapspy_bin=real_bin,
    )
    assert not err, detail
    at = detail["top_instances"][0]["allocated_at"]
    assert at["linked_objects"] == 1 and at["linked_bytes"] == 1024
    assert at["stacks"][0]["allocated_in"] == "app/session.py:41"
    assert at["stacks"][0]["top_stack_rank"] is None
    assert [n["code"] for n in detail["allocations"]["notes"]] == ["allocations_sampled"]


def test_analyze_allocations_matches_fixture_fields(real_cli, features, contract_files) -> None:
    """The real allocations block has every field of the copied example."""
    if not features["allocations"]:
        pytest.skip("this heapspy has no --allocations")
    snap, prof = contract_files
    real = real_cli.analyze(snap, top=5, allocations=prof)
    fixture = json.loads((CLI_FIXTURES / "analyze_allocations.json").read_text())
    assert _keys(real["allocations"]) >= _keys(fixture["allocations"])
    real_ret = next(r for r in real["top_retainers"] if r["allocated_at"]["stacks"])
    assert _keys(real_ret["allocated_at"]) >= _keys(fixture["top_retainers"][0]["allocated_at"])


def test_invalid_allocations_code(real_cli, features, contract_files) -> None:
    snap, _ = contract_files
    bogus = snap.with_name("bogus.hpya")
    bogus.write_bytes(b"definitely not a profile")
    with pytest.raises(HeapspyError) as e:
        real_cli.analyze(snap, top=1, allocations=bogus)
    expected = "invalid_allocations" if features["allocations_flag"] else "allocations_unsupported"
    assert e.value.code == expected
    assert e.value.to_dict()["hint"]
