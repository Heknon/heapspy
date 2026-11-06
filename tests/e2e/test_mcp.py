"""Smoke test of the CLI / JSON contract between heapspy and heapspy-mcp.

Skipped unless ``HEAPSPY_MCP_DIR`` points at a checkout of
``python/heapspy-mcp``. The tools run in that project's own environment
(``uv run --project``), against the real heapspy binary and the
unbounded-cache victim, through ``mcp_driver.py``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import HERE, IS_LINUX, SLEEPER, VICTIMS, gcore, run

MCP_DIR = os.environ.get("HEAPSPY_MCP_DIR")

pytestmark = [
    pytest.mark.mcp,
    pytest.mark.skipif(not MCP_DIR, reason="HEAPSPY_MCP_DIR is not set"),
]


def ok(results: dict, key: str) -> dict:
    is_error, payload = results[key]
    assert not is_error, (key, payload)
    return payload


def test_mcp_tools_against_real_heapspy(heapspy_bin, start_victim, tmp_path, python) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is needed to run heapspy-mcp in its own environment")
    victim = start_victim(python, "unbounded_cache.py")
    core = str(gcore(victim.pid, tmp_path)) if IS_LINUX else None
    sleeper = subprocess.Popen(SLEEPER, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    args = {
        "heapspy_bin": str(heapspy_bin),
        "snapshot_dir": str(tmp_path / "mcp-snapshots"),
        "allow": ["*unbounded_cache.py*", f"pid:{sleeper.pid}"],
        "pid": victim.pid,
        "other_pid": os.getpid(),  # this pytest process: a Python, not allowlisted
        "not_python_pid": sleeper.pid,
        "core": core,
        "repo": str(VICTIMS),
    }
    (tmp_path / "args.json").write_text(json.dumps(args))
    try:
        r = run(
            [
                uv,
                "run",
                "--project",
                MCP_DIR,
                "python",
                str(HERE / "mcp_driver.py"),
                str(tmp_path / "args.json"),
            ],
            step="mcp driver",
        )
    finally:
        sleeper.kill()
        sleeper.wait(timeout=30)
    victim.kill()
    assert r.returncode == 0, r.describe()
    results = json.loads(r.stdout)

    # Process listing sees the victim and the allowlist admits it.
    listed = {p["pid"]: p for p in ok(results, "list")["processes"]}
    assert victim.pid in listed, listed
    assert listed[victim.pid]["capture_allowed"], listed[victim.pid]

    # The allowlist gate refuses a process that does not match.
    is_error, refused = results["refused"]
    assert is_error and refused["error"]["reason"] == "not_allowlisted", refused

    # An allowlisted process that is not Python: dump has no --json, so the
    # server can only pass heapspy's stderr through as code "cli_failed".
    is_error, not_python = results["not_python"]
    assert is_error, not_python
    assert not_python["error"]["code"] == "cli_failed", not_python
    assert "not a CPython process" in not_python["error"]["message"], not_python

    # Capture parses heapspy dump's summary line.
    cap = ok(results, "capture_pid")
    stats = cap["stats"]
    assert stats["objects"] and stats["edges"] and stats["roots"], cap
    assert stats["truncated"] is False, cap
    assert Path(cap["path"]).is_file()
    if core:
        assert ok(results, "capture_core")["stats"]["objects"] > 0

    # heap_summary reads analyze --json.
    summary = ok(results, "summary")
    top = summary["top_retainers"][0]
    assert top["type"] == "builtins.dict", top
    assert top["path"]["rendered"] == "sys.modules['__main__'].__dict__['CACHE']", top
    assert "__main__.CACHE" in results["hints"], results["hints"]
    assert summary["snapshot"]["python_version"].startswith(python.version)

    # retaining_path by type and by address read query --type / --retaining-path.
    targets = ok(results, "path_type")["targets"]
    assert targets, results["path_type"]
    assert all("['CACHE']" in t["paths"][0]["rendered"] for t in targets), targets
    assert ok(results, "path_addr")["targets"], results["path_addr"]

    detail = ok(results, "type_detail")
    assert detail, results["type_detail"]

    diff = ok(results, "diff")
    assert diff, results["diff"]

    # map_to_source resolves the global to the line that defines it.
    i = results["hints"].index("__main__.CACHE")
    mapped = ok(results, f"map_{i}")
    locations = [c["location"] for c in mapped["candidates"]]
    source = (VICTIMS / "unbounded_cache.py").read_text().splitlines()
    line = next(n for n, text in enumerate(source, 1) if text.startswith("CACHE = "))
    assert f"unbounded_cache.py:{line}" in locations, mapped
