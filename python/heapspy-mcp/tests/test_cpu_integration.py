"""The CPU tools against the real py-spy and real CPython processes.

Off by default. Run with:

    HEAPSPY_MCP_PYSPY_TESTS=1 uv run pytest -m pyspy_integration

Interpreters come from HEAPSPY_MCP_TEST_PYTHONS (separated by os.pathsep), else
python3.12, python3.13 and python3.14 where they exist. If
HEAPSPY_MCP_PYSPY_REPORT names a file, a JSON line with the key numbers of
each run is appended to it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from heapspy_mcp.config import Config, resolve_py_spy
from heapspy_mcp.server import build_server

HERE = Path(__file__).resolve().parent

pytestmark = [
    pytest.mark.pyspy_integration,
    pytest.mark.skipif(
        os.environ.get("HEAPSPY_MCP_PYSPY_TESTS") != "1",
        reason="set HEAPSPY_MCP_PYSPY_TESTS=1 to run the py-spy integration tests",
    ),
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only"),
]


def _pythons() -> list[str]:
    configured = os.environ.get("HEAPSPY_MCP_TEST_PYTHONS")
    names = (
        configured.split(os.pathsep)
        if configured
        else ["/usr/bin/python3.12", "/usr/local/bin/python3.13", "python3.14"]
    )
    return [n for n in names if n]


PYTHONS = _pythons()


def _version(python: str) -> str:
    return python.rsplit("python", 1)[-1] or python


@pytest.fixture(params=PYTHONS, ids=_version)
def python(request) -> str:
    path = shutil.which(request.param)
    if path is None:
        pytest.skip(f"{request.param} not found")
    return path


@pytest.fixture
def py_spy() -> Path:
    found = resolve_py_spy(None)
    if found is None:
        pytest.skip("py-spy not found (uv sync --extra pyspy)")
    return found


@pytest.fixture
def victim(python: str, tmp_path: Path):
    procs: list[subprocess.Popen[str]] = []

    def start(mode: str) -> subprocess.Popen[str]:
        proc = subprocess.Popen(
            [python, str(HERE / "cpu_victims.py"), mode, str(tmp_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )
        procs.append(proc)
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "ready"
        time.sleep(0.5)  # let the threads reach their steady state
        return proc

    yield start
    for proc in procs:
        proc.kill()
        proc.wait()


@pytest.fixture
def run(py_spy: Path, tmp_path: Path):
    async def call(proc: subprocess.Popen[str], tool: str, args: dict[str, Any]) -> Any:
        config = Config(
            heapspy_bin=None,
            snapshot_dir=tmp_path / "snaps",
            allow=[f"pid:{proc.pid}"],
            py_spy_bin=py_spy,
        )
        async with Client(build_server(config)) as client:
            result = await client.call_tool(tool, {"pid": proc.pid, **args})
        assert not result.is_error, result.content[0].text
        return result.structured_content

    return call


def report(python: str, victim: str, data: dict[str, Any]) -> None:
    path = os.environ.get("HEAPSPY_MCP_PYSPY_REPORT")
    if path:
        with open(path, "a") as f:
            f.write(json.dumps({"python": _version(python), "victim": victim, **data}) + "\n")


async def test_cpu_bound_loop(victim, run, python) -> None:
    proc = victim("burn")
    out = await run(proc, "cpu_profile", {"duration_s": 3})
    assert out["top_self"][0]["function"] == "burn_cpu"
    assert out["top_self"][0]["pct_of_samples"] > 90
    assert out["split"]["on_cpu"]["pct_of_samples"] > 80
    top = await run(proc, "cpu_top", {"duration_s": 3})
    assert top["top_functions"][0]["function"] == "burn_cpu"
    assert top["cpu_pct_of_one_core"] > 70
    report(
        python,
        "a_cpu_bound",
        {
            "top_self": out["top_self"][0],
            "on_cpu_pct": out["split"]["on_cpu"]["pct_of_samples"],
            "samples": out["samples"]["total"],
            "py_spy_errors": out["samples"]["py_spy_errors"],
            "cpu_pct_of_one_core": top["cpu_pct_of_one_core"],
        },
    )


async def test_blocked_threads(victim, run, python) -> None:
    proc = victim("sleep")
    out = await run(proc, "cpu_stacks", {})
    threads = {t["name"] or "MainThread": t for t in out["threads"]}
    assert set(threads) >= {"MainThread", "reader"}
    for t in threads.values():
        assert t["active"] is False
        assert t["owns_gil"] is False
        assert t["os_state"]["code"] == "S"
        assert t["os_state"]["label"] == "sleeping (blocked in a syscall)"
    assert threads["MainThread"]["frames"][0]["function"] == "sleep_forever"
    assert threads["reader"]["frames"][0]["function"] == "read_socket"
    top = await run(proc, "cpu_top", {"duration_s": 3})
    used = top["cpu_seconds_user"] + top["cpu_seconds_system"]
    assert used < 0.15
    assert top["samples"]["total"] == 0
    report(
        python,
        "b_blocked",
        {
            "threads": {n: {"active": t["active"], **t["os_state"]} for n, t in threads.items()},
            "cpu_seconds": round(used, 3),
            "wall_seconds": top["wall_seconds"],
            "on_cpu_samples": top["samples"]["total"],
        },
    )


async def test_gil_contention(victim, run, python) -> None:
    proc = victim("gil")
    out = await run(proc, "cpu_profile", {"duration_s": 3})
    gil = out["gil"]
    assert gil["held_pct_of_ticks"] >= 80
    assert gil["threads_that_held_gil"] >= 3
    assert gil["futex_waiters_avg"] >= 2
    assert gil["contention"] == "likely"
    assert out["top_self"][0]["function"] == "contend"
    assert out["os_thread_states"]["pct_of_samples"]["sleeping_futex"] > 40
    top = await run(proc, "cpu_top", {"duration_s": 3})
    # Four CPU-bound threads, but the GIL lets only one run Python code at a time.
    assert top["cpu_pct_of_one_core"] < 160
    report(
        python,
        "c_gil",
        {
            "gil": {k: gil[k] for k in gil if k != "explanation"},
            "split_pct": {
                k: out["split"][k]["pct_of_samples"]
                for k in ("on_cpu", "idle", "gil_held", "on_cpu_without_gil")
            },
            "os_states": out["os_thread_states"]["pct_of_samples"],
            "cpu_pct_of_one_core": top["cpu_pct_of_one_core"],
        },
    )


async def test_disk_io(victim, run, python) -> None:
    proc = victim("fsync")
    stacks = await run(proc, "cpu_stacks", {})
    top = await run(proc, "cpu_top", {"duration_s": 3})
    prof = await run(proc, "cpu_profile", {"duration_s": 3, "include_idle": True})
    assert prof["top_self"][0]["function"] == "fsync_loop"
    states = prof["os_thread_states"]["pct_of_samples"]
    # The thread is running, in disk wait, or briefly asleep; it is never only running.
    assert states.get("running", 0) < 100
    if top["cpu_usage"]["delay_accounting_enabled"]:
        assert top["iowait_seconds"] is not None
    else:
        assert top["iowait_seconds"] is None
    report(
        python,
        "d_fsync",
        {
            "stacks_os_state": stacks["threads"][0]["os_state"],
            "stacks_active": stacks["threads"][0]["active"],
            "iowait_seconds": top["iowait_seconds"],
            "delay_accounting": top["cpu_usage"]["delay_accounting_enabled"],
            "cpu_seconds_user": top["cpu_seconds_user"],
            "cpu_seconds_system": top["cpu_seconds_system"],
            "wall_seconds": top["wall_seconds"],
            "on_cpu_pct_of_samples": prof["split"]["on_cpu"]["pct_of_samples"],
            "os_states": states,
        },
    )
