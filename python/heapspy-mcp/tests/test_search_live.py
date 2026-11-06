"""find_processes and scan_processes against real processes with known behaviour."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc")

# Two threads hashing large buffers release the GIL: about two cores busy.
BURNER = """
import hashlib, threading
buf = b"x" * (1 << 20)
def burn():
    while True:
        hashlib.sha256(buf).digest()
for _ in range(2):
    threading.Thread(target=burn, daemon=True).start()
threading.Event().wait()
"""
GROWER = """
import time
keep = []
while len(keep) < 400:
    keep.append(b"g" * (1 << 20))
    time.sleep(0.04)
time.sleep(600)
"""
FD_HOLDER = """
import os, resource, time
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (min(4096, hard), hard))
fds = [os.open("/dev/null", os.O_RDONLY) for _ in range(min(4096, hard) - 200)]
print("ready", flush=True)
time.sleep(600)
"""
ZOMBIE_PARENT = """
import os, time
for _ in range(3):
    if os.fork() == 0:
        os._exit(0)
time.sleep(600)
"""
LOCK_PINGPONG = """
import sys, threading
sys.setswitchinterval(1e-4)
lock = threading.Lock()
def worker():
    while True:
        with lock:
            pass
for _ in range(2):
    threading.Thread(target=worker).start()
"""


@pytest.fixture(scope="module")
def suspects() -> Iterator[dict[str, subprocess.Popen[bytes]]]:
    started: dict[str, subprocess.Popen[bytes]] = {}
    try:
        for name, code in [
            ("burner", BURNER),
            ("grower", GROWER),
            ("fds", FD_HOLDER),
            ("zombies", ZOMBIE_PARENT),
            ("lock", LOCK_PINGPONG),
        ]:
            started[name] = subprocess.Popen(
                [sys.executable, "-c", code, f"heapspy-suspect-{name}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if name == "fds" else subprocess.DEVNULL,
            )
        assert started["fds"].stdout is not None
        assert started["fds"].stdout.readline().strip() == b"ready"
        time.sleep(0.5)
        yield started
    finally:
        for p in started.values():
            p.kill()
        for p in started.values():
            p.wait()


def first_pids(rows: list[dict], n: int = 1) -> list[int]:
    return [r["pid"] for r in rows[:n]]


async def test_scan_puts_each_suspect_on_top(call, suspects) -> None:
    err, out = await call("scan_processes", {"window_s": 2, "limit_per_metric": 3})
    assert not err, out
    top = out["outliers_by_metric"]
    print(
        "\n[scan]",
        json.dumps(
            {
                m: [(r["pid"], r["comm"], r["value"]) for r in top[m]]
                for m in (
                    "cpu_percent_on_cpu",
                    "rss_growth_bytes_per_s",
                    "open_fds",
                    "fd_limit_used_pct",
                    "voluntary_switches_per_s",
                )
            }
        ),
        json.dumps(out["cost"]),
        json.dumps(out["skipped"]),
    )
    assert first_pids(top["cpu_percent_on_cpu"]) == [suspects["burner"].pid]
    assert first_pids(top["rss_growth_bytes_per_s"]) == [suspects["grower"].pid]
    assert first_pids(top["open_fds"]) == [suspects["fds"].pid]
    assert first_pids(top["fd_limit_used_pct"]) == [suspects["fds"].pid]
    assert first_pids(top["voluntary_switches_per_s"]) == [suspects["lock"].pid]
    cond = out["conditions"]
    zombie_rows = cond["zombies_by_parent"]["rows"]
    mine = next(z for z in zombie_rows if z["parent_pid"] == suspects["zombies"].pid)
    assert mine["zombie_count"] == 3
    assert suspects["fds"].pid in [r["pid"] for r in cond["fd_usage_above_threshold"]["rows"]]
    assert suspects["grower"].pid in [r["pid"] for r in cond["rss_grew_every_sample"]["rows"]]
    assert "outliers_by_metric" in out and "bad" not in json.dumps(list(out))


@pytest.mark.parametrize(
    ("metric", "who"),
    [
        ("cpu_percent_on_cpu", "burner"),
        ("rss_growth_bytes_per_s", "grower"),
        ("open_fds", "fds"),
        ("voluntary_switches_per_s", "lock"),
    ],
)
async def test_find_sorts_by_metric(call, suspects, metric: str, who: str) -> None:
    err, out = await call("find_processes", {"sort_by": metric, "limit": 5, "window_s": 1.5})
    assert not err, out
    assert out["processes"][0]["pid"] == suspects[who].pid, [
        (r["pid"], r["comm"], r["metrics"][metric]) for r in out["processes"]
    ]
    assert out["sorted_by"] == metric


async def test_find_filters(call, suspects) -> None:
    err, out = await call("find_processes", {"state": "Z", "window_s": 0})
    assert not err, out
    zpids = {r["pid"] for r in out["processes"] if r["ppid"] == suspects["zombies"].pid}
    assert len(zpids) == 3
    err, out = await call(
        "find_processes",
        {"parent_pid": suspects["zombies"].pid, "window_s": 0, "include_descendants": False},
    )
    assert {r["ppid"] for r in out["processes"]} == {suspects["zombies"].pid}
    err, out = await call("find_processes", {"cmdline": "heapspy-suspect-grower", "window_s": 0})
    assert [r["pid"] for r in out["processes"]] == [suspects["grower"].pid]
    err, out = await call(
        "find_processes", {"cmdline_regex": r"heapspy-suspect-(fds|lock)$", "window_s": 0}
    )
    assert {r["pid"] for r in out["processes"]} == {suspects["fds"].pid, suspects["lock"].pid}
    err, out = await call(
        "find_processes", {"pids": [suspects["burner"].pid], "is_python": True, "window_s": 0}
    )
    assert [r["pid"] for r in out["processes"]] == [suspects["burner"].pid]
    err, out = await call("find_processes", {"user": str(os.getuid()), "window_s": 0})
    assert all(r["uid"] == os.getuid() for r in out["processes"])
    err, out = await call("find_processes", {"sort_by": "bogus"})
    assert err and out["error"]["code"] == "invalid_argument"
    err, out = await call("find_processes", {"cmdline_regex": "("})
    assert err and out["error"]["code"] == "invalid_argument"


async def test_find_redacts_cmdline(call, procs_with_secret) -> None:
    err, out = await call("find_processes", {"cmdline": "heapspy-secret-test", "window_s": 0})
    assert not err, out
    text = out["processes"][0]["cmdline"]
    assert "hunter2" not in text and "<redacted>" in text


@pytest.fixture
def procs_with_secret() -> Iterator[None]:
    p = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
            "heapspy-secret-test",
            "--password",
            "hunter2",
        ],
    )
    time.sleep(0.2)
    try:
        yield
    finally:
        p.kill()
        p.wait()


def test_unreadable_and_exited_processes_are_counted(tmp_path: Path) -> None:
    import anyio

    from heapspy_mcp.system import search

    proc = tmp_path / "proc"
    (proc / "123").mkdir(parents=True)  # no stat: exited between listdir and read
    (proc / "uptime").write_text("100.0 50.0\n")
    out = anyio.run(
        lambda: search.find_processes(
            proc,
            search.Filters(),
            sort_by=None,
            descending=True,
            limit=10,
            window_s=0,
            window_cap=10,
            cgroup_root=None,
        )
    )
    assert out["processes"] == []
    assert out["skipped"]["exited_during_scan"] == 1
