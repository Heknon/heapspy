"""Live scenarios on this machine: real processes, real /proc, real cgroups.

The numbers each scenario produced are printed (run with ``-s`` to see them).
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import time
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc")

NPROC = os.cpu_count() or 1

SPIN = "while True: pass"
LOCK_PINGPONG = """
import sys, threading
sys.setswitchinterval(1e-4)
lock = threading.Lock()
def worker():
    n = 0
    while True:
        with lock:
            n += 1
threads = [threading.Thread(target=worker) for _ in range(2)]
for t in threads: t.start()
for t in threads: t.join()
"""


def spawn(code: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL)


@pytest.fixture
def procs() -> Iterator[list[subprocess.Popen[bytes]]]:
    started: list[subprocess.Popen[bytes]] = []
    try:
        yield started
    finally:
        for p in started:
            p.kill()
        for p in started:
            p.wait()


def report(name: str, data: Any) -> None:
    print(f"\n[{name}] {json.dumps(data, sort_keys=True)}")


def hyp(out: dict[str, Any], hid: str) -> dict[str, Any]:
    return next(h for h in out["hypotheses"] if h["id"] == hid)


async def test_per_pid_tools_need_the_allowlist(call, procs) -> None:
    p = spawn(SPIN)
    procs.append(p)
    err, out = await call("process_cpu", {"pid": p.pid, "window_s": 0.2})
    assert err and out["error"]["reason"] == "allowlist_empty"
    err, out = await call("hw_counters", {"pid": p.pid}, allow=["pid:1"])
    assert err and out["error"]["reason"] == "not_allowlisted"
    err, out = await call("diagnose_process_cpu", {"pid": 999_999_999}, allow=["*"])
    assert err and out["error"]["reason"] == "no_such_process"


async def test_a_cpu_bound_process(call, procs) -> None:
    p = spawn(SPIN)
    procs.append(p)
    time.sleep(0.3)
    err, out = await call("process_cpu", {"pid": p.pid, "window_s": 2}, allow=[f"pid:{p.pid}"])
    assert not err, out
    cpu, cs = out["cpu"], out["context_switches"]
    report("a.process_cpu", {"cpu": cpu, "context_switches": cs, "sched": out["scheduler"]})
    assert out["measurement"]["window_s"] >= 1.9
    assert cpu["cpu_seconds_user"] > 1.0
    assert cpu["user_share"] > 0.9
    assert cs["voluntary_switches_per_s"] < 20
    err, dx = await call(
        "diagnose_process_cpu", {"pid": p.pid, "window_s": 2}, allow=[f"pid:{p.pid}"]
    )
    assert not err, dx
    report("a.ranking", [(h["id"], h["score"], h["assessment"]) for h in dx["hypotheses"]])
    lock = hyp(dx, "lock_contention")
    assert lock["assessment"] == "not_indicated"
    assert lock["rank"] > 3


async def test_b_more_busy_processes_than_cores(call, procs) -> None:
    victim = spawn(SPIN)
    procs.append(victim)
    allow = {"allow": [f"pid:{victim.pid}"]}
    time.sleep(0.3)
    err, alone = await call("process_cpu", {"pid": victim.pid, "window_s": 2}, **allow)
    assert not err, alone
    for _ in range(4 * NPROC - 1):
        procs.append(spawn(SPIN))
    time.sleep(1.0)
    err, crowded = await call("process_cpu", {"pid": victim.pid, "window_s": 2}, **allow)
    assert not err, crowded

    def pick(v: dict[str, Any]) -> dict[str, Any]:
        host = v["environment"]["host"]
        return {
            "runqueue_wait_ratio": v["scheduler"]["runqueue_wait_ratio"],
            "nonvoluntary_switches_per_s": v["context_switches"]["nonvoluntary_switches_per_s"],
            "procs_running_per_core": host["procs_running_per_core"],
            "psi_cpu_some_window_pct": host["psi"]["cpu"]["some"]["window_pct"],
        }

    a, b = pick(alone), pick(crowded)
    report("b.alone", a)
    report("b.crowded", b)
    assert b["runqueue_wait_ratio"] > a["runqueue_wait_ratio"] + 0.5
    # Not asserted: a spinning task is preempted at about the same rate whether or not
    # others wait for its CPU (each preemption just lasts longer), so non-voluntary
    # switches per second barely move here. Run-queue wait is the separating signal.
    assert b["nonvoluntary_switches_per_s"] is not None
    assert b["psi_cpu_some_window_pct"] > a["psi_cpu_some_window_pct"]
    assert b["procs_running_per_core"] > 1.0
    err, dx = await call("diagnose_process_cpu", {"pid": victim.pid, "window_s": 2}, **allow)
    assert not err, dx
    report("b.ranking", [(h["id"], h["score"], h["assessment"]) for h in dx["hypotheses"]])
    assert dx["hypotheses"][0]["id"] == "runqueue_contention"
    cache = hyp(dx, "cache_or_memory_bound_contention")
    if dx["hw"]["ipc"] is None:
        assert cache["assessment"] == "insufficient_signals"
        assert any("PMU" in u["reason"] or "perf" in u["reason"] for u in cache["unknown"])


async def test_c_lock_ping_pong(call, procs) -> None:
    p = spawn(LOCK_PINGPONG)
    procs.append(p)
    time.sleep(0.5)
    allow = {"allow": [f"pid:{p.pid}"]}
    err, out = await call("process_cpu", {"pid": p.pid, "window_s": 2}, **allow)
    assert not err, out
    cs = out["context_switches"]
    report("c.process_cpu", {"context_switches": cs, "wait_sites": out["wait_sites"]})
    assert cs["voluntary_share"] > 0.7
    assert cs["voluntary_switches_per_s"] > 200
    err, dx = await call("diagnose_process_cpu", {"pid": p.pid, "window_s": 2}, **allow)
    assert not err, dx
    report("c.ranking", [(h["id"], h["score"], h["assessment"]) for h in dx["hypotheses"]])
    lock, rq = hyp(dx, "lock_contention"), hyp(dx, "runqueue_contention")
    assert lock["score"] > 0
    busy = dx["signals"]["procs_running_per_core"]
    if busy is not None and busy >= 1.0:
        # Other load on this machine made the host CPU-contended during the window, so
        # run-queue contention is then a fair reading too; the ordering is not asserted.
        print(f"\n[c.note] host procs_running_per_core={busy}: ordering not asserted")
        return
    assert lock["rank"] < rq["rank"]


@pytest.fixture
def quota_cgroup() -> Iterator[Path]:
    """A cgroup with a 0.2-core quota: cgroup v2 cpu.max, or v1 cfs_quota_us on hybrid hosts."""
    if os.geteuid() != 0:
        pytest.skip("needs root to create a cgroup")
    name = f"heapspy-test-{os.getpid()}"
    made: list[Path] = []
    v1 = Path("/sys/fs/cgroup/cpu")
    v2 = Path("/sys/fs/cgroup")
    if (v1 / "cpu.cfs_quota_us").exists():
        d = v1 / name
        d.mkdir()
        made.append(d)
        (d / "cpu.cfs_quota_us").write_text("20000")
        acct = Path("/sys/fs/cgroup/cpuacct")
        if (acct / "cpuacct.usage").exists() and acct.resolve() != v1.resolve():
            (acct / name).mkdir()
            made.append(acct / name)
    elif "cpu" in (v2 / "cgroup.subtree_control").read_text().split():
        d = v2 / name
        d.mkdir()
        made.append(d)
        (d / "cpu.max").write_text("20000 100000")
    else:
        pytest.skip("no writable cpu controller (v1 cpu mount or v2 root with +cpu)")
    try:
        yield made[0]
    finally:
        # Fixtures are torn down in reverse order, so the busy loop placed in
        # this cgroup is usually still alive here. Move its tasks to the parent
        # first: rmdir fails on a cgroup that still has tasks.
        for d in reversed(made):
            _empty_cgroup(d)
            for _ in range(50):
                try:
                    d.rmdir()
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                warnings.warn(f"could not remove test cgroup {d}", stacklevel=1)


def _empty_cgroup(d: Path) -> None:
    """Move every task in cgroup ``d`` (v1 or v2) to its parent cgroup."""
    procs = d / "cgroup.procs"
    if not procs.exists():
        return
    for _ in range(20):
        pids = procs.read_text().split()
        if not pids:
            return
        for pid in pids:
            with contextlib.suppress(OSError):  # the task may have exited meanwhile
                (d.parent / "cgroup.procs").write_text(pid)
        time.sleep(0.05)


async def test_d_cfs_throttling(call, procs, quota_cgroup: Path) -> None:
    p = spawn(SPIN)
    procs.append(p)
    for d in [quota_cgroup, quota_cgroup.parent.parent / "cpuacct" / quota_cgroup.name]:
        if d.is_dir():
            (d / "cgroup.procs").write_text(str(p.pid))
    time.sleep(0.5)
    allow = {"allow": [f"pid:{p.pid}"]}
    err, out = await call("process_cpu", {"pid": p.pid, "window_s": 2}, **allow)
    assert not err, out
    cgv = out["environment"]["cgroup"]
    report("d.cgroup", {"own": cgv["own"], "tightest_limit_cores": cgv["tightest_limit_cores"]})
    assert cgv["path"].endswith(quota_cgroup.name)
    assert cgv["tightest_limit_cores"] == 0.2
    assert cgv["max_cfs_throttled_ratio"] > 0.5
    assert cgv["own"]["throttled_seconds"] > 0
    err, dx = await call("diagnose_process_cpu", {"pid": p.pid, "window_s": 2}, **allow)
    assert not err, dx
    report("d.ranking", [(h["id"], h["score"], h["assessment"]) for h in dx["hypotheses"]])
    assert dx["hypotheses"][0]["id"] == "cfs_throttling"
