"""Live memory-stall scenarios: real cgroups, a real file-backed working set.

Root only (they create cgroups); skipped otherwise. Run with ``-s`` to see the
numbers each scenario measured. Every scenario removes its cgroups and its
temporary file on every path, including failures.

Scenario (a) needs real eviction. On the development VM there is no swap, so the
thrash is file-backed: a process maps a 256 MiB file and reads one byte of each
page in a fixed random order, inside a memory cgroup limited to 64 MiB. The
file's page cache is dropped first (``POSIX_FADV_DONTNEED`` on that file only),
otherwise the pages stay charged to the cgroup that wrote them and the scanner
never faults. A random order matters: a sequential scan is served by
readahead, so most faults find the page already in cache (minor faults) and
the major-fault count stays low even while the cgroup refaults gigabytes.

The VM's disk is served from the host's cache at more than 1 GB/s, so each
refault completes in microseconds and the scanner stays on a CPU, mostly in the
kernel (a1). With a cgroup read limit on the block device (a2, 16 MiB/s) each
fault waits on the disk as it would on a slower one, and the thread stops
making progress for seconds at a time.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

import pytest

from heapspy_mcp.system import cgroups as cg

pytestmark = [
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc"),
    pytest.mark.skipif(os.geteuid() != 0, reason="needs root to create cgroups and read stacks"),
]

FILE_MIB = 256
LIMIT = 64 * 1024 * 1024
READ_BPS = 16 * 1024 * 1024
WARMUP_S = 3.0

SCANNER = """
import mmap, random, sys
f = open(sys.argv[1], "rb")
m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
order = list(range(0, len(m), 4096))
random.Random(1).shuffle(order)
while True:
    s = 0
    for off in order:
        s += m[off]
"""
SPIN = "while True: pass"


def report(name: str, data: Any) -> None:
    print(f"\n[{name}] {json.dumps(data, sort_keys=True)}")


def mounts() -> cg.CgroupMounts:
    return cg.parse_mountinfo(Path("/proc/self/mountinfo").read_text())


def _rmdir(d: Path) -> None:
    for _ in range(200):
        try:
            d.rmdir()
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"could not remove {d}")


@contextmanager
def cgroups(
    name: str, *, mem_limit: int | None = None, read_bps: int | None = None, freezer: bool = False
) -> Iterator[dict[str, Path]]:
    """Make the cgroups a scenario needs and remove them afterwards.

    Keys: ``v2`` (always, for pressure and the v2 freezer), ``memory`` (v1, or the v2
    directory when the memory controller is on v2), ``blkio`` (v1 read limit),
    ``freezer`` (v1). Skips when a needed controller is not available.
    """
    mt = mounts()
    made: dict[str, Path] = {}
    try:
        if mt.v2 is not None:
            made["v2"] = mt.v2 / name
            made["v2"].mkdir()
        if mem_limit is not None:
            if "memory" in mt.v1:
                made["memory"] = mt.v1["memory"] / name
                made["memory"].mkdir()
                (made["memory"] / "memory.limit_in_bytes").write_text(str(mem_limit))
            elif "v2" in made and (made["v2"] / "memory.max").exists():
                made["memory"] = made["v2"]
                (made["v2"] / "memory.max").write_text(str(mem_limit))
            else:
                pytest.skip("no memory controller (v1 mount, or v2 with +memory)")
        if read_bps is not None:
            dev = os.stat(tempfile.gettempdir()).st_dev
            block = Path(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}")
            if (block / "partition").exists():
                block = block.resolve().parent
            majmin = (block / "dev").read_text().strip()
            if "blkio" in mt.v1:
                made["blkio"] = mt.v1["blkio"] / name
                made["blkio"].mkdir()
                (made["blkio"] / "blkio.throttle.read_bps_device").write_text(
                    f"{majmin} {read_bps}"
                )
            elif "v2" in made and (made["v2"] / "io.max").exists():
                (made["v2"] / "io.max").write_text(f"{majmin} rbps={read_bps}")
            else:
                pytest.skip("no block I/O controller to limit reads")
        if freezer and "freezer" in mt.v1:
            made["freezer"] = mt.v1["freezer"] / name
            made["freezer"].mkdir()
        yield made
    finally:
        for key in ("freezer", "blkio", "memory", "v2"):
            d = made.get(key)
            if d is None or (key == "memory" and d == made.get("v2")):
                continue
            if key == "freezer" and d.exists():
                (d / "freezer.state").write_text("THAWED")
            if key == "v2" and (d / "cgroup.freeze").exists():
                (d / "cgroup.freeze").write_text("0")
            _rmdir(d)


def spawn_in(dirs: list[Path], code: str, *args: str) -> subprocess.Popen[bytes]:
    """A Python child that joins ``dirs`` before it runs ``code``, so all its memory is
    charged to the new cgroup from the start."""
    join = "".join(
        f"open({str(d / 'cgroup.procs')!r}, 'w').write(str(os.getpid()))\n" for d in dirs
    )
    boot = f"import os, sys\n{join}sys.argv = ['scan', *sys.argv[1:]]\nexec({code!r})\n"
    return subprocess.Popen([sys.executable, "-c", boot, *args], stdin=subprocess.DEVNULL)


def thaw(dirs: dict[str, Path]) -> None:
    """A frozen task cannot exit, so thaw before killing."""
    if "freezer" in dirs and (dirs["freezer"] / "freezer.state").exists():
        (dirs["freezer"] / "freezer.state").write_text("THAWED")
    if "v2" in dirs and (dirs["v2"] / "cgroup.freeze").exists():
        (dirs["v2"] / "cgroup.freeze").write_text("0")


@contextmanager
def started(
    p: subprocess.Popen[bytes], dirs: dict[str, Path] | None = None
) -> Iterator[subprocess.Popen[bytes]]:
    try:
        yield p
    finally:
        if dirs:
            thaw(dirs)
        with suppress(ProcessLookupError):
            os.kill(p.pid, signal.SIGCONT)
        p.kill()
        p.wait()


@pytest.fixture(scope="module")
def data_file() -> Iterator[Path]:
    """A 256 MiB file of random bytes, removed at the end of the module."""
    fd, name = tempfile.mkstemp(prefix="heapspy-stall-", suffix=".bin")
    path = Path(name)
    try:
        chunk = os.urandom(1 << 20)
        with os.fdopen(fd, "wb") as f:
            for _ in range(FILE_MIB):
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
        yield path
    finally:
        path.unlink(missing_ok=True)


def drop_cache(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    finally:
        os.close(fd)


def warm_cache(path: Path) -> None:
    with open(path, "rb") as f:
        while f.read(1 << 22):
            pass


def watch_numbers(out: dict[str, Any]) -> dict[str, Any]:
    pr = out["process"]
    cgm = out["environment"]["cgroup_memory"]
    ivs = pr["longest_no_progress_intervals"]
    return {
        "major_faults_per_s": pr["major_faults_per_s"],
        "minor_faults_per_s": pr["minor_faults_per_s"],
        "cpu_cores_used": pr["cpu_cores_used"],
        "system_share": pr["system_share"],
        "category_share": pr["category_share"],
        "memory_stall_share_of_active": pr["memory_stall_share_of_active"],
        "memory_stall_no_progress_seconds_per_s": pr["memory_stall_no_progress_seconds_per_s"],
        "longest_interval_s": ivs[0]["duration_s"] if ivs else None,
        "longest_interval_category": ivs[0]["dominant_category"] if ivs else None,
        "cgroup_refaults_per_s": cgm.get("refaults_per_s"),
        "cgroup_usage_to_max_ratio": cgm.get("usage_to_max_ratio"),
        "cgroup_max_events_in_window": (cgm.get("events_in_window") or {}).get("max"),
        "cgroup_psi_full_window_pct": ((cgm.get("pressure") or {}).get("full") or {}).get(
            "window_pct"
        ),
        "host_refaults_per_s": out["environment"]["host"]["refaults_per_s"],
        "frozen_or_stopped": out["frozen_or_stopped"]["assessment"],
    }


def allow(p: subprocess.Popen[bytes]) -> dict[str, Any]:
    return {"allow": [f"pid:{p.pid}"]}


async def test_a1_thrashing_on_a_fast_disk(call, data_file: Path) -> None:
    drop_cache(data_file)
    with cgroups(f"heapspy-a1-{os.getpid()}", mem_limit=LIMIT) as dirs:
        joined = [d for k, d in dirs.items() if k in ("v2", "memory")]
        with started(spawn_in(list(dict.fromkeys(joined)), SCANNER, str(data_file))) as p:
            time.sleep(WARMUP_S)
            err, out = await call("watch_process_stalls", {"pid": p.pid, "window_s": 5}, **allow(p))
            assert not err, out
            n = watch_numbers(out)
            report("a1.watch", n)
            assert out["measurement"]["stack_source"] == "/proc/<tid>/stack"
            assert n["major_faults_per_s"] > 1000
            assert n["cgroup_refaults_per_s"] > 1000
            assert (
                n["category_share"].get("page_fault_io", 0)
                + n["category_share"].get("direct_reclaim", 0)
                > 0.3
            )
            assert n["frozen_or_stopped"] == "not_frozen_or_stopped"


async def test_a2_thrashing_that_stops_progress(call, data_file: Path) -> None:
    drop_cache(data_file)
    with cgroups(f"heapspy-a2-{os.getpid()}", mem_limit=LIMIT, read_bps=READ_BPS) as dirs:
        joined = [d for k, d in dirs.items() if k in ("v2", "memory", "blkio")]
        with started(spawn_in(list(dict.fromkeys(joined)), SCANNER, str(data_file))) as p:
            time.sleep(WARMUP_S)
            err, out = await call("watch_process_stalls", {"pid": p.pid, "window_s": 5}, **allow(p))
            assert not err, out
            n = watch_numbers(out)
            report("a2.watch", n)
            report("a2.longest_interval", out["process"]["longest_no_progress_intervals"][0])
            # Each fault waits for one read-limited readahead window: fewer, longer faults.
            assert n["major_faults_per_s"] > 50
            assert n["cgroup_refaults_per_s"] > 100
            assert n["memory_stall_share_of_active"] > 0.8
            assert n["longest_interval_s"] > 0.5
            assert n["longest_interval_category"] in ("page_fault_io", "direct_reclaim")
            assert n["memory_stall_no_progress_seconds_per_s"] > 0.5


async def test_b_same_scan_without_a_limit(call, data_file: Path) -> None:
    warm_cache(data_file)
    with (
        cgroups(f"heapspy-b-{os.getpid()}") as dirs,
        started(spawn_in(list(dirs.values()), SCANNER, str(data_file))) as p,
    ):
        time.sleep(WARMUP_S)
        err, out = await call("watch_process_stalls", {"pid": p.pid, "window_s": 5}, **allow(p))
        assert not err, out
        n = watch_numbers(out)
        report("b.watch", n)
        assert n["major_faults_per_s"] < 5
        assert (n["memory_stall_share_of_active"] or 0) < 0.05
        assert n["longest_interval_category"] not in ("page_fault_io", "direct_reclaim")


async def test_c_cpu_bound(call) -> None:
    with started(subprocess.Popen([sys.executable, "-c", SPIN])) as p:
        time.sleep(0.5)
        err, out = await call("watch_process_stalls", {"pid": p.pid, "window_s": 3}, **allow(p))
        assert not err, out
        n = watch_numbers(out)
        report("c.watch", n)
        assert n["major_faults_per_s"] < 5
        assert (n["memory_stall_share_of_active"] or 0) < 0.05
        assert n["category_share"].get("running", 0) > 0.9
        assert n["memory_stall_no_progress_seconds_per_s"] == 0


async def test_d1_sigstopped(call) -> None:
    with started(subprocess.Popen([sys.executable, "-c", SPIN])) as p:
        time.sleep(0.3)
        os.kill(p.pid, signal.SIGSTOP)
        time.sleep(0.2)
        err, out = await call("watch_process_stalls", {"pid": p.pid, "window_s": 2}, **allow(p))
        assert not err, out
        n = watch_numbers(out)
        report("d1.watch", n)
        assert n["frozen_or_stopped"] == "stopped_by_signal_or_ptrace"
        assert n["category_share"] == {"stopped_or_frozen": 1.0}
        assert n["longest_interval_category"] == "stopped_or_frozen"
        assert (n["memory_stall_share_of_active"] or 0) == 0


@pytest.mark.parametrize("kind", ["v1_freezer", "v2_freeze"])
async def test_d2_frozen_cgroup(call, kind: str) -> None:
    with cgroups(f"heapspy-d2-{os.getpid()}", freezer=kind == "v1_freezer") as dirs:
        if kind == "v1_freezer" and "freezer" not in dirs:
            pytest.skip("no cgroup v1 freezer hierarchy")
        if kind == "v2_freeze" and not ("v2" in dirs and (dirs["v2"] / "cgroup.freeze").exists()):
            pytest.skip("no cgroup v2 cgroup.freeze")
        with started(spawn_in(list(dirs.values()), SPIN), dirs) as p:
            time.sleep(0.3)
            if kind == "v1_freezer":
                (dirs["freezer"] / "freezer.state").write_text("FROZEN")
            else:
                (dirs["v2"] / "cgroup.freeze").write_text("1")
            time.sleep(0.3)
            err, out = await call("watch_process_stalls", {"pid": p.pid, "window_s": 2}, **allow(p))
            assert not err, out
            n = watch_numbers(out)
            report(f"d2.{kind}.watch", {**n, "freezer": out["frozen_or_stopped"]["freezer"]})
            assert n["frozen_or_stopped"] == "frozen_by_cgroup_freezer"
            assert out["frozen_or_stopped"]["cgroup_frozen"] is True
            assert n["category_share"] == {"stopped_or_frozen": 1.0}
            assert (n["memory_stall_share_of_active"] or 0) == 0


def _pids(rows: list[dict[str, Any]]) -> set[int]:
    return {pid for row in rows for pid in row.get("pids", [row.get("pid")])}


async def test_e_scan_finds_the_thrashing_process(call, data_file: Path) -> None:
    drop_cache(data_file)
    with cgroups(f"heapspy-e-{os.getpid()}", mem_limit=LIMIT) as dirs:
        joined = list(dict.fromkeys(d for k, d in dirs.items() if k in ("v2", "memory")))
        with started(spawn_in(joined, SCANNER, str(data_file))) as p:
            time.sleep(WARMUP_S)
            err, out = await call("scan_processes", {"window_s": 3})
            assert not err, out
            top = out["outliers_by_metric"]["major_faults_per_s"]
            cond = out["conditions"]
            report(
                "e.scan",
                {
                    "top_major_faults": [(x["pid"] == p.pid, x["value"]) for x in top[:3]],
                    "major_faults_whole_window": cond["major_faults_whole_window"]["rows"][:3],
                    "cgroup_memory_pressure_full": [
                        {k: x[k] for k in ("cgroup", "full_window_pct", "pids")}
                        for x in cond["cgroup_memory_pressure_full"]["rows"][:3]
                    ],
                    "cost": {k: out["cost"][k] for k in ("processes_seen", "sampling_cpu_seconds")},
                },
            )
            assert top[0]["pid"] == p.pid
            assert p.pid in _pids(cond["major_faults_whole_window"]["rows"])
            own = [
                x
                for x in cond["cgroup_memory_pressure_full"]["rows"]
                if x["cgroup"].endswith(dirs["v2"].name)
            ]
            assert own and own[0]["pids"] == [p.pid]
            err, found = await call("find_processes", {"sort_by": "major_faults_per_s", "limit": 3})
            assert not err, found
            assert found["processes"][0]["pid"] == p.pid


async def test_e2_scan_lists_threads_in_a_memory_wait(call, data_file: Path) -> None:
    drop_cache(data_file)
    with cgroups(f"heapspy-e2-{os.getpid()}", mem_limit=LIMIT, read_bps=READ_BPS) as dirs:
        joined = list(dict.fromkeys(d for k, d in dirs.items() if k in ("v2", "memory", "blkio")))
        with started(spawn_in(joined, SCANNER, str(data_file))) as p:
            time.sleep(WARMUP_S)
            err, out = await call("scan_processes", {"window_s": 2})
            assert not err, out
            cond = out["conditions"]["disk_wait_in_memory_management"]
            mine = [x for x in cond["rows"] if x["pid"] == p.pid]
            report("e2.scan", {"rows": mine, "candidates": len(cond["d_state_candidates"])})
            assert mine and mine[0]["category"] == "page_fault_io"
            assert mine[0]["source"] == "stack"


async def test_e3_scan_reports_frozen_and_stopped(call) -> None:
    with cgroups(f"heapspy-e3-{os.getpid()}", freezer=True) as dirs:
        if "freezer" not in dirs and not ("v2" in dirs and (dirs["v2"] / "cgroup.freeze").exists()):
            pytest.skip("no cgroup freezer")
        with (
            started(spawn_in(list(dirs.values()), SPIN), dirs) as frozen,
            started(subprocess.Popen([sys.executable, "-c", SPIN])) as stopped,
        ):
            time.sleep(0.3)
            if "freezer" in dirs:
                (dirs["freezer"] / "freezer.state").write_text("FROZEN")
            else:
                (dirs["v2"] / "cgroup.freeze").write_text("1")
            os.kill(stopped.pid, signal.SIGSTOP)
            time.sleep(0.3)
            err, out = await call("scan_processes", {"window_s": 1})
            assert not err, out
            cond = out["conditions"]
            fz = cond["frozen_or_stopped"]
            report("e3.scan", fz)
            assert frozen.pid in _pids(fz["frozen_cgroups"])
            assert stopped.pid in {x["pid"] for x in fz["stopped_processes"]}
            # A v1-frozen task sits in D in __refrigerator: not a memory wait.
            d_rows = cond["disk_wait_in_memory_management"]
            assert frozen.pid not in {x["pid"] for x in d_rows["rows"]}
            assert frozen.pid not in {x["pid"] for x in d_rows["d_state_candidates"]}
