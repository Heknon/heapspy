"""An opt-in cache-sensitivity probe for hosts without hardware counters.

``cache_sensitivity_probe`` runs a small benchmark in separate processes. It
never attaches to, reads or signals the target. Per working-set size it walks
a randomly linked list of 64-byte nodes (one dependent load per cache line)
pinned to one CPU, first alone and then with that CPU shared:

- ``synthetic``: with two neighbours pinned to the same CPU, one walking a large
  buffer (it evicts the probe's working set from the per-core caches) and one
  that sleeps about 50 us between short bursts (its wakeups preempt the probe,
  which cuts the probe's timeslices short);
- ``colocated``: on the CPU where the target ran most, so the target's
  co-located tasks are the neighbours.

The probe's throughput is measured per second of its own CPU time, so the
share of the CPU it gets does not count; what remains is the extra time each
access takes after the CPU ran something else. Each phase also reads the
probe's own ``/proc/self/schedstat``, which gives its timeslice count and
an estimate of the extra CPU time per timeslice.

This measures how sensitive a synthetic workload of a given size is to cache
sharing on this host. It does not measure the target's cache misses.

The benchmark is a C program built with the host's C compiler on first use;
without one it falls back to the same benchmark in pure Python, whose
interpreter overhead per access hides much of the difference.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import anyio

from . import procfs as pf

MAX_SIZES = 6
MAX_WORKING_SET = 64 * 1024 * 1024
MIN_WORKING_SET = 4096
DEFAULT_PHASE_S = 1.0
MAX_PHASE_S = 3.0
WAKER_SLEEP_US = 50
FALLBACK_SIZES = (16 * 1024, 1024 * 1024, 1536 * 1024, 8 * 1024 * 1024)

C_SOURCE = r"""
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
typedef struct node { uint64_t next; char pad[56]; } node;
static double clk(clockid_t c) {
  struct timespec t; clock_gettime(c, &t);
  return t.tv_sec + t.tv_nsec * 1e-9;
}
static void sched(unsigned long long *v) {
  FILE *f = fopen("/proc/thread-self/schedstat", "r");
  v[0] = v[1] = v[2] = 0;
  if (!f) return;
  if (fscanf(f, "%llu %llu %llu", &v[0], &v[1], &v[2]) != 3) v[0] = v[1] = v[2] = 0;
  fclose(f);
}
int main(int argc, char **argv) {
  if (argc < 5) { fprintf(stderr, "usage: probe walk|waker WS_BYTES SECONDS CPU\n"); return 2; }
  int waker = strcmp(argv[1], "waker") == 0;
  size_t n = strtoull(argv[2], 0, 10) / sizeof(node);
  double dur = atof(argv[3]);
  int cpu = atoi(argv[4]);
  cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
  if (sched_setaffinity(0, sizeof set, &set) != 0) { perror("sched_setaffinity"); return 3; }
  if (n < 2) n = 2;
  node *a = aligned_alloc(64, n * sizeof(node));
  uint64_t *perm = malloc(n * sizeof(uint64_t));
  if (!a || !perm) return 4;
  for (size_t i = 0; i < n; i++) perm[i] = i;
  srand(12345);
  for (size_t i = n - 1; i > 0; i--) {
    size_t j = (size_t)rand() % (i + 1);
    uint64_t t = perm[i]; perm[i] = perm[j]; perm[j] = t;
  }
  for (size_t i = 0; i < n; i++) a[perm[i]].next = perm[(i + 1) % n];
  free(perm);
  uint64_t p = 0;
  for (size_t i = 0; i < n; i++) p = a[p].next;  /* warm up */
  unsigned long long s0[3], s1[3];
  sched(s0);
  double w0 = clk(CLOCK_MONOTONIC), c0 = clk(CLOCK_THREAD_CPUTIME_ID), w = w0;
  unsigned long long steps = 0;
  struct timespec nap = {0, WAKER_SLEEP_NS};
  while (w - w0 < dur) {
    if (waker) { nanosleep(&nap, 0); for (int k = 0; k < 64; k++) p = a[p].next; steps += 64; }
    else { for (int k = 0; k < 4096; k++) p = a[p].next; steps += 4096; }
    w = clk(CLOCK_MONOTONIC);
  }
  double c1 = clk(CLOCK_THREAD_CPUTIME_ID);
  sched(s1);
  printf("%llu %.9f %.9f %llu %llu %llu %llu\n", steps, c1 - c0, w - w0,
         s1[0] - s0[0], s1[1] - s0[1], s1[2] - s0[2], (unsigned long long)(p & 1));
  return 0;
}
""".replace("WAKER_SLEEP_NS", str(WAKER_SLEEP_US * 1000))

PY_SOURCE = r"""
import os, random, sys, time
from array import array
mode, ws, dur, cpu = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4])
os.sched_setaffinity(0, {cpu})
n = max(2, ws // 64)
perm = list(range(n)); random.Random(12345).shuffle(perm)
a = array("q", bytes(8 * 8 * n))  # one entry used per 64-byte line
for i in range(n):
    a[perm[i] * 8] = perm[(i + 1) % n] * 8
def sched():
    try:
        return [int(x) for x in open("/proc/thread-self/schedstat").read().split()[:3]]
    except OSError:
        return [0, 0, 0]
p = 0
for _ in range(n):
    p = a[p]
s0 = sched(); w0 = time.monotonic(); c0 = time.thread_time(); w = w0; steps = 0
while w - w0 < dur:
    if mode == "waker":
        time.sleep(SLEEP_S)
        for _ in range(64):
            p = a[p]
        steps += 64
    else:
        for _ in range(4096):
            p = a[p]
        steps += 4096
    w = time.monotonic()
c1 = time.thread_time(); s1 = sched()
print(steps, c1 - c0, w - w0, s1[0] - s0[0], s1[1] - s0[1], s1[2] - s0[2], p & 1)
""".replace("SLEEP_S", repr(WAKER_SLEEP_US / 1e6))


class ProbeError(Exception):
    pass


_built: dict[str, Any] = {}
_build_dirs: list[str] = []


def _cleanup_build() -> None:
    for d in _build_dirs:
        shutil.rmtree(d, ignore_errors=True)
    _build_dirs.clear()


atexit.register(_cleanup_build)


def build_helper() -> tuple[list[str], str, str | None]:
    """(argv prefix, implementation, note). Builds the C helper once per server process."""
    if "argv" in _built:
        return _built["argv"], _built["impl"], _built.get("note")
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    note = None
    if cc:
        d = tempfile.mkdtemp(prefix="heapspy-probe-")
        _build_dirs.append(d)
        src, exe = Path(d) / "probe.c", Path(d) / "probe"
        src.write_text(C_SOURCE)
        try:
            subprocess.run(
                [cc, "-O2", "-o", str(exe), str(src)],
                check=True,
                capture_output=True,
                timeout=60,
            )
            _built.update(argv=[str(exe)], impl="c")
            return _built["argv"], "c", None
        except (subprocess.SubprocessError, OSError) as e:
            note = f"C build with {cc} failed ({type(e).__name__}); using the Python benchmark"
    else:
        note = "no C compiler on PATH; using the Python benchmark"
    script = Path(tempfile.mkdtemp(prefix="heapspy-probe-")) / "probe.py"
    _build_dirs.append(str(script.parent))
    script.write_text(PY_SOURCE)
    _built.update(argv=[sys.executable, "-I", str(script)], impl="python", note=note)
    return _built["argv"], "python", note


def default_sizes(topology: list[dict[str, Any]]) -> tuple[list[int], str]:
    l1 = pf.cache_size(topology, 1)
    l2 = pf.cache_size(topology, 2)
    l3 = pf.cache_size(topology, 3)
    if not l2:
        return list(FALLBACK_SIZES), "no L2 size in sysfs; fixed sizes 16 KiB, 1, 1.5, 8 MiB"
    sizes = [min(16 * 1024, (l1 or 48 * 1024) // 3), l2 // 2, l2 * 3 // 4, l2 * 4]
    basis = "L1d / 3 (at most 16 KiB), L2 / 2, L2 x 3/4, L2 x 4"
    if l3 and l3 * 2 <= MAX_WORKING_SET and l3 * 2 > l2 * 4:
        sizes.append(l3 * 2)
        basis += ", L3 x 2"
    return sorted({max(MIN_WORKING_SET, min(x, MAX_WORKING_SET)) for x in sizes}), basis


def _parse(line: str) -> dict[str, float]:
    parts = line.split()
    if len(parts) < 6:
        raise ProbeError(f"unexpected benchmark output: {line[:200]!r}")
    steps, cpu_s, wall_s = int(parts[0]), float(parts[1]), float(parts[2])
    run_ns, wait_ns, slices = int(parts[3]), int(parts[4]), int(parts[5])
    return {
        "accesses": steps,
        "cpu_seconds": cpu_s,
        "wall_seconds": wall_s,
        "run_ns": run_ns,
        "wait_ns": wait_ns,
        "timeslices": slices,
    }


def _phase_view(x: dict[str, float]) -> dict[str, Any]:
    acc = max(x["accesses"], 1)
    return {
        "ns_per_access": round(x["cpu_seconds"] / acc * 1e9, 3),
        "accesses": int(x["accesses"]),
        "cpu_seconds": round(x["cpu_seconds"], 4),
        "cpu_share_of_wall": round(x["cpu_seconds"] / x["wall_seconds"], 3)
        if x["wall_seconds"]
        else None,
        "timeslices_per_s": round(x["timeslices"] / x["wall_seconds"], 1)
        if x["wall_seconds"]
        else None,
        "avg_timeslice_us": round(x["run_ns"] / x["timeslices"] / 1000, 1)
        if x["timeslices"]
        else None,
    }


class Children:
    """Every process the probe starts, killed (whole session) on every exit path."""

    def __init__(self) -> None:
        self.procs: list[subprocess.Popen[str]] = []

    def start(self, argv: list[str]) -> subprocess.Popen[str]:
        p = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.procs.append(p)
        return p

    def kill_all(self) -> None:
        for p in self.procs:
            if p.poll() is None:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(p.pid, signal.SIGKILL)
        for p in self.procs:
            with contextlib.suppress(Exception):
                p.wait(timeout=5)
        self.procs.clear()


async def _run_one(children: Children, argv: list[str], timeout: float) -> dict[str, float]:
    p = children.start(argv)
    out, err = await anyio.to_thread.run_sync(lambda: p.communicate(timeout=timeout))
    if p.returncode != 0:
        raise ProbeError(f"benchmark exited with {p.returncode}: {(err or '').strip()[:300]}")
    return _parse(out.strip().splitlines()[-1] if out.strip() else "")


async def run_probe(
    *,
    cpu: int,
    shared_cpu: int,
    sizes: list[int],
    phase_s: float,
    mode: str,
    neighbour_bytes: int,
) -> dict[str, Any]:
    prefix, impl, note = await anyio.to_thread.run_sync(build_helper)
    children = Children()
    rows = []
    timeout = phase_s + 30
    try:
        for ws in sizes:
            alone = await _run_one(
                children, [*prefix, "walk", str(ws), f"{phase_s:g}", str(cpu)], timeout
            )
            neighbours = []
            if mode == "synthetic":
                span = f"{phase_s + 1:g}"
                neighbours = [
                    children.start([*prefix, "walk", str(neighbour_bytes), span, str(shared_cpu)]),
                    children.start([*prefix, "waker", str(16 * 1024), span, str(shared_cpu)]),
                ]
                await anyio.sleep(0.1)
            shared = await _run_one(
                children, [*prefix, "walk", str(ws), f"{phase_s:g}", str(shared_cpu)], timeout
            )
            for p in neighbours:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(p.pid, signal.SIGKILL)
            a, s = _phase_view(alone), _phase_view(shared)
            slowdown = (
                round(s["ns_per_access"] / a["ns_per_access"], 3) if a["ns_per_access"] else None
            )
            extra = None
            if shared["timeslices"]:
                expected = shared["accesses"] * alone["cpu_seconds"] / max(alone["accesses"], 1)
                extra = round((shared["cpu_seconds"] - expected) / shared["timeslices"] * 1e6, 2)
            rows.append(
                {
                    "working_set_bytes": ws,
                    "alone": a,
                    "shared": s,
                    "slowdown_ratio": slowdown,
                    "extra_cpu_us_per_timeslice": extra,
                }
            )
    finally:
        children.kill_all()
    return {"implementation": impl, "implementation_note": note, "sizes": rows}


def target_home_cpu(proc_root: Path, pid: int, samples: int = 20) -> int | None:
    """The CPU the target's threads were last on most often, from stat field 39."""
    from collections import Counter

    seen: Counter[int] = Counter()
    base = proc_root / str(pid) / "task"
    try:
        tids = [t for t in os.listdir(base) if t.isdigit()][:64]
    except OSError:
        return None
    for _ in range(samples):
        for t in tids:
            text = pf.read_text(base / t / "stat")
            if text:
                with contextlib.suppress(ValueError, IndexError):
                    c = pf.parse_pid_stat(text).processor
                    if c is not None:
                        seen[c] += 1
    return seen.most_common(1)[0][0] if seen else None
