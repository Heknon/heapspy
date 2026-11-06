"""The two-service workload of the CPU-contention blind test, built and run in a
temporary directory.

``api``: 8 workers, each walking a 1.5 MiB working set, 6500 requests/s offered.
``edge``: 4 workers with a 16 KiB working set, 20000 requests/s offered; they sleep
on short timers between requests. ``cores(k)`` pins every worker to CPUs 0..k-1,
as the blind test's ``svc.sh cores K`` did.

Each worker writes ``done timestamp`` to its stats file every 0.5 s, so the served
rate over an interval comes from the workers' own counts and clocks.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "contention_worker.c"

SERVICES = {
    # name: (workers, working set bytes, offered requests/s per worker, steps per request)
    "api": (8, 1572864, 6500, 2000),
    "edge": (4, 16384, 20000, 2000),
}


class Workload:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "contend-worker"
        self.stats = root / "stats"
        self.procs: dict[str, list[subprocess.Popen[bytes]]] = {}

    def build(self) -> None:
        cc = shutil.which("gcc") or shutil.which("cc")
        if cc is None:
            raise RuntimeError("no C compiler")
        subprocess.run([cc, "-O2", "-o", str(self.bin), str(SOURCE)], check=True)

    def start(self) -> None:
        self.stats.mkdir(exist_ok=True)
        for name, (n, ws, rate, steps) in SERVICES.items():
            self.procs[name] = []
            for i in range(1, n + 1):
                p = subprocess.Popen(
                    [
                        str(self.bin),
                        str(ws),
                        str(rate),
                        str(steps),
                        str(self.stats / f"{name}-{i}"),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                self.procs[name].append(p)

    def pids(self, name: str | None = None) -> list[int]:
        names = [name] if name else list(self.procs)
        return [p.pid for n in names for p in self.procs.get(n, [])]

    def cores(self, k: int) -> None:
        cpus = set(range(k))
        for pid in self.pids():
            for tid in os.listdir(f"/proc/{pid}/task"):
                with contextlib.suppress(OSError):
                    os.sched_setaffinity(int(tid), cpus)

    def _read(self) -> dict[str, tuple[int, float]]:
        out = {}
        for f in self.stats.iterdir():
            parts = f.read_text().split()
            if len(parts) >= 2:
                out[f.name] = (int(parts[0]), float(parts[1]))
        return out

    def counts(self) -> dict[str, tuple[int, float]]:
        return self._read()

    @staticmethod
    def served(
        a: dict[str, tuple[int, float]], b: dict[str, tuple[int, float]]
    ) -> dict[str, float]:
        """Requests/s per service between two ``counts()`` readings."""
        out = {name: 0.0 for name in SERVICES}
        for f, (n2, t2) in b.items():
            n1, t1 = a.get(f, (n2, t2))
            if t2 > t1:
                out[f.split("-")[0]] += (n2 - n1) / (t2 - t1)
        return out

    def stop(self) -> None:
        for ps in self.procs.values():
            for p in ps:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(p.pid, signal.SIGKILL)
        for ps in self.procs.values():
            for p in ps:
                with contextlib.suppress(Exception):
                    p.wait(timeout=5)
        self.procs.clear()


def wait_for_stats(w: Workload, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    want = sum(n for n, *_ in SERVICES.values())
    while time.monotonic() < deadline:
        if w.stats.is_dir() and len(list(w.stats.iterdir())) >= want:
            return
        time.sleep(0.1)
