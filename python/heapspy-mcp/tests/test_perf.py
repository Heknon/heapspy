"""perf_event_open: a real call for software events, mocked hardware paths."""

from __future__ import annotations

import errno
import os
import sys
import time
from pathlib import Path

import pytest

from heapspy_mcp.system import perf

linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")


def _sys_tree(tmp_path: Path, devices: list[str]) -> Path:
    root = tmp_path / "sys"
    d = root / "bus" / "event_source" / "devices"
    d.mkdir(parents=True)
    for name in devices:
        (d / name).mkdir()
    return root


class FakeBackend:
    """Counts grow by ``rate[event]`` per read; ``running_fraction`` simulates multiplexing."""

    def __init__(
        self,
        fail: dict[str, int] | None = None,
        running_fraction: float = 1.0,
        fail_hw_cache: bool = False,
    ):
        self.fail = fail or {}
        self.fail_hw_cache = fail_hw_cache
        self.running_fraction = running_fraction
        self.fds: dict[int, tuple[str, int]] = {}
        self.reads: dict[int, int] = {}
        self.closed: set[int] = set()
        self.rate = {
            "cycles": 1_000_000,
            "instructions": 500_000,
            "llc_references": 20_000,
            "llc_misses": 5_000,
            "context_switches": 10,
            "cpu_migrations": 1,
            "task_clock": 1_000_000,
        }

    def open(self, spec: perf.EventSpec, tid: int) -> int:
        if self.fail_hw_cache and spec.type == perf.PERF_TYPE_HW_CACHE:
            raise OSError(errno.ENOENT, "no LL entry")
        if spec.name in self.fail:
            raise OSError(self.fail[spec.name], os.strerror(self.fail[spec.name]))
        fd = 1000 + len(self.fds)
        self.fds[fd] = (spec.name, tid)
        self.reads[fd] = 0
        return fd

    def read(self, fd: int) -> tuple[int, int, int]:
        n = self.reads[fd]
        self.reads[fd] += 1
        name = self.fds[fd][0]
        enabled = n * 1_000_000
        hw = name in ("cycles", "instructions", "llc_references", "llc_misses")
        running = int(enabled * (self.running_fraction if hw else 1.0))
        # The counter only advances while it is on the PMU.
        value = int(n * self.rate[name] * (self.running_fraction if hw else 1.0))
        return value, enabled, running

    def close(self, fd: int) -> None:
        self.closed.add(fd)


def _session(tmp_path: Path, backend: FakeBackend, devices: list[str]) -> perf.CounterSession:
    return perf.CounterSession(
        os.getpid(), sys_root=_sys_tree(tmp_path, devices), backend=backend, max_threads=1
    )


def test_mocked_success(tmp_path: Path) -> None:
    be = FakeBackend()
    s = _session(tmp_path, be, ["cpu", "software"])
    s.start()
    counters = s.stop()
    assert counters["cycles"]["value"] == 1_000_000
    assert counters["cycles"]["multiplexed"] is False
    d = perf.derived(counters, 1.0)
    assert d["ipc"] == 0.5
    assert d["llc_mpki"] == 10.0  # 5000 misses per 500000 instructions
    assert d["llc_miss_ratio"] == 0.25
    assert d["context_switches_per_s"] == 10.0
    assert be.closed == set(be.fds)


def test_mocked_multiplexing_scales(tmp_path: Path) -> None:
    be = FakeBackend(running_fraction=0.25)
    s = _session(tmp_path, be, ["cpu"])
    s.start()
    counters = s.stop()
    c = counters["cycles"]
    assert c["raw_value"] == 250_000
    assert c["running_fraction"] == 0.25
    assert c["multiplexed"] is True
    assert c["value"] == 1_000_000  # scaled by enabled/running
    assert perf.derived(counters, 1.0)["ipc"] == 0.5


def test_mocked_no_pmu(tmp_path: Path) -> None:
    hw = ["cycles", "instructions", "llc_references", "llc_misses"]
    be = FakeBackend(fail=dict.fromkeys(hw, errno.ENOENT))
    s = _session(tmp_path, be, ["software", "tracepoint", "msr"])
    s.start()
    counters = s.stop()
    for name in hw:
        assert counters[name]["value"] is None
        assert counters[name]["unavailable_reason"].startswith(
            "unavailable: no PMU exposed (common in VMs)"
        )
    d = perf.derived(counters, 1.0)
    assert d["ipc"] is None and "no PMU" in d["unavailable"]["ipc"]
    assert d["context_switches_per_s"] == 10.0  # software events still reported


def test_mocked_llc_fallback_to_generic_cache_events(tmp_path: Path) -> None:
    be = FakeBackend(fail_hw_cache=True)
    s = _session(tmp_path, be, ["cpu"])
    s.start()
    counters = s.stop()
    assert counters["llc_misses"]["value"] == 5_000
    assert "PERF_COUNT_HW_CACHE_MISSES" in counters["llc_misses"]["event"]


def test_mocked_pmu_without_event(tmp_path: Path) -> None:
    be = FakeBackend(fail={"llc_references": errno.ENOENT, "llc_misses": errno.ENOENT})
    s = _session(tmp_path, be, ["cpu"])
    s.start()
    counters = s.stop()
    # A PMU exists but has neither the LL nor the generic cache event.
    assert counters["llc_misses"]["unavailable_reason"].startswith("ENOENT: the PMU does not")
    assert counters["cycles"]["value"] == 1_000_000


def test_mocked_eacces(tmp_path: Path) -> None:
    be = FakeBackend(fail={n.name: errno.EACCES for n in perf.EVENTS})
    s = _session(tmp_path, be, ["cpu"])
    s.start()
    counters = s.stop()
    for name in ("cycles", "context_switches"):
        reason = counters[name]["unavailable_reason"]
        assert reason.startswith("EACCES: permission denied")
        assert "CAP_PERFMON" in reason
    d = perf.derived(counters, 1.0)
    assert d["context_switches_per_s"] is None
    assert "EACCES" in d["unavailable"]["context_switches_per_s"]


@linux_only
def test_real_software_events() -> None:
    s = perf.CounterSession(os.getpid(), max_threads=4)
    s.start()
    if s.events["context_switches"].error:
        pytest.skip(f"perf_event_open unavailable here: {s.events['context_switches'].error}")
    t0 = time.monotonic()
    while time.monotonic() - t0 < 0.05:
        time.sleep(0.001)  # voluntary switches
    counters = s.stop()
    assert counters["context_switches"]["value"] > 0
    assert counters["task_clock"]["value"] > 0
    d = perf.derived(counters, time.monotonic() - t0)
    assert d["context_switches_per_s"] > 0
    devices = perf.pmu_devices()
    if not perf.has_cpu_pmu(devices):
        assert counters["cycles"]["value"] is None
        assert "no PMU exposed (common in VMs)" in counters["cycles"]["unavailable_reason"]


def test_resctrl_tree(tmp_path: Path) -> None:
    root = tmp_path / "resctrl"
    assert perf.resctrl_for_pid(1, root)["available"] is False
    (root / "mon_groups" / "app").mkdir(parents=True)
    (root / "tasks").write_text("1\n2\n")
    (root / "mon_groups" / "app" / "tasks").write_text("42\n")
    for dom in ("mon_L3_00", "mon_L3_01"):
        d = root / "mon_groups" / "app" / "mon_data" / dom
        d.mkdir(parents=True)
        (d / "llc_occupancy").write_text("1048576\n")
        (d / "mbm_total_bytes").write_text("5000\n")
    r = perf.resctrl_for_pid(42, root)
    assert r["available"] is True
    assert r["llc_occupancy_bytes"] == 2 * 1048576
    assert r["l3_domains"] == 2
    assert perf.resctrl_for_pid(7, root)["available"] is False
