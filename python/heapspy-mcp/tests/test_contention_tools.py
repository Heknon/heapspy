"""The contention tools through the MCP server: per-call command-line length, wait-site
sampling rate, cpu_colocation and group_cpu without the allowlist, the hw_counters
fallback, and the cache_sensitivity_probe gates."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from heapspy_mcp.config import ConfigError, DiagnosticsConfig
from heapspy_mcp.system.redact import redact_cmdline

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc")


def test_cmdline_redacted_before_cut_keeps_leading_args() -> None:
    args = ["/a/very/long/path/svc-worker", "--password=hunter2", "x" * 300, "/dev/shm/api-1"]
    out = redact_cmdline(args, 60)
    assert out.startswith("/a/very/long/path/svc-worker --password=<redacted>")
    assert out.endswith("...") and len(out) == 60
    assert "hunter2" not in redact_cmdline(args, 45)
    assert redact_cmdline(args, 4096).endswith("/dev/shm/api-1")


def test_diagnostics_config_new_flags() -> None:
    c = DiagnosticsConfig.from_sources(env={})
    assert c.max_cmdline_chars == 4096 and c.allow_load_probes is False
    c = DiagnosticsConfig.from_sources(
        env={"HEAPSPY_MCP_MAX_CMDLINE_CHARS": "800", "HEAPSPY_MCP_ALLOW_LOAD_PROBES": "1"}
    )
    assert c.max_cmdline_chars == 800 and c.allow_load_probes is True
    with pytest.raises(ConfigError):
        DiagnosticsConfig.from_sources(max_cmdline_chars=5, env={})


@linux
async def test_find_processes_cmdline_max_chars(call, tmp_path: Path) -> None:
    import subprocess

    tail = "/" + "d" * 150 + "/edge-4"
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", tail])
    try:
        err, out = await call("find_processes", {"pids": [p.pid], "window_s": 0})
        assert not err, out
        short = out["processes"][0]["cmdline"]
        assert len(short) == 200 and short.endswith("...")
        err, out = await call(
            "find_processes", {"pids": [p.pid], "window_s": 0, "cmdline_max_chars": 2000}
        )
        assert out["processes"][0]["cmdline"].endswith("/edge-4")
        from heapspy_mcp.config import DiagnosticsConfig as DC

        err, out = await call(
            "find_processes",
            {"pids": [p.pid], "window_s": 0, "cmdline_max_chars": 2000},
            diagnostics=DC(max_cmdline_chars=100),
        )
        assert len(out["processes"][0]["cmdline"]) == 100
        err, out = await call("find_processes", {"pids": [p.pid], "cmdline_max_chars": 3})
        assert err and out["error"]["reason"] == "invalid_argument"
    finally:
        p.kill()
        p.wait()


@linux
async def test_wait_sites_sampled_at_rate(call) -> None:
    import subprocess

    # Sleeps about a third of the time in short timer sleeps, like the blind test's edge.
    code = (
        "import time\n"
        "while True:\n"
        "    t = time.perf_counter()\n"
        "    while time.perf_counter() - t < 0.002: pass\n"
        "    time.sleep(0.001)\n"
    )
    p = subprocess.Popen([sys.executable, "-c", code])
    try:
        allow = {"allow": [f"pid:{p.pid}"]}
        err, out = await call("process_cpu", {"pid": p.pid, "window_s": 1.0}, **allow)
        assert not err, out
        ws = out["wait_sites"]
        assert ws["rate_hz"] == 50.0
        assert ws["samples"] >= 40
        assert ws["sleeping_thread_samples"] > 0
        assert out["measurement"]["wait_site_sampling"]["samples"] == ws["samples"]
        sched = out["scheduler"]
        assert sched["avg_timeslice_us"] is not None and sched["sched_slice_us"]
        err, out = await call(
            "process_cpu", {"pid": p.pid, "window_s": 0.5, "wait_sample_rate_hz": 500}, **allow
        )
        assert out["wait_sites"]["rate_hz"] == 100.0  # the server's --max-stall-rate
    finally:
        p.kill()
        p.wait()


@linux
async def test_hw_counters_points_to_software_fallback(call, child_python) -> None:
    allow = {"allow": [f"pid:{child_python.pid}"]}
    err, out = await call("hw_counters", {"pid": child_python.pid, "window_s": 0.3}, **allow)
    assert not err, out
    if out["ipc"] is None:
        fb = out["software_fallback"]
        assert "timeslices_per_s" in fb and "context_switches_per_cpu_second" in fb
        assert any("cache_sensitivity_probe" in x and "disabled" in x for x in fb["see_also"])
    else:
        assert out["software_fallback"] is None


@linux
async def test_colocation_and_group_tools_without_allowlist(call) -> None:
    import subprocess

    p = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    try:
        err, out = await call("cpu_colocation", {"pid": p.pid, "window_s": 0.5})
        assert not err, out
        assert out["targets"]["tasks"] == 1 and out["measurement"]["samples"] >= 10
        assert out["target_tasks"][0]["on_cpu_seconds_per_s"] > 0.3
        assert out["placement"]["cpus"]
        err, out = await call("cpu_colocation", {"window_s": 0.5})
        assert err and out["error"]["reason"] == "invalid_argument"
        err, out = await call("group_cpu", {"pids": [p.pid, os.getpid()], "window_s": 0.5})
        assert not err, out
        assert out["members_measured"] == 1  # the server's own process is left out
        g = out["groups"][0]
        assert g["metrics"]["cpu_cores_used"]["sum"] > 0.3
        assert g["metrics"]["runnable_share"]["pooled"] > 0.5
        err, snap = await call(
            "snapshot_group_metrics", {"pids": [p.pid], "window_s": 0.3, "work_rate": 10.0}
        )
        assert not err and snap["token"].startswith("pg-")
        assert snap["groups"]["all"]["work"]["cpu_seconds_per_unit_work"] > 0
    finally:
        p.kill()
        p.wait()


async def test_probe_is_off_by_default_and_needs_confirm(call) -> None:
    from heapspy_mcp.config import DiagnosticsConfig as DC

    err, out = await call("cache_sensitivity_probe", {"confirm": True})
    assert err and out["error"]["reason"] == "load_probes_disabled"
    on = {"diagnostics": DC(allow_load_probes=True)}
    err, out = await call("cache_sensitivity_probe", {}, **on)
    assert err and out["error"]["reason"] == "confirmation_required"
    assert out["error"]["plan"]["working_set_bytes"]
    err, out = await call("cache_sensitivity_probe", {"confirm": True, "mode": "colocated"}, **on)
    assert err and out["error"]["reason"] == "invalid_argument"
    err, out = await call("cache_sensitivity_probe", {"confirm": True, "sizes_bytes": [1, 2]}, **on)
    assert err and out["error"]["reason"] == "invalid_argument"
