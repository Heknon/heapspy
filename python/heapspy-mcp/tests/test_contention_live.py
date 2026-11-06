"""Live re-test of the CPU-contention blind test.

The workload (``contention_workload.py``) is built from ``contention_worker.c``
into a temporary directory: service ``api`` (8 workers, 1.5 MiB working set
each) and service ``edge`` (4 workers, 16 KiB, short timer sleeps between
requests). ``cores(k)`` pins every worker to CPUs 0..k-1. With k=2, edge's
wakeups preempt api, api's timeslices get short, and each api slice pays a
fixed cost to refill its working set into the per-core cache.

Root only (the blind test ran as root, and diagnose reads kernel stacks), Linux
only, and it needs a C compiler and at least 4 CPUs. Run with ``-s`` to see the
numbers. The VM is shared, so each check takes the median over repeats and
asserts only what held with margin across runs. Every path stops the workers.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from heapspy_mcp.config import Config, DiagnosticsConfig
from heapspy_mcp.server import build_server
from tests.contention_workload import Workload, wait_for_stats

pytestmark = [
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc"),
    pytest.mark.skipif(os.geteuid() != 0, reason="root only, as the blind test ran"),
    pytest.mark.skipif(
        shutil.which("gcc") is None and shutil.which("cc") is None, reason="needs a C compiler"
    ),
    pytest.mark.skipif(
        not hasattr(os, "sched_getaffinity") or len(os.sched_getaffinity(0)) < 4,
        reason="needs 4 CPUs",
    ),
]

SETTLE_S = 2.5
GROUP_RE = r"/(api|edge)-\d+$"


def report(name: str, data: Any) -> None:
    print(f"\n[{name}] {json.dumps(data, sort_keys=True)}")


@pytest.fixture(scope="module")
def workload() -> Iterator[Workload]:
    with tempfile.TemporaryDirectory(prefix="contend-") as d:
        w = Workload(Path(d))
        w.build()
        try:
            w.start()
            wait_for_stats(w)
            yield w
        finally:
            w.stop()


def config(w: Workload, **diag: Any) -> Config:
    return Config(
        heapspy_bin=None,
        allow=[f"pid:{p}" for p in w.pids()],
        diagnostics=DiagnosticsConfig(**diag),
    )


async def tool(client: Client, name: str, args: dict[str, Any]) -> dict[str, Any]:
    res = await client.call_tool(name, args)
    assert not res.is_error, res.content[0].text
    return res.structured_content


def at_cores(w: Workload, k: int) -> None:
    w.cores(k)
    time.sleep(SETTLE_S)


async def test_two_cores_api_vs_edge(workload: Workload) -> None:
    w = workload
    at_cores(w, 2)
    sel = {"cmdline": str(w.stats), "group_by": "cmdline_regex", "group_regex": GROUP_RE}
    rows: dict[str, list[dict[str, float]]] = {"api": [], "edge": []}
    coloc = []
    async with Client(build_server(config(w))) as c:
        for _ in range(3):
            g = await tool(c, "group_cpu", {**sel, "window_s": 3, "include_members": False})
            for grp in g["groups"]:
                m = grp["metrics"]
                rows[grp["key"]].append(
                    {
                        "voluntary_share": m["voluntary_share"]["pooled"],
                        "avg_timeslice_us": m["avg_timeslice_us"]["pooled"],
                        "nonvoluntary_per_member": m["nonvoluntary_switches_per_s"]["mean"],
                        "nonvoluntary_max_to_min": m["nonvoluntary_switches_per_s"][
                            "max_to_min_ratio"
                        ],
                        "voluntary_per_member": m["voluntary_switches_per_s"]["mean"],
                        "runnable_share": m["runnable_share"]["pooled"],
                    }
                )
            co = await tool(c, "cpu_colocation", {"cmdline": str(w.stats / "api-"), "window_s": 3})
            coloc.append(co)

    def median(xs: list[float | None]) -> float | None:
        vals = [x for x in xs if x is not None]
        return statistics.median(vals) if vals else None

    med = {svc: {k: median([r[k] for r in rs]) for k in rs[0]} for svc, rs in rows.items()}
    report("2c.group_medians", med)
    # api: mostly preempted, short slices; edge: blocks on its own and wakes often.
    assert med["api"]["voluntary_share"] < 0.2
    assert med["edge"]["voluntary_share"] > 0.8
    assert med["api"]["avg_timeslice_us"] < 600  # se.slice is 2100 us here
    assert med["edge"]["voluntary_per_member"] > 1000
    assert med["api"]["runnable_share"] > 0.7

    per_run = []
    for co in coloc:
        cpus = {c["cpu"]: c for c in co["cpus"]}
        att = co["wakeup_preemption_attribution"]
        per_run.append(
            {
                "placement_api_by_cpu": co["placement"]["target_tasks_by_cpu"],
                "placement_other_by_cpu": co["placement"]["other_busy_tasks_by_cpu"],
                "colocated_wakeups_per_s_by_cpu": {
                    k: v["colocated_wakeups_per_s"] for k, v in cpus.items()
                },
                "short_sleeper_share_by_cpu": {
                    k: v["colocated_short_sleeper_wakeup_share"] for k, v in cpus.items()
                },
                "api_preemptions_per_colocated_wakeup_by_cpu": {
                    k: v["target_preemptions_per_colocated_wakeup"] for k, v in cpus.items()
                },
                "api_nonvoluntary_per_s_by_cpu": {
                    k: v["target_nonvoluntary_switches_per_s"] for k, v in cpus.items()
                },
                "api_avg_timeslice_us_pooled": co["targets"]["avg_timeslice_us_pooled"],
                "api_sched_slice_us": co["targets"]["sched_slice_us_median"],
                "correlation": att["correlation_target_nonvoluntary_vs_colocated_wakeups"],
                "top_short_sleepers": [t["pid"] for t in att["top_short_sleepers_on_target_cpus"]],
                "share_on_target_cpus": att["colocated_short_sleeper_wakeup_share_on_target_cpus"],
            }
        )
    report("2c.colocation", per_run)
    edge = set(w.pids("edge"))
    for r in per_run:
        # placement is reported per CPU for both CPUs, and every api worker is placed
        # (keys are strings after the JSON round trip)
        assert {int(k) for k in r["placement_api_by_cpu"]} == {0, 1}
        assert sum(r["placement_api_by_cpu"].values()) == 8
        # The CPU with more co-located wakeups is the one where api is preempted more, and
        # where co-located wakeups are frequent, a good part of them preempt an api worker.
        wake = {int(k): v for k, v in r["colocated_wakeups_per_s_by_cpu"].items()}
        nv = {int(k): v for k, v in r["api_nonvoluntary_per_s_by_cpu"].items()}
        assert max(wake, key=wake.get) == max(nv, key=nv.get)
        for k, ratio in r["api_preemptions_per_colocated_wakeup_by_cpu"].items():
            if wake[int(k)] >= 1000:
                assert ratio is not None and 0.1 < ratio < 1.5
    assert statistics.median(r["share_on_target_cpus"] for r in per_run) > 0.8
    tops = [p for r in per_run for p in r["top_short_sleepers"][:2]]
    assert sum(p in edge for p in tops) >= len(tops) * 0.8
    assert statistics.median(r["api_avg_timeslice_us_pooled"] for r in per_run) < 600


async def test_per_slice_cost_fit_over_core_counts(workload: Workload) -> None:
    w = workload
    sel = {
        "cmdline": str(w.stats / "api-"),
        "group_by": "none",
        "window_s": 4,
    }
    fits = []
    async with Client(build_server(config(w))) as c:
        for order in ((4, 2, 1), (1, 2, 4)):
            tokens, rates, points = [], {}, []
            for k in order:
                at_cores(w, k)
                a = w.counts()
                snap = await tool(c, "snapshot_group_metrics", {**sel, "label": f"{k} cores"})
                b = w.counts()
                served = w.served(a, b)["api"]
                tokens.append(snap["token"])
                rates[snap["token"]] = served
                points.append((k, round(served)))
            fit = await tool(c, "fit_per_slice_cost", {"tokens": tokens, "work_rates": rates})
            fits.append(fit)
            report(
                f"fit.{order}",
                {
                    "served_api_req_s": points,
                    "points": [
                        {
                            k: p[k]
                            for k in (
                                "label",
                                "cpu_us_per_unit_work",
                                "avg_timeslice_us",
                                "timeslices_per_s",
                                "units_of_work_per_timeslice",
                            )
                        }
                        for p in fit["points"]
                    ],
                    "fit": {k: v for k, v in (fit["fit"] or {}).items() if k != "meaning"},
                    "warnings": fit["warnings"],
                },
            )
    w.cores(4)
    costs = [f["fit"]["fixed_cost_per_timeslice_us"] for f in fits if f["fit"]]
    assert len(costs) == 2
    med = statistics.median(costs)
    report("fit.median_fixed_cost_per_timeslice_us", med)
    # The blind test measured about 70 us; anything in the tens of microseconds is the
    # right mechanism. A loose band, because the VM is shared.
    assert 10 <= med <= 300
    for f in fits:
        assert not f["warnings"]
        # per-request CPU rises as slices get shorter
        pts = sorted(f["points"], key=lambda p: p["units_of_work_per_timeslice"])
        assert pts[0]["cpu_us_per_unit_work"] > pts[-1]["cpu_us_per_unit_work"]


async def test_diagnose_starved_api_worker(workload: Workload) -> None:
    w = workload
    at_cores(w, 2)
    pid = w.pids("api")[0]
    async with Client(build_server(config(w))) as c:
        dx = await tool(c, "diagnose_process", {"pid": pid, "window_s": 4, "focus": "cpu"})
    w.cores(4)
    hyp = {h["id"]: h for h in dx["hypotheses"]}
    s = dx["signals"]
    report(
        "2c.diagnose",
        {
            "ranking": [(h["id"], h["score"], h["assessment"]) for h in dx["hypotheses"]],
            "signals": {
                k: s.get(k)
                for k in (
                    "cpu_cores_used",
                    "runqueue_wait_ratio",
                    "runnable_share",
                    "avg_timeslice_us",
                    "sched_slice_us",
                    "avg_timeslice_to_sched_slice_ratio",
                    "colocated_wakeups_per_s",
                    "colocated_short_sleeper_wakeup_share",
                    "voluntary_share",
                )
            },
            "spin_against": hyp["spin_waiting_or_compute"]["evidence_against"],
        },
    )
    spin = hyp["spin_waiting_or_compute"]
    # Starved, not idle: no "mostly idle" evidence against compute.
    assert not any(e["signal"] == "cpu_cores_used" for e in spin["evidence_against"])
    assert spin["assessment"] != "not_indicated"
    assert hyp["runqueue_contention"]["assessment"] == "consistent_with_measurements"
    assert hyp["short_timeslices"]["assessment"] == "consistent_with_measurements"
    assert dx["colocation"]["targets"]["tasks"] == 1


async def test_cache_probe_against_synthetic_neighbour(workload: Workload) -> None:
    w = workload
    at_cores(w, 2)  # keeps the workers off CPU 3, where the probe runs
    from heapspy_mcp.system import procfs as pf

    l2 = pf.cache_size(pf.read_cache_topology(), 2)
    if not l2:
        pytest.skip("no L2 size in sysfs")
    sizes = [16 * 1024, l2 * 3 // 4]
    async with Client(build_server(config(w, allow_load_probes=True))) as c:
        out = await tool(
            c,
            "cache_sensitivity_probe",
            {"confirm": True, "cpu": 3, "sizes_bytes": sizes, "phase_s": 0.7},
        )
    w.cores(4)
    rows = {r["working_set_bytes"]: r for r in out["sizes"]}
    report(
        "probe",
        {
            "implementation": out["implementation"],
            "rows": [
                {
                    "bytes": k,
                    "slowdown": r["slowdown_ratio"],
                    "extra_cpu_us_per_timeslice": r["extra_cpu_us_per_timeslice"],
                    "shared_avg_timeslice_us": r["shared"]["avg_timeslice_us"],
                }
                for k, r in rows.items()
            ],
        },
    )
    if out["implementation"] == "c":
        # A working set that fits the per-core cache alone slows down more when sliced
        # than one that fits L1, and pays more extra CPU per timeslice.
        small, big = rows[sizes[0]], rows[sizes[1]]
        assert big["slowdown_ratio"] > small["slowdown_ratio"] + 0.15
        assert big["extra_cpu_us_per_timeslice"] > small["extra_cpu_us_per_timeslice"] + 10
