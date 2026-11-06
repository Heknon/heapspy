"""watch_process_stalls: interval logic on synthetic samples, and a fake /proc tree."""

from __future__ import annotations

from pathlib import Path

import anyio

from heapspy_mcp.system import stalls as st

STAT = "{pid} (worker) {state} 1 1 1 0 -1 0 {minflt} 0 {majflt} 0 {utime} {stime} 0 0 20 0 1 0 100"


def sample(t: float, cpu: int, cat: str, state: str = "D", majflt: int = 0) -> st.TSample:
    return st.TSample(
        t=t,
        state=state,
        minflt=0,
        majflt=majflt,
        cpu_ticks=cpu,
        utime=cpu,
        stime=0,
        wchan=None,
        frames=["folio_wait_bit_common", "filemap_fault"] if cat == "page_fault_io" else None,
        category=cat,
        matched=None,
    )


def test_no_progress_interval_and_dominant_category() -> None:
    cats = ["running"] * 3 + ["page_fault_io"] * 8 + ["running"] * 3
    cpu = [0, 1, 2] + [2] * 8 + [3, 4, 5]
    track = st.ThreadTrack(
        7,
        "worker",
        [sample(i * 0.05, c, k) for i, (c, k) in enumerate(zip(cpu, cats, strict=False))],
    )
    ivs = st.no_progress_intervals(track)
    assert len(ivs) == 1
    iv = ivs[0]
    assert round(iv.duration, 3) == 0.4  # from the last advancing sample to the last stalled one
    view = st.interval_view(iv, 0.0)
    assert view["dominant_category"] == "page_fault_io"
    assert view["example_stack"] == ["folio_wait_bit_common", "filemap_fault"]
    assert not view["began_before_window"] and not view["still_open_at_window_end"]


def test_voluntary_idle_is_not_no_progress() -> None:
    track = st.ThreadTrack(
        8, "idle", [sample(i * 0.05, 0, "futex" if i % 2 else "poll", "S") for i in range(20)]
    )
    assert st.no_progress_intervals(track) == []
    # A thread stuck for the whole window is open at both ends.
    track = st.ThreadTrack(9, "stuck", [sample(i * 0.05, 5, "direct_reclaim") for i in range(5)])
    (iv,) = st.no_progress_intervals(track)
    assert iv.open_at_start and iv.open_at_end


def test_summary_shares_and_memory_stall_share() -> None:
    s = st.StallSampler(Path("/nonexistent"), 1)
    s.ticks = 10
    s.first_t, s.last_t = 0.0, 0.45
    s.tracks = {
        1: st.ThreadTrack(1, "main", [sample(i * 0.05, 0, "page_fault_io") for i in range(10)]),
        2: st.ThreadTrack(2, "io", [sample(i * 0.05, 0, "futex", "S") for i in range(10)]),
    }
    out = st.summarize(s)
    assert out["thread_samples"] == 20
    assert out["category_share"] == {"page_fault_io": 0.5, "futex": 0.5}
    assert out["memory_stall_share_of_active"] == 1.0
    assert out["no_progress_seconds_by_category"] == {"page_fault_io": 0.45}
    assert out["memory_stall_no_progress_seconds_per_s"] == 1.0
    assert out["threads"][0]["tid"] == 1
    assert out["longest_no_progress_intervals"][0]["tid"] == 1


def test_frozen_view_assessments() -> None:
    summary = {"category_share": {"stopped_or_frozen": 1.0}, "state_share": {"T": 1.0}}
    assert st.frozen_view({"frozen": False}, summary, "T")["assessment"] == (
        "stopped_by_signal_or_ptrace"
    )
    summary = {"category_share": {"stopped_or_frozen": 1.0}, "state_share": {"D": 1.0}}
    assert st.frozen_view({"frozen": True}, summary, "D")["assessment"] == (
        "frozen_by_cgroup_freezer"
    )
    summary = {"category_share": {"page_fault_io": 1.0}, "state_share": {"D": 1.0}}
    assert st.frozen_view({"frozen": False}, summary, "D")["assessment"] == (
        "not_frozen_or_stopped"
    )


def _thread(proc: Path, pid: int, tid: int, state: str, wchan: str, stack: str | None) -> None:
    d = proc / str(pid) / "task" / str(tid)
    d.mkdir(parents=True)
    (d / "stat").write_text(
        STAT.format(pid=tid, state=state, minflt=10, majflt=5, utime=100, stime=50) + "\n"
    )
    (d / "wchan").write_text(wchan)
    if stack is not None:
        (d / "stack").write_text(stack)


def fake_proc(tmp_path: Path, stacks: bool) -> Path:
    proc = tmp_path / "proc"
    pid = 4242
    base = proc / str(pid)
    base.mkdir(parents=True)
    (base / "stat").write_text(
        STAT.format(pid=pid, state="D", minflt=10, majflt=5, utime=100, stime=50) + "\n"
    )
    (base / "status").write_text("Name:\tworker\nVmRSS:\t   2048 kB\nVmSwap:\t      0 kB\n")
    (base / "cgroup").write_text("0::/\n")
    if stacks:
        (base / "stack").write_text("")
    fault = "[<0>] folio_wait_bit_common+0x110/0x310\n[<0>] filemap_fault+0x739/0x1650\n"
    _thread(proc, pid, pid, "D", "folio_wait_bit_common", fault if stacks else None)
    _thread(
        proc,
        pid,
        pid + 1,
        "S",
        "futex_do_wait",
        "[<0>] futex_do_wait+0x46/0x90\n" if stacks else None,
    )
    (proc / "sys" / "kernel").mkdir(parents=True)
    (proc / "sys" / "kernel" / "task_delayacct").write_text("0\n")
    (proc / "pressure").mkdir()
    (proc / "pressure" / "memory").write_text(
        "some avg10=1.00 avg60=0.00 avg300=0.00 total=100\n"
        "full avg10=1.00 avg60=0.00 avg300=0.00 total=100\n"
    )
    (proc / "vmstat").write_text("pgmajfault 10\nworkingset_refault_file 7\nallocstall_normal 0\n")
    (proc / "meminfo").write_text("MemTotal: 1000 kB\nSwapTotal: 0 kB\n")
    return proc


def test_watch_on_a_fake_tree_with_stacks(tmp_path: Path) -> None:
    proc = fake_proc(tmp_path, stacks=True)
    out = anyio.run(lambda: st.watch(proc, 4242, 0.2, 20, host=True, cgroup_root=None))
    m = out["measurement"]
    assert m["stack_source"] == "/proc/<tid>/stack" and m["threads_sampled"] == 2
    assert m["samples"] >= 3
    pr = out["process"]
    assert pr["category_share"] == {"page_fault_io": 0.5, "futex": 0.5}
    assert pr["memory_stall_share_of_active"] == 1.0
    # CPU never advanced: the faulting thread has one interval spanning the window.
    iv = pr["longest_no_progress_intervals"][0]
    assert iv["tid"] == 4242 and iv["dominant_category"] == "page_fault_io"
    assert iv["began_before_window"] and iv["still_open_at_window_end"]
    assert pr["delay_accounting"]["available"] is False
    assert "task_delayacct=1" in pr["delay_accounting"]["reason"]
    assert pr["memory"]["rss_bytes"] == 2048 * 1024 and pr["memory"]["vm_swap_bytes"] == 0
    assert out["environment"]["host"]["refaults_per_s"] == 0.0
    assert "swap_note" in out["environment"]["host"]
    assert out["frozen_or_stopped"]["assessment"] == "not_frozen_or_stopped"
    assert set(out["wait_category_meanings"]) == {"page_fault_io", "futex"}


def test_watch_without_stacks_falls_back_to_wchan(tmp_path: Path) -> None:
    proc = fake_proc(tmp_path, stacks=False)
    out = anyio.run(lambda: st.watch(proc, 4242, 0.2, 20, host=False, cgroup_root=None))
    assert out["measurement"]["stack_source"] == "wchan"
    assert "kernel_stacks" in out["unavailable"]
    # majflt never rose, so a folio wait seen only through wchan counts as block I/O.
    assert out["process"]["category_share"] == {"block_io": 0.5, "futex": 0.5}
    assert out["environment"]["host"] is None


def test_rate_is_capped(tmp_path: Path) -> None:
    proc = fake_proc(tmp_path, stacks=True)
    out = anyio.run(
        lambda: st.watch(proc, 4242, 0.1, 5000, host=False, cgroup_root=None, rate_cap_hz=50)
    )
    assert out["measurement"]["rate_hz"] == 50 and out["measurement"]["rate_hz_requested"] == 5000


async def test_tool_is_gated_by_the_allowlist(call) -> None:
    import os

    err, out = await call("watch_process_stalls", {"pid": os.getpid(), "window_s": 0.1})
    assert err and out["error"]["reason"] == "allowlist_empty"
    err, out = await call(
        "watch_process_stalls", {"pid": os.getpid(), "rate_hz": 0}, allow=[f"pid:{os.getpid()}"]
    )
    assert err and out["error"]["reason"] == "invalid_argument"


def test_scan_memory_conditions_from_a_crafted_state(tmp_path: Path) -> None:
    from heapspy_mcp.system import cgroups as cg
    from heapspy_mcp.system import search

    state = search.ScanState(tmp_path)
    for pid, comm in ((10, "thrash"), (11, "burst"), (12, "stopped")):
        state.statics[pid] = search.Static(pid, comm, 1, "S", 0, None, None, None, False, 0)
    # pid 10 faults at >= 100/s in every interval; pid 11 only in one.
    state.majflt_series[10] = [(0.0, 0), (0.5, 200), (1.0, 400), (1.5, 600), (2.0, 800)]
    state.majflt_series[11] = [(0.0, 0), (0.5, 0), (1.0, 900), (1.5, 900), (2.0, 900)]
    last = search.Counters(
        t=2.0,
        utime=0,
        stime=0,
        rss_pages=0,
        minflt=0,
        majflt=0,
        state="T",
        threads=1,
        vol=None,
        nonvol=None,
        run_ns=None,
        wait_ns=None,
        blkio=None,
        d_tids=set(),
        threads_truncated=False,
        read_bytes=None,
        write_bytes=None,
    )
    state.last[12] = last
    state.pressure["/x"] = search.PressureCounters(
        "/job",
        tmp_path,
        {"some": {"total_us": 0}, "full": {"total_us": 0}},
        {"some": {"total_us": 400_000}, "full": {"total_us": 200_000}},
        [10],
    )
    state.pressure["/"] = search.PressureCounters(
        "/", tmp_path, {"full": {"total_us": 5}}, {"full": {"total_us": 5}}, [11]
    )
    state.d_inspected = [
        {"pid": 10, "tid": 10, "category": "page_fault_io", "source": "stack"},
        {"pid": 11, "tid": 11, "category": "block_io", "source": "stack"},
        {"pid": 11, "tid": 13, "category": "stopped_or_frozen", "source": "stack"},
    ]
    state.freezers = [{"freezer": {"v2": {"path": "/frozen"}, "v1": None}, "pids": [11]}]
    mloc = cg.MemoryLocation("v2", "/job", tmp_path, tmp_path, tmp_path)
    state.memory["/job"] = search.MemoryCounters(mloc, {"oom_kill": 1}, {"oom_kill": 3}, [10])
    rows = {
        pid: {"metrics": {"major_faults_per_s": 400.0}, "cgroup": "/job"} for pid in (10, 11, 12)
    }
    facts = search._memory_conditions(state, rows, 100.0, 5, 2.0)
    assert [x["pid"] for x in facts["major_faults_whole_window"]["rows"]] == [10]
    (full,) = facts["cgroup_memory_pressure_full"]["rows"]
    assert full["cgroup"] == "/job" and full["full_window_pct"] == 10.0
    assert full["some_window_pct"] == 20.0
    d = facts["disk_wait_in_memory_management"]
    assert [x["pid"] for x in d["rows"]] == [10]
    assert [x["tid"] for x in d["d_state_candidates"]] == [11]
    fz = facts["frozen_or_stopped"]
    assert fz["frozen_cgroups"][0]["cgroup_v2"] == "/frozen"
    assert fz["stopped_processes"] == [{"pid": 12, "comm": "stopped", "state": "T"}]
    assert facts["oom_kill_counters"]["rows"][0]["oom_kill_in_window"] == 2


async def test_diagnose_process_focus_and_alias(call, child_python) -> None:
    allow = {"allow": [f"pid:{child_python.pid}"]}
    args = {"pid": child_python.pid, "window_s": 0.3}
    err, out = await call("diagnose_process", {**args, "focus": "memory"}, **allow)
    assert not err, out
    assert {h["id"] for h in out["hypotheses"]} == {
        "memory_thrashing",
        "cache_or_memory_bound_contention",
    }
    assert out["fact_checks"][0]["id"] == "deliberately_frozen"
    assert out["fact_checks"][0]["value"] is False
    assert out["memory_stalls"]["frozen_or_stopped"]["assessment"] == "not_frozen_or_stopped"
    assert out["measurement"]["stall_sampling"]["rate_hz"] == 10.0
    err, alias = await call("diagnose_process_cpu", args, **allow)
    assert not err, alias
    assert alias["focus"] == "all" and len(alias["hypotheses"]) == 10
    assert alias["colocation"]["targets"]["tasks"] == 1
    err, bad = await call("diagnose_process", {**args, "focus": "disk"}, **allow)
    assert err and bad["error"]["reason"] == "invalid_argument"
