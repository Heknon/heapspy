"""Memory-stall parsers and the kernel wait-site classifier, against fixtures."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from heapspy_mcp.system import cgroups as cg
from heapspy_mcp.system import procfs as pf
from heapspy_mcp.system import taskstats as ts
from heapspy_mcp.system import wait_categories as wc

FIX = Path(__file__).resolve().parent / "fixtures" / "system"


def fx(name: str) -> str:
    return (FIX / name).read_text()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def stack_samples() -> list[tuple[str, str, str, str]]:
    """(expected category, state, source, stack text) from kernel_stacks.txt."""
    out = []
    head = None
    lines: list[str] = []
    for line in [*fx("kernel_stacks.txt").splitlines(), "### end"]:
        if line.startswith("## "):
            continue
        if line.startswith("### "):
            if head is not None:
                cat, state, source = head.split(" ", 2)
                out.append((cat, state, source, "\n".join(lines)))
            head = line[4:]
            lines = []
        else:
            lines.append(line)
    return out


SAMPLES = stack_samples()


@pytest.mark.parametrize(
    ("category", "state", "source", "text"), SAMPLES, ids=[s[2] for s in SAMPLES]
)
def test_stack_fixture_classification(category: str, state: str, source: str, text: str) -> None:
    frames = pf.parse_stack(text)
    got = wc.classify_stack(frames, state)
    assert got.category == category, (source, frames)


def test_every_table_category_has_a_fixture() -> None:
    covered = {s[0] for s in SAMPLES}
    assert {c.name for c in wc.CATEGORIES} <= covered


def test_parse_stack_forms() -> None:
    assert pf.parse_stack("[<0>] shrink_node.isra.0+0x2b8/0x7c0\n[<0>] kcompactd+0x2e5/0x3b0") == [
        "shrink_node",
        "kcompactd",
    ]
    assert pf.parse_stack("[<ffffffff8118a6b5>] io_schedule+0x16/0x40 [ext4]\n") == ["io_schedule"]
    assert pf.parse_stack("") == [] and pf.parse_stack(None) == []
    assert pf.parse_wchan("0") is None and pf.parse_wchan("") is None
    assert pf.parse_wchan("folio_wait_bit_common\n") == "folio_wait_bit_common"


def test_wchan_only_classification() -> None:
    # A page-lock wait seen through wchan is a fault only if majflt rose.
    assert wc.classify_wchan("folio_wait_bit_common", "D", True).category == "page_fault_io"
    assert wc.classify_wchan("folio_wait_bit_common", "D", False).category == "block_io"
    assert wc.classify_wchan("hrtimer_nanosleep", "S", False).category == "nanosleep"
    assert wc.classify_wchan("mem_cgroup_handle_over_high", "S", False).category == (
        "memcg_high_throttle"
    )
    assert wc.classify_wchan(None, "R", False).category == "running"
    # wchan 0 while the state letter said S: it woke up between the two reads.
    assert wc.classify_wchan(None, "S", False).category == "running"
    assert wc.classify_wchan(None, "S", False, readable=False).category == "unavailable"
    assert wc.classify_wchan("anything", "T", False).category == "stopped_or_frozen"
    other = wc.classify_stack(["some_new_driver_wait"], "D")
    assert other.category == "other" and other.frames == ["some_new_driver_wait"]


def test_category_flags_and_meanings() -> None:
    assert {"futex", "poll", "nanosleep", "ipc_wait"} == wc.VOLUNTARY_IDLE
    assert wc.MEMORY_STALL <= wc.MEMORY_MANAGEMENT
    assert "block_io" not in wc.MEMORY_MANAGEMENT
    meanings = wc.meanings()
    assert list(meanings)[: len(wc.CATEGORIES)] == [c.name for c in wc.CATEGORIES]
    assert {"running", "other", "unavailable"} <= set(meanings)


def test_status_smaps_rollup_vmstat_meminfo() -> None:
    st = pf.parse_status_memory(fx("status_6.18.txt"))
    assert st["VmSwap"] == 0 and st["VmRSS"] > 0 and st["VmRSS"] % 1024 == 0
    sm = pf.parse_smaps_rollup(fx("smaps_rollup_6.18.txt"))
    assert sm["Rss"] == 2068 * 1024 and sm["Pss"] == 757 * 1024
    assert sm["Swap"] == 0 and sm["SwapPss"] == 0
    vm = pf.parse_vmstat(fx("vmstat_6.18.txt"))
    for key in ("pgmajfault", "workingset_refault_file", "pswpin", "allocstall_normal"):
        assert key in vm
    mi = pf.parse_kb_fields(fx("meminfo_6.18.txt"), pf.MEMINFO_KEYS)
    assert mi["SwapTotal"] == 0 and mi["MemTotal"] > mi["MemAvailable"] > 0


def test_memory_v2_tree(tmp_path: Path) -> None:
    root = tmp_path / "cgroup"
    job = root / "work.slice" / "job.scope"
    _write(root / "work.slice" / "memory.max", "268435456\n")
    _write(root / "work.slice" / "memory.high", "max\n")
    _write(job / "memory.current", "201326592\n")
    _write(job / "memory.max", "max\n")
    _write(job / "memory.high", "134217728\n")
    _write(job / "memory.swap.current", "0\n")
    _write(job / "memory.events", fx("memory_events_v2_6.6.txt"))
    _write(job / "memory.stat", fx("memory_stat_v2_6.6.txt"))
    _write(job / "memory.pressure", fx("psi_memory_cgroup_6.18.txt"))
    _write(job / "cgroup.events", fx("cgroup_events_frozen_6.18.txt"))
    _write(job / "cgroup.freeze", "1\n")
    mounts = cg.CgroupMounts(v2=root)
    pc = cg.parse_pid_cgroup("0::/work.slice/job.scope\n")
    loc = cg.locate_memory(pc, mounts)
    assert loc is not None and loc.version == "v2" and loc.dir == job
    m = cg.read_memory(loc)
    assert m["usage_bytes"] == 201326592
    assert m["max_bytes"] is None and m["high_bytes"] == 134217728
    assert m["events"] == {
        "low": 0,
        "high": 18342,
        "max": 2210,
        "oom": 3,
        "oom_kill": 1,
        "oom_group_kill": 0,
    }
    assert m["stat"]["workingset_refault_file"] == 4127718
    assert m["stat"]["pgscan"] == 9311542 and m["stat"]["pgmajfault"] == 2231409
    assert m["pressure"]["full"]["total_us"] == 647427
    assert "stat.pgscan" not in m["unavailable"]
    limits = cg.memory_limits(loc)
    assert limits == [
        {"path": "/work.slice/job.scope", "max_bytes": None, "high_bytes": 134217728},
        {"path": "/work.slice", "max_bytes": 268435456, "high_bytes": None},
    ]
    fr = cg.read_freezer(pc, mounts)
    assert fr["frozen"] is True and fr["v2"]["frozen"] is True
    _write(job / "cgroup.events", fx("cgroup_events_5.0.txt"))
    _write(job / "cgroup.freeze", "0\n")
    # Before 5.2 cgroup.events has no "frozen": unknown, not False.
    assert cg.read_freezer(pc, mounts)["v2"]["frozen"] is None


def test_memory_v1_hybrid_tree(tmp_path: Path) -> None:
    mem = tmp_path / "memory"
    frz = tmp_path / "freezer"
    v2 = tmp_path / "unified"
    job = mem / "job"
    _write(job / "memory.usage_in_bytes", "67022848\n")
    _write(job / "memory.limit_in_bytes", "67108864\n")
    _write(job / "memory.failcnt", "132281\n")
    _write(job / "memory.oom_control", fx("memory_oom_control_v1_6.18.txt"))
    _write(job / "memory.stat", fx("memory_stat_v1_6.18.txt"))
    _write(v2 / "job" / "memory.pressure", fx("psi_memory_cgroup_6.18.txt"))
    _write(frz / "job" / "freezer.state", fx("freezer_state_v1.txt"))
    _write(frz / "job" / "freezer.self_freezing", "1\n")
    _write(frz / "job" / "freezer.parent_freezing", "0\n")
    mounts = cg.parse_mountinfo(fx("mountinfo_hybrid_6.18.txt"))
    mounts.v1["memory"] = mem
    mounts.v1["freezer"] = frz
    mounts.v2 = v2
    pc = cg.parse_pid_cgroup("6:freezer:/job\n4:memory:/job\n1:cpu:/\n0::/job\n")
    loc = cg.locate_memory(pc, mounts)
    assert loc is not None and loc.version == "v1"
    assert loc.pressure_dir == v2 / "job"
    assert any("v1" in n for n in loc.notes)
    m = cg.read_memory(loc)
    assert m["usage_bytes"] == 67022848
    # The tighter of the own limit and hierarchical_memory_limit (unlimited here).
    assert m["max_bytes"] == 67108864
    assert m["events"]["max"] == 132281 and m["events"]["oom_kill"] == 0
    assert m["events"]["high"] is None and "events.high" in m["unavailable"]
    assert m["under_oom"] is False
    assert m["stat"]["pgmajfault"] == 88212  # total_ value preferred over 2665
    assert m["stat"]["workingset_refault_file"] == 0
    assert m["swap_usage_bytes"] is None and "swap_usage_bytes" in m["unavailable"]
    assert "stat.pgscan" in m["unavailable"] and "pressure_level" in m["unavailable"]
    assert m["pressure"]["some"]["avg10"] == 4.43
    fr = cg.read_freezer(pc, mounts)
    assert fr["frozen"] is True and fr["v1"]["state"] == "FROZEN" and fr["v1"]["self_freezing"]


def test_memory_v1_older_stat_and_limit() -> None:
    raw = cg.parse_flat_keyed(fx("memory_stat_v1_5.4.txt"))
    stat = cg._v1_stat(raw)
    assert stat["workingset_refault"] == 412355
    assert stat["hierarchical_memory_limit"] == 67108864
    assert cg.parse_memory_value("9223372036854771712") is None
    assert cg.parse_memory_value("max") is None
    assert cg.parse_memory_value("1024") == 1024


def test_freezer_root_cgroups_are_not_frozen(tmp_path: Path) -> None:
    mounts = cg.CgroupMounts(v2=tmp_path / "unified", v1={"freezer": tmp_path / "freezer"})
    (tmp_path / "unified").mkdir()
    (tmp_path / "freezer").mkdir()
    fr = cg.read_freezer(cg.parse_pid_cgroup("6:freezer:/\n0::/\n"), mounts)
    assert fr["frozen"] is False and "root" in fr["note"]
    fr = cg.read_freezer(cg.PidCgroups(), cg.CgroupMounts())
    assert fr["frozen"] is None and fr["unavailable_reason"]


def _taskstats_struct(version: int) -> bytes:
    raw = bytearray(400)
    struct.pack_into("H", raw, 0, version)
    for _name, (offset, _since) in ts.FIELDS.items():
        struct.pack_into("Q", raw, offset, 1000 + offset)
    struct.pack_into("I", raw, ts.PID_OFFSET, 4242)
    raw[ts.COMM_OFFSET : ts.COMM_OFFSET + 6] = b"python"
    return bytes(raw)


def test_taskstats_reply_parsing() -> None:
    stats = ts._attr(ts.TASKSTATS_TYPE_STATS, _taskstats_struct(16))
    nested = ts._attr(ts.TASKSTATS_TYPE_AGGR_TGID | 0x8000, ts._attr(2, b"\x92\x10\0\0") + stats)
    body = struct.pack("BBH", 1, 1, 0) + nested
    reply = struct.pack("IHHII", 16 + len(body), 23, 0, 2, 0) + body
    out = ts.stats_from_reply(reply)
    assert out["version"] == 16 and out["ac_pid"] == 4242 and out["ac_comm"] == "python"
    assert out["thrashing_delay_total_ns"] == 1000 + 336
    assert out["compact_delay_total_ns"] == 1000 + 360
    old = ts.parse_taskstats(_taskstats_struct(8))
    assert old["thrashing_delay_total_ns"] is None and old["swapin_delay_total_ns"] == 1056
    err = struct.pack("IHHII", 36, ts.NLMSG_ERROR, 0, 2, 0) + struct.pack("i", -1) + b"\0" * 16
    with pytest.raises(ts.TaskstatsError, match="errno 1"):
        ts.stats_from_reply(err)
