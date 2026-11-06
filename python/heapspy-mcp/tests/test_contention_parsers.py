"""Parsers for the contention tools: stat field 39, schedstat timeslices,
/proc/<pid>/sched se.slice, CPU lists, sysfs cache topology and the scheduler's default slice."""

from __future__ import annotations

from pathlib import Path

import pytest

from heapspy_mcp.system import procfs as pf

FIX = Path(__file__).resolve().parent / "fixtures" / "contention"


def stat_line(pid: int, comm: str, state: str, cpu: int, utime: int = 0, ppid: int = 1) -> str:
    """A /proc/<pid>/stat line with 52 fields; field 39 is the last CPU."""
    fields = ["0"] * 52
    fields[0], fields[1], fields[2], fields[3] = str(pid), f"({comm})", state, str(ppid)
    fields[13] = str(utime)
    fields[38] = str(cpu)
    return " ".join(fields) + "\n"


def test_stat_field_39_is_last_cpu() -> None:
    st = pf.parse_pid_stat(stat_line(42, "svc worker (x)", "R", 3))
    assert st.processor == 3 and st.state == "R" and st.comm == "svc worker (x)"
    # A kernel line cut before field 39 gives no CPU rather than a wrong one.
    short = "42 (a) S " + " ".join(["0"] * 30)
    assert pf.parse_pid_stat(short).processor is None


def test_schedstat_third_field_is_timeslices() -> None:
    ss = pf.parse_pid_schedstat("1215700000 6792900000 1591\n")
    assert ss is not None and ss.timeslices == 1591 and ss.wait_ns == 6792900000
    assert pf.parse_pid_schedstat("12 34") is None


def test_sched_se_slice_on_eevdf_kernel() -> None:
    fields = pf.parse_pid_sched((FIX / "sched_6_18.txt").read_text())
    assert pf.sched_slice_ns(fields) == 2100000
    assert "se.nr_migrations" in fields
    assert "current_node=0, numa_group_id=0" not in fields


def test_sched_without_se_slice_on_cfs_kernel() -> None:
    fields = pf.parse_pid_sched((FIX / "sched_5_15.txt").read_text())
    assert pf.sched_slice_ns(fields) is None
    assert fields["se.nr_migrations"] == 42
    assert fields["se.statistics.wait_sum"] == pytest.approx(123.456789)
    assert fields["nr_involuntary_switches"] == 200


@pytest.mark.parametrize(
    ("text", "cpus"),
    [("0-3", [0, 1, 2, 3]), ("0-1,4,6-7\n", [0, 1, 4, 6, 7]), ("5", [5]), ("", [])],
)
def test_cpu_list(text: str, cpus: list[int]) -> None:
    assert pf.parse_cpu_list(text) == cpus


def test_cpu_list_malformed() -> None:
    assert pf.parse_cpu_list("3-1") is None
    assert pf.parse_cpu_list("a-b") is None
    assert pf.parse_cpu_list(None) is None


def write_cache(root: Path, cpu: int, entries: list[tuple[int, str, str, str]]) -> None:
    base = root / "devices" / "system" / "cpu" / f"cpu{cpu}" / "cache"
    for i, (level, kind, size, shared) in enumerate(entries):
        d = base / f"index{i}"
        d.mkdir(parents=True)
        (d / "level").write_text(f"{level}\n")
        (d / "type").write_text(f"{kind}\n")
        (d / "size").write_text(f"{size}\n")
        (d / "shared_cpu_list").write_text(f"{shared}\n")
        (d / "coherency_line_size").write_text("64\n")
    (base / "uevent").write_text("")


def test_cache_topology_from_sysfs(tmp_path: Path) -> None:
    write_cache(
        tmp_path,
        0,
        [
            (1, "Data", "48K", "0"),
            (1, "Instruction", "64K", "0"),
            (2, "Unified", "2048K", "0"),
            (3, "Unified", "32M", "0-3"),
        ],
    )
    topo = pf.read_cache_topology(tmp_path)
    assert [c["level"] for c in topo] == [1, 1, 2, 3]
    assert pf.cache_size(topo, 1) == 48 * 1024  # the data cache, not instruction
    assert pf.cache_size(topo, 2) == 2 * 1024 * 1024
    assert topo[3]["shared_cpu_count"] == 4
    assert pf.read_cache_topology(tmp_path / "missing") == []


@pytest.mark.parametrize(("text", "n"), [("48K", 49152), ("2048K", 2097152), ("32M", 33554432)])
def test_cache_size(text: str, n: int) -> None:
    assert pf.parse_cache_size(text) == n


def test_default_base_slice(tmp_path: Path) -> None:
    proc, sys_ = tmp_path / "proc", tmp_path / "sys"
    est = pf.default_base_slice(proc, sys_, 4, release="6.18.44")
    assert est == {**est, "slice_ns": 2100000, "estimate": True}
    assert pf.default_base_slice(proc, sys_, 4, release="6.6.10")["slice_ns"] == 2250000
    assert pf.default_base_slice(proc, sys_, 1, release="6.18")["slice_ns"] == 700000
    assert pf.default_base_slice(proc, sys_, 64, release="6.18")["slice_ns"] == 2800000
    d = sys_ / "kernel" / "debug" / "sched"
    d.mkdir(parents=True)
    (d / "base_slice_ns").write_text("3000000\n")
    got = pf.default_base_slice(proc, sys_, 4)
    assert got["slice_ns"] == 3000000 and got["estimate"] is False
