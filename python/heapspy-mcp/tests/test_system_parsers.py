"""Parsers for /proc and cgroup files, against fixtures from 5.x and 6.x kernels."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from heapspy_mcp.system import cgroups as cg
from heapspy_mcp.system import procfs as pf

FIX = Path(__file__).resolve().parent / "fixtures" / "system"


def fx(name: str) -> str:
    return (FIX / name).read_text()


def test_pid_status_5x_and_6x() -> None:
    s = pf.parse_pid_status(fx("status_5.4.txt"))
    assert s["State"] == "S"
    assert s["Threads"] == 9
    assert s["voluntary_ctxt_switches"] == 15321
    assert s["nonvoluntary_ctxt_switches"] == 877
    assert s["Uid"] == 1000
    assert s["NSpid"] == [4242, 7]
    assert s["Cpus_allowed_list"] == "0-3"
    s = pf.parse_pid_status(fx("status_6.18.txt"))
    assert s["Threads"] >= 1
    assert "voluntary_ctxt_switches" in s
    assert "nonvoluntary_ctxt_switches" in s


def test_pid_stat_with_parens_in_comm() -> None:
    st = pf.parse_pid_stat(fx("stat_5.4_comm_with_parens.txt"))
    assert st.comm == "gunicorn: worker [app) x]"
    assert st.state == "S"
    assert st.ppid == 1
    assert st.majflt == 3
    assert (st.utime_ticks, st.stime_ticks) == (1204, 311)
    assert st.num_threads == 9
    assert st.starttime_ticks == 88123
    assert st.rss_pages == 15306
    assert st.processor == 2
    assert st.delayacct_blkio_ticks == 7
    st = pf.parse_pid_stat(fx("stat_6.18.txt"))
    assert st.ppid == 0 and st.delayacct_blkio_ticks is not None


def test_pid_stat_short_line_leaves_fields_none() -> None:
    st = pf.parse_pid_stat("1 (init) S 0 1 1 0 -1 0 0 0 0 0 5 6")
    assert st.utime_ticks == 5 and st.stime_ticks == 6
    assert st.processor is None and st.delayacct_blkio_ticks is None


def test_pid_schedstat_and_sched() -> None:
    ss = pf.parse_pid_schedstat("583924 33797 2\n")
    assert (ss.run_ns, ss.wait_ns, ss.timeslices) == (583924, 33797, 2)
    assert pf.parse_pid_schedstat("garbage") is None
    sched = "python3 (31806, #threads: 2)\n---\nse.exec_start : 1.0\nse.nr_migrations : 17\n"
    assert pf.parse_pid_sched_migrations(sched) == 17
    assert pf.parse_pid_sched_migrations("nothing here") is None


@pytest.mark.parametrize(
    ("name", "fields", "ctxt", "running"),
    [
        ("proc_stat_5.4.txt", 10, 1990473, 1),
        ("proc_stat_2.6_short.txt", 7, 1990473, 3),
        ("proc_stat_6.18.txt", 10, None, None),
    ],
)
def test_proc_stat(name: str, fields: int, ctxt: int | None, running: int | None) -> None:
    st = pf.parse_proc_stat(fx(name))
    assert len(st.cpu_ticks) == fields
    if fields < 8:
        assert "steal" not in st.cpu_ticks  # missing column is absent, not 0
    if ctxt is not None:
        assert st.ctxt == ctxt
        assert st.procs_running == running
    else:
        assert st.ctxt and st.procs_running is not None
    assert st.per_cpu_count >= 1


@pytest.mark.parametrize("version", [15, 16, 17])
def test_proc_schedstat_known_versions(version: int) -> None:
    ss = pf.parse_proc_schedstat(fx(f"proc_schedstat_v{version}.txt"))
    assert ss.version == version
    assert ss.note is None
    assert ss.cpus[0].cpu == 0
    if version == 15:
        assert ss.cpus[0].running_ns == 1185394588640
        assert ss.cpus[0].waiting_ns == 266371810544
        assert ss.cpus[0].timeslices == 2254453
        assert len(ss.cpus) == 2


def test_proc_schedstat_unknown_version_is_not_guessed() -> None:
    ss = pf.parse_proc_schedstat(fx("proc_schedstat_v99.txt"))
    assert ss.cpus == []
    assert "version 99" in (ss.note or "")


def test_psi() -> None:
    cpu54 = pf.parse_psi(fx("psi_cpu_5.4.txt"))
    assert cpu54["some"] == {"avg10": 12.5, "avg60": 8.03, "avg300": 2.1, "total_us": 8845310228}
    assert "full" not in cpu54  # host cpu has no full line before 5.13
    mem = pf.parse_psi(fx("psi_memory_5.4.txt"))
    assert mem["full"]["total_us"] == 630112
    io = pf.parse_psi(fx("psi_io_6.18.txt"))
    assert set(io) == {"some", "full"}


def test_loadavg_and_misc() -> None:
    la = pf.parse_loadavg("0.16 0.73 0.71 2/108 12345\n")
    assert la["runnable_entities"] == 2 and la["total_entities"] == 108
    io = pf.parse_pid_io("rchar: 4092\nwchar: 0\nread_bytes: 8192\nwrite_bytes: 0\n")
    assert io["read_bytes"] == 8192
    limits = (
        "Limit                     Soft Limit           Hard Limit           Units     \n"
        "Max open files            1024                 524288               files     \n"
    )
    assert pf.parse_nofile_limit(limits) == 1024
    assert pf.parse_nofile_limit("Max open files  unlimited unlimited files") is None
    assert pf.parse_syscall_nr("202 0x7f 0x80 0x0") == 202
    assert pf.parse_syscall_nr("running") is None
    assert pf.parse_syscall_nr("-1 0x0") is None


@pytest.mark.parametrize(
    ("wchan", "nr", "site"),
    [
        ("futex_do_wait", None, "futex"),
        ("futex_wait_queue", None, "futex"),
        ("do_epoll_wait", None, "poll_epoll_select"),
        ("hrtimer_nanosleep", None, "timer_sleep"),
        ("io_schedule", None, "block_io"),
        ("pipe_read", None, "pipe_socket"),
        ("0", 202, "futex"),
        ("0", None, "unknown"),
        ("some_other_fn", None, "other"),
    ],
)
def test_wait_site_classification(wchan: str, nr: int | None, site: str) -> None:
    assert pf.classify_wait_site(wchan, nr, 202) == site


def test_cgroup_stat_and_limits() -> None:
    v515 = cg.parse_flat_keyed(fx("cpu_stat_v2_5.15.txt"))
    assert v515["nr_throttled"] == 341 and v515["throttled_usec"] == 22130984
    v66 = cg.parse_flat_keyed(fx("cpu_stat_v2_6.6.txt"))
    assert v66["nr_periods"] == 51234 and v66["nr_bursts"] == 0
    v1 = cg.parse_flat_keyed(fx("cpu_stat_v1_6.18.txt"))
    assert "throttled_time" in v1
    assert cg.parse_cpu_max("max 100000\n") == {
        "quota_usec": None,
        "period_usec": 100000,
        "limit_cores": None,
    }
    assert cg.parse_cpu_max("50000 100000\n")["limit_cores"] == 0.5
    assert cg.parse_v1_quota("-1\n", "100000\n")["quota_usec"] is None
    assert cg.parse_v1_quota("250000", "100000")["limit_cores"] == 2.5
    assert cg.parse_cpu_list("0-3,8,10-11\n") == [0, 1, 2, 3, 8, 10, 11]


def test_mountinfo_variants() -> None:
    m = cg.parse_mountinfo(fx("mountinfo_v2_only.txt"))
    assert m.v2 == Path("/sys/fs/cgroup") and m.v1 == {}
    m = cg.parse_mountinfo(fx("mountinfo_v1_combined.txt"))
    assert m.v2 == Path("/sys/fs/cgroup/unified")
    assert m.v1["cpu"] == m.v1["cpuacct"] == Path("/sys/fs/cgroup/cpu,cpuacct")
    assert "systemd" not in m.v1
    m = cg.parse_mountinfo(fx("mountinfo_hybrid_6.18.txt"))
    assert m.v1["cpu"] == Path("/sys/fs/cgroup/cpu")
    assert m.v1["cpuacct"] == Path("/sys/fs/cgroup/cpuacct")


def test_pid_cgroup_files() -> None:
    pc = cg.parse_pid_cgroup(fx("pid_cgroup_v2_kubepods.txt"))
    assert pc.v2_path and pc.v2_path.startswith("/kubepods.slice/")
    assert pc.v1_paths == {}
    pc = cg.parse_pid_cgroup(fx("pid_cgroup_v1_cgroupfs.txt"))
    assert pc.v2_path == "/"
    assert pc.v1_paths["cpu"] == pc.v1_paths["cpuacct"]
    assert "name=systemd" not in pc.v1_paths


@pytest.mark.parametrize(
    ("path", "uid", "qos", "cid", "runtime"),
    [
        (
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod5f1a7c2e_3b9d_4e8a_"
            "9c61_2d4f8b7a1e03.slice/cri-containerd-" + "ab" * 32 + ".scope",
            "5f1a7c2e-3b9d-4e8a-9c61-2d4f8b7a1e03",
            "Burstable",
            "ab" * 32,
            "cri-containerd",
        ),
        (
            "/kubepods.slice/kubepods-pod11111111_2222_3333_4444_555555555555.slice/crio-"
            + "cd" * 32
            + ".scope",
            "11111111-2222-3333-4444-555555555555",
            "Guaranteed",
            "cd" * 32,
            "crio",
        ),
        (
            "/kubepods/besteffort/pod0b8e2f61-9a4c-4d37-8e15-6c2a9f3b7d40/" + "ef" * 32,
            "0b8e2f61-9a4c-4d37-8e15-6c2a9f3b7d40",
            "BestEffort",
            "ef" * 32,
            None,
        ),
        (
            "/kubepods/pod0b8e2f61-9a4c-4d37-8e15-6c2a9f3b7d40",
            "0b8e2f61-9a4c-4d37-8e15-6c2a9f3b7d40",
            "Guaranteed",
            None,
            None,
        ),
        (
            "/../../kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod0b8e2f61_"
            "9a4c_4d37_8e15_6c2a9f3b7d40.slice/docker-" + "12" * 32 + ".scope",
            "0b8e2f61-9a4c-4d37-8e15-6c2a9f3b7d40",
            "BestEffort",
            "12" * 32,
            "docker",
        ),
    ],
)
def test_kubepods_paths(path, uid, qos, cid, runtime) -> None:
    k = cg.parse_kubepods_path(path)
    assert k is not None
    assert k["pod_uid"] == uid
    assert k["qos_class"] == qos
    assert k["container_id"] == cid
    assert k.get("container_runtime") == runtime


def test_kubepods_non_matches() -> None:
    assert cg.parse_kubepods_path("/system.slice/sshd.service") is None
    assert cg.parse_kubepods_path("/") is None
    above = cg.parse_kubepods_path("/kubepods.slice/kubepods-burstable.slice")
    assert above is not None and above["pod_uid"] is None


# --- fake cgroupfs trees ------------------------------------------------------


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the fake kubepods cgroup path is longer than Windows' MAX_PATH",
)
def test_locate_and_read_v2_tree(tmp_path: Path) -> None:
    root = tmp_path / "cgroup"
    pod = (
        "kubepods.slice/kubepods-burstable.slice/"
        "kubepods-burstable-pod5f1a7c2e_3b9d_4e8a_9c61_2d4f8b7a1e03.slice"
    )
    ctr = f"{pod}/cri-containerd-{'ab' * 32}.scope"
    _write(root / "cpu.stat", "usage_usec 1\n")
    _write(root / pod / "cpu.max", "200000 100000\n")
    _write(root / pod / "cpu.stat", fx("cpu_stat_v2_5.15.txt"))
    _write(root / ctr / "cpu.max", "max 100000\n")
    _write(root / ctr / "cpu.stat", fx("cpu_stat_v2_6.6.txt"))
    _write(root / ctr / "cpu.pressure", fx("psi_memory_5.4.txt"))
    _write(root / ctr / "cpuset.cpus.effective", "0-1\n")
    pc = cg.parse_pid_cgroup(f"0::/{ctr}\n")
    loc = cg.locate(pc, cg.CgroupMounts(v2=root))
    assert loc is not None and loc.version == "v2"
    assert loc.cpu_dir == root / ctr
    stat = cg.read_cpu_stat(loc)
    assert stat["nr_throttled"] == 1022 and stat["usage_usec"] == 1329334661
    assert cg.read_limit(loc, root / ctr)["quota_usec"] is None
    levels = cg.limited_ancestors(loc)
    assert levels == [root / ctr, root / pod]  # own cgroup, then the ancestor with a quota
    assert cg.read_limit(loc, levels[1])["limit_cores"] == 2.0
    assert cg.read_pressure(loc)["cpu"]["full"]["total_us"] == 630112
    assert cg.read_pressure(loc)["io"] is None
    assert cg.read_cpuset(loc) == [0, 1]
    assert cg.parse_kubepods_path(loc.path)["qos_class"] == "Burstable"


def test_locate_v1_hybrid_tree(tmp_path: Path) -> None:
    cpu = tmp_path / "cpu"
    acct = tmp_path / "cpuacct"
    v2 = tmp_path / "unified"
    _write(cpu / "job" / "cpu.cfs_quota_us", "20000\n")
    _write(cpu / "job" / "cpu.cfs_period_us", "100000\n")
    _write(cpu / "job" / "cpu.stat", "nr_periods 10\nnr_throttled 9\nthrottled_time 750000000\n")
    _write(cpu / "cpu.cfs_quota_us", "-1\n")
    _write(cpu / "cpu.cfs_period_us", "100000\n")
    _write(acct / "job" / "cpuacct.usage", "2000000000\n")
    _write(acct / "job" / "cpuacct.usage_user", "1500000000\n")
    _write(acct / "job" / "cpuacct.usage_sys", "500000000\n")
    _write(v2 / "cpu.pressure", fx("psi_cpu_5.4.txt"))
    mounts = cg.CgroupMounts(v2=v2, v1={"cpu": cpu, "cpuacct": acct})
    pc = cg.parse_pid_cgroup("3:cpuacct:/job\n2:cpu:/job\n0::/\n")
    loc = cg.locate(pc, mounts)
    assert loc is not None and loc.version == "v1+v2"
    stat = cg.read_cpu_stat(loc)
    assert stat == {
        "nr_periods": 10,
        "nr_throttled": 9,
        "throttled_usec": 750000,
        "usage_usec": 2000000,
        "user_usec": 1500000,
        "system_usec": 500000,
    }
    assert cg.read_limit(loc, cpu / "job")["limit_cores"] == 0.2
    assert cg.read_pressure(loc)["cpu"]["some"]["avg10"] == 12.5
    # cpuacct in a different cgroup from cpu: usage is not attributed to the cpu cgroup.
    pc = cg.parse_pid_cgroup("3:cpuacct:/\n2:cpu:/job\n0::/\n")
    loc = cg.locate(pc, mounts)
    assert loc is not None and not loc.cpuacct_matches
    assert cg.read_cpu_stat(loc)["usage_usec"] is None


def test_path_outside_cgroup_namespace(tmp_path: Path) -> None:
    root = tmp_path / "host-cgroup"
    (root / "kubepods.slice").mkdir(parents=True)
    pc = cg.parse_pid_cgroup("0::/../../kubepods.slice\n")
    loc = cg.locate(pc, cg.CgroupMounts(v2=root))
    assert loc is not None and loc.cpu_dir == root / "kubepods.slice"
    assert any("namespace" in n for n in loc.notes)
