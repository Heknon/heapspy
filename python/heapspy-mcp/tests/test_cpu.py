"""The CPU tools and their gates, against the fake py-spy."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest
from mcp import Client

from heapspy_mcp.cpu import AttachRefused, aggregate, check_target
from heapspy_mcp.pyspy import parse_folded
from heapspy_mcp.server import build_server

CPU_TOOLS = ("cpu_stacks", "cpu_profile", "cpu_top", "cpu_flamegraph")


@pytest.fixture
def cpu_call(call, fake_pyspy: Path):
    """call() with the fake py-spy configured."""

    async def run(tool: str, args: dict, **overrides):
        overrides.setdefault("py_spy_bin", fake_pyspy)
        return await call(tool, args, **overrides)

    return run


def allow(proc) -> dict:
    return {"allow": [f"pid:{proc.pid}"]}


# -- check_target -------------------------------------------------------------------


def test_check_target_needs_an_allowlist(make_config, child_python) -> None:
    with pytest.raises(AttachRefused) as e:
        check_target(make_config(allow=[]), child_python.pid)
    assert e.value.reason == "attach_disabled"
    assert e.value.to_dict()["code"] == "attach_refused"
    assert "--allow" in e.value.message


def test_check_target_not_allowlisted(make_config, child_python) -> None:
    with pytest.raises(AttachRefused) as e:
        check_target(make_config(allow=["gunicorn*", "pid:1"]), child_python.pid)
    assert e.value.reason == "not_allowlisted"
    assert e.value.to_dict()["pid"] == child_python.pid


def test_check_target_refuses_own_pid(make_config) -> None:
    with pytest.raises(AttachRefused) as e:
        check_target(make_config(allow=["*"]), os.getpid())
    assert e.value.reason == "invalid_argument"


@pytest.mark.parametrize(
    ("pid", "reason"),
    [(0, "invalid_argument"), (-5, "invalid_argument"), (2**22 + 12345, "no_such_process")],
)
def test_check_target_bad_pid(make_config, pid, reason) -> None:
    with pytest.raises(AttachRefused) as e:
        check_target(make_config(allow=["*"]), pid)
    assert e.value.reason == reason


def test_check_target_by_pid_and_name_pattern(make_config, child_python) -> None:
    target = check_target(make_config(allow=[f"pid:{child_python.pid}"]), child_python.pid)
    assert target["allowlist_entry"] == f"pid:{child_python.pid}"
    target = check_target(make_config(allow=["*time.sleep(120)*"]), child_python.pid)
    assert target["allowlist_entry"] == "*time.sleep(120)*"
    assert target["pid"] == child_python.pid
    assert target["name"].startswith("python")


# -- tool gates ---------------------------------------------------------------------


@pytest.mark.parametrize("tool", CPU_TOOLS)
async def test_disabled_with_empty_allowlist(cpu_call, child_python, pyspy_argv, tool) -> None:
    err, out = await cpu_call(tool, {"pid": child_python.pid})
    assert err
    assert out["error"]["code"] == "attach_refused"
    assert out["error"]["reason"] == "attach_disabled"
    assert "--allow" in out["error"]["message"]
    assert pyspy_argv() == []


@pytest.mark.parametrize("tool", CPU_TOOLS)
async def test_refuses_pid_not_on_allowlist(cpu_call, child_python, pyspy_argv, tool) -> None:
    err, out = await cpu_call(tool, {"pid": child_python.pid}, allow=["gunicorn*", "pid:1"])
    assert err and out["error"]["reason"] == "not_allowlisted"
    assert out["error"]["pid"] == child_python.pid
    assert pyspy_argv() == []


@pytest.mark.parametrize("tool", CPU_TOOLS)
async def test_refuses_own_pid_even_with_wildcard(cpu_call, pyspy_argv, tool) -> None:
    err, out = await cpu_call(tool, {"pid": os.getpid()}, allow=["*"])
    assert err and out["error"]["reason"] == "invalid_argument"
    assert pyspy_argv() == []


@pytest.mark.parametrize("pid", [0, -5, 2**22 + 12345])
async def test_refuses_bad_or_dead_pid(cpu_call, pyspy_argv, pid) -> None:
    err, out = await cpu_call("cpu_stacks", {"pid": pid}, allow=["*"])
    assert err and out["error"]["reason"] in {"invalid_argument", "no_such_process"}
    assert pyspy_argv() == []


@pytest.mark.parametrize("tool", CPU_TOOLS)
async def test_py_spy_not_found(call, child_python, tool) -> None:
    err, out = await call(tool, {"pid": child_python.pid}, py_spy_bin=None, **allow(child_python))
    assert err and out["error"]["code"] == "py_spy_not_found"
    assert "pyspy" in out["error"]["hint"]


async def test_attach_is_logged(cpu_call, child_python, caplog) -> None:
    caplog.set_level(logging.INFO, logger="heapspy_mcp")
    err, _ = await cpu_call("cpu_stacks", {"pid": child_python.pid}, **allow(child_python))
    assert not err
    messages = [r.getMessage() for r in caplog.records if r.name == "heapspy_mcp.cpu"]
    assert any(
        "py-spy attach: tool=cpu_stacks" in m and str(child_python.pid) in m for m in messages
    )


# -- cpu_stacks ---------------------------------------------------------------------


async def test_cpu_stacks(cpu_call, child_python, pyspy_argv) -> None:
    err, out = await cpu_call("cpu_stacks", {"pid": child_python.pid}, **allow(child_python))
    assert not err, out
    assert pyspy_argv()[-1] == ["dump", f"--pid={child_python.pid}", "--json", "--nonblocking"]
    assert out["nonblocking"] is True
    main, worker = out["threads"]
    assert main["name"] == "MainThread" and main["owns_gil"] and main["active"]
    assert worker["name"] == "worker" and not worker["active"]
    assert main["frames"][0] == {
        "function": "compute",
        "location": "app/hot.py:12",
        "file": "/srv/app/app/hot.py",
        "line": 12,
        "module": "app.hot",
        "native": False,
    }
    assert out["summary"]["gil_holder"] == "MainThread"
    assert out["summary"]["threads"] == 2
    # The fake reports the child's pid as the OS thread id, so /proc has a real state.
    if main["os_state"] is not None:
        assert main["os_state"]["label"] == "sleeping (blocked in a syscall)"


async def test_cpu_stacks_hides_idle(cpu_call, child_python) -> None:
    err, out = await cpu_call(
        "cpu_stacks", {"pid": child_python.pid, "include_idle": False}, **allow(child_python)
    )
    assert not err
    assert [t["name"] for t in out["threads"]] == ["MainThread"]
    assert out["idle_threads_hidden"] == 1


async def test_cpu_stacks_native_turns_off_nonblocking(cpu_call, child_python, pyspy_argv) -> None:
    err, out = await cpu_call(
        "cpu_stacks", {"pid": child_python.pid, "native": True}, **allow(child_python)
    )
    assert not err, out
    assert pyspy_argv()[-1] == ["dump", f"--pid={child_python.pid}", "--json", "--native"]
    assert out["nonblocking"] is False


async def test_cpu_stacks_never_returns_locals(cpu_call, child_python, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_PYSPY_MODE", "locals")
    err, out = await cpu_call("cpu_stacks", {"pid": child_python.pid}, **allow(child_python))
    assert not err
    assert "hunter2" not in str(out) and "locals" not in str(out["threads"])


async def test_cpu_stacks_caps(cpu_call, child_python, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_PYSPY_MODE", "big")
    err, out = await cpu_call(
        "cpu_stacks",
        {"pid": child_python.pid, "max_threads": 10_000, "max_frames": 10_000},
        **allow(child_python),
    )
    assert not err
    assert len(out["threads"]) == 200
    assert out["threads_omitted"] == 300
    assert all(len(t["frames"]) == 100 and t["frames_truncated"] for t in out["threads"])
    err, out = await cpu_call(
        "cpu_stacks", {"pid": child_python.pid, "max_threads": 0}, **allow(child_python)
    )
    assert len(out["threads"]) == 1


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("permission", "permission_denied"),
        ("not_python", "not_python"),
        ("no_such_process", "no_such_process"),
        ("not_json", "bad_output"),
    ],
)
async def test_cpu_stacks_errors(cpu_call, child_python, monkeypatch, mode, code) -> None:
    monkeypatch.setenv("FAKE_PYSPY_MODE", mode)
    err, out = await cpu_call("cpu_stacks", {"pid": child_python.pid}, **allow(child_python))
    assert err and out["error"]["code"] == code
    if code == "permission_denied":
        assert "ptrace_scope" in out["error"]["hint"]


# -- aggregation ---------------------------------------------------------------------


def test_aggregate_self_total_and_stacks() -> None:
    stacks = parse_folded(
        "thread (1): Main;main (app/m.py:1);a (app/a.py:5);b (app/b.py:9) 6\n"
        "thread (1): Main;main (app/m.py:1);a (app/a.py:6) 3\n"
        "thread (2): W;main (app/m.py:1);a (app/a.py:5);b (app/b.py:9) 1\n"
        "thread (3): empty 2\n"
    )
    agg = aggregate(stacks, top=10, top_stacks=10)
    assert agg["samples_total"] == 12
    assert agg["samples_without_python_frames"] == 2
    self_rows = {r["function"]: r for r in agg["top_self"]}
    assert self_rows["b"]["samples"] == 7 and self_rows["b"]["pct_of_samples"] == 58.3
    assert self_rows["b"]["module"] == "app.b" and self_rows["b"]["location"] == "app/b.py:9"
    assert self_rows["a"]["samples"] == 3 and self_rows["a"]["location"] == "app/a.py:6"
    total_rows = {r["function"]: r for r in agg["top_total"]}
    assert total_rows["main"]["samples"] == 10 and total_rows["a"]["samples"] == 10
    first = agg["top_stacks"][0]
    assert first["samples"] == 7 and first["frames"][0] == "b (app/b.py:9)"
    assert first["threads"] == ["Main", "W"]


def test_aggregate_counts_recursion_once_in_total() -> None:
    stacks = parse_folded("f (a.py:1);f (a.py:1);f (a.py:2) 4\n")
    agg = aggregate(stacks, top=5, top_stacks=5)
    assert agg["top_total"][0]["samples"] == 4
    assert agg["top_self"][0]["samples"] == 4


# -- cpu_profile ---------------------------------------------------------------------


async def test_cpu_profile_default_mode(cpu_call, child_python, pyspy_argv) -> None:
    err, out = await cpu_call(
        "cpu_profile", {"pid": child_python.pid, "duration_s": 1}, **allow(child_python)
    )
    assert not err, out
    assert out["sampling"]["mode"] == "on_cpu"
    assert "on-CPU samples only" in out["sampling"]["description"]
    assert out["sampling"]["passes"] == 3
    calls = pyspy_argv()
    assert len(calls) == 3
    assert all("--nonblocking" in c and "--threads" in c and "--format=raw" in c for c in calls)
    flags = sorted(tuple(a for a in c if a in ("--idle", "--gil")) for c in calls)
    assert flags == [(), ("--idle",), ("--idle", "--gil")]

    assert out["samples"]["total"] == 90
    assert out["top_self"][0]["function"] == "compute"
    assert out["top_self"][0]["pct_of_samples"] == 88.9
    assert out["top_self"][0]["location"] == "app/hot.py:12"
    assert {r["function"] for r in out["top_total"][:2]} == {"<module>", "main"}

    split = out["split"]
    assert split["samples_all_threads"] == 190
    assert split["on_cpu"] == {"samples": 90, "pct_of_samples": 47.4}
    assert split["idle"] == {"samples": 100, "pct_of_samples": 52.6}
    assert split["gil_held"] == {"samples": 80, "pct_of_samples": 42.1}
    assert split["on_cpu_without_gil"]["samples"] == 10

    assert out["samples"]["ticks_estimate"] == 100
    assert out["gil"]["held_pct_of_ticks"] == 80.0
    assert out["gil"]["threads_that_held_gil"] == 1
    assert out["gil"]["contention"] == "unlikely"
    threads = {t["name"]: t for t in out["threads"]}
    assert threads["worker"]["on_cpu_samples"] == 0
    assert threads["MainThread"]["gil_samples"] == 80
    assert out["folded_path"] is None
    assert "pct_of_samples" not in str(out.get("cpu_usage"))


async def test_cpu_profile_all_mode_reuses_pass(cpu_call, child_python, pyspy_argv) -> None:
    err, out = await cpu_call(
        "cpu_profile",
        {"pid": child_python.pid, "duration_s": 1, "include_idle": True},
        **allow(child_python),
    )
    assert not err, out
    assert out["sampling"]["mode"] == "all"
    assert out["sampling"]["passes"] == 3
    assert out["samples"]["total"] == 190
    assert out["top_self"][0]["function"] == "wait"


async def test_cpu_profile_gil_only(cpu_call, child_python) -> None:
    err, out = await cpu_call(
        "cpu_profile",
        {"pid": child_python.pid, "duration_s": 1, "gil_only": True},
        **allow(child_python),
    )
    assert not err, out
    assert out["sampling"]["mode"] == "gil_on_cpu"
    assert out["sampling"]["passes"] == 4
    assert out["samples"]["total"] == 80


async def test_cpu_profile_native_has_no_split(cpu_call, child_python, pyspy_argv) -> None:
    err, out = await cpu_call(
        "cpu_profile",
        {"pid": child_python.pid, "duration_s": 1, "native": True},
        **allow(child_python),
    )
    assert not err, out
    assert len(pyspy_argv()) == 1
    assert "--native" in pyspy_argv()[0] and "--nonblocking" not in pyspy_argv()[0]
    assert out["split"] is None and out["gil"] is None
    assert any("native=true" in n for n in out["notes"])


async def test_cpu_profile_caps_duration_and_rate(cpu_call, child_python, pyspy_argv) -> None:
    err, out = await cpu_call(
        "cpu_profile",
        {"pid": child_python.pid, "duration_s": 999, "rate_hz": 50_000, "top": 500},
        cpu_max_duration=2,
        **allow(child_python),
    )
    assert not err, out
    assert out["duration_s"] == 2 and out["rate_hz"] == 1000
    assert all("--duration=2" in c and "--rate=1000" in c for c in pyspy_argv())
    assert any("clamped" in n for n in out["notes"])


async def test_cpu_profile_save_folded(cpu_call, child_python, snapshot_dir: Path) -> None:
    err, out = await cpu_call(
        "cpu_profile",
        {"pid": child_python.pid, "duration_s": 1, "save_folded": True},
        **allow(child_python),
    )
    assert not err, out
    path = Path(out["folded_path"])
    assert path.parent == snapshot_dir and path.name.startswith("cpu-")
    assert path.read_text().count("\n") == 3


async def test_cpu_profile_subprocess_stacks(cpu_call, child_python, pyspy_argv) -> None:
    err, out = await cpu_call(
        "cpu_profile",
        {"pid": child_python.pid, "duration_s": 1, "subprocesses": True},
        **allow(child_python),
    )
    assert not err, out
    assert all("--subprocesses" in c for c in pyspy_argv())
    assert out["top_self"][0]["function"] == "compute"
    assert "app.py; x" not in str(out)


async def test_cpu_profile_caps_output(cpu_call, child_python, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_PYSPY_MODE", "big")
    err, out = await cpu_call(
        "cpu_profile",
        {"pid": child_python.pid, "duration_s": 1, "top": 1000, "top_stacks": 1000},
        **allow(child_python),
    )
    assert not err, out
    assert len(out["top_self"]) == 50 and len(out["top_total"]) == 50
    assert len(out["top_stacks"]) == 50
    assert all(len(s["frames"]) == 30 for s in out["top_stacks"])
    assert out["top_stacks"][0]["frames_elided"] == 171


@pytest.mark.parametrize(
    ("mode", "code"),
    [("permission", "permission_denied"), ("bad_folded", "bad_output"), ("crash", "py_spy_failed")],
)
async def test_cpu_profile_errors_leave_no_files(
    cpu_call, child_python, monkeypatch, snapshot_dir, mode, code
) -> None:
    import tempfile

    before = set(Path(tempfile.gettempdir()).glob("heapspy-mcp-cpu-*"))
    monkeypatch.setenv("FAKE_PYSPY_MODE", mode)
    err, out = await cpu_call(
        "cpu_profile",
        {"pid": child_python.pid, "duration_s": 1, "save_folded": True},
        **allow(child_python),
    )
    assert err and out["error"]["code"] == code
    assert set(Path(tempfile.gettempdir()).glob("heapspy-mcp-cpu-*")) == before
    assert not list(snapshot_dir.glob("cpu-*")) if snapshot_dir.exists() else True


async def test_cpu_profile_no_samples(cpu_call, child_python, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_PYSPY_MODE", "empty")
    err, out = await cpu_call(
        "cpu_profile", {"pid": child_python.pid, "duration_s": 1}, **allow(child_python)
    )
    assert not err, out
    assert out["samples"]["total"] == 0 and out["top_self"] == []
    assert any("include_idle=true" in n for n in out["notes"])


# -- cpu_top and cpu_flamegraph --------------------------------------------------------


async def test_cpu_top(cpu_call, child_python) -> None:
    err, out = await cpu_call(
        "cpu_top", {"pid": child_python.pid, "duration_s": 1}, **allow(child_python)
    )
    assert not err, out
    assert out["top_functions"][0]["function"] == "compute"
    for name in ("cpu_seconds_user", "cpu_seconds_system", "wall_seconds"):
        assert isinstance(out[name], float)
    # The child sleeps: it used next to no CPU while being sampled.
    assert out["cpu_seconds_user"] + out["cpu_seconds_system"] < 0.5
    assert "iowait_seconds" in out
    if out["iowait_seconds"] is None:
        assert out["cpu_usage"]["iowait_note"]
    assert out["sampling"]["mode"] == "on_cpu"


@pytest.mark.parametrize(
    ("fmt", "suffix"), [("speedscope", ".speedscope.json"), ("flamegraph", ".svg")]
)
async def test_cpu_flamegraph(cpu_call, child_python, snapshot_dir, pyspy_argv, fmt, suffix):
    err, out = await cpu_call(
        "cpu_flamegraph",
        {"pid": child_python.pid, "duration_s": 1, "format": fmt},
        **allow(child_python),
    )
    assert not err, out
    path = Path(out["path"])
    assert path.parent == snapshot_dir and path.name.endswith(suffix) and path.is_file()
    assert out["samples"] == 90
    assert "<svg" not in str(out) and "$schema" not in str(out)
    assert f"--format={fmt}" in pyspy_argv()[-1]


async def test_cpu_flamegraph_rejects_format(cpu_call, child_python, pyspy_argv) -> None:
    err, out = await cpu_call(
        "cpu_flamegraph", {"pid": child_python.pid, "format": "html"}, **allow(child_python)
    )
    assert err and out["error"]["code"] == "invalid_argument"
    assert pyspy_argv() == []


async def test_cpu_flamegraph_missing_output(cpu_call, child_python, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_PYSPY_MODE", "no_output")
    err, out = await cpu_call(
        "cpu_flamegraph", {"pid": child_python.pid, "duration_s": 1}, **allow(child_python)
    )
    assert err and out["error"]["code"] == "bad_output"


# -- metadata -----------------------------------------------------------------------


async def test_tools_listed_with_descriptions(make_config) -> None:
    async with Client(build_server(make_config())) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert set(CPU_TOOLS) <= set(tools)
        assert "pct_of_samples" in tools["cpu_profile"].description
        assert "NOT a share of machine" in tools["cpu_profile"].description
        assert "torn" in tools["cpu_stacks"].description
        assert "never the contents" in tools["cpu_flamegraph"].description
        assert "locals" not in str(tools["cpu_stacks"].input_schema)
        resource = await client.read_resource("heapspy://workflow/cpu")
        assert "Heap tools" in resource.contents[0].text
        prompt = await client.get_prompt("investigate_cpu", {"target": "pid 42"})
        assert "pid 42" in prompt.messages[0].content.text
        assert "cpu_top" in (client.instructions or "")
