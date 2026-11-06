"""The CPU tools and their gates, against the fake py-spy."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest
from mcp import Client

from heapspy_mcp.cpu import AttachRefused, check_target
from heapspy_mcp.server import build_server

CPU_TOOLS = ("cpu_stacks",)


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


# -- metadata -----------------------------------------------------------------------


async def test_cpu_stacks_is_listed(make_config) -> None:
    async with Client(build_server(make_config())) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert "torn" in tools["cpu_stacks"].description
    assert "locals" not in str(tools["cpu_stacks"].input_schema)
    assert tools["cpu_stacks"].annotations.read_only_hint is True
