"""capture_snapshot and its safety gates."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from mcp import Client

from heapspy_mcp.server import build_server
from heapspy_mcp.snapshots import HANDLE_RE


@pytest.fixture
def core_file(tmp_path: Path) -> Path:
    path = tmp_path / "core.1234"
    path.write_bytes(b"\x7fELF")
    return path


async def test_capture_is_described_as_privileged(make_config) -> None:
    async with Client(build_server(make_config())) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    capture = tools["capture_snapshot"]
    assert "PRIVILEGED" in capture.description
    assert "ask the user" in capture.description
    assert capture.annotations.read_only_hint is False
    assert capture.input_schema["properties"]["confirm"]["default"] is False
    assert tools["list_python_processes"].annotations.read_only_hint is True


async def test_refuses_without_confirm(call, child_python, argv_log) -> None:
    for confirm in (False, None):
        args = {"pid": child_python.pid}
        if confirm is not None:
            args["confirm"] = confirm
        err, out = await call("capture_snapshot", args, allow=[f"pid:{child_python.pid}"])
        assert err
        assert out["error"]["code"] == "capture_refused"
        assert out["error"]["reason"] == "confirmation_required"
    assert argv_log() == []


async def test_refuses_with_empty_allowlist(call, child_python, argv_log) -> None:
    err, out = await call("capture_snapshot", {"pid": child_python.pid, "confirm": True})
    assert err and out["error"]["reason"] == "capture_disabled"
    assert "--allow" in out["error"]["message"]
    assert argv_log() == []


async def test_refuses_process_not_on_allowlist(call, child_python, argv_log) -> None:
    err, out = await call(
        "capture_snapshot",
        {"pid": child_python.pid, "confirm": True},
        allow=["gunicorn*", "pid:1"],
    )
    assert err and out["error"]["reason"] == "not_allowlisted"
    assert out["error"]["pid"] == child_python.pid
    assert argv_log() == []


async def test_refuses_over_rss_guard(call, child_python, argv_log) -> None:
    err, out = await call(
        "capture_snapshot",
        {"pid": child_python.pid, "confirm": True},
        allow=[f"pid:{child_python.pid}"],
        max_rss_bytes=1024,
    )
    assert err and out["error"]["reason"] == "rss_limit"
    assert out["error"]["rss_bytes"] > 1024
    assert out["error"]["max_rss_bytes"] == 1024
    assert argv_log() == []


async def test_refuses_contents_without_server_permission(call, child_python, argv_log):
    err, out = await call(
        "capture_snapshot",
        {"pid": child_python.pid, "confirm": True, "capture_contents": True},
        allow=[f"pid:{child_python.pid}"],
    )
    assert err and out["error"]["reason"] == "contents_not_allowed"
    assert "--allow-contents" in out["error"]["message"]
    assert argv_log() == []


async def test_refuses_contents_for_core_too(call, core_file) -> None:
    err, out = await call(
        "capture_snapshot",
        {"core_path": str(core_file), "confirm": True, "capture_contents": True},
    )
    assert err and out["error"]["reason"] == "contents_not_allowed"


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"pid": 1, "core_path": "/x"},
        {"pid": -3},
        {"core_path": "/definitely/not/here"},
        {"minidump_path": "/definitely/not/here.dmp"},
    ],
)
async def test_refuses_bad_targets(call, args, argv_log) -> None:
    err, out = await call("capture_snapshot", {**args, "confirm": True}, allow=["*"])
    assert err and out["error"]["reason"] == "invalid_argument"
    assert argv_log() == []


async def test_refuses_dead_pid(call) -> None:
    err, out = await call("capture_snapshot", {"pid": 2**22 + 12345, "confirm": True}, allow=["*"])
    assert err and out["error"]["reason"] == "no_such_process"


async def test_refuses_own_pid(call) -> None:
    import os

    err, out = await call("capture_snapshot", {"pid": os.getpid(), "confirm": True}, allow=["*"])
    assert err and out["error"]["reason"] == "invalid_argument"


async def test_max_str_needs_contents(call, core_file) -> None:
    err, out = await call(
        "capture_snapshot", {"core_path": str(core_file), "confirm": True, "max_str": 10}
    )
    assert err and "max_str" in out["error"]["message"]


async def test_live_capture_allowed_by_pid(
    call, child_python, snapshot_dir: Path, argv_log, caplog
) -> None:
    caplog.set_level(logging.INFO, logger="heapspy_mcp")
    err, out = await call(
        "capture_snapshot",
        {"pid": child_python.pid, "confirm": True},
        allow=[f"pid:{child_python.pid}"],
    )
    assert not err, out
    assert HANDLE_RE.match(out["snapshot"])
    path = Path(out["path"])
    assert path.parent == snapshot_dir and path.is_file()
    assert out["target"]["kind"] == "pid"
    assert out["target"]["allowlist_entry"] == f"pid:{child_python.pid}"
    assert out["stats"]["objects"] == 10
    assert out["contents_captured"] is False
    staged = snapshot_dir / f".{out['snapshot']}.partial" / path.name
    assert argv_log()[-1] == ["dump", f"--pid={child_python.pid}", f"--output={staged}"]
    assert sorted(p.name for p in snapshot_dir.iterdir()) == [path.name]
    messages = [r.getMessage() for r in caplog.records if r.name == "heapspy_mcp.capture"]
    assert any("capture start" in m and out["snapshot"] in m for m in messages)
    assert any("capture done" in m for m in messages)

    # The handle works with the analysis tools.
    err, summary = await call("heap_summary", {"snapshot": out["snapshot"]})
    assert not err and summary["snapshot_ref"] == out["snapshot"]


async def test_live_capture_allowed_by_name_pattern(call, child_python) -> None:
    err, out = await call(
        "capture_snapshot",
        {"pid": child_python.pid, "confirm": True},
        allow=["*time.sleep(120)*"],
    )
    assert not err, out
    assert out["target"]["allowlist_entry"] == "*time.sleep(120)*"


async def test_contents_capture_when_permitted_is_logged(
    call, child_python, argv_log, caplog
) -> None:
    caplog.set_level(logging.INFO, logger="heapspy_mcp")
    err, out = await call(
        "capture_snapshot",
        {"pid": child_python.pid, "confirm": True, "capture_contents": True, "max_str": 64},
        allow=[f"pid:{child_python.pid}"],
        allow_contents=True,
    )
    assert not err, out
    assert out["contents_captured"] is True
    assert argv_log()[-1][-2:] == ["--capture-contents", "--max-str=64"]
    assert any("CONTENTS" in r.getMessage() for r in caplog.records)


async def test_core_ingest_needs_only_confirm(call, core_file, argv_log) -> None:
    err, out = await call("capture_snapshot", {"core_path": str(core_file), "confirm": True})
    assert not err, out
    assert out["target"] == {"kind": "core", "path": str(core_file)}
    assert argv_log()[-1][1] == f"--core={core_file}"


async def test_minidump_ingest(call, tmp_path, argv_log) -> None:
    dmp = tmp_path / "app.dmp"
    dmp.write_bytes(b"MDMP")
    err, out = await call("capture_snapshot", {"minidump_path": str(dmp), "confirm": True})
    assert not err, out
    assert argv_log()[-1][1] == f"--minidump={dmp}"


async def test_failed_dump_leaves_no_snapshot(
    call, core_file, snapshot_dir: Path, monkeypatch
) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "dump_fail")
    err, out = await call("capture_snapshot", {"core_path": str(core_file), "confirm": True})
    assert err and out["error"]["code"] == "cli_failed"
    assert list(snapshot_dir.glob("*.hpy")) == []


async def test_dump_without_output_file_is_an_error(call, core_file, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "dump_no_file")
    err, out = await call("capture_snapshot", {"core_path": str(core_file), "confirm": True})
    assert err and out["error"]["code"] == "cli_failed"


async def test_killed_dump_leaves_no_temporary_file(
    call, core_file, snapshot_dir: Path, monkeypatch
) -> None:
    # heapspy writes through a .tmpXXXXXX file next to its output; a dump killed
    # by the capture timeout must not leave it (or anything else) behind.
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "dump_hang")
    err, out = await call(
        "capture_snapshot", {"core_path": str(core_file), "confirm": True}, capture_timeout=1.0
    )
    assert err and out["error"]["code"] == "timeout"
    assert list(snapshot_dir.iterdir()) == []


async def test_failed_dump_removes_staging_directory(
    call, core_file, snapshot_dir: Path, monkeypatch
) -> None:
    for mode in ("dump_fail", "dump_no_file", "error:io"):
        monkeypatch.setenv("FAKE_HEAPSPY_MODE", mode)
        err, _ = await call("capture_snapshot", {"core_path": str(core_file), "confirm": True})
        assert err
        assert list(snapshot_dir.iterdir()) == []
