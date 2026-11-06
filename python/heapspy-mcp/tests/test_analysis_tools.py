"""heap_summary, retaining_path, type_detail and diff_snapshots through the MCP server."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp import Client

from heapspy_mcp import summarize as S
from heapspy_mcp.server import build_server

ANALYSIS_TOOLS = {"heap_summary", "retaining_path", "type_detail", "diff_snapshots"}


async def test_analysis_tools_are_read_only(make_config) -> None:
    async with Client(build_server(make_config())) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(tools) >= ANALYSIS_TOOLS
    for name in ANALYSIS_TOOLS:
        assert tools[name].annotations.read_only_hint is True
    assert "map_to_source" in tools["heap_summary"].description


async def test_heap_summary(call, snap_file: Path, argv_log) -> None:
    err, out = await call("heap_summary", {"snapshot": str(snap_file), "top": 5})
    assert not err, out
    assert argv_log()[-1] == ["analyze", str(snap_file), "--json", "--top=5"]
    first = out["top_retainers"][0]
    assert first["type"] == "builtins.dict"
    assert first["retained_human"] == "412.6 MiB"
    assert first["path"]["rendered"] == "sys.modules['app.cache'].__dict__['CACHE']"
    assert first["path"]["source_hints"] == ["app.cache.CACHE"]
    assert first["path"]["direct_holder"]["edge"] == "['CACHE']"
    assert "hops" not in first["path"]
    assert out["type_histogram"][1]["type"] == "app.session.Session"
    assert out["memory"]["outside_graph_pct"] == 76.97
    assert {n["code"] for n in out["notes"]} == {"untracked_objects", "outside_graph"}
    assert out["snapshot"]["python_version"] == "3.12.4"


async def test_heap_summary_accepts_handle(call, snapshot_dir: Path) -> None:
    snapshot_dir.mkdir()
    (snapshot_dir / "hs-0123abcd.hpy").write_bytes(b"x")
    err, out = await call("heap_summary", {"snapshot": "hs-0123abcd"})
    assert not err, out
    assert out["snapshot_ref"] == "hs-0123abcd"


async def test_heap_summary_bad_snapshot_ref(call, tmp_path: Path) -> None:
    err, out = await call("heap_summary", {"snapshot": str(tmp_path / "nope.hpy")})
    assert err
    assert out["error"]["code"] == "invalid_argument"
    err, out = await call("heap_summary", {"snapshot": "hs-ffffffff"})
    assert err and "unknown snapshot handle" in out["error"]["message"]


async def test_cli_error_becomes_structured_tool_error(call, snap_file, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "error:invalid_snapshot")
    err, out = await call("heap_summary", {"snapshot": str(snap_file)})
    assert err
    assert out["error"]["code"] == "invalid_snapshot"
    assert out["error"]["exit_status"] == 1
    assert "hint" in out["error"]


async def test_schema_mismatch_is_reported(call, snap_file, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "bad_schema")
    err, out = await call("type_detail", {"snapshot": str(snap_file), "type": "Session"})
    assert err and out["error"]["code"] == "schema_mismatch"


async def test_timeout_is_reported(call, snap_file, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "timeout")
    err, out = await call("heap_summary", {"snapshot": str(snap_file)}, timeout=0.5)
    assert err and out["error"]["code"] == "timeout"


async def test_missing_binary_is_reported(call, snap_file) -> None:
    err, out = await call("heap_summary", {"snapshot": str(snap_file)}, heapspy_bin=None)
    assert err and out["error"]["code"] == "binary_not_found"
    assert "HEAPSPY_BIN" in out["error"]["hint"]


async def test_retaining_path_by_address(call, snap_file: Path, argv_log) -> None:
    err, out = await call(
        "retaining_path", {"snapshot": str(snap_file), "address": "0x7F3A1E104000"}
    )
    assert not err, out
    assert argv_log()[-1][2] == "--retaining-path=0x7f3a1e104000"
    target = out["targets"][0]
    assert target["reachable"] is True
    path = target["paths"][0]
    assert path["rendered"] == ("sys.modules['app.cache'].__dict__['CACHE']['user:8812'].payload")
    assert path["direct_holder"] == {
        "type": "app.session.Session",
        "address": "0x7f3a1e002a10",
        "edge": ".payload",
    }
    assert "app.session.Session.payload" in path["source_hints"]
    assert "app.cache.CACHE" in path["source_hints"]
    assert path["hops"][0]["root_kind"] == "module_dict"
    assert len(path["hops"]) == 5


async def test_retaining_path_by_type(call, snap_file: Path, argv_log) -> None:
    err, out = await call(
        "retaining_path", {"snapshot": str(snap_file), "type": "app.session.Session"}
    )
    assert not err, out
    calls = argv_log()
    assert calls[0][2] == "--type=app.session.Session"
    assert calls[1][2] == "--retaining-path=0x7f3a1e002a10"
    assert out["query"] == {"by": "type", "value": "app.session.Session"}
    assert out["type_match"]["instances"] == 400000
    assert len(out["targets"]) == 1
    assert {n["code"] for n in out["notes"]} == {"keys_redacted"}


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"address": "0x1", "type": "T"},
        {"address": "7f3a"},
        {"address": "0xzz"},
        {"type": "has space"},
    ],
)
async def test_retaining_path_rejects_bad_arguments(call, snap_file: Path, args, argv_log):
    err, out = await call("retaining_path", {"snapshot": str(snap_file), **args})
    assert err and out["error"]["code"] == "invalid_argument"
    assert argv_log() == []


async def test_retaining_path_not_found(call, snap_file: Path) -> None:
    err, out = await call("retaining_path", {"snapshot": str(snap_file), "address": "0xdead"})
    assert err and out["error"]["code"] == "not_found"


async def test_type_detail(call, snap_file: Path) -> None:
    err, out = await call("type_detail", {"snapshot": str(snap_file), "type": "Session"})
    assert not err, out
    assert out["query"] == "Session"
    assert out["matched_types"] == ["app.session.Session"]
    assert out["instances"] == 400000
    assert out["holders"] == [{"type": "builtins.dict", "edge": "[<key>]", "count": 400000}]
    inst = out["top_instances"][0]
    assert inst["path"]["rendered"].endswith("['CACHE'][<str len=9>]")


async def test_type_detail_not_found(call, snap_file: Path) -> None:
    err, out = await call("type_detail", {"snapshot": str(snap_file), "type": "Missing"})
    assert err and out["error"]["code"] == "not_found"


async def test_diff_surfaces_identity_approximate(call, tmp_path: Path) -> None:
    before, after = tmp_path / "before.hpy", tmp_path / "after.hpy"
    before.write_bytes(b"x")
    after.write_bytes(b"x")
    err, out = await call("diff_snapshots", {"before": str(before), "after": str(after)})
    assert not err, out
    assert out["identity_approximate"] is True
    assert "not by address" in out["identity_note"]
    assert out["by_site"][0]["site"] == "sys.modules['app.cache'].__dict__['CACHE']"
    assert out["by_type"][0]["delta_bytes"] == 309067776
    assert out["by_type"][1]["delta_human"] == "-37.5 KiB"
    assert out["totals"]["delta_objects"] == 1400000


# -- output bounds ---------------------------------------------------------------------


async def test_top_is_capped_server_side(call, snap_file: Path, argv_log, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "big")
    err, out = await call("heap_summary", {"snapshot": str(snap_file), "top": 10_000})
    assert not err
    assert argv_log()[-1][-1] == f"--top={S.MAX_TOP}"
    assert len(out["top_retainers"]) == S.MAX_TOP
    assert len(out["type_histogram"]) == S.MAX_TOP
    assert len(out["notes"]) == S.MAX_NOTES
    assert all(len(n["message"]) <= 500 for n in out["notes"])
    rendered = out["top_retainers"][0]["path"]["rendered"]
    assert "...76 hops..." in rendered
    assert len(rendered) < 24 * (S.MAX_LABEL + 1)
    err, out = await call("heap_summary", {"snapshot": str(snap_file), "top": -5})
    assert len(out["top_retainers"]) == 1


async def test_large_inputs_are_truncated(call, snap_file: Path, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "big")
    err, out = await call(
        "retaining_path",
        {"snapshot": str(snap_file), "address": "0x10", "max_paths": 500},
    )
    assert not err
    target = out["targets"][0]
    assert len(target["paths"]) == S.MAX_PATHS
    assert target["paths_total"] == 20
    hops = target["paths"][0]["hops"]
    assert len(hops) == S.MAX_HOPS + 1
    assert {"elided_hops": 60 - S.MAX_HOPS} in hops
    assert all(len(h.get("edge") or "") <= S.MAX_LABEL for h in hops)

    err, out = await call("type_detail", {"snapshot": str(snap_file), "type": "Session", "top": 3})
    assert len(out["top_instances"]) == 3
    assert len(out["holders"]) == 3
    assert len(out["matched_types"]) == S.MAX_MATCHED_TYPES
    assert out["matched_types_total"] == 300

    err, out = await call(
        "retaining_path", {"snapshot": str(snap_file), "type": "Session", "max_targets": 99}
    )
    assert len(out["targets"]) == S.MAX_TARGETS

    before = tmp_path / "b.hpy"
    before.write_bytes(b"x")
    err, out = await call("diff_snapshots", {"before": str(before), "after": str(snap_file)})
    assert len(out["by_type"]) == 10 and out["by_type_total"] == 200
    assert len(out["by_site"]) == 10 and out["by_site_total"] == 200
    assert len(json.dumps(out)) < 20_000
