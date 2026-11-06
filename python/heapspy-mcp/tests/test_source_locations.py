"""Source locations from heapspy reports in the analysis tools' summaries.

The fake heapspy prints docs/examples, which have the location fields; in
``old_binary`` mode it removes them, as a heapspy from before them would.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from heapspy_mcp import summarize as S

SESSION_AT = {
    "location": "app/session.py:~14",
    "file": "app/session.py",
    "line": 14,
    "exact": False,
    "via": "methods",
}


async def test_heap_summary_passes_type_locations(call, snap_file: Path) -> None:
    err, out = await call("heap_summary", {"snapshot": str(snap_file), "top": 5})
    assert not err, out
    first = out["top_retainers"][0]
    # builtins.dict is a C type: no location, and the reason says why.
    assert first["type_location"] is None
    assert first["type_location_reason"] == "type_not_in_snapshot"
    # The module root has no location without contents capture; nothing to list.
    assert first["path"]["source_locations"] == []
    session = out["type_histogram"][1]
    assert session["type"] == "app.session.Session"
    assert session["type_location"] == SESSION_AT
    assert session["type_location_reason"] is None


async def test_type_detail_passes_type_locations(call, snap_file: Path) -> None:
    err, out = await call("type_detail", {"snapshot": str(snap_file), "type": "Session"})
    assert not err, out
    assert out["type_locations"] == [
        {
            "type": "app.session.Session",
            "type_location": SESSION_AT,
            "type_location_reason": None,
        }
    ]
    inst = out["top_instances"][0]
    assert "source_loc" not in inst  # an instance of a class has none of its own
    assert inst["path"]["source_locations"] == [
        {"of": "type", "name": "app.session.Session", **SESSION_AT}
    ]


async def test_retaining_path_passes_hop_locations(call, snap_file: Path) -> None:
    err, out = await call(
        "retaining_path", {"snapshot": str(snap_file), "address": "0x7f3a1e104000"}
    )
    assert not err, out
    target = out["targets"][0]
    assert target["type_location"] is None
    assert target["type_location_reason"] == "type_not_in_snapshot"
    path = target["paths"][0]
    module_at = {
        "location": "app/cache.py",
        "file": "app/cache.py",
        "line": None,
        "exact": True,
        "via": "module_file",
    }
    assert path["hops"][0]["source_loc"] == module_at
    assert all("source_loc" not in h for h in path["hops"][1:])
    assert path["source_locations"] == [
        {
            "of": "hop",
            "type": "builtins.module",
            "address": "0x7f3a2d000040",
            "edge": None,
            **module_at,
        }
    ]
    # source_hints are unchanged: names for map_to_source.
    assert "app.cache.CACHE" in path["source_hints"]


async def test_old_binary_summaries_are_unchanged(
    call, snap_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "old_binary")
    err, out = await call("heap_summary", {"snapshot": str(snap_file), "top": 5})
    assert not err, out
    assert "type_location" not in out["top_retainers"][0]
    assert "source_locations" not in out["top_retainers"][0]["path"]
    assert "type_location" not in out["type_histogram"][1]
    err, out = await call("type_detail", {"snapshot": str(snap_file), "type": "Session"})
    assert not err, out
    assert "type_locations" not in out
    assert "source_locations" not in out["top_instances"][0]["path"]
    err, out = await call(
        "retaining_path", {"snapshot": str(snap_file), "address": "0x7f3a1e104000"}
    )
    assert not err, out
    target = out["targets"][0]
    assert "type_location" not in target
    assert "source_loc" not in target["paths"][0]["hops"][0]
    assert "source_locations" not in target["paths"][0]


def test_locations_are_bounded() -> None:
    hops = [
        {
            "address": f"0x{i:x}",
            "type": "builtins.function",
            "edge": f"['f{i}']",
            "source_loc": {"file": "x/" * 400 + f"{i}.py", "line": i, "exact": True, "via": "f"},
        }
        for i in range(1, 40)
    ]
    out = S.source_locations(hops, {"file": "t.py", "line": 1, "exact": False}, "app.T")
    assert len(out) == S.MAX_SOURCE_HINTS
    assert out[0]["location"] == "t.py:~1"
    assert all(len(e["file"]) <= 400 for e in out)
    # The target end of the path first.
    assert out[1]["edge"] == "['f39']"
    assert S.compact_location({"file": None}) is None
    assert S.compact_location("app.py:3") is None
