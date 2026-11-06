"""Source locations from heapspy reports in the analysis tools' summaries, and
map_to_source's exact resolution through ``query --locate``.

The fake heapspy prints docs/examples, which have the location fields; in
``old_binary`` mode it removes them, as a heapspy from before them would.
"""

from __future__ import annotations

import json
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


MAIN_SCRIPT = (
    "import time\n"
    "\n"
    "\n"
    "class Session:\n"
    "    def __init__(self):\n"
    "        self.items = []\n"
    "\n"
    "\n"
    'if __name__ == "__main__":\n'
    "    Session()\n"
)


@pytest.fixture
def two_scripts(tmp_path: Path) -> Path:
    """A repository with two scripts that both define Session at line 4."""
    repo = tmp_path / "repo"
    for name in ("a_first.py", "b_second.py"):
        (repo / "jobs").mkdir(parents=True, exist_ok=True)
        (repo / "jobs" / name).write_text(MAIN_SCRIPT)
    return repo


def locate_table(monkeypatch: pytest.MonkeyPatch, table: dict) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_LOCATE", json.dumps(table))


def session_match(file: str) -> dict:
    return {
        "kind": "type",
        "name": "__main__.Session",
        "module": "__main__",
        "qualname": "Session",
        "address": "0x7f0000005000",
        "source_loc": {"file": file, "line": 5, "exact": False, "via": "methods"},
        "source_loc_reason": None,
    }


async def test_map_to_source_with_snapshot_is_exact(
    call, snap_file: Path, two_scripts: Path, monkeypatch: pytest.MonkeyPatch, argv_log
) -> None:
    recorded = str(two_scripts / "jobs" / "b_second.py")
    locate_table(monkeypatch, {"__main__.Session": [session_match(recorded)]})
    args = {"qualname": "__main__.Session", "repo_path": str(two_scripts)}
    err, out = await call("map_to_source", {**args, "snapshot": str(snap_file)})
    assert not err, out
    assert argv_log()[-1] == ["query", str(snap_file), "--locate=__main__.Session", "--json"]
    assert out["heuristic"] is False and out["via"] == "snapshot"
    assert [c["location"] for c in out["candidates"]] == ["jobs/b_second.py:4"]
    assert out["candidates"][0]["matched_by"] == "exact_path"

    # Without the snapshot, both scripts are heuristic candidates.
    err, out = await call("map_to_source", args)
    assert not err, out
    assert out["heuristic"] is True
    assert len(out["candidates"]) == 2


async def test_map_to_source_name_not_in_snapshot_falls_back(
    call, snap_file: Path, two_scripts: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    locate_table(monkeypatch, {})
    args = {"qualname": "__main__.Session", "repo_path": str(two_scripts)}
    err, out = await call("map_to_source", {**args, "snapshot": str(snap_file)})
    assert not err, out
    assert out["heuristic"] is True
    assert out["snapshot_lookup"]["status"] == "not_in_snapshot"
    assert len(out["candidates"]) == 2


async def test_map_to_source_old_binary_is_unchanged(
    call, snap_file: Path, two_scripts: Path, monkeypatch: pytest.MonkeyPatch, argv_log
) -> None:
    args = {"qualname": "__main__.Session", "repo_path": str(two_scripts)}
    err, before = await call("map_to_source", args)
    assert not err, before
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "old_binary")
    err, out = await call("map_to_source", {**args, "snapshot": str(snap_file)})
    assert not err, out
    assert argv_log()[-1][2] == "--locate=__main__.Session"
    assert out == before


async def test_map_to_source_checks_arguments_before_running_heapspy(
    call, snap_file: Path, two_scripts: Path, argv_log
) -> None:
    err, out = await call(
        "map_to_source",
        {"qualname": "../etc", "repo_path": str(two_scripts), "snapshot": str(snap_file)},
    )
    assert err and out["error"]["code"] == "invalid_argument"
    err, out = await call(
        "map_to_source",
        {"qualname": "a.B", "repo_path": str(two_scripts), "snapshot": "hs-ffffffff"},
    )
    assert err and out["error"]["code"] == "invalid_argument"
    assert argv_log() == []


async def test_map_to_source_snapshot_errors_are_reported(
    call, snap_file: Path, two_scripts: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "error:invalid_snapshot")
    err, out = await call(
        "map_to_source",
        {"qualname": "a.B", "repo_path": str(two_scripts), "snapshot": str(snap_file)},
    )
    assert err and out["error"]["code"] == "invalid_snapshot"


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
