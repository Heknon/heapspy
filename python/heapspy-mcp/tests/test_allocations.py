"""Allocation profiles: heap_summary and type_detail with allocations, and allocation_sites.

The fake heapspy prints ``tests/fixtures/heapspy/analyze_allocations.json``
(from feature/alloc-join) for ``--allocations``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp import Client

from heapspy_mcp import allocations as A
from heapspy_mcp.server import build_server


@pytest.fixture
def profile(tmp_path: Path) -> Path:
    path = tmp_path / "app.hpya"
    path.write_bytes(b"HPYA\0")
    return path


async def test_allocation_sites_is_read_only_and_documented(make_config) -> None:
    async with Client(build_server(make_config())) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        workflow = (await client.read_resource("heapspy://workflow")).contents[0].text
    tool = tools["allocation_sites"]
    assert tool.annotations.read_only_hint is True
    assert "approximate" in tool.description and "map_to_source" in tool.description
    assert "allocations" in tools["heap_summary"].input_schema["properties"]
    assert "allocations" in tools["type_detail"].input_schema["properties"]
    # No tool runs `heapspy record`.
    assert not any("record" in name for name in tools)
    assert "allocation_sites" in workflow
    assert "heapspy record` is not implemented" in workflow


async def test_heap_summary_with_allocations(call, snap_file, profile, argv_log) -> None:
    err, out = await call(
        "heap_summary", {"snapshot": str(snap_file), "top": 5, "allocations": str(profile)}
    )
    assert not err, out
    assert argv_log()[-1] == [
        "analyze",
        str(snap_file),
        "--json",
        "--top=5",
        f"--allocations={profile}",
    ]
    first = out["top_retainers"][0]
    at = first["allocated_at"]
    assert at["linked_bytes"] == 62914560 and at["linked_human"] == "60.0 MiB"
    stack = at["stacks"][0]
    assert stack["allocated_in"] == "app/session.py:41"
    assert stack["top_stack_rank"] == 1
    assert [f["function"] for f in stack["frames"]] == [
        "Session.__init__",
        "SessionStore.create",
        "handle_login",
    ]
    assert stack["source_hints"][0] == {
        "location": "app/session.py:41",
        "file": "app/session.py",
        "line": 41,
        "function": "Session.__init__",
        "qualname_guess": "app.session.Session.__init__",
    }
    alloc = out["allocations"]
    assert alloc["recording"]["mechanisms"] == ["ebpf"]
    assert alloc["recording"]["sampling"]["events"] == ["arena", "large_object"]
    assert alloc["coverage"]["linked_pct"] == 13.62
    assert alloc["coverage"]["exact_linked_bytes"] == 1048576
    assert [s["rank"] for s in alloc["top_stacks"]] == [1, 2]
    assert [n["code"] for n in alloc["notes"]] == ["allocations_sampled"]
    assert len(alloc["caveats"]) == 3
    assert "warning" not in alloc


async def test_heap_summary_without_allocations_has_no_block(call, snap_file) -> None:
    err, out = await call("heap_summary", {"snapshot": str(snap_file)})
    assert not err, out
    assert "allocations" not in out
    assert "allocated_at" not in out["top_retainers"][0]


async def test_type_detail_with_allocations(call, snap_file, profile, argv_log) -> None:
    err, out = await call(
        "type_detail", {"snapshot": str(snap_file), "type": "Session", "allocations": str(profile)}
    )
    assert not err, out
    assert argv_log()[-1][-1] == f"--allocations={profile}"
    at = out["top_instances"][0]["allocated_at"]
    assert at["stacks"][0]["top_stack_rank"] is None
    assert at["stacks"][0]["source_hints"][0]["location"] == "app/session.py:41"
    assert [n["code"] for n in out["allocations"]["notes"]] == ["allocations_sampled"]


async def test_not_linked_profile_warns(call, snap_file, profile, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "alloc_not_linked")
    err, out = await call("allocation_sites", {"profile": str(profile), "snapshot": str(snap_file)})
    assert not err, out
    assert {"allocations_pid_mismatch", "allocations_not_linked"} <= {
        n["code"] for n in out["notes"]
    }
    assert "No object was linked" in out["warning"]
    assert out["top_stacks"][0]["linked_bytes"] == 0
    err, out = await call(
        "type_detail", {"snapshot": str(snap_file), "type": "Session", "allocations": str(profile)}
    )
    assert not err, out
    assert "No object was linked" in out["allocations"]["warning"]


async def test_allocation_sites_with_snapshot(call, snap_file, profile, argv_log) -> None:
    err, out = await call(
        "allocation_sites", {"profile": str(profile), "snapshot": str(snap_file), "top": 3}
    )
    assert not err, out
    assert argv_log()[-1] == [
        "analyze",
        str(snap_file),
        "--json",
        "--top=3",
        f"--allocations={profile}",
    ]
    assert out["mode"] == "joined"
    assert out["profile"] == str(profile)
    assert out["snapshot"]["python_version"] == "3.12.4"
    first = out["top_stacks"][0]
    assert first["allocated_in"] == "app/session.py:41"
    assert first["estimated_bytes"] == 94371840 and first["estimated_human"] == "90.0 MiB"
    assert first["linked_bytes"] == 62914560
    assert first["exact_linked_bytes"] == 0
    assert first["samples"] == 1790
    assert first["events"] == ["arena", "large_object"]
    assert out["recording"]["pid"] == 1234
    assert out["recording"]["overhead"]["samples_dropped"] == 0
    assert out["coverage"]["linked_objects"] == 61204
    assert out["caveats"] == list(A.CAVEATS)


async def test_allocation_sites_profile_only(call, profile, argv_log) -> None:
    err, out = await call("allocation_sites", {"profile": str(profile)})
    assert not err, out
    assert argv_log()[-1] == [
        "flamegraph",
        f"--allocations={profile}",
        "--folded",
        "--min-bytes=0",
    ]
    assert out["mode"] == "profile_only"
    stacks = out["top_stacks"]
    # Lines with the same frames are merged: 94371840 + 1024.
    assert stacks[0]["estimated_bytes"] == 94371840 + 1024
    assert stacks[0]["frames"][0]["function"] == "Session.__init__"
    assert stacks[0]["frames"][0]["line"] == 41
    assert stacks[0]["frames"][0]["approximate"] is None
    assert stacks[0]["source_hints"][0]["qualname_guess"] == "app.session.Session.__init__"
    assert stacks[0]["samples"] is None and stacks[0]["linked_bytes"] is None
    assert out["stacks_total"] == 3
    assert out["estimated_bytes"] == 94371840 + 10485760 + 4096 + 1024
    no_stack = next(s for s in stacks if s["frames"][0]["function"] == "[no Python stack]")
    assert no_stack["allocated_in"] is None and no_stack["source_hints"] == []
    assert "need a snapshot" in out["note"]


@pytest.mark.parametrize(
    ("name", "code"),
    [("corrupt.hpya", "invalid_allocations"), ("gone.hpya", None)],
)
async def test_bad_profiles(call, snap_file, tmp_path: Path, name: str, code) -> None:
    path = tmp_path / name
    if code is not None:
        path.write_bytes(b"junk")
    err, out = await call("heap_summary", {"snapshot": str(snap_file), "allocations": str(path)})
    assert err
    if code is None:
        # Checked by the server before heapspy runs.
        assert out["error"]["code"] == "invalid_argument"
        assert "not found" in out["error"]["message"]
    else:
        assert out["error"]["code"] == code
        assert "allocation profile" in out["error"]["hint"]


async def test_profile_must_be_hpya(call, snap_file, argv_log) -> None:
    err, out = await call(
        "allocation_sites", {"profile": str(snap_file), "snapshot": str(snap_file)}
    )
    assert err and out["error"]["code"] == "invalid_argument"
    err, out = await call("allocation_sites", {"profile": "--help.hpya"})
    assert err and out["error"]["code"] == "invalid_argument"
    assert argv_log() == []


async def test_binary_without_allocations(call, snap_file, profile, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "old_binary")
    err, out = await call("heap_summary", {"snapshot": str(snap_file), "allocations": str(profile)})
    assert err and out["error"]["code"] == "allocations_unsupported"
    assert "Upgrade heapspy" in out["error"]["hint"]
    err, out = await call("allocation_sites", {"profile": str(profile)})
    assert err and out["error"]["code"] == "allocations_unsupported"


async def test_binary_with_allocations_flag_but_no_join(
    call, snap_file, profile, monkeypatch
) -> None:
    """heapspy from feature/alloc-format alone: --allocations is accepted and the
    profile checked, but allocations and allocated_at are null."""
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "alloc_not_joined")
    for tool, args in [
        ("heap_summary", {"snapshot": str(snap_file), "allocations": str(profile)}),
        (
            "type_detail",
            {"snapshot": str(snap_file), "type": "Session", "allocations": str(profile)},
        ),
        ("allocation_sites", {"profile": str(profile), "snapshot": str(snap_file)}),
        ("allocation_sites", {"profile": str(profile)}),
    ]:
        err, out = await call(tool, args)
        assert err and out["error"]["code"] == "allocations_unsupported", (tool, out)
        assert "Upgrade heapspy" in out["error"]["hint"]
    # Without a profile the same binary works as before.
    err, out = await call("heap_summary", {"snapshot": str(snap_file)})
    assert not err, out


async def test_allocation_output_is_bounded(call, snap_file, profile, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "big")
    err, out = await call(
        "allocation_sites", {"profile": str(profile), "snapshot": str(snap_file), "top": 50}
    )
    assert not err, out
    assert len(json.dumps(out)) < 250_000
    stack = out["top_stacks"][0]
    assert len(stack["frames"]) == A.MAX_FRAMES and stack["frames_total"] == 200
    assert all(len(f["function"]) <= 200 and len(f["file"]) <= 160 for f in stack["frames"])
    assert stack["frames"][0]["file"].endswith("x/y.py")
    assert len(stack["source_hints"]) <= A.MAX_STACK_HINTS
    err, out = await call(
        "heap_summary", {"snapshot": str(snap_file), "top": 50, "allocations": str(profile)}
    )
    assert not err, out
    at = out["top_retainers"][0]["allocated_at"]
    assert len(at["stacks"]) == A.MAX_ALLOCATED_AT_STACKS and at["stacks_total"] == 5
    assert len(out["allocations"]["top_stacks"]) == A.MAX_SUMMARY_STACKS
    err, out = await call("allocation_sites", {"profile": str(profile), "top": 50})
    assert not err, out
    # 5000 stacks and "[no Python stack]"; the repeated first line is merged.
    assert len(out["top_stacks"]) == 50 and out["stacks_total"] == 5001


@pytest.mark.parametrize(
    ("function", "file", "guess"),
    [
        ("Session.__init__", "app/session.py", "app.session.Session.__init__"),
        ("<module>", "app/__init__.py", "app"),
        ("make.<locals>.inner", "app/f.py", "app.f.make.<locals>.inner"),
        ("run", "/srv/app/app/worker.py", None),
        ("run", "<string>", None),
        ("run", "my-scripts/x.py", None),
        ("<lambda>", "app/f.py", None),
    ],
)
def test_qualname_guess(function: str, file: str, guess: str | None) -> None:
    assert A.qualname_guess(function, file) == guess


def test_parse_folded_locations() -> None:
    frames, weight = A.parse_folded("outer (a/b.py:3);inner (c.py:?);x (<unknown>) 7\n")[0]
    assert weight == 7
    assert [(f["function"], f["file"], f["line"]) for f in frames] == [
        ("x", None, None),
        ("inner", "c.py", None),
        ("outer", "a/b.py", 3),
    ]
    assert A.parse_folded("garbage\n\n") == []
