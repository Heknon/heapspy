"""Known answers for each leak fixture.

Each victim in ``victims/`` writes ``ready.json`` with facts it measured
about itself (``expected_retained`` from ``sys.getsizeof``, counts, indices).
The specs here say what heapspy must report in terms of those facts, so
nothing depends on per-version object sizes.

Retained bytes are checked against a band around ``expected_retained``.
heapspy's shallow size of an instance is ``sys.getsizeof`` plus the
instance's attribute values array, which ``getsizeof`` leaves out (see
docs/cpython-internals.md, "Shallow sizes"), so heapspy reads a little high
for classes with instance dicts: about 2% for the fixtures here. The band
allows 2% under and 10% over. Counting the churned objects in the deep-chain
fixture, or missing the entries of any fixture, is far outside it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

MAIN = "sys.modules['__main__'].__dict__"

Info = dict[str, Any]

RETAINED_LO = 0.98
RETAINED_HI = 1.10


@dataclass(frozen=True)
class Holder:
    """A ``holders[]`` row expected in ``query --type``."""

    type: str
    edge: str
    count: Callable[[Info], int]


@dataclass(frozen=True)
class TypeQuery:
    type: str
    instances: Callable[[Info], int]
    holders: list[Holder]


@dataclass(frozen=True)
class PathTypeQuery:
    """``query --retaining-path-type``: every target has a path with these edges."""

    type: str
    edges: Callable[[Info], list[str]]
    root_path_prefix: str | None = None
    # How many of the largest instances to trace.
    top: int = 3


@dataclass(frozen=True)
class Fixture:
    name: str
    script: str
    # Rank 1 in `analyze --json`.
    top_type: str
    top_root_path: Callable[[Info], str]
    # Edge labels the retaining path of the top retainer must contain, in order.
    top_path_edges: Callable[[Info], list[str]]
    # Other retainers that must be listed below the leak (proves the noise is
    # there and ranked lower).
    noise_root_paths: list[str] = field(default_factory=list)
    type_query: TypeQuery | None = None
    path_type_query: PathTypeQuery | None = None
    # Extra checks: (analyze report, victim info) -> None.
    extra: Callable[[dict[str, Any], Info], None] | None = None


def _deep_chain_extra(report: dict[str, Any], info: Info) -> None:
    totals = report["totals"]
    # About 1 GiB was allocated and dropped. If any of it were counted the
    # heap would be hundreds of MiB; the whole graph is a few MiB.
    graph = totals["reachable_bytes"] + totals["unreachable_bytes"]
    assert graph < info["churned_bytes"] / 50, (graph, info["churned_bytes"])
    # The deepest frame was walked: its local is a frame-local root.
    label = "frame __main__:level_10 local 'scratch'"
    scratch = [t for t in report["top_retainers"] if t["path"][0]["root_label"] == label]
    assert scratch, [t["path"][0]["root_label"] for t in report["top_retainers"]]
    s = scratch[0]
    assert s["path"][0]["root_kind"] == "frame_local"
    assert s["type"] == "builtins.list"
    expected = info["scratch_retained"]
    assert expected * RETAINED_LO <= s["retained_bytes"] <= expected * RETAINED_HI, (
        s["retained_bytes"],
        expected,
    )


FIXTURES = [
    Fixture(
        name="unbounded_cache",
        script="unbounded_cache.py",
        top_type="builtins.dict",
        top_root_path=lambda i: f"{MAIN}['CACHE']",
        top_path_edges=lambda i: [".__dict__", "['CACHE']"],
        noise_root_paths=[f"{MAIN}['SESSIONS']"],
        type_query=TypeQuery(
            type="__main__.CachedResponse",
            instances=lambda i: i["entries"] + 100,
            holders=[
                Holder("builtins.dict", "[<key>]", lambda i: i["entries"]),
                Holder("builtins.list", "[<index>]", lambda i: 100),
            ],
        ),
        path_type_query=PathTypeQuery(
            type="__main__.CachedResponse",
            # Keys are "GET /api/items/NNNNNN" (21 characters), redacted.
            edges=lambda i: [".__dict__", "['CACHE']", "[<str len=21>]"],
            root_path_prefix=f"{MAIN}['CACHE']",
        ),
    ),
    Fixture(
        name="deep_chain",
        script="deep_chain.py",
        top_type="builtins.list",
        top_root_path=lambda i: f"{MAIN}['KEPT']",
        top_path_edges=lambda i: [".__dict__", "['KEPT']"],
        noise_root_paths=[f"{MAIN}['HISTORY']", "frame __main__:level_10 local 'scratch'"],
        extra=_deep_chain_extra,
    ),
    Fixture(
        name="growing_list",
        script="growing_list.py",
        top_type="builtins.list",
        top_root_path=lambda i: f"{MAIN}['EVENTS']",
        top_path_edges=lambda i: [".__dict__", "['EVENTS']"],
        noise_root_paths=[f"{MAIN}['COUNTERS']"],
        type_query=TypeQuery(
            type="__main__.Event",
            instances=lambda i: i["events"] + 20,
            holders=[
                Holder("builtins.list", "[<index>]", lambda i: i["events"] + 20),
            ],
        ),
    ),
    Fixture(
        name="closure_capture",
        script="closure_capture.py",
        top_type="builtins.bytearray",
        top_root_path=lambda i: f"{MAIN}['HANDLER'].__closure__[{i['cell_index']}].cell_contents",
        top_path_edges=lambda i: [
            "['HANDLER']",
            f".__closure__[{i['cell_index']}]",
            ".cell_contents",
        ],
        noise_root_paths=[f"{MAIN}['FRAMES']", f"{MAIN}['STATIC_BUFFER']"],
        path_type_query=PathTypeQuery(
            type="builtins.bytearray",
            edges=lambda i: [f".__closure__[{i['cell_index']}]", ".cell_contents"],
            root_path_prefix=f"{MAIN}['HANDLER']",
            # Only the largest one: the others are the noise buffers.
            top=1,
        ),
    ),
    Fixture(
        name="listener_registry",
        script="listener_registry.py",
        top_type="builtins.list",
        top_root_path=lambda i: f"{MAIN}['BUS'].listeners",
        top_path_edges=lambda i: [".__dict__", "['BUS']", ".listeners"],
        noise_root_paths=[f"{MAIN}['WIDGET_NAMES']"],
        type_query=TypeQuery(
            type="__main__.Listener",
            instances=lambda i: i["listeners"] + 10,
            holders=[
                Holder("builtins.list", "[<index>]", lambda i: i["listeners"] + 10),
            ],
        ),
        path_type_query=PathTypeQuery(
            type="__main__.Listener",
            edges=lambda i: ["['BUS']", ".listeners"],
        ),
    ),
]
