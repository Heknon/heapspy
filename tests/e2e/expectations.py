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
allows 2% under and 10% over. Missing the entries of a fixture is far
outside it.
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
]
