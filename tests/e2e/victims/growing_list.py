"""A module-level list that keeps growing.

Leak: every "request" appends an ``Event`` to ``EVENTS`` and nothing removes
them. Expected top retainer: ``EVENTS`` (``builtins.list``) at
``sys.modules['__main__'].__dict__['EVENTS']``.

Each trigger file (see ``_victim.serve``) appends ``GROW_BY`` more events,
so the diff test can dump, grow, and dump again. ``done-<n>.json`` reports
the new count and the bytes added, computed with ``sys.getsizeof``.

Noise:
- ``COUNTERS``: a list with ten times as many items as ``EVENTS`` (floats),
  but fewer bytes, so "longest list" picks the wrong one.
- ``ERRORS``: a short list of ``Event`` objects, so the type is not unique
  to the leak.
"""

import sys

from _victim import ready, serve

INITIAL = 3000
GROW_BY = 1500
DETAIL = 400


class Event:
    __slots__ = ("seq", "kind", "detail")

    def __init__(self, seq, kind):
        self.seq = 1_000_000 + seq
        self.kind = kind
        self.detail = bytes([seq % 251]) * DETAIL


EVENTS = []
COUNTERS = [float(i) for i in range(INITIAL * 10)]
ERRORS = [Event(i, "error") for i in range(20)]


def event_size(e):
    return sys.getsizeof(e) + sys.getsizeof(e.seq) + sys.getsizeof(e.detail)


def handle_requests(n):
    added = 0
    for _ in range(n):
        e = Event(len(EVENTS), "request")
        EVENTS.append(e)
        added += event_size(e)
    return added


def retained():
    return sys.getsizeof(EVENTS) + sum(event_size(e) for e in EVENTS)


handle_requests(INITIAL)


def grow(step):
    before = retained()
    handle_requests(GROW_BY)
    return {
        "events": len(EVENTS),
        "added_events": GROW_BY,
        "expected_retained": retained(),
        "delta_retained": retained() - before,
    }


if __name__ == "__main__":
    ready(
        events=len(EVENTS),
        per_event_bytes=event_size(EVENTS[0]),
        expected_retained=retained(),
        grow_by=GROW_BY,
    )
    serve(grow)
