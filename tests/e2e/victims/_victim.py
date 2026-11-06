"""Shared plumbing for victim scripts.

A victim is started as ``python VICTIM.py WORKDIR``. It builds its structure,
then calls :func:`ready` with a dict of facts the test needs (sizes computed
with ``sys.getsizeof``, counts, indices). ``ready`` writes ``WORKDIR/ready.json``
atomically and returns; the victim then calls :func:`serve`, which sleeps until
the process is killed.

Victims that change their heap on request pass a callback to :func:`serve`.
The test asks for step ``n`` by creating ``WORKDIR/trigger-<n>``; the victim
runs the callback and writes ``WORKDIR/done-<n>.json`` with what it returns.
A file trigger works the same way on Linux and Windows (no signals).

This module is imported by the victims, so it is part of every victim heap.
Keep it small and free of large objects.
"""

from __future__ import annotations

import json
import os
import sys
import time

WORKDIR = sys.argv[1] if len(sys.argv) > 1 else "."


def _write_json(name: str, data: dict) -> None:
    path = os.path.join(WORKDIR, name)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def ready(**info: object) -> None:
    """Report that the heap is built. ``info`` must be JSON-serializable."""
    info.setdefault("pid", os.getpid())
    info.setdefault("python", ".".join(map(str, sys.version_info[:3])))
    _write_json("ready.json", dict(info))


def serve(on_trigger=None, poll: float = 0.05) -> None:
    """Sleep until killed, running ``on_trigger(n)`` for each ``trigger-<n>`` file."""
    step = 1
    while True:
        if on_trigger is not None:
            trigger = os.path.join(WORKDIR, f"trigger-{step}")
            if os.path.exists(trigger):
                result = on_trigger(step)
                _write_json(f"done-{step}.json", dict(result or {}))
                step += 1
                continue
        time.sleep(poll)
