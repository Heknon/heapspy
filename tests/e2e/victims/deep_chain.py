"""Partial retention at the bottom of a deep call chain.

``level_1`` calls ``level_2`` ... down to ``level_10``. The leaf allocates
``ITERATIONS`` 1 KiB blobs and keeps one in every ``KEEP_EVERY`` in the
module-level list ``KEPT``; the rest are dropped at once. Over the run the
leaf allocates about 1 GiB, but only about 1 MiB stays alive.

Expected top retainer: ``KEPT`` (``builtins.list``) at
``sys.modules['__main__'].__dict__['KEPT']``, retaining only the kept blobs.
If churned blobs were counted, retained and reachable sizes would be
hundreds of times larger.

The process then sleeps inside ``level_10``, so the whole chain is on the
stack when the dump is taken. Noise:
- ``scratch``, a local of ``level_10`` holding 300 half-KiB blobs: a
  frame-local root, ``frame __main__:level_10 local 'scratch'``.
- ``HISTORY``, a global list with more items than ``KEPT`` but small ones.
"""

import sys

from _victim import ready, serve

ITERATIONS = 1_000_000
KEEP_EVERY = 1000
BLOB = 1024

KEPT = []
HISTORY = [float(i) for i in range(5000)]


def level_10(depth):
    scratch = [bytes(512) for _ in range(300)]
    churned = 0
    for i in range(ITERATIONS):
        blob = bytes(BLOB)
        if i % KEEP_EVERY == 0:
            KEPT.append(blob)
        else:
            churned += sys.getsizeof(blob)
    del blob
    ready(
        depth=depth,
        kept=len(KEPT),
        blob_bytes=sys.getsizeof(KEPT[0]),
        expected_retained=sys.getsizeof(KEPT) + sum(sys.getsizeof(b) for b in KEPT),
        churned_bytes=churned,
        scratch_retained=sys.getsizeof(scratch) + sum(sys.getsizeof(b) for b in scratch),
    )
    serve()


def level_9(depth):
    level_10(depth + 1)


def level_8(depth):
    level_9(depth + 1)


def level_7(depth):
    level_8(depth + 1)


def level_6(depth):
    level_7(depth + 1)


def level_5(depth):
    level_6(depth + 1)


def level_4(depth):
    level_5(depth + 1)


def level_3(depth):
    level_4(depth + 1)


def level_2(depth):
    level_3(depth + 1)


def level_1(depth):
    level_2(depth + 1)


if __name__ == "__main__":
    level_1(1)
