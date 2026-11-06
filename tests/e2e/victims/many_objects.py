"""A heap of about two million objects, for the performance budget test.

``RECORDS`` holds ``N`` small lists ``[int, str]``; every list, int and str is
a separate object, so the walker sees about ``3 * N`` objects plus the
interpreter's own. ``INDEX`` maps every tenth id to its record, adding a
dict and many shared edges.
"""

import gc
import sys

from _victim import ready, serve

N = 700_000

gc.disable()  # building is much faster without collections in between
RECORDS = [[1_000_000 + i, f"r{i}"] for i in range(N)]
INDEX = {r[0]: r for r in RECORDS[::10]}
gc.enable()


def record_size(r):
    return sys.getsizeof(r) + sys.getsizeof(r[0]) + sys.getsizeof(r[1])


# Every tenth record is also reachable from INDEX, so RECORDS does not
# dominate it.
if __name__ == "__main__":
    ready(
        records=N,
        approx_objects=3 * N,
        expected_retained=sys.getsizeof(RECORDS)
        + sum(record_size(r) for i, r in enumerate(RECORDS) if i % 10),
    )
    serve()
