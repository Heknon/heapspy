"""A process that never goes idle: two threads allocate and free in a loop.

Used to check that a dump taken while the heap is changing still produces a
consistent snapshot. ``STABLE`` is a fixed structure built before the loop
starts, so the test can still check that it is found and sized correctly.
The main thread churns dicts and lists and keeps a bounded ring of recent
ones; a second thread builds and drops nested containers and forces GC
passes, so GC lists are being relinked while the dump runs.
"""

import gc
import sys
import threading

from _victim import ready

STABLE = {f"k{i}": bytes(1024) for i in range(1000)}
RING_SIZE = 512
RING = [None] * RING_SIZE


def churn_nested():
    n = 0
    while True:
        tree = {"children": [[{"v": j, "b": bytes(64)} for j in range(20)] for _ in range(20)]}
        tree["self"] = tree  # a cycle, so the collector has work to do
        del tree
        n += 1
        if n % 200 == 0:
            gc.collect()


threading.Thread(target=churn_nested, name="churn", daemon=True).start()

if __name__ == "__main__":
    ready(
        stable_entries=len(STABLE),
        expected_stable=sys.getsizeof(STABLE)
        + sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in STABLE.items()),
    )

    i = 0
    while True:
        RING[i % RING_SIZE] = {"seq": i, "payload": [i] * 16, "tag": str(i)}
        i += 1
