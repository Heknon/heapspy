"""Unbounded module-level cache.

Leak: ``CACHE`` maps a request key to a ``CachedResponse`` and is never
evicted. Expected top retainer: that dict, at
``sys.modules['__main__'].__dict__['CACHE']``, retaining about
``expected_retained`` bytes (computed below with ``sys.getsizeof``).

Noise, all smaller in bytes than the leak:
- ``SESSIONS``: a dict with more entries than ``CACHE`` (so "dict with the
  most entries" picks the wrong one) of a similarly shaped class with small
  payloads.
- ``RECENT``: a list of ``CachedResponse`` objects that also appear nowhere
  else, so the type is not unique to the leak's holder.
- ``CONFIG``: a plain nested dict.
"""

import sys

from _victim import ready, serve

ENTRIES = 2000
PAYLOAD = 2048


class CachedResponse:
    def __init__(self, i, size):
        self.status = 200 + (i % 3)
        self.request_id = 10_000 + i
        self.body = bytes([i % 251]) * size


class Session:
    def __init__(self, i):
        self.user_id = 50_000 + i
        self.token = bytes(16)


CACHE = {}
for i in range(ENTRIES):
    CACHE[f"GET /api/items/{i:06d}"] = CachedResponse(i, PAYLOAD)

SESSIONS = {f"user-{i}": Session(i) for i in range(ENTRIES * 2)}
RECENT = [CachedResponse(i, 256) for i in range(100)]
CONFIG = {"db": {"host": "localhost", "port": 5432}, "workers": list(range(8))}


def entry_size(key, value):
    """getsizeof over the objects one cache entry owns."""
    return (
        sys.getsizeof(key)
        + sys.getsizeof(value)
        + sys.getsizeof(value.body)
        + sys.getsizeof(value.request_id)
    )


if __name__ == "__main__":
    per_entry = [entry_size(k, v) for k, v in CACHE.items()]
    ready(
        entries=ENTRIES,
        per_entry_bytes=per_entry[0],
        container_bytes=sys.getsizeof(CACHE),
        expected_retained=sys.getsizeof(CACHE) + sum(per_entry),
        noise_retained=sys.getsizeof(SESSIONS)
        + sum(
            sys.getsizeof(k) + sys.getsizeof(s) + sys.getsizeof(s.token) + sys.getsizeof(s.user_id)
            for k, s in SESSIONS.items()
        ),
    )
    serve()
