"""A listener registry that is never cleaned up.

Leak: every ``Widget`` subscribes a ``Listener`` to the global ``BUS`` and
never unsubscribes. The widgets are gone, but ``BUS.listeners`` keeps every
listener and the buffer it captured. Expected top retainer: the list at
``sys.modules['__main__'].__dict__['BUS'].listeners``.

Noise:
- ``ADMIN_BUS``: a second ``EventBus`` with a few listeners.
- ``WIDGET_NAMES``: a list with more items than ``BUS.listeners`` (strings).
- ``LIVE_WIDGETS``: a handful of live widgets that are still subscribed;
  their listeners are shared with ``BUS.listeners``.
"""

import sys

from _victim import ready, serve

WIDGETS = 1500
STATE = 1536


class Listener:
    def __init__(self, owner_id, size):
        self.owner_id = 100_000 + owner_id
        self.state = bytearray(size)

    def __call__(self, event):
        return len(self.state)


class EventBus:
    def __init__(self, name):
        self.name = name
        self.listeners = []

    def subscribe(self, listener):
        self.listeners.append(listener)


class Widget:
    def __init__(self, i, bus, size):
        self.listener = Listener(i, size)
        bus.subscribe(self.listener)


BUS = EventBus("main")
ADMIN_BUS = EventBus("admin")

for i in range(WIDGETS):
    Widget(i, BUS, STATE)  # dropped at once; its listener stays in BUS
for i in range(10):
    Widget(i, ADMIN_BUS, 256)
LIVE_WIDGETS = [Widget(WIDGETS + i, BUS, STATE) for i in range(5)]
WIDGET_NAMES = [f"widget-{i}" for i in range(WIDGETS * 4)]


def listener_size(listener):
    return (
        sys.getsizeof(listener) + sys.getsizeof(listener.owner_id) + sys.getsizeof(listener.state)
    )


# The listeners of LIVE_WIDGETS are also reachable from LIVE_WIDGETS, so the
# list does not dominate them.
if __name__ == "__main__":
    dropped = BUS.listeners[:WIDGETS]
    ready(
        listeners=len(BUS.listeners),
        dropped=len(dropped),
        expected_retained=sys.getsizeof(BUS.listeners) + sum(listener_size(x) for x in dropped),
    )
    del dropped
    serve()
