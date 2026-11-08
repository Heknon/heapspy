"""Send this process's memory profiles to Pyroscope, the pyroscope-io way.

    pip install heapspy
    python examples/pyroscope_configure.py

Then open Grafana (or Pyroscope's UI) on service `leaky-shop`, profile type
memory:inuse_space, filtered on heapspy_profile="memory" or "retained".
"""

import logging
import time

import heapspy

logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")

heapspy.configure(
    application_name="leaky-shop",
    server_address="http://localhost:4040",
    tags={"env": "dev", "region": "eu-west-1"},
    enable_logging=True,
    upload_interval=5,  # memory profile every 5 s (default 15)
    # Opt in to more than where the memory is:
    retained=True,  # who holds it, a snapshot every retained_interval
    retained_interval=30,
)

SESSIONS = {}


class Session:
    def __init__(self, n):
        self.history = []
        self.token = "t" * 32 + str(n)


def handle_request(n):
    s = SESSIONS.setdefault(n % 5000, Session(n))
    s.history.append(f"GET /cart/{n}")  # never trimmed: the leak


try:
    n = 0
    while True:
        for _ in range(20000):
            handle_request(n)
            n += 1
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
finally:
    heapspy.shutdown()  # also runs at exit
