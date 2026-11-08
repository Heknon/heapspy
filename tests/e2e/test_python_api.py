"""``heapspy.configure()``: the pyroscope-io interface, in Python.

An application calls ``heapspy.configure(...)`` with the arguments it would
give ``pyroscope.configure(...)``; heapspy's agent starts for that process
and pushes memory profiles to the server. A mock Pyroscope records the
pushes: the labels, the credentials and headers, and that the agent stops
with ``shutdown()``.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from harness import IS_LINUX, TIMEOUT

MODULE = Path(__file__).resolve().parents[2] / "python" / "heapspy"

APP = """
import json, sys, time
import heapspy

heapspy.configure(
    application_name="checkout",
    server_address=sys.argv[1],
    basic_auth_username="123456",
    basic_auth_password="s3cret",
    tags={"env": "e2e", "region": "eu"},
    http_headers={"X-Team": "payments"},
    upload_interval=0.3,
    # pyroscope-io's CPU options are accepted, and ignored:
    sample_rate=100, oncpu=True, gil_only=True, report_pid=True,
)
keep = [bytes(512) for _ in range(20000)]
deadline = time.time() + 20
while time.time() < deadline and int(open(sys.argv[2]).read() or 0) < 2:
    time.sleep(0.1)
running = heapspy.is_running()
stopped = heapspy.shutdown()
print(json.dumps({"running": running, "stopped": stopped, "after": heapspy.is_running()}))
"""


class Pyroscope:
    """Records every push and writes how many to ``count_file``."""

    def __init__(self, count_file: Path):
        self.pushes: list[tuple[dict, dict]] = []
        pushes, lock = self.pushes, threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with lock:
                    for s in body["series"]:
                        labels = {x["name"]: x["value"] for x in s["labels"]}
                        pushes.append((labels, dict(self.headers)))
                    count_file.write_text(str(len(pushes)))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args) -> None:
                pass

        count_file.write_text("0")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()


@pytest.mark.skipif(not IS_LINUX, reason="reading without stopping is checked on Linux")
def test_configure_sends_memory_profiles(heapspy_bin, python, tmp_path) -> None:
    count = tmp_path / "count"
    server = Pyroscope(count)
    script = tmp_path / "app.py"
    script.write_text(APP)
    env = dict(os.environ, PYTHONPATH=str(MODULE), HEAPSPY_BIN=str(heapspy_bin))
    try:
        app = subprocess.Popen(
            [str(python.path), str(script), server.url, str(count)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        out, err = app.communicate(timeout=TIMEOUT)
    finally:
        server.close()
    assert app.returncode == 0, err
    assert json.loads(out) == {"running": True, "stopped": True, "after": False}, err

    assert len(server.pushes) >= 2, (server.pushes, err)
    labels, headers = server.pushes[0]
    assert labels["__name__"] == "memory"
    assert labels["heapspy_profile"] == "memory"
    assert labels["service_name"] == "checkout"
    assert labels["pid"] == str(app.pid)
    assert labels["env"] == "e2e" and labels["region"] == "eu"
    auth = base64.b64encode(b"123456:s3cret").decode()
    assert headers.get("Authorization") == f"Basic {auth}", headers
    assert headers.get("X-Team") == "payments", headers

    # The password is not on the agent's command line.
    agents = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
    assert "s3cret" not in agents
    assert f"agent --server {server.url}" not in agents, "the agent outlived shutdown()"


def test_configure_checks_its_arguments(heapspy_bin) -> None:
    sys.path.insert(0, str(MODULE))
    try:
        import heapspy
    finally:
        sys.path.remove(str(MODULE))
    with pytest.raises(ValueError, match="tag"):
        heapspy.configure(tags={"service_name": "x"})
    with pytest.raises(ValueError, match="tag key"):
        heapspy.configure(tags={"1st": "x"})
    with pytest.raises(ValueError, match="retained"):
        heapspy.configure(stop=True)
    with pytest.raises(ValueError, match="upload_interval"):
        heapspy.configure(upload_interval=0)
    assert not heapspy.is_running()
