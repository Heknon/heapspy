"""Target processes for the py-spy integration tests.

python cpu_victims.py burn|sleep|gil|fsync [dir]

Prints "ready" once the threads are set up, then runs until killed.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time


def burn_cpu() -> None:
    x = 0
    while True:
        for i in range(10_000):
            x += i * i


def sleep_forever() -> None:
    while True:
        time.sleep(1)


def read_socket(sock: socket.socket) -> None:
    sock.recv(10)  # nothing is ever sent


def contend() -> None:
    x = 0
    while True:
        for i in range(10_000):
            x += i * i


def fsync_loop(directory: str) -> None:
    fd, _path = tempfile.mkstemp(dir=directory)
    block = b"x" * 4096
    while True:
        os.write(fd, block)
        os.fsync(fd)


def main() -> None:
    mode = sys.argv[1]
    if mode == "burn":
        print("ready", flush=True)
        burn_cpu()
    elif mode == "sleep":
        a, _b = socket.socketpair()
        threading.Thread(target=read_socket, args=(a,), name="reader", daemon=True).start()
        print("ready", flush=True)
        sleep_forever()
    elif mode == "gil":
        for n in range(4):
            threading.Thread(target=contend, name=f"worker-{n}", daemon=True).start()
        print("ready", flush=True)
        threading.Event().wait()
    elif mode == "fsync":
        print("ready", flush=True)
        fsync_loop(sys.argv[2])
    else:
        raise SystemExit(f"unknown mode {mode}")


if __name__ == "__main__":
    main()
