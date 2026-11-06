"""A stand-in for the py-spy binary, driven by argv and environment variables.

``dump --json`` prints two threads: MainThread (active, holds the GIL, in
app.hot.compute) and worker (idle, in app.pool.wait). ``record --format raw``
writes folded stacks for the same threads, filtered the way py-spy filters
them: without ``--idle`` only the active thread, with ``--gil`` only the GIL
holder.

Environment:
    FAKE_PYSPY_MODE  ok (default), permission, not_python, no_such_process, crash,
                     not_json, timeout, big, locals, no_output, bad_folded, behind,
                     empty
    FAKE_PYSPY_LOG   if set, each argv is appended to this file as a JSON line
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

MODE = os.environ.get("FAKE_PYSPY_MODE", "ok")


def opt(args: list[str], name: str) -> str | None:
    for a in args:
        if a.startswith(f"--{name}="):
            return a.split("=", 1)[1]
    return None


def frame(name: str, short: str, line: int, *, locals_: bool = False) -> dict:
    out = {
        "name": name,
        "filename": f"/srv/app/{short}",
        "module": None,
        "short_filename": short,
        "line": line,
        "locals": None,
        "is_entry": False,
        "is_shim_entry": False,
    }
    if locals_:
        out["locals"] = [{"name": "password", "addr": 1, "arg": True, "repr": "'hunter2'"}]
    return out


def dump_doc(pid: int) -> list[dict]:
    loc = MODE == "locals"
    threads = [
        {
            "pid": pid,
            "thread_id": 140000000000001,
            "thread_name": "worker",
            "os_thread_id": pid,
            "active": False,
            "owns_gil": False,
            "frames": [
                frame("wait", "app/pool.py", 40, locals_=loc),
                frame("Thread.run", "threading.py", 1010),
            ],
        },
        {
            "pid": pid,
            "thread_id": 140000000000002,
            "thread_name": "MainThread",
            "os_thread_id": pid,
            "active": True,
            "owns_gil": True,
            "frames": [
                frame("compute", "app/hot.py", 12, locals_=loc),
                frame("main", "app/__main__.py", 5),
                frame("<module>", "<string>", 1),
            ],
        },
    ]
    if MODE == "big":
        deep = [frame(f"f{i}", "app/deep.py", i + 1) for i in range(300)]
        threads = [
            {**threads[0], "thread_name": f"t{i}", "frames": deep, "active": i % 2 == 0}
            for i in range(500)
        ]
    return threads


MAIN = "thread ({tid}): MainThread;<module> (<string>:1);main (app/__main__.py:5)"
HOT = MAIN + ";compute (app/hot.py:{line})"
HELPER = MAIN + ";helper (app/hot.py:30)"
IDLE = "thread ({tid}): worker;Thread.run (threading.py:1010);wait (app/pool.py:40)"


def folded(args: list[str], pid: int) -> list[str]:
    idle = "--idle" in args
    gil = "--gil" in args
    lines = [HOT.format(tid=pid, line=12) + " 60", HOT.format(tid=pid, line=13) + " 20"]
    if not gil:
        # Active without the GIL: e.g. C code that released it.
        lines.append(HELPER.format(tid=pid) + " 10")
    if idle and not gil:
        lines.append(IDLE.format(tid=pid + 1) + " 100")
    if "--subprocesses" in args:
        lines = [f'process {pid}:"python app.py; x";{line}' for line in lines]
    if MODE == "big":
        deep = ";".join(f"f{i} (app/deep.py:{i + 1})" for i in range(200))
        lines = [
            f"thread ({pid}): MainThread;{deep};leaf{i} (app/leaf.py:{i}) 1" for i in range(500)
        ]
    return lines


def fail(message: str, status: int = 1) -> None:
    print(f"Error: {message}\n\nStack backtrace:\n   0: anyhow::error", file=sys.stderr)
    sys.exit(status)


def main() -> None:
    log = os.environ.get("FAKE_PYSPY_LOG")
    if log:
        with open(log, "a") as f:
            f.write(json.dumps(sys.argv[1:]) + "\n")
    args = sys.argv[1:]
    cmd = args[0] if args else ""
    pid = int(opt(args, "pid") or 0)

    if MODE == "timeout":
        time.sleep(60)
    if MODE == "permission":
        print(
            "Permission Denied: Try running again with elevated permissions by going "
            "'sudo env \"PATH=$PATH\" !!'",
            file=sys.stderr,
        )
        sys.exit(1)
    if MODE == "not_python":
        fail("Failed to find python version from target process")
    if MODE == "no_such_process":
        fail("Failed to get process executable name. Check that the process is running.")
    if MODE == "crash":
        fail("something unexpected happened", status=101)
    if "--locals" in args:
        fail("the fake refuses --locals: heapspy-mcp must never pass it", status=2)

    if cmd == "dump":
        if "--native" in args and "--nonblocking" in args:
            fail("Can't get native stack traces with the --nonblocking option.")
        if MODE == "not_json":
            print("Thread 1 (active): MainThread")
            sys.exit(0)
        print(json.dumps(dump_doc(pid), indent=2))
        sys.exit(0)

    if cmd == "record":
        out = opt(args, "output")
        fmt = opt(args, "format")
        if not out or not fmt:
            sys.exit(2)
        print("py-spy> Sampling process 100 times a second. Press Control-C to exit.")
        if MODE == "behind":
            print(
                "py-spy> 1.20s behind in sampling, results may be inaccurate. "
                "Try reducing the sampling rate"
            )
        if MODE == "no_output":
            sys.exit(0)
        if fmt == "raw":
            if MODE == "empty":
                lines = []
            elif MODE == "bad_folded":
                lines = ["this is not a folded line"]
            else:
                lines = folded(args, pid)
            Path(out).write_text("".join(line + "\n" for line in lines))
            samples = sum(int(line.rsplit(" ", 1)[1]) for line in lines if line[-1:].isdigit())
        elif fmt == "speedscope":
            Path(out).write_text(
                '{"$schema": "https://www.speedscope.app/file-format-schema.json"}'
            )
            samples = 90
        elif fmt == "flamegraph":
            Path(out).write_text("<svg></svg>")
            samples = 90
        else:
            sys.exit(2)
        print(f"py-spy> Wrote data to '{out}'. Samples: {samples} Errors: 0")
        sys.exit(0)

    sys.exit(2)


if __name__ == "__main__":
    main()
