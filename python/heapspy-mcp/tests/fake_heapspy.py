"""A stand-in for the heapspy binary, driven by argv and environment variables.

It prints the documents from ``docs/examples`` (adjusted to the arguments)
the way ``heapspy ... --json`` would.

Environment:
    FAKE_HEAPSPY_EXAMPLES  directory holding the example JSON documents (required)
    FAKE_HEAPSPY_MODE      ok (default), error:<code>, bad_schema, not_json, timeout,
                           usage, wrong_kind, crash, big, error_exit0,
                           dump_hang (dump writes a temporary file and hangs)
    FAKE_HEAPSPY_LOG       if set, each argv is appended to this file as a JSON line
"""

from __future__ import annotations

import copy
import json
import os
import sys
import time
from pathlib import Path

EXAMPLES = Path(os.environ["FAKE_HEAPSPY_EXAMPLES"])
MODE = os.environ.get("FAKE_HEAPSPY_MODE", "ok")


def load(name: str) -> dict:
    return json.loads((EXAMPLES / f"{name}.json").read_text())


def emit(doc: dict, status: int = 0) -> None:
    print(json.dumps(doc, indent=2))
    sys.exit(status)


def fail(code: str, message: str) -> None:
    print(f"heapspy: error: {message}", file=sys.stderr)
    emit({"schema_version": 1, "kind": "error", "error": {"code": code, "message": message}}, 1)


def opt(args: list[str], name: str) -> str | None:
    for i, a in enumerate(args):
        if a.startswith(f"--{name}="):
            return a.split("=", 1)[1]
        if a == f"--{name}" and i + 1 < len(args):
            return args[i + 1]
    return None


def hop(i: int, label_len: int = 10) -> dict:
    return {
        "address": f"0x{0x7F0000000000 + i * 16:x}",
        "type": "builtins.dict" if i % 2 else "app.node.Node",
        "shallow_bytes": 64,
        "edge": None if i == 0 else f"['{'k' * label_len}{i}']",
        "root_label": "sys.modules['app.big']" if i == 0 else None,
        "root_kind": "module_dict" if i == 0 else None,
    }


def long_path(n: int) -> list[dict]:
    return [hop(i, label_len=400) for i in range(n)]


def big_analyze() -> dict:
    doc = load("analyze")
    doc["top_retainers"] = [
        {
            "rank": r + 1,
            "address": f"0x{0x7E0000000000 + r * 64:x}",
            "type": "app.node.Node",
            "shallow_bytes": 64,
            "retained_bytes": 10_000_000 - r,
            "retained_objects": 10,
            "retained_pct": 1.0,
            "path": long_path(100),
        }
        for r in range(500)
    ]
    doc["type_histogram"] = [
        {"type": f"app.t.T{i}", "count": 1, "shallow_bytes": 1, "retained_bytes": 1}
        for i in range(500)
    ]
    doc["notes"] = [{"code": "x", "message": "m" * 5000}] * 100
    return doc


def main() -> None:
    log = os.environ.get("FAKE_HEAPSPY_LOG")
    if log:
        with open(log, "a") as f:
            f.write(json.dumps(sys.argv[1:]) + "\n")

    args = sys.argv[1:]
    if MODE == "timeout":
        time.sleep(30)
    if MODE == "usage":
        print("error: unexpected argument", file=sys.stderr)
        sys.exit(2)
    if MODE == "crash":
        print("thread 'main' panicked at src/main.rs:1", file=sys.stderr)
        sys.exit(101)
    if MODE == "not_json":
        print("Top retainers by retained size\n  412.6 MiB builtins.dict")
        sys.exit(0)
    if MODE.startswith("error:"):
        code = MODE.split(":", 1)[1]
        fail(code, f"simulated {code} error")
    if MODE == "error_exit0":
        emit({"schema_version": 1, "kind": "error", "error": {"code": "io", "message": "x"}}, 0)

    cmd = args[0] if args else ""
    if cmd == "dump":
        out = opt(args, "output")
        if not out:
            sys.exit(2)
        if MODE == "dump_fail":
            print("heapspy: error: cannot open pid 1: permission denied", file=sys.stderr)
            sys.exit(1)
        if MODE == "dump_no_file":
            sys.exit(0)
        if MODE == "dump_hang":
            # Like heapspy's writer: a temporary file next to the output, then a hang.
            (Path(out).parent / ".tmpAbC123").write_bytes(b"partial")
            time.sleep(30)
        Path(out).write_bytes(b"HPYSNAP\0" + b"\0" * 120)
        trunc = " (truncated)" if MODE == "dump_truncated" else ""
        print(f"wrote {out}: 10 objects, 20 edges, 3 roots, 128 bytes{trunc}", file=sys.stderr)
        sys.exit(0)

    if "--json" not in args:
        sys.exit(2)

    if cmd == "analyze":
        doc = big_analyze() if MODE == "big" else load("analyze")
        doc["snapshot"]["path"] = args[1]
        top = int(opt(args, "top") or 20)
        doc["top_retainers"] = doc["top_retainers"][:top]
        doc["type_histogram"] = doc["type_histogram"][:top]
    elif cmd == "query" and opt(args, "type") is not None:
        t = opt(args, "type")
        if t == "Missing":
            fail("not_found", f"no type matches {t}")
        doc = load("type_query")
        doc["snapshot"]["path"] = args[1]
        doc["query"] = t
        if MODE == "big":
            inst = doc["top_instances"][0]
            doc["top_instances"] = [
                {**copy.deepcopy(inst), "address": f"0x{0x7D0000000000 + i * 64:x}"}
                for i in range(20)
            ]
            doc["matched_types"] = [f"app.m{i}.Session" for i in range(300)]
            doc["holders"] = [doc["holders"][0]] * 20
    elif cmd == "query" and opt(args, "retaining-path") is not None:
        addr = opt(args, "retaining-path")
        if addr == "0xdead":
            fail("not_found", f"no object at address {addr} in {args[1]}")
        doc = load("retaining_path")
        doc["snapshot"]["path"] = args[1]
        doc["query"]["value"] = addr
        doc["targets"][0]["address"] = addr
        if MODE == "big":
            doc["targets"][0]["paths"] = [long_path(60) for _ in range(20)]
    elif cmd == "diff":
        doc = load("diff")
        doc["before"]["path"], doc["after"]["path"] = args[1], args[2]
        if MODE == "big":
            row = doc["by_type"][0]
            doc["by_type"] = [{**row, "type": f"app.t.T{i}"} for i in range(200)]
            doc["by_site"] = [doc["by_site"][0]] * 200
    else:
        sys.exit(2)

    if MODE == "bad_schema":
        doc["schema_version"] = 2
    if MODE == "wrong_kind":
        doc["kind"] = "something_else"
    emit(doc)


if __name__ == "__main__":
    main()
