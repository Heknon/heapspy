"""A stand-in for the heapspy binary, driven by argv and environment variables.

It prints the documents from ``docs/examples`` and ``tests/fixtures/heapspy``
(adjusted to the arguments) the way ``heapspy ... --json`` would.

Environment:
    FAKE_HEAPSPY_EXAMPLES  directory holding the example JSON documents (required)
    FAKE_HEAPSPY_FIXTURES  directory holding examples from unmerged heapspy branches
                           (needed for dump --json and --allocations output)
    FAKE_HEAPSPY_MODE      ok (default), error:<code>, bad_schema, not_json, timeout,
                           usage, wrong_kind, crash, big, error_exit0;
                           for dump also dump_fail (text error, no document),
                           dump_no_file, dump_hang (writes a temporary file and
                           hangs), dump_truncated, dump_no_json (exit 0, no
                           document), dump_usage (usage error naming --json in its
                           Usage line), old_binary (a heapspy without dump --json,
                           --allocations, flamegraph, query --locate or the source
                           location fields in its reports);
                           with --allocations also alloc_not_linked (a profile from
                           another pid); a profile path containing "corrupt" fails with
                           invalid_allocations, a missing one with io
    FAKE_HEAPSPY_LOG       if set, each argv is appended to this file as a JSON line
    FAKE_HEAPSPY_LOCATE    JSON object mapping a name to the ``matches`` that
                           ``query --locate NAME`` prints; a name not in it (and not the
                           example's) is not_found
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


def load_fixture(name: str) -> dict:
    """An example from a heapspy branch not merged here (tests/fixtures/heapspy)."""
    fixtures = Path(os.environ["FAKE_HEAPSPY_FIXTURES"])
    return json.loads((fixtures / f"{name}.json").read_text())


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


LOCATION_FIELDS = (
    "source_loc",
    "source_loc_reason",
    "type_location",
    "type_location_reason",
    "matched_type_locations",
)


def strip_locations(value: object) -> None:
    """Remove the source location fields, as a heapspy from before them prints."""
    if isinstance(value, dict):
        for key in LOCATION_FIELDS:
            value.pop(key, None)
        for v in value.values():
            strip_locations(v)
    elif isinstance(value, list):
        for v in value:
            strip_locations(v)


def usage_error(flag: str, usage: str) -> None:
    """clap's message for an argument this heapspy version does not know."""
    print(
        f"error: unexpected argument '{flag}' found\n\nUsage: {usage}\n\n"
        "For more information, try '--help'.",
        file=sys.stderr,
    )
    sys.exit(2)


def dump(args: list[str]) -> None:
    out = opt(args, "output")
    if not out:
        sys.exit(2)
    json_out = "--json" in args
    if json_out and MODE == "old_binary":
        usage_error("--json", "heapspy dump --output <OUT> <--pid <PID>|--core <PATH>>")
    if MODE == "dump_usage":
        # A newer heapspy prints --json in the Usage line of every dump usage error.
        print(
            "error: the following required arguments were not provided:\n"
            "  --capture-contents\n\n"
            "Usage: heapspy dump --output <OUT> --capture-contents --json --max-str <N> "
            "<--pid <PID>|--core <PATH>|--minidump <PATH>>",
            file=sys.stderr,
        )
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
    truncated = MODE == "dump_truncated"
    Path(out).write_bytes(b"HPYSNAP\0" + b"\0" * 120)
    trunc = " (truncated)" if truncated else ""
    print(f"wrote {out}: 10 objects, 20 edges, 3 roots, 128 bytes{trunc}", file=sys.stderr)
    if not json_out or MODE in ("old_binary", "dump_no_json"):
        sys.exit(0)
    doc = load_fixture("dump")
    doc["path"] = out
    for kind in ("pid", "core", "minidump"):
        ref = opt(args, kind)
        if ref is not None:
            doc["source"] = {"kind": kind, "ref": ref}
            if kind != "pid":
                doc["pause_ms"] = None
    doc["contents_captured"] = "--capture-contents" in args
    doc.update(objects=10, edges=20, roots=3, bytes_written=128)
    if truncated:
        doc["truncated"] = True
        doc["image"]["missing_bytes"] = 4096
        doc["notes"] = [
            {"code": "truncated_snapshot", "message": "The snapshot is marked truncated."},
            {"code": "image_incomplete", "message": "The image is missing 4096 bytes."},
            *doc["notes"],
        ]
    emit(doc)


def check_profile(args: list[str]) -> str | None:
    """The --allocations path, after the checks heapspy makes when opening it."""
    profile = opt(args, "allocations")
    if profile is None:
        return None
    if MODE == "old_binary":
        usage_error("--allocations", f"heapspy {args[0]} <SNAP>")
    if "corrupt" in profile:
        fail("invalid_allocations", f"{profile} is not an allocation profile")
    if not Path(profile).is_file():
        fail("io", f"cannot open {profile}: No such file or directory (os error 2)")
    return profile


NOT_LINKED_NOTES = [
    {
        "code": "allocations_pid_mismatch",
        "message": "The allocation profile was recorded from pid 999, the snapshot from 1234.",
    },
    {
        "code": "allocations_not_linked",
        "message": "No object was linked to an allocation sample.",
    },
]


def analyze_with_allocations(args: list[str], profile: str, top: int) -> dict:
    doc = load_fixture("analyze_allocations")
    doc["snapshot"]["path"] = args[1]
    doc["allocations"]["path"] = profile
    doc["top_retainers"] = doc["top_retainers"][:top]
    doc["type_histogram"] = doc["type_histogram"][:top]
    doc["allocations"]["top_stacks"] = doc["allocations"]["top_stacks"][:top]
    if MODE == "alloc_not_linked":
        cov = doc["allocations"]["coverage"]
        for k in cov:
            cov[k] = 0
        for s in doc["allocations"]["top_stacks"]:
            s["linked_bytes"] = s["exact_linked_bytes"] = 0
        for r in doc["top_retainers"]:
            r["allocated_at"] = {
                "linked_objects": 0,
                "linked_bytes": 0,
                "exact_linked_bytes": 0,
                "stacks": [],
                "approximate": False,
            }
        doc["notes"] = [*doc["notes"], *NOT_LINKED_NOTES]
    if MODE == "big":
        stack = doc["allocations"]["top_stacks"][0]
        frame = stack["frames"][0]
        many = [{**frame, "function": "f" * 1000, "file": "x/" * 400 + "y.py"}] * 200
        doc["allocations"]["top_stacks"] = [
            {**copy.deepcopy(stack), "rank": i + 1, "frames": many} for i in range(top)
        ]
        at = doc["top_retainers"][0]["allocated_at"]
        at["stacks"] = [{**copy.deepcopy(at["stacks"][0]), "frames": many}] * 5
    return doc


def flamegraph(args: list[str]) -> None:
    """flamegraph --allocations FILE --folded, from the fixture's top stacks."""
    if MODE == "old_binary":
        print(
            "error: unrecognized subcommand 'flamegraph'\n\nUsage: heapspy <COMMAND>",
            file=sys.stderr,
        )
        sys.exit(2)
    profile = opt(args, "allocations")
    if profile is None or "--folded" not in args:
        sys.exit(2)
    if "corrupt" in profile:
        print(f"heapspy: error: {profile} is not an allocation profile", file=sys.stderr)
        sys.exit(1)
    doc = load_fixture("analyze_allocations")
    lines = []
    for stack in doc["allocations"]["top_stacks"]:
        frames = [f"{f['function']} ({f['location']})" for f in reversed(stack["frames"])]
        lines.append(f"{';'.join(frames)} {stack['estimated_bytes']}")
    if MODE == "big":
        lines = [f"main (app/main.py:1);f{i} (app/f.py:{i}) {i + 1}" for i in range(5000)]
    # A stack without Python frames, and one split across two lines (merged by the reader).
    lines.append("[no Python stack] 4096")
    lines.append(lines[0].rsplit(" ", 1)[0] + " 1024")
    print("\n".join(sorted(lines)))
    sys.exit(0)


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
        dump(args)
    if cmd == "flamegraph":
        flamegraph(args)

    if "--json" not in args:
        sys.exit(2)

    profile = check_profile(args)
    if cmd == "analyze" and profile is not None:
        doc = analyze_with_allocations(args, profile, int(opt(args, "top") or 20))
    elif cmd == "analyze":
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
        if profile is not None:
            # As analyze_allocations' first retainer; query reports have no top_stacks.
            at = copy.deepcopy(load_fixture("analyze_allocations")["top_retainers"][0])
            at = at["allocated_at"]
            for stack in at["stacks"]:
                stack["top_stack_rank"] = None
            for inst in doc["top_instances"]:
                inst["allocated_at"] = at
            sampled = load_fixture("analyze_allocations")["notes"][-1]
            doc["notes"] = [*doc["notes"], sampled]
            if MODE == "alloc_not_linked":
                for inst in doc["top_instances"]:
                    inst["allocated_at"] = {**at, "linked_objects": 0, "stacks": []}
                doc["notes"] = [*doc["notes"], *NOT_LINKED_NOTES]
        if MODE == "big":
            inst = doc["top_instances"][0]
            doc["top_instances"] = [
                {**copy.deepcopy(inst), "address": f"0x{0x7D0000000000 + i * 64:x}"}
                for i in range(20)
            ]
            doc["matched_types"] = [f"app.m{i}.Session" for i in range(300)]
            doc["holders"] = [doc["holders"][0]] * 20
    elif cmd == "query" and opt(args, "locate") is not None:
        name = opt(args, "locate")
        if MODE == "old_binary":
            usage_error("--locate", "heapspy query <SNAP> <--type <T>|--retaining-path <ADDR>>")
        doc = load("locate")
        doc["snapshot"]["path"] = args[1]
        table = os.environ.get("FAKE_HEAPSPY_LOCATE")
        matches = json.loads(table).get(name) if table else None
        if matches is None and name == doc["query"]:
            matches = doc["matches"]
        if not matches:
            fail("not_found", f"no type, function or module named {name!r} in the snapshot")
        doc["query"] = name
        doc["matches"] = matches
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

    if MODE == "old_binary":
        strip_locations(doc)
    if MODE == "bad_schema":
        doc["schema_version"] = 2
    if MODE == "wrong_kind":
        doc["kind"] = "something_else"
    emit(doc)


if __name__ == "__main__":
    main()
