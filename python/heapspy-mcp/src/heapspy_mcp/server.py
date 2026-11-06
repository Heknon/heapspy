"""The heapspy MCP server: tool definitions."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Annotated, Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import capture as capture_mod
from . import processes
from . import summarize as S
from .cli import HeapspyCLI, HeapspyError
from .config import Config
from .snapshots import SnapshotRefError, SnapshotStore

log = logging.getLogger("heapspy_mcp")

WORKFLOW = """\
heapspy answers "what is retained, and by whom?" from a snapshot of a CPython heap.

The loop:
1. list_python_processes: find the PID (or use an existing core / minidump file).
2. capture_snapshot(confirm=true): only after the user agreed. Returns a snapshot handle.
   If a .hpy file already exists, skip this and pass its path as `snapshot`.
3. heap_summary(snapshot): top retainers, type histogram, memory accounting.
4. Pick a suspect: a retainer with a large retained_pct, or a type with many instances.
5. retaining_path(snapshot, address=... or type=...): the labelled chain of references
   from a root (module global, thread, frame local) to the suspect.
6. type_detail(snapshot, type): instance counts, the largest instances, who holds them.
7. map_to_source(qualname, repo_path): turn a source_hints entry (e.g. app.cache.CACHE,
   app.session.Session) into file:line, then read that code and find where the holder
   grows without being cleared.
8. For growth over time: capture twice and diff_snapshots(before, after). Objects are
   matched by type and retaining site, not by address, so per-object identity is approximate.

Limits:
- No allocation history. heapspy cannot say where an object was allocated, only what keeps
  it alive now. For allocation stacks use tracemalloc or memray from process start.
- Untracked objects (bare ints, short strings, raw buffers) are seen only through a
  tracked container that references them.
- Native memory (C extensions, malloc outside Python objects) is invisible to the object
  graph. heap_summary reports how much of RSS falls outside the graph; if that share is
  large, the leak may be native and heapspy cannot point at it.
- Dict keys are redacted unless the snapshot was captured with contents.
"""

T = TypeVar("T")


class InvalidArgument(Exception):
    """A tool argument is malformed; nothing was run."""


def _tool_error(payload: dict[str, Any]) -> ToolError:
    return ToolError(json.dumps({"error": payload}, ensure_ascii=False))


def _guard(fn: Callable[[], T]) -> T:
    """Run a tool body and turn anticipated failures into structured tool errors."""
    try:
        return fn()
    except HeapspyError as e:
        raise _tool_error(e.to_dict()) from e
    except capture_mod.CaptureRefused as e:
        raise _tool_error(e.to_dict()) from e
    except (InvalidArgument, SnapshotRefError) as e:
        raise _tool_error({"code": "invalid_argument", "message": str(e)}) from e


def _clean_address(address: str) -> str:
    text = address.strip().lower()
    if (
        not text.startswith("0x")
        or not all(c in "0123456789abcdef" for c in text[2:])
        or not (2 < len(text) <= 18)
    ):
        raise InvalidArgument(
            f"address {address!r} must be hex with a 0x prefix, e.g. 0x7f3a2c41b0d0"
        )
    return text


def _clean_type(type_name: str) -> str:
    text = type_name.strip()
    if not text or len(text) > 500 or any(c.isspace() or not c.isprintable() for c in text):
        raise InvalidArgument(f"type {type_name!r} is not a module.qualname type name")
    return text


SnapshotArg = Annotated[
    str,
    Field(
        description="Snapshot handle from capture_snapshot (hs-xxxxxxxx) or a path to a .hpy file."
    ),
]
TopArg = Annotated[
    int, Field(description=f"How many ranked rows to return per list (1 to {S.MAX_TOP}).")
]


def build_server(config: Config) -> MCPServer:
    cli = HeapspyCLI(
        config.heapspy_bin, timeout=config.timeout, capture_timeout=config.capture_timeout
    )
    store = SnapshotStore(config.snapshot_dir)
    server = MCPServer("heapspy", instructions=WORKFLOW)
    read_only = ToolAnnotations(read_only_hint=True, open_world_hint=False)

    @server.tool(
        annotations=read_only,
        description=(
            "List Python processes on this machine: pid, name, truncated command line, RSS, "
            "detected CPython version, and whether the server's allowlist permits capturing it. "
            "Read-only; does not touch the processes. Use this to find the PID for "
            "capture_snapshot. Sorted by RSS, largest first."
        ),
    )
    def list_python_processes(
        name_filter: Annotated[
            str | None,
            Field(description="Case-insensitive substring to match in the name or command line."),
        ] = None,
        limit: Annotated[int, Field(description="Maximum processes to return (1 to 200).")] = 50,
    ) -> dict[str, Any]:
        return processes.list_python_processes(
            name_filter, limit=S.clamp(limit, 1, processes.MAX_PROCESSES), allow=config.allow
        )

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
        description=(
            "Capture a heap snapshot. PRIVILEGED: this is the only tool that touches a process. "
            "Give exactly one of pid (dump a live process; it is paused while the image is "
            "taken), core_path (Linux ELF core) or minidump_path (Windows full minidump). "
            "confirm must be true, and you must ask the user before setting it. Live capture "
            "only works for processes on the allowlist the user configured when starting the "
            "server, and under its RSS limit; refusals explain which gate failed, and only the "
            "user can change the gates. capture_contents=true records string/bytes contents "
            "(may include secrets) and needs --allow-contents on the server. Returns a snapshot "
            "handle to pass to heap_summary, retaining_path, type_detail and diff_snapshots."
        ),
    )
    def capture_snapshot(
        confirm: Annotated[
            bool, Field(description="Must be true. Set it only after the user agreed.")
        ] = False,
        pid: Annotated[int | None, Field(description="PID of a live CPython process.")] = None,
        core_path: Annotated[str | None, Field(description="Path to an ELF core file.")] = None,
        minidump_path: Annotated[
            str | None, Field(description="Path to a Windows full-memory minidump.")
        ] = None,
        capture_contents: Annotated[
            bool, Field(description="Also record string contents and dict keys (size-capped).")
        ] = False,
        max_str: Annotated[
            int | None,
            Field(description="Cap on captured text per string, in characters (with contents)."),
        ] = None,
    ) -> dict[str, Any]:
        return _guard(
            lambda: capture_mod.capture_snapshot(
                config,
                cli,
                store,
                pid=pid,
                core_path=core_path,
                minidump_path=minidump_path,
                confirm=confirm,
                capture_contents=capture_contents,
                max_str=max_str,
            )
        )

    @server.tool(
        annotations=read_only,
        description=(
            "Summarize a snapshot: the objects that retain the most memory (with the root path "
            "holding each one and source_hints for map_to_source), the type histogram by "
            "retained size, and memory accounting (RSS vs. bytes in the object graph). Start "
            "here after capture_snapshot. If memory.outside_graph_pct is high, most memory is "
            "native or untracked and the object graph cannot explain it. The report shows what "
            "is retained now, not where it was allocated."
        ),
    )
    def heap_summary(snapshot: SnapshotArg, top: TopArg = 10) -> dict[str, Any]:
        def body() -> dict[str, Any]:
            n = S.clamp(top, 1, S.MAX_TOP)
            path = store.resolve(snapshot)
            doc = cli.analyze(path, top=n)
            return {
                "snapshot_ref": store.handle_for(path) or str(path),
                **S.summarize_analyze(doc, n),
            }

        return _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Show why an object is alive: the labelled chain of references from a GC root "
            "(module global, thread, frame local) to the object, root first. Give address "
            "(from heap_summary or type_detail) or type (e.g. app.session.Session; the "
            "largest instances are traced). Each path has rendered text, hops, and "
            "source_hints: module.qualname names to pass to map_to_source. The edge just "
            "before the target (direct_holder) is usually the reference to remove."
        ),
    )
    def retaining_path(
        snapshot: SnapshotArg,
        address: Annotated[
            str | None, Field(description="Object address, 0x-prefixed hex.")
        ] = None,
        type: Annotated[
            str | None, Field(description="Type name, module.qualname or unqualified.")
        ] = None,
        max_paths: Annotated[int, Field(description=f"Paths per object (1 to {S.MAX_PATHS}).")] = 3,
        max_targets: Annotated[
            int,
            Field(
                description=f"With type: how many of the largest instances (1 to {S.MAX_TARGETS})."
            ),
        ] = 3,
    ) -> dict[str, Any]:
        def body() -> dict[str, Any]:
            if (address is None) == (type is None):
                raise InvalidArgument("give exactly one of address or type")
            paths_n = S.clamp(max_paths, 1, S.MAX_PATHS)
            path = store.resolve(snapshot)
            if address is not None:
                doc = cli.retaining_path(path, _clean_address(address))
                targets = (doc.get("targets") or [])[:1]
                result_notes = doc.get("notes")
                snap = doc.get("snapshot")
                query = {"by": "address", "value": address}
                matched = None
            else:
                # The CLI traces one address per call; trace the largest instances of the type.
                tq = cli.query_type(path, _clean_type(type or ""))
                n = S.clamp(max_targets, 1, S.MAX_TARGETS)
                targets = []
                result_notes = list(tq.get("notes") or [])
                for inst in (tq.get("top_instances") or [])[:n]:
                    try:
                        one = cli.retaining_path(path, inst["address"])
                        targets.extend((one.get("targets") or [])[:1])
                        for note in one.get("notes") or []:
                            if note not in result_notes:
                                result_notes.append(note)
                    except HeapspyError:
                        # Fall back to the single shortest path the type query gave.
                        targets.append(
                            {
                                **{
                                    k: inst.get(k)
                                    for k in ("address", "type", "shallow_bytes", "retained_bytes")
                                },
                                "reachable": inst.get("path") is not None,
                                "paths": [inst["path"]] if inst.get("path") else [],
                            }
                        )
                snap = tq.get("snapshot")
                query = {"by": "type", "value": type}
                matched = {
                    "matched_types": (tq.get("matched_types") or [])[: S.MAX_MATCHED_TYPES],
                    "instances": tq.get("instances"),
                }
            out: dict[str, Any] = {
                "snapshot_ref": store.handle_for(path) or str(path),
                "snapshot": S.snapshot_summary(snap),
                "query": query,
                "targets": [S.summarize_target(t, paths_n) for t in targets],
                "notes": S.notes(result_notes),
            }
            if matched is not None:
                out["type_match"] = matched
            return out

        return _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Detail for one type: instance count, total shallow and retained size, the largest "
            "instances with their root paths, and holders (which container types and edges "
            "reference the instances, grouped, e.g. builtins.dict [<key>] x 400000). Accepts a "
            "full name (app.session.Session) or an unqualified one (Session). Use it to judge "
            "whether a type is leaking and who is accumulating it."
        ),
    )
    def type_detail(
        snapshot: SnapshotArg,
        type: Annotated[str, Field(description="Type name, module.qualname or unqualified.")],
        top: TopArg = 10,
    ) -> dict[str, Any]:
        def body() -> dict[str, Any]:
            n = S.clamp(top, 1, S.MAX_TOP)
            path = store.resolve(snapshot)
            doc = cli.query_type(path, _clean_type(type))
            return {
                "snapshot_ref": store.handle_for(path) or str(path),
                **S.summarize_type_query(doc, n),
            }

        return _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Compare two snapshots of the same process: growth by type and by retaining site "
            "(rendered root path such as sys.modules['app.cache'].__dict__['CACHE']). Sites "
            "with large delta_retained_bytes are leak candidates; pass the site's names to "
            "map_to_source. identity_approximate is always true: addresses change between "
            "dumps, so objects are matched by type and site, not one to one. Do not claim that "
            "a specific object survived or was freed based on a diff."
        ),
    )
    def diff_snapshots(
        before: Annotated[str, Field(description="Earlier snapshot: handle or .hpy path.")],
        after: Annotated[str, Field(description="Later snapshot: handle or .hpy path.")],
        top: TopArg = 10,
    ) -> dict[str, Any]:
        def body() -> dict[str, Any]:
            n = S.clamp(top, 1, S.MAX_TOP)
            doc = cli.diff(store.resolve(before), store.resolve(after))
            return S.summarize_diff(doc, n)

        return _guard(body)

    @server.resource(
        "heapspy://workflow",
        name="workflow",
        description="How to investigate Python memory with these tools, and their limits.",
        mime_type="text/markdown",
    )
    def workflow_resource() -> str:
        return WORKFLOW

    @server.prompt(
        name="investigate_memory",
        description="Walk through finding what keeps memory alive in a Python process.",
    )
    def investigate_memory(target: str = "") -> str:
        lead = (
            f"Investigate what is retaining memory in {target}.\n\n"
            if target
            else "Investigate what is retaining memory in a Python process.\n\n"
        )
        return lead + WORKFLOW

    return server
