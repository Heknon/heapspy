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

from . import allocations as A
from . import capture as capture_mod
from . import cpu as cpu_tools
from . import processes, source_map
from . import summarize as S
from .cli import HeapspyCLI, HeapspyError
from .config import Config
from .snapshots import SnapshotRefError, SnapshotStore, resolve_profile
from .system import register as register_process_diagnostics

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
7. map_to_source(qualname, repo_path, snapshot): turn a source_hints entry (e.g.
   app.cache.CACHE, app.session.Session) into file:line, then read that code and find where
   the holder grows without being cleared. With snapshot, types and functions resolve
   exactly from the locations the snapshot recorded (type_location, source_locations).
8. For growth over time: capture twice and diff_snapshots(before, after). Objects are
   matched by type and retaining site, not by address, so per-object identity is approximate.

"Where was this memory allocated?" needs an allocation profile (.hpya) recorded from the
process before the snapshot was taken:
- allocation_sites(profile, snapshot): the top allocating stacks with file:line, estimated
  bytes, and the bytes still alive in the snapshot that link to each stack (exact for large
  objects, approximate for arena and pool samples). Without a snapshot: estimated bytes only.
- heap_summary(snapshot, allocations=profile) and type_detail(..., allocations=profile):
  allocated_at on each top retainer or instance, the stacks that allocated what it retains.
- Each stack has source_hints: file:line to read, and a qualname_guess for map_to_source.

Limits:
- Allocation data exists only for a recorded .hpya profile. It covers sampled events
  (arena, pool, large object) during the recording window, not objects allocated before it.
  `heapspy record` is not implemented yet and this server has no tool that records; without
  a profile, heapspy can say what keeps an object alive, not where it was allocated. For
  allocation stacks from process start use tracemalloc or memray.
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
    except (InvalidArgument, SnapshotRefError, source_map.SourceMapError) as e:
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
AllocationsArg = Annotated[
    str | None,
    Field(
        description=(
            "Optional path to a .hpya allocation profile recorded from the same process "
            "before the snapshot. Adds allocated_at (allocating stacks) to the result."
        )
    ),
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
            "detected CPython version, thread count and threads_by_state, optional "
            "cpu_percent_on_cpu (measure_s), and whether the server's allowlist permits "
            "capturing it. "
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
        measure_s: Annotated[
            float,
            Field(description="Window for cpu_percent_on_cpu, 0 to 2 s; 0 (default) skips it."),
        ] = 0.0,
    ) -> dict[str, Any]:
        return processes.list_python_processes(
            name_filter,
            limit=S.clamp(limit, 1, processes.MAX_PROCESSES),
            allow=config.allow,
            measure_s=measure_s,
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
            "handle to pass to heap_summary, retaining_path, type_detail and diff_snapshots, "
            "and the dump's stats (objects, roots, pause_ms, truncated, missing_bytes, "
            "read_errors) and notes. A failed dump returns heapspy's error code (e.g. "
            "permission_denied, not_python, no_such_process) with a hint."
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
            "retained size, and memory accounting (RSS vs. bytes in the object graph). Retainers "
            "and histogram rows have type_location: where the type is defined, as recorded in "
            "the snapshot (file:line; file:~line for a class, located near its first method), "
            "and paths have source_locations. Start "
            "here after capture_snapshot. If memory.outside_graph_pct is high, most memory is "
            "native or untracked and the object graph cannot explain it. The report shows what "
            "is retained now. With allocations (a .hpya profile), each retainer also gets "
            "allocated_at (the sampled stacks that allocated what it retains) and the result "
            "gets an allocations block with the top allocating stacks and their caveats."
        ),
    )
    def heap_summary(
        snapshot: SnapshotArg, top: TopArg = 10, allocations: AllocationsArg = None
    ) -> dict[str, Any]:
        def body() -> dict[str, Any]:
            n = S.clamp(top, 1, S.MAX_TOP)
            path = store.resolve(snapshot)
            profile = resolve_profile(allocations) if allocations is not None else None
            doc = cli.analyze(path, top=n, allocations=profile)
            out = {
                "snapshot_ref": store.handle_for(path) or str(path),
                **S.summarize_analyze(doc, n),
            }
            if profile is not None:
                A.add_to_analyze(out, doc, n)
            return out

        return _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Show why an object is alive: the labelled chain of references from a GC root "
            "(module global, thread, frame local) to the object, root first. Give address "
            "(from heap_summary or type_detail) or type (e.g. app.session.Session; the "
            "largest instances are traced). Each path has rendered text, hops, "
            "source_hints (module.qualname names to pass to map_to_source) and "
            "source_locations (file:line recorded in the snapshot for the target's type and "
            "for functions, classes and modules on the path). The edge just "
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
            "reference the instances, grouped, e.g. builtins.dict [<key>] x 400000), and "
            "type_locations: where each matched type is defined, as recorded in the snapshot. "
            "Accepts a full name (app.session.Session) or an unqualified one (Session). Use it "
            "to judge "
            "whether a type is leaking and who is accumulating it. With allocations (a .hpya "
            "profile), each instance gets allocated_at: the sampled stacks that allocated it "
            "and what it retains."
        ),
    )
    def type_detail(
        snapshot: SnapshotArg,
        type: Annotated[str, Field(description="Type name, module.qualname or unqualified.")],
        top: TopArg = 10,
        allocations: AllocationsArg = None,
    ) -> dict[str, Any]:
        def body() -> dict[str, Any]:
            n = S.clamp(top, 1, S.MAX_TOP)
            path = store.resolve(snapshot)
            profile = resolve_profile(allocations) if allocations is not None else None
            doc = cli.query_type(path, _clean_type(type), allocations=profile)
            out = {
                "snapshot_ref": store.handle_for(path) or str(path),
                **S.summarize_type_query(doc, n),
            }
            if profile is not None:
                A.add_to_type_query(out, doc)
            return out

        return _guard(body)

    @server.tool(
        annotations=read_only,
        description=(
            "Where memory was allocated, from a .hpya allocation profile: the top allocating "
            "Python stacks (innermost frame first, each with file:line) by estimated bytes. "
            "With snapshot (taken from the same process after recording), each stack also "
            "has linked_bytes, the bytes of objects still alive in the snapshot that were "
            "allocated there (exact_linked_bytes: the exact part, through large-object "
            "samples; arena and pool links are approximate), plus coverage, the recording "
            "mechanisms, sampling parameters and notes. Without snapshot only estimated "
            "bytes per stack are available. Each stack has source_hints (file:line, "
            "qualname_guess for map_to_source). The data is sampled and covers the recording "
            "window only; see caveats in the result."
        ),
    )
    def allocation_sites(
        profile: Annotated[str, Field(description="Path to a .hpya allocation profile.")],
        snapshot: Annotated[
            str | None,
            Field(
                description=(
                    "Optional snapshot handle or .hpy path of the same process, taken after "
                    "recording, to link stacks to live memory."
                )
            ),
        ] = None,
        top: TopArg = 10,
    ) -> dict[str, Any]:
        def body() -> dict[str, Any]:
            n = S.clamp(top, 1, S.MAX_TOP)
            prof = resolve_profile(profile)
            if snapshot is None:
                text = cli.allocation_folded(prof)
                return {
                    "profile": str(prof),
                    "mode": "profile_only",
                    **A.summarize_folded(text, n),
                    "note": (
                        "Without a snapshot, heapspy gives only folded stacks (flamegraph "
                        "--allocations --folded), aggregated here: estimated bytes per stack. "
                        "Sample counts, event kinds, the recording header (mechanisms, "
                        "sampling parameters, overhead) and linked bytes need a snapshot."
                    ),
                    "caveats": list(A.CAVEATS),
                }
            path = store.resolve(snapshot)
            doc = cli.analyze(path, top=n, allocations=prof)
            summary = A.summarize_allocations(doc.get("allocations"), doc.get("notes"), n)
            if summary is None:
                raise HeapspyError(
                    "bad_output",
                    "heapspy analyze --allocations returned no allocations block",
                )
            return {
                "profile": str(prof),
                "snapshot_ref": store.handle_for(path) or str(path),
                "snapshot": S.snapshot_summary(doc.get("snapshot")),
                "mode": "joined",
                **summary,
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

    @server.tool(
        annotations=read_only,
        description=(
            "Resolve a module.qualname from heapspy output (a type such as "
            "app.session.Session, a module global such as app.cache.CACHE, a method such as "
            "app.cache.Store.get, or an attribute set as self.x in a method) to file:line "
            "inside repo_path, with a short source excerpt. Handles src/ layouts and packages. "
            "With snapshot, a type or function the snapshot has a recorded location for "
            "(co_filename:co_firstlineno, or a class's methods) is resolved exactly "
            "(heuristic=false, via=snapshot); the recorded file is matched to a file inside "
            "repo_path by exact path, repo-relative path or a unique path suffix. Give the "
            "snapshot for __main__ names especially. Without it, or when the snapshot has no "
            "location in the repo (snapshot_lookup says why), names are resolved from the "
            "repo's files, and __main__.X heuristically (heuristic=true): every script in the "
            "repo that binds X at top level is a candidate, ranked by main_evidence "
            "(__main__.py, a main guard, a #! line); confirm against the process's command "
            "line. Read-only and confined to repo_path. Next step: read the file "
            "around that line and find where the holder grows without being cleared."
        ),
    )
    def map_to_source(
        qualname: Annotated[str, Field(description="Dotted name, e.g. app.cache.CACHE.")],
        repo_path: Annotated[str, Field(description="Absolute path of the repository root.")],
        snapshot: Annotated[
            str | None,
            Field(
                description=(
                    "Optional snapshot handle (hs-xxxxxxxx) or .hpy path the name came from, "
                    "for its recorded source locations."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        def body() -> dict[str, Any]:
            source_map.check_arguments(qualname, repo_path)
            located: dict[str, Any] | None = None
            if snapshot is not None:
                path = store.resolve(snapshot)
                try:
                    doc = cli.locate(path, qualname.strip())
                    located = {"matches": doc.get("matches") or []}
                except HeapspyError as e:
                    if e.code == "not_found":
                        located = {"matches": []}
                    elif e.code != "locate_unsupported":
                        raise
                    # A heapspy without --locate: resolve from the repository as before.
            return source_map.map_to_source(qualname, repo_path, located)

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

    register_process_diagnostics(server, config)
    cpu_tools.register(server, config)
    return server
