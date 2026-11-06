"""The heapspy MCP server: tool definitions."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .cli import HeapspyError
from .config import Config
from .snapshots import SnapshotRefError

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
    except (InvalidArgument, SnapshotRefError) as e:
        raise _tool_error({"code": "invalid_argument", "message": str(e)}) from e


def build_server(config: Config) -> MCPServer:
    server = MCPServer("heapspy", instructions=WORKFLOW)

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
