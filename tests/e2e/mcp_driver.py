"""Drive heapspy-mcp's tools in-process against a real heapspy binary.

Run by test_mcp.py inside the heapspy-mcp project's environment::

    uv run --project $HEAPSPY_MCP_DIR python mcp_driver.py ARGS.json

ARGS.json holds ``heapspy_bin``, ``snapshot_dir``, ``allow`` (list), ``pid``,
``other_pid``, ``not_python_pid``, ``core`` (path or null) and ``repo``. The
driver calls the tools through the MCP client the package's own tests use and
prints one JSON object mapping each call to ``[is_error, payload]``.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from heapspy_mcp.config import Config
from heapspy_mcp.server import build_server
from mcp import Client


async def main(args: dict[str, Any]) -> dict[str, Any]:
    config = Config(
        heapspy_bin=Path(args["heapspy_bin"]),
        snapshot_dir=Path(args["snapshot_dir"]),
        allow=args["allow"],
        timeout=120.0,
        capture_timeout=300.0,
    )
    out: dict[str, Any] = {}
    async with Client(build_server(config)) as client:

        async def call(key: str, tool: str, params: dict[str, Any]) -> Any:
            result = await client.call_tool(tool, params)
            if result.is_error:
                text = result.content[0].text
                start = text.find("{")
                payload: Any = json.loads(text[start:]) if start >= 0 else text
            else:
                payload = result.structured_content
            out[key] = [bool(result.is_error), payload]
            return payload

        await call("list", "list_python_processes", {"name_filter": "unbounded_cache"})
        await call("refused", "capture_snapshot", {"confirm": True, "pid": args["other_pid"]})
        if args.get("not_python_pid"):
            await call(
                "not_python", "capture_snapshot", {"confirm": True, "pid": args["not_python_pid"]}
            )
        cap = await call("capture_pid", "capture_snapshot", {"confirm": True, "pid": args["pid"]})
        handle = cap.get("snapshot") if isinstance(cap, dict) else None
        if args.get("core"):
            await call(
                "capture_core", "capture_snapshot", {"confirm": True, "core_path": args["core"]}
            )
        if handle:
            summary = await call("summary", "heap_summary", {"snapshot": handle, "top": 5})
            await call(
                "path_type",
                "retaining_path",
                {"snapshot": handle, "type": "__main__.CachedResponse", "max_targets": 2},
            )
            top = (summary.get("top_retainers") or [{}])[0] if isinstance(summary, dict) else {}
            if top.get("address"):
                await call(
                    "path_addr", "retaining_path", {"snapshot": handle, "address": top["address"]}
                )
            await call("type_detail", "type_detail", {"snapshot": handle, "type": "CachedResponse"})
            await call("diff", "diff_snapshots", {"before": handle, "after": handle})
            hints = (top.get("path") or {}).get("source_hints") or []
            out["hints"] = hints
            for i, hint in enumerate(hints):
                await call(
                    f"map_{i}", "map_to_source", {"qualname": hint, "repo_path": args["repo"]}
                )
    return out


if __name__ == "__main__":
    params = json.loads(Path(sys.argv[1]).read_text())
    print(json.dumps(asyncio.run(main(params))))
