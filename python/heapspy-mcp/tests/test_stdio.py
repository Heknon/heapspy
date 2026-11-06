"""The console entry point serves MCP over stdio."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from mcp import Client, StdioServerParameters

from .conftest import EXAMPLES


async def test_stdio_server_end_to_end(fake_bin: Path, snap_file: Path, tmp_path: Path) -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "heapspy_mcp",
            "--heapspy-bin",
            str(fake_bin),
            "--snapshot-dir",
            str(tmp_path / "snaps"),
        ],
        env={
            "FAKE_HEAPSPY_EXAMPLES": str(EXAMPLES),
            "PATH": os.environ.get("PATH", ""),
        },
    )
    async with Client(params) as client:
        assert client.server_info.name == "heapspy"
        tools = (await client.list_tools()).tools
        assert "heap_summary" in {t.name for t in tools}
        result = await client.call_tool("heap_summary", {"snapshot": str(snap_file), "top": 1})
        assert not result.is_error
        assert result.structured_content["top_retainers"][0]["rank"] == 1
