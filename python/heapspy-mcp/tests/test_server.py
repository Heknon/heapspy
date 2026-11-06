"""Server metadata: tool list, workflow resource and prompt."""

from __future__ import annotations

from mcp import Client

from heapspy_mcp.server import build_server


async def test_workflow_resource_and_prompt(make_config) -> None:
    async with Client(build_server(make_config())) as client:
        resource = await client.read_resource("heapspy://workflow")
        text = resource.contents[0].text
        assert "No allocation history" in text
        assert "Native memory" in text
        prompt = await client.get_prompt("investigate_memory", {"target": "pid 1234"})
        assert "pid 1234" in prompt.messages[0].content.text
