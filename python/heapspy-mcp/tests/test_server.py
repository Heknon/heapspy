"""Server metadata: tool list, workflow resource and prompt."""

from __future__ import annotations

from mcp import Client

from heapspy_mcp.server import build_server

EXPECTED_TOOLS = {
    "list_python_processes",
    "capture_snapshot",
    "heap_summary",
    "retaining_path",
    "type_detail",
    "diff_snapshots",
    "map_to_source",
    # process diagnostics (heapspy_mcp.system)
    "find_processes",
    "scan_processes",
    "process_cpu",
    "hw_counters",
    "snapshot_process_metrics",
    "compare_process_snapshots",
    "diagnose_process_cpu",
    "watch_process_stalls",
    # CPU tools (py-spy)
    "cpu_stacks",
    "cpu_profile",
    "cpu_top",
    "cpu_flamegraph",
}


async def test_all_tools_are_listed(make_config) -> None:
    async with Client(build_server(make_config())) as client:
        assert client.server_info.name == "heapspy"
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(tools) == EXPECTED_TOOLS
    read_only = {name for name, t in tools.items() if t.annotations.read_only_hint}
    assert read_only == EXPECTED_TOOLS - {"capture_snapshot", "cpu_flamegraph"}


async def test_workflow_resource_and_prompt(make_config) -> None:
    async with Client(build_server(make_config())) as client:
        resource = await client.read_resource("heapspy://workflow")
        text = resource.contents[0].text
        assert "No allocation history" in text
        assert "Native memory" in text
        prompt = await client.get_prompt("investigate_memory", {"target": "pid 1234"})
        assert "pid 1234" in prompt.messages[0].content.text


async def test_process_workflow_resource_prompt_and_instructions(make_config) -> None:
    async with Client(build_server(make_config())) as client:
        assert "scan_processes" in (client.instructions or "")
        resource = await client.read_resource("heapspy://process-workflow")
        assert "find_processes" in resource.contents[0].text
        prompt = await client.get_prompt("investigate_process_cpu", {"target": "pid 7"})
        assert "pid 7" in prompt.messages[0].content.text
