from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from heapspy_mcp.config import Config
from heapspy_mcp.server import build_server

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
EXAMPLES = REPO_ROOT / "docs" / "examples"
# Examples from heapspy branches that are not merged here yet (see its README).
CLI_FIXTURES = HERE / "fixtures" / "heapspy"


@pytest.fixture
def fake_bin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An executable fake heapspy that runs tests/fake_heapspy.py with this interpreter."""
    if sys.platform == "win32":
        pytest.skip("the fake heapspy executable uses a shebang")
    script = (HERE / "fake_heapspy.py").read_text()
    exe = tmp_path / "bin" / "heapspy"
    exe.parent.mkdir()
    exe.write_text(f"#!{sys.executable}\n{script}")
    exe.chmod(0o755)
    monkeypatch.setenv("FAKE_HEAPSPY_EXAMPLES", str(EXAMPLES))
    monkeypatch.setenv("FAKE_HEAPSPY_FIXTURES", str(CLI_FIXTURES))
    monkeypatch.setenv("FAKE_HEAPSPY_LOG", str(tmp_path / "argv.log"))
    monkeypatch.delenv("FAKE_HEAPSPY_MODE", raising=False)
    return exe


@pytest.fixture
def argv_log(tmp_path: Path):
    def read() -> list[list[str]]:
        path = tmp_path / "argv.log"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    return read


@pytest.fixture
def snapshot_dir(tmp_path: Path) -> Path:
    return tmp_path / "snapshots"


@pytest.fixture
def snap_file(tmp_path: Path) -> Path:
    path = tmp_path / "app.hpy"
    path.write_bytes(b"HPYSNAP\0")
    return path


@pytest.fixture
def make_config(fake_bin: Path, snapshot_dir: Path):
    def make(**overrides: Any) -> Config:
        values: dict[str, Any] = {
            "heapspy_bin": fake_bin,
            "snapshot_dir": snapshot_dir,
            "allow": [],
            "timeout": 20.0,
            "capture_timeout": 20.0,
        }
        values.update(overrides)
        return Config(**values)

    return make


@pytest.fixture
def call(make_config):
    """call(tool, args, **config_overrides) -> (is_error, payload) through an in-memory client."""

    async def run(tool: str, args: dict[str, Any], **overrides: Any) -> tuple[bool, Any]:
        server = build_server(make_config(**overrides))
        async with Client(server) as client:
            result = await client.call_tool(tool, args)
        if result.is_error:
            text = result.content[0].text
            start = text.find("{")
            return True, json.loads(text[start:]) if start >= 0 else text
        return False, result.structured_content

    return run


@pytest.fixture
def child_python() -> Iterator[subprocess.Popen[bytes]]:
    """A sleeping Python child process to use as a capture target."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdin=subprocess.DEVNULL,
        env={**os.environ},
    )
    try:
        yield proc
    finally:
        proc.kill()
        proc.wait()


# --- CPU profiling (py-spy) ---------------------------------------------------------


@pytest.fixture
def fake_pyspy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An executable fake py-spy that runs tests/fake_pyspy.py with this interpreter."""
    if sys.platform == "win32":
        pytest.skip("the fake py-spy executable uses a shebang")
    script = (HERE / "fake_pyspy.py").read_text()
    exe = tmp_path / "pyspy-bin" / "py-spy"
    exe.parent.mkdir()
    exe.write_text(f"#!{sys.executable}\n{script}")
    exe.chmod(0o755)
    monkeypatch.setenv("FAKE_PYSPY_LOG", str(tmp_path / "pyspy-argv.log"))
    monkeypatch.delenv("FAKE_PYSPY_MODE", raising=False)
    return exe


@pytest.fixture
def pyspy_argv(tmp_path: Path):
    def read() -> list[list[str]]:
        path = tmp_path / "pyspy-argv.log"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    return read


# --- end CPU profiling --------------------------------------------------------------
