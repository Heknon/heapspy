from __future__ import annotations

from pathlib import Path

import pytest

from heapspy_mcp.__main__ import main
from heapspy_mcp.config import (
    DEFAULT_MAX_RSS,
    Config,
    ConfigError,
    parse_size,
    resolve_binary,
)
from heapspy_mcp.snapshots import SnapshotRefError, SnapshotStore


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("1024", 1024),
        ("8G", 8 * 1024**3),
        ("8GiB", 8 * 1024**3),
        ("512m", 512 * 1024**2),
        ("1.5K", 1536),
        ("2 TB", 2 * 1024**4),
    ],
)
def test_parse_size(text: str, value: int) -> None:
    assert parse_size(text) == value


@pytest.mark.parametrize("text", ["", "lots", "8X", "-1G"])
def test_parse_size_rejects(text: str) -> None:
    with pytest.raises(ConfigError):
        parse_size(text)


def test_binary_order(fake_bin: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    other = tmp_path / "other-heapspy"
    other.write_text("#!/bin/sh\n")
    other.chmod(0o755)
    env = {"HEAPSPY_BIN": str(other)}
    assert resolve_binary(str(fake_bin), env) == fake_bin.resolve()
    assert resolve_binary(None, env) == other.resolve()
    monkeypatch.setenv("PATH", str(fake_bin.parent))
    assert resolve_binary(None, {}) == fake_bin.resolve()
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert resolve_binary(None, {}) is None


def test_explicit_binary_must_exist(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="--heapspy-bin"):
        resolve_binary(str(tmp_path / "missing"), {})
    with pytest.raises(ConfigError, match="HEAPSPY_BIN"):
        resolve_binary(None, {"HEAPSPY_BIN": str(tmp_path / "missing")})


def test_main_exits_with_clear_error_for_bad_binary(tmp_path: Path, capsys) -> None:
    assert main(["--heapspy-bin", str(tmp_path / "missing")]) == 2
    assert "not an executable file" in capsys.readouterr().err


def test_flags_merge_over_env(fake_bin: Path, tmp_path: Path) -> None:
    env = {
        "HEAPSPY_MCP_ALLOW": "gunicorn*, pid:7",
        "HEAPSPY_MCP_MAX_RSS": "1G",
        "HEAPSPY_MCP_SNAPSHOT_DIR": str(tmp_path / "env-dir"),
        "HEAPSPY_MCP_ALLOW_CONTENTS": "yes",
    }
    cfg = Config.from_sources(heapspy_bin=str(fake_bin), allow=["worker,celery*"], env=env)
    assert cfg.allow == ["gunicorn*", "pid:7", "worker", "celery*"]
    assert cfg.max_rss_bytes == 1024**3
    assert cfg.snapshot_dir == tmp_path / "env-dir"
    assert cfg.allow_contents is True
    cfg = Config.from_sources(
        heapspy_bin=str(fake_bin), max_rss="2G", snapshot_dir=str(tmp_path / "f"), env=env
    )
    assert cfg.max_rss_bytes == 2 * 1024**3
    assert cfg.snapshot_dir == tmp_path / "f"


def test_defaults(fake_bin: Path) -> None:
    cfg = Config.from_sources(heapspy_bin=str(fake_bin), env={})
    assert cfg.allow == []
    assert cfg.allow_contents is False
    assert cfg.max_rss_bytes == DEFAULT_MAX_RSS
    assert "heapspy-mcp" in str(cfg.snapshot_dir)


def test_snapshot_refs(tmp_path: Path, snap_file: Path) -> None:
    store = SnapshotStore(tmp_path / "snaps")
    handle, path = store.new_handle()
    path.write_bytes(b"x")
    assert store.resolve(handle) == path.resolve()
    assert store.handle_for(path) == handle
    assert store.resolve(str(snap_file)) == snap_file
    assert store.handle_for(snap_file) is None
    for bad in ["", "hs-00000000", str(tmp_path / "missing.hpy"), "/etc/passwd"]:
        with pytest.raises(SnapshotRefError):
            store.resolve(bad)
