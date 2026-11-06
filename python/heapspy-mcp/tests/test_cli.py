from __future__ import annotations

from pathlib import Path

import pytest

from heapspy_mcp.cli import HeapspyCLI, HeapspyError


@pytest.fixture
def cli(fake_bin: Path) -> HeapspyCLI:
    return HeapspyCLI(fake_bin, timeout=20, capture_timeout=20)


def test_analyze_parses_document(cli: HeapspyCLI, snap_file: Path, argv_log) -> None:
    doc = cli.analyze(snap_file, top=1)
    assert doc["kind"] == "analyze"
    assert len(doc["top_retainers"]) == 1
    assert argv_log()[-1] == ["analyze", str(snap_file), "--json", "--top=1"]


def test_values_are_passed_as_single_long_options(cli: HeapspyCLI, snap_file: Path, argv_log):
    cli.query_type(snap_file, "-rf")
    cli.retaining_path(snap_file, "0x10")
    assert argv_log()[-2] == ["query", str(snap_file), "--type=-rf", "--json"]
    assert argv_log()[-1] == ["query", str(snap_file), "--retaining-path=0x10", "--json"]


def test_error_document_maps_to_code(cli: HeapspyCLI, snap_file: Path) -> None:
    with pytest.raises(HeapspyError) as e:
        cli.retaining_path(snap_file, "0xdead")
    assert e.value.code == "not_found"
    assert e.value.exit_status == 1
    assert "0xdead" in e.value.message
    assert e.value.to_dict()["hint"]


@pytest.mark.parametrize(
    "code", ["unimplemented", "invalid_snapshot", "io", "permission_denied", "internal"]
)
def test_every_cli_error_code_passes_through(
    cli: HeapspyCLI, snap_file: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", f"error:{code}")
    with pytest.raises(HeapspyError) as e:
        cli.analyze(snap_file, top=5)
    assert e.value.code == code


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("bad_schema", "schema_mismatch"),
        ("not_json", "bad_output"),
        ("usage", "usage_error"),
        ("wrong_kind", "unexpected_kind"),
        ("crash", "cli_failed"),
        ("error_exit0", "io"),
    ],
)
def test_failure_modes(
    cli: HeapspyCLI, snap_file: Path, monkeypatch: pytest.MonkeyPatch, mode: str, code: str
) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", mode)
    with pytest.raises(HeapspyError) as e:
        cli.analyze(snap_file, top=5)
    assert e.value.code == code


def test_crash_keeps_stderr(cli: HeapspyCLI, snap_file: Path, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "crash")
    with pytest.raises(HeapspyError) as e:
        cli.analyze(snap_file, top=5)
    assert e.value.exit_status == 101
    assert "panicked" in (e.value.stderr or "")


def test_timeout(fake_bin: Path, snap_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "timeout")
    cli = HeapspyCLI(fake_bin, timeout=0.5, capture_timeout=0.5)
    with pytest.raises(HeapspyError) as e:
        cli.analyze(snap_file, top=5)
    assert e.value.code == "timeout"


def test_missing_binary(snap_file: Path, tmp_path: Path) -> None:
    with pytest.raises(HeapspyError) as e:
        HeapspyCLI(None, timeout=1, capture_timeout=1).analyze(snap_file, top=1)
    assert e.value.code == "binary_not_found"
    with pytest.raises(HeapspyError) as e:
        HeapspyCLI(tmp_path / "nope", timeout=1, capture_timeout=1).analyze(snap_file, top=1)
    assert e.value.code == "binary_not_found"


def test_dump_parses_stats(cli: HeapspyCLI, tmp_path: Path, argv_log) -> None:
    out = tmp_path / "x.hpy"
    result = cli.dump(output=out, pid=42, capture_contents=True, max_str=64)
    assert out.is_file()
    assert (result.objects, result.edges, result.roots, result.bytes_written) == (10, 20, 3, 128)
    assert result.truncated is False
    assert argv_log()[-1] == [
        "dump",
        "--pid=42",
        f"--output={out}",
        "--capture-contents",
        "--max-str=64",
    ]


def test_dump_failure_is_text_on_stderr(cli: HeapspyCLI, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "dump_fail")
    with pytest.raises(HeapspyError) as e:
        cli.dump(output=tmp_path / "x.hpy", core=tmp_path / "core")
    assert e.value.code == "cli_failed"
    assert "permission denied" in e.value.message
