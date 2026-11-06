from __future__ import annotations

from pathlib import Path

import pytest

from heapspy_mcp.cli import CLI_ERROR_CODES, HeapspyCLI, HeapspyError


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
    assert result.report == "json"
    assert (result.objects, result.edges, result.roots, result.bytes_written) == (10, 20, 3, 128)
    assert (result.types, result.read_errors, result.missing_bytes) == (1184, 2, 0)
    assert result.truncated is False
    assert result.pause_ms == 182.417
    assert result.python_version == "3.12.4"
    assert [n["code"] for n in result.notes] == ["read_errors"]
    assert argv_log()[-1] == [
        "dump",
        "--pid=42",
        f"--output={out}",
        "--capture-contents",
        "--max-str=64",
        "--json",
    ]


def test_dump_failure_is_text_on_stderr(cli: HeapspyCLI, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "dump_fail")
    with pytest.raises(HeapspyError) as e:
        cli.dump(output=tmp_path / "x.hpy", core=tmp_path / "core")
    assert e.value.code == "cli_failed"
    assert "permission denied" in e.value.message


def test_dump_core_has_no_pause(cli: HeapspyCLI, tmp_path: Path) -> None:
    result = cli.dump(output=tmp_path / "x.hpy", core=tmp_path / "core")
    assert result.report == "json"
    assert result.pause_ms is None


def test_dump_truncated_report(cli: HeapspyCLI, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "dump_truncated")
    result = cli.dump(output=tmp_path / "x.hpy", core=tmp_path / "core")
    assert result.truncated is True
    assert result.missing_bytes == 4096
    assert {"truncated_snapshot", "image_incomplete"} <= {n["code"] for n in result.notes}


@pytest.mark.parametrize(
    "code",
    [
        "not_python",
        "unsupported_python",
        "no_such_process",
        "invalid_image",
        "truncated_image",
        "unsupported",
        "permission_denied",
        "io",
        "internal",
    ],
)
def test_dump_error_codes_have_hints(
    cli: HeapspyCLI, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    assert code in CLI_ERROR_CODES
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", f"error:{code}")
    with pytest.raises(HeapspyError) as e:
        cli.dump(output=tmp_path / "x.hpy", pid=42)
    assert e.value.code == code
    assert e.value.exit_status == 1
    d = e.value.to_dict()
    assert d["hint"]
    assert "cli_code" not in d


def test_permission_hint_names_ptrace(cli: HeapspyCLI, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "error:permission_denied")
    with pytest.raises(HeapspyError) as e:
        cli.dump(output=tmp_path / "x.hpy", pid=42)
    hint = e.value.to_dict()["hint"]
    assert "CAP_SYS_PTRACE" in hint and "SeDebugPrivilege" in hint


def test_unknown_code_is_internal(cli: HeapspyCLI, snap_file: Path, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "error:brand_new_code")
    with pytest.raises(HeapspyError) as e:
        cli.analyze(snap_file, top=1)
    assert e.value.code == "internal"
    assert e.value.to_dict()["cli_code"] == "brand_new_code"


def test_dump_falls_back_for_binary_without_dump_json(
    cli: HeapspyCLI, tmp_path: Path, monkeypatch, argv_log
) -> None:
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "old_binary")
    out = tmp_path / "x.hpy"
    result = cli.dump(output=out, pid=42)
    assert result.report == "stderr_line"
    assert (result.objects, result.edges, result.roots, result.bytes_written) == (10, 20, 3, 128)
    assert result.pause_ms is None and result.types is None and result.notes == ()
    calls = argv_log()
    assert calls[-2] == ["dump", "--pid=42", f"--output={out}", "--json"]
    assert calls[-1] == ["dump", "--pid=42", f"--output={out}"]
    # The answer is remembered: the next dump does not try --json again.
    other = tmp_path / "y.hpy"
    cli.dump(output=other, pid=42)
    assert argv_log()[-1] == ["dump", "--pid=42", f"--output={other}"]
    assert len(argv_log()) == 3


def test_dump_old_binary_failure_is_text(
    cli: HeapspyCLI, tmp_path: Path, monkeypatch, argv_log
) -> None:
    cli.dump_json = False  # as after a fallback
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "dump_fail")
    with pytest.raises(HeapspyError) as e:
        cli.dump(output=tmp_path / "x.hpy", pid=42)
    assert e.value.code == "cli_failed"
    assert "permission denied" in e.value.message
    assert "--json" not in argv_log()[-1]


def test_dump_without_document_uses_stderr_line(cli: HeapspyCLI, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "dump_no_json")
    result = cli.dump(output=tmp_path / "x.hpy", pid=42)
    assert result.report == "stderr_line"
    assert result.objects == 10


def test_dump_usage_error_naming_json_is_not_a_fallback(
    cli: HeapspyCLI, tmp_path: Path, monkeypatch, argv_log
) -> None:
    # A newer heapspy shows --json in the Usage line of any dump usage error.
    monkeypatch.setenv("FAKE_HEAPSPY_MODE", "dump_usage")
    with pytest.raises(HeapspyError) as e:
        cli.dump(output=tmp_path / "x.hpy", pid=42)
    assert e.value.code == "usage_error"
    assert len(argv_log()) == 1
