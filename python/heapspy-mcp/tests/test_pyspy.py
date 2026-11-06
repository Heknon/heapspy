"""The py-spy runner, its parsers and its configuration."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from heapspy_mcp.__main__ import main
from heapspy_mcp.config import Config, ConfigError, load_cpu_settings, resolve_py_spy
from heapspy_mcp.pyspy import (
    PySpy,
    PySpyError,
    RecordSpec,
    classify_failure,
    clean_stderr,
    frame_from_dump,
    module_from_filename,
    parse_folded,
    parse_folded_line,
    parse_frame,
    parse_stat_state,
    parse_syscall,
    read_folded,
    state_bucket,
    thread_state,
)


@pytest.fixture
def spy(fake_pyspy: Path) -> PySpy:
    return PySpy(fake_pyspy, dump_timeout=10, record_grace=10)


# -- folded parsing ----------------------------------------------------------------


def test_parse_frame() -> None:
    f = parse_frame("compute (app/hot.py:12)")
    assert (f.function, f.file, f.line) == ("compute", "app/hot.py", 12)
    assert f.location == "app/hot.py:12"
    assert f.render() == "compute (app/hot.py:12)"
    f = parse_frame("<module> (<string>:1)")
    assert (f.function, f.file, f.line) == ("<module>", "<string>", 1)
    f = parse_frame("Thread.run (threading.py)")  # --nolineno
    assert (f.file, f.line) == ("threading.py", None)
    f = parse_frame("0x7f03a5698e51 (libc.so.6)")  # a native frame
    assert (f.function, f.file, f.line) == ("0x7f03a5698e51", "libc.so.6", None)
    f = parse_frame("bare")
    assert (f.function, f.file) == ("bare", None)


def test_parse_folded_line_with_thread() -> None:
    s = parse_folded_line(
        "thread (31853): worker-1;Thread.run (threading.py:1010);contend (victims.py:10) 24\n"
    )
    assert s is not None
    assert (s.thread_id, s.thread_name, s.count, s.pids) == ("31853", "worker-1", 24, ())
    assert [f.function for f in s.frames] == ["Thread.run", "contend"]


def test_parse_folded_line_without_thread_and_with_hex_id() -> None:
    s = parse_folded_line("<module> (victim.py:25);burn_cpu (victim.py:9) 46")
    assert s is not None and s.thread_id is None and len(s.frames) == 2
    s = parse_folded_line("thread (0x7f3cf107c080);f (a.py:1) 3")
    assert s is not None and s.thread_id == "0x7f3cf107c080" and s.thread_name is None


def test_parse_folded_line_with_processes() -> None:
    line = (
        'process 1:"bash -c \\"a; b\\"";process 22:"python app.py; x";'
        "thread (22): MainThread;f (app.py:3) 7"
    )
    s = parse_folded_line(line)
    assert s is not None
    assert s.pids == (1, 22)
    assert s.thread_id == "22" and s.thread_name == "MainThread"
    assert [f.function for f in s.frames] == ["f"]


def test_parse_folded_rejects_garbage() -> None:
    assert parse_folded_line("   \n") is None
    with pytest.raises(ValueError):
        parse_folded_line("no count here")
    assert parse_folded("") == []


def test_read_folded_missing_and_bad(tmp_path: Path) -> None:
    assert read_folded(tmp_path / "missing") == []
    bad = tmp_path / "bad.folded"
    bad.write_text("not folded\n")
    with pytest.raises(PySpyError) as e:
        read_folded(bad)
    assert e.value.code == "bad_output"


# -- dump parsing ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("short", "module"),
    [
        ("app/cache.py", "app.cache"),
        ("app/__init__.py", "app"),
        ("threading.py", "threading"),
        ("<string>", None),
        ("<frozen importlib._bootstrap>", None),
        ("/abs/path.py", None),
        ("libc.so.6", None),
        ("my-dir/x.py", None),
        (None, None),
    ],
)
def test_module_from_filename(short, module) -> None:
    assert module_from_filename(short) == module


def test_frame_from_dump_drops_locals() -> None:
    f = frame_from_dump(
        {
            "name": "login",
            "filename": "/srv/app/auth.py",
            "short_filename": "app/auth.py",
            "line": 7,
            "module": None,
            "locals": [{"name": "password", "repr": "'hunter2'"}],
        }
    )
    assert f == {
        "function": "login",
        "location": "app/auth.py:7",
        "file": "/srv/app/auth.py",
        "line": 7,
        "module": "app.auth",
        "native": False,
    }
    native = frame_from_dump({"name": "memcpy", "filename": "libc.so.6", "module": "libc.so.6"})
    assert native["native"] is True and native["module"] == "libc.so.6"


# -- /proc parsing -----------------------------------------------------------------


def test_parse_stat_state_handles_odd_comm() -> None:
    assert parse_stat_state("123 (we) ird) name) S 1 2 3") == "S"
    assert parse_stat_state("123 (python3) R 1") == "R"
    assert parse_stat_state("garbage") is None


def test_parse_syscall() -> None:
    assert parse_syscall("running") is None
    assert parse_syscall(None) is None
    assert parse_syscall("-1 0x0") is None
    name = parse_syscall("202 0x1 0x2")
    assert name in {"futex", "syscall 202", "accept"}  # depends on the architecture


def test_state_bucket() -> None:
    assert state_bucket("R", None, None) == "running"
    assert state_bucket("D", None, None) == "disk_wait"
    assert state_bucket("S", "futex", None) == "sleeping_futex"
    assert state_bucket("S", None, "futex_do_wait") == "sleeping_futex"
    assert state_bucket("S", "clock_nanosleep", None) == "sleeping_other"
    assert state_bucket("t", None, None) == "stopped"
    assert state_bucket("Z", None, None) == "other"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
def test_thread_state_of_a_sleeping_child(child_python) -> None:
    import time

    time.sleep(0.3)
    state = thread_state(child_python.pid, child_python.pid)
    assert state is not None
    assert state["code"] == "S"
    assert state["label"] == "sleeping (blocked in a syscall)"
    assert thread_state(child_python.pid, 2**22 + 7) is None


# -- error classification ----------------------------------------------------------


@pytest.mark.parametrize(
    ("stderr", "code"),
    [
        ("Permission Denied: Try running again with elevated permissions", "permission_denied"),
        ("Error: Operation not permitted (os error 1)", "permission_denied"),
        (
            "Error: Failed to get process executable name. Check that the process is running.",
            "no_such_process",
        ),
        ("Error: Failed to find python version from target process", "not_python"),
        ("Error: something else", "py_spy_failed"),
    ],
)
def test_classify_failure(stderr: str, code: str) -> None:
    err = classify_failure(stderr + "\n\nStack backtrace:\n   0: anyhow", 1)
    assert err.code == code
    assert "Stack backtrace" not in err.message
    if code == "permission_denied":
        assert "CAP_SYS_PTRACE" in err.to_dict()["hint"]


def test_clean_stderr_drops_progress_and_backtrace() -> None:
    text = "py-spy> Sampling\nError: boom\n\nStack backtrace:\n  0: x\n"
    assert clean_stderr(text) == "Error: boom"


# -- runner -------------------------------------------------------------------------


def test_dump_passes_safe_flags(spy: PySpy, pyspy_argv) -> None:
    threads = spy.dump(1234)
    assert [t["thread_name"] for t in threads] == ["worker", "MainThread"]
    argv = pyspy_argv()[-1]
    assert argv == ["dump", "--pid=1234", "--json", "--nonblocking"]
    spy.dump(1234, native=True, nonblocking=False)
    assert pyspy_argv()[-1] == ["dump", "--pid=1234", "--json", "--native"]
    assert not any("--locals" in a or a == "-l" for call in pyspy_argv() for a in call)


def test_dump_refuses_native_nonblocking(spy: PySpy, pyspy_argv) -> None:
    with pytest.raises(PySpyError) as e:
        spy.dump(1, native=True, nonblocking=True)
    assert e.value.code == "invalid_argument"
    assert pyspy_argv() == []


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("permission", "permission_denied"),
        ("not_python", "not_python"),
        ("no_such_process", "no_such_process"),
        ("crash", "py_spy_failed"),
        ("not_json", "bad_output"),
    ],
)
def test_dump_failures(spy: PySpy, monkeypatch, mode: str, code: str) -> None:
    monkeypatch.setenv("FAKE_PYSPY_MODE", mode)
    with pytest.raises(PySpyError) as e:
        spy.dump(1)
    assert e.value.code == code


def test_dump_timeout(fake_pyspy: Path, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_PYSPY_MODE", "timeout")
    with pytest.raises(PySpyError) as e:
        PySpy(fake_pyspy, dump_timeout=0.5).dump(1)
    assert e.value.code == "timeout"


def test_missing_binary(tmp_path: Path) -> None:
    for binary in (None, tmp_path / "nope"):
        with pytest.raises(PySpyError) as e:
            PySpy(binary).dump(1)
        assert e.value.code == "py_spy_not_found"
        with pytest.raises(PySpyError) as e:
            PySpy(binary).record(1, [RecordSpec(output=tmp_path / "x", duration_s=1, rate_hz=1)])
        assert e.value.code == "py_spy_not_found"


def test_record_runs_passes_concurrently(spy: PySpy, tmp_path: Path, pyspy_argv) -> None:
    specs = [
        RecordSpec(output=tmp_path / "a.folded", duration_s=2, rate_hz=50, idle=True),
        RecordSpec(output=tmp_path / "b.folded", duration_s=2, rate_hz=50, gil=True),
    ]
    results = spy.record(77, specs)
    assert [r.samples for r in results] == [190, 80]
    assert [r.errors for r in results] == [0, 0]
    assert sum(s.count for s in read_folded(tmp_path / "a.folded")) == 190
    calls = sorted(pyspy_argv())
    assert calls[0] == [
        "record",
        "--pid=77",
        f"--output={tmp_path / 'a.folded'}",
        "--format=raw",
        "--duration=2",
        "--rate=50",
        "--idle",
        "--threads",
        "--nonblocking",
    ]
    assert "--gil" in calls[1]


def test_record_reports_behind_warning(spy: PySpy, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_PYSPY_MODE", "behind")
    (result,) = spy.record(1, [RecordSpec(output=tmp_path / "a", duration_s=1, rate_hz=1)])
    assert result.warnings and "behind in sampling" in result.warnings[0]


def test_record_timeout_kills_and_cleans_up(fake_pyspy: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("FAKE_PYSPY_MODE", "timeout")
    out = tmp_path / "a.folded"
    out.write_text("partial")
    spy = PySpy(fake_pyspy, record_grace=0.5)
    before = _children()
    with pytest.raises(PySpyError) as e:
        spy.record(1, [RecordSpec(output=out, duration_s=1, rate_hz=1)])
    assert e.value.code == "timeout"
    assert not out.exists()
    assert _children() <= before


def test_record_failure_removes_all_outputs(spy: PySpy, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_PYSPY_MODE", "permission")
    specs = [
        RecordSpec(output=tmp_path / "a", duration_s=1, rate_hz=1),
        RecordSpec(output=tmp_path / "b", duration_s=1, rate_hz=1),
    ]
    with pytest.raises(PySpyError) as e:
        spy.record(1, specs)
    assert e.value.code == "permission_denied"
    assert list(tmp_path.glob("[ab]")) == []


def _children() -> set[int]:
    import psutil

    return {p.pid for p in psutil.Process().children(recursive=True) if p.is_running()}


# -- configuration -------------------------------------------------------------------


def test_resolve_py_spy_order(fake_pyspy: Path, tmp_path: Path, monkeypatch) -> None:
    other = tmp_path / "other-py-spy"
    other.write_text("#!/bin/sh\n")
    other.chmod(0o755)
    env = {"PY_SPY_BIN": str(other)}
    assert resolve_py_spy(str(fake_pyspy), env) == fake_pyspy.resolve()
    assert resolve_py_spy(None, env) == other.resolve()
    monkeypatch.setenv("PATH", str(fake_pyspy.parent))
    assert resolve_py_spy(None, {}) == fake_pyspy.resolve()
    with pytest.raises(ConfigError, match="--py-spy-bin"):
        resolve_py_spy(str(tmp_path / "missing"), {})
    with pytest.raises(ConfigError, match="PY_SPY_BIN"):
        resolve_py_spy(None, {"PY_SPY_BIN": str(tmp_path / "missing")})


def test_resolve_py_spy_next_to_interpreter(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    beside = Path(sys.executable).parent / "py-spy"
    found = resolve_py_spy(None, {})
    if beside.is_file():
        assert found == beside.resolve()
    else:
        assert found is None


def test_load_cpu_settings(fake_pyspy: Path) -> None:
    cfg = Config(heapspy_bin=None)
    assert cfg.py_spy_bin is None and cfg.cpu_max_duration == 30
    load_cpu_settings(cfg, py_spy_bin=str(fake_pyspy), env={"HEAPSPY_MCP_CPU_MAX_DURATION": "12"})
    assert cfg.py_spy_bin == fake_pyspy.resolve() and cfg.cpu_max_duration == 12
    load_cpu_settings(cfg, py_spy_bin=str(fake_pyspy), cpu_max_duration=5, env={})
    assert cfg.cpu_max_duration == 5
    for bad in ({"HEAPSPY_MCP_CPU_MAX_DURATION": "ten"}, {"HEAPSPY_MCP_CPU_MAX_DURATION": "0"}):
        with pytest.raises(ConfigError):
            load_cpu_settings(cfg, py_spy_bin=str(fake_pyspy), env=bad)


def test_main_rejects_bad_py_spy_bin(tmp_path: Path, capsys) -> None:
    assert main(["--py-spy-bin", str(tmp_path / "missing")]) == 2
    assert "--py-spy-bin" in capsys.readouterr().err
