"""Fixtures for the heapspy end-to-end suite. See README.md in this directory."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

import harness
from harness import Heapspy, Victim

REPO_ROOT = Path(__file__).resolve().parents[2]
EXE = ".exe" if harness.IS_WINDOWS else ""


@dataclass(frozen=True)
class Interpreter:
    label: str
    path: Path
    version: str

    @property
    def minor(self) -> int:
        return int(self.version.split(".")[1])


_PROBE = (
    "import json, sys, sysconfig;"
    "print(json.dumps([list(sys.version_info[:3]),"
    " bool(sysconfig.get_config_var('Py_GIL_DISABLED')), hasattr(sys, 'gettotalrefcount')]))"
)


def _probe(label: str | None, path: str) -> Interpreter:
    out = subprocess.run(
        [path, "-E", "-c", _PROBE], capture_output=True, text=True, timeout=60, check=False
    )
    if out.returncode != 0:
        raise pytest.UsageError(f"cannot run interpreter {path}: {out.stderr.strip()}")
    (major, minor, micro), free_threaded, debug = json.loads(out.stdout)
    if (major, minor) < (3, 12) or free_threaded or debug:
        raise pytest.UsageError(
            f"{path} is CPython {major}.{minor}.{micro}"
            f"{' free-threaded' if free_threaded else ''}{' debug' if debug else ''}; "
            "heapspy supports default builds of 3.12 to 3.14"
        )
    version = f"{major}.{minor}.{micro}"
    return Interpreter(label or f"py{major}.{minor}", Path(path), version)


def _uv_find(version: str) -> str | None:
    uv = shutil.which("uv")
    if uv is None:
        return None
    out = subprocess.run(
        [uv, "python", "find", version], capture_output=True, text=True, timeout=120, check=False
    )
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else None


def discover_interpreters() -> list[Interpreter]:
    """``$HEAPSPY_E2E_PYTHONS``, else whatever ``uv python find`` gives for 3.12 to 3.14.

    The variable is a list separated by ``os.pathsep`` (``:`` on Linux, ``;``
    on Windows). Each entry is a path, or ``label=path`` to name it in test ids.
    """
    spec = os.environ.get("HEAPSPY_E2E_PYTHONS", "").strip()
    found: list[Interpreter] = []
    if spec:
        for entry in filter(None, (e.strip() for e in spec.split(os.pathsep))):
            label, sep, path = entry.partition("=")
            found.append(_probe(label if sep else None, path if sep else entry))
    else:
        for version in ("3.12", "3.13", "3.14"):
            path = _uv_find(version)
            if path:
                found.append(_probe(None, path))
    labels = [i.label for i in found]
    dupes = {lbl for lbl in labels if labels.count(lbl) > 1}
    if dupes:
        raise pytest.UsageError(f"duplicate interpreter labels {sorted(dupes)}; use label=path")
    if not found:
        raise pytest.UsageError("no interpreters: set HEAPSPY_E2E_PYTHONS or install uv")
    return found


INTERPRETERS: list[Interpreter] = []


def pytest_configure(config: pytest.Config) -> None:
    INTERPRETERS.extend(discover_interpreters())


def pytest_report_header(config: pytest.Config) -> list[str]:
    return [f"victim interpreter {i.label}: {i.version} at {i.path}" for i in INTERPRETERS]


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "python" in metafunc.fixturenames:
        metafunc.parametrize("python", INTERPRETERS, ids=[i.label for i in INTERPRETERS])
    if "method" in metafunc.fixturenames:
        metafunc.parametrize("method", harness.acquisition_methods())


@pytest.fixture(autouse=True)
def _current_test(request: pytest.FixtureRequest) -> Iterator[None]:
    harness.CURRENT_TEST[0] = request.node.nodeid.split("::", 1)[-1]
    yield
    harness.CURRENT_TEST[0] = "?"


@pytest.fixture(scope="session")
def heapspy_bin() -> Path:
    """``$HEAPSPY_BIN``, else ``cargo build --release`` and use target/release/heapspy."""
    configured = os.environ.get("HEAPSPY_BIN")
    if configured:
        path = Path(configured)
        if not path.is_file():
            raise pytest.UsageError(f"HEAPSPY_BIN={configured} is not a file")
        return path.resolve()
    cargo = shutil.which("cargo")
    if cargo is None:
        raise pytest.UsageError("set HEAPSPY_BIN or install cargo")
    subprocess.run(
        [cargo, "build", "--release", "--locked", "-p", "heapspy"], cwd=REPO_ROOT, check=True
    )
    return REPO_ROOT / "target" / "release" / f"heapspy{EXE}"


@pytest.fixture(scope="session")
def heapspy(heapspy_bin: Path) -> Heapspy:
    return Heapspy(heapspy_bin)


@pytest.fixture
def start_victim(tmp_path: Path) -> Iterator:
    """Start victims; every one is killed when the test ends, pass or fail."""
    started: list[Victim] = []

    def start(python: Interpreter, script: str, name: str = "victim") -> Victim:
        v = Victim(python.path, script, tmp_path / name)
        started.append(v)
        v.wait_ready()
        return v

    yield start
    for v in started:
        v.kill()


def pytest_terminal_summary(terminalreporter, exitstatus: int, config: pytest.Config) -> None:
    if not harness.TIMINGS:
        return
    tr = terminalreporter
    tr.section("heapspy timings (seconds)")
    by_test: dict[str, list[str]] = {}
    for t in harness.TIMINGS:
        by_test.setdefault(t.test, []).append(f"{t.step} {t.seconds:.2f}")
    width = max(len(name) for name in by_test)
    for name, steps in by_test.items():
        tr.write_line(f"{name:<{width}}  {', '.join(steps)}")
    report = os.environ.get("HEAPSPY_E2E_REPORT")
    if report:
        Path(report).write_text(json.dumps([t.__dict__ for t in harness.TIMINGS], indent=1) + "\n")
