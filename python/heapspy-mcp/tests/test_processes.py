from __future__ import annotations

import os
import sys

import pytest

from heapspy_mcp.processes import (
    MAX_CMDLINE,
    matches_allowlist,
    version_from_exe,
    version_from_maps_text,
)


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("python3.12", "3.12"),
        ("/usr/bin/python3.13", "3.13"),
        ("python3.13t", "3.13"),
        ("python3.12d", "3.12"),
        ("python312.exe", "3.12"),
        ("pythonw3.11", "3.11"),
        ("python3", None),
        ("python", None),
        ("pythonista", None),
        ("bash", None),
        (None, None),
    ],
)
def test_version_from_exe(name, version) -> None:
    assert version_from_exe(name) == version


def test_version_from_maps() -> None:
    maps = (
        "7f00-7f01 r--p 00000000 08:01 123 /usr/lib/python3.12/lib-dynload/_json.cpython-312.so\n"
        "7f02-7f03 r-xp 00000000 08:01 456 /usr/lib/x86_64-linux-gnu/libpython3.12.so.1.0\n"
    )
    assert version_from_maps_text(maps) == "3.12"
    assert version_from_maps_text(r"C:\Python313\python313.dll") == "3.13"
    assert version_from_maps_text("/opt/lib/libpython3.14t.so") == "3.14"
    assert version_from_maps_text("/usr/lib/libc.so.6") is None
    assert version_from_maps_text("/usr/lib/python3.12/os.py") is None


def test_allowlist_matching() -> None:
    kw = {
        "pid": 10,
        "name": "gunicorn",
        "exe": "/usr/bin/python3.12",
        "cmdline": ["/usr/bin/python3.12", "-m", "gunicorn", "app:wsgi"],
    }
    assert matches_allowlist([], **kw) is None
    assert matches_allowlist(["pid:10"], **kw) == "pid:10"
    assert matches_allowlist(["10"], **kw) == "10"
    assert matches_allowlist(["11", "pid:12"], **kw) is None
    assert matches_allowlist(["gunicorn"], **kw) == "gunicorn"
    assert matches_allowlist(["python3.*"], **kw) == "python3.*"
    assert matches_allowlist(["*app:wsgi*"], **kw) == "*app:wsgi*"
    assert matches_allowlist(["Gunicorn"], **kw) is None
    assert matches_allowlist(["celery*"], **kw) is None


async def test_lists_this_test_process(call) -> None:
    err, out = await call("list_python_processes", {"limit": 200})
    assert not err, out
    me = next(p for p in out["processes"] if p["pid"] == os.getpid())
    assert me["is_this_server"] is True
    assert me["rss_bytes"] > 0
    assert me["python_version"] == f"{sys.version_info.major}.{sys.version_info.minor}"
    assert me["version_source"] in {"exe_name", "libpython_mapping"}
    assert len(me["cmdline"]) <= MAX_CMDLINE
    assert me["capture_allowed"] is False
    assert out["capture_allowlist_configured"] is False


async def test_name_filter_and_limit(call, child_python) -> None:
    err, out = await call(
        "list_python_processes",
        {"name_filter": "TIME.SLEEP(120)"},
        allow=[f"pid:{child_python.pid}"],
    )
    assert not err, out
    assert [p["pid"] for p in out["processes"]] == [child_python.pid]
    assert out["processes"][0]["capture_allowed"] is True
    err, out = await call("list_python_processes", {"limit": 0})
    assert len(out["processes"]) <= 1
