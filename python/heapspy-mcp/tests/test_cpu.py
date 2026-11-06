"""The attach gates of the CPU tools."""

from __future__ import annotations

import os

import pytest

from heapspy_mcp.cpu import AttachRefused, check_target

# -- check_target -------------------------------------------------------------------


def test_check_target_needs_an_allowlist(make_config, child_python) -> None:
    with pytest.raises(AttachRefused) as e:
        check_target(make_config(allow=[]), child_python.pid)
    assert e.value.reason == "attach_disabled"
    assert e.value.to_dict()["code"] == "attach_refused"
    assert "--allow" in e.value.message


def test_check_target_not_allowlisted(make_config, child_python) -> None:
    with pytest.raises(AttachRefused) as e:
        check_target(make_config(allow=["gunicorn*", "pid:1"]), child_python.pid)
    assert e.value.reason == "not_allowlisted"
    assert e.value.to_dict()["pid"] == child_python.pid


def test_check_target_refuses_own_pid(make_config) -> None:
    with pytest.raises(AttachRefused) as e:
        check_target(make_config(allow=["*"]), os.getpid())
    assert e.value.reason == "invalid_argument"


@pytest.mark.parametrize(
    ("pid", "reason"),
    [(0, "invalid_argument"), (-5, "invalid_argument"), (2**22 + 12345, "no_such_process")],
)
def test_check_target_bad_pid(make_config, pid, reason) -> None:
    with pytest.raises(AttachRefused) as e:
        check_target(make_config(allow=["*"]), pid)
    assert e.value.reason == reason


def test_check_target_by_pid_and_name_pattern(make_config, child_python) -> None:
    target = check_target(make_config(allow=[f"pid:{child_python.pid}"]), child_python.pid)
    assert target["allowlist_entry"] == f"pid:{child_python.pid}"
    target = check_target(make_config(allow=["*time.sleep(120)*"]), child_python.pid)
    assert target["allowlist_entry"] == "*time.sleep(120)*"
    assert target["pid"] == child_python.pid
    assert target["name"].startswith("python")
