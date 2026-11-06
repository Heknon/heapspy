from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from heapspy_mcp.source_map import (
    MAX_EXCERPT_LINES,
    MAX_LINE,
    SourceMapError,
    map_to_source,
)


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"))
    return path


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    write(root, "app/__init__.py", '"""The app package."""\nVERSION = "1"\n')
    write(
        root,
        "app/cache.py",
        """
        import threading
        from typing import Any

        CACHE: dict[str, Any] = {}
        _lock = threading.Lock()


        class Session:
            def __init__(self, payload):
                self.payload = payload
                self.user = None


        class Store:
            class Inner:
                def method(self):
                    return 1

            @staticmethod
            def get(key):
                return CACHE.get(key)


        def make_handler():
            class Handler:
                pass

            return Handler


        try:
            import ujson as json
        except ImportError:
            import json
        """,
    )
    write(root, "src/svc/__init__.py", "")
    write(root, "src/svc/models.py", "class Model:\n    registry = []\n")
    write(
        root,
        "tool.py",
        """
        class Job:
            pending = []


        if __name__ == "__main__":
            Job()
        """,
    )
    write(root, "app/__main__.py", "RUNNING = True\n")
    long_body = "\n".join(f"    x{i} = {i}" for i in range(100))
    write(root, "app/big.py", f"def big():\n{long_body}\n\nLONG = '{'z' * 1000}'\n")
    write(root, "services/billing/billing/ledger.py", "LEDGER = []\n")
    return root


def resolve(qualname: str, repo: Path) -> dict:
    return map_to_source(qualname, str(repo))


def only(result: dict) -> dict:
    assert len(result["candidates"]) == 1, result
    return result["candidates"][0]


def test_module_level_assignment(repo: Path) -> None:
    c = only(resolve("app.cache.CACHE", repo))
    assert c["location"] == "app/cache.py:4"
    assert c["kind"] == "assignment"
    assert "CACHE: dict[str, Any] = {}" in c["excerpt"]


def test_class_in_package(repo: Path) -> None:
    c = only(resolve("app.cache.Session", repo))
    assert (c["file"], c["line"], c["kind"]) == ("app/cache.py", 8, "class")
    assert c["module"] == "app.cache" and c["qualname"] == "Session"


def test_nested_class_method(repo: Path) -> None:
    c = only(resolve("app.cache.Store.Inner.method", repo))
    assert (c["line"], c["kind"]) == (16, "function")


def test_decorated_method_excerpt_starts_at_decorator(repo: Path) -> None:
    c = only(resolve("app.cache.Store.get", repo))
    assert c["line"] == 19
    assert c["excerpt"].splitlines()[0].strip().endswith("@staticmethod")


def test_instance_attribute(repo: Path) -> None:
    c = only(resolve("app.cache.Session.payload", repo))
    assert (c["line"], c["kind"]) == (10, "instance_attribute")


def test_locals(repo: Path) -> None:
    c = only(resolve("app.cache.make_handler.<locals>.Handler", repo))
    assert (c["line"], c["kind"]) == (25, "class")


def test_names_bound_in_try_blocks(repo: Path) -> None:
    result = resolve("app.cache.json", repo)
    assert [c["kind"] for c in result["candidates"]] == ["import", "import"]


def test_package_init_and_module(repo: Path) -> None:
    c = only(resolve("app.VERSION", repo))
    assert c["location"] == "app/__init__.py:2"
    c = only(resolve("app.cache", repo))
    assert (c["kind"], c["line"]) == ("module", 1)


def test_src_layout(repo: Path) -> None:
    c = only(resolve("svc.models.Model.registry", repo))
    assert c["location"] == "src/svc/models.py:2"


def test_monorepo_subproject(repo: Path) -> None:
    c = only(resolve("billing.ledger.LEDGER", repo))
    assert c["file"] == "services/billing/billing/ledger.py"


def test_main_module(repo: Path) -> None:
    c = only(resolve("__main__.Job.pending", repo))
    assert c["location"] == "tool.py:2"
    c = only(resolve("__main__.RUNNING", repo))
    assert c["file"] == "app/__main__.py"


def test_excerpt_is_bounded(repo: Path) -> None:
    c = only(resolve("app.big.big", repo))
    assert len(c["excerpt"].splitlines()) == MAX_EXCERPT_LINES
    assert c["end_line"] == 101
    c = only(resolve("app.big.LONG", repo))
    assert max(len(line) for line in c["excerpt"].splitlines()) <= MAX_LINE + 7


def test_not_found_reports_partial_match(repo: Path) -> None:
    result = resolve("app.cache.Session.nothing_here", repo)
    assert result["candidates"] == []
    assert result["partial_match"]["file"] == "app/cache.py"
    assert result["partial_match"]["unresolved"] == "nothing_here"


def test_builtins_and_third_party(repo: Path) -> None:
    assert "builtins" in resolve("builtins.dict", repo)["note"]
    result = resolve("requests.sessions.Session", repo)
    assert result["candidates"] == [] and "third-party" in result["note"]


@pytest.mark.parametrize(
    "qualname",
    [
        "",
        "..etc.passwd",
        "app/../../etc",
        "app..cache",
        "app.cache.\\x",
        "app.ca che",
        "<locals>.x",
    ],
)
def test_rejects_bad_qualnames(repo: Path, qualname: str) -> None:
    with pytest.raises(SourceMapError):
        resolve(qualname, repo)


def test_rejects_traversal_in_repo_path(repo: Path) -> None:
    with pytest.raises(SourceMapError, match=r"\.\."):
        map_to_source("app.cache.CACHE", str(repo / "app" / ".." / ".."))
    with pytest.raises(SourceMapError):
        map_to_source("app.cache.CACHE", str(repo / "missing"))
    with pytest.raises(SourceMapError):
        map_to_source("app.cache.CACHE", str(repo / "tool.py"))


def test_does_not_follow_symlinks_outside_repo(repo: Path, tmp_path: Path) -> None:
    outside = write(tmp_path, "outside/secret.py", "SECRET = 'hunter2'\n")
    (repo / "app" / "leak.py").symlink_to(outside)
    (repo / "outpkg").symlink_to(outside.parent, target_is_directory=True)
    for name in ("app.leak.SECRET", "outpkg.secret.SECRET"):
        result = resolve(name, repo)
        assert result["candidates"] == []
        assert all("secret" not in f for f in result["searched_files"])
    # A symlink that stays inside the repository is fine.
    (repo / "app" / "alias.py").symlink_to(repo / "app" / "cache.py")
    c = only(resolve("app.alias.CACHE", repo))
    assert c["file"] == "app/cache.py"


async def test_through_server(call, repo: Path) -> None:
    err, out = await call("map_to_source", {"qualname": "app.cache.CACHE", "repo_path": str(repo)})
    assert not err, out
    assert out["candidates"][0]["location"] == "app/cache.py:4"
    err, out = await call("map_to_source", {"qualname": "../x", "repo_path": str(repo)})
    assert err and out["error"]["code"] == "invalid_argument"
