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
    result = resolve("__main__.Job.pending", repo)
    c = only(result)
    assert c["location"] == "tool.py:2"
    assert c["main_evidence"] == [
        "has an if __name__ == '__main__' guard",
        "defines Job at top level",
    ]
    assert result["heuristic"] is True
    assert "whichever script was started" in result["main_resolution"]["note"]
    c = only(resolve("__main__.RUNNING", repo))
    assert c["file"] == "app/__main__.py"
    assert c["main_evidence"][0] == "named __main__.py"


def test_main_script_without_guard(repo: Path) -> None:
    write(
        repo,
        "scripts/leaky.py",
        """
        import time

        class Holder:
            items = []


        while True:
            Holder.items.append(bytearray(1024))
            time.sleep(0.01)
        """,
    )
    result = resolve("__main__.Holder.items", repo)
    c = only(result)
    assert c["location"] == "scripts/leaky.py:4"
    assert c["kind"] == "assignment"
    assert c["main_evidence"] == ["defines Holder at top level"]
    assert result["main_resolution"]["files_matched"] == 1


def test_main_name_defined_in_two_scripts(repo: Path) -> None:
    write(repo, "jobs/a_plain.py", "BUFFER = []\n")
    write(
        repo,
        "jobs/b_runner.py",
        """
        #!/usr/bin/env python3
        BUFFER = []


        if __name__ == "__main__":
            BUFFER.append(1)
        """,
    )
    write(repo, "jobs/c_import.py", "from jobs.a_plain import BUFFER\n")
    write(repo, "jobs/d_mention.py", "def f():\n    BUFFER = 1\n    return BUFFER\n")
    result = resolve("__main__.BUFFER", repo)
    files = [c["file"] for c in result["candidates"]]
    # Main guard and #! first; a plain definition next; an import last; a local is no match.
    assert files == ["jobs/b_runner.py", "jobs/a_plain.py", "jobs/c_import.py"]
    assert result["candidates"][0]["main_evidence"] == [
        "has an if __name__ == '__main__' guard",
        "starts with a #! line",
        "defines BUFFER at top level",
    ]
    assert result["candidates"][2]["kind"] == "import"
    assert result["heuristic"] is True


def test_main_scan_stays_in_repo(repo: Path, tmp_path: Path) -> None:
    outside = write(tmp_path, "outside/evil.py", "SECRET_HOLDER = []\n")
    write(tmp_path, "outside/deep/more.py", "SECRET_HOLDER = []\n")
    (repo / "linked.py").symlink_to(outside)
    (repo / "linkdir").symlink_to(outside.parent, target_is_directory=True)
    write(repo, ".hidden/x.py", "SECRET_HOLDER = []\n")
    write(repo, ".venv/lib/x.py", "SECRET_HOLDER = []\n")
    result = resolve("__main__.SECRET_HOLDER", repo)
    assert result["candidates"] == []
    assert result["searched_files"] == []
    assert result["main_resolution"]["files_matched"] == 0


def test_main_scan_is_bounded(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import heapspy_mcp.source_map as source_map

    monkeypatch.setattr(source_map, "MAX_MAIN_SCAN", 3)
    result = resolve("__main__.Job", repo)
    assert result["main_resolution"]["files_scanned"] == 3
    assert result["main_resolution"]["scan_limit_reached"] is True


def test_non_main_names_are_not_heuristic(repo: Path) -> None:
    result = resolve("app.cache.CACHE", repo)
    assert "heuristic" not in result and "main_resolution" not in result


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


# -- exact resolution from a snapshot's recorded locations --------------------------


def located(*matches: dict) -> dict:
    return {"matches": list(matches)}


def match(kind: str, module: str, qualname: str, file: str, line: int | None, **loc) -> dict:
    exact = loc.pop("exact", kind != "type")
    via = loc.pop("via", "methods" if kind == "type" else "function")
    return {
        "kind": kind,
        "name": f"{module}.{qualname}" if qualname else module,
        "module": module,
        "qualname": qualname,
        "address": "0x7f0000001000",
        "source_loc": {"file": file, "line": line, "exact": exact, "via": via},
        "source_loc_reason": None,
    }


@pytest.fixture
def reads(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Every file map_to_source parses or excerpts."""
    import heapspy_mcp.source_map as source_map

    seen: list[Path] = []
    parse, raw = source_map._parse, source_map._raw_excerpt

    def spy_parse(path: Path):
        seen.append(path)
        return parse(path)

    def spy_raw(path: Path, line: int):
        seen.append(path)
        return raw(path, line)

    monkeypatch.setattr(source_map, "_parse", spy_parse)
    monkeypatch.setattr(source_map, "_raw_excerpt", spy_raw)
    return seen


def test_exact_from_relative_recorded_path(repo: Path) -> None:
    # A class is recorded at its first method's line; the class statement is above.
    m = match("type", "app.cache", "Session", "app/cache.py", 9)
    result = map_to_source("app.cache.Session", str(repo), located(m))
    assert result["heuristic"] is False and result["via"] == "snapshot"
    c = only(result)
    assert c["location"] == "app/cache.py:8"
    assert c["kind"] == "class"
    assert c["matched_by"] == "repo_relative"
    assert c["recorded"] == {"file": "app/cache.py", "line": 9, "exact": False, "via": "methods"}
    assert c["excerpt"].splitlines()[0] == "    8  class Session:"
    assert "source_mismatch" not in c
    assert result["searched_files"] == ["app/cache.py"]


def test_exact_from_absolute_path_inside_repo(repo: Path) -> None:
    # A decorated function's co_firstlineno is its first decorator.
    m = match("function", "app.cache", "Store.get", str(repo / "app" / "cache.py"), 19)
    c = only(map_to_source("app.cache.Store.get", str(repo), located(m)))
    assert (c["location"], c["kind"], c["matched_by"]) == (
        "app/cache.py:19",
        "function",
        "exact_path",
    )


def test_absolute_path_outside_repo_is_never_read(
    repo: Path, tmp_path: Path, reads: list[Path]
) -> None:
    outside = write(tmp_path, "outside/secret_mod.py", "class Session:\n    SECRET = 'hunter2'\n")
    m = match("type", "secret_mod", "Session", str(outside), 2)
    result = map_to_source("secret_mod.Session", str(repo), located(m))
    assert result["candidates"] == []
    assert "heuristic" not in result
    lookup = result["snapshot_lookup"]
    assert lookup["status"] == "not_in_repo"
    assert lookup["recorded"] == [
        {
            "file": str(outside),
            "line": 2,
            "exact": False,
            "via": "methods",
            "reason": "not_in_repo",
        }
    ]
    assert all(p.is_relative_to(repo.resolve()) for p in reads), reads
    assert "hunter2" not in repr(result)


def test_absolute_path_from_another_machine_by_suffix(repo: Path) -> None:
    m = match("type", "app.cache", "Session", "/srv/build/checkout/app/cache.py", 9)
    c = only(map_to_source("app.cache.Session", str(repo), located(m)))
    assert (c["file"], c["matched_by"], c["line"]) == ("app/cache.py", "suffix", 8)
    # Windows paths too.
    m = match("type", "app.cache", "Session", r"C:\build\app\cache.py", 9)
    c = only(map_to_source("app.cache.Session", str(repo), located(m)))
    assert (c["file"], c["matched_by"]) == ("app/cache.py", "suffix")


def test_ambiguous_suffix_falls_back(repo: Path) -> None:
    write(repo, "lib/models.py", "class Model:\n    pass\n")
    m = match("type", "svc.models", "Model", "/elsewhere/models.py", 1)
    result = map_to_source("svc.models.Model", str(repo), located(m))
    assert result.get("via") != "snapshot"
    assert result["snapshot_lookup"]["recorded"][0]["reason"] == "ambiguous_suffix"
    # The fallback still finds src/svc/models.py from the module path.
    assert only(result)["file"] == "src/svc/models.py"


def test_snapshot_disambiguates_two_main_scripts(repo: Path) -> None:
    script = """
        class Session:
            def __init__(self):
                self.items = []


        if __name__ == "__main__":
            Session()
        """
    write(repo, "jobs/a_first.py", script)
    b = write(repo, "jobs/b_second.py", "import os\n\n" + textwrap.dedent(script).lstrip("\n"))
    heuristic = map_to_source("__main__.Session", str(repo))
    # Both scripts rank equally (main guard, definition); app/cache.py also defines Session.
    files = [c["file"] for c in heuristic["candidates"]]
    assert files == ["jobs/a_first.py", "jobs/b_second.py", "app/cache.py"]
    assert heuristic["heuristic"] is True
    m = match("type", "__main__", "Session", str(b), 4)
    result = map_to_source("__main__.Session", str(repo), located(m))
    c = only(result)
    assert (c["location"], c["kind"]) == ("jobs/b_second.py:3", "class")
    assert result["heuristic"] is False and "main_resolution" not in result


def test_symlink_out_of_repo_is_not_followed(repo: Path, tmp_path: Path, reads: list[Path]) -> None:
    outside = write(tmp_path, "outside/secret.py", "class Leak:\n    SECRET = 'hunter2'\n")
    (repo / "app" / "leak.py").symlink_to(outside)
    for recorded in (str(repo / "app" / "leak.py"), "app/leak.py", "/x/app/leak.py"):
        m = match("type", "app.leak", "Leak", recorded, 2)
        result = map_to_source("app.leak.Leak", str(repo), located(m))
        assert result["candidates"] == []
        assert result["snapshot_lookup"]["status"] == "not_in_repo"
    assert all(p.resolve().is_relative_to(repo.resolve()) for p in reads), reads


def test_generated_filenames_and_missing_locations_fall_back(repo: Path) -> None:
    m = match("function", "app.cache", "Session.__init__", "<string>", 1)
    result = map_to_source("app.cache.Session.__init__", str(repo), located(m))
    assert result["snapshot_lookup"]["recorded"][0]["reason"] == "generated_filename"
    # The fallback still finds it from the files.
    assert only(result)["location"] == "app/cache.py:9"

    no_loc = {**m, "source_loc": None, "source_loc_reason": "no_python_methods"}
    result = map_to_source("app.cache.Session", str(repo), located(no_loc))
    assert result["snapshot_lookup"]["status"] == "no_location"
    assert result["snapshot_lookup"]["reasons"] == ["no_python_methods"]

    result = map_to_source("app.cache.Session", str(repo), located())
    assert result["snapshot_lookup"]["status"] == "not_in_snapshot"
    assert only(result)["location"] == "app/cache.py:8"


def test_changed_file_is_flagged(repo: Path) -> None:
    # The snapshot says line 4, where the file now has CACHE, not Session.
    m = match("type", "app.cache", "Session", "app/cache.py", 4)
    c = only(map_to_source("app.cache.Session", str(repo), located(m)))
    assert c["source_mismatch"] is True
    assert c["location"] == "app/cache.py:4"
    assert c["excerpt"].splitlines()[0].endswith("CACHE: dict[str, Any] = {}")
    assert len(c["excerpt"].splitlines()) <= MAX_EXCERPT_LINES


def test_module_location(repo: Path) -> None:
    m = match("module", "app.cache", "", "app/cache.py", None, exact=True, via="module_file")
    c = only(map_to_source("app.cache", str(repo), located(m)))
    assert (c["location"], c["kind"]) == ("app/cache.py:1", "module")


def test_without_located_result_is_unchanged(repo: Path) -> None:
    assert map_to_source("__main__.Job", str(repo), None) == map_to_source(
        "__main__.Job", str(repo)
    )
