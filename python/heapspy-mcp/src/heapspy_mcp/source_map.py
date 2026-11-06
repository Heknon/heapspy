"""Resolve ``module.qualname`` names from heapspy output to ``file:line``.

Read-only and confined to one repository directory: every file that is
opened must resolve (after following symlinks) to a path inside the
repository root.
"""

from __future__ import annotations

import ast
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_CANDIDATES = 10
MAX_EXCERPT_LINES = 8
MAX_LINE = 200
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SEARCHED = 20
MAX_MAIN_SCAN = 500
MAX_SUBDIR_ROOTS = 200
LOCALS = "<locals>"

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".tox",
    ".nox",
    "build",
    "dist",
    "site-packages",
    "target",
}


class SourceMapError(Exception):
    """Bad arguments: the repository path or the qualname is unusable."""


@dataclass
class _Hit:
    file: Path
    node: ast.AST
    kind: str
    qualname: str


def _check_qualname(qualname: str) -> list[str]:
    qualname = qualname.strip()
    if not qualname:
        raise SourceMapError("empty qualname")
    if "/" in qualname or "\\" in qualname:
        raise SourceMapError(f"{qualname!r} looks like a path; give a dotted module.qualname")
    parts = qualname.split(".")
    for part in parts:
        if part == LOCALS:
            continue
        if not part.isidentifier():
            raise SourceMapError(
                f"{qualname!r}: segment {part!r} is not a Python identifier "
                "(path traversal and file paths are not accepted)"
            )
    if parts[0] == LOCALS:
        raise SourceMapError(f"{qualname!r} does not start with a module name")
    return parts


def _check_repo(repo_path: str) -> Path:
    if not repo_path or not repo_path.strip():
        raise SourceMapError("repo_path is empty")
    raw = Path(repo_path).expanduser()
    if ".." in raw.parts:
        raise SourceMapError(f"repo_path {repo_path!r} contains '..'; give the repository root")
    try:
        root = raw.resolve(strict=True)
    except (OSError, RuntimeError) as e:
        raise SourceMapError(f"repo_path {repo_path!r} does not exist") from e
    if not root.is_dir():
        raise SourceMapError(f"repo_path {repo_path!r} is not a directory")
    return root


def _inside(root: Path, path: Path) -> Path | None:
    """``path`` with symlinks resolved, if it stays inside ``root`` and is a file."""
    try:
        real = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    try:
        real.relative_to(root)
    except ValueError:
        return None
    return real if real.is_file() else None


def _search_roots(root: Path, top: str) -> list[Path]:
    """Directories that may contain the top-level package or module ``top``."""
    roots = [root]
    for name in ("src", "lib", "python"):
        if (root / name).is_dir():
            roots.append(root / name)

    # Monorepos: <root>/<project>/[src/]<top>, two directory levels deep at most.
    def subdirs(path: Path) -> list[Path]:
        try:
            return sorted(
                p
                for p in path.iterdir()
                if p.is_dir() and p.name not in _SKIP_DIRS and not p.name.startswith(".")
            )
        except OSError:
            return []

    level1 = subdirs(root)[:MAX_SUBDIR_ROOTS]
    level2 = [d for sub in level1 for d in subdirs(sub)][:MAX_SUBDIR_ROOTS]
    for sub in [*level1, *level2]:
        for base in (sub, sub / "src"):
            if base in roots:
                continue
            if (base / top).is_dir() or (base / f"{top}.py").is_file():
                roots.append(base)
    return roots


def _module_files(root: Path, base: Path, module_parts: list[str]) -> Iterator[Path]:
    rel = Path(*module_parts)
    for candidate in (base / rel.with_suffix(".py"), base / rel / "__init__.py"):
        real = _inside(root, candidate)
        if real is not None:
            yield real


_MAIN_GUARD_RE = re.compile(r"""^\s*if\s+__name__\s*==\s*['"]__main__['"]""", re.MULTILINE)


@dataclass
class _MainCandidate:
    """A file that may have run as ``__main__``, and why it ranks where it does."""

    file: Path
    evidence: list[str]
    score: int
    depth: int


@dataclass
class _MainScan:
    candidates: list[_MainCandidate]
    scanned: int
    limit_reached: bool


def _main_candidates(root: Path, name: str | None) -> _MainScan:
    """Files that may have run as ``__main__`` and bind ``name`` at top level.

    ``__main__`` is whichever script was started, so it cannot be found by
    module path. Every ``.py`` file in the repository (at most
    ``MAX_MAIN_SCAN``, skipping virtualenvs, build output and hidden
    directories, and never leaving the repository through a symlink) is
    checked for a top-level class, function, assignment or import of
    ``name``. Without a name, only ``__main__.py`` files and scripts with a
    main guard qualify. Ranking, best first: a file named ``__main__.py``, a
    main guard, a ``#!`` line, a definition rather than an import, then
    shallower paths, then the path.
    """
    found: list[_MainCandidate] = []
    scanned = 0
    limit_reached = False
    word = re.compile(rf"\b{re.escape(name)}\b") if name else None
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not d.startswith("."))
        for fname in sorted(filenames):
            if not fname.endswith(".py"):
                continue
            if scanned >= MAX_MAIN_SCAN:
                limit_reached = True
                break
            scanned += 1
            real = _inside(root, Path(dirpath) / fname)
            if real is None:
                continue
            try:
                if real.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = real.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            evidence: list[str] = []
            score = 0
            if fname == "__main__.py":
                evidence.append("named __main__.py")
                score += 8
            if _MAIN_GUARD_RE.search(text):
                evidence.append("has an if __name__ == '__main__' guard")
                score += 4
            if text.startswith("#!"):
                evidence.append("starts with a #! line")
                score += 2
            if word is None:
                if score < 4:
                    continue
            else:
                # Cheap text check first; only files that mention the name are parsed.
                if not word.search(text):
                    continue
                try:
                    tree = ast.parse(text, filename=str(real))
                except (SyntaxError, ValueError):
                    continue
                kinds = {kind for _, kind in _find_in_scope(tree.body, name or "")}
                if not kinds:
                    continue
                if kinds - {"import"}:
                    evidence.append(f"defines {name} at top level")
                    score += 1
                else:
                    evidence.append(f"imports {name} at top level")
            depth = len(real.relative_to(root).parts)
            found.append(_MainCandidate(real, evidence, score, depth))
        if limit_reached:
            break
    found.sort(key=lambda c: (-c.score, c.depth, c.file.relative_to(root).as_posix()))
    return _MainScan(found, scanned, limit_reached)


def _parse(path: Path) -> tuple[ast.Module, list[str]] | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
        return ast.parse(text, filename=str(path)), text.splitlines()
    except (OSError, SyntaxError, ValueError):
        return None


def _scope_statements(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Statements of one scope, looking through if/try/with/for/while blocks."""
    for stmt in body:
        yield stmt
        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            yield from _scope_statements(stmt.body)
            yield from _scope_statements(stmt.orelse)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            yield from _scope_statements(stmt.body)
        elif isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
            yield from _scope_statements(stmt.body)  # type: ignore[attr-defined]
            for handler in stmt.handlers:  # type: ignore[attr-defined]
                yield from _scope_statements(handler.body)
            yield from _scope_statements(stmt.orelse)  # type: ignore[attr-defined]
            yield from _scope_statements(stmt.finalbody)  # type: ignore[attr-defined]


def _target_names(target: ast.expr) -> Iterator[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _target_names(elt)
    elif isinstance(target, ast.Starred):
        yield from _target_names(target.value)


def _find_in_scope(body: list[ast.stmt], name: str) -> list[tuple[ast.AST, str]]:
    found: list[tuple[ast.AST, str]] = []
    for stmt in _scope_statements(body):
        if isinstance(stmt, ast.ClassDef) and stmt.name == name:
            found.append((stmt, "class"))
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == name:
            found.append((stmt, "function"))
        elif isinstance(stmt, ast.Assign):
            if any(name in _target_names(t) for t in stmt.targets):
                found.append((stmt, "assignment"))
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            if name in _target_names(stmt.target):
                found.append((stmt, "assignment"))
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                bound = alias.asname or alias.name.split(".")[0]
                if bound == name:
                    found.append((stmt, "import"))
        elif type(stmt).__name__ == "TypeAlias" and getattr(stmt, "name", None) is not None:
            alias_name = stmt.name  # type: ignore[attr-defined]
            if isinstance(alias_name, ast.Name) and alias_name.id == name:
                found.append((stmt, "type_alias"))
    return found


def _instance_attributes(cls: ast.ClassDef, name: str) -> list[tuple[ast.AST, str]]:
    """``self.<name> = ...`` assignments in the methods of ``cls``."""
    found: list[tuple[ast.AST, str]] = []
    for stmt in cls.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) or not stmt.args.args:
            continue
        self_name = stmt.args.args[0].arg
        for node in ast.walk(stmt):
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                targets = [node.target]
            for t in targets:
                if (
                    isinstance(t, ast.Attribute)
                    and t.attr == name
                    and isinstance(t.value, ast.Name)
                    and t.value.id == self_name
                ):
                    found.append((node, "instance_attribute"))
    return found


def _resolve_in_module(tree: ast.Module, rest: list[str]) -> tuple[list[tuple[ast.AST, str]], int]:
    """Nodes matching ``rest`` inside ``tree``, and how many segments matched."""
    if not rest:
        return [(tree, "module")], 0
    scopes: list[ast.AST] = [tree]
    matched = 0
    hits: list[tuple[ast.AST, str]] = []
    for i, name in enumerate(rest):
        if name == LOCALS:
            # The next name lives inside the function body; keep only functions.
            scopes = [s for s in scopes if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
            matched += 1
            continue
        hits = []
        for scope in scopes:
            body = getattr(scope, "body", None)
            if not isinstance(body, list):
                continue
            hits.extend(_find_in_scope(body, name))
            if isinstance(scope, ast.ClassDef) and i == len(rest) - 1 and not hits:
                hits.extend(_instance_attributes(scope, name))
        if not hits:
            return [], matched
        matched += 1
        scopes = [node for node, _ in hits]
    return hits, matched


def _excerpt(lines: list[str], node: ast.AST) -> tuple[int, int, str]:
    if isinstance(node, ast.Module):
        start = 1
        end = min(len(lines), MAX_EXCERPT_LINES)
    else:
        decorators = getattr(node, "decorator_list", None) or []
        start = min([getattr(node, "lineno", 1), *(d.lineno for d in decorators)])
        end_line = getattr(node, "end_lineno", None) or start
        end = min(end_line, start + MAX_EXCERPT_LINES - 1)
    body = []
    for no in range(start, end + 1):
        if no - 1 >= len(lines):
            break
        text = lines[no - 1]
        if len(text) > MAX_LINE:
            text = text[: MAX_LINE - 3] + "..."
        body.append(f"{no:>5}  {text}")
    return start, getattr(node, "end_lineno", None) or end, "\n".join(body)


def map_to_source(qualname: str, repo_path: str) -> dict[str, Any]:
    parts = _check_qualname(qualname)
    root = _check_repo(repo_path)
    searched: list[str] = []
    candidates: list[dict[str, Any]] = []
    partial: dict[str, Any] | None = None
    seen: set[tuple[Path, int]] = set()

    def rel(p: Path) -> str:
        return p.relative_to(root).as_posix()

    def consider(
        path: Path, module: str, rest: list[str], extra: dict[str, Any] | None = None
    ) -> None:
        nonlocal partial
        if len(searched) < MAX_SEARCHED:
            searched.append(rel(path))
        parsed = _parse(path)
        if parsed is None:
            return
        tree, lines = parsed
        hits, matched = _resolve_in_module(tree, rest)
        if not hits:
            if partial is None or matched > partial["matched_segments"]:
                partial = {
                    "file": rel(path),
                    "module": module,
                    "matched_segments": matched,
                    "unresolved": ".".join(rest[matched:]),
                }
            return
        for node, kind in hits:
            start, end, text = _excerpt(lines, node)
            key = (path, start)
            if key in seen or len(candidates) >= MAX_CANDIDATES:
                continue
            seen.add(key)
            candidates.append(
                {
                    "file": rel(path),
                    "line": start,
                    "end_line": end,
                    "location": f"{rel(path)}:{start}",
                    "kind": kind,
                    "module": module,
                    "qualname": ".".join(rest),
                    "excerpt": text,
                    **(extra or {}),
                }
            )

    main_scan: _MainScan | None = None
    if parts[0] == "__main__":
        main_scan = _main_candidates(root, parts[1] if len(parts) > 1 else None)
        for cand in main_scan.candidates:
            consider(cand.file, "__main__", parts[1:], {"main_evidence": cand.evidence})
    else:
        roots = _search_roots(root, parts[0])
        # Longest module prefix first: app.cache.Session -> module app.cache, name Session.
        for split in range(len(parts), 0, -1):
            module_parts, rest = parts[:split], parts[split:]
            if LOCALS in module_parts:
                continue
            for base in roots:
                for path in _module_files(root, base, module_parts):
                    consider(path, ".".join(module_parts), rest)
            if candidates:
                break

    result: dict[str, Any] = {
        "qualname": qualname,
        "repo_path": str(root),
        "candidates": candidates,
        "searched_files": searched,
    }
    if main_scan is not None:
        result["heuristic"] = True
        result["main_resolution"] = {
            "note": (
                "__main__ is whichever script was started, so it cannot be found by module "
                "path. Candidates are files that bind the name at top level, ranked by "
                "main_evidence: a file named __main__.py, a main guard, a #! line, a "
                "definition rather than an import, then shallower paths. Check the "
                "process's command line (list_python_processes) for the script that ran."
            ),
            "files_scanned": main_scan.scanned,
            "scan_limit_reached": main_scan.limit_reached,
            "files_matched": len(main_scan.candidates),
        }
    if not candidates:
        if parts[0] == "builtins":
            result["note"] = "builtins types are implemented in C and have no source in the repo."
        elif partial is not None:
            result["partial_match"] = partial
            result["note"] = (
                "The module was found but not the full name. The object may be created "
                "dynamically, or the name may come from a different module."
            )
        else:
            result["note"] = (
                "No module file for this name inside the repository. It may be a "
                "third-party or standard-library module."
            )
    return result
