"""Resolve ``module.qualname`` names from heapspy output to ``file:line``.

Read-only and confined to one repository directory: every file that is
opened must resolve (after following symlinks) to a path inside the
repository root.
"""

from __future__ import annotations

import ast
import os
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


def _main_files(root: Path) -> Iterator[Path]:
    """Files that may have run as ``__main__``: ``__main__.py`` and scripts with a main guard."""
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not d.startswith("."))
        for fname in sorted(filenames):
            if not fname.endswith(".py"):
                continue
            scanned += 1
            if scanned > MAX_MAIN_SCAN:
                return
            path = Path(dirpath) / fname
            real = _inside(root, path)
            if real is None:
                continue
            if fname == "__main__.py":
                yield real
                continue
            try:
                if real.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = real.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "__name__" in text and "__main__" in text:
                yield real


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

    def consider(path: Path, module: str, rest: list[str]) -> None:
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
                }
            )

    if parts[0] == "__main__":
        for path in _main_files(root):
            consider(path, "__main__", parts[1:])
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
