"""Resolve ``module.qualname`` names from heapspy output to ``file:line``.

Read-only and confined to one repository directory: every file that is
opened must resolve (after following symlinks) to a path inside the
repository root. That includes files named by a snapshot's recorded
locations: a recorded path outside the repository is never opened.
"""

from __future__ import annotations

import ast
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Any

MAX_CANDIDATES = 10
MAX_SUFFIX_SCAN = 20000
MAX_RECORDED = 5
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


def check_arguments(qualname: str, repo_path: str) -> None:
    """Raise :class:`SourceMapError` for an unusable qualname or repository,
    before anything else (such as a heapspy call) is run with them."""
    _check_qualname(qualname)
    _check_repo(repo_path)


# -- exact resolution from a snapshot's recorded location --------------------------


def _recorded_path(recorded: str) -> PurePath:
    """The recorded filename as a path of the platform that wrote it."""
    if re.match(r"^[A-Za-z]:[\\/]", recorded) or ("\\" in recorded and "/" not in recorded):
        return PureWindowsPath(recorded)
    return PurePosixPath(recorded)


def _suffix_match(root: Path, parts: tuple[str, ...]) -> tuple[Path | None, int]:
    """The repository file whose path ends with the most trailing components of
    ``parts`` (the file name at least), if exactly one has that many.

    Returns ``(file, 0)`` on a unique match, else ``(None, n)`` with ``n`` the
    number of files tied for the best match. Only names are compared; no file
    is opened. At most ``MAX_SUFFIX_SCAN`` files are looked at.
    """
    if not parts:
        return None, 0
    name = parts[-1]
    best: list[Path] = []
    best_len = 0
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not d.startswith("."))
        seen += len(filenames)
        if name in filenames:
            rel = (Path(dirpath) / name).relative_to(root).parts
            n = 0
            while n < min(len(rel), len(parts)) and rel[-1 - n] == parts[-1 - n]:
                n += 1
            if n > best_len:
                best, best_len = [Path(dirpath) / name], n
            elif n == best_len:
                best.append(Path(dirpath) / name)
        if seen >= MAX_SUFFIX_SCAN:
            break
    if len(best) != 1:
        return None, len(best)
    return _inside(root, best[0]), 0


def _find_recorded(root: Path, recorded: str) -> tuple[Path | None, str]:
    """Map a recorded filename to a file inside ``root``.

    Tried in order: the path itself when it is absolute and inside the
    repository, the path relative to the repository root, then a unique
    suffix match. An absolute path outside the repository is never opened.
    Returns the file and how it was found, or ``None`` and the reason.
    """
    p = _recorded_path(recorded)
    if p.is_absolute():
        # Only a path of this platform's kind can name a file here.
        if isinstance(p, PureWindowsPath) == (os.name == "nt"):
            real = _inside(root, Path(recorded))
            if real is not None:
                return real, "exact_path"
    elif ".." not in p.parts:
        real = _inside(root, root.joinpath(*p.parts))
        if real is not None:
            return real, "repo_relative"
    parts = tuple(x for x in p.parts if x not in (p.anchor, ".", ".."))
    real, tied = _suffix_match(root, parts)
    if real is not None:
        return real, "suffix"
    return None, "ambiguous_suffix" if tied > 1 else "not_in_repo"


def _raw_excerpt(path: Path, line: int) -> tuple[int, int, str] | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not 1 <= line <= len(lines):
        return None
    end = min(len(lines), line + MAX_EXCERPT_LINES - 1)
    body = []
    for no in range(line, end + 1):
        text = lines[no - 1]
        if len(text) > MAX_LINE:
            text = text[: MAX_LINE - 3] + "..."
        body.append(f"{no:>5}  {text}")
    return line, end, "\n".join(body)


def _node_start(node: ast.AST) -> int:
    decorators = getattr(node, "decorator_list", None) or []
    return min([getattr(node, "lineno", 1), *(d.lineno for d in decorators)])


def _clip(text: Any, limit: int = 400) -> Any:
    if not isinstance(text, str) or len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _recorded(loc: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": _clip(loc.get("file")),
        "line": loc.get("line") if isinstance(loc.get("line"), int) else None,
        "exact": bool(loc.get("exact")),
        "via": _clip(loc.get("via"), 40),
    }


def _exact_candidates(
    root: Path, matches: list[Any]
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    """Candidates for the snapshot's recorded locations that are in the repository,
    the files read, and the recorded locations that could not be used."""
    candidates: list[dict[str, Any]] = []
    searched: list[str] = []
    unresolved: list[dict[str, Any]] = []
    seen: set[tuple[Path, int]] = set()
    for m in matches:
        if not isinstance(m, dict):
            continue
        loc = m.get("source_loc")
        if not isinstance(loc, dict) or not isinstance(loc.get("file"), str) or not loc["file"]:
            continue
        rec = _recorded(loc)
        if loc["file"].startswith("<"):
            unresolved.append({**rec, "reason": "generated_filename"})
            continue
        path, how = _find_recorded(root, loc["file"])
        if path is None:
            unresolved.append({**rec, "reason": how})
            continue
        rel = path.relative_to(root).as_posix()
        if len(searched) < MAX_SEARCHED and rel not in searched:
            searched.append(rel)
        rest = [p for p in str(m.get("qualname") or "").split(".") if p]
        line = rec["line"]
        node, kind = None, None
        lines: list[str] = []
        parsed = _parse(path)
        if parsed is not None:
            tree, lines = parsed
            hits, _ = _resolve_in_module(tree, rest)
            for hit, hit_kind in hits:
                start = 1 if isinstance(hit, ast.Module) else _node_start(hit)
                end = getattr(hit, "end_lineno", None) or start
                if line is None or start <= line <= end:
                    node, kind = hit, hit_kind
                    break
        cand: dict[str, Any] = {
            "file": rel,
            "kind": kind or m.get("kind"),
            "module": m.get("module"),
            "qualname": m.get("qualname"),
            "via": "snapshot",
            "matched_by": how,
            "recorded": rec,
        }
        if node is not None:
            start, end, text = _excerpt(lines, node)
        else:
            # The file does not define the name around the recorded line: it
            # may have changed since the snapshot. Show the recorded line.
            raw = _raw_excerpt(path, line) if line is not None else None
            start, end, text = raw if raw is not None else (line or 1, line or 1, "")
            cand["source_mismatch"] = True
        if (path, start) in seen or len(candidates) >= MAX_CANDIDATES:
            continue
        seen.add((path, start))
        cand.update(line=start, end_line=end, location=f"{rel}:{start}", excerpt=text)
        candidates.append(cand)
    return candidates, searched, unresolved


def map_to_source(
    qualname: str, repo_path: str, located: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Resolve ``qualname`` inside ``repo_path``.

    ``located`` is what the snapshot says about the name: ``{"matches": [...]}``
    from ``heapspy query --locate``, with an empty list when the snapshot has
    no object of that name. When a recorded location maps to a file in the
    repository, the result is exact (``heuristic: false``, ``via:
    "snapshot"``). Otherwise, and when ``located`` is ``None`` (no snapshot
    given, or a heapspy without ``--locate``), the name is resolved from the
    repository's files as before.
    """
    parts = _check_qualname(qualname)
    root = _check_repo(repo_path)
    lookup: dict[str, Any] | None = None
    if located is not None:
        matches = [m for m in located.get("matches") or [] if isinstance(m, dict)]
        candidates, searched, unresolved = _exact_candidates(root, matches)
        if candidates:
            return {
                "qualname": qualname,
                "repo_path": str(root),
                "candidates": candidates,
                "searched_files": searched,
                "heuristic": False,
                "via": "snapshot",
            }
        if not matches:
            lookup = {"status": "not_in_snapshot"}
        elif unresolved:
            lookup = {"status": "not_in_repo", "recorded": unresolved[:MAX_RECORDED]}
        else:
            lookup = {
                "status": "no_location",
                "reasons": sorted(
                    {str(m.get("source_loc_reason")) for m in matches if m.get("source_loc_reason")}
                ),
            }
        lookup["note"] = (
            "The snapshot gave no location inside the repository for this name, so it "
            "was resolved from the repository's files."
        )
    result = _heuristic(qualname, parts, root)
    if lookup is not None:
        result["snapshot_lookup"] = lookup
    return result


def _heuristic(qualname: str, parts: list[str], root: Path) -> dict[str, Any]:
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
