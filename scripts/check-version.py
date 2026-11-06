#!/usr/bin/env python3
"""Check that the release tag and the package versions agree.

The source of truth is `[workspace.package] version` in the root Cargo.toml.
This script checks that:

  - crates/heapspy/Cargo.toml inherits that version (or states the same one),
  - the tag, if given, is "v" followed by that version,
  - python/heapspy-mcp, if it exists, has the same version in its
    pyproject.toml and, if defined, in heapspy_mcp.__version__.

Usage:
    scripts/check-version.py [TAG] [--root DIR]

TAG may be "v0.1.0" or "refs/tags/v0.1.0". Without TAG, only the versions
inside the repository are compared. Exits 1 with a message on a mismatch.
Needs Python 3.11 or later (for tomllib).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    sys.exit("check-version: needs Python 3.11 or later (tomllib)")


def load_toml(path: Path) -> dict:
    with path.open("rb") as f:
        return tomllib.load(f)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tag", nargs="?", help='release tag, e.g. "v0.1.0"')
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (default: parent of scripts/)",
    )
    args = parser.parse_args()
    root: Path = args.root
    errors: list[str] = []

    workspace = load_toml(root / "Cargo.toml")
    try:
        version = workspace["workspace"]["package"]["version"]
    except KeyError:
        print("check-version: Cargo.toml has no [workspace.package] version", file=sys.stderr)
        return 1
    print(f"Cargo.toml [workspace.package] version: {version}")

    crate_toml = root / "crates" / "heapspy" / "Cargo.toml"
    crate_version = load_toml(crate_toml)["package"].get("version")
    if crate_version != {"workspace": True} and crate_version != version:
        errors.append(
            f"{crate_toml.relative_to(root)}: version is {crate_version!r}; "
            f"use `version.workspace = true` or {version!r}"
        )

    if args.tag is not None:
        tag = args.tag.removeprefix("refs/tags/")
        expected = f"v{version}"
        print(f"tag: {tag}")
        if tag != expected:
            errors.append(
                f"tag {tag!r} does not match Cargo.toml version {version!r} "
                f"(expected tag {expected!r})"
            )

    mcp_dir = root / "python" / "heapspy-mcp"
    if mcp_dir.is_dir():
        mcp_toml = mcp_dir / "pyproject.toml"
        mcp_version = load_toml(mcp_toml).get("project", {}).get("version")
        print(f"{mcp_toml.relative_to(root)} version: {mcp_version}")
        if mcp_version != version:
            errors.append(
                f"{mcp_toml.relative_to(root)}: version is {mcp_version!r}, "
                f"Cargo.toml has {version!r}"
            )
        init_py = mcp_dir / "src" / "heapspy_mcp" / "__init__.py"
        if init_py.is_file():
            m = re.search(
                r'^__version__\s*=\s*["\']([^"\']+)["\']', init_py.read_text(), re.MULTILINE
            )
            if m and m.group(1) != version:
                errors.append(
                    f"{init_py.relative_to(root)}: __version__ is {m.group(1)!r}, "
                    f"Cargo.toml has {version!r}"
                )
    else:
        print("python/heapspy-mcp not present, skipping its version check")

    if errors:
        print("\nVersion check failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print("\nSee docs/releasing.md for how to bump versions.", file=sys.stderr)
        return 1
    print("Version check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
