"""Managed snapshot directory and snapshot handles.

A handle is the file stem of a snapshot in the managed directory
(``hs-1a2b3c4d`` for ``<dir>/hs-1a2b3c4d.hpy``), so handles survive server
restarts without an index file.
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

HANDLE_RE = re.compile(r"^hs-[0-9a-f]{8}$")


class SnapshotRefError(Exception):
    """A snapshot argument does not name a usable snapshot."""


class SnapshotStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def ensure_dir(self) -> Path:
        # Snapshots can hold memory contents: keep the directory private.
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        return self.directory

    def new_handle(self) -> tuple[str, Path]:
        directory = self.ensure_dir()
        while True:
            handle = f"hs-{secrets.token_hex(4)}"
            path = directory / f"{handle}.hpy"
            if not path.exists():
                return handle, path

    def handle_for(self, path: Path) -> str | None:
        """The handle of ``path`` if it lives in the managed directory."""
        try:
            if path.resolve().parent == self.directory.resolve() and HANDLE_RE.match(path.stem):
                return path.stem
        except OSError:
            return None
        return None

    def resolve(self, ref: str) -> Path:
        """Turn a handle or a path to a ``.hpy`` file into an absolute path."""
        ref = ref.strip()
        if not ref:
            raise SnapshotRefError("empty snapshot reference")
        if HANDLE_RE.match(ref):
            path = self.directory / f"{ref}.hpy"
            if not path.is_file():
                raise SnapshotRefError(
                    f"unknown snapshot handle {ref!r} (no {ref}.hpy in {self.directory})"
                )
            return path.resolve()
        path = Path(ref).expanduser()
        if path.suffix != ".hpy":
            raise SnapshotRefError(
                f"{ref!r} is neither a snapshot handle (hs-xxxxxxxx) nor a path to a .hpy file"
            )
        if not path.is_file():
            raise SnapshotRefError(f"snapshot file not found: {ref}")
        # Absolute, so the argument can never start with '-' on the heapspy command line.
        return Path(os.path.abspath(path))


def resolve_profile(ref: str) -> Path:
    """Turn a path to a ``.hpya`` allocation profile into an absolute path."""
    ref = ref.strip()
    if not ref:
        raise SnapshotRefError("empty allocation profile path")
    path = Path(ref).expanduser()
    if path.suffix != ".hpya":
        raise SnapshotRefError(f"{ref!r} is not a path to a .hpya allocation profile")
    if not path.is_file():
        raise SnapshotRefError(f"allocation profile not found: {ref}")
    # Absolute, so the argument can never start with '-' on the heapspy command line.
    return Path(os.path.abspath(path))
