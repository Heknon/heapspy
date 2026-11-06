"""Command-line entry point: ``heapspy-mcp``."""

from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .config import (
    DEFAULT_CAPTURE_TIMEOUT,
    DEFAULT_TIMEOUT,
    ENV_ALLOW,
    ENV_ALLOW_CONTENTS,
    ENV_BIN,
    ENV_CAPTURE_TIMEOUT,
    ENV_MAX_RSS,
    ENV_SNAPSHOT_DIR,
    ENV_TIMEOUT,
    Config,
    ConfigError,
    default_snapshot_dir,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="heapspy-mcp",
        description="MCP server exposing heapspy heap snapshots and analysis to coding agents.",
    )
    p.add_argument("--version", action="version", version=f"heapspy-mcp {__version__}")
    p.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    p.add_argument("--host", default="127.0.0.1", help="streamable-http bind address")
    p.add_argument("--port", type=int, default=8000, help="streamable-http port")
    p.add_argument(
        "--heapspy-bin",
        metavar="PATH",
        help=f"heapspy executable (else ${ENV_BIN}, else 'heapspy' on PATH)",
    )
    p.add_argument(
        "--allow",
        action="append",
        metavar="PATTERN",
        help=(
            "allow live capture of processes matching PATTERN: a glob on the process name, "
            "executable name or command line, or pid:N. Repeatable; comma-separated lists "
            f"accepted. Merged with ${ENV_ALLOW}. Default: none (live capture disabled)."
        ),
    )
    p.add_argument(
        "--allow-contents",
        action="store_true",
        help=f"permit capture_contents=true (also ${ENV_ALLOW_CONTENTS}=1)",
    )
    p.add_argument(
        "--max-rss",
        metavar="SIZE",
        help=f"refuse live capture above this RSS, e.g. 8G (also ${ENV_MAX_RSS}; default 8G)",
    )
    p.add_argument(
        "--snapshot-dir",
        metavar="DIR",
        help=f"where snapshots are written (also ${ENV_SNAPSHOT_DIR}; "
        f"default {default_snapshot_dir()})",
    )
    p.add_argument(
        "--timeout",
        type=float,
        metavar="SECONDS",
        help=f"timeout for analysis commands (also ${ENV_TIMEOUT}; default {DEFAULT_TIMEOUT:g})",
    )
    p.add_argument(
        "--capture-timeout",
        type=float,
        metavar="SECONDS",
        help=f"timeout for heapspy dump (also ${ENV_CAPTURE_TIMEOUT}; "
        f"default {DEFAULT_CAPTURE_TIMEOUT:g})",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("heapspy-mcp: %(levelname)s %(message)s"))
    log = logging.getLogger("heapspy_mcp")
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False

    try:
        config = Config.from_sources(
            heapspy_bin=args.heapspy_bin,
            snapshot_dir=args.snapshot_dir,
            allow=args.allow,
            allow_contents=args.allow_contents,
            max_rss=args.max_rss,
            timeout=args.timeout,
            capture_timeout=args.capture_timeout,
        )
    except ConfigError as e:
        print(f"heapspy-mcp: error: {e}", file=sys.stderr)
        return 2

    if config.heapspy_bin is None:
        log.warning(
            "heapspy executable not found (no --heapspy-bin, no $%s, not on PATH); "
            "analysis and capture tools will return binary_not_found",
            ENV_BIN,
        )
    log.info(
        "heapspy=%s snapshot_dir=%s allow=%s allow_contents=%s max_rss=%d",
        config.heapspy_bin,
        config.snapshot_dir,
        config.allow or "(none: live capture disabled)",
        config.allow_contents,
        config.max_rss_bytes,
    )

    from .server import build_server

    server = build_server(config)
    if args.transport == "stdio":
        server.run("stdio")
    else:
        server.run("streamable-http", host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
