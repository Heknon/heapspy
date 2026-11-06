# heapspy-mcp

An MCP (Model Context Protocol) server that gives coding agents access to
[heapspy](../../README.md). It runs the `heapspy` binary, parses its `--json`
output (schema version 1, see [`docs/json-schema.md`](../../docs/json-schema.md))
and returns short, ranked summaries. The raw object graph is never sent to the
model.

The intended loop for an agent:

1. `list_python_processes` to find the PID.
2. `capture_snapshot` (after the user agrees) to get a snapshot handle.
3. `heap_summary` to see the top retainers.
4. Pick a suspect, then `retaining_path` to see the chain of references keeping it alive.
5. `map_to_source` to turn a name from that path into `file:line`.
6. Read the code and find where the holder grows without being cleared.

heapspy shows what is retained now, not where it was allocated. Memory held by
C extensions, and leaks made only of untracked objects (bare ints, short
strings), are not visible in the object graph. `heap_summary` reports how much
of RSS falls outside the graph.

## Install

Requires Python 3.10 or later and the `heapspy` binary.

From this repository:

```sh
cd python/heapspy-mcp
uv sync                # creates .venv with heapspy-mcp and its dependencies
uv run heapspy-mcp --help
```

Once published, `pip install heapspy-mcp` (and `pip install heapspy` for the
binary).

The server is built on the official `mcp` SDK, version 2 (`MCPServer`, which
replaced `FastMCP` in that release).

## Running

```sh
heapspy-mcp                                   # stdio (default)
heapspy-mcp --transport streamable-http --host 127.0.0.1 --port 8000
```

The HTTP endpoint is served at `/mcp`. It has no authentication; keep it on
localhost.

### Configuration

Flags take precedence over environment variables.

| Flag | Environment variable | Default | Meaning |
|---|---|---|---|
| `--heapspy-bin PATH` | `HEAPSPY_BIN` | `heapspy` on `PATH` | heapspy executable. A configured path that is not executable stops the server at startup. If nothing is configured and `heapspy` is not on `PATH`, the server starts and the analysis tools return `binary_not_found`. |
| `--allow PATTERN` | `HEAPSPY_MCP_ALLOW` | empty | Processes that `capture_snapshot` may dump. Repeatable; comma-separated lists are accepted; flag and variable entries are merged. Empty means live capture is disabled. |
| `--allow-contents` | `HEAPSPY_MCP_ALLOW_CONTENTS=1` | off | Permit `capture_contents=true`. |
| `--max-rss SIZE` | `HEAPSPY_MCP_MAX_RSS` | `8G` | Refuse live capture of processes with a larger RSS. Binary suffixes: `512M`, `8G`, `8GiB`, or plain bytes. |
| `--snapshot-dir DIR` | `HEAPSPY_MCP_SNAPSHOT_DIR` | `~/.cache/heapspy-mcp/snapshots` on Linux, `~/Library/Caches/heapspy-mcp/snapshots` on macOS, `%LOCALAPPDATA%\heapspy-mcp\Cache\snapshots` on Windows | Where captured snapshots are written. Created with mode 0700. |
| `--timeout SECONDS` | `HEAPSPY_MCP_TIMEOUT` | 120 | Timeout for `analyze`, `query` and `diff`. |
| `--capture-timeout SECONDS` | `HEAPSPY_MCP_CAPTURE_TIMEOUT` | 900 | Timeout for `dump`. |
| `--transport` | | `stdio` | `stdio` or `streamable-http`. |
| `--host`, `--port` | | `127.0.0.1`, `8000` | Bind address for `streamable-http`. |

Allowlist entries:

- `pid:1234` or `1234` matches that PID exactly.
- Anything else is a case-sensitive glob (`fnmatch`) tried against the process
  name, the executable's file name, and the whole command line joined by
  spaces. `gunicorn*`, `python3.12`, and `*manage.py runserver*` are all valid.

## Safety model

`capture_snapshot` is the only tool that touches a process. Taking a live dump
pauses the target and writes a memory image to disk, and it needs ptrace or
debug privileges. It is gated as follows, in this order:

1. `confirm` must be `true`. The tool description tells the agent to ask the
   user before setting it.
2. Exactly one of `pid`, `core_path` or `minidump_path`.
3. `capture_contents=true` is refused unless the server was started with
   `--allow-contents`. By default snapshots hold types, sizes and references,
   but no string or bytes contents, which often hold credentials and user data.
4. For a `pid`: the allowlist must be non-empty and the process must match an
   entry, and its RSS must be at or below `--max-rss`. The server's own PID is
   refused.

Ingesting an existing core file or minidump needs only `confirm`, since no
process is touched.

Every capture is logged to stderr with the handle, target, contents setting and
output path, before and after the dump. A capture that records contents logs an
extra line saying so.

The agent cannot change any of these settings: they are fixed when the server
starts. A refusal says which gate failed and what the user would have to
change.

The other tools only read snapshot files (or, for `list_python_processes`,
process metadata through `psutil` and `/proc/<pid>/maps`). `map_to_source` only
reads files inside the given repository; see below.

Tool output is bounded: every `top`, `limit`, `max_paths` and `max_targets`
argument is capped on the server (50 rows, 10 paths, 10 targets, 200
processes), retaining paths longer than 24 hops are elided in the middle, and
edge and root labels are clipped to 160 characters.

## Client configuration

Claude Code, `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "heapspy": {
      "command": "heapspy-mcp",
      "args": ["--allow", "gunicorn*", "--max-rss", "4G"],
      "env": {
        "HEAPSPY_BIN": "/usr/local/bin/heapspy"
      }
    }
  }
}
```

To run it from a checkout of this repository instead:

```json
{
  "mcpServers": {
    "heapspy": {
      "command": "uv",
      "args": ["run", "--directory", "python/heapspy-mcp", "heapspy-mcp"]
    }
  }
}
```

Leave out `--allow` to analyze existing snapshots and core files only.

## Tools

All tools return a JSON object (MCP structured content). Byte counts are
integers with a `*_human` companion such as `"412.6 MiB"`. Failures are tool
errors whose text is a JSON document:

```json
{"error": {"code": "not_found", "message": "no object at address 0x7f3a2c41b0d8 in app.hpy",
           "exit_status": 1, "hint": "..."}}
```

`code` is one of the heapspy error codes (`unimplemented`, `invalid_argument`,
`not_found`, `invalid_snapshot`, `io`, `permission_denied`, `internal`), one
added by the wrapper (`binary_not_found`, `timeout`, `usage_error` for exit
status 2, `bad_output` for output that is not JSON, `schema_mismatch`,
`unexpected_kind`, `cli_failed` for a failure with no error document), or
`capture_refused` with a `reason`.

A `snapshot` argument is a handle returned by `capture_snapshot`
(`hs-1a2b3c4d`, a file in the snapshot directory) or a path to a `.hpy` file.

### `list_python_processes(name_filter?, limit=50)`

Python processes sorted by RSS: `pid`, `name`, `exe`, `cmdline` (truncated to
200 characters), `rss_bytes`, `python_version`, `version_source`
(`exe_name` or `libpython_mapping`), `username`, `is_this_server`, and
`capture_allowed` (whether the allowlist matches). The version comes from the
executable name (`python3.12`), or on Linux from a mapped
`libpython3.12.so`, and on Windows from a mapped `python312.dll`.

### `capture_snapshot(confirm, pid? | core_path? | minidump_path?, capture_contents=false, max_str?)`

Runs `heapspy dump` into the snapshot directory. Returns `snapshot` (the
handle), `path`, `target` (pid, name, RSS, the allowlist entry that matched),
`contents_captured` and `stats` (objects, edges, roots, file size, truncated).
`max_str` (1 to 4096) only applies with `capture_contents`.

### `heap_summary(snapshot, top=10)`

Runs `heapspy analyze --json --top N`. Returns `top_retainers` (rank, address,
type, retained bytes and percentage, and a `path` with the rendered root path,
`root_kind`, `direct_holder` and `source_hints`), `type_histogram`, `totals`,
`memory` (RSS, graph bytes, bytes outside the graph) and `notes`.

`source_hints` are `module.qualname` names derived from the path that
`map_to_source` can resolve: `sys.modules['app.cache'].__dict__['CACHE']`
gives `app.cache.CACHE`, and an `app.session.Session` instance followed by
`.payload` gives `app.session.Session.payload`.

### `retaining_path(snapshot, address? | type?, max_paths=3, max_targets=3)`

With `address`, runs `heapspy query --retaining-path`. With `type`, runs
`heapspy query --type` and then traces the `max_targets` largest instances.
Each target has `reachable` and up to `max_paths` paths, each with `rendered`,
`hops` (root first), `direct_holder` and `source_hints`.

### `type_detail(snapshot, type, top=10)`

Runs `heapspy query --type`. Returns `matched_types`, `instances`, shallow and
retained totals, `top_instances` with their paths, `holders` (referrer type and
generalised edge, with a count) and `notes`.

### `diff_snapshots(before, after, top=10)`

Runs `heapspy diff`. Returns `identity_approximate` (always true) and
`identity_note`, `totals`, `by_type` and `by_site` growth rows, and `notes`.
Objects are matched by type and retaining site, not by address.

### `map_to_source(qualname, repo_path)`

Resolves a dotted name to candidates with `file`, `line`, `end_line`,
`location` (`file:line`), `kind` (`module`, `class`, `function`, `assignment`,
`instance_attribute`, `import`, `type_alias`) and an `excerpt` of at most 8
lines.

- The longest module prefix that exists as a file wins: `app.cache.Session`
  looks for `app/cache/Session.py`, then `app/cache.py` with the name
  `Session`.
- Modules are looked for in the repository root, in `src/`, `lib/` and
  `python/`, and in project directories up to two levels down that contain the
  top-level package (`services/billing/[src/]billing/`).
- `__main__.X` is looked up in every `__main__.py` and in every script with a
  `__name__ == "__main__"` guard.
- Names are found as classes, functions, methods, nested classes,
  module-level and class-level assignments (including those inside `if` and
  `try` blocks), imports, and `self.X = ...` assignments in methods.
  `<locals>` segments (`app.make.<locals>.Handler`) are followed into
  function bodies.
- When nothing matches, the result has `partial_match` (the file and the part
  of the name that did not resolve) or a `note`.

The qualname must be dotted Python identifiers; paths are rejected.
`repo_path` must be an existing directory and may not contain `..`. Every file
is opened only if its real path, after following symlinks, is inside the
repository.

### Resource and prompt

- Resource `heapspy://workflow`: the workflow and its limits as text.
- Prompt `investigate_memory(target?)`: the same text, as a starting prompt.

## Development

```sh
cd python/heapspy-mcp
uv run pytest
uv run ruff check
uv run ruff format --check
```

The tests use `tests/fake_heapspy.py` as the `heapspy` binary. It prints the
documents in `docs/examples/` adjusted to its arguments, and can simulate
error documents, a wrong schema version, timeouts, output that is not JSON,
usage errors and oversized reports.
