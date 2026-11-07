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

heapspy shows what is retained now. Where it was allocated is known only when
an allocation profile (`.hpya`) was recorded from the process before the
snapshot; see [Where was this memory allocated?](#where-was-this-memory-allocated).
Memory held by C extensions, and leaks made only of untracked objects (bare
ints, short strings), are not visible in the object graph. `heap_summary`
reports how much of RSS falls outside the graph.

The server also has process diagnostics for any process, not only Python: find
or scan processes by measured metrics, then measure one process's CPU,
scheduler behaviour and environment (cgroup, host) over a window, sample its
threads for memory stalls (page-fault I/O, reclaim, `memory.high` throttling),
and weigh competing explanations for its CPU use, slowness or stalls. See
[Process diagnostics](#process-diagnostics).

The same server also has CPU tools backed by [py-spy](https://github.com/benfred/py-spy):
where a process spends its time, and whether its threads are running, blocked
in a syscall, waiting for the GIL, or idle. See [CPU tools](#cpu-tools-py-spy).

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

The CPU tools need py-spy (0.4 or later). It is an optional extra:

```sh
uv sync --extra pyspy                 # from this repository
pip install 'heapspy-mcp[pyspy]'      # once published
```

Without py-spy the server starts as usual and the CPU tools return
`py_spy_not_found`.

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
| `--max-str N` | `HEAPSPY_MCP_MAX_STR` | 1024 | Per-string cap, in characters, used when a `capture_contents=true` call gives no `max_str` (1 to 1048576). |
| `--max-rss SIZE` | `HEAPSPY_MCP_MAX_RSS` | `8G` | Refuse live capture of processes with a larger RSS. Binary suffixes: `512M`, `8G`, `8GiB`, or plain bytes. |
| `--snapshot-dir DIR` | `HEAPSPY_MCP_SNAPSHOT_DIR` | `~/.cache/heapspy-mcp/snapshots` on Linux, `~/Library/Caches/heapspy-mcp/snapshots` on macOS, `%LOCALAPPDATA%\heapspy-mcp\Cache\snapshots` on Windows | Where captured snapshots are written. Created with mode 0700. |
| `--timeout SECONDS` | `HEAPSPY_MCP_TIMEOUT` | 120 | Timeout for `analyze`, `query` and `diff`. |
| `--capture-timeout SECONDS` | `HEAPSPY_MCP_CAPTURE_TIMEOUT` | 900 | Timeout for `dump`. |
| `--max-window SECONDS` | `HEAPSPY_MCP_MAX_WINDOW` | 10 | Cap on every measurement window of the process diagnostics. |
| `--no-host-context` | `HEAPSPY_MCP_NO_HOST_CONTEXT=1` | off | Leave host-wide load, steal and PSI out of the process tools' `environment` block. |
| `--proc-root DIR` | `HEAPSPY_MCP_PROC_ROOT` | `/proc` | procfs to read. |
| `--cgroup-root DIR` | `HEAPSPY_MCP_CGROUP_ROOT` | from `/proc/self/mountinfo` | A cgroup v2 mount to read instead, for example the host's cgroupfs mounted into a container. |
| `--max-stall-rate HZ` | `HEAPSPY_MCP_MAX_STALL_RATE` | 100 | Cap on the per-thread sampling rate of `watch_process_stalls`, and on the in-window sampling rates of `process_cpu`, `cpu_colocation` and `group_cpu` (1 to 1000). |
| `--max-cmdline-chars N` | `HEAPSPY_MCP_MAX_CMDLINE_CHARS` | 4096 | Cap on the `cmdline_max_chars` a call may ask for (16 to 131072). |
| `--allow-load-probes` | `HEAPSPY_MCP_ALLOW_LOAD_PROBES=1` | off | Enable `cache_sensitivity_probe`, which runs a benchmark that adds CPU load. |

| `--py-spy-bin PATH` | `PY_SPY_BIN` | `py-spy` on `PATH`, else next to the server's Python | py-spy executable for the CPU tools. A configured path that is not executable stops the server at startup. If none is found the CPU tools return `py_spy_not_found`. |
| `--cpu-max-duration SECONDS` | `HEAPSPY_MCP_CPU_MAX_DURATION` | 30 | Longest profile a CPU tool records (1 to 3600). Longer `duration_s` values are clamped, with a note in the result. |
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
3. Contents are the agent's call. Without `capture_contents`, snapshots hold
   types, sizes and references only. With it, they also hold the text of
   `str` and `bytes` objects (cut at `max_str`) and real dict keys, which can
   include credentials and user data. Every such capture is logged.
4. For a `pid`: the allowlist must be non-empty and the process must match an
   entry, and its RSS must be at or below `--max-rss`. The server's own PID is
   refused.

Ingesting an existing core file or minidump needs only `confirm`, since no
process is touched.

Every capture is logged to stderr with the handle, target, contents setting and
output path, before and after the dump. A capture that records contents logs an
extra line saying so.

The CPU tools attach to live processes too; their gates are described in
[Safety of the CPU tools](#safety-of-the-cpu-tools).

The agent cannot change any of these settings: they are fixed when the server
starts. A refusal says which gate failed and what the user would have to
change.

The other tools only read snapshot files (or, for `list_python_processes`,
process metadata through `psutil` and `/proc/<pid>/maps`). `map_to_source` only
reads files inside the given repository; see below. The process diagnostics
are read-only too; their access rules are in
[Safety and access](#safety-and-access).

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

`code` is one of:

- a heapspy error code: `unimplemented`, `invalid_argument`, `not_found`,
  `invalid_snapshot`, `invalid_allocations`, `io`, `permission_denied`,
  `internal`, and for dumps `no_such_process`, `not_python`,
  `unsupported_python`, `invalid_image`, `truncated_image` and `unsupported`.
  A code this server does not know is reported as `internal`, with heapspy's
  code in `cli_code`;
- one added by the wrapper: `binary_not_found`, `timeout`, `usage_error` for
  exit status 2, `bad_output` for output that is not JSON, `schema_mismatch`,
  `unexpected_kind`, `cli_failed` for a failure with no error document, and
  `allocations_unsupported` for a heapspy that has no `--allocations`, or
  takes it but does not join (note `allocations_not_joined`);
- `capture_refused`, with a `reason`.

Most codes come with a `hint`. For captures: `permission_denied` names the
privilege (`CAP_SYS_PTRACE` or `kernel.yama.ptrace_scope` on Linux,
`SeDebugPrivilege` on Windows), `not_python` suggests checking that the PID is
the Python process and not a wrapper around it, `unsupported_python` lists the
versions heapspy reads (3.12 to 3.14 release builds), and `invalid_image` and
`truncated_image` describe what a core or minidump must contain.

A `snapshot` argument is a handle returned by `capture_snapshot`
(`hs-1a2b3c4d`, a file in the snapshot directory) or a path to a `.hpy` file.

### `list_python_processes(name_filter?, limit=50, measure_s=0)`

Python processes sorted by RSS: `pid`, `name`, `exe`, `cmdline` (redacted, see
[Command-line redaction](#command-line-redaction), and truncated to 200
characters), `rss_bytes`, `python_version`, `version_source`
(`exe_name` or `libpython_mapping`), `username`, `is_this_server`, and
`capture_allowed` (whether the allowlist matches). The version comes from the
executable name (`python3.12`), or on Linux from a mapped
`libpython3.12.so`, and on Windows from a mapped `python312.dll`.

On Linux each row also has `threads` and `threads_by_state`
(`running_or_runnable`, `sleeping`, `disk_wait`, `other`, from
`/proc/<pid>/task/*/stat`, at most 256 threads per process). With
`measure_s` above 0 (capped at 2), `cpu_percent_on_cpu` is measured over one
shared window for all listed processes (100 = one core busy) and
`cpu_percent_window_s` gives the window. The default is 0 so the listing stays
instant; then `cpu_percent_on_cpu` is `null` and
`cpu_percent_unavailable_reason` says why.

### `capture_snapshot(confirm, pid? | core_path? | minidump_path?, capture_contents=false, max_str?)`

Runs `heapspy dump --json` into the snapshot directory. Returns `snapshot`
(the handle), `path`, `target` (pid, name, RSS, the allowlist entry that
matched), `python_version`, `contents_captured`, `stats` (objects, edges,
types, roots, file size, `truncated`, `missing_bytes` of the image,
`read_errors`, and `pause_ms`, how long a live target was stopped; `null` for
cores and minidumps), the dump's `notes`, and `report` (`json`, or
`stderr_line` for an older heapspy, see
[Compatibility with older heapspy binaries](#compatibility-with-older-heapspy-binaries)).
A truncated snapshot also gets a `warning`: its numbers are lower bounds.
`max_str` (1 to 1048576) only applies with `capture_contents`; without it the
server default (`--max-str`, 1024) is used. The result's `max_str` is the cap
that was applied. An agent that finds the prefixes too short to tell what the
data is can capture again with a larger `max_str`.

heapspy writes into a private staging directory
(`<snapshot dir>/.<handle>.partial/`) that is removed on every path, so a dump
that fails or is killed by the capture timeout leaves nothing behind. On a
failed dump the error has heapspy's code and hint (see above).

### `heap_summary(snapshot, top=10, allocations?)`

Runs `heapspy analyze --json --top N`. Returns `top_retainers` (rank, address,
type, retained bytes and percentage, and a `path` with the rendered root path,
`root_kind`, `direct_holder` and `source_hints`), `type_histogram`, `totals`,
`memory` (RSS, graph bytes, bytes outside the graph) and `notes`.

With `allocations` (a path to a `.hpya` profile), it passes
`--allocations` and adds:

- `allocated_at` on each top retainer: the linked objects and bytes in what it
  retains (`exact_linked_bytes` is the exact part), and at most 3 allocating
  stacks, each with `allocated_in` (`file:line` of the innermost frame), at
  most 6 frames (innermost first), `top_stack_rank` and `source_hints`;
- `allocations`: `recording` (pid, Python version, start, duration,
  mechanisms, sampling parameters, overhead, samples, estimated bytes),
  `coverage`, the first 5 (or `top`) `top_stacks`, the `allocations_*` notes,
  and `caveats`; plus a `warning` when the profile does not match the
  snapshot and nothing was linked.

`source_hints` are `module.qualname` names derived from the path that
`map_to_source` can resolve: `sys.modules['app.cache'].__dict__['CACHE']`
gives `app.cache.CACHE`, and an `app.session.Session` instance followed by
`.payload` gives `app.session.Session.payload`.

Source locations recorded in the snapshot (from a heapspy whose reports have
them; see "Source locations" in `docs/json-schema.md`) are passed through:

- `type_location` and `type_location_reason` on each top retainer and
  histogram row: where the object's type is defined. A location is `location`
  (`file:line`, `file:~line` for a class, which is located near its first
  method; the class statement is at or before that line), `file`, `line`,
  `exact` and `via`. The reason says why it is `null`, e.g.
  `type_not_in_snapshot` for C types such as `builtins.dict`.
- `source_locations` on each path: at most 5 locations, the target's type
  first (`of: "type"`), then functions, classes, code objects and modules on
  the path from the target back to the root (`of: "hop"`, with the hop's
  `type`, `address` and `edge`).

`file` is the path the target process recorded, which can be outside the
repository or on another machine. To read the code, pass the type's name to
`map_to_source` with the snapshot.

With a heapspy without these fields, the summaries are as before: no
`type_location` and no `source_locations` keys.

### `retaining_path(snapshot, address? | type?, max_paths=3, max_targets=3)`

With `address`, runs `heapspy query --retaining-path`. With `type`, runs
`heapspy query --type` and then traces the `max_targets` largest instances.
Each target has `reachable`, `type_location` and up to `max_paths` paths,
each with `rendered`, `hops` (root first; a hop with a recorded location has
`source_loc`), `direct_holder`, `source_hints` and `source_locations`.

### `type_detail(snapshot, type, top=10, allocations?)`

Runs `heapspy query --type`. Returns `matched_types`, `type_locations` (the
`type_location` of each matched type), `instances`, shallow and
retained totals, `top_instances` with their paths (and `source_loc` for an
instance that is itself a function, class or module), `holders` (referrer type
and generalised edge, with a count) and `notes`. With `allocations`, each instance
gets `allocated_at` as in `heap_summary` (`top_stack_rank` is always `null`
here), and the result gets `allocations` with the notes and caveats.

### `diff_snapshots(before, after, top=10)`

Runs `heapspy diff`. Returns `identity_approximate` (always true) and
`identity_note`, `totals`, `by_type` and `by_site` growth rows, and `notes`.
Objects are matched by type and retaining site, not by address.

### `map_to_source(qualname, repo_path, snapshot?)`

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
- `__main__.X` is heuristic, since `__main__` is whichever script was
  started. Every `.py` file in the repository (at most 500, with the skip and
  symlink rules below) that binds `X` at top level is a candidate, also a
  plain script with no main guard. Candidates are ranked: a file named
  `__main__.py`, then one with an `if __name__ == "__main__"` guard, then one
  starting with `#!`, then a definition over an import, then shallower paths.
  Each candidate lists its `main_evidence`, and the result has
  `heuristic: true` and `main_resolution` (a note, files scanned, whether the
  scan limit was reached). Compare with the process's command line from
  `list_python_processes`.
- With `snapshot` (a handle or `.hpy` path), the server first runs
  `heapspy query --locate NAME`. For a type, function or module the snapshot
  has a location for, the recorded file is mapped to a file inside
  `repo_path`: the path itself when it is absolute and inside the repository,
  then the path relative to the repository root, then a unique path-suffix
  match (`/srv/build/app/cache.py` finds `app/cache.py` when exactly one file
  ends that way). The result then has `heuristic: false` and `via:
  "snapshot"`, and each candidate has `matched_by` (`exact_path`,
  `repo_relative`, `suffix`) and `recorded` (the file, line, `exact` and `via`
  from the snapshot). The line is that of the definition found around the
  recorded line, so a class (recorded at its first method) is shown from its
  `class` statement. If the file no longer defines the name there, the
  candidate has `source_mismatch: true` and an excerpt at the recorded line.
  This settles `__main__` names, which are otherwise heuristic.
- The repository rules apply to recorded files as well: a recorded path
  outside `repo_path`, or one that leaves it through a symlink, is never
  opened.
- When the snapshot has no usable location, the name is resolved from the
  repository's files as below, and the result has `snapshot_lookup`:
  `status` (`not_in_snapshot`, `not_in_repo` with the `recorded` locations
  and why each was not used, or `no_location` with the snapshot's
  `reasons`) and a `note`. With a heapspy without `--locate`, the result is
  the same as without `snapshot`.
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

### `allocation_sites(profile, snapshot?, top=10)`

The top allocating Python stacks of a `.hpya` profile, by estimated bytes.
Each stack has `rank`, `estimated_bytes`, `allocated_in`, `frames` (at most 6,
innermost first, each with `function`, `file`, `line`, `location` and
`approximate`), `frames_total` and `source_hints`.

- With `snapshot` (handle or `.hpy` path), it runs
  `heapspy analyze SNAP --allocations PROFILE --json --top N`. Each stack also
  has `samples`, `events`, `linked_bytes` (bytes of objects still alive in the
  snapshot that link to the stack's samples) and `exact_linked_bytes`. The
  result has `recording` (mechanisms, sampling parameters, overhead and so
  on), `coverage`, the `allocations_*` notes, `caveats`, and a `warning` when
  nothing was linked (another pid, another CPython version, or a snapshot
  taken before recording started).
- Without `snapshot`, it runs
  `heapspy flamegraph --allocations PROFILE --folded --min-bytes=0`, the only
  profile-only output heapspy has, and adds up the folded stacks itself. Each
  stack then has `estimated_bytes` and `estimated_pct` only: `samples`,
  `events`, the linked fields, `recording` and `coverage` are not available,
  and frames have `approximate: null`. The result says so in `note`.

`source_hints` lists up to 3 frames from the innermost: `location`, `file`,
`line`, `function` and `qualname_guess`, a `module.qualname` for
`map_to_source` when `co_filename` is a relative path of identifiers
(`app/session.py` and `Session.__init__` give `app.session.Session.__init__`).
For an absolute `co_filename` there is no guess; read the file at the line.

### Where was this memory allocated?

1. Record a profile from the process, then take a snapshot of it (see
   heapspy's `docs/allocation-sampling.md`). The profile must come from the
   same pid and CPython version, and recording must start before the
   snapshot.
2. `allocation_sites(profile, snapshot)`: which stacks allocated the memory
   that is still alive (`linked_bytes`), next to how much each allocated while
   recording (`estimated_bytes`).
3. `heap_summary(snapshot, allocations=profile)`: for each top retainer, the
   stacks that allocated what it retains. `type_detail(..., allocations=...)`
   does the same per instance.
4. Read the file at `allocated_in`, or pass `qualname_guess` to
   `map_to_source`.

Limits, also in each result's `caveats`:

- Allocation data needs a `.hpya` file recorded with `heapspy record` (this
  server has no tool that records). Without a profile, heapspy says what
  keeps an object alive, not where it was allocated.
- Samples are taken only for arena, pool and large-object events during the
  recording window. Objects allocated before recording started, and blocks
  reused from freed memory, have no stack.
- Links through arena and pool samples are approximate: they name the most
  recent growth event that created the memory, not necessarily the call that
  allocated the object. Links through large-object samples are exact
  (`exact_linked_bytes`).
- `estimated_bytes` estimates what was allocated while recording;
  `linked_bytes` is what is still alive in the snapshot.

### Compatibility with older heapspy binaries

- `dump --json`: a heapspy without it rejects the flag while parsing
  arguments, before it touches the target, with clap's
  `unexpected argument '--json'` message. The server then runs the same dump
  without `--json`, parses the `wrote OUT: N objects, ...` line on stderr, and
  remembers this for the rest of its run. `report` is then `stderr_line`, and
  `types`, `read_errors`, `missing_bytes`, `pause_ms`, `python_version` and
  `notes` are `null` or empty. Failures from such a binary have no error
  document and are reported as `cli_failed` with heapspy's stderr. A newer
  heapspy prints `--json` in the `Usage:` line of every dump usage error, so
  that line alone is not taken as a sign of an older binary. The same
  fallback applies when a dump exits 0 without a dump document on stdout.
- `--allocations` and `flamegraph`: a heapspy without them gives
  `allocations_unsupported`. So does one that takes `--allocations` but
  reports the note `allocations_not_joined` (null `allocations` and
  `allocated_at`): it checks the profile, so a corrupt profile is still
  `invalid_allocations`, but it has no allocation data to return.
- Fields added within schema version 1 (such as `allocations` and
  `allocated_at`) are read as `null` when missing.

### Resource and prompt

- Resource `heapspy://workflow`: the workflow and its limits as text.
- Prompt `investigate_memory(target?)`: the same text, as a starting prompt.

## Process diagnostics

Linux only. These tools read `/proc`, cgroup files and, for `hw_counters`,
`perf_event_open(2)`. Every tool is keyed on a process. Host and cgroup
figures appear only as the `environment` of that process: what it is subject
to. The resource `heapspy://process-workflow` and the prompt
`investigate_process_cpu(target?)` describe the loop:

1. Not sure which process? `scan_processes` or `find_processes`.
2. `process_cpu(pid)` for one process and its environment.
3. Process hangs or is intermittently slow? `watch_process_stalls(pid)`, then
   `diagnose_process(pid)`.
4. Many processes on few CPUs, or sibling workers that behave differently?
   `cpu_colocation` for who shares the target's CPUs, and `group_cpu` to
   measure a set of processes at once and compare services.
5. `hw_counters(pid)` for IPC and cache misses, where a PMU exists; without
   one, its `software_fallback` and the opt-in `cache_sensitivity_probe`.
6. `diagnose_process(pid)` to weigh explanations against one window of numbers.
7. `snapshot_process_metrics` or `snapshot_group_metrics` before and after a
   change, then `compare_process_snapshots`; with three or more settings,
   `fit_per_slice_cost`.
8. For Python processes, the heap tools above.

Conventions:

- Field names carry their unit: `_seconds`, `_per_s`, `_pct`, `_ratio`,
  `_bytes`, `_cores`.
- Rates are measured over `window_s` (default 2 s, capped by `--max-window`).
  Every result has a `measurement` block with the window actually measured.
- A signal that cannot be measured is `null`, with the reason in an
  `unavailable` (or `*_unavailable_reason`) entry. It is never reported as 0.
- Lists are capped: 200 rows for `find_processes`, 20 per metric and 20 per
  condition for `scan_processes`, 20 threads per top list, 64 CPUs, 9 cgroup
  levels. Sampling reads at most 1024 threads per process in `process_cpu`,
  64 per process and 20000 in total in a scan, 128 threads in `hw_counters`,
  and 64 threads in `watch_process_stalls` (20 thread rows, 10 intervals per
  process, 3 per thread, 8 frames per example stack). `cpu_colocation` lists at
  most 8192 host tasks, tracks at most 512 that ran, and takes at most 64
  target pids; `group_cpu` measures at most 256 members, 64 threads each, in at
  most 32 groups. The result says when it truncated.
- In-window samplers keep to a budget: 5000 thread samples per second for
  `process_cpu` and `group_cpu`, 20000 task samples per second for
  `cpu_colocation`. With more threads the rate is lowered and the result
  says so (`rate_note`).

### Process search

`find_processes(sort_by?, filters..., limit=20, window_s=1)` lists every process
the server can see, filtered, and sorted by one metric:

| Metric | Source |
|---|---|
| `cpu_percent_on_cpu` | `utime + stime` delta from `/proc/<pid>/stat` (100 = one core) |
| `rss_bytes`, `rss_growth_bytes_per_s` | `/proc/<pid>/stat` RSS pages |
| `threads` | `/proc/<pid>/stat` |
| `voluntary_switches_per_s`, `nonvoluntary_switches_per_s` | `/proc/<pid>/task/*/status`, summed over threads |
| `runqueue_wait_ratio` | `/proc/<pid>/task/*/schedstat`: wait time / on-CPU time |
| `iowait_seconds` | `delayacct_blkio_ticks`, needs delay accounting |
| `open_fds`, `fd_limit_used_pct` | `/proc/<pid>/fd`, soft `Max open files` in `/proc/<pid>/limits` |
| `read_bytes_per_s`, `write_bytes_per_s` | `/proc/<pid>/io` (storage-layer bytes) |
| `uptime_s` | start time against `/proc/uptime` |
| `cfs_throttled_ratio` | `nr_throttled / nr_periods` of the process's cgroup in the window |
| `major_faults_per_s` | `majflt` delta from `/proc/<pid>/stat` |

Filters, all optional: `name` (glob on the name or the executable's file
name), `cmdline` (substring), `cmdline_regex`, `user` (name or uid), `pids`,
`parent_pid` with `include_descendants`, `cgroup` (substring of the path),
`container_id` (prefix), `pod_uid`, `state` (`/proc` state letters, e.g. `D`),
`is_python`, `include_kernel_threads`. `window_s=0` gives an instant listing
with the rate metrics `null`. `cmdline_max_chars` (default 200, capped by
`--max-cmdline-chars`) sets how much of each redacted command line is
returned; the start is kept. `scan_processes` takes it too. Each row has `pid`, `ppid`, `comm`, `exe`,
redacted `cmdline`, `user`, `state`, `cgroup`, `kubernetes` (pod UID, QoS
class, container id) and `metrics`.

`scan_processes(window_s=2, limit_per_metric=5, fd_threshold_pct=80,
major_fault_threshold_per_s=100)` makes one pass over every process and returns
`outliers_by_metric` (the top N for each metric above) and `conditions`, each
with its definition and raw values:

- `disk_wait_whole_window`: threads in state `D` in all 5 samples of the window.
- `zombies_by_parent`: processes in state `Z`, grouped by parent.
- `fd_usage_above_threshold`: open fds above `fd_threshold_pct` of the soft `RLIMIT_NOFILE`.
- `rss_grew_every_sample`: RSS strictly increased between each of the 5 samples.
- `cgroups_throttled_in_window`: cgroups of scanned processes whose `nr_throttled` rose.
- `major_faults_whole_window`: major faults at or above
  `major_fault_threshold_per_s` in each of the 4 intervals between the samples.
- `cgroup_memory_pressure_full`: cgroup v2 directories of scanned processes
  whose `memory.pressure` `full` total rose in the window, with `full` and
  `some` as a share of the window. The root cgroup's row covers the whole host
  and is listed last. On a host without a v2 hierarchy this is empty with a
  note (cgroup v1 `memory.pressure_level` is an eventfd notification and cannot
  be read).
- `disk_wait_in_memory_management`: threads in `D` at the end of the window
  whose kernel stack (as root) or `wchan` is in a memory-management category
  (`page_fault_io`, `direct_reclaim`, `memcg_high_throttle`, `dirty_throttle`,
  `compaction`, `oom`). Other `D` threads are listed as `d_state_candidates`
  for `watch_process_stalls`, including a page or folio wait seen only through
  `wchan`, which may be a fault or a `read(2)`. At most 64 threads are inspected.
- `frozen_or_stopped`: cgroups frozen by the freezer (v2 `cgroup.events`
  `frozen`, v1 `freezer.state` `FROZEN` or `FREEZING`) and processes in state
  `T` or `t`. These are held on purpose; a v1-frozen task sits in `D` in
  `__refrigerator` and is not listed as a memory wait.
- `oom_kill_counters`: memory cgroups whose `oom_kill` counter is above 0 (v2
  `memory.events`, v1 `memory.oom_control`).

Both read a bounded set of files per process at the start and end of the
window, plus `/proc/<pid>/stat` (RSS and the major-fault count; and thread
states for processes that had threads in `D`) at three points inside it, and
once per distinct cgroup `cpu.stat`, `memory.events` (or v1
`memory.oom_control` and `memory.failcnt`), `memory.pressure` and the freezer
state. Processes that exit mid-scan or cannot be read are skipped and counted
in `skipped`; they never cause an error. Each result has a `cost` block with
the time spent reading `/proc` and cgroup files, the number of distinct
cgroups read, the number of `D` threads inspected, and the list of files read.
Measured on a 4-core VM with about 1000 processes (1000 idle `sleep`
processes added), outside the window's sleeps: 0.29 to 0.32 s of CPU and
wall time per call before the memory conditions were added, 0.30 to 0.31 s
after, with 6 distinct cgroups read.

### `process_cpu(pid, window_s=2, top_threads=5, wait_sample_rate_hz=50)`

Samples the process and its threads at the start and end of the window.
Inside it, thread states and wait sites are sampled at `wait_sample_rate_hz`
(capped by `--max-stall-rate` and the thread-sample budget), and the host's
runnable count four times. `measurement.wait_site_sampling` gives the rate
used, the sample count and late samples. Four samples in a window were too
few: in the CPU-contention blind test (end of this file), a worker asleep
about 28% of the time showed no sleeping samples.

- `cpu`: `cpu_seconds_user`, `cpu_seconds_system`, `cpu_cores_used`,
  `cpu_percent_on_cpu`, `user_share`.
- `iowait_seconds`: block I/O delay from delay accounting. `null` with a reason
  when `kernel.task_delayacct=0`.
- `context_switches`: `voluntary_switches_per_s`, `nonvoluntary_switches_per_s`
  (summed over threads, from `/proc/<pid>/task/*/status`), `voluntary_share`,
  `switches_per_cpu_second`.
- `scheduler`: `on_cpu_seconds`, `runqueue_wait_seconds` and
  `runqueue_wait_ratio` (time runnable but waiting for a CPU, over time on CPU,
  from `/proc/<pid>/task/*/schedstat`), `runqueue_wait_seconds_per_s` (mean
  number of the process's threads waiting), `on_cpu_seconds_per_s`,
  `timeslices_per_s` (schedstat field 3, `pcount`), `cpu_migrations_per_s`
  (`se.nr_migrations`, needs `CONFIG_SCHED_DEBUG`), `avg_timeslice_us`
  (on-CPU time / timeslices; on-CPU time / switches, and said so, where
  there is no timeslice count), `sched_slice_us` (`se.slice` from
  `/proc/<tid>/sched` on 6.6+; otherwise debugfs `base_slice_ns`, the sysctl,
  or the EEVDF default for the running kernel, marked as an estimate) and
  `avg_timeslice_to_sched_slice_ratio`.
- `page_faults`: major and minor faults per second.
- `threads`: count, `threads_by_state`, `state_share_over_window`, started and
  exited in the window.
- `wait_sites`: where sleeping threads were blocked in the kernel
  (`/proc/<tid>/wchan` and `/proc/<tid>/syscall`), grouped as `futex`,
  `poll_epoll_select`, `timer_sleep`, `block_io`, `pipe_socket`, `other`, with
  the most common raw wait channels. `futex` covers mutexes, condition
  variables and the GIL.
- `top_threads`: by CPU seconds, non-voluntary and voluntary switches, and
  run-queue wait.
- `environment.cgroup`: the cgroup from `/proc/<pid>/cgroup`, its version, the
  Kubernetes pod UID, QoS class and container id parsed from the path, its own
  `cpu.stat` deltas (usage, user, system, `nr_periods`, `nr_throttled`,
  `throttled_seconds`, `cfs_throttled_ratio`) and limit, the same for each
  ancestor that has a quota (`ancestors_with_quota`, since a pod-level limit
  throttles its containers), `tightest_limit_cores`,
  `max_cfs_throttled_ratio`, PSI from `cpu.pressure`, `memory.pressure` and
  `io.pressure` (`avg10_pct`, `avg60_pct`, and `window_pct` from the `total`
  delta), and `cpuset_cpus_effective`.
- `environment.host` (unless `--no-host-context`): `cores_online`,
  `cpu_time_pct` (user, nice, system, idle, iowait, irq, softirq, steal),
  `context_switches_per_s`, `procs_running_mean` and `procs_running_per_core`
  (sampled in the window), load average, PSI for cpu, memory and io, and
  run-queue wait per CPU from `/proc/schedstat` (versions 15 to 17; other
  versions or a kernel without `CONFIG_SCHEDSTATS` give `null` and a reason).

On a cgroup v2 host everything comes from the unified hierarchy. On a hybrid
host where the `cpu` controller is still on cgroup v1, CPU accounting and
throttling come from the v1 `cpu` and `cpuacct` hierarchies (`cpu.stat`
`throttled_time`, `cpu.cfs_quota_us`, `cpuacct.usage*`) and pressure from the
v2 directory; `notes` says so. Kubernetes pod names are not looked up; the UID
is returned.

### `hw_counters(pid, window_s=2)`

Opens counters with `perf_event_open` through ctypes (no `perf` binary) on each
thread of the process, with `inherit` so threads started in the window are
counted when they exit: cycles, instructions, last-level cache read accesses
and misses (`PERF_TYPE_HW_CACHE`, falling back to the generic cache events),
context switches, CPU migrations and task clock. Returns `ipc`, `llc_mpki`
(misses per 1000 instructions), `llc_miss_ratio`, the software rates, and per
counter `raw_value`, `time_enabled_ns`, `time_running_ns`, `running_fraction`
and `multiplexed`. When the kernel multiplexes counters, `value` is
`raw_value * time_enabled / time_running`.

When a hardware event cannot be opened, its value is `null` and the reason is
exact: `unavailable: no PMU exposed (common in VMs)` with the event source
devices that do exist, `EACCES`/`EPERM` with `perf_event_paranoid` and the
capability needed (`CAP_PERFMON` on 5.8+, `CAP_SYS_ADMIN` before), `ENOENT`
for an event this PMU lacks, and so on. Software events are still reported.

When IPC or LLC misses are `null`, `software_fallback` lists what can be
measured instead over the same window: the perf software events
(`context_switches_per_s`, `context_switches_per_cpu_second`,
`cpu_migrations_per_s`), and from `/proc/<tid>/schedstat` `on_cpu_seconds_per_s`,
`timeslices_per_s`, `avg_timeslice_us`, `switches_per_cpu_second`,
`voluntary_share` and `runqueue_wait_ratio`. `see_also` points to
`cpu_colocation`, `fit_per_slice_cost` and `cache_sensitivity_probe`, and says
whether the probe is enabled on this server.

If `/sys/fs/resctrl` is mounted and the pid is in a resctrl group, `resctrl`
reports that group's L3 occupancy and cumulative memory-bandwidth bytes. These
cover every task in the group. The tool never creates a group. Per-process
monitoring groups are a possible future addition.

### `snapshot_process_metrics(pid, window_s=2, work_rate?, label?)` and `compare_process_snapshots(before, after)`

A snapshot measures one window (as `process_cpu`, plus hardware counters) and
keeps the key numbers in server memory under a token (`pm-1a2b3c4d`; the newest
64 are kept). `work_rate` is a number the caller supplies from its own
metrics, such as requests per second during the window. With it the snapshot
records `cpu_seconds_per_unit_work`.

The comparison gives each metric `before`, `after`, `change` and
`after_to_before_ratio`. When both snapshots have a `work_rate`, `work` gives
`work_rate_ratio`, `cpu_cores_ratio` and `cpu_per_unit_work_ratio`. A value
above 1 means CPU grew faster than work between the windows: the pattern to
look for when a feedback loop is suspected.

Process snapshots also keep `on_cpu_seconds_per_s`, `timeslices_per_s`,
`avg_timeslice_us` and `sched_slice_us`. `compare_process_snapshots` also
takes two group snapshots (below) and then compares per group key.

### `cpu_colocation(pid | pids | name | cmdline | ..., window_s=2, rate_hz=50, colocated_per_cpu=10)`

Which tasks shared CPUs with a target over the window, and how often they
woke. It answers what `runqueue_contention` alone does not: who preempts whom
and why per-unit CPU changed.

At the start it reads `stat`, `status` and `schedstat` of every task on the
host. Every task that runs in the window (its on-CPU time advanced, checked
every 0.5 s, or it was runnable) is then sampled at `rate_hz` for its state
and the CPU it last ran on (`/proc/<pid>/task/<tid>/stat` field 39; for a
runnable task, the run queue it waits on). At the end it reads `stat`,
`status`, `schedstat` and `sched` (for `se.slice`) of those tasks. The
server's own process is left out.

- `target_tasks`: per target thread, `home_cpu` (where most samples were),
  samples per CPU and runnable samples per CPU, `cpus_allowed`
  (`Cpus_allowed_list`), on-CPU and run-queue wait per second, voluntary and
  non-voluntary switches per second, `timeslices_per_s`, `avg_timeslice_us`
  with its source, `sched_slice_us`, `avg_sleep_us` and `short_sleeper`.
- `cpus`: for each CPU the targets ran on or may run on: target tasks and other
  busy tasks with that home CPU, `mean_runnable_tasks`, on-CPU and run-queue
  wait per second, voluntary and non-voluntary switches per second,
  `wakeups_per_s`, `colocated_wakeups_per_s` (non-target tasks only),
  `colocated_short_sleeper_wakeup_share`, the targets' non-voluntary switches
  there, `target_preemptions_per_colocated_wakeup`, and the co-located tasks
  (by their on-CPU time there) with the same per-task fields. A task's rates
  are spread over CPUs in proportion to its samples on each.
- `placement`: target and other busy tasks per CPU, mean runnable tasks per
  CPU, and the imbalance (`runnable_max_minus_min`, `runnable_max_to_min_ratio`,
  `runnable_cv`, `busy_tasks_max_minus_min`).
- `wakeup_preemption_attribution`: labelled `inference`. A task's voluntary
  switches are taken as its wakeups: each voluntary switch is a sleep, and
  each sleep ends in a wakeup. Per target thread, its non-voluntary switches
  (also per second on CPU) next to the co-located wakeups on its home CPU; the
  totals on the target CPUs; the share from short sleepers; the Pearson
  correlation across target threads between non-voluntary switches per second
  on CPU and co-located wakeups (per second on CPU, because a wakeup can only
  preempt the task that is running); and the top short sleepers. A short
  sleeper wakes at least 100 times a second and sleeps under 1 ms per wakeup
  on average, where sleep is the window minus on-CPU time minus run-queue wait
  (this needs no `CONFIG_SCHEDSTATS`). No trace is taken of which wakeup
  preempted which task.
- `cost`: tasks listed and tracked, rescans, the sampler's CPU seconds, and the
  files read.

The selector takes the `find_processes` filters: `pid`, `pids`, `name`,
`cmdline`, `cmdline_regex`, `parent_pid`, `cgroup`, `pod_uid`,
`container_id`. All threads of the matching processes are targets.

### `group_cpu(selector..., group_by="none", group_regex?, window_s=2, rate_hz=20, work_rate?, work_rates?, include_members=true)`

Measures a set of processes over one window, as `process_cpu` measures one.
A single-pid view hid that sibling workers of one service behaved very
differently; this one shows them side by side.

- `member_rows`: per member `cpu_cores_used`, `on_cpu_seconds_per_s`, user and
  system CPU per second, voluntary and non-voluntary switches per second,
  `voluntary_share`, `switches_per_cpu_second`, run-queue wait per second and
  ratio, `timeslices_per_s`, `avg_timeslice_us`, `cpu_migrations_per_s`, major
  and minor faults per second, `threads`, `runnable_share` (share of in-window
  thread samples in state R), `home_cpu`, samples per CPU and `cpus_allowed`.
- `groups`: per group key, for every metric above: `sum` (for rates that add
  up; `null` for ratios), `mean`, `p50`, `p90`, `min`, `max`, `spread` (max
  minus min), `max_to_min_ratio` and `cv`; for ratios also `pooled`, recomputed
  from the members' summed counts (for example `avg_timeslice_us` = total
  on-CPU time / total timeslices). `placement` gives members per home CPU and
  mean runnable member threads per CPU.
- `comparison`: with two or more groups, each group's per-member mean or
  pooled ratio side by side.
- `work`: with `work_rate` (one group) or `work_rates` (group key to units per
  second): `cpu_seconds_per_unit_work` (from schedstat on-CPU time, or clock
  ticks without schedstat), `timeslices_per_unit_work` and
  `units_of_work_per_timeslice`.

`group_by`: `none`, `comm`, `exe`, `parent`, `cgroup`, `pod`, `container`,
`cmdline_arg:N` (the Nth argument of the redacted command line, 0 being the
program), or `cmdline_regex` with `group_regex` (its first capture group,
searched in the redacted command line). The selector takes the
`find_processes` filters. The server's own process is left out.

### `snapshot_group_metrics(selector..., group_by, work_rate?, work_rates?, label?)` and `fit_per_slice_cost(tokens, group?, work_rates?)`

`snapshot_group_metrics` measures as `group_cpu` does and keeps each group's
numbers under a token (`pg-...`, in the same store as process snapshots).
Compare two with `compare_process_snapshots`.

`fit_per_slice_cost` takes three or more snapshots of one process or one group
taken at different settings (CPU count, co-location, slice length) and fits

    cpu_seconds_per_unit_work = a + b * timeslices_per_unit_work

which is the same as `a + b / units_of_work_per_timeslice`. `b`, reported as
`fixed_cost_per_timeslice_us`, is CPU each timeslice costs on top of the work
in it, for example refilling caches after other tasks ran; `a`,
`cost_per_unit_work_without_slicing_us`, is the cost with infinitely long
slices. The result has standard errors, R squared, residuals per point and
the largest residual as a share, and each point with its work rate, CPU per
unit of work, average timeslice and timeslices per second. With fewer than
three usable points it warns; with all points at the same timeslices per unit
of work, or a negative slope, it says the model does not describe them.
`work_rates` (token to units per second) supplies the rate for snapshots whose
rate was known only after the window.

### `cache_sensitivity_probe(confirm, mode="synthetic", pid?, cpu?, sizes_bytes?, phase_s=1, neighbour_bytes?)`

For hosts without hardware counters. Off unless the server runs with
`--allow-load-probes`, and every call needs `confirm=true`; without it the
result is `confirmation_required` with the plan (CPUs, sizes, longest
duration). It is the one process-diagnostics tool that is not read-only.

It runs a small benchmark in separate processes and never attaches to, reads
or signals the target. Per working-set size it walks a random linked list of
64-byte nodes (one dependent load per cache line) pinned to one CPU, first
alone and then shared:

- `mode="synthetic"`: two neighbours pinned to the same CPU, one walking a
  large buffer (default 4 x L2, at least 8 MiB) that evicts the probe's
  working set from the per-core caches, and one that sleeps about 50 us
  between short bursts, so its wakeups preempt the probe.
- `mode="colocated"`: the shared phase runs on the CPU where `pid` ran most
  (the pid must be on the allowlist), against the target's co-located tasks;
  the alone phase runs on another CPU.

Throughput is measured per second of the probe's own CPU time, so the share
of the CPU it gets does not count. Per size: `ns_per_access` alone and shared,
`slowdown_ratio`, the probe's timeslices per second and average timeslice
(from its own `/proc/thread-self/schedstat`), and `extra_cpu_us_per_timeslice`,
an estimate of the refill per slice to compare with
`fixed_cost_per_timeslice_us`. Sizes default to the host's caches from
`/sys/devices/system/cpu/cpu0/cache/`: L1d / 3 (at most 16 KiB), L2 / 2,
L2 x 3/4, L2 x 4, and L3 x 2 when that is at most 64 MiB.

It measures how sensitive a synthetic workload of a given size is to cache
sharing on this host. It does not measure the target's cache misses. It adds
up to one CPU of load on the chosen CPU for at most 2 x sizes x `phase_s`
seconds (at most 6 sizes, `phase_s` at most 3). The benchmark is C, built
once per server process with the host's C compiler into a temporary directory;
without a compiler it falls back to the same walk in Python, whose interpreter
overhead per access hides much of the difference. Every child process is
killed on every exit path. Refusals are `diagnostics_refused` with reason
`load_probes_disabled`, `confirmation_required` or `invalid_argument`; a
benchmark that fails returns `probe_failed`.

### `watch_process_stalls(pid, window_s=5, rate_hz=20)`

For a process that hangs or is intermittently slow. A process that keeps
taking page faults, or waits in reclaim, swap-in or `memory.high` throttling,
keeps leaving its hot path for the kernel; it looks hung or slow while its own
code is fine. This tool samples every thread at a fixed rate (`rate_hz`,
capped by `--max-stall-rate`, default 100; `window_s` capped by
`--max-window`) and reads, per sample:

- the state letter, `minflt`, `majflt` and `utime + stime` from
  `/proc/<pid>/task/<tid>/stat`;
- `/proc/<tid>/wchan`;
- the kernel stack from `/proc/<pid>/task/<tid>/stack` (root only; otherwise
  `measurement.stack_source` is `wchan` and `unavailable.kernel_stacks` says
  why).

Each sample gets one wait category (below). Per thread the result has the
share of samples in each state and category, major and minor faults per
second, CPU seconds, and its longest no-progress intervals. A no-progress
interval is a run of consecutive samples in which the thread's
`utime + stime` (in clock ticks) did not advance and the thread was not
voluntarily idle (`futex`, `poll`, `nanosleep`, `ipc_wait`). Each interval has
its duration, start offset, dominant category, counts by category and state,
the major faults taken in it, an example kernel stack (8 frames) and `wchan`,
and whether it began before or was still open at the end of the window.

Per process (`process`): fault totals and rates, CPU split and
`system_share`, `category_share` over all thread samples and
`category_share_of_active` (excluding voluntary idle),
`memory_stall_share_of_active` (share of non-idle samples in
`page_fault_io`, `direct_reclaim`, `memcg_high_throttle` or `compaction`),
`no_progress_seconds_by_category`, `memory_stall_no_progress_seconds_per_s`,
the 10 longest intervals across threads, the frames that matched each
category, unclassified stacks (10, innermost frames kept), and `memory`:
`VmRSS`, `VmHWM`, `RssAnon`, `RssFile`, `VmSwap` from `status` and `Rss`,
`Pss`, `Swap`, `SwapPss` from `smaps_rollup`.

`process.delay_accounting`: when delay accounting is on, the per-second
deltas of `thrashing_delay`, `swapin_delay`, `freepages_delay` (direct
reclaim), `blkio_delay`, `compact_delay` and `cpu_delay`, summed over the
process's threads, from the taskstats generic-netlink interface (needs
`CAP_NET_ADMIN`). When `kernel.task_delayacct=0` they are `null` and the reason
says how to enable it: `sysctl kernel.task_delayacct=1` or the `delayacct`
boot option. The server never changes the sysctl and has no option to.

`environment.cgroup_memory`: the memory cgroup. On cgroup v2: `memory.current`
against `memory.max` and `memory.high` (`usage_to_max_ratio`,
`usage_to_high_ratio`, and each ancestor with a limit), `memory.events`
deltas (`low`, `high`, `max`, `oom`, `oom_kill`, `oom_group_kill`),
`memory.stat` deltas and rates (`workingset_refault_anon` and `_file`,
`pgmajfault`, `pgfault`, `pgscan`, `pgsteal`, `pgscan_direct`,
`pgscan_kswapd`), `refaults_per_s`, and `memory.pressure` `some` and `full`
with `avg10_pct`, `avg60_pct` and `window_pct`. On a hybrid host where the
memory controller is on cgroup v1: `memory.usage_in_bytes` against the
tighter of `memory.limit_in_bytes` and `hierarchical_memory_limit`,
`memory.failcnt` as the `max` event count, `oom_kill` and `under_oom` from
`memory.oom_control`, the hierarchical (`total_`) `memory.stat` counters, and
`memory.pressure` from the process's v2 directory (PSI follows the v2
hierarchy). Values v1 does not have (`memory.high`, the `oom` event, `pgscan`,
`pgsteal`) are `null` with a reason; `memory.pressure_level` is an eventfd
notification and cannot be read. `environment.host`: `/proc/pressure/memory`
over the window, `/proc/vmstat` deltas and rates (`pgmajfault`,
`workingset_refault_*`, `allocstall_*` summed as `allocstall_total`,
`pgscan_direct`, `pgscan_kswapd`, `pgsteal_direct`, `pswpin`, `pswpout`,
`compact_stall`, `oom_kill`), and `meminfo` (`MemAvailable`, `SwapTotal`,
`SwapFree`), with a note when no swap is configured.

#### Wait categories

`CATEGORIES` in `src/heapspy_mcp/system/wait_categories.py` is the one table
that maps kernel frames to categories. It is checked in order and the first
category with a matching frame wins, so memory-management waits are found
even when the innermost frame is a generic sleep. Names are matched without
offsets and compiler suffixes (`.isra.0`), exactly or by prefix.

| Category | Meaning | Frames (examples) |
|---|---|---|
| `stopped_or_frozen` | stopped by a signal or ptrace (state `T`/`t`), or frozen by the cgroup freezer | `__refrigerator`, `do_freezer_trap`, `do_signal_stop`, `ptrace_stop`; `get_signal` as the innermost frame (v2 freeze) |
| `oom` | inside the OOM killer, or waiting for an OOM kill in its cgroup | `out_of_memory`, `mem_cgroup_out_of_memory`, `mem_cgroup_oom_synchronize` |
| `memcg_high_throttle` | over `memory.high`: reclaiming and then sleeping on return to user space | `mem_cgroup_handle_over_high` |
| `compaction` | compacting memory for a high-order allocation, or kcompactd | `compact_zone`, `try_to_compact_pages`, `__alloc_pages_direct_compact`, `kcompactd` |
| `direct_reclaim` | an allocation or a cgroup charge reclaims memory itself, or is throttled while others reclaim | `try_to_free_pages`, `try_to_free_mem_cgroup_pages`, `shrink_*`, `__alloc_pages_slowpath`, `try_charge_memcg`, `reclaim_throttle` |
| `dirty_throttle` | a writer paused until writeback catches up | `balance_dirty_pages` |
| `page_fault_io` | a page fault waits for the page to be read in: a file page (often a refault) or a swap-in | `do_swap_page`, `swap_readpage`; `folio_wait_bit_common`, `__folio_lock`, `wait_on_page_bit`, `io_schedule` when a fault frame (`filemap_fault`, `handle_mm_fault`, `exc_page_fault`, ...) is on the stack |
| `futex` | a mutex, condition variable, semaphore or the Python GIL | `futex_*`, `do_futex` |
| `poll` | poll, select, epoll or io_uring waits | `do_epoll_wait`, `ep_poll`, `do_select`, `do_sys_poll` |
| `nanosleep` | a timed sleep | `hrtimer_nanosleep`, `do_nanosleep` |
| `ipc_wait` | input from a socket, pipe or terminal, a child to exit, or a signal | `unix_stream_read_generic`, `anon_pipe_read`, `do_wait`, `sk_wait_data` |
| `block_io` | block I/O outside a page fault: `read(2)` of an uncached page, fsync, writeback, journal | `submit_bio_wait`, `jbd2_*`, `blk_mq_*`, page and folio waits without a fault frame |
| `running` | state `R`, or an empty stack with `wchan` 0 (it woke up between the reads); no wait site is known for a task on a CPU | |
| `other` | not in the table; the innermost frames are kept in `unclassified_stacks` | e.g. a fault waiting on `mmap_lock` (`rwsem_down_read_slowpath`) |
| `unavailable` | neither the stack nor `wchan` could be read | |

`futex`, `poll`, `nanosleep` and `ipc_wait` are voluntary idle and do not
count towards no-progress intervals. Without stacks (not root), a page or
folio wait seen through `wchan` counts as `page_fault_io` when the thread's
major-fault count rose since its previous sample, and as `block_io`
otherwise.

#### Frozen vs thrashing

A process frozen by the cgroup freezer, or stopped by `SIGSTOP` or a
debugger, also makes no progress, and a v1-frozen task is in state `D`. The
result reports this separately in `frozen_or_stopped`: the freezer state of
its cgroups (v2 `cgroup.events` `frozen` and `cgroup.freeze`, v1
`freezer.state`, `self_freezing`, `parent_freezing`), the share of samples in
state `T`/`t` and in `stopped_or_frozen`, and an `assessment`:
`frozen_by_cgroup_freezer`, `stopped_by_signal_or_ptrace`,
`held_in_freezer_or_signal_stop`, `partly_stopped_or_frozen` or
`not_frozen_or_stopped`. The no-progress intervals of such a process have the
dominant category `stopped_or_frozen`, not a memory one.

### `diagnose_process(pid, window_s=2, focus="all")` and `diagnose_process_cpu(pid, window_s=2)`

Measures the process, its environment and its hardware counters in one
window and, side by side in the same window, samples its threads as
`watch_process_stalls` does at 10 Hz and its CPUs as `cpu_colocation` does at
20 Hz. It then checks one fact and scores
these explanations for its CPU use, CPU wait, slowness or stalls:

| id | What it describes |
|---|---|
| `runqueue_contention` | runnable threads waiting for a CPU |
| `short_timeslices` | timeslices far shorter than the scheduler slice, ending in preemption, with frequent wakeups of co-located tasks |
| `cache_or_memory_bound_contention` | low IPC with many LLC misses |
| `cfs_throttling` | the cgroup or an ancestor hits its quota |
| `lock_contention` | frequent blocking and waking, mostly in futex |
| `spin_waiting_or_compute` | on CPU, few switches, normal IPC; counters cannot separate the two |
| `gil_convoy` | several Python threads, CPU near one core, frequent hand-offs |
| `steal` | the hypervisor runs other guests on this VM's CPUs |
| `memory_thrashing` | threads keep waiting for memory: refaults, swap-in, reclaim, `memory.high` throttling, compaction |
| `io_pressure` | I/O stalls (PSI), iowait, threads in block I/O outside page faults |

`memory_thrashing` replaces the earlier `memory_pressure`, which read only
memory PSI and the major-fault rate. It reads those (major faults at
100/s or more, PSI `full` at 1% or more, or `some` at 5% or more) plus
workingset refaults (100 pages/s or more, from the cgroup's `memory.stat`, or
the host's `/proc/vmstat` without one), the share of non-idle thread samples
in `page_fault_io`, `direct_reclaim`, `memcg_high_throttle` or `compaction`
(0.5 or more scores high, 0.1 some), and no-progress time in those waits
(0.2 s/s or more). Evidence against is the absence of each: under 5 major
faults/s, under 10 refaults/s, PSI `some` under 0.5%, and under 1% of
non-idle samples in a memory wait. Keeping both hypotheses would have counted
the same PSI and fault evidence twice. With per-thread categories,
`io_pressure`'s disk-wait share counts only `block_io` samples, since `D`
samples in page faults are memory waits. Refault and `memory.stat` counters
cover every process in the cgroup; the wait share is the process's own.

A thread that is runnable but not running is starved, not idle. When
`runqueue_wait_ratio` is at least 0.2 or the thread was in state R in at least
90% of samples (`runnable_share`), `spin_waiting_or_compute` judges busy and
idle by `cpu_demand_cores` (on-CPU time plus run-queue wait, per second)
instead of `cpu_cores_used`, and `runqueue_contention` gets evidence for from
the runnable share. When `voluntary_share` is under 0.5, most switches are
preemptions, so a high `switches_per_cpu_second` no longer counts against
compute or for lock contention. In the blind test, a starved worker using
0.151 cores with a run-queue wait ratio of 5.6 had compute marked
`not_indicated` as mostly idle; it now counts 1.0 cores of demand.

`short_timeslices` reads `avg_timeslice_to_sched_slice_ratio` (under 0.1
scores 3, under 0.25 scores 2, 0.5 or more is against), `voluntary_share`
(under 0.5 for: slices end in preemption; 0.7 or more against: the threads
block on their own), `colocated_wakeups_per_s` (1000 or more) and
`colocated_short_sleeper_wakeup_share` (0.5 or more). Its next measurements
are `cpu_colocation`, moving the co-located short sleepers to a separate
cpuset and comparing CPU per unit of work, comparing CPU per unit of work at
different slice lengths with `fit_per_slice_cost`, and, without a PMU,
`cache_sensitivity_probe`.

`fact_checks` comes first. `deliberately_frozen` is true when the process's
cgroup is frozen or at least 90% of thread samples were stopped or frozen.
Then the result says that the explanations are moot until the process is
thawed or continued, every hypothesis carries `moot_because`, and
`memory_thrashing` has evidence against.

`focus` (`all`, `cpu`, `memory`, `io`) limits which explanations are listed;
all are measured. `diagnose_process_cpu` is the same tool with
`focus="all"`, kept under its earlier name. Besides the hypotheses the result
has `signals`, `memory_stalls` (the stall numbers that were scored, the 3
longest no-progress intervals, `frozen_or_stopped`), `colocation` (the
co-location numbers that were scored, with the top 3 co-located tasks per
CPU), and
`environment.cgroup_memory` and `environment.host_memory` as in
`watch_process_stalls`.

Each hypothesis has `evidence_for` and `evidence_against` (signal, raw value,
threshold name and value, unit, weight), `unknown` (signals that could not be
measured, with the reason), a `score` (sum of weights for minus against), an
`assessment` (`consistent_with_measurements` for a score of 3 or more,
`partly_consistent` for 1 or 2, `not_indicated` for 0 or less with evidence,
`insufficient_signals` when nothing was measured) and `next_measurements`
that would separate it from the others, such as measuring IPC at two
densities, pinning with the static CPU manager, reducing threads per process
or removing the CPU limit on one instance. The ranking says how well each
explanation fits the numbers of one window. It does not establish a cause, and
several can hold at once.

All thresholds are in one table, `THRESHOLDS` in
`src/heapspy_mcp/system/diagnose.py`, and the result repeats it under
`thresholds`.

### Signals and what they separate

| Signal | Field | Separates |
|---|---|---|
| Voluntary vs non-voluntary switches | `voluntary_share`, `*_switches_per_s` | blocking (locks, I/O, GIL) vs preemption (CPU contention, quota) |
| Run-queue wait | `runqueue_wait_ratio` | waiting for a CPU vs running |
| Runnable share and CPU demand | `runnable_share`, `cpu_demand_cores` | a starved thread vs an idle one |
| Average timeslice vs scheduler slice | `avg_timeslice_us`, `sched_slice_us` | slices cut short by preemption vs full slices |
| Co-located wakeups | `colocated_wakeups_per_s`, `colocated_short_sleeper_wakeup_share` | preemption by short sleepers on the same CPU vs by other CPU-bound tasks |
| Placement | `placement` in `cpu_colocation` and `group_cpu` | uneven spread of tasks over CPUs vs an even one |
| Per-slice cost | `fixed_cost_per_timeslice_us` | CPU per unit of work that rises with slicing vs a fixed cost per unit |
| Host runnable per core | `procs_running_per_core` | host-wide CPU contention vs a quota on an otherwise idle host |
| PSI cpu, memory, io | `psi`, `pressure` | CPU vs memory vs I/O stalls, host and cgroup |
| CFS throttling | `cfs_throttled_ratio`, `throttled_seconds_per_s` | quota limits vs host contention |
| Steal | `steal_pct` | hypervisor contention vs guest-side causes |
| IPC, LLC MPKI | `ipc`, `llc_mpki` | memory or shared-cache bound vs compute or spin |
| Wait sites | `wait_sites.share_by_site` | futex vs poll vs block I/O |
| CPU per unit of work | `cpu_seconds_per_unit_work` | efficiency change vs load change |
| Major faults | `major_faults_per_s` | pages read from storage on access vs a working set in memory |
| Workingset refaults | `refaults_per_s`, `stat_per_s.workingset_refault_*` | a working set that does not fit (evicted pages needed again) vs first-time reads |
| Memory wait share | `memory_stall_share_of_active`, `category_share` | threads held in page-fault I/O, reclaim, `memory.high` throttling or compaction vs running, locks or block I/O |
| No-progress intervals | `longest_no_progress_intervals`, `no_progress_seconds_by_category` | a thread that stops for seconds in one wait vs one that keeps running |
| Memory PSI `full` | `pressure.full.window_pct` | every task in the cgroup stalled on memory at once vs some tasks |
| `memory.events` `high`, `max` | `events_in_window` | throttling at `memory.high` or reclaim at `memory.max` vs no limit pressure |
| System share of CPU | `system_share` | time in the kernel (reclaim, faults) vs user code |
| Freezer and `T` state | `frozen_or_stopped`, `fact_checks` | a process held on purpose vs one that is stalled |

### Safety and access

All of these tools are read-only except `cache_sensitivity_probe`, which
starts benchmark processes and is off by default.

- `find_processes`, `scan_processes`, `cpu_colocation` and `group_cpu` read the
  same per-task `/proc` files that `ps` and `top` show (`stat`, `status`,
  `schedstat`, `sched`, `cgroup`), and are open without the allowlist, so an
  agent can find the process to look at. They do not read wait channels,
  syscalls or stacks. Command lines are redacted.
- `cache_sensitivity_probe` needs `--allow-load-probes` on the server and
  `confirm=true` on the call; with `mode="colocated"` the pid must also be on
  the allowlist. It never touches the target.
- `process_cpu`, `hw_counters`, `snapshot_process_metrics`,
  `watch_process_stalls`, `diagnose_process` and `diagnose_process_cpu` read
  one process in depth (its threads' wait channels, kernel stacks and
  syscalls, its taskstats, and performance counters attached to it) and
  follow the same `--allow` list as `capture_snapshot`. An unlisted pid is
  refused with `diagnostics_refused` and a reason (`allowlist_empty`,
  `not_allowlisted`, `no_such_process`).
- The scan's memory conditions read the kernel stack (or `wchan`) only of
  threads in `D`, at most 64, and report only their wait category and three
  innermost frames.
- No tool changes kernel settings. Delay accounting is reported as `null`
  with how to enable it, never switched on.
- Host-wide context (load, steal, host PSI) is included by default because it
  is what the process is subject to and it describes no other process. On a
  shared host where that aggregate should not reach an agent, start the server
  with `--no-host-context`. The process's own cgroup is always reported.

### Command-line redaction

Command lines returned by `find_processes`, `scan_processes` and
`list_python_processes`, `cpu_colocation` and `group_cpu` pass through a
best-effort filter (`src/heapspy_mcp/system/redact.py`) before truncation,
so a cut never leaves part of a secret. Truncation keeps the start (the
program and the leading arguments); `cmdline_max_chars` sets the length per
call, up to `--max-cmdline-chars`. `group_by="cmdline_arg:N"` and
`cmdline_regex` read the redacted command line too. It replaces with
`<redacted>`: values of options whose name looks secret (`--password=x`,
`--token x`, `--api-key`, `--client-secret`), `NAME=value` pairs with a secret
name (`*_KEY`, `*_TOKEN`, `*_SECRET`, `*PASSWORD*`), `Authorization:` and
similar header values, the password (or a lone token) in `scheme://user:pass@`
URLs, and secret-named query parameters. It does not make a command line safe
to publish.

### What works where

| Placement | Works | Does not |
|---|---|---|
| Local machine | Everything for your own processes; root (or `CAP_SYS_PTRACE`) for other users' threads' wait channels, syscalls and `/proc/<pid>/io` | `hw_counters` on other users' processes without `CAP_PERFMON` |
| Pod without host access | Processes in the pod's own PID namespace, the pod's cgroup, host `/proc/stat` and PSI (not namespaced) | Other pods' processes; `perf_event_open` without `PERFMON` |
| Sidecar with `shareProcessNamespace: true` | The other containers of the pod, with `SYS_PTRACE` | Other pods |
| Node agent (DaemonSet, `hostPID: true`) | Every process on the node, its cgroup, pod UID and container id; add `--cgroup-root` with the host cgroupfs mounted if the container's cgroup namespace hides it | Pod names (only UIDs) |
| VM without a PMU | Everything except hardware counters, which are `null` with `no PMU exposed (common in VMs)`; `cache_or_memory_bound_contention` is then `insufficient_signals`. `hw_counters` returns `software_fallback`, and `cache_sensitivity_probe` (opt-in) measures this host's cache sensitivity with a synthetic workload | IPC, LLC misses |

Kernel features that change what is available, each reported as a reason when
missing: delay accounting (`kernel.task_delayacct`) for iowait and the
stall delays, `CONFIG_TASKSTATS` and `CAP_NET_ADMIN` for the taskstats
delays, `CONFIG_SCHEDSTATS` for `/proc/schedstat`, `CONFIG_SCHED_DEBUG` for
`se.nr_migrations` and `se.slice` (6.6+ for `se.slice`), PSI (`psi=1`) for pressure files, root
(`CAP_SYS_ADMIN`) and `CONFIG_STACKTRACE` for `/proc/<tid>/stack`, and a v2
hierarchy (unified or hybrid) for cgroup memory pressure and the v2 freezer.

See [`deploy/kubernetes/daemonset.yaml`](deploy/kubernetes/daemonset.yaml) for
a node-agent example.

## CPU tools (py-spy)

py-spy reads a running CPython process's stacks from outside, the way heapspy
reads its heap. The CPU tools answer:

| Tool | Question |
|---|---|
| `cpu_stacks(pid)` | What is every thread doing right now? |
| `cpu_top(pid, duration_s=5)` | Where are the running threads, and how much CPU did the process really use? |
| `cpu_profile(pid, duration_s)` | Where does the time go over a longer window, and is the GIL contended? |
| `cpu_flamegraph(pid, duration_s)` | Write a flame graph file for the user to open. |

Use the heap tools when memory grows or RSS is high. Use the CPU tools when a
process is slow, hot, hung, or a request takes too long. If both, start with
`cpu_top`: it is cheap, and it shows whether the time goes into allocation or
garbage collection, which would point back at the heap.

### What the numbers mean

A **sample** is one thread at one sampling tick. At 100 Hz for 10 s, a process
with 4 Python threads gives up to 4000 samples when idle threads are counted.

Every percentage in the profile tools is `pct_of_samples`: a share of the
samples in the stated sampling mode. It is not a share of machine CPU, nor of
one core. "40% of on-CPU samples in `parse()`" means `parse()` was on the
stack in 40% of the times a thread was seen running. Each result has
`sampling.mode` and `sampling.description`:

- `on_cpu` (default): only threads py-spy flags as active.
- `all` (`include_idle=true`): every Python thread at every tick, including
  sleeping, blocked and GIL-waiting threads. Use it to see where threads wait.
- `gil` / `gil_on_cpu` (`gil_only=true`): only the thread holding the GIL.

For real CPU time use `cpu_top`: `cpu_seconds_user` and `cpu_seconds_system`
are the kernel's accounting for the target process over the profile window
(psutil `cpu_times` deltas), with `wall_seconds` and `cpu_pct_of_one_core`.
`iowait_seconds` is the time the process spent waiting for block I/O,
from Linux delay accounting. Delay accounting is off by default on recent
kernels (`kernel.task_delayacct=0`); then `iowait_seconds` is `null` and
`iowait_note` says how to turn it on (`sysctl kernel.task_delayacct=1`, or boot
with `delayacct`). It is never reported as 0 when it was not measured.

### Idle, GIL and OS thread state

Three different signals, from three sources:

- **py-spy's active/idle flag.** On Linux py-spy calls a thread active when its
  OS thread is running, or when it holds the GIL, and idle otherwise; it also
  treats a few known wait functions (`threading` waits, `selectors.select`) as
  idle. A thread that waits for the GIL sleeps on a condition variable, so py-spy
  counts it as **idle**. py-spy alone cannot tell "waiting for the GIL" from
  "sleeping".
- **GIL ownership.** `owns_gil` in `cpu_stacks`, and the `--gil` pass in the
  profile tools. Only one thread holds the GIL at a time (on a GIL build).
- **OS thread state**, read by the server from `/proc/<pid>/task/<tid>/stat`
  (Linux only): `running/runnable` (R), `sleeping (blocked in a syscall)` (S),
  `disk wait (uninterruptible)` (D), `stopped` (T), `zombie` (Z). For a sleeping
  thread `cpu_stacks` adds `kernel_wait` (from `wchan`, for example
  `hrtimer_nanosleep`, `unix_stream_read_generic`, `futex_do_wait`) and
  `syscall` (from `/proc/.../syscall`, for example `clock_nanosleep`,
  `recvfrom`, `futex`, `fsync`), when the kernel exposes them.

`cpu_profile` and `cpu_top` combine these:

- `split`: the profile is recorded by three py-spy passes over the same window,
  run side by side with `--nonblocking`: all threads (`--idle`), active threads
  only, and the GIL holder (`--gil --idle`). `split` gives `on_cpu`, `idle`,
  `gil_held` and `on_cpu_without_gil`, each with `samples` and `pct_of_samples`
  of the all-threads samples. The passes sample independently, so the parts are
  estimates and need not add up exactly. `on_cpu_without_gil` is time running C
  code that released the GIL (I/O, compression, numpy), or spinning before
  taking it.
- `os_thread_states`: the server samples `/proc/<pid>/task/*/stat` at 20 Hz
  during the profile and reports `running`, `sleeping_futex` (asleep in
  `futex()`: waiting for the GIL, a lock, a queue or a condition),
  `sleeping_other` (sleep, socket read, poll), `disk_wait` and `stopped`, as
  percentages of thread-state samples. This covers all threads of the process,
  including threads without Python frames.
- `gil`: `held_pct_of_ticks` (in how many ticks some thread held the GIL),
  `threads_that_held_gil`, `futex_waiters_avg`, and `contention`: `likely` when
  the GIL was held in at least 80% of ticks, at least two threads took turns
  holding it, and on average at least half a thread was asleep on a futex.
  Futex waits include ordinary lock and queue waits, so the explanation says to
  confirm with `cpu_stacks` that the waiting threads are in plain Python code.
- `threads`: per thread, the samples in each pass and its OS state shares.

With `native=true` py-spy needs blocking reads, which cannot run side by side,
so `split` and `gil` are `null` and a note says why.

### `cpu_stacks(pid, include_idle=true, native=false, nonblocking=true, max_threads=50, max_frames=20)`

Runs `py-spy dump --json`. Per thread: `thread_id` (OS thread id),
`python_thread_id`, `name`, `active`, `owns_gil`, `os_state` (`code`, `label`,
and for a sleeping thread `kernel_wait` and `syscall`), and `frames`, innermost
first, each with `function`, `location` (`file:line` as py-spy shortens it),
`file`, `line`, `module` and `native`. `module` is derived from the shortened
path (`app/cache.py` gives `app.cache`) and is a guess for scripts run by path.
`summary` counts threads, active and idle threads, the GIL holder and OS states.
At most 200 threads and 100 frames per thread are returned.

`nonblocking=true` (the default) passes `--nonblocking`: py-spy reads the
target's memory while it runs. The target is never paused, but a stack can be
torn or wrong if the thread moved while it was read. `nonblocking=false` pauses
the process for the few milliseconds of the read and gives a consistent
snapshot; use it when a stack looks impossible. `native=true` also unwinds
C, C++ and Cython frames and always pauses the process (py-spy cannot read
native stacks without pausing). The OS state is read right after py-spy's
sample, not atomically with it, so a thread can show `active: false` with state
`R` when it woke up in between.

### `cpu_profile(pid, duration_s=10, rate_hz=100, include_idle=false, gil_only=false, subprocesses=false, native=false, top=15, top_stacks=5, save_folded=false)`

Runs `py-spy record --format raw --threads --nonblocking` into a private
temporary directory, parses the folded stacks in Python, and returns:

- `sampling` (mode, description, flags, number of py-spy passes) and
  `samples` (`total` in this mode, `ticks_estimate`, `py_spy_errors`).
- `top_self`: functions ranked by self samples (the function was the innermost
  frame). `top_total`: ranked by total samples (the function was anywhere on the
  stack; recursion counts once). Each row has `function`, `module`, `location`
  (the most sampled line), `samples` and `pct_of_samples`.
- `top_stacks`: whole stacks, innermost first, with the threads that ran them.
- `split`, `os_thread_states`, `gil` and `threads`, described above.
- `folded_path`: with `save_folded=true`, the folded file is kept in the
  snapshot directory (`cpu-xxxxxxxx.folded`, mode 0700 directory) for
  speedscope, `flamegraph.pl` or `inferno-flamegraph`. Otherwise `null`. With
  `subprocesses=true` the file's process frames contain command lines; the
  file stays on the local disk and its contents are never returned.

`duration_s` is a whole number, clamped to 1 .. `--cpu-max-duration` (default
30). `rate_hz` is clamped to 1 .. 1000. Lists are capped at 50 rows and stacks
at 30 frames.

### `cpu_top(pid, duration_s=5, top=10)`

An on-CPU profile like `cpu_profile`, summarised as `top_functions` (by self
samples), next to `wall_seconds`, `cpu_seconds_user`, `cpu_seconds_system`,
`iowait_seconds` and `cpu_pct_of_one_core` for the same window, plus `split`,
`gil` and `os_thread_states`. Compare the two: `pct_of_samples` says where the
running threads were; CPU seconds say how much running there was. A process
whose CPU seconds are near zero is waiting, not computing.

### `cpu_flamegraph(pid, duration_s=10, format="speedscope", include_idle=false, rate_hz=100)`

Runs `py-spy record --format speedscope` (or `flamegraph` for an SVG) into the
snapshot directory and returns `path`, size and sample count. The file's
contents are never returned through MCP: give the path to the user, who opens it
in https://www.speedscope.app or a browser.

### Errors

Errors use the same JSON shape as the heap tools. Codes: `attach_refused` (with
`reason`: `attach_disabled`, `not_allowlisted`, `invalid_argument`,
`no_such_process`, `process_inaccessible`), `py_spy_not_found`,
`permission_denied`, `no_such_process`, `not_python` (no CPython interpreter
found in the process), `timeout`, `bad_output`, `invalid_argument` and
`py_spy_failed`.

### Permissions

py-spy reads another process's memory, which needs the same rights as a
debugger. On Linux, any one of:

- run the server as the target's user with `kernel.yama.ptrace_scope` at 0
  (`sudo sysctl kernel.yama.ptrace_scope=0`); the Ubuntu default of 1 only lets
  a process trace its own children;
- give py-spy `CAP_SYS_PTRACE`: `sudo setcap cap_sys_ptrace+ep "$(which py-spy)"`;
- run the server as root.

In Docker, start the target's container with `--cap-add SYS_PTRACE` (and run
py-spy inside it, or share the PID namespace). In Kubernetes add `SYS_PTRACE` to
`securityContext.capabilities.add`. On macOS py-spy needs root. A refusal comes
back as `permission_denied` with these steps in `hint`; only the user can apply
them.

### Safety of the CPU tools

- **Allowlist.** The CPU tools use the same allowlist as `capture_snapshot`
  (`--allow` / `HEAPSPY_MCP_ALLOW`). It is empty by default, so the CPU tools are
  disabled until the user configures it. A pid that does not match is refused
  with `not_allowlisted`; the server's own pid is refused even with `--allow '*'`.
  With `subprocesses=true`, children of an allowlisted process are sampled too.
- **No `confirm` flag.** `capture_snapshot` needs `confirm=true` because it
  pauses the target and writes a memory image to disk. The CPU tools only read
  stacks and, by default, use `--nonblocking`, so the target is never paused;
  the allowlist is the user's consent to that. `nonblocking=false` and
  `native=true` pause the target for each sample (milliseconds) and are opt-in
  per call.
- **Logging.** Every attach is logged to stderr before py-spy runs: tool, pid,
  process name, the allowlist entry that matched, and the sampling settings;
  profiles also log when they finish.
- **No local variables.** py-spy's `--locals` prints the values of local
  variables. The server never passes it and drops any `locals` field from
  py-spy's output: values can hold credentials, tokens and user data, the same
  reason heapspy does not record string contents by default.
- **Timeouts and cleanup.** `py-spy dump` has a 30 s timeout; `py-spy record`
  gets `duration_s` plus 30 s. On a timeout or failure every py-spy process
  still running is killed and its output file deleted, and the temporary
  directory is always removed.
- **Bounded output.** Thread, frame, row and stack counts are capped as listed
  above; flame graphs are returned as paths only.

### CPU resource and prompt

- Resource `heapspy://workflow/cpu`: when to use CPU tools rather than heap
  tools, the CPU loop, and what the numbers mean.
- Prompt `investigate_cpu(target?)`: the same text, as a starting prompt.
- The server instructions sent at initialisation include the same text after
  the heap workflow.

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
usage errors and oversized reports. The dump report and the analyze report
with allocations come from heapspy branches not merged here yet; copies are in
`tests/fixtures/heapspy/`, whose README names the source commits. The fake also
simulates a heapspy without `dump --json`, `--allocations` and `flamegraph`,
each dump error code, a profile that does not match the snapshot, and a dump
killed while writing.

#### Contract tests against a real heapspy

`tests/test_contract_real.py` runs a real heapspy binary. It is off by
default:

```sh
HEAPSPY_MCP_REAL_BIN=/path/to/heapspy uv run pytest tests/test_contract_real.py
```

It reads `--help` to see whether the binary has `dump --json` and
`--allocations`, and checks the matching behaviour (or the fallback). It
captures a running `/usr/bin/python3.12` (`HEAPSPY_MCP_REAL_PYTHON` overrides
it) and checks the capture, `heap_summary`, `type_detail` and `map_to_source`
on a `__main__` class of a script without a main guard; dumps `sleep`
(`not_python`), a missing pid, a garbage core and a missing core; runs the
allocation tools against a synthetic snapshot and profile in
`tests/fixtures/heapspy/` (the README there has the program that writes them);
and checks that the real dump and allocation reports have every field of the
copied examples. Live captures need ptrace rights and are skipped without
them. Child processes are killed on every path.

No heapspy branch has both features yet, so both were used. Results on the
development VM (Linux 6.18, CPython 3.12.3, run as root):

| binary | passed | skipped |
|---|---|---|
| `feature/dump-json-errors` at 2ae7ec2 (dump --json, no --allocations) | 8 | 1 (allocation report fields) |
| `feature/alloc-join` at b04cc2f (--allocations, no dump --json) | 8 | 1 (dump report fields) |

With the first, captures were parsed from the dump report, `sleep` gave
`not_python`, and the allocation tools gave `allocations_unsupported`. With
the second, captures fell back to the stderr line, dump failures were
`cli_failed`, and the allocation tools returned the numbers the synthetic
files were built with (203 linked objects, 3 of them through exact links).
The `feature/dump-json-errors` head (40c85ed) differs from 2ae7ec2 only in
`tests/e2e/`.

The process diagnostics have parser tests against fixture files from 5.x and
6.x kernels (`tests/fixtures/system/`) and fake cgroupfs trees, mocked
`perf_event_open` paths (success, no PMU, `EACCES`, multiplexing), and live
tests on Linux that start real processes: a CPU-bound loop, more spinning
processes than cores, a lock ping-pong, a process in a cgroup with a 0.2-core
quota (root only; skipped otherwise), and, for the search tools, a CPU burner,
a process with growing RSS, one holding thousands of fds, a parent of zombies
and a lock ping-pong. `uv run pytest -s tests/test_system_live.py` prints the
numbers each scenario measured.

The memory-stall tools have classifier tests against kernel stacks
(`tests/fixtures/system/kernel_stacks.txt`: stacks captured on 6.18, and call
chains of 4.4 to 6.6 for waits the development VM cannot produce, such as
swap-in and `memory.high` throttling), parser tests for v2 and v1
`memory.*`, `vmstat`, `smaps_rollup` and freezer files, fake `/proc` trees for
the sampler, and live tests in `tests/test_stalls_live.py` (root only). They
create their own cgroups and a 256 MiB temporary file, and remove both on
every path. `uv run pytest -s tests/test_stalls_live.py` prints the numbers.

The contention tools have parser tests for `/proc/<pid>/task/<tid>/stat`
field 39, schedstat `pcount`, `/proc/<pid>/sched` from a 6.18 kernel (with
`se.slice`) and a 5.15-style one (without), CPU lists and a fake sysfs cache
tree (`tests/test_contention_parsers.py`); the co-location math on a fake
`/proc` (`tests/test_colocation.py`); the group aggregation
(`tests/test_groups.py`); the fit on exact and degenerate points
(`tests/test_slice_fit.py`); the starvation gating and `short_timeslices`,
including a regression test on the signals of the starved worker from the
blind test (`tests/test_diagnose_contention.py`); and the tools through the
server (`tests/test_contention_tools.py`). The live re-test of the blind
test is described at the end of this file.

The thrash in those tests is file-backed, since the development VM has no
swap: a process maps the file and reads one byte of each page in a fixed
random order inside a memory cgroup limited to 64 MiB. Three things were
needed to make eviction happen. The file's page cache is dropped first with
`POSIX_FADV_DONTNEED`, or its pages stay charged to the cgroup that wrote
them and the scanner never faults. The order is random, because a sequential
scan is served by readahead: most faults then find the page already in cache
(minor faults), and the major-fault count stays low even while the cgroup
refaults gigabytes. And to see threads stop for seconds, a cgroup read limit
on the block device (16 MiB/s) stands in for a slow disk; the VM's disk is
served from the host's cache at more than 1 GB/s, so without it each refault
finishes in microseconds and the thread stays on a CPU, mostly in the
kernel. Results on the development VM (Linux 6.18, 4 cores, cgroup v1 memory
controller with v2 pressure, 5 s windows):

| Scenario | Major faults/s | Refaults/s (cgroup) | Wait categories | Longest no-progress | `diagnose_process` |
|---|---|---|---|---|---|
| (a1) 64 MiB limit | 8700 to 9900 | 250000 | `page_fault_io` 0.50 to 0.62, `running` the rest; `system_share` 0.98; cgroup memory PSI `full` 10 to 17% | none (CPU kept advancing, in the kernel) | `memory_thrashing` first, score 9 |
| (a2) 64 MiB limit and 16 MiB/s reads | 138 | 500 | `page_fault_io` 1.0, state `D` | 1.6 to 1.9 s, `page_fault_io`, stack `folio_wait_bit_common < filemap_fault < __do_fault < ...`; 0.93 to 0.97 s/s in memory waits | `memory_thrashing` first, score 7; `io_pressure` 1 |
| (b) same scan, no limit, file cached | 0 | 0 | `running` 1.0 | none | `memory_thrashing` not indicated (-5); `spin_waiting_or_compute` first |
| (c) CPU-bound loop | 0 | 0 | `running` 1.0 | none | `memory_thrashing` not indicated (-5) |
| (d1) `SIGSTOP` | 0 | 0 | `stopped_or_frozen` 1.0 | the whole window, `stopped_or_frozen` | `deliberately_frozen` true, all moot, `memory_thrashing` -8 |
| (d2) v1 freezer `FROZEN`, v2 `cgroup.freeze=1` | 0 | 0 | `stopped_or_frozen` 1.0 (v1: state `D` in `__refrigerator`) | the whole window, `stopped_or_frozen` | `deliberately_frozen` true, `frozen_by_cgroup_freezer` |

With (a1) running, `scan_processes` put it first on `major_faults_per_s`
(about 9900/s), listed it under `major_faults_whole_window` (lowest interval
9000/s) and its cgroup under `cgroup_memory_pressure_full` (`full` 11 to
12% of the window); `find_processes(sort_by="major_faults_per_s")` put it
first. With (a2), `disk_wait_in_memory_management` listed its thread as
`page_fault_io` from its stack. A frozen cgroup and a stopped process
appeared under `frozen_or_stopped`, and the v1-frozen task in `D` was not
listed as a memory wait.

The CPU tool tests use `tests/fake_pyspy.py` as `py-spy` in the same way. The
integration tests in `tests/test_cpu_integration.py` run the real py-spy against
real Python processes (`tests/cpu_victims.py`: a CPU-bound loop, threads blocked
in `time.sleep` and a socket read, four threads contending for the GIL, and an
`os.fsync` loop). They are off by default:

```sh
uv sync --extra pyspy
HEAPSPY_MCP_PYSPY_TESTS=1 uv run pytest -m pyspy_integration
```

They need ptrace rights (see Permissions) and use `/usr/bin/python3.12`,
`/usr/local/bin/python3.13` and `python3.14` where present; set
`HEAPSPY_MCP_TEST_PYTHONS` (separated by `:`) to choose others.

Results on the development VM (Linux 6.18, py-spy 0.4.3, CPython 3.12.3,
3.13.18 and 3.14.6, 3 s windows, two runs), which matched within noise across
the three versions:

- CPU-bound loop: `burn_cpu` had 100% of on-CPU samples; on-CPU was 100% of
  all samples; `cpu_pct_of_one_core` 99 to 100.
- Threads in `time.sleep` and `socket.recv`: both idle, state S, with
  `kernel_wait` `hrtimer_nanosleep` / `unix_stream_read_generic` and syscall
  `clock_nanosleep` / `recvfrom`; 0.00 CPU seconds and 0 on-CPU samples in 3 s.
- Four threads contending for the GIL: GIL held in 98 to 100% of ticks by 4
  threads in turn, 3.6 to 4.0 threads asleep on a futex on average (the three
  waiting workers and the main thread in `Event.wait`), `contention: likely`;
  on-CPU 20 to 27% and idle 73 to 80% of all samples; `cpu_pct_of_one_core`
  93 to 100, not 400.
- `os.fsync` loop: these numbers are noisy and depend on the VM's disk. The
  thread was in disk wait (D) in 37 to 75% of state samples and running in the
  rest; py-spy flagged 31 to 68% of samples on-CPU, roughly tracking the
  running share; `cpu_seconds_system` was 0.2 to 0.75 of about 3 s wall. Delay
  accounting is off on this VM, so `iowait_seconds` was `null`. In some runs
  `cpu_stacks` showed the thread idle with state R, because it woke up between
  py-spy's read and the `/proc` read.

### Live re-test of the CPU-contention blind test

`tests/test_contention_live.py` (root only, needs a C compiler and 4 CPUs)
re-runs the scenario of a blind test in which an agent, given only "CPU went
to 100% after capacity was halved, and context switches were high", found the
mechanism partly with scripts of its own. It builds `tests/contention_worker.c`
into a temporary directory and starts two services: `api`, 8 workers each
walking a 1.5 MiB working set at 6500 requests/s offered, and `edge`, 4
workers with a 16 KiB working set that sleep on short timers at 20000
requests/s offered. `cores(k)` pins every worker to CPUs 0 to k-1. Each check
takes medians over repeats. `uv run pytest -s tests/test_contention_live.py`
prints the numbers. On the development VM (Linux 6.18, 4 vCPUs, L2 2 MiB per
core, `se.slice` 2.1 ms, shared with other work), over five runs:

| Check | Result |
|---|---|
| `group_cpu` at 2 cores, api | `voluntary_share` 0.002 to 0.039; pooled `avg_timeslice_us` 170 to 327; `runnable_share` 1.0; non-voluntary switches 580 to 1150/s per worker, max/min across workers 1.1 to 33 |
| `group_cpu` at 2 cores, edge | `voluntary_share` 0.998 to 1.0; `avg_timeslice_us` 22 to 28; 3900 to 4600 voluntary switches/s per worker; `runnable_share` 0.67 to 0.73 |
| `cpu_colocation` at 2 cores, api as targets | placement 4+4 api workers in most runs, 5+3 in one; edge split 2+2, 3+1 or 4+0; co-located wakeups 4000 to 17000/s on CPUs with edge workers, 9/s on the CPU without; short-sleeper share 0.998; `target_preemptions_per_colocated_wakeup` 0.26 to 1.01; the top short sleepers are the edge workers |
| `fit_per_slice_cost` over 1, 2 and 4 cores (two orders per run, four runs) | `fixed_cost_per_timeslice_us` 39 to 79 (run medians 70, 71, 43, 56); per request without slicing 25 to 44 us; R squared 0.63 to 0.996 |
| `diagnose_process` on a starved api worker at 2 cores | `cpu_cores_used` 0.17 to 0.29 with `runqueue_wait_ratio` 2.5 to 4.8 and `runnable_share` 1.0; `runqueue_contention` 7, `short_timeslices` 6 (average slice 146 to 168 us of 2100, 5200 to 14000 co-located wakeups/s, short-sleeper share 0.997 to 0.998), `spin_waiting_or_compute` partly consistent with no idle evidence against |
| `cache_sensitivity_probe`, synthetic, CPU 3 | 16 KiB: slowdown 1.09 to 1.12, 11 to 14 us extra per slice; 1.5 MiB: slowdown 1.6 to 5.2, 50 to 111 us extra per slice, at 130 to 139 us slices |

The blind test measured about 70 us of refill per api slice. The fit and the
probe give the same order of magnitude; runs with other load on the VM give
the lower fitted costs and the lower R squared.
