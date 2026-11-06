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
| `--allow-contents` | `HEAPSPY_MCP_ALLOW_CONTENTS=1` | off | Permit `capture_contents=true`. |
| `--max-rss SIZE` | `HEAPSPY_MCP_MAX_RSS` | `8G` | Refuse live capture of processes with a larger RSS. Binary suffixes: `512M`, `8G`, `8GiB`, or plain bytes. |
| `--snapshot-dir DIR` | `HEAPSPY_MCP_SNAPSHOT_DIR` | `~/.cache/heapspy-mcp/snapshots` on Linux, `~/Library/Caches/heapspy-mcp/snapshots` on macOS, `%LOCALAPPDATA%\heapspy-mcp\Cache\snapshots` on Windows | Where captured snapshots are written. Created with mode 0700. |
| `--timeout SECONDS` | `HEAPSPY_MCP_TIMEOUT` | 120 | Timeout for `analyze`, `query` and `diff`. |
| `--capture-timeout SECONDS` | `HEAPSPY_MCP_CAPTURE_TIMEOUT` | 900 | Timeout for `dump`. |
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

The CPU tools attach to live processes too; their gates are described in
[Safety of the CPU tools](#safety-of-the-cpu-tools).

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
usage errors and oversized reports.

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
