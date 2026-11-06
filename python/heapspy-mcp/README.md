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

The server also has process diagnostics for any process, not only Python: find
or scan processes by measured metrics, then measure one process's CPU,
scheduler behaviour and environment (cgroup, host) over a window, and weigh
competing explanations for its CPU use or slowness. See
[Process diagnostics](#process-diagnostics).

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
| `--max-window SECONDS` | `HEAPSPY_MCP_MAX_WINDOW` | 10 | Cap on every measurement window of the process diagnostics. |
| `--no-host-context` | `HEAPSPY_MCP_NO_HOST_CONTEXT=1` | off | Leave host-wide load, steal and PSI out of the process tools' `environment` block. |
| `--proc-root DIR` | `HEAPSPY_MCP_PROC_ROOT` | `/proc` | procfs to read. |
| `--cgroup-root DIR` | `HEAPSPY_MCP_CGROUP_ROOT` | from `/proc/self/mountinfo` | A cgroup v2 mount to read instead, for example the host's cgroupfs mounted into a container. |
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

`code` is one of the heapspy error codes (`unimplemented`, `invalid_argument`,
`not_found`, `invalid_snapshot`, `io`, `permission_denied`, `internal`), one
added by the wrapper (`binary_not_found`, `timeout`, `usage_error` for exit
status 2, `bad_output` for output that is not JSON, `schema_mismatch`,
`unexpected_kind`, `cli_failed` for a failure with no error document), or
`capture_refused` with a `reason`.

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

## Process diagnostics

Linux only. These tools read `/proc`, cgroup files and, for `hw_counters`,
`perf_event_open(2)`. Every tool is keyed on a process. Host and cgroup
figures appear only as the `environment` of that process: what it is subject
to. The resource `heapspy://process-workflow` and the prompt
`investigate_process_cpu(target?)` describe the loop:

1. Not sure which process? `scan_processes` or `find_processes`.
2. `process_cpu(pid)` for one process and its environment.
3. `hw_counters(pid)` for IPC and cache misses, where a PMU exists.
4. `diagnose_process_cpu(pid)` to weigh explanations against one window of numbers.
5. `snapshot_process_metrics` before and after a change, then
   `compare_process_snapshots`.
6. For Python processes, the heap tools above.

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
  64 per process and 20000 in total in a scan, and 128 threads in
  `hw_counters`; the result says when it truncated.

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

Filters, all optional: `name` (glob on the name or the executable's file
name), `cmdline` (substring), `cmdline_regex`, `user` (name or uid), `pids`,
`parent_pid` with `include_descendants`, `cgroup` (substring of the path),
`container_id` (prefix), `pod_uid`, `state` (`/proc` state letters, e.g. `D`),
`is_python`, `include_kernel_threads`. `window_s=0` gives an instant listing
with the rate metrics `null`. Each row has `pid`, `ppid`, `comm`, `exe`,
redacted `cmdline`, `user`, `state`, `cgroup`, `kubernetes` (pod UID, QoS
class, container id) and `metrics`.

`scan_processes(window_s=2, limit_per_metric=5, fd_threshold_pct=80)` makes
one pass over every process and returns `outliers_by_metric` (the top N for
each metric above) and `conditions`, each with its definition and raw values:

- `disk_wait_whole_window`: threads in state `D` in all 5 samples of the window.
- `zombies_by_parent`: processes in state `Z`, grouped by parent.
- `fd_usage_above_threshold`: open fds above `fd_threshold_pct` of the soft `RLIMIT_NOFILE`.
- `rss_grew_every_sample`: RSS strictly increased between each of the 5 samples.
- `cgroups_throttled_in_window`: cgroups of scanned processes whose `nr_throttled` rose.
- `oom_kill_counters`: cgroups whose v2 `memory.events` `oom_kill` is above 0.

Both read a bounded set of files per process at the start and end of the
window, plus `statm` (and thread states for processes that had threads in `D`)
at three points inside it. Processes that exit mid-scan or cannot be read are
skipped and counted in `skipped`; they never cause an error. Each result has a
`cost` block with the time spent reading `/proc`. Measured on a 4-core VM with
about 1000 processes: 0.29 to 0.34 s of CPU and wall time per call, outside the
window's sleeps.

### `process_cpu(pid, window_s=2, top_threads=5)`

Samples the process and its threads at the start and end of the window and
four times inside it.

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
  number of the process's threads waiting), `timeslices_per_s`,
  `cpu_migrations_per_s` (`se.nr_migrations`, needs `CONFIG_SCHED_DEBUG`).
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

### `diagnose_process_cpu(pid, window_s=2)`

Measures the process, its environment and its hardware counters in one window
and scores these explanations for its CPU use, CPU wait or slowness:

| id | What it describes |
|---|---|
| `runqueue_contention` | runnable threads waiting for a CPU |
| `cache_or_memory_bound_contention` | low IPC with many LLC misses |
| `cfs_throttling` | the cgroup or an ancestor hits its quota |
| `lock_contention` | frequent blocking and waking, mostly in futex |
| `spin_waiting_or_compute` | on CPU, few switches, normal IPC; counters cannot separate the two |
| `gil_convoy` | several Python threads, CPU near one core, frequent hand-offs |
| `steal` | the hypervisor runs other guests on this VM's CPUs |
| `memory_pressure` | memory stalls (PSI) and major faults |
| `io_pressure` | I/O stalls (PSI), iowait, threads in disk wait |

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
| Host runnable per core | `procs_running_per_core` | host-wide CPU contention vs a quota on an otherwise idle host |
| PSI cpu, memory, io | `psi`, `pressure` | CPU vs memory vs I/O stalls, host and cgroup |
| CFS throttling | `cfs_throttled_ratio`, `throttled_seconds_per_s` | quota limits vs host contention |
| Steal | `steal_pct` | hypervisor contention vs guest-side causes |
| IPC, LLC MPKI | `ipc`, `llc_mpki` | memory or shared-cache bound vs compute or spin |
| Wait sites | `wait_sites.share_by_site` | futex vs poll vs block I/O |
| CPU per unit of work | `cpu_seconds_per_unit_work` | efficiency change vs load change |

### Safety and access

All of these tools are read-only.

- `find_processes` and `scan_processes` read the same `/proc` metadata that
  `ps` and `top` show, and are open without the allowlist, so an agent can find
  the process to look at. Command lines are redacted.
- `process_cpu`, `hw_counters`, `snapshot_process_metrics` and
  `diagnose_process_cpu` read one process in depth (its threads' wait
  channels and syscalls, and performance counters attached to it) and follow
  the same `--allow` list as `capture_snapshot`. An unlisted pid is refused
  with `diagnostics_refused` and a reason (`allowlist_empty`,
  `not_allowlisted`, `no_such_process`).
- Host-wide context (load, steal, host PSI) is included by default because it
  is what the process is subject to and it describes no other process. On a
  shared host where that aggregate should not reach an agent, start the server
  with `--no-host-context`. The process's own cgroup is always reported.

### Command-line redaction

Command lines returned by `find_processes`, `scan_processes` and
`list_python_processes` pass through a best-effort filter
(`src/heapspy_mcp/system/redact.py`) before truncation. It replaces with
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
| VM without a PMU | Everything except hardware counters, which are `null` with `no PMU exposed (common in VMs)`; `cache_or_memory_bound_contention` is then `insufficient_signals` | IPC, LLC misses |

Kernel features that change what is available, each reported as a reason when
missing: delay accounting (`kernel.task_delayacct`) for iowait,
`CONFIG_SCHEDSTATS` for `/proc/schedstat`, `CONFIG_SCHED_DEBUG` for
`se.nr_migrations`, PSI (`psi=1`) for pressure files.

See [`deploy/kubernetes/daemonset.yaml`](deploy/kubernetes/daemonset.yaml) for
a node-agent example.

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

The process diagnostics have parser tests against fixture files from 5.x and
6.x kernels (`tests/fixtures/system/`) and fake cgroupfs trees, mocked
`perf_event_open` paths (success, no PMU, `EACCES`, multiplexing), and live
tests on Linux that start real processes: a CPU-bound loop, more spinning
processes than cores, a lock ping-pong, a process in a cgroup with a 0.2-core
quota (root only; skipped otherwise), and, for the search tools, a CPU burner,
a process with growing RSS, one holding thousands of fds, a parent of zombies
and a lock ping-pong. `uv run pytest -s tests/test_system_live.py` prints the
numbers each scenario measured.
