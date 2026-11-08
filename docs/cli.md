# heapspy on the command line

heapspy reads a CPython process's memory from the outside, the way py-spy
reads its stacks: nothing is injected or imported into the target. This page
covers every command, what its output means, and what it costs the process
you point it at. `heapspy --help` and `heapspy <command> --help` print the
same information in short form.

- [Which command to use](#which-command-to-use)
- [What the process pays](#what-the-process-pays)
- [Reading the reports](#reading-the-reports)
- [top](#top): live view
- [watch](#watch): growth over time, as plain lines, or live counters
  ([`--counters`](#live-counters---counters))
- [analyze](#analyze): one report, from a process or a file
- [agent](#agent): continuous memory profiles, sent to Pyroscope
- [dump](#dump), [record](#record): capture
- [query](#query), [diff](#diff), [flamegraph](#flamegraph): dig into snapshots
- [Global options, output and exit codes](#global-options-output-and-exit-codes)

## Which command to use

| You want to | Run |
|---|---|
| see what a process's memory is and what is growing, live | `sudo heapspy top --pid PID` |
| one readable report, right now | `sudo heapspy analyze --pid PID` |
| know whether it leaks, and what, over minutes or hours, in a log | `sudo heapspy watch --pid PID --every 5m` |
| graph memory and the GC every second, or feed your own graphs, without ever pausing the process | `top` (tab 6), or `sudo heapspy watch --pid PID --counters --json` |
| keep memory profiles of production processes over days, in Pyroscope or Grafana | `sudo heapspy agent --server URL --discover NAME` |
| keep a snapshot to analyze later, elsewhere, or attach to a bug | `sudo heapspy dump --pid PID -o app.hpy` |
| know which code allocated the memory that stays alive | `top --alloc`, or `record` then `analyze --allocations` |
| follow one object or type to what holds it | `heapspy query app.hpy --retaining-path-type T` |

## What the process pays

| What | Stops the process? | Cost |
|---|---|---|
| memory totals (`/proc`) | no | nothing measurable |
| thread stacks (`top` every second, `analyze --pid` once) | no | a few small reads per thread |
| counters (`top` every second, `watch --counters`) | no | a 48-byte read per pymalloc pool (64 per MiB of arenas), batched: about a millisecond for tens of MiB, ~30 ms per GiB |
| a snapshot (`dump`, `analyze --pid`, every `watch` round, every `top --every`) | **yes**, for the whole walk | from ~100 ms on a small heap to seconds on a heap of millions of objects; the pause is printed |
| a snapshot with `--no-stop` (`dump`, `analyze --pid`, `top`, `watch`; Linux) | no | none, but the result is approximate and a walk can fail |
| allocation sampling, arenas | no | a few percent |
| allocation sampling, large objects | no | ~0.5 µs per `malloc` above 512 bytes; 30–50% on an allocation-heavy benchmark |

Reading another process needs ptrace rights on Linux (`CAP_SYS_PTRACE`, or a
permissive `kernel.yama.ptrace_scope`; in containers `SYS_PTRACE` and a
shared PID namespace) and an elevated prompt on Windows. Allocation sampling
on Linux needs root or `CAP_BPF` and `CAP_PERFMON`. Commands that only read
snapshot files need nothing.

## Reading the reports

`analyze` and `top` are about **what** is in memory: which objects, how many,
how big, whether they grow, and who keeps them alive. Where the memory
sits (Python's allocator, malloc, libraries) is one bar at the top.

```
Memory 65.0 MiB resident  ███████████████████████████
  ■ Python objects 25.7 MiB 39%   ■ Native, in use 23.9 MiB 37%   ■ Native, leaked 4.6 MiB 7%
  ■ Code, files, stacks 10.0 MiB 15%

What the memory is                mostly held by              count       size     each  keeps alive
  native malloc blocks, in use     98% app.native.BUFFERS      1483   23.5 MiB 16.2 KiB     23.5 MiB
  bytes                            99% app.cache.CACHE        11664   18.7 MiB  1.6 KiB     18.7 MiB
  native malloc blocks, leaked    nothing: leaked              1272    4.6 MiB  3.7 KiB      4.6 MiB
  bytearray                       100% …EGISTRY.listeners       282    2.2 MiB  8.1 KiB      2.2 MiB
  interpreter internals           the interpreter itself       1120  964.5 KiB    881 B    964.5 KiB
  app.cache.Session               100% app.cache.CACHE         9340  875.6 KiB     96 B     20.1 MiB

Who holds it                                                    retained    python    native   share
 1  app.native.BUFFERS                                          23.5 MiB  14.9 KiB  23.4 MiB   47.3%
      list · 751 objects · holds native malloc blocks, in use 23.5 MiB
 2  app.cache.CACHE                                             20.8 MiB  20.8 MiB         0   42.0%
      dict · 46534 objects · holds bytes 18.7 MiB, str 1.0 MiB, app.cache.Session 875.6 KiB
```

**What the memory is** has one row per type, by the bytes its objects take
themselves (`size`), and next to it the holder that keeps most of them
alive and the share it keeps. The interpreter's own objects (code, classes,
descriptors, modules) are folded into one `interpreter internals` row; in
`top`, one that grows keeps its own row, and `i` lists them all. Native `malloc` blocks are rows too, split into blocks
something points to and leaked blocks nothing points to. `keeps alive` is
what the objects retain, themselves included. `mostly held by` names the
holder that keeps most of them alive, and how much of them.

Holders are named the way code names them. A pointer in a library's C
globals is named by the global when the library has a symbol table
(`libfoo.so: g_cache`, `python3.13: _PyRuntime`). A pointer in a Python
object's own C struct reads as `C field +offset` after the object's type
(`[<index>] ctypes.c_char_Array_32768 → C field +16`), and a chain of raw
pointers through native blocks as `→ C memory`. The interpreter's own
holders (libpython's C globals, interpreter state, code objects) are one
`the interpreter itself` entry; holders with less than 1% of a type's bytes
are `smaller holders`.

**Who holds it** lists the objects that keep the most memory alive (their
retained size: what would be freed if they went away), split into Python
and native bytes. Holders are named the way code names them:
`sys.modules['app.cache'].__dict__['CACHE']` is `app.cache.CACHE`. Under
each, the kinds of objects it is the main holder of.

The bar's kinds of memory:

| Row | What it is | If it is large |
|---|---|---|
| Python objects | objects in the graph: pymalloc's small objects and larger ones from `malloc` | see *What the memory is* and *Who holds it* |
| Native, in use | `malloc` blocks that a Python object, another block, a C global or a stack points to: numpy buffers, C extension state | the holders table splits each holder into Python and native bytes; native-only holders show as `libfoo.so globals` or `thread N stack` |
| Native, leaked | `malloc` blocks nothing points to: their address is gone, so nothing can free them | a C-level leak. Blocks of one size usually mean one leak site. Watch it grow in `top`; `record --events native` (Windows) records who allocates them |
| Allocator free | free chunks and the unused top of glibc's heaps | fragmentation, often from many threads. `MALLOC_ARENA_MAX=2` or a periodic `malloc_trim(0)` usually returns it |
| Other private | private memory outside any heap block | memory mapped directly by C code, or another allocator (jemalloc, tcmalloc, mimalloc: their heaps are not walked) |
| pymalloc free | empty space in Python's arenas | normal after a burst of small objects |
| Code, files, stacks | libraries, mapped files, thread stacks | rarely the problem |

The native rows need a heap walk, which heapspy does for glibc's `malloc` on
Linux (and the Windows heap from a minidump). Without one, the native rows
are one `Native (not walked)` row. Free memory is sized from chunk headers
and capped by what is resident, so it is an upper bound.

## top

```sh
sudo heapspy top --pid 1234
```

A full-screen view that keeps refreshing:

- **Header**: pid, Python version, command line, run time, `● live`.
- **Memory line**: RSS with its growth per minute, refreshed every second,
  and how old the last snapshot is and how long it stopped the process.
  Under it, one bar of the kinds of memory, each with its growth (`▲`).
- **Tabs** (`1`–`6`, Tab):
  1. **Objects** (the default): what the memory is, one row per type and
     native blocks in use and leaked, with count, size, growth per minute,
     a trend, and the holder that keeps most of them. `s` sorts by size,
     growth or count.
  2. **Holders**: who keeps memory alive, Python and native together, by
     retained bytes or growth, and what each holds. Leaked native blocks
     are a row of their own.
  3. **Native**: native totals, malloc's arenas and free space, leaked
     blocks by size, and the holders that keep native memory.
  4. **Threads**: what each thread runs now, and the frames seen most often
     over the last 10 minutes.
  5. **Allocated**: with allocation sampling, the Python stacks that
     allocated the most and how much of it is still alive.
  6. **Graphs**: [counters](#live-counters---counters) read every second
     without stopping the process. One chart of RSS, pymalloc's arenas,
     the Python objects in them and glibc malloc's heaps; one of the GC's
     generation 0 count against its threshold (it climbs with allocations
     and drops at each collection), titled with the collections in the
     window; and the numbers now, with their change per minute, the
     arenas, the busiest size classes and the GC counts. `s` cycles the
     window: 1, 5, 15 or 30 minutes.
- **Enter** opens details. On an object row: what keeps those objects
  alive, grouped by holder, with the path from each holder to them and
  their sizes (`92% app.cache.CACHE 2081 B ×660, through [<key>]
  app.cache.Session → .payload`), then their sizes, largest instances and
  direct referrers; this is `heapspy query --type` on the latest snapshot.
  Elsewhere:
  a holder's path from its root, a thread's whole stack, an allocation
  stack.

Keys: `↑↓`/`jk` move, `PgUp`/`PgDn`, `Enter` details, `Esc` close, `s` sort
(on Graphs: the window),
`d` snapshot now, `w` save the latest snapshot to
`heapspy-PID-TIME.hpy`, `a` start or stop allocation sampling, `i` list
interpreter internals type by type, `space`
pause, `?` help, `q` quit.

| Option | Default | |
|---|---|---|
| `--every DURATION` | `10s` | time between snapshots; memory totals, stacks and counters refresh every second regardless |
| `--no-stop` | off | never stop the process; snapshots are approximate |
| `--max-pause DURATION` | none | stop scheduled snapshots while the last one paused the process longer (`d` still works) |
| `--alloc` | off | start allocation sampling at once |
| `--alloc-for DURATION` | `60s` | how long sampling runs before it stops by itself |
| `--alloc-events KINDS` | `arena,large` | as `record --events` |
| `--top N` | `50` | rows per table |

Growth rates compare the newest snapshot with the oldest one in the last
10 minutes. They need two snapshots, so the Δ columns show `—` at first.

**Allocation sampling in `top`** uses eBPF on Linux and ETW on Windows only.
`heapspy record` can fall back to ptrace or a debugger, but both stop the
target, which a monitor must not do without being asked. Sampling runs for
`--alloc-for`, then the next snapshot is joined with the samples. ALLOCATED
is the estimated bytes each stack allocated while sampling; ALIVE is the
bytes of its sampled allocations still in the snapshot.

## watch

```sh
sudo heapspy watch --pid 1234 --every 30s
```

Takes a snapshot every `--every` and prints one line per round:

```
time           RSS     python     native     leaked      Δ RSS   pause  grew most since the last round
0:00     349.4 MiB  153.1 MiB  152.0 MiB   28.7 MiB   baseline   982ms
0:30     379.1 MiB  166.3 MiB  165.4 MiB   31.2 MiB  +29.7 MiB  1063ms  sys.modules['app.native'].__dict__['BUFFERS']  +13.4 MiB (+430 objects)
```

On Ctrl-C, or after `--rounds N`, it prints each holder's growth over the
whole run with a verdict:

| Verdict | Means |
|---|---|
| grew in N/N rounds → likely leak | grew in at least 80% of rounds |
| grew in k/N rounds → keep watching | grew, but not steadily: a cache warming up, batches |
| flat → fine, shrank → fine | |

The first and the latest snapshot stay in `--dir` (default `watch-PID`),
ready for `heapspy diff`. With `--max-pause`, the interval doubles whenever
a snapshot pauses the process longer. `--json` prints one `watch_round`
object per round and a final `watch_summary` object (JSON Lines; see
[json-schema.md](json-schema.md#watch-json-lines)).

`--no-stop` (Linux) takes the snapshots while the process runs, so it is
never paused. The walk races with the program, so a round can miss objects
or count some twice, and a growth in every round can be noise: no holder is
then called a likely leak (the best is `keep watching`), the summary says
so, and every JSON object has `"approximate": true`.

### Live counters (`--counters`)

```sh
sudo heapspy watch --pid 1234 --counters                 # a line a second
sudo heapspy watch --pid 1234 --counters --every 250ms
sudo heapspy watch --pid 1234 --counters --json | your-grapher
```

No snapshot is taken. Each round reads counters that CPython and glibc keep
about their own memory, while the process runs: about a millisecond for a
heap of tens of MiB, ~30 ms per GiB of pymalloc arenas (`took_ms` in the
JSON):

```
time            RSS      Δ RSS     python   pymalloc     malloc  gc
0.0s       12.4 MiB   baseline    3.6 MiB    4.0 MiB  896.0 KiB  gen0 121/700
0.5s       14.2 MiB   +1.7 MiB    4.9 MiB    6.0 MiB    1.0 MiB  gen0 126/700
1.0s       15.9 MiB   +1.8 MiB    6.3 MiB    7.0 MiB    1.0 MiB  gen0 131/700 · 1 collection
```

| Column | What it is |
|---|---|
| RSS | resident memory, from the OS (Windows: the working set) |
| python | bytes of the blocks pymalloc has handed out: Python objects of 512 bytes or less (most of them), and small buffers. Larger objects come from malloc |
| pymalloc | pymalloc's arenas (1 MiB each): what it holds from the OS. The difference from `python` is free space inside them |
| malloc | glibc malloc's heaps (the brk heap and thread arenas), by their headers. Allocations of 128 KiB and more get their own mapping and are not in it (Linux only) |
| gc | generation 0's count and threshold: tracked objects allocated minus freed since the last collection; a collection runs when the count passes the threshold. Then the collections since the last line |

Nothing here follows a pointer from one object to another, which is what
makes a snapshot of a running process approximate: each counter is a word
read on its own, and a value that changes during the read is dropped.
Counters are still read a few microseconds apart, so samples say
`"approximate": true`. They say how memory moves, not who holds it: there
are no holders and no verdicts. On Ctrl-C (or after `--rounds`) the summary
gives each series' value now, change, change per minute, low and high, and
the GC's collections and freed objects over the run.

`--json` prints one `sample` object per round, flushed as it is taken, and
a `watch_counters_summary` at the end (see
[json-schema.md](json-schema.md#watch-json-lines)). When the reader goes
away (`| head`), `watch` stops quietly. `--every` defaults to `1s` here;
`--dir`, `--max-pause`, `--top` and `--no-stop` do not apply.

| Option | Default | |
|---|---|---|
| `--every DURATION` | `30s`, or `1s` with `--counters` | time between rounds |
| `--rounds N` | until Ctrl-C | stop after N rounds |
| `--counters` | off | sample counters instead of taking snapshots |
| `--no-stop` | off | take snapshots without stopping the process (Linux) |
| `--max-pause DURATION` | none | double the interval when a snapshot pauses the process longer |
| `--dir DIR` | `watch-PID` | where the first and the latest snapshot are kept |
| `--top N` | `10` | rows in the summary |
| `--json` | off | JSON Lines instead of text |

## agent

```sh
sudo heapspy agent --server http://pyroscope:4040 --pid 1234
sudo heapspy agent --server http://pyroscope:4040 --discover gunicorn --tag env=prod
sudo heapspy agent --server http://pyroscope:4040 --pid 1234 --memory --retained --alloc
```

Runs until Ctrl-C (or until every watched process has exited), collecting
memory profiles and sending them to [Pyroscope](https://grafana.com/oss/pyroscope/)
(or Grafana Cloud Profiles). There they are flame graphs you can scrub
through time, compare between two moments, and filter by label, next to the
CPU profiles of the same service.

Each kind of profile is opt-in, and none of them stops the process unless
you ask:

| Flag | Profile in Pyroscope (`heapspy_profile`) | What it shows | Cost to the process |
|---|---|---|---|
| `--memory` (the default when none is chosen) | `memory` · `inuse_space` bytes (`memory`) | where the memory is, as one stack per kind: Python objects by pymalloc block size, free space inside pymalloc, glibc malloc's heaps, and the rest of RSS (code, stacks, buffers of 128 KiB and more). The slices add up to RSS | never stopped: [counters](#live-counters---counters), every `--memory-every` (15s) |
| `--retained` | `memory` · `inuse_space` bytes (`retained`) | who holds the memory: the [retention flame graph](#flamegraph) of a snapshot, every `--retained-every` (5m). Labelled `heapspy_snapshot=approximate` or `stopped` | not stopped (Linux): the snapshot is approximate. `--stop` takes exact snapshots and pauses the process for each walk |
| `--alloc` | `memory` · `alloc_space` bytes (`allocations`) | what allocated memory: Python stacks of sampled allocations, during a window of `--alloc-for` (30s) every `--alloc-every` (5m) | never stopped: eBPF on Linux (root or `CAP_BPF` and `CAP_PERFMON`), ETW on Windows (elevated). A few percent while a window runs |

**Which processes.** `--pid` (repeatable) watches given processes; a pid
that is not a CPython heapspy can read is an error. `--discover TEXT`
reads the process list every 10 seconds and picks up every CPython process
whose command line contains TEXT, ignoring case (on Windows, whose
executable name does), including those that start later. A process that
exits is let go. One agent per host or container is enough.

**Labels.** Every profile has `service_name` (`--app-name`, else the
script's or module's name: `app/server.py` → `server`, `-m uvicorn` →
`uvicorn`), `pid`, `hostname`, and each `--tag KEY=VALUE`. Keys use
letters, digits and `_`, as Pyroscope requires.

**Sending.** Profiles are pprof, pushed to `/push.v1.PusherService/Push`,
the endpoint Grafana Alloy uses. One thread sends, so collecting never
waits for the network. When the server cannot be reached (or answers 429
or 5xx), profiles wait in memory, at most 512, and are tried again with a
growing delay up to a minute; the agent says so once a minute. A refusal
(401, 400) drops the profile and says why. On exit the agent prints how
many it sent and dropped.

**Credentials** come from the environment, so they never show in `ps`:

```sh
# Grafana Cloud: the stack's Profiles user id and an access policy token
export HEAPSPY_PYROSCOPE_PASSWORD=glc_...
sudo -E heapspy agent --server https://profiles-prod-001.grafana.net \
    --basic-auth-user 123456 --discover myapp
# A bearer token, for a proxy in front of Pyroscope
export HEAPSPY_PYROSCOPE_TOKEN=...
```

`--tenant-id` sets `X-Scope-OrgID` for a multi-tenant Pyroscope.
`HEAPSPY_PYROSCOPE_HEADERS`, a JSON object (`{"X-Name": "value"}`), adds
headers to every request.

`--memory` and `--retained` share one profile type, so that Grafana
graphs both in bytes (it graphs any type it does not know as bytes per
second). Filter on `heapspy_profile` to see one of them: a query of
`memory:inuse_space` with both on and no such filter adds them up.

**In Grafana**, add Pyroscope as a data source and query the profile types
above, filtered on `service_name` and `heapspy_profile`, e.g.
`{service_name="shop", heapspy_profile="memory"}`. All three are gauges
or windows, not counters, and Pyroscope adds up every profile that falls
in a time step or in a flame graph's range. So:

- in a time series panel, each point should be one reading: set the
  query's min interval to the agent's interval for that profile
  (`--memory-every`, `--retained-every`). Grafana never steps below the
  data source's **Minimal step** (15s by default, as is `--memory-every`):
  for a shorter `--memory-every`, lower it to match. A longer range forces
  wider steps, and each point is then the sum of several readings;
- a flame graph over a range is the sum of the profiles in it: read its
  proportions, or narrow the range (a panel's relative time) for one
  reading's bytes. A profile is stamped when its reading starts, and a
  snapshot or an allocation window arrives when it ends, so give those a
  relative time of about twice their interval.

A profile that takes longer than its interval skips the readings it
missed, so profiles stay one interval apart.

**Before sending anything,** `--dry-run DIR` writes each profile as
`DIR/NNNNNN-PID-KIND.pprof` with its labels in a `.json` next to it, and
`--once` collects one round from each process and exits. The files open
in `go tool pprof`.

| Option | Default | |
|---|---|---|
| `--server URL` | | Pyroscope's base URL (`http://` or `https://`) |
| `--dry-run DIR` | | write profiles to DIR instead of sending them |
| `--pid PID` | | a process to watch, repeatable |
| `--discover TEXT` | | watch CPython processes whose command line contains TEXT |
| `--app-name NAME` | script or module name | `service_name` |
| `--tag KEY=VALUE` | | a label for every profile, repeatable |
| `--memory`, `--memory-every` | on, `15s` | where the memory is |
| `--retained`, `--retained-every` | off, `5m` | who holds it |
| `--stop` | off | stop the process for each retained snapshot |
| `--alloc`, `--alloc-every`, `--alloc-for` | off, `5m`, `30s` | what allocated it |
| `--alloc-events KINDS` | `arena,large` | as `record --events` |
| `--basic-auth-user USER` | | basic auth; password from `HEAPSPY_PYROSCOPE_PASSWORD` |
| `--tenant-id ID` | | `X-Scope-OrgID` |
| `--once` | off | one round, then exit |

A heapspy built without the `tls` Cargo feature (on by default) sends only
to `http://` servers.

### From Python: `heapspy.configure()`

The `heapspy` package also has a Python module with the interface of
Pyroscope's Python client (`pyroscope-io`): the application starts the
agent for itself, with the same call it would make to `pyroscope.configure`.

```python
import heapspy

heapspy.configure(
    application_name="checkout",            # service_name
    server_address="http://pyroscope:4040",
    tags={"env": "prod", "region": "eu-west-1"},
    # Grafana Cloud: basic_auth_username="123456", basic_auth_password="glc_...",
    # tenant_id="team-a", http_headers={"X-Name": "value"},
    # heapspy's own profiles, keyword only; memory is on, the rest opt-in:
    retained=True, retained_interval=300,   # who holds it (approximate)
    # stop=True,                            # exact snapshots, pausing the process
    # alloc=True, alloc_interval=300, alloc_duration=30,  # needs eBPF / ETW
)
...
heapspy.shutdown()                          # also runs at exit
```

`configure()` starts `heapspy agent --pid <this process>` as a child
process, with the arguments translated: `upload_interval` (seconds, 15) is
`--memory-every`, `tags` are `--tag`s, and the password and `http_headers`
go through the environment (`HEAPSPY_PYROSCOPE_PASSWORD`,
`HEAPSPY_PYROSCOPE_HEADERS`), not the command line. Nothing runs inside the
interpreter. The agent's messages go to the `heapspy` logger with
`enable_logging=True`. Calling `configure()` again replaces the agent;
`shutdown()` stops it after it sends what it collected, and the agent also
exits when the process does. `is_running()` says whether it is running.

`pyroscope.configure`'s CPU options (`sample_rate`, `oncpu`, `gil_only`,
`report_thread_id`, ...) are accepted and ignored, so `import heapspy as
pyroscope` runs unchanged; every profile has a `pid` label, as with
`report_pid`. The two can run side by side: Pyroscope for CPU, heapspy for
memory, under the same `application_name`.

The agent reads this process from outside, so it needs the same permission
as `heapspy agent --pid` run by the same user. Under Yama's
`ptrace_scope` 1 (Ubuntu's default), a process may only read its
descendants; `configure()` names the agent as the process allowed to read
this one (`prctl(PR_SET_PTRACER)`). Scope 2 needs `CAP_SYS_PTRACE`.

A process started by `fork()` (a gunicorn or multiprocessing worker) is
not the one the agent watches: call `configure()` in each worker, e.g.
from gunicorn's `post_fork` hook. The binary is found next to the module
(the package's script), on `PATH`, or at `$HEAPSPY_BIN`.

## analyze

```sh
sudo heapspy analyze --pid 1234                  # snapshot now, report, delete the snapshot
sudo heapspy analyze --pid 1234 --keep app.hpy   # ... and keep it
heapspy analyze app.hpy                          # a snapshot file
```

The report has these sections (see [Reading the reports](#reading-the-reports)):

1. **Memory**: one bar of the kinds of memory.
2. **What the memory is**: objects by type, native blocks in use and
   leaked, with what holds most of each.
3. **Who holds it**: the holders that keep the most alive, Python and
   native bytes, and what they hold.
4. **Leaked native memory**: leaked blocks grouped by size.
5. **Allocator free**: when malloc keeps a lot of free memory.
6. With `--allocations FILE.hpya`: **Allocated by**, the stacks that
   allocated the most and what each holder's memory was allocated by.
7. With `--pid`: **Threads**, what each thread was running.

`--json` prints the same as a stable document (see
[json-schema.md](json-schema.md)); `--top N` sets the length of the lists.
`--no-stop` (with `--pid`, Linux) takes the snapshot without stopping the
process: the report is approximate, and its header says `not stopped,
approximate`.

## dump

```sh
sudo heapspy dump --pid 1234 -o app.hpy
heapspy dump --core core.1234 -o app.hpy
heapspy dump --minidump app.dmp -o app.hpy
sudo heapspy dump --pid 1234 --no-stop -o approx.hpy
```

Writes a snapshot: the object graph, native heap blocks and the memory map.
Strings and bytes are not recorded unless `--capture-contents` (capped by
`--max-str`). `--no-stop` (Linux) walks the process while it runs: use it
when even a short pause is not an option, and read the result as
approximate.

## record

```sh
sudo heapspy record --pid 1234 --duration 60s -o app.hpya --then-dump app.hpy
heapspy analyze app.hpy --allocations app.hpya
```

Samples allocations with their Python stacks for a time window, without
running code in the target, and writes an allocation profile (`.hpya`).
Joined with a snapshot, it says which code allocated the memory that is
still alive.

Options: `--events arena,pool,large,native`, `--interval BYTES` (mean bytes
between large-object samples, default 512K), `--max-frames N` (default 64),
`--mechanism auto|ebpf|ptrace|etw|debugger`. Ctrl-C ends a recording early
with a valid profile flagged truncated.

| Mechanism | Needs | Records | Cost |
|---|---|---|---|
| Linux eBPF (default) | root or `CAP_BPF` + `CAP_PERFMON`, kernel 5.8+ | arenas from `mmap`, sampled large objects from allocator uprobes, Python stack read in the kernel | arenas: a few percent; large objects: one uprobe trap per allocator call above 512 bytes (~0.5 µs), 30–50% on an allocation-heavy benchmark |
| Linux ptrace (fallback) | ptrace rights | arenas only, exact stacks | stops the target at system calls |
| Windows ETW (default) | an elevated prompt | arenas with approximate frames; `--events native` for the C heap after `--prepare` | does not stop the target |
| Windows debugger | an elevated prompt | exact frames | stops the target's threads for most of the window |

Pools are never recorded: pool carving is inlined in every build checked. On
Windows, if heapspy is killed while recording, a guardian process restores
the target and stops heapspy's ETW session (see [windows.md](windows.md#when-heapspy-is-killed)).

`analyze --allocations` and `query --type --allocations` link each snapshot
object to the latest sample whose range contains it, and add the stacks that
allocated the most and, under each holder, the stacks that allocated what it
retains. Read the numbers as an estimate of where growth came from:

- Only allocations made while recording are covered. Memory allocated
  before, and blocks reused from freed memory, have no stack.
- Links through large-object samples are exact. Links through arena and pool
  samples are approximate (marked `approx`): they name the growth event that
  created the memory, not necessarily the call that allocated the object.
- A profile from another pid or CPython version, or one that started after
  the snapshot, links nothing, with a warning.

Design, events and measurements: [allocation-sampling.md](allocation-sampling.md).

## query

```sh
heapspy query app.hpy --type app.session.Session
heapspy query app.hpy --type native.heap_block      # who keeps native blocks, and how
heapspy query app.hpy --retaining-path 0x7f3a2c41b0d0
heapspy query app.hpy --retaining-path-type Session --top 3
heapspy query app.hpy --locate app.cache.Store.get
```

`--type` groups the instances by what keeps them alive: the holder whose
dominator subtree they are in, the most common path from it to them, and
their sizes. Instances nothing reaches are their own group (leaked for
native blocks). Then come their sizes, the largest instances, and the direct
referrers.

## diff

```sh
heapspy diff before.hpy after.hpy
```

Growth by type and by retaining site. Addresses change between snapshots,
so objects are matched by type and path, and the result is aggregates.

## flamegraph

```sh
heapspy flamegraph app.hpy -o app.svg
heapspy flamegraph --diff before.hpy after.hpy -o grew.svg
heapspy flamegraph --allocations app.hpya --retained app.hpy -o alive.svg
```

How to read them, the frame format and the cutoffs: [flamegraph.md](flamegraph.md).

## Global options, output and exit codes

- `--color auto|always|never`: color text output. `auto` colors a terminal
  unless `NO_COLOR` is set.
- Text output is for people and may change between versions. Use `--json`
  (every command but `top` and `flamegraph`) in scripts.
- Exit status 0 on success, 1 on error. With `--json`, an error is also a
  JSON document with a stable `code`, such as `permission_denied`,
  `no_such_process` or `not_python` (see [json-schema.md](json-schema.md)).
