# heapspy on the command line

heapspy reads a CPython process's memory from the outside, the way py-spy
reads its stacks: nothing is injected or imported into the target. This page
covers every command, what its output means, and what it costs the process
you point it at. `heapspy --help` and `heapspy <command> --help` print the
same information in short form.

- [Which command to use](#which-command-to-use)
- [What the process pays](#what-the-process-pays)
- [Reading the memory overview](#reading-the-memory-overview)
- [top](#top): live view
- [watch](#watch): growth over time, as plain lines
- [analyze](#analyze): one report, from a process or a file
- [dump](#dump), [record](#record): capture
- [query](#query), [diff](#diff), [flamegraph](#flamegraph): dig into snapshots
- [Global options, output and exit codes](#global-options-output-and-exit-codes)

## Which command to use

| You want to | Run |
|---|---|
| see what a process's memory is and what is growing, live | `sudo heapspy top --pid PID` |
| one readable report, right now | `sudo heapspy analyze --pid PID` |
| know whether it leaks, and what, over minutes or hours, in a log | `sudo heapspy watch --pid PID --every 5m` |
| keep a snapshot to analyze later, elsewhere, or attach to a bug | `sudo heapspy dump --pid PID -o app.hpy` |
| know which code allocated the memory that stays alive | `top --alloc`, or `record` then `analyze --allocations` |
| follow one object or type to what holds it | `heapspy query app.hpy --retaining-path-type T` |

## What the process pays

| What | Stops the process? | Cost |
|---|---|---|
| memory totals (`/proc`) | no | nothing measurable |
| thread stacks (`top` every second, `analyze --pid` once) | no | a few small reads per thread |
| a snapshot (`dump`, `analyze --pid`, every `watch` round, every `top --every`) | **yes**, for the whole walk | from ~100 ms on a small heap to seconds on a heap of millions of objects; the pause is printed |
| a snapshot with `--no-stop` (`dump`, `top`) | no | none, but the result is approximate and a walk can fail |
| allocation sampling, arenas | no | a few percent |
| allocation sampling, large objects | no | ~0.5 µs per `malloc` above 512 bytes; 30–50% on an allocation-heavy benchmark |

Reading another process needs ptrace rights on Linux (`CAP_SYS_PTRACE`, or a
permissive `kernel.yama.ptrace_scope`; in containers `SYS_PTRACE` and a
shared PID namespace) and an elevated prompt on Windows. Allocation sampling
on Linux needs root or `CAP_BPF` and `CAP_PERFMON`. Commands that only read
snapshot files need nothing.

## Reading the memory overview

`analyze` and `top` open with the process's memory split by what it is:

```
Where the 1.91 GiB of resident memory is
  ■ Python objects       448.0 MiB  23%   pymalloc 82.0 MiB · larger objects from malloc 366.0 MiB
  ■ Native, in use       905.0 MiB  46%   malloc'd blocks something still points to
  ■ Native, leaked       118.0 MiB   6%   malloc'd blocks nothing points to
  ■ Allocator free       298.0 MiB  15%   freed by C code, kept by malloc in 16 arenas, not returned to the OS
  ■ Other private         48.0 MiB   2%   allocator overhead, memory C code mapped itself
  ■ pymalloc free         21.0 MiB   1%   empty space in Python's own arenas
  ■ Code, files, stacks  118.0 MiB   6%   libraries 74.0 MiB · mapped files 38.0 MiB · thread stacks 6.0 MiB
```

| Row | What it is | If it is large |
|---|---|---|
| Python objects | objects in the graph: pymalloc's small objects and larger ones from `malloc` | see *What is holding memory* |
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
- **Memory panel**: RSS with its growth per minute, refreshed every second;
  then the overview above, refreshed with each snapshot, with a sparkline
  and a growth rate per row. The right side says how old the split is,
  how long the snapshot stopped the process, and when the next one is.
- **Tabs** (`1`–`5`, Tab):
  1. **Holders**: what holds memory, Python and native together, ranked by
     retained bytes or growth (`s`). Leaked native blocks are a row of their
     own. Below the table: the line most often on thread stacks.
  2. **Types**: count and shallow bytes per type, with growth per minute.
     Sorted by growth by default.
  3. **Native**: native totals, malloc's arenas and free space, leaked
     blocks by size, and the holders that keep native memory.
  4. **Threads**: what each thread runs now, and the frames seen most often
     over the last 10 minutes.
  5. **Allocated**: with allocation sampling, the Python stacks that
     allocated the most and how much of it is still alive.
- **Enter** opens details: a holder's path from its root, a type's largest
  instances and what holds them, a thread's whole stack, an allocation
  stack.

Keys: `↑↓`/`jk` move, `PgUp`/`PgDn`, `Enter` details, `Esc` close, `s` sort,
`d` snapshot now, `w` save the latest snapshot to
`heapspy-PID-TIME.hpy`, `a` start or stop allocation sampling, `space`
pause, `?` help, `q` quit.

| Option | Default | |
|---|---|---|
| `--every DURATION` | `10s` | time between snapshots; memory totals and stacks refresh every second regardless |
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
a snapshot pauses the process longer. `--json` prints one JSON object per
round and a final `watch_summary` object (JSON Lines).

## analyze

```sh
sudo heapspy analyze --pid 1234                  # snapshot now, report, delete the snapshot
sudo heapspy analyze --pid 1234 --keep app.hpy   # ... and keep it
heapspy analyze app.hpy                          # a snapshot file
```

The report has these sections:

1. **Where the memory is**: the overview above.
2. **What is holding memory**: objects ranked by retained size, the bytes
   that would be freed if they went away, split into Python and native, with
   the path from their root and their type.
3. **Biggest types**: count, shallow and retained bytes per type.
4. **Leaked native memory**: leaked blocks grouped by size.
5. **Allocator free**: when malloc keeps a lot of free memory.
6. With `--allocations FILE.hpya`: **Allocated by**, the stacks that
   allocated the most and what each holder's memory was allocated by.
7. With `--pid`: **Threads**, what each thread was running.

`--json` prints the same as a stable document (see
[json-schema.md](json-schema.md)); `--top N` sets the length of the lists.

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

Samples allocations with their Python stacks for a time window. See
[allocation-sampling.md](allocation-sampling.md) for the mechanisms, events
and costs.

## query

```sh
heapspy query app.hpy --type app.session.Session
heapspy query app.hpy --retaining-path 0x7f3a2c41b0d0
heapspy query app.hpy --retaining-path-type Session --top 3
heapspy query app.hpy --locate app.cache.Store.get
```

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

See the [README](../README.md#retention-flame-graph) for how to read a
retention flame graph.

## Global options, output and exit codes

- `--color auto|always|never`: color text output. `auto` colors a terminal
  unless `NO_COLOR` is set.
- Text output is for people and may change between versions. Use `--json`
  (every command but `top` and `flamegraph`) in scripts.
- Exit status 0 on success, 1 on error. With `--json`, an error is also a
  JSON document with a stable `code`, such as `permission_denied`,
  `no_such_process` or `not_python` (see [json-schema.md](json-schema.md)).
