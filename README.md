# heapspy

Read the object graph of a running Python process from the outside, and find out what is keeping memory alive.

py-spy reads a process's stacks without touching it. heapspy does the same for the heap: it takes a consistent memory image of a CPython process, rebuilds the object graph from it, and computes dominators and retained sizes. Nothing is injected or imported into the target.

> **Status: design stage.** No code exists yet. This README describes what heapspy is meant to do and how it will be used. Commands below are the planned interface and will not work until the first milestones land.

## What it answers, and what it doesn't

heapspy answers **"what is retained, and by whom?"** For a leak, that is usually the question that matters: the reference holding the memory is the thing you delete to fix it, and that reference is sitting in the heap right now. Eclipse MAT finds JVM leaks the same way, from heap dumps with no allocation stacks.

heapspy cannot answer **"where was this allocated?"** for memory that already exists. That history is only recorded if a tracer was running at allocation time. If you need allocation call chains, use tracemalloc or memray from process start. For CPU and allocation churn, use py-spy alongside heapspy.

## How it works

```
target Python process        untouched, no agent
        |
        |  heapspy dump        privileged, read-only
        v                      Linux: gcore / process_vm_readv
snapshot.hpy                   Windows: full minidump / ReadProcessMemory
        |
        |  heapspy analyze / query / diff     unprivileged, file only
        v
dominator tree, retained sizes, type histogram, retaining paths, diffs
```

`dump` is the only step that touches the target and the only step that needs privileges. It locates `PyRuntime` in libpython (or `python3xx.dll`), walks the GC generation lists to find every tracked container, follows each object's references the way its `tp_traverse` would, and writes a compact binary snapshot.

Everything else reads the snapshot file. You can re-analyze without re-dumping, attach a snapshot to a bug report, or diff two captures taken an hour apart.

## Planned usage

### Capture a snapshot

```sh
# Dump a live process (brief pause while the image is taken)
heapspy dump --pid 1234 -o app.hpy

# Or convert an image you already have
heapspy dump --core core.1234 -o app.hpy      # Linux ELF core
heapspy dump --minidump app.dmp -o app.hpy    # Windows full minidump
```

By default the snapshot records types, sizes, lengths, and references, but **not** string or bytes contents. Contents often hold tokens, credentials, and user data. To include them, opt in explicitly; values are size-capped and redacted:

```sh
heapspy dump --pid 1234 --capture-contents --max-str 128 -o app.hpy
```

### Find what retains memory

```sh
heapspy analyze app.hpy
```

Example output (illustrative):

```
Top retainers by retained size

  retained   shallow   type                  root path
  412.6 MiB  36.9 MiB  builtins.dict         sys.modules['app.cache'].__dict__['CACHE']
   18.2 MiB   1.1 KiB  app.events.Registry   sys.modules['app.events'].__dict__['REGISTRY']
    4.0 MiB  12.0 KiB  builtins.list         frame worker:run -> local 'pending'

Python graph accounts for 448 MiB of 1.9 GiB RSS. The rest is outside the
object graph (native allocations, C extensions, untracked objects).
```

### Drill into a type or object

```sh
# All instances of a type, with sample holders
heapspy query app.hpy --type app.session.Session

# The labelled chain of references keeping one object alive
heapspy query app.hpy --retaining-path 0x7f3a2c41b0d0
```

A retaining path reads root-first, one labelled hop per line:

```
sys.modules['app.cache']
  .__dict__['CACHE']            builtins.dict
  ['user:8812']                 app.session.Session
  .payload                      builtins.bytes  (1.0 MiB)
```

### Compare two captures

```sh
heapspy dump --pid 1234 -o before.hpy
# ... let the process run ...
heapspy dump --pid 1234 -o after.hpy

heapspy diff before.hpy after.hpy
```

`diff` reports growth by type and by retaining site. Object addresses change between dumps, so matching individual objects across snapshots is approximate. The output says so and reports aggregates.

### JSON output

Every analysis command takes `--json`. The schema is versioned and kept stable, since tooling (including the MCP server below) builds on it.

```sh
heapspy analyze app.hpy --json | jq '.top_retainers[0]'
```

## Permissions

Dumping another process needs elevated rights. Analysis does not.

| OS      | `dump` needs                                                                 |
|---------|------------------------------------------------------------------------------|
| Linux   | `CAP_SYS_PTRACE`, or a permissive `kernel.yama.ptrace_scope`. In containers: `SYS_PTRACE` and a shared PID namespace. |
| Windows | `SeDebugPrivilege` (run elevated) to read another user's process.            |

Taking the image pauses the target. On a large heap, expect a pause of a few seconds and a multi-gigabyte image file.

## Supported targets (v1)

| | v1 | Later |
|---|---|---|
| OS | Linux, Windows | macOS |
| CPython | 3.12, 3.13, 3.14 | free-threaded builds |
| Acquisition | consistent dump (ELF core, full minidump) | live attach with a brief stop |
| Graph | GC-tracked containers and the leaf objects they reference | full pymalloc arena walk |
| Native memory | totals only, from memory maps | per-allocation detail |

Out of scope for v1: allocation call chains, per-object native or C-extension memory, leaks made only of untracked objects, reads with no pause, and runtimes other than CPython.

## Known blind spots

- **Untracked objects.** Bare ints, short strings, and raw buffers are not on the GC lists. heapspy sees them only when a tracked container references them. A leak made entirely of floating untracked objects will not show up in v1, and the output will say so.
- **Native memory.** Memory allocated by C extensions is invisible to the object graph. heapspy reports how much of RSS falls outside the graph rather than guessing.
- **Struct layouts.** CPython's internal layouts change between versions and builds. heapspy uses DWARF or PDB symbols when available, 3.14's debug offsets section where present, and shipped per-version offset tables otherwise.

## Agent integration: heapspy-mcp

A second package, `heapspy-mcp`, will expose heapspy to coding agents over the Model Context Protocol. It shells out to the `heapspy` binary and parses `--json`. The intended loop: capture a snapshot, summarize it, pick a suspect, trace what retains it, map the holder to `file:line` in your repo, read the code, diagnose.

Planned tools:

| Tool | Purpose |
|---|---|
| `list_python_processes` | candidate PIDs with RSS, command line, Python version |
| `capture_snapshot` | dump a PID or ingest a core/minidump (privileged, requires confirmation) |
| `heap_summary` | top retainers and type histogram |
| `retaining_path` | the chain keeping an object or type alive |
| `type_detail` | instances, sizes, sample holders for one type |
| `diff_snapshots` | growth between two captures |
| `map_to_source` | resolve `module.qualname` to `file:line` |

`capture_snapshot` is the only tool that touches a process, and it is gated by confirmation, a process allowlist, and a heap-size limit. The other tools only read snapshot files. Tools return bounded, ranked summaries. The raw graph is never sent to the model, both to keep token use down and to keep memory contents out of transcripts.

## Installation (planned)

heapspy will be a Rust binary distributed as PyPI wheels, the same way py-spy is:

```sh
pip install heapspy
pip install heapspy-mcp   # optional, for agent integration
```

## Roadmap

| Milestone | Deliverable |
|---|---|
| M1 | Linux core dump reader to snapshot, proven on one `gcore` of a 3.12 process |
| M2 | Analyzer: dominators, retained sizes, histogram, retaining paths, `--json`, property tests |
| M3 | Linux end-to-end test matrix (3.12 to 3.14) passing in CI |
| M4 | Windows minidump backend |
| M5 | Windows end-to-end test matrix passing on `windows-latest` |
| M6 | `heapspy-mcp` |

The end-to-end tests run heapspy against fixture processes with known leaks (an unbounded module-level cache, a listener registry that never shrinks, a closure holding a large object, and others) and check that the analyzer names the right holder, reports a retained size within tolerance, and produces the expected retaining path.

## License

MIT. See [LICENSE](LICENSE).
