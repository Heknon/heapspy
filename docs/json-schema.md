# JSON report schema, version 1

`heapspy dump`, `record`, `analyze`, `query` and `diff` print a JSON
document on stdout when given `--json`. This is the machine interface that tooling (including
`heapspy-mcp`) binds to. The Rust definitions are in
`crates/heapspy-analyzer/src/report.rs`. Complete example documents are in
`docs/examples/`; a test (`crates/heapspy-analyzer/tests/examples.rs`) checks
that each example matches the structs field for field.

## Rules

- Every document has `"schema_version": 1` and a `"kind"`:
  `"dump"`, `"record"`, `"analyze"`, `"type_query"`, `"retaining_path"`, `"locate"`,
  `"diff"` or `"error"`.
- Within version 1, fields are only added, never removed or redefined.
  Consumers must ignore fields they do not know. A breaking change means
  `schema_version: 2`.
- Fields documented as nullable are always present, with `null` when the
  value is unknown. Fields are never omitted.
- Fields added within version 1 (marked "added in M7" below) may be missing
  from documents written by an older heapspy. Readers treat a missing
  added field as `null`; the Rust types do this with `#[serde(default)]`.
- Byte and object counts are non-negative JSON integers. Deltas (`delta_*`)
  are signed integers.
- Addresses are strings: lowercase hex with a `0x` prefix, e.g.
  `"0x7f3a2c41b0d0"`. (64-bit values do not survive JSON number parsing in
  JavaScript.)
- Percentages are floats from 0 to 100.
- Type names are `module.qualname`: `"builtins.dict"`, `"app.session.Session"`.
- Ranked arrays are sorted largest first and hold at most `--top` entries
  (default 20) unless stated otherwise.
- `notes[].code` is stable; `notes[].message` is for people and may change.

## Exit status

| status | meaning |
|---:|---|
| 0 | success; the report is on stdout |
| 1 | failure; with `--json`, an [error document](#error) is on stdout |
| 2 | command-line usage error (from the argument parser; no JSON) |

Human-readable diagnostics always go to stderr.

## Shared objects

### `snapshot` (SnapshotSummary)

Also used for `before` and `after` in a diff.

| field | type | meaning |
|---|---|---|
| `path` | string | snapshot file path as given on the command line |
| `format_version` | integer | snapshot file format version (1) |
| `python_version` | string | target CPython version, `sys.version` style: `"3.12.4"`, `"3.13.0rc1"` |
| `os` | string | `"linux"`, `"windows"`, `"macos"`, or `"unknown"` |
| `arch` | string | `"x86_64"`, `"aarch64"`, or `"unknown"` |
| `pointer_size` | integer | target pointer size in bytes |
| `captured_at` | integer | Unix seconds when the memory image was taken |
| `source.kind` | string | `"pid"`, `"core"` or `"minidump"` |
| `source.ref` | string | the PID as text, or the core / minidump path as given to `dump` |
| `contents_captured` | bool | the snapshot holds string contents and ordinary dict keys |
| `truncated` | bool | the dump did not finish, or the memory image was incomplete (e.g. a core file cut short); all numbers are lower bounds |

### Path hop (PathHop)

A retaining path is an array of hops, **root first**: `path[0]` is the root
object and the last hop is the object the path is about.

Paths are shortest paths. When an object is equally close to several roots,
the path starts at the best-ranked root: `module_dict` first, then
`frame_local`, `thread_locals`, `interp`, `other`, ties broken by root label.
So a module global is reported under `sys.modules[...]` even when a running
frame also reaches it through a function's `__globals__`.

| field | type | meaning |
|---|---|---|
| `address` | string | object address |
| `type` | string | object type |
| `shallow_bytes` | integer | object's own size |
| `edge` | string, nullable | rendered label of the reference from the previous hop to this one; `null` on the first hop |
| `root_label` | string, nullable | root description, first hop only, e.g. `"sys.modules['app.cache']"` |
| `root_kind` | string, nullable | first hop only: `"module_dict"`, `"thread_locals"`, `"frame_local"`, `"interp"`, `"other"` |
| `source_loc` | SourceLocation, nullable | where the object at this hop is defined, when it is a function, method, code object, class or module (see [Source locations](#source-locations)); `null` for other objects |
| `source_loc_reason` | string, nullable | why `source_loc` is `null` for an object of one of those kinds; `null` otherwise |

Edge labels are rendered as follows (see `docs/snapshot-format.md`, "Edge
labels"):

| label | example |
|---|---|
| dict value | `['cache']`, `[3]`, redacted `[<str len=9>]`, unreadable `[?]` |
| dict key object | `<key ['cache']>` |
| list / tuple item | `[3]` |
| set element | `<set item>` |
| attribute, slot, named C field | `.payload`, `.__dict__`, `.__globals__` |
| type pointer | `.__class__` |
| cell contents | `.cell_contents` |
| closure cell | `.__closure__[0]` |
| frame local | `local 'pending'` |
| other | `<weakref callback>`, `<?>` |

Joining `root_label` and the `edge` strings of the following hops gives the
rendered root path used as the `site` key in diffs, e.g.
`sys.modules['app.cache'].__dict__['CACHE']`. (Hops whose `edge` starts with
a letter, such as `local 'x'` or `<key ...>`, are joined with a space.)

### Source locations

`source_loc` (on path hops, `query --type` instances and `locate` matches)
is where an object itself is defined. `type_location` (on top retainers,
type-histogram rows, `query --type` matched types and retaining-path
targets) is where the object's type is defined: the location of the type
object that the object's `ob_type` points to. Both are a SourceLocation or
`null`, each with a `*_reason` field next to it.

SourceLocation:

| field | type | meaning |
|---|---|---|
| `file` | string | `co_filename`, or a module's `__file__`, exactly as the target recorded it |
| `line` | integer, nullable | 1-based line; `null` for a module |
| `exact` | bool | `true` for the object's own recorded location; `false` when derived (a class) |
| `via` | string | how it was found, below |

| object | `via` | how | `exact` |
|---|---|---|---|
| code object | `"code_object"` | its `co_filename` and `co_firstlineno` | true |
| function | `"function"` | the code object reached by its `.__code__` edge | true |
| bound method, `classmethod`, `staticmethod` | `"method"` | the function reached by `.__func__`, then its code object | true |
| class (type object) | `"methods"` | the functions defined in the class body, below | false |
| module | `"module_file"` | the str in `__dict__['__file__']` | true |

A class has no code object at runtime, so its location is derived from its
methods: the function objects in the type's `__dict__` (`tp_dict`),
directly or inside a `classmethod`, `staticmethod` or `property`, whose
code object's `co_qualname` is `<class qualname>.<name>`. Functions
assigned to a class attribute from elsewhere, and decorator wrappers made
with `functools.wraps` (they copy `__qualname__` but not the code), are
left out, and so are functions with a generated filename starting with `<`
(the `__init__` that `dataclasses` builds with `exec` has `<string>`). When
all the remaining functions have the same `file`, that file is reported
with the smallest `co_firstlineno` as `line`. The class statement is at or
before that line: above it are the class line, the docstring and class
attributes. Decorators count: the first line of a decorated method is its
first decorator.

`co_firstlineno` of a decorated function is the line of its first
decorator, so a function's `line` may be above its `def`.

`file` is not normalised, and it is a path on the machine (or in the
container) the target ran on. On CPython 3.12 to 3.14 a script started as
`python app/main.py` and modules imported from `sys.path` have absolute
paths, also when the path entry was relative. Relative or otherwise
unusual names come from code compiled with an explicit filename
(`compile(src, "app/x.py", "exec")`, template engines), from `.pyc` files
compiled with `compileall -d` and run without sources, from zip imports
(`/srv/app.zip/app/x.py`), from `python -c` (`<string>`), and from frozen
modules (`<frozen ...>`). A tool that maps a location to a checkout of the
repository has to resolve the path itself.

Reasons (`source_loc_reason`, `type_location_reason`):

| code | when |
|---|---|
| `no_code_object` | a function or method whose code object is not in the snapshot or has no recorded location |
| `no_python_methods` | a class with no Python function defined in its body (only attributes, or only generated methods) |
| `methods_disagree` | a class whose methods were compiled from more than one file |
| `contents_not_captured` | a module, in a snapshot taken without `--capture-contents` |
| `no_file` | a module whose `__dict__` has no `__file__` str (built-in modules, `__main__` of `python -c`) |
| `content_truncated` | a module whose `__file__` text was cut at `--max-str` |
| `type_not_in_snapshot` | the type object is not in the snapshot; this is the usual case for types implemented in C (`builtins.dict`), which are not GC objects |
| `unknown_type` | the object's type could not be read |

New codes may be added in version 1.

Redaction: `co_filename` and `co_firstlineno` are code metadata, not data
the program handles, and the walker stores a code object's and a
function's `source_loc` with or without `--capture-contents` (see
"Redaction policy" in `docs/snapshot-format.md`). Code and class locations
are therefore available in every snapshot. A module's `__file__` is the
text of an ordinary str object, which is only stored with contents
capture, so module locations need `--capture-contents`.

Cost: locations are computed only for the objects and types a report
lists (path hops, the listed retainers, rows, instances and targets), not
for the whole heap. A class location looks at the entries of one type's
`__dict__`.

### Note

| field | type | meaning |
|---|---|---|
| `code` | string | stable identifier |
| `message` | string | human-readable text |

Codes defined so far:

| code | when |
|---|---|
| `untracked_objects` | always on analyze: untracked objects are only seen through tracked referrers |
| `outside_graph` | RSS is known and most of it is outside the graph |
| `keys_redacted` | the snapshot was taken without `--capture-contents`, so dict keys are placeholders |
| `truncated_snapshot` | `snapshot.truncated` is true |
| `dangling_edges` | some edges point at addresses not in the snapshot |
| `missing_roots` | some root addresses are not in the snapshot |
| `identity_approximate` | always on diff |
| `unreachable_target` | a retaining-path target has no path from any root |
| `image_incomplete` | dump: `image.missing_bytes` is non-zero |
| `read_errors` | dump: `read_errors` is non-zero |
| `recaptured` | dump `--pid`: the first capture's GC lists could not be followed, so the target was captured again (up to 3 captures in all) |
| `allocations_pid_mismatch` | `--allocations`: the profile was recorded from another pid than the (live-process) snapshot |
| `allocations_python_mismatch` | `--allocations`: the profile and the snapshot name different CPython versions |
| `allocations_after_snapshot` | `--allocations`: the snapshot was taken before recording started, so no sampled allocation can be in it |
| `allocations_not_linked` | `--allocations` on analyze and `query --type`: one of the three notes above applies, so no object was linked to a sample; `top_stacks` is still reported, with `linked_bytes` 0 |
| `allocations_sampled` | always on analyze and `query --type` with `--allocations`: what the samples cover (allocations made while recording, sampled events only) and that arena and pool links are approximate |
| `allocations_unlinked_reused` | `--allocations` on analyze and `query --type`, when `coverage.unlinked_reused_objects` (see Allocations) is not 0: how many reachable objects sit on memory of a sampled large allocation they do not match, and are therefore not linked |
| `allocations_not_joined` | no longer emitted. heapspy versions before the join printed it when `--allocations` was given to analyze or `query --type` |

`truncated_snapshot` is also used by dump, when `truncated` is true.

New codes may be added in version 1.

## `dump`

`heapspy dump (--pid PID | --core PATH | --minidump PATH) -o OUT --json`.
Example: `docs/examples/dump.json`.

Printed after the snapshot has been written. The one-line summary on stderr
is printed with or without `--json`, in this format (the suffix only when
the snapshot is truncated):

```text
wrote OUT: N objects, N edges, N roots, N bytes (truncated)
```

| field | type | meaning |
|---|---|---|
| `schema_version` | 1 | |
| `kind` | `"dump"` | |
| `path` | string | the snapshot file written, as given with `-o` |
| `source.kind` | string | `"pid"`, `"core"` or `"minidump"` |
| `source.ref` | string | the PID as text, or the core / minidump path as given |
| `python_version` | string | CPython version found in the target, `sys.version` style |
| `contents_captured` | bool | `--capture-contents` was given |
| `objects` | integer | objects written |
| `edges` | integer | references written |
| `types` | integer | distinct type records written |
| `roots` | integer | root entries written |
| `bytes_written` | integer | size of the snapshot file |
| `read_errors` | integer | reads of target memory that failed; the objects involved are marked partial in the snapshot |
| `truncated` | bool | the snapshot is marked truncated (the walk did not finish, or the image is incomplete); same as `snapshot.truncated` in the other reports |
| `image.missing_bytes` | integer | bytes of memory the image's headers describe but the file does not contain (a core cut short); 0 when complete or not known |
| `pause_ms` | float, nullable | how long a live target was stopped, in milliseconds; `null` for cores and minidumps, and on Windows, where the pause is inside the minidump write and not measured |
| `notes` | array of Note | |

## `record`

`heapspy record --pid PID --duration D -o OUT.hpya [--then-dump SNAP] --json`.
Added in M7. Example: `docs/examples/record.json`.

Printed after the allocation profile (and the `--then-dump` snapshot, when
asked for) has been written. The summary lines on stderr are printed with or
without `--json`.

On failure `record --json` prints an [error document](#error) and exits
with status 1. The checks run in this order, and the first that fails gives
the code:

1. option values (`--duration 0s`, `--max-frames 0`, `--then-dump` equal to
   `-o`): `invalid_argument`
2. on Linux, whether a process has the PID: `no_such_process`
3. the recorders for `--mechanism`, in order: `unsupported` when the
   mechanism is not available here, `permission_denied` when none may run
   (with `auto`, the first recorder's error is reported)
4. finding CPython in the target: `not_python`, `unsupported_python`

No profile file is written on failure. Ctrl-C (SIGINT, SIGTERM) ends the
window early: the profile is written and `truncated` is `true`.

| field | type | meaning |
|---|---|---|
| `schema_version` | 1 | |
| `kind` | `"record"` | |
| `path` | string | the allocation profile written, as given with `-o` |
| `pid` | integer | the process recorded |
| `python_version` | string | CPython version found in the target, `sys.version` style |
| `duration_ms` | integer | measured length of the recording window, in milliseconds |
| `mechanisms` | array of string | mechanisms that ran: `"ebpf"`, `"ptrace"`, `"etw"`, `"debugger"` |
| `sampling` | object | as `allocations.sampling` in [Allocations](#allocations-allocations): `events`, `byte_interval`, `max_frames` |
| `samples` | integer | samples written to the profile |
| `bytes_written` | integer | size of the profile file |
| `overhead` | object | as `allocations.overhead`: `samples_taken`, `samples_dropped`, `probe_hits`, `total_pause_ns` |
| `truncated` | bool | recording stopped early or lost samples that `overhead` does not count |
| `then_dump` | string, nullable | the `--then-dump` snapshot written, as given; `null` without `--then-dump` |

## `analyze`

`heapspy analyze SNAP --json [--top N] [--allocations FILE.hpya]`. Examples: `docs/examples/analyze.json`, and with allocations `docs/examples/analyze_allocations.json`.

| field | type | meaning |
|---|---|---|
| `schema_version` | 1 | |
| `kind` | `"analyze"` | |
| `snapshot` | SnapshotSummary | |
| `totals` | object | below |
| `memory` | object | below |
| `top_retainers` | array of Retainer | objects with the largest `retained_bytes` |
| `type_histogram` | array of TypeRow | types by `retained_bytes` |
| `notes` | array of Note | |
| `allocations` | Allocations, nullable | added in M7: the `--allocations` profile joined with the snapshot, see [Allocations](#allocations); `null` without `--allocations` |

`totals`:

| field | type | meaning |
|---|---|---|
| `objects` | integer | objects in the snapshot |
| `edges` | integer | references in the snapshot |
| `types` | integer | distinct types |
| `roots` | integer | root entries |
| `shallow_bytes` | integer | sum of shallow sizes of all objects |
| `reachable_objects` | integer | objects reachable from at least one root |
| `reachable_bytes` | integer | sum of shallow sizes of reachable objects |
| `external_objects` | integer | objects no root reaches that something outside the recorded graph owns, as their refcounts show (native code, C globals, memory heapspy could not lay out). Paths to them start at the root `held outside the Python graph`, kind `external`. 0 when `refcounts_checked` is false |
| `external_bytes` | integer | their shallow sizes |
| `unreachable_objects` | integer | objects neither reachable nor held from outside. When `refcounts_checked` is true, their owners are all each other: cyclic garbage the collector will free. When it is false, this also includes what `external_objects` would have counted |
| `unreachable_bytes` | integer | their shallow sizes |
| `dangling_edges` | integer | edges whose target is not in the snapshot |
| `refcounts_checked` | boolean | whether the snapshot recorded refcounts and references were checked against them |
| `borrowed_edges_dropped` | integer | scanned edges (fields of a layout heapspy does not know) dropped because their target had more of them than owners |
| `stale_edges_dropped` | integer | out-of-line pointers dropped because nothing about their target needed them. Without refcounts, every out-of-line pointer |
| `out_of_line_edges` | integer | out-of-line references kept: objects held through memory their owner points at but does not lay out, such as a `deque`'s blocks |

Percentages in reports (`retained_pct`) are of everything held:
`reachable_bytes + external_bytes`.

`memory`:

| field | type | meaning |
|---|---|---|
| `rss_bytes` | integer, nullable | process resident set size, if the source recorded it |
| `graph_bytes` | integer | bytes in the object graph (`totals.shallow_bytes`) |
| `outside_graph_bytes` | integer, nullable | `rss_bytes - graph_bytes`, floored at 0 |
| `outside_graph_pct` | float, nullable | `outside_graph_bytes / rss_bytes * 100` |

Retainer (`top_retainers[]`):

| field | type | meaning |
|---|---|---|
| `rank` | integer | 1-based position |
| `address` | string | |
| `type` | string | |
| `shallow_bytes` | integer | |
| `retained_bytes` | integer | memory freed if this object were freed: shallow sizes of all objects it dominates, itself included |
| `retained_objects` | integer | number of objects it dominates, itself included |
| `retained_pct` | float | `retained_bytes / totals.reachable_bytes * 100` |
| `path` | array of PathHop | one shortest path from a root |
| `allocated_at` | AllocatedAt, nullable | added in M7: allocation stacks of the sampled objects this entry retains, see [AllocatedAt](#allocatedat); `null` without `--allocations` |
| `type_location` | SourceLocation, nullable | where the object's type is defined ([Source locations](#source-locations)) |
| `type_location_reason` | string, nullable | why `type_location` is `null` |

Which objects are listed:

1. Namespaces are never listed: module objects, frame objects, type objects,
   and the `__dict__` of each, also when something else references that
   dict (a function's `__globals__` is its module's `__dict__`). The
   variables inside them are listed instead.
2. A chain of wrappers that only restate their contents is reported once, at
   the object where the memory accumulates. Starting at an object A, follow
   A's largest dominated child while it still retains at least 90% of A's
   `retained_bytes`, for at most 8 steps; only the last object of the chain
   is listed. So `module -> __dict__ -> CACHE` lists `CACHE`, and
   `function -> closure cell -> large object` lists the large object. The
   `path` still shows the wrappers. The 90% is measured against the top of
   the chain, so a long linked list is reported near its head, not at its
   tail.
3. Entries are ranked by `retained_bytes` (ties by address), and an object
   dominated by an entry already listed is skipped. The entries are therefore
   disjoint: their retained sets do not overlap.

TypeRow (`type_histogram[]`):

| field | type | meaning |
|---|---|---|
| `type` | string | |
| `count` | integer | instances |
| `shallow_bytes` | integer | sum of instance shallow sizes |
| `retained_bytes` | integer | retained size of the set of instances: sum of `retained_bytes` over instances not dominated by another instance of the same type |
| `type_location` | SourceLocation, nullable | where the type is defined; when several type objects share the name, the first one with a location |
| `type_location_reason` | string, nullable | why `type_location` is `null` |

The `retained_bytes` rule means nested instances are not counted twice: for
a dict of dicts, only the outer dict's retained size counts, since it already
includes the inner ones. The result equals the total shallow size of every
object dominated by at least one instance. Unreachable instances count in
`count` and `shallow_bytes` but retain nothing. Types are grouped by display
name, so two type objects with the same `module.qualname` are one row.

## `type_query`

`heapspy query SNAP --type T --json`. Example: `docs/examples/type_query.json`.

`T` may be a full name (`app.session.Session`) or an unqualified one
(`Session`), which can match several types.

| field | type | meaning |
|---|---|---|
| `schema_version` | 1 | |
| `kind` | `"type_query"` | |
| `snapshot` | SnapshotSummary | |
| `query` | string | `T` as given |
| `matched_types` | array of string | full names of matching types, sorted; empty means no match (the command then fails with `not_found`) |
| `matched_type_locations` | array of TypeLocation | one per entry of `matched_types`, in the same order |
| `instances` | integer | instances of the matched types |
| `shallow_bytes` | integer | their shallow sizes |
| `retained_bytes` | integer | retained size of the set, as for TypeRow |
| `top_instances` | array of Instance | largest by `retained_bytes` |
| `holders` | array of Holder | direct referrers, grouped, by `count` |
| `notes` | array of Note | |

Instance:

| field | type | meaning |
|---|---|---|
| `address` | string | |
| `type` | string | |
| `shallow_bytes` | integer | |
| `retained_bytes` | integer | |
| `length` | integer, nullable | `len()` if recorded |
| `path` | array of PathHop, nullable | shortest retaining path; `null` if unreachable |
| `allocated_at` | AllocatedAt, nullable | added in M7: as on Retainer; `null` without `--allocations` |
| `source_loc` | SourceLocation, nullable | where the instance itself is defined, when it is a function, method, code object, class or module (`query --type builtins.function`) |
| `source_loc_reason` | string, nullable | why `source_loc` is `null` for such an instance |

TypeLocation:

| field | type | meaning |
|---|---|---|
| `type` | string | a matched type |
| `type_location` | SourceLocation, nullable | where it is defined |
| `type_location_reason` | string, nullable | why `type_location` is `null` |

Holder:

| field | type | meaning |
|---|---|---|
| `type` | string | type of the referring object |
| `edge` | string | edge label from referrer to instance, generalised: dict keys become `[<key>]` and indices `[<index>]`, so one container holding many instances is one row |
| `count` | integer | instances held this way |

## Allocations

Added in M7. `heapspy analyze SNAP --allocations FILE.hpya --json` joins an
allocation profile written by `heapspy record` (format:
`docs/alloc-format.md`) with the snapshot. Example:
`docs/examples/analyze_allocations.json`. `heapspy query --type T
--allocations FILE.hpya` fills `allocated_at` on `top_instances`; the
`retaining_path` and `diff` reports have no allocation fields and only
check the profile (its notes are added).

Samples are an estimate of where growth came from during the recording
window, not a full allocation history: only arena, pool, large-object and
native heap events are sampled, blocks reused from freed memory are not,
and objects allocated before recording started have no sample. An object
is *linked* to a sample when its address lies inside the sampled range and
no later sample covers that address. For a `large_object` sample the object
must also be that allocation: it starts at the sample's address plus 0, 16
or 32 bytes (no GC header, the GC header, or the GC header and the managed
dict and weakref words), and the sample's requested size is within 16
bytes of the object's `shallow_size` (for a type object, at most 16 bytes
above it). When the latest covering sample is a `large_object` sample the
object does not match, the object is not linked at all and is counted in
`coverage.unlinked_reused_*`. A `native` sample is matched differently: its
address is the pointer *inside* the block that the allocator returned, so
the object linked is the one whose range contains the whole returned block;
this runs as a separate pass and never overrides an exact or arena/pool
link (see `docs/allocation-sampling.md`, "Native samples: by containment").
Samples taken after the snapshot's capture second are not used for linking.
When the profile does not match the snapshot (the `allocations_*_mismatch`
and `allocations_after_snapshot` notes), nothing is linked and the report
carries `allocations_not_linked`. The algorithm is described in
`docs/allocation-sampling.md`, "Joining with a snapshot".

Links through `large_object` and `native` samples are *exact*: the sample
is the object's own allocation. Links through `arena` and `pool` samples
(and `other`) are *approximate*: the sample is the most recent growth event
that created the memory, not necessarily the call that allocated the
object. The `exact_linked_*` fields give the exact part of each linked
count. The `approximate` flags mean something else: Python frames matched
to the event by time (ETW).

### Allocations (`allocations`)

| field | type | meaning |
|---|---|---|
| `path` | string | profile path as given on the command line |
| `pid` | integer | process the samples were recorded from |
| `python_version` | string | CPython version recorded in the profile, `sys.version` style |
| `started_at` | integer | Unix seconds when recording started |
| `duration_ms` | integer | length of the recording window in milliseconds |
| `mechanisms` | array of string | mechanisms that ran: `"ebpf"`, `"ptrace"`, `"etw"`, `"debugger"` |
| `sampling.events` | array of string | event kinds enabled: `"arena"`, `"pool"`, `"large_object"`, `"native"` |
| `sampling.byte_interval` | integer | mean bytes between large-object and native samples; 0 means every one was kept |
| `sampling.max_frames` | integer | most Python frames kept per sample |
| `overhead.samples_taken` | integer | samples written |
| `overhead.samples_dropped` | integer | samples lost before they were written (buffer full, stack unreadable) |
| `overhead.probe_hits` | integer | times a probe fired, including events the byte sampler skipped |
| `overhead.total_pause_ns` | integer | total time target threads were stopped, summed over threads (0 for eBPF and ETW) |
| `truncated` | bool | recording stopped early or lost samples the overhead does not count |
| `approximate` | bool | some frames were matched to events by time (ETW) rather than read at the event |
| `samples` | integer | samples in the profile |
| `estimated_bytes` | integer | sum of sample weights: estimated bytes allocated through sampled events during the window |
| `coverage.linked_objects` | integer | reachable objects linked to a sample |
| `coverage.linked_bytes` | integer | their shallow bytes |
| `coverage.linked_pct` | float | `coverage.linked_bytes / totals.reachable_bytes * 100` |
| `coverage.exact_linked_objects` | integer | the part of `coverage.linked_objects` linked through `large_object` or `native` samples (exact links) |
| `coverage.exact_linked_bytes` | integer | their shallow bytes |
| `coverage.unlinked_reused_objects` | integer | reachable objects not linked because the latest sample over their address is a `large_object` sample they do not match: the sampled block was freed and the memory reused by an allocation that was not sampled. Added after the first M7 release; reads as 0 when missing |
| `coverage.unlinked_reused_bytes` | integer | their shallow bytes; reads as 0 when missing |
| `top_stacks` | array of AllocationStack | stacks by `estimated_bytes`, at most `--top` |

AllocationStack (`top_stacks[]`):

| field | type | meaning |
|---|---|---|
| `rank` | integer | 1-based position |
| `frames` | array of StackFrame | innermost first: `frames[0]` is the function that allocated |
| `estimated_bytes` | integer | sum of the weights of this stack's samples |
| `samples` | integer | samples with this stack |
| `events` | array of string | event kinds among them, sorted |
| `linked_bytes` | integer | shallow bytes of reachable objects linked to these samples |
| `exact_linked_bytes` | integer | the part of `linked_bytes` linked through `large_object` or `native` samples |
| `approximate` | bool | any frame of any of these samples was approximate |

Two samples have the same stack when their frames have the same
`function` and `location` in the same order.

StackFrame:

| field | type | meaning |
|---|---|---|
| `function` | string | `co_qualname`, e.g. `"SessionStore.create"`; `"<unknown>"` if the code object could not be read |
| `file` | string, nullable | `co_filename` |
| `line` | integer, nullable | line of the executing instruction, from `co_linetable` |
| `location` | string | `file:line`; `file:?` without a line; `"<unknown>"` without a file |
| `approximate` | bool | this frame was matched to the event by time, not read at it |

### AllocatedAt

On a Retainer (`top_retainers[].allocated_at`) or an Instance
(`top_instances[].allocated_at`): which stacks allocated the linked objects
in the entry's dominator subtree, i.e. the memory it retains. With
`--allocations`, every listed entry has one; an entry with no linked
objects has `linked_objects: 0` and no stacks.

| field | type | meaning |
|---|---|---|
| `linked_objects` | integer | objects in the subtree linked to a sample |
| `linked_bytes` | integer | their shallow bytes |
| `exact_linked_bytes` | integer | the part of `linked_bytes` linked through `large_object` or `native` samples |
| `stacks` | array of AllocatedAtStack | by `linked_bytes`, at most 5 |
| `approximate` | bool | any listed stack is approximate |

AllocatedAtStack:

| field | type | meaning |
|---|---|---|
| `frames` | array of StackFrame | innermost first |
| `linked_objects` | integer | linked objects in the subtree allocated through this stack |
| `linked_bytes` | integer | their shallow bytes |
| `exact_linked_bytes` | integer | the part of `linked_bytes` linked through `large_object` or `native` samples |
| `top_stack_rank` | integer, nullable | `rank` of the same stack in `allocations.top_stacks`, if it is listed there; always `null` on query reports |

## `retaining_path`

`heapspy query SNAP --retaining-path ADDR --json`, or
`heapspy query SNAP --retaining-path-type T --json` for the largest
instances of a type (`query.by` is then `"type"`). `--top N` bounds the
number of targets and `--max-paths N` the paths per target (default 3).
Example: `docs/examples/retaining_path.json`.

| field | type | meaning |
|---|---|---|
| `schema_version` | 1 | |
| `kind` | `"retaining_path"` | |
| `snapshot` | SnapshotSummary | |
| `query.by` | string | `"address"` or `"type"` |
| `query.value` | string | the address or type name as given |
| `targets` | array of PathTarget | one entry for an address; for a type, up to `--top` instances by retained size |
| `notes` | array of Note | |

PathTarget:

| field | type | meaning |
|---|---|---|
| `address` | string | |
| `type` | string | |
| `shallow_bytes` | integer | |
| `retained_bytes` | integer | |
| `reachable` | bool | false if no root reaches the object; `paths` is then empty |
| `paths` | array of array of PathHop | shortest first, at most 3 by default; each path differs from the others in at least one hop |
| `type_location` | SourceLocation, nullable | where the object's type is defined |
| `type_location_reason` | string, nullable | why `type_location` is `null` |

An address that is not an object in the snapshot is an error (`not_found`),
not an empty report.

## `locate`

`heapspy query SNAP --locate NAME --json`. Example:
`docs/examples/locate.json`.

Where the type, function or module with the full name `NAME` is defined.
`NAME` is `module.qualname` as reports show it: `app.session.Session`,
`app.session.Session.__init__`, `app.cache.make_key`,
`__main__.main.<locals>.handler`, or a module name such as `app.cache`.
Unqualified names are not matched. This query does not build the dominator
tree, so it is cheaper than the others.

| field | type | meaning |
|---|---|---|
| `schema_version` | 1 | |
| `kind` | `"locate"` | |
| `snapshot` | SnapshotSummary | |
| `query` | string | `NAME` as given |
| `matches` | array of LocateMatch | types first, then functions, then modules; at most `--top`. No match is an error (`not_found`) |
| `notes` | array of Note | |

LocateMatch:

| field | type | meaning |
|---|---|---|
| `kind` | string | `"type"`, `"function"` or `"module"` |
| `name` | string | the full name; equal to `query` |
| `module` | string | the module part of `name`; for a module, `name` itself |
| `qualname` | string | the rest of `name`; empty for a module |
| `address` | string | the type object, function or module |
| `source_loc` | SourceLocation, nullable | as for path hops |
| `source_loc_reason` | string, nullable | why `source_loc` is `null` |

How names are matched:

- A type matches when its display name is `NAME`. Every type object with
  that name is listed (a class defined twice gives two entries).
- A function matches when `<module>.<__qualname__>` is `NAME`, where
  `<module>` is the name of the module whose `__dict__` is the function's
  `__globals__`. Functions with the same location (a closure created many
  times) are listed once. If some of them also have `NAME`'s qualname as
  their code object's `co_qualname`, the others (decorator wrappers that
  copied `__qualname__`) are left out.
- A module matches by its `__name__`.

## `diff`

`heapspy diff BEFORE AFTER --json`. Example: `docs/examples/diff.json`.

Addresses change between dumps, so objects are not matched one to one.
Growth is reported by type and by retaining site (the rendered root path).

| field | type | meaning |
|---|---|---|
| `schema_version` | 1 | |
| `kind` | `"diff"` | |
| `identity_approximate` | bool | always `true` |
| `before`, `after` | SnapshotSummary | |
| `totals.before`, `totals.after` | object | `objects`, `shallow_bytes`, `reachable_bytes` of each snapshot |
| `totals.delta_objects` | integer | after minus before |
| `totals.delta_shallow_bytes` | integer | |
| `totals.delta_reachable_bytes` | integer | |
| `by_type` | array of TypeGrowth | by `delta_bytes`, largest growth first |
| `by_site` | array of SiteGrowth | by `delta_retained_bytes`, largest growth first |
| `notes` | array of Note | |

TypeGrowth (counts and shallow bytes over all instances):

| field | type |
|---|---|
| `type` | string |
| `before_count`, `after_count` | integer |
| `delta_count` | signed integer |
| `before_bytes`, `after_bytes` | integer |
| `delta_bytes` | signed integer |

SiteGrowth:

| field | type | meaning |
|---|---|---|
| `site` | string | rendered root path; the match key between the snapshots |
| `type` | string | type at the site in `after` (in `before` if the site is gone) |
| `before_retained_bytes`, `after_retained_bytes` | integer | retained size at the site, 0 if absent |
| `delta_retained_bytes` | signed integer | |
| `before_retained_objects`, `after_retained_objects` | integer | |
| `delta_retained_objects` | signed integer | |

How sites are built. A site is a position in the dominator tree, named by
labels so that it can be found again in another dump:

- The site of a root object is its root label. When an object is a root
  more than once, one entry is chosen: `module_dict` first, then
  `frame_local`, `thread_locals`, `interp`, `other`, ties broken by label.
- The site of any other object is the site of its immediate dominator plus
  the label of the edge into the object, joined as in a root path. If the
  object's shortest-path parent is not its immediate dominator (it is
  reached through several objects its dominator owns), the label is written
  as `...` followed by the label of the last edge, e.g.
  `sys.modules['app'].__dict__['PENDING']...[<index>]`.
- An object that is not a root but is dominated only by the super-root
  (several roots reach it and none of them owns it, e.g. a list imported
  into two modules, or a module `__dict__` that is also the `__globals__` of
  a function a running frame holds) has no owning site. Its site is its
  shortest path (the `path` that `analyze` reports for it), rendered as a
  root path with indices generalised, e.g.
  `sys.modules['app.a'].__dict__['SHARED']`.
- List and tuple indices are generalised to `[<index>]`, since positions
  shift as a container changes.
- Only the first 6 levels of the dominator tree get sites (level 1 is the
  root objects). Deeper objects are counted in the retained size of their
  ancestor's site.
- Objects that end up with the same site are summed: every value of a dict
  with redacted keys of one length, every item of one list. `type` is the
  type of the largest contributor.

Which sites are listed: sites whose retained bytes and objects did not
change are left out, and so is a site whose change is at least 90% in one
child site that is a single object in both snapshots (with the same sign).
Growth in `CACHE` also shows as growth in the module and the module's
`__dict__`; only `CACHE` is listed. A child site that sums many objects does
not hide its parent.

## `error`

Printed on stdout by any `--json` command that fails, followed by exit
status 1. Example: `docs/examples/error.json`.

| field | type | meaning |
|---|---|---|
| `schema_version` | 1 | |
| `kind` | `"error"` | |
| `error.code` | string | below |
| `error.message` | string | human-readable, includes the cause chain |

| code | meaning |
|---|---|
| `unimplemented` | the command or feature is not built yet |
| `invalid_argument` | a value on the command line is malformed (e.g. an address without `0x`), or a `record` option is out of range (`--duration 0s`, `--max-frames 0`) |
| `not_found` | the requested address or type is not in the snapshot |
| `invalid_snapshot` | the file is not a snapshot, is truncated or corrupt, or has an unsupported format version |
| `invalid_allocations` | the `--allocations` file is not an allocation profile, is truncated or corrupt, or has an unsupported format version |
| `io` | a file could not be read or written (missing core file, unreadable snapshot, full disk) |
| `permission_denied` | reading the target process was refused: ptrace `EPERM` on Linux (needs root or `CAP_SYS_PTRACE`, see `kernel.yama.ptrace_scope`), access denied on Windows (needs `SeDebugPrivilege` or the same user). For `record`, also a recorder that lacks its privileges (`CAP_BPF` and `CAP_PERFMON` for eBPF) |
| `no_such_process` | dump, record: no process has that PID, or it exited before it could be stopped |
| `not_python` | dump, record: no CPython runtime in the target (no module exports `_PyRuntime`, or it could not be read) |
| `unsupported_python` | dump, record: CPython was found, but its version or build is refused (outside 3.12 to 3.14, free-threaded, or debug) |
| `invalid_image` | dump: the core or minidump is not one heapspy reads (not an ELF core or minidump, corrupt, 32-bit, big-endian, another CPU), or memory the runtime points to is not in the image |
| `truncated_image` | dump: the image file ends before data its own headers describe (cut short by a size limit or a full disk), and the dump could not go on. A core cut only inside memory segments can still give a snapshot, marked `truncated`. A minidump cut inside data that only a stream refers to (a module or thread name) is reported as `invalid_image` |
| `unsupported` | dump, record: the request cannot be done here (dumping heapspy itself, a live process on a platform without a live backend, a target that keeps creating threads while it is being stopped; for `record`, a `--mechanism` this OS does not have, or a recording larger than the profile format holds) |
| `internal` | a bug in heapspy |

The codes are stable; `error.message` is for people and may change. New
codes may be added in version 1, so treat an unknown code like `internal`.
