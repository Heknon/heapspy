# JSON report schema, version 1

`heapspy analyze`, `query` and `diff` print a JSON document on stdout when
given `--json`. This is the machine interface that tooling (including
`heapspy-mcp`) binds to. The Rust definitions are in
`crates/heapspy-analyzer/src/report.rs`. Complete example documents are in
`docs/examples/`; a test (`crates/heapspy-analyzer/tests/examples.rs`) checks
that each example matches the structs field for field.

## Rules

- Every document has `"schema_version": 1` and a `"kind"`:
  `"analyze"`, `"type_query"`, `"retaining_path"`, `"diff"` or `"error"`.
- Within version 1, fields are only added, never removed or redefined.
  Consumers must ignore fields they do not know. A breaking change means
  `schema_version: 2`.
- Fields documented as nullable are always present, with `null` when the
  value is unknown. Fields are never omitted.
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
| `truncated` | bool | the dump did not finish; all numbers are lower bounds |

### Path hop (PathHop)

A retaining path is an array of hops, **root first**: `path[0]` is the root
object and the last hop is the object the path is about.

| field | type | meaning |
|---|---|---|
| `address` | string | object address |
| `type` | string | object type |
| `shallow_bytes` | integer | object's own size |
| `edge` | string, nullable | rendered label of the reference from the previous hop to this one; `null` on the first hop |
| `root_label` | string, nullable | root description, first hop only, e.g. `"sys.modules['app.cache']"` |
| `root_kind` | string, nullable | first hop only: `"module_dict"`, `"thread_locals"`, `"frame_local"`, `"interp"`, `"other"` |

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

New codes may be added in version 1.

## `analyze`

`heapspy analyze SNAP --json [--top N]`. Example: `docs/examples/analyze.json`.

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
| `unreachable_objects` | integer | objects no root reaches (cyclic garbage not yet collected, or held only from outside the recorded graph) |
| `unreachable_bytes` | integer | their shallow sizes |
| `dangling_edges` | integer | edges whose target is not in the snapshot |

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

Holder:

| field | type | meaning |
|---|---|---|
| `type` | string | type of the referring object |
| `edge` | string | edge label from referrer to instance, generalised: dict keys become `[<key>]` and indices `[<index>]`, so one container holding many instances is one row |
| `count` | integer | instances held this way |

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

An address that is not an object in the snapshot is an error (`not_found`),
not an empty report.

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
  into two modules) has no owning site. Its site is `...` followed by the
  label of the edge it was first reached through, e.g. `...['SHARED']`.
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
| `invalid_argument` | a value on the command line is malformed (e.g. an address without `0x`) |
| `not_found` | the requested address or type is not in the snapshot |
| `invalid_snapshot` | the file is not a snapshot, is truncated or corrupt, or has an unsupported format version |
| `io` | the file could not be read |
| `permission_denied` | reading the target process was refused |
| `internal` | anything else |
