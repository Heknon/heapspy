# Snapshot file format, version 1

A heapspy snapshot (`.hpy`) holds one CPython object graph captured from one
process at one point in time. This document is the normative description. The
implementation is `crates/heapspy-snapshot`; its constants live in
`src/format.rs` and must match the tables here.

Design goals:

- Tens of millions of objects. Fixed-size records, no per-object allocation
  when reading, edges in CSR layout (each object owns a contiguous edge range).
- Written in one sequential pass (no seeking), so it can go to a pipe.
- Read by memory-mapping the file. All integers are decoded from byte slices,
  so nothing depends on alignment or host byte order.
- Readers can skip sections they do not know.

## Conventions

- All integers are **little-endian**, regardless of the target's byte order.
- Offsets are byte offsets from the start of the file.
- `u8`/`u16`/`u32`/`u64` are unsigned. Reserved bytes are written as 0 and
  ignored on read.
- **String id**: a `u32` index into the strings section. `0xFFFF_FFFF`
  (`NO_STRING`) means "no string".
- **Type id**: a `u32` index into the types section. `0xFFFF_FFFF`
  (`UNKNOWN_TYPE`) means the object's type could not be read.
- **Object index**: an object's position (0-based) in the objects section.
  Objects are sorted by address, so this is also the address rank. The
  analyzer uses it as the dense node id. At most 2^32 - 1 objects.

## File layout

```
offset 0     header (64 bytes)
offset 64    section table (section_count x 24 bytes)
             padding to 8
             sections, each starting at a multiple of 8, in any order
             padding to 8
end          file_len (recorded in the header)
```

The writer currently emits sections in this order: strings, types, objects,
edges, roots, extras, memory summary (only if non-empty), meta. Readers must
not rely on the order; they use the section table.

## Header (64 bytes)

| offset | size | field | notes |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `HPSY` (`48 50 53 59`) |
| 4 | 2 | `format_version` | `1`. Readers reject any other value. |
| 6 | 2 | `header_len` | `64`. A reader accepts values >= 64 and ignores the extra bytes. |
| 8 | 1 | `py_major` | e.g. 3 |
| 9 | 1 | `py_minor` | e.g. 12 |
| 10 | 1 | `py_micro` | e.g. 4 |
| 11 | 1 | `pointer_size` | target pointer size in bytes: 8 |
| 12 | 1 | `endianness` | target byte order: 1 = little, 2 = big |
| 13 | 1 | `os` | 1 = linux, 2 = windows, 3 = macos |
| 14 | 1 | `arch` | 1 = x86_64, 2 = aarch64 |
| 15 | 1 | `source_kind` | 1 = pid (live process), 2 = ELF core, 3 = minidump |
| 16 | 4 | `flags` | see below |
| 20 | 4 | `source_ref` | string id: the PID as decimal text, or the input path as given |
| 24 | 8 | `captured_at` | Unix seconds when the memory image was taken |
| 32 | 8 | `section_table_offset` | 64 in files written by this version |
| 40 | 4 | `section_count` | number of section table entries |
| 44 | 1 | `py_release_level` | `PY_RELEASE_LEVEL`: 0xA alpha, 0xB beta, 0xC rc, 0xF final |
| 45 | 1 | `py_release_serial` | `PY_RELEASE_SERIAL` |
| 46 | 2 | reserved | |
| 48 | 8 | `file_len` | total file length in bytes; detects truncation |
| 56 | 8 | reserved | |

Unknown codes in `os`, `arch` and `source_kind` are not errors; the reader
reports them as `Unknown(code)`.

Header `flags`:

| bit | name | meaning |
|---:|---|---|
| 0 | `CONTENTS_CAPTURED` | str/bytes contents and ordinary dict keys were captured (`--capture-contents`) |
| 1 | `TRUNCATED` | the walk stopped early or hit read errors, or the memory image is missing data its own headers describe (a cut core); the graph is incomplete |
| 2 | `PY_FREE_THREADED` | target is a free-threaded (`Py_GIL_DISABLED`) build |
| 3 | `PY_DEBUG_BUILD` | target is a `Py_DEBUG` build |

## Section table

`section_count` entries of 24 bytes starting at `section_table_offset`:

| offset | size | field |
|---:|---:|---|
| 0 | 4 | `kind` |
| 4 | 4 | `flags`: bit 0 `REQUIRED` |
| 8 | 8 | `offset` of the section |
| 16 | 8 | `length` of the section in bytes |

Section kinds:

| kind | name | required | presence |
|---:|---|---|---|
| 1 | strings | yes | always |
| 2 | types | yes | always |
| 3 | objects | yes | always |
| 4 | edges | yes | always |
| 5 | roots | yes | always |
| 6 | extras | no | always written (may hold 0 records) |
| 7 | memory_summary | no | only if the source had memory map data |
| 8 | meta | no | always written (may hold 0 records) |

Rules for readers:

- Each kind appears at most once.
- A section must lie entirely inside the file and after the section table.
- An unknown kind with the `REQUIRED` flag set means the file needs a newer
  reader: refuse it. An unknown kind without the flag is skipped.
- Missing required sections are an error.

This is how the format grows without a version bump: new optional data goes
in new section kinds. A change that old readers must not ignore uses a new
kind with `REQUIRED` set, or bumps `format_version`.

## Record sections

Every section except strings is a *record section*:

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `count` |
| 8 | 4 | `record_len` |
| 12 | 4 | reserved |
| 16 | `count * record_len` | records |

The section `length` must equal `16 + count * record_len` exactly.
`record_len` must be at least the size listed for that section below. A
reader uses `record_len` as the stride and reads only the fields it knows, so
later revisions can append fields to a record without breaking old readers.

### Strings (kind 1)

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `count` |
| 8 | 8 | `data_len` |
| 16 | `(count + 1) * 8` | `offsets[0..=count]`: u64, relative to the data start |
| 16 + (count+1)*8 | `data_len` | UTF-8 bytes, concatenated, no terminators |

String `i` is `data[offsets[i] .. offsets[i+1]]`. `offsets[0]` is 0 and
`offsets[count]` is `data_len`. The section length must equal
`16 + (count + 1) * 8 + data_len`. Strings are deduplicated by the writer, but
readers must not assume uniqueness. Readers check `offsets[i] <= offsets[i+1]
<= data_len` and UTF-8 validity on each lookup, not up front.

String 0 is not special. The writer always interns `source_ref` first, so it
is normally id 0.

### Types (kind 2), record_len 24

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `addr`: address of the type object (0 if unknown) |
| 8 | 4 | `qualname`: string id, the type's `__qualname__` (`dict`, `Session`, `Outer.Inner`) |
| 12 | 4 | `module`: string id, the type's `__module__` (`builtins`, `app.session`) |
| 16 | 8 | reserved |

The display name is `module + "." + qualname`, or `qualname` alone if `module`
is the empty string. Type ids are positions in this section.

### Objects (kind 3), record_len 40

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `addr`: object address in the target |
| 8 | 8 | `shallow_size`: bytes owned by this object alone |
| 16 | 8 | `edge_start`: index of the object's first edge in the edges section |
| 24 | 4 | `edge_count` |
| 28 | 4 | `type_id` (or `UNKNOWN_TYPE`) |
| 32 | 4 | `flags` |
| 36 | 4 | reserved |

Invariants, checked by the reader when the file is opened:

- `addr` is strictly increasing (sorted, no duplicates).
- CSR: object 0 has `edge_start` 0, and each object's `edge_start` equals the
  previous object's `edge_start + edge_count`. The last object's range ends
  exactly at the edges section's `count`.
- `type_id` is `UNKNOWN_TYPE` or less than the types `count`.

`shallow_size` is what `sys.getsizeof(obj)` would return, including the GC
header for GC-tracked objects (CPython's `__sizeof__` plus the pre-header) and
the out-of-line storage the object owns outright (a list's item array, a
dict's keys/values tables, a bytearray's buffer). Memory shared between
objects (such as split-table dict keys shared by instances) is attributed to
one owner only, the type for split keys. A split table's values array is
counted once: in the materialized `__dict__` if there is one (as
`getsizeof(dict)` does), otherwise in the instance that holds it (3.12 managed
values, 3.13+ inline values), which `getsizeof(instance)` leaves out.

Object `flags`:

| bit | name | meaning |
|---:|---|---|
| 0 | `GC_TRACKED` | found on a GC list / tracked by the GC |
| 1 | `PARTIAL` | some references could not be read; the edge list is incomplete |
| 2 | `IMMORTAL` | immortal refcount (3.12+) |
| 3 | `IS_TYPE` | the object is a type object (its address is also in the types section) |

Untracked objects (str, bytes, int, float, and containers the GC untracked)
appear only when a recorded object references them, and have bit 0 clear.

Address to index lookup is a binary search on `addr`.

### Edges (kind 4), record_len 16

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `target`: address of the referenced object |
| 8 | 4 | `label_operand` |
| 12 | 1 | `label_kind` |
| 13 | 1 | `label_flags` |
| 14 | 2 | reserved |

`target` is an address, not an object index: the target may be missing from
the dump (an untracked object the walker chose not to record, or a read
failure). The analyzer resolves targets with the binary search and counts
the misses as dangling edges. Edges are listed in the order the walker found
them, which for containers is item order.

### Edge labels

A label says why the source object references the target. It is what each
hop of a retaining path shows.

| kind | name | operand | rendered | used for |
|---:|---|---|---|---|
| 0 | `Other(desc)` | string id or `NO_STRING` | `<desc>` / `<?>` | references with no Python-level name |
| 1 | `DictValue(key)` | key string id | `[key]` | dict -> value stored under `key` |
| 2 | `DictKey(key)` | key string id | `<key [key]>` | dict -> the key object itself |
| 3 | `ListItem(index)` | index | `[index]` | list (and other mutable sequences) items |
| 4 | `TupleItem(index)` | index | `[index]` | tuple items |
| 5 | `SetItem` | 0 | `<set item>` | set / frozenset elements |
| 6 | `Attr(name)` | string id | `.name` | named fields, see below |
| 7 | `Type` | 0 | `.__class__` | `ob_type` |
| 8 | `CellContents` | 0 | `.cell_contents` | cell -> contents |
| 9 | `ClosureCell(index)` | index | `.__closure__[index]` | function -> closure cell |
| 10 | `FrameLocal(name)` | string id | `local 'name'` | frame -> local variable value |

Kinds 11-255 are reserved. A reader that meets one decodes it as
`Unknown { kind, flags, operand }` and renders `<edge kind=N>`.

`label_flags` bit 0, `KEY_REDACTED`, applies to kinds 1 and 2 only: the
operand string is a redaction placeholder (below), not the key's repr. All
other flag bits are reserved.

**Dict key operands.** For kinds 1 and 2 the operand is a string id holding
either the key's `repr()` text (`'cache'`, `3`, `('a', 1)`) or, with
`KEY_REDACTED`, a placeholder. `NO_STRING` means the key could not be read
and renders as `[?]`. Rendering is the same either way: `[` + text + `]`, so
`['cache']` and `[<str len=9>]`.

**`Attr(name)`** covers every reference that has a Python-visible name:

- an instance attribute stored inline (3.11+ inline values / managed dict
  without a materialized dict object);
- a `__slots__` member;
- a C struct member exposed under a Python name: `__dict__`, `__globals__`,
  `__code__`, `__defaults__`, `__self__`, `__func__`, `f_back`, `f_code`,
  `__weakref__`, and so on.

When an instance has a materialized `__dict__`, the walker emits
`Attr("__dict__")` to the dict and `DictValue` edges from the dict, rather than
pretending the dict is not there. Otherwise the dict's own size would be lost
from retained sizes. A module is a root whose `__dict__` is reached the same
way, which gives paths like `sys.modules['app.cache']` -> `.__dict__` ->
`['CACHE']`. Text renderers may collapse these hops for display.

### Redaction policy

By default (no `--capture-contents`), the snapshot records types, sizes,
lengths and references, but no string or bytes contents. Dict keys are
treated as follows:

**Always stored as text** (they are code identifiers, not data):

- attribute names (`Attr`), local variable names (`FrameLocal`);
- `str` keys of a module's `__dict__`;
- `str` keys of a type's `__dict__`;
- `str` keys of an instance `__dict__` (a dict reached from an object's
  dict slot).

The walker can only apply this rule to a dict it knows is one of these. If it
cannot tell, it must redact.

**Stored as text only with `--capture-contents`:** keys of every other dict
(ordinary dicts), and keys of any type other than `str` in the dicts above.
With contents capture the key's repr is stored, cut to `--max-str`
characters, with `...` appended when cut.

**Otherwise redacted** to a placeholder built from the key's type and length:
`<str len=9>`, `<bytes len=16>`, `<tuple len=2>`, `<int>` (types without
`len()` get no length). `heapspy_snapshot::redacted_key_placeholder` builds
it. The label has `KEY_REDACTED` set and renders as `[<str len=9>]`.

Captured contents in the extras section (`content`) follow the same rule:
present only when the header has `CONTENTS_CAPTURED`, cut to `--max-str`
characters with `...` appended and `CONTENT_TRUNCATED` set when cut. Root
labels and `source_loc` are always stored; they are names and file paths.
`source_loc` is built from a code object's `co_filename` and
`co_firstlineno`, which are code metadata, not data the program handles.
The analyzer reports it as `source_loc` and `type_location` (see "Source
locations" in `docs/json-schema.md`). A module's `__file__` is an ordinary
str value in the module dict, so its text is stored only with contents
capture.

### Roots (kind 5), record_len 16

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `addr`: the root object |
| 8 | 4 | `label`: string id, rendered root description |
| 12 | 1 | `root_kind` |
| 13 | 3 | reserved |

| code | root_kind | addr is | example label |
|---:|---|---|---|
| 0 | `other` | anything else held from outside the graph | `gc.garbage` |
| 1 | `module_dict` | a module object from `sys.modules` | `sys.modules['app.cache']` |
| 2 | `thread_locals` | per-thread state (thread dict, current exception) | `thread 4021 dict` |
| 3 | `frame_local` | the value of a live frame's local variable | `frame worker:run local 'pending'` |
| 4 | `interp` | interpreter-wide state (builtins, `sys` attributes, caches) | `interp builtins` |

Roots are not sorted and an address may appear more than once with
different labels. A root address may be missing from the objects section
(the analyzer reports it).

`frame_local` roots point at the variable's value, so the label carries the
frame and variable name. A walker may instead record frames as objects and
root the frame itself (kind `other`, label `frame worker:run`) with
`FrameLocal` edges; both are valid.

### Extras (kind 6), record_len 32

Optional per-object data, sparse: only objects that have at least one field
get a record.

| offset | size | field |
|---:|---:|---|
| 0 | 4 | `object_index` |
| 4 | 4 | `fields`: which of the following are present |
| 8 | 8 | `length`: `len()` of str, bytes, bytearray, list, tuple, dict, set, frozenset |
| 16 | 4 | `qualname`: string id (modules, functions, code objects, types) |
| 20 | 4 | `source_loc`: string id, `path/to/mod.py:88` (functions, code, frames) |
| 24 | 4 | `content`: string id, captured content (only with `CONTENTS_CAPTURED`) |
| 28 | 4 | reserved |

`fields` bits: 0 `LENGTH`, 1 `QUALNAME`, 2 `SOURCE_LOC`, 3 `CONTENT`,
4 `CONTENT_TRUNCATED`. A field whose bit is clear is ignored (written as 0).

Records are sorted by `object_index`, strictly increasing, each less than the
objects `count`; the reader checks this on open and looks records up by binary
search.

### Memory summary (kind 7), record_len 24

Totals from the process memory map, so the analyzer can say how much of RSS
is outside the Python graph. Present only if the source knew them.

| offset | size | field |
|---:|---:|---|
| 0 | 4 | `region_kind` |
| 4 | 4 | reserved |
| 8 | 8 | `mapped_bytes` |
| 16 | 8 | `resident_bytes`, or `0xFFFF_FFFF_FFFF_FFFF` if unknown |

| code | region_kind |
|---:|---|
| 0 | `other` |
| 1 | `heap` (brk heap / process default heap) |
| 2 | `anonymous` (private anonymous mappings) |
| 3 | `image` (executables and shared libraries) |
| 4 | `stack` |
| 5 | `python_arena` (pymalloc arenas, if identified) |
| 6 | `mapped_file` (file-backed data mappings) |

Several records may share a kind; readers sum them. Process RSS is the sum of
`resident_bytes`; if the source knows RSS directly it also records it as meta
key `process.rss_bytes`.

### Meta (kind 8), record_len 8

| offset | size | field |
|---:|---:|---|
| 0 | 4 | `key`: string id |
| 4 | 4 | `value`: string id |

Free-form key/value pairs. Keys in use:

| key | value |
|---|---|
| `heapspy.version` | version of the heapspy that wrote the file |
| `process.rss_bytes` | process RSS in bytes, decimal |
| `image.missing_bytes` | bytes of memory the image's headers describe but the file lacks (only written when non-zero), decimal |

## Validation on open

`Snapshot::open` checks, in order, and returns an error (never panics) on the
first failure:

1. magic, then `format_version == 1` (otherwise `UnsupportedVersion`), then
   the header is complete and `header_len` is sane;
2. `file_len` equals the actual length (shorter means truncated);
3. the section table and every section lie inside the file, no duplicate
   kinds, no unknown required kinds, all required kinds present;
4. every record section's length matches `16 + count * record_len` and
   `record_len` is large enough; the strings section's length matches;
5. the objects invariants (sorted, CSR-contiguous, valid type ids);
6. the extras invariants;
7. the header's `source_ref` string resolves.

After a successful open, object, edge, root and extras accessors cannot fail.
String lookups are checked individually. The file must not be modified or
truncated while it is mapped.

## Writer notes (not part of the format)

`SnapshotWriter` accepts objects in any order, each with all of its edges.
Object and edge records are appended to spill buffers (temporary files when a
spill directory is given); only 16 bytes per object (address, spill position)
and the string table stay in memory. `finish` sorts by address, rejects
duplicate addresses, and writes the file sequentially. `finish_to_path` writes
to a temporary file in the target directory and renames it into place.
