# Allocation profile format (`.hpya`), version 1

An allocation profile holds the allocation samples that `heapspy record`
took from one process during one window: for each sampled allocator event,
when it happened, which thread, what range was allocated, how many bytes it
stands for, and the Python stack that allocated it. The analyzer joins it
with a snapshot (`.hpy`) taken at the end of the window
(`heapspy analyze app.hpy --allocations app.hpya`). The design is in
`docs/allocation-sampling.md`.

This document is the normative description. The implementation is
`crates/heapspy-alloc`; its constants live in `src/format.rs` and must match
the tables here. The container follows the snapshot format
(`docs/snapshot-format.md`): magic, versioned header, section table with a
`REQUIRED` bit, record sections with `record_len`, little-endian, read by
memory-mapping and validated on open.

Design goals:

- A million samples or more. Fixed-size records, frames in CSR layout (each
  sample owns a contiguous frame range), no per-sample allocation when
  reading.
- Written in one sequential pass, so it can go to a pipe. The writer sorts
  samples by time before writing.
- Every integer decoded from byte slices, so nothing depends on alignment or
  host byte order.
- Readers can skip sections they do not know.
- No contents. Samples hold addresses, sizes, code object addresses and
  instruction offsets. The only text is code object names and file names,
  which are identifiers, not user data.

## Conventions

- All integers are **little-endian**.
- Offsets are byte offsets from the start of the file.
- `u8`/`u16`/`u32`/`u64` are unsigned, `i32` is two's complement. Reserved
  bytes are written as 0 and ignored on read.
- **String id**: a `u32` index into the strings section. `0xFFFF_FFFF`
  (`NO_STRING`) means "no string".
- **Blob id**: a `u32` index into the blobs section. `0xFFFF_FFFF`
  (`NO_BLOB`) means "no blob".
- **Code id**: a `u32` index into the codes section (the entry's position).
  `0xFFFF_FFFF` (`NO_CODE`) means the frame's code object was not
  identified.
- **Timestamps** are nanoseconds since the Unix epoch (UTC). A recorder with
  a monotonic clock converts once, with an offset measured when recording
  starts.
- **Instruction offset**: the byte offset of the executing instruction from
  the start of the code object's bytecode, `instr_ptr - _PyCode_CODE(co)`
  (`prev_instr` on 3.12). This equals the frame's `f_lasti` in bytes on
  every supported version and is what `PyCode_Addr2Line` takes.

## File layout

```
offset 0     header (128 bytes)
offset 128   section table (section_count x 24 bytes)
             padding to 8
             sections, each starting at a multiple of 8, in any order
             padding to 8
end          file_len (recorded in the header)
```

The writer emits sections in this order: strings, blobs, codes, samples,
frames, meta. Readers must not rely on the order; they use the section
table.

## Header (128 bytes)

| offset | size | field | notes |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `HPYA` (`48 50 59 41`) |
| 4 | 2 | `format_version` | `1`. Readers reject any other value. |
| 6 | 2 | `header_len` | `128`. A reader accepts values >= 128 and ignores the extra bytes. |
| 8 | 1 | `py_major` | e.g. 3 |
| 9 | 1 | `py_minor` | e.g. 12 |
| 10 | 1 | `py_micro` | e.g. 4 |
| 11 | 1 | `py_release_level` | `PY_RELEASE_LEVEL`: 0xA alpha, 0xB beta, 0xC rc, 0xF final |
| 12 | 1 | `py_release_serial` | `PY_RELEASE_SERIAL` |
| 13 | 1 | `pointer_size` | target pointer size in bytes: 8 |
| 14 | 1 | `os` | 1 = linux, 2 = windows, 3 = macos (same codes as the snapshot) |
| 15 | 1 | `arch` | 1 = x86_64, 2 = aarch64 (same codes as the snapshot) |
| 16 | 4 | `pid` | process id of the target |
| 20 | 4 | `flags` | see below |
| 24 | 4 | `mechanisms` | set of mechanisms that ran, see below |
| 28 | 4 | `events` | set of event kinds the recorder had enabled: bit `1 << event_kind` |
| 32 | 8 | `start_ns` | when recording started |
| 40 | 8 | `end_ns` | when recording stopped |
| 48 | 8 | `byte_interval` | mean bytes between kept large-object samples; 0 = every event kept |
| 56 | 4 | `max_frames` | most Python frames recorded per sample |
| 60 | 4 | reserved | |
| 64 | 8 | `samples_taken` | samples that reached the writer (normally the samples count) |
| 72 | 8 | `samples_dropped` | samples lost before the writer: ring buffer full, stack unreadable, rate limit |
| 80 | 8 | `probe_hits` | times a probe fired, including events the byte sampler skipped |
| 88 | 8 | `total_pause_ns` | total time target threads were stopped by the recorder, summed over threads; 0 for eBPF and ETW |
| 96 | 8 | `section_table_offset` | 128 in files written by this version |
| 104 | 4 | `section_count` | number of section table entries |
| 108 | 4 | reserved | |
| 112 | 8 | `file_len` | total file length in bytes; detects truncation |
| 120 | 8 | reserved | |

Unknown codes in `os` and `arch` are not errors; the reader reports them as
`Unknown(code)`. Unknown bits in `mechanisms` and `events` are kept.

Header `flags`:

| bit | name | meaning |
|---:|---|---|
| 0 | `TRUNCATED` | recording stopped before the requested window ended (the target exited, a probe was detached), or samples were lost in a way the overhead counters do not describe |

`mechanisms` bits:

| bit | name | what |
|---:|---|---|
| 0 | `ebpf` | Linux eBPF tracepoints and uprobes, Python stack read in the kernel |
| 1 | `ptrace` | Linux ptrace breakpoints on the arena path |
| 2 | `etw` | Windows Event Tracing; Python frames matched by time (approximate) |
| 3 | `debugger` | Windows debugger breakpoints on the arena path |

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
| 2 | blobs | yes | always |
| 3 | codes | yes | always |
| 4 | samples | yes | always |
| 5 | frames | yes | always |
| 6 | meta | no | always written (may hold 0 records) |

Rules for readers (as for snapshots):

- Each kind appears at most once.
- A section must lie entirely inside the file and after the section table.
- An unknown kind with the `REQUIRED` flag set means the file needs a newer
  reader: refuse it. An unknown kind without the flag is skipped.
- Missing required sections are an error.

New optional data goes in new section kinds; a change old readers must not
ignore uses a new kind with `REQUIRED` set, or bumps `format_version`.

## Strings (kind 1) and blobs (kind 2)

Both use the snapshot's strings layout:

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `count` |
| 8 | 8 | `data_len` |
| 16 | `(count + 1) * 8` | `offsets[0..=count]`: u64, relative to the data start |
| 16 + (count+1)*8 | `data_len` | bytes, concatenated, no terminators |

Entry `i` is `data[offsets[i] .. offsets[i+1]]`. `offsets[0]` is 0,
offsets never decrease, and `offsets[count]` is `data_len`; the reader
checks the whole offsets array on open. The section length must equal
`16 + (count + 1) * 8 + data_len`, and `count` is less than `2^32 - 1`.
Strings are UTF-8; blobs are raw bytes (line tables). The writer
deduplicates both; readers must not assume uniqueness.

## Record sections

Codes, samples, frames and meta are record sections:

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `count` |
| 8 | 4 | `record_len` |
| 12 | 4 | reserved |
| 16 | `count * record_len` | records |

The section `length` must equal `16 + count * record_len` exactly.
`record_len` must be at least the size listed below. A reader uses
`record_len` as the stride and reads only the fields it knows, so later
revisions can append fields to a record without breaking old readers.

### Codes (kind 3), record_len 32

One entry per code object seen in a frame.

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `addr`: address of the code object in the target |
| 8 | 4 | `qualname`: string id, `co_qualname` (`Cache.load`, `<module>`, `<lambda>`) |
| 12 | 4 | `filename`: string id, `co_filename` as the target has it |
| 16 | 4 | `firstlineno`: i32, `co_firstlineno` |
| 20 | 4 | `linetable`: blob id, the raw `co_linetable` bytes |
| 24 | 1 | `linetable_format`: see below |
| 25 | 1 | `flags`: bit 0 `UNRESOLVED` |
| 26 | 6 | reserved |

`linetable_format`:

| code | format |
|---:|---|
| 0 | none: no line table, lines are unknown |
| 1 | the location table of CPython 3.11 to 3.14 (`Objects/locations.md` in the CPython tree), as decoded by `heapspy_alloc::linetable` |

A reader that does not know a format reports lines as unknown. `UNRESOLVED`
means only `addr` is known (the code object could not be read); the other
fields are then `NO_STRING`, 0, `NO_BLOB`, 0.

`addr` is **not unique**. A code object freed during recording and another
allocated at the same address are two entries; frames refer to entries by
code id, not by address. Codes are in the order the recorder found them,
not sorted. The reader indexes them by address on open
(`Profile::codes_at`).

Validated on open: string ids are `NO_STRING` or in range and valid UTF-8;
blob ids are `NO_BLOB` or in range; `count < 2^32 - 1`.

#### Mapping an instruction offset to a line

The table is a sequence of entries, each covering 1 to 8 code units (2
bytes each) of bytecode, in order. An entry starts with a byte that has bit
7 set; its continuation bytes have bit 7 clear.

```
first byte: 1 cccc lll    c = code (0..=15), l = code units covered - 1
```

| code | form | line | following bytes |
|---:|---|---|---|
| 0-9 | short | unchanged | 1 byte `b`: column = `code << 3 \| b >> 4`, end column = column + `b & 15` |
| 10-12 | one line | + (code - 10) | column byte, end column byte |
| 13 | no columns | + svarint | none further |
| 14 | long | + svarint | end line delta (varint), column + 1 (varint), end column + 1 (varint) |
| 15 | none | unchanged; the instruction has no line | none |

A varint is little-endian groups of 6 bits, with bit 6 (0x40) set on every
group but the last. An svarint is a varint `v` read as `v >> 1`, negated
when `v & 1` is set. The running line starts at `firstlineno`.

To find the line of byte offset `o`: walk the entries, adding each entry's
length to a running byte offset, until the entry whose range contains
`o & ~1`; its line is the answer (none for code 15). An offset past the end
has no line. A frame without an offset (`NO_OFFSET`) resolves to
`firstlineno`, which is what `PyCode_Addr2Line` returns for a negative
offset. A table that does not decode (a continuation byte where an entry
should start, a truncated entry) gives no line from that point on; it never
fails the file.

`crates/heapspy-alloc/tests/linetable.rs` checks this against every code
object of a fixture source compiled by CPython 3.12, 3.13 and 3.14
(`co_positions()` and `co_lines()`).

### Samples (kind 4), record_len 64

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `timestamp_ns` |
| 8 | 8 | `tid`: OS thread id (Linux TID, Windows thread id) |
| 16 | 8 | `address`: start of the allocated range |
| 24 | 8 | `size`: bytes in the allocated range |
| 32 | 8 | `weight`: bytes of allocation this sample stands for |
| 40 | 8 | `native_return_address`: return address of the allocator call in native code; 0 if unknown |
| 48 | 8 | `frame_start`: index of the sample's first frame in the frames section |
| 56 | 4 | `frame_count` |
| 60 | 1 | `event_kind`: see below |
| 61 | 1 | `flags`: see below |
| 62 | 2 | reserved |

`event_kind`:

| code | kind | event |
|---:|---|---|
| 0 | `other` | anything else (a recorder-specific probe) |
| 1 | `arena` | a pymalloc arena was mapped (`mmap` / `VirtualAlloc`, 1 MiB on 3.10+) |
| 2 | `pool` | pymalloc carved a new 16 KiB pool out of an arena |
| 3 | `large_object` | an allocation above pymalloc's small-object threshold (512 bytes) went to the system allocator |

Codes 4-255 are reserved; a reader decodes them as `Unknown(code)`.

Sample `flags`:

| bit | name | meaning |
|---:|---|---|
| 0 | `APPROXIMATE_FRAMES` | the Python frames were matched to the event by time (ETW), not read at the event |
| 1 | `STACK_TRUNCATED` | the stack was deeper than `max_frames`; the outermost frames are missing |
| 2 | `NO_THREAD_STATE` | the allocating thread had no Python thread state (a native thread); no frames |

`weight`: arena and pool events are never sub-sampled and weigh their
`size`. Large objects are sampled by byte interval: the recorder keeps an
allocation of `s` bytes with probability `p = 1 - exp(-s / byte_interval)`
and weighs it `s / p` (`heapspy_alloc::sampled_weight`), so the sum of
weights estimates the bytes allocated. With `byte_interval` 0 every event
is kept and weighs its size.

Invariants, checked on open:

- `timestamp_ns` never decreases from one record to the next (samples are
  sorted by time; equal timestamps keep the order the recorder gave).
- CSR: sample 0 has `frame_start` 0, each sample's `frame_start` equals the
  previous sample's `frame_start + frame_count`, and the last sample's
  range ends exactly at the frames section's `count`.

Because samples are sorted by time, "a later sample covers this address"
(the rule the analyzer uses to link an object to the most recent sample
whose range contains it) is "a sample with a higher index".

### Frames (kind 5), record_len 12

The Python frames of each sample, innermost first: a sample's first frame
is the function that allocated.

| offset | size | field |
|---:|---:|---|
| 0 | 4 | `code_id`: code id, or `NO_CODE` |
| 4 | 4 | `instr_offset`: instruction offset in bytes (see Conventions) |
| 8 | 2 | `flags`: see below |
| 10 | 2 | reserved |

Frame `flags`:

| bit | name | meaning |
|---:|---|---|
| 0 | `APPROXIMATE` | this frame was attributed by time correlation |
| 1 | `NO_OFFSET` | `instr_offset` is not meaningful (the frame had not started, or the pointer was unreadable); the line is `firstlineno` |

Validated on open: `code_id` is `NO_CODE` or less than the codes `count`.

### Meta (kind 6), record_len 8

| offset | size | field |
|---:|---:|---|
| 0 | 4 | `key`: string id |
| 4 | 4 | `value`: string id |

Free-form key/value pairs; keys need not be unique. Keys in use:

| key | value |
|---|---|
| `heapspy.version` | version of the heapspy that wrote the file |
| `heapspy.recorder` | recorder that ran: `linux-ebpf`, `linux-ptrace`, `windows-etw`, `windows-debugger`, `windows-etw-debugger` |
| `heapspy.skipped_events` | comma-separated event kinds that were asked for but could not be recorded by this mechanism |

## Validation on open

`Profile::open` checks, in order, and returns an error (never panics) on
the first failure:

1. magic (`BadMagic`), then `format_version == 1` (`UnsupportedVersion`),
   then the header is complete and `header_len` is sane;
2. `file_len` equals the actual length (shorter means truncated, longer is
   trailing data);
3. the section table and every section lie inside the file, no duplicate
   kinds, no unknown required kinds, all required kinds present;
4. the strings and blobs sections' lengths and their full offsets arrays;
   every record section's length matches `16 + count * record_len` and
   `record_len` is large enough;
5. the codes invariants;
6. the samples invariants (time order, CSR);
7. the frames invariants.

After a successful open, code, sample and frame accessors, and the
resolved stack (`Profile::stack`), cannot fail. Meta strings are checked on
each lookup. The file must not be modified or truncated while it is mapped.
The tests cut the file at every length and flip bytes at every position and
at random, and check that no input panics.

## Writer notes (not part of the format)

`AllocWriter` accepts samples in any order, each with all of its frames.
Sample and frame records go to spill buffers (temporary files in the output
directory when a spill directory is given); only 16 bytes per sample
(timestamp, spill position) and the code, string and blob tables stay in
memory. Code entries can be added up front (`add_code`), or created from an
address while recording (`code_for_addr`, `add_unresolved_code`) and filled
in once the code object has been read (`set_code`). `finish` sorts the
samples by time (stable) and writes the file sequentially;
`finish_to_path` writes a temporary file in the target directory and
renames it into place.
