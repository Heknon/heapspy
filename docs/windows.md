# Windows: capturing and reading minidumps

On Windows heapspy reads the target from a **full-memory minidump** (`.dmp`).
There are two ways to get one:

- `heapspy dump --pid <pid> -o app.hpy` on the Windows machine. heapspy writes
  a temporary full minidump of the process, reads it, and deletes it.
- Capture a dump yourself (procdump, Task Manager, WinDbg) and convert it with
  `heapspy dump --minidump app.dmp -o app.hpy`. The conversion runs on any OS,
  so the dump can be copied to a Linux machine and converted there.

Only 64-bit targets (x86_64 and ARM64) are supported.

## Capturing with procdump

[procdump](https://learn.microsoft.com/sysinternals/downloads/procdump) from
Sysinternals, from an elevated prompt:

```bat
procdump -ma 1234 C:\dumps\app.dmp
procdump -ma python.exe C:\dumps\app.dmp
```

`-ma` is required: it writes all process memory (`MiniDumpWithFullMemory`).
The smaller dump types (`-mp`, `-mm`, the default without `-ma`) contain
thread stacks and a few referenced pages but not the heap, and heapspy rejects
them with an error that says so.

Other tools that write full-memory dumps:

- Task Manager: Details tab, right-click the process, "Create memory dump
  file" ("Create dump file" on older versions). The file goes to `%TEMP%`.
- WinDbg / cdb attached to the process: `.dump /ma C:\dumps\app.dmp`.
- Windows Error Reporting with `LocalDumps` and `DumpType` set to 2 (full).

## Permissions

Reading another process's memory needs `PROCESS_QUERY_INFORMATION` and
`PROCESS_VM_READ` access to it.

- A process running as the same user, at the same or lower integrity level,
  can usually be dumped without elevation.
- A process of another user, a service, or an elevated process needs
  `SeDebugPrivilege`. Administrators have it, but only in an elevated prompt
  ("Run as administrator"). heapspy and procdump both enable it when the token
  has it.
- Protected processes (PPL, for example antimalware services) cannot be dumped
  this way at all.

When access is denied, `heapspy dump --pid` fails with a "permission denied"
error naming these causes.

## Size and pause

A full-memory dump holds every committed page of the process: the private
memory (heaps, pymalloc arenas, stacks), the mapped DLL and EXE images, and
mapped file views. Expect the file to be about the process's commit size
(Task Manager, "Commit size" column) plus the size of its loaded images, and
make sure the target volume has that much free space.

`MiniDumpWriteDump` suspends all threads of the target while it copies memory
and resumes them when the file is written. The pause is roughly the time it
takes to write the file: a few seconds per several GiB on an SSD. procdump's
`-r` option takes the dump from a clone of the process, which shortens the
pause; heapspy reads the resulting dump the same way.

## What `heapspy dump --pid` does

1. Enables `SeDebugPrivilege` if the process token has it.
2. Opens the target with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
   PROCESS_DUP_HANDLE`. If `PROCESS_DUP_HANDLE` is refused it retries without
   it and leaves handle data out of the dump.
3. Calls `MiniDumpWriteDump` with `MiniDumpWithFullMemory |
   MiniDumpWithHandleData | MiniDumpWithThreadInfo | MiniDumpWithFullMemoryInfo
   | MiniDumpIgnoreInaccessibleMemory`, writing to a temporary file opened with
   `FILE_FLAG_DELETE_ON_CLOSE`. The file is removed when heapspy is done with
   it, including when heapspy exits on an error.
4. Reads the dump exactly as `--minidump` would.

The temporary file goes in the scratch directory passed to
`heapspy_reader::source::open_in`. `source::open` uses the system temporary
directory (`%TEMP%`). To keep the dump, capture with procdump instead, or use
`heapspy_reader::source::windows_live::write_dump`.

## What the dump must contain

| stream | required | heapspy uses it for |
|---|---|---|
| `Memory64ListStream` | yes | all memory reads. Ranges are sorted; a read may span adjacent ranges and fails if any byte is missing. |
| `SystemInfoStream` | yes | CPU architecture (AMD64 or ARM64) |
| `ModuleListStream` | in practice | finding `python3XY.dll`: name and path (UTF-16), base, size, file version, and the CodeView record (PDB GUID and age) |
| `ThreadListStream` | in practice | thread ids, TEB addresses (`ThreadInfo::tls_base`), stack pointers from the thread contexts |
| `ThreadNamesStream` | no | thread names set with `SetThreadDescription` |
| `MemoryInfoListStream` | no | protection of each range (`mapped_ranges`), committed bytes by kind (`memory_summary`), and allocation bases and reservation sizes for the native heap walk (`native_blocks`) |
| `MiscInfoStream` | no | process id and creation time |

The header's `TimeDateStamp` is recorded as the snapshot's capture time.

`MemoryListStream` (the memory list of small dumps) is read only when a caller
opts in with `MinidumpOptions::allow_partial_memory`, for looking at modules
and threads. It does not contain the heap.

### Memory summary

From `MemoryInfoListStream`, committed regions are counted as:

| snapshot region kind | minidump regions |
|---|---|
| `image` | `MEM_IMAGE` |
| `mapped_file` | `MEM_MAPPED` |
| `stack` | `MEM_PRIVATE` allocations that contain a thread's stack |
| `heap` | `MEM_PRIVATE` allocations whose base is a heap listed in the PEB (`ProcessHeaps`). This counts the first segment of each NT heap, not segments added later. |
| `anonymous` | all other `MEM_PRIVATE` memory, which includes pymalloc arenas (CPython allocates them with `VirtualAlloc`) |

Minidumps do not record which pages were resident, so resident bytes and RSS
are unknown.

### Native heap blocks

`MemorySource::native_blocks` lists every busy block of the target's NT heaps
(what `malloc` and `HeapAlloc` handed out), read from the heap metadata in the
dump the way WinDbg's `!heap` reads it. Nothing is asked of the target, so it
works the same for `--pid` and for a full-memory dump opened with
`--minidump`, on any host OS. The code and the details are in
`crates/heapspy-reader/src/source/minidump/nt_heap.rs`.

- **Which heaps.** On Windows 11 build 26300 `PEB.ProcessHeaps` listed only
  the default heap; `msvcrt.dll`'s private heap and other `HeapCreate` heaps
  were not in it. So heapspy also probes the base of every committed private
  allocation for an NT heap header, and walks every heap it finds.
  `NativeBlock::heap` indexes `PEB.ProcessHeaps` first, then the heaps found
  only this way, by address.
- **Backend blocks.** Each segment (the heap itself, then `_HEAP.SegmentList`)
  is walked header by header. Headers are XOR-decoded with `_HEAP.Encoding`,
  and their checksum and previous-size field are checked. Uncommitted runs
  (the segment's UCR list) are skipped. A header that fails a check, or
  cannot be read, ends that segment's walk; the other segments are still
  walked. A block is reported as `[header + 8, header + 8 + size)`, because on
  x64 a block's data may run into the first 8 bytes of the next header. The
  pointer the program holds is 8 bytes into the range.
- **Large blocks.** Allocations of about 512 KiB and more have their own
  `VirtualAlloc` (`_HEAP.VirtualAllocdBlocks`). The entry sits at a random page
  offset inside it, so the whole reservation (from `MemoryInfoListStream`) is
  reported as `Large`. Without that stream it is the entry and its committed
  size.
- **LFH.** Low-fragmentation-heap user blocks are decoded into their busy
  blocks (`Allocation`, one per busy bit, the full block stride each). The
  layout is checked against every block's header. An area that does not
  check out is reported whole as one `SmallBlockContainer`.
- **Left out.** Free blocks; the block holding the heap's `_LFH_HEAP`; and
  **segment heaps** (signature 0xDDEEDDEE, used by apps that opt in through
  their manifest and by many system processes, but not by `python.exe`).
  Segment heaps are detected and skipped. If no NT heap is found,
  `native_blocks` returns `None`.

Offsets used (64-bit Windows 10/11; ARM64 is assumed to match but was not
tested):

| structure | field | offset |
|---|---|---|
| `_HEAP_SEGMENT` | `SegmentSignature` (0xFFEEFFEE), `SegmentListEntry`, `Heap`, `FirstEntry`, `LastValidEntry`, `UCRSegmentList` | 0x10, 0x18, 0x28, 0x40, 0x48, 0x60 |
| `_HEAP` | `EncodeFlagMask`, `Encoding`, `Signature` (0xEEFFEEFF), `VirtualAllocdBlocks`, `SegmentList`, `FrontEndHeap` | 0x7c, 0x80, 0x98, 0x110, 0x120, 0x1a8 |
| `_HEAP_ENTRY` (decoded bytes 8..16) | `Size` (u16, ×16), `Flags`, checksum, `PreviousSize` (u16, ×16), `UnusedBytes` | 8, 0xa, 0xb, 0xc, 0xf |
| `_HEAP_UCR_DESCRIPTOR` | `SegmentEntry`, `Address`, `Size` | 0x10, 0x20, 0x28 |
| `_HEAP_VIRTUAL_ALLOC_ENTRY` | `CommitSize`, `BusyBlock` (user data at +0x40) | 0x20, 0x30 |
| `_HEAP_USERDATA_HEADER` | `SubSegment`, `Signature` (0xF0E0D0C0), `EncodedOffsets`, `BusyBitmap` (bits, buffer), bitmap words | 0, 0x14, 0x18, 0x20, 0x30 |
| `_HEAP_SUBSEGMENT` | `UserBlocks`, `BlockSize` (×16), `BlockCount` | 0x08, 0x24, 0x28 |

Verified on Windows 11 build 26300 (x64) by reading each field from live
processes and comparing the walk with `RtlQueryProcessDebugInformation`'s
heap block lists. On a CPython 3.12 process with about 400 MB of heap blocks
(250,000 `malloc`ed `bytes` objects), the walk found 253,539 blocks and 305 MB
(Rtl: 253,402 and 305 MB) plus the same 22 large blocks, in about 0.2 s.

## Finding CPython in the dump

- **Module.** The runtime is in `python3XY.dll` (`python312.dll`,
  `python313.dll`, `python314.dll`), with a `t` suffix for free-threaded builds
  (`python313t.dll`) and `_d` for debug builds (`python313_d.dll`).
  `python3.dll` is the stable-ABI forwarder and does not contain the runtime.
  `symbols::pe::python_dll` parses these names.
- **venv launchers.** A venv's `Scripts\python.exe` is not the interpreter:
  it is a small launcher that loads no `python3XY.dll` and starts the base
  `python.exe` as a child process. Dump the child's pid, not the launcher's.
  heapspy says so when it is given a launcher
  (`symbols::is_windows_launcher`).
- **`_PyRuntime`.** Exported by `python3XY.dll`. heapspy reads the DLL's PE
  headers and export directory from the dump's memory (the image headers are
  part of every full-memory dump) and resolves the name to `base + RVA`.
- **Version.** The DLL's file version encodes the full CPython version:
  `3.12.4150.1013` is 3.12.4 final (the third field is `micro * 1000 +
  release_level * 10 + serial`). See
  `symbols::pe::python_version_from_file_version`.
- **Debug symbols.** The CodeView record gives the PDB name, GUID and age,
  which identify the matching PDB on a symbol server. `Module::build_id` holds
  the 16 GUID bytes as stored in the file followed by the age as a
  little-endian u32.

## Converting on another machine

The parser is plain Rust with no Windows dependency. Copy the `.dmp` file and
run `heapspy dump --minidump app.dmp -o app.hpy` on Linux or macOS. The file
is memory-mapped, so converting a multi-GiB dump does not need that much RAM;
it must not be modified while heapspy reads it.

## Recording (`heapspy record`)

`heapspy record` on Windows records pymalloc arenas through ETW: a real-time kernel session with `VirtualAlloc` events, and Python frames sampled every 5 ms and matched by time, so they are flagged approximate. It does not stop the target. `--mechanism auto` is ETW only.

`--mechanism debugger` gives exact stacks: a breakpoint on `VirtualAlloc`, with the stack read while the thread is stopped. Every breakpoint stops every thread of the target. On windows-latest the target was stopped for 2.5 to 2.9 s of a 3 s recording, so this mechanism is used only when asked for, and heapspy prints a warning when it is. The design and results are in [allocation-sampling.md](allocation-sampling.md#windows-etw-plus-debugger-breakpoints) and [windows-record-test-plan.md](windows-record-test-plan.md).

### When heapspy is killed

If heapspy dies while recording (`TerminateProcess`, `taskkill /F`, a crash), a **guardian** process cleans up after it:

- The recorder starts `heapspy __guardian <recorder pid>` before it changes anything. The guardian runs in its own process group, so Ctrl-Break to the recorder does not reach it. It breaks away from the recorder's job when the job allows that. It watches the recorder's process handle and its stdin pipe.
- The recorder tells it what it changes: each byte, *before* writing `int3` there, and again after writing the original back; the ETW session it started; and a duplicate of its debug object. Because the guardian holds that handle, the debug object outlives a killed recorder. The target stays attached to it, with the dead recorder's pending debug state intact.
- When the recorder ends without saying `done`, the guardian installs the debug object as its own and becomes the target's debugger. It writes back each original byte, but only where the byte still holds heapspy's `int3`; other bytes are skipped and reported. It then suspends each thread in turn. A thread stopped just after one of our `int3`s is rewound onto the restored instruction, a trap flag is cleared, and an event the recorder had read but not continued is continued. Events still queued are handled the same way until the target is quiet. Then it detaches, stops heapspy's ETW session by name, and writes one line to stderr and the details to `<profile>.guardian.log`. It never runs code inside the target.
- On a clean finish, an error, or a panic, the recorder detaches and stops the session itself, then sends `done`. The guardian exits without acting. It also exits when the target exits, unless an ETW session still needs stopping.
- **Found on windows-latest** (two `kill_mid_run_debugger` runs, `TerminateProcess` 2.5 s into a debugger recording):
  - Always: the `int3` on `VirtualAlloc`'s first byte (restored, `0xcc -> 0x48`) and the debug attachment. The debug object outlived the recorder because the guardian held it, so the target stayed attached until the guardian detached it.
  - In one run, also a thread in the middle of a step over the breakpoint: its trap flag was set and its `EXCEPTION_SINGLE_STEP` event had been read by the recorder and not continued. The thread was blocked in that event. The guardian cleared the flag and continued the event (`DBG_CONTINUE`). Left alone, the thread stays blocked until the debug object closes, and then the target dies with `STATUS_SINGLE_STEP` (0x80000004) or, from the `int3`, `STATUS_BREAKPOINT` (0x80000003).
  - No thread was seen stopped right after an `int3` (`rip` one past a patched byte). The rewind is there for a kill that lands inside a breakpoint hit.

**Limits.**
- A process-tree kill (`taskkill /T /F`, a job object closed with kill-on-close where breakaway is not allowed) also kills the guardian. Then the `int3` stays in the target, and the ETW session keeps running until the next `heapspy record` stops it (see below) or `logman stop heapspy-<pid> -ets`.
- A library embedding the recorder needs a `heapspy.exe`: `HEAPSPY_GUARDIAN_EXE`, or one next to its executable or one directory up. Without it the recording runs and warns that nothing will clean up after a kill.
- The guardian treats any trap flag in the target as the recorder's. A target that single-steps itself under heapspy's debugger is not supported anyway.

**ETW session.** The session is `heapspy-<recorder pid>`, a `SystemTraceProvider` session in `EVENT_TRACE_SYSTEM_LOGGER_MODE` (Windows 8 / Server 2012 and later; confirmed on windows-latest), so it does not take the single `NT Kernel Logger`, and two recordings or another kernel tracer can run side by side. Where Windows refuses the mode, heapspy falls back to `NT Kernel Logger`. At start, sessions named exactly `heapspy-<pid>` whose pid is not a running heapspy are stopped, and the stop is printed. No session of any other name is touched. A real conflict fails with `unsupported`, and the message names the session. Stopping a system logger session needs a bare properties block (sizes and name offsets): passing the start block, with its GUID and kernel flags, fails with `ERROR_INVALID_PARAMETER`.
