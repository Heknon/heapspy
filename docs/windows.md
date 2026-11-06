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
| `MemoryInfoListStream` | no | protection of each range (`mapped_ranges`), and committed bytes by kind (`memory_summary`) |
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

## Finding CPython in the dump

- **Module.** The runtime is in `python3XY.dll` (`python312.dll`,
  `python313.dll`, `python314.dll`), with a `t` suffix for free-threaded builds
  (`python313t.dll`) and `_d` for debug builds (`python313_d.dll`).
  `python3.dll` is the stable-ABI forwarder and does not contain the runtime.
  `symbols::pe::python_dll` parses these names.
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
