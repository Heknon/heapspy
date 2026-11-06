# Allocation sampling (M7): design

Status: in progress. The shared contracts are in place: the `.hpya` format ([docs/alloc-format.md](alloc-format.md), `crates/heapspy-alloc`), the recorder interface (`crates/heapspy-record`), the frame offsets recorders read stacks with (`heapspy_reader::cpython::frames`), the `record` command and `--allocations` flags, and the report fields ([docs/json-schema.md](json-schema.md#allocations)). The recorders (M7a, M7b) and the join (M7c) are stubs. [Decisions](#decisions) records what was settled while building the contracts. The spike checklist at the end is still open.

## Why

A snapshot shows what is retained and by whom. It cannot show where an object was allocated, because CPython does not store that. For most leaks the retaining path is enough. It falls short when one type is created by several code paths and ends up in the same container. Then you need the allocating stack.

That history can be recorded from outside the process, but only for allocations made after recording starts. `heapspy record` attaches to a running process for a bounded window, samples allocations with their Python stacks, and writes a sidecar file. The analyzer joins it against a snapshot taken at the end of the window.

## Constraints

These carry over from the rest of heapspy:

- **No code runs inside the target.** No injected library, no `sys.remote_exec`, no tracemalloc. Every mechanism below observes the process from the kernel or from a debugger.
- **Overhead is bounded and stated.** Recording is opt-in, time-limited (`--duration`, required), and reports the measured cost when it stops.
- **Python stacks, not just native ones.** A native stack ending in `_PyEval_EvalFrameDefault` tells you nothing. Every sample must carry Python frames (code object and instruction offset), resolved to `file:line` afterwards.
- **Contents are never recorded.** Samples hold addresses, sizes, code object pointers and offsets. Function names and file names come from code objects, and they are identifiers, not user data.

## Command

```sh
heapspy record --pid 1234 --duration 60s -o app.hpya
heapspy dump   --pid 1234 -o app.hpy
heapspy analyze app.hpy --allocations app.hpya
```

`record` can also take the final snapshot itself (`--then-dump app.hpy`), so the samples and the snapshot line up in time.

## What gets sampled

Probing every allocator call is too slow. A Python process can make millions of small allocations per second, and a trap costs on the order of a microsecond. So heapspy samples events that are rare and still tell you about growth:

| Event | Granularity | Notes |
|---|---|---|
| pymalloc arena allocation | 1 MiB (256 KiB before 3.10) | Arenas come from `mmap` on Linux and `VirtualAlloc` on Windows. Linux sees them through a syscall tracepoint, which needs no symbols. |
| pymalloc new pool carved from an arena | 16 KiB, one size class | Better attribution than arenas. Needs a probe on an internal function, which may be inlined. Verify for each build. |
| Large object allocation (> 512 bytes, goes to the system allocator) | per call, sampled | Fewer calls than small objects, but still frequent. Use a byte-interval sampler: keep a sample when the accumulated bytes pass the next random threshold. |

Arena and pool events happen only when the allocator needs fresh memory, which is what happens while a process is leaking. Blocks reused from freed memory are not sampled. This is a deliberate bias: the output is **an estimate of where growth came from**, and it says so. It does not try to profile all allocation churn.

Each sample records:
- timestamp
- thread id
- event kind
- address range
- size
- the native return address
- up to 64 Python frames, each as `(code object address, instruction offset)`

Code object addresses are turned into `qualname` and `file:line` after recording stops. Recording reads them from the target. A later snapshot also has them as `source_loc` extras, so most stay resolvable.

## Linux: eBPF

- **Probes.**
  - `tracepoint:syscalls:sys_enter_mmap` / `sys_exit_mmap`, filtered by pid and by the arena size, catch arenas.
  - A uprobe on the pool-carving function catches pools where the symbol exists.
  - A uprobe on `PyMem_RawMalloc`/`malloc`, with an in-kernel size filter and a byte-interval sampler, catches large objects.
- **Python stack capture inside the BPF program.**
  - Find the current thread's `PyThreadState`: walk `interp->threads` comparing `native_thread_id` with the current tid, or read the thread-local `_Py_tss_tstate` through the task's `fsbase` where the TLS offset is known.
  - Then follow `current_frame` → `previous`, copying `f_executable` and `instr_ptr` per frame.
  - The offsets come from the same per-version tables (and `_Py_DebugOffsets` on 3.13+) that the snapshot walker uses, passed to the program as a map.
  - This is the technique Parca and Pyroscope use for Python CPU profiling.
- **Output.** Samples go out through a ring buffer, and user space writes them to the `.hpya` file.
- **Crate.** `aya` keeps it in pure Rust with no clang at runtime. Build the BPF object at compile time and embed it.
- **Permissions.** `CAP_BPF` + `CAP_PERFMON` (or root), and kernel 5.8+ for the ring buffer. In containers this needs the capabilities and access to the host's tracefs.
- **Fallback when eBPF is unavailable.** A ptrace breakpoint on the arena path only. That event is rare enough to stop the thread for each hit, read the Python stack with `process_vm_readv`, and continue. Slower per event, same output.

## Windows: ETW plus debugger breakpoints

ETW records native stacks with low overhead, but it cannot run code at event time. So it cannot read `PyThreadState` while the allocating thread is still at the allocation site. heapspy uses two mechanisms, each where it is good:

1. **ETW for counts and native context, without stopping the target.**
   - A real-time kernel session with `EVENT_TRACE_FLAG_VIRTUAL_ALLOC` and stack walk on VirtualAlloc catches arenas.
   - The heap provider, with heap tracing enabled for the target pid and stack walk on `HeapAlloc`/`HeapRealloc`, catches large objects.
   - Python frames are attributed **approximately**. A side thread samples each Python thread's frame chain with `ReadProcessMemory` at a fixed rate (py-spy style), and each ETW event is matched to the nearest Python stack sample for that thread by timestamp. The output marks these frames as approximate.
2. **Debugger breakpoints for exact Python stacks on rare events.**
   - `DebugActiveProcess` with `DebugSetProcessKillOnExit(FALSE)`, plus a breakpoint on the arena allocation path. That is `VirtualAlloc` called from `python3XY.dll`, or the internal arena function when PDB symbols are available. python.org publishes PDBs.
   - On each hit, read the stopped thread's Python stack, record it, and continue.
   - Arena events are rare, so the pause per event costs little in total.
   - Detach with `DebugActiveProcessStop`. The target is never killed on exit.

Both need an elevated process with `SeDebugPrivilege`. ETW heap tracing on an already running process needs to be confirmed on the Windows versions we support. Pinning that down is part of the spike.

## Sidecar format (`.hpya`)

Specified byte for byte in [docs/alloc-format.md](alloc-format.md). This uses the same container conventions as `.hpy`: magic `HPYA`, a versioned header, and a section table. It holds:

- **header:** pid, python version, start and end time, the mechanisms used, sampling parameters, and the measured overhead
- **string table** and **code table:** code address → qualname, filename, first line, and the line table bytes needed to map instruction offsets to lines
- **samples:** fixed-size records with a frame-chain offset
- **frames:** `(code_id, instr_offset, approximate: bool)`

## Joining with a snapshot

- **By address.** If an object's address falls inside a sampled pool or large allocation, and no later sample covers that range, the object is linked to that sample. This gives a per-object `allocated_at` for some objects. Only some get one, because only a sample of allocations is recorded.
- **By site.** Sampled growth bytes are aggregated by Python stack, and the stacks that produced the most growth are shown next to the top retainers. For each retainer, the stacks of the linked objects in its dominator subtree are summed.
- **Report additions** (schema v1, additive): `allocations` on `AnalyzeReport` (top growth stacks, sampling parameters, the approximate flag, coverage) and `allocated_at` on retainer entries and on `query --type` instances. Older consumers ignore both. Defined in [docs/json-schema.md](json-schema.md#allocations).
- **MCP:** a new `allocation_sites` tool, and `heap_summary` passes `allocated_at` through when a sidecar is given.

## Decisions

Settled while building the shared contracts, before the recorders.

**Crates.**
- `heapspy-alloc` is the format: types, `AllocWriter`, `Profile`, the line-table decoder and `ProfileBuilder` for tests. It depends only on `heapspy-snapshot` (for `PythonVersion`, `Os`, `Arch`), so the analyzer can read profiles without pulling in recorders.
- `heapspy-record` holds the recorders and what they share: `RecordOptions`, the `Recorder` trait, `Target`, `SampleSink`, and `record` / `record_with`, which own the header, the overhead fields and the file. It depends on `heapspy-reader` and `heapspy-alloc`. Platform crates (`aya`, ETW bindings) go here, behind `cfg`.
- The join lives in `heapspy-analyzer::allocations` (`analyze_with_allocations`, `query_type_with_allocations`), next to the dominator tree it needs.

**CPython offsets for recorders.** A recorder calls `Target::locate`, which runs `heapspy_reader::cpython::locate_runtime` and `cpython::frame_offsets` on a reader of the running process. That is the same code and the same per-version tables the snapshot walker uses, with `_Py_DebugOffsets` applied on 3.13+. `FrameOffsets` is the subset needed to go from `_PyRuntime` to each thread state, along the frame chain, and into code objects. It is plain `Copy` data, so the eBPF recorder copies it into a map. `cpython::frames::{thread_states, read_stack, read_code}` are the user-space reference for the same walk; the ptrace, debugger and ETW-sampler paths use them directly. Two fields were added to the offset table for this: `instr_ptr` (`prev_instr` on 3.12, 56 on all three versions) and `co_code_adaptive` (192, 200, 208). An ignored test reads the stack of running 3.12, 3.13 and 3.14 processes and checks every frame's function and line.

**Reading a running process.** `heapspy dump`'s live sources stop the target, which a recorder must not do. `heapspy_record::live::open` is the seam for a reader that never stops it: `process_vm_readv` on Linux, `ReadProcessMemory` on Windows. It is a stub, with notes, for M7a and M7b to fill in.

**Code objects.**
- Frames are recorded as (code object address, instruction offset).
- `SampleSink` reads each code object the first time its address appears, while the frame using it is executing and the object is alive. This replaces "after recording stops" above: by then a short-lived code object (a lambda, exec'd code) may be gone. The snapshot's `source_loc` extras remain a fallback for entries left unresolved.
- Code entries are keyed by address but not unique: an address can be reused during the window, and a recorder that notices this starts a new entry (`SampleSink::refresh_code`). Frames refer to entries by id.

**Instruction offsets and lines.**
- The offset is `instr_ptr - _PyCode_CODE(code)` in bytes, which is `f_lasti` on every supported version.
- The code table stores raw `co_linetable` bytes with a format code. Format 1, the 3.11 to 3.14 location table, is decoded in `heapspy_alloc::linetable` and checked against `co_positions()` of real code objects from 3.12, 3.13 and 3.14.
- A frame that has not started (3.12 `prev_instr` before the code) has no offset and resolves to `co_firstlineno`, as `PyCode_Addr2Line` does.

**Samples.**
- Timestamps are Unix-epoch nanoseconds.
- The file is sorted by time, so "a later sample covers this address" in the join is "a sample with a higher index".
- Arena and pool samples weigh their size. Large objects use a Poisson byte sampler: keep with probability `1 - exp(-size / interval)` and weigh `size / p` (`heapspy_alloc::sampled_weight`).
- Frames are innermost first, with flags for approximate frames (ETW), a truncated stack, and a native thread with no thread state.

**Defaults.** `--events arena,large`, `--interval 512K`, `--max-frames 64` (at most 1024). The interval is provisional until the spike measures the uprobe overhead.

**Mechanism selection.**
- `--mechanism auto` on Linux tries eBPF, then ptrace. Each recorder's `probe` returns `Unsupported` or `PermissionDenied` to move on.
- On Windows, `auto` runs ETW and debugger breakpoints together. `etw` or `debugger` runs one; with `debugger` alone, only arenas are recorded.
- The ptrace fallback records arenas only. It notes the event kinds it skipped in the `heapspy.skipped_events` meta key instead of failing.

**Failure handling.** A recording that fails writes no file; the writer only renames its temporary file into place on success.

**Joining, until M7c.**
- `--allocations` opens and validates the profile. It then checks the profile against the snapshot (`AFTER` for diff): the pid (for live-process snapshots), the CPython version, and that the snapshot was not taken before recording started.
- A mismatch is a warning on stderr and a note in the report (`allocations_pid_mismatch`, `allocations_python_mismatch`, `allocations_after_snapshot`).
- While the join is a stub, `analyze` and `query --type` print the plain report with an `allocations_not_joined` note. `diff` and `--retaining-path` have no allocation fields and only check the profile.
- A missing profile is error code `io`. A corrupt one is `invalid_allocations`.

**Report fields.** The new fields are always present in new documents (`null` without `--allocations`), as the schema rules require. They deserialize to `null` when missing, so documents from older versions still parse.

## Milestones

| | Deliverable |
|---|---|
| M7a | Linux eBPF recorder: arena and large-object probes, Python stack capture, `.hpya` writer, overhead measurement |
| M7b | Windows recorder: ETW session, debugger-breakpoint path, approximate stack correlation |
| M7c | Analyzer join, report fields, text output, MCP tool, e2e fixtures with a known allocating call chain on both OSes |

## Spike checklist

- Find out which builds (Debian, python.org, python-build-standalone, Windows python.org) expose a probe-able pool-carving function, and which inline it.
- Measure the overhead of the large-object uprobe with the byte sampler on an allocation-heavy benchmark. Pick the default interval.
- On 3.12, 3.13 and 3.14, verify that eBPF can find the current `PyThreadState` within the verifier's instruction limits.
- Confirm that ETW heap tracing can attach to a running process, and measure how far apart ETW events and Python stack samples land in time.
- Confirm that the breakpoint path works with Windows Defender and other EDR software running, since attaching a debugger can trigger them.
