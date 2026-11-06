# Allocation sampling (M7): design

Status: built. The `.hpya` format ([docs/alloc-format.md](alloc-format.md), `crates/heapspy-alloc`), the recorder interface and recorders (`crates/heapspy-record`), the frame offsets recorders read stacks with (`heapspy_reader::cpython::frames`), the `record` command and `--allocations` flags, the join (M7c) and the report fields ([docs/json-schema.md](json-schema.md#allocations)). The Linux recorders (M7a) are tested against live 3.12, 3.13 and 3.14 processes; the Windows recorder (M7b) is compiled and its logic unit-tested, but has not run on Windows yet ([test plan](windows-record-test-plan.md)). [Decisions](#decisions) records what was settled while building the contracts, [Measurements](#measurements) the overhead, and [Spike results](#spike-results) what the spike found.

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

As built (`crates/heapspy-record/src/linux_ebpf.rs` has the details, `bpf/heapspy.bpf.c` the kernel side):

- **Arenas.** Raw tracepoints `sys_enter` / `sys_exit`, filtered in the kernel to the target's tgid and to `mmap(NULL, 1 MiB, ..., MAP_ANONYMOUS, -1, ...)`, enter and exit paired per thread. No symbols, no tracefs.
- **Pools.** Not recorded: no build tested has an out-of-line pool-carving function. Asked for, they go to meta `heapspy.skipped_events`.
- **Large objects.** Probes on `_PyMem_RawMalloc`, `_PyMem_RawCalloc` and `_PyMem_RawRealloc` when the interpreter's `.symtab` has them, else libc `malloc`, `calloc` and `realloc` (Debian's 3.12 has only dynamic symbols). pymalloc hands every request above 512 bytes to the raw allocator, so either set sees every large object. `_PyObject_Malloc` is not probed, because it calls the raw allocator and nested probes overwrite each other's pending entry. The size filter (> 512) and the byte-interval sampler (a per-CPU countdown refilled from 256 quantiles of an exponential distribution) run in the kernel.
  - **Kernel 6.13+:** one *uprobe session* program per function. The entry decides whether the call is sampled and returns non-zero to skip the return probe, so an unsampled call costs one trap, not two.
  - **Older kernels:** a uprobe and a uretprobe per function, as perf events for the target pid.
  - Entries and returns are paired by (tid, stack pointer at entry), which is exact under nesting.
  - A leading `endbr64` (CET builds of glibc) is skipped: the kernel cannot emulate it and single-steps it out of line, which made every libc `malloc` hit cost tens of microseconds (Debian 3.12 ran at 2% of its speed). The next instruction, `push %rbp`, is emulated.
- **Python stack in the kernel.** The thread state is found by `native_thread_id` (an LRU cache, else a bounded walk of 4 interpreters × 256 threads), then the frame chain is followed exactly like `read_stack`: `cframe` on 3.12, entry frames (owner `FRAME_OWNED_BY_CSTACK`, or `FRAME_OWNED_BY_INTERPRETER` on 3.14) skipped, `f_executable & ~3` on 3.14. Up to 128 frames are copied (more are marked truncated). User space keeps the frames whose type is `code` and whose code object is not CPython's `_Py_InitCleanup` shim ("Shim frames" under [Decisions](#decisions)), and computes instruction offsets. Bounded loops, no `bpf_loop`; the frame count lives in map memory so the verifier prunes loop states (with it in a register, the walk hit the 1M-instruction limit).
- **Output.** Events are assembled in a per-CPU scratch map and copied to a 16 MiB ring buffer with only the frames used. Reserving fixed-size 3 KiB events dropped about 7% of samples at high rates; this drops none in the benchmark. Times are `CLOCK_MONOTONIC`, converted with an offset measured at start.
- **Build.** No `aya` and no libbpf: the BPF object is built from C with clang (`bpf/build.sh`, clang 18), committed, and embedded with `include_bytes!`. A ~300-line loader on the `object` crate creates the maps (legacy `maps` section, no BTF) and patches map references. A plain `cargo build` needs no clang, so the manylinux wheel builds need nothing new. After editing `heapspy.bpf.c`, run `bpf/build.sh` and commit the object. `bpf/build.sh --check` (or the ignored test `committed_object_matches_source`) verifies that the committed copy matches the source. x86_64 only.
- **Cleanup.** Every map, program and attachment is a file descriptor (uprobe perf events or links for the pid, raw tracepoint links). Nothing is registered in tracefs, so the kernel removes everything when heapspy exits, however it exits, SIGKILL included. While probes are attached, the kernel's copy-on-write pages of the target's code hold `int3`s; they are restored when the probes go. The live tests check both.
- **Permissions.** Root, or `CAP_BPF` + `CAP_PERFMON` and `CAP_SYS_PTRACE` (for reading the target), kernel 5.8+. `auto` falls back to ptrace on `PermissionDenied` or `Unsupported`.

### Fallback: ptrace

Arenas only, with exact stacks (`linux_ptrace.rs`). Every thread is seized with `PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE`, and syscall stops are used: no symbols, and nothing is written into the target. At an arena `mmap`'s exit the thread is still stopped inside the allocating call, so `read_stack` reads exact frames. The tracer waits in `sigtimedwait(SIGCHLD)`, so each stop is handled when it is reported. Group stops are kept with `PTRACE_LISTEN`, and signals are re-injected. Every thread is detached on every exit path; if heapspy is killed, the kernel detaches the tracees.

**Pause per hit.** Every syscall of every thread stops twice, not only `mmap`. Seccomp filtering would avoid that, but it needs code run in the target. The tracer's own handling is about 9 µs per stop (`total_pause_ns` / `probe_hits`), and an arena hit adds the stack read. The full cost includes two context switches per stop: a victim making 25k `stat` calls a second ran 86% slower under ptrace. A victim that makes few syscalls barely notices it (see [Measurements](#measurements)).

## Windows: ETW plus debugger breakpoints

**As built** (`crates/heapspy-record/src/windows.rs`; compiled and unit-tested on Linux, not yet run on Windows, see [the test plan](windows-record-test-plan.md)):
- Arenas only, on both paths. Heap tracing applies only to processes started after `TracingFlags` is set in Image File Execution Options, so it cannot attach to a running process. Large objects go to `heapspy.skipped_events`.
- ETW: the "NT Kernel Logger" with `EVENT_TRACE_FLAG_VIRTUAL_ALLOC`, `PageFault_VirtualAlloc` events of 1 MiB with `MEM_COMMIT | MEM_RESERVE`, no stack walks. A real-time consumer gets FILETIME timestamps. A side thread samples every Python thread's stack every 5 ms. An event takes the same thread's nearest sample within 20 ms (`windows::matcher`), else no frames. Events are held 2 s so that an arena the debugger also saw is written once, with exact frames. `EventsLost` and `RealTimeBuffersLost` count as dropped.
- Debugger: a breakpoint on `VirtualAlloc` in `kernelbase.dll` (found through the export table, no PDBs). A hit is an arena call when the arguments match and `[rsp]` is in the Python DLL. The stack is read there, and a one-shot breakpoint at the return address gets the result. The event loop is a pure state machine (`windows::debug`) with unit tests. It removes every `int3` and trap flag and drains late hits before `DebugActiveProcessStop`, also on drop.
- `live::open`: `ReadProcessMemory`, `EnumProcessModulesEx`, a Toolhelp thread snapshot. Nothing is suspended.

The design as first written:

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

Implemented in `heapspy_analyzer::allocations`. `analyze --allocations`, `query --type --allocations` and `flamegraph --allocations` use it.

**Preconditions.** The profile is checked against the snapshot first: same pid (for a snapshot of a live process), same CPython version, and recording started no later than the snapshot. If any check fails, the report carries the mismatch note and `allocations_not_linked`, no object is linked, and only the sampled stacks are reported. Samples whose timestamp is past the snapshot's capture second are not used for linking, because they describe memory the snapshot has not seen.

**By address.** A sample covers `[address, address + size)`: a pool sample one 16 KiB pool, an arena sample one 1 MiB arena, a large-object sample one allocation. An object is linked to the latest sample (highest index, since samples are sorted by time) whose range contains the object's address. A later sample over the same memory supersedes an earlier one, because the memory was freed and reused in between. The objects are already sorted by address. The join sorts the sample ranges by start once, then walks the objects in address order. Each sample whose range starts at or before the current address is pushed onto a max-heap keyed by sample index. Samples whose range has ended are popped from the top. The top is then the answer. An ended sample below the top is popped later, when it reaches the top. It never hides a live sample, because the top has the largest index of all entries. Each sample is pushed and popped once, so the sweep is `O(n + m log m)` for `n` objects and `m` samples. It needs `O(m)` extra memory (ranges, order, heap) plus one `u32` per object for the result.

**Large-object samples link only their own allocation.** A large-object sample describes one allocation: a requested size at an address. With a byte-interval sampler most large allocations are not sampled, and the system allocator readily puts a new block where a freed one was. So the latest sample over an object's address is often an earlier, freed block, and the object is a later allocation that was not sampled. Linking it to that sample would be wrong and labelled exact: a recording of a service that leaks 8 KB blobs per session while rendering and dropping 20 KB pages attributed 13 MiB of the leak to the page renderer. An object is therefore linked to a large-object sample only if it is that allocation (`allocations::matches_large_object`):

- **Start.** The allocation starts at the object minus its pre-header (`_PyType_PreHeaderSize`, the same on 3.12, 3.13 and 3.14): 0 for a type without `Py_TPFLAGS_HAVE_GC`, 16 for the GC header, 32 for the GC header plus the managed dict and weakref words. The snapshot does not record type flags, and a GC object the collector untracked (an atomic tuple) has no `GC_TRACKED` flag, so the join accepts an object at the sample address plus 0, 16 or 32, except 0 for a GC-tracked object.
- **Size.** The sample's requested size is within 16 bytes of the object's `shallow_size`, which includes the pre-header as the request does. Measured on 3.12, 3.13 and 3.14 with every large allocation sampled (`--interval 1`) on a mix of bytes, str, int, tuples, slotted instances, generators, code objects, classes and subclasses of int and tuple: the request equals the shallow size, except one item plus rounding to 8 more for instances of variable-size subclasses (`PyType_GenericAlloc` allocates one item extra: 4 bytes for an `int` subclass, 8 for a `tuple` subclass), 4 more for an int whose top digit was normalised away, and blocks resized in place by a `realloc` that was not recorded. A type object's shallow size also counts its shared-keys table, a separate allocation, so for type objects only the upper bound applies.

When the latest covering sample is a large-object sample the object does not match, the object is not linked, neither to that sample nor to an older one (older samples at the address describe even earlier allocations). Reachable objects left unlinked this way are counted in `coverage.unlinked_reused_objects` and `unlinked_reused_bytes`, with a note (`allocations_unlinked_reused`).

Arena and pool links are not affected. System-allocator blocks (the `brk` heap, or an `mmap` of their own for large ones) and pymalloc arenas (1 MiB `mmap`s) never overlap while both are mapped. A large-object sample's range can overlap an arena only when one was unmapped and the range mapped again for the other. If the arena came later, its sample is the later one and covers the objects carved from it. If the large block came later, the arena's objects are gone, and objects later carved from a new arena there are covered by that arena's sample, since arena events are not sampled. Only a recording without arena events (`--events large`) leaves pymalloc objects under a stale large-object sample, and they are then left unlinked rather than linked wrongly.

**Exact and approximate links.** A large-object sample that matches is the object's own allocation, so a link through it is exact. An arena or pool sample covers memory that many objects are later allocated from, so a link through it only says "the most recent growth event that created this memory". It is not necessarily the call that allocated the object. Reports keep the two apart with `exact_linked_objects` and `exact_linked_bytes`. The `approximate` flags keep their meaning: Python frames matched to the event by time (ETW).

**By site.** Samples are grouped by resolved stack, the sequence of `(function, file:line)` innermost first. Raw frames are resolved once per distinct `(code entry, instruction offset)` and interned, so a stack is a short list of ids and grouping costs one hash lookup per frame. Per stack, `estimated_bytes` sums the sample weights and `linked_bytes` sums the shallow bytes of the reachable objects linked to its samples. The largest stacks by estimated bytes are `top_stacks`. `coverage` counts the linked reachable objects, their bytes, and their share of the reachable bytes.

**Per retainer and instance (`allocated_at`).** The dominator subtree of `v` is the nodes whose dominator-tree preorder number lies in `tin[v] .. tin[v] + retained_count[v]` (the interval check in `analysis.rs`). The reachable linked objects are scattered into preorder once (`O(n)`). Each listed object's subtree is then one slice, found by two binary searches, and only the linked objects in that slice are visited. Top retainers are disjoint, so together they visit each linked object at most once. Type-query instances can nest, so the cost there is at most `--top` times the linked objects. Per stack, the linked objects and their shallow bytes are summed, and the five largest by bytes are listed. `top_stack_rank` points at the same stack in `top_stacks`.

**Cost.** On the ignored scale test (10 million objects, 1 million samples of 24 frames each, release build), the address sweep takes 0.19 s and stack grouping 0.36 s. Peak RSS of `analyze --allocations` is the same as plain `analyze` (2.0 GiB, mostly the dominator analysis and the mapped snapshot).

**What it cannot see.**
- Blocks reused from freed memory are not sampled, and objects allocated before recording started have no sample.
- A large allocation that is not an object, such as a list's item array, a dict's key table, or a bytearray's buffer, has a different address from the object that owns it. Its sample links to nothing, and its owner is not linked through it.
- An object allocated, unsampled, on memory of a freed large block that was sampled is left unlinked (`coverage.unlinked_reused_*`). With byte-interval sampling and churn of large blocks this is the common case, so expect most unsampled large objects there to stay unlinked; a smaller `--interval` samples more of them.
- The large-object match cannot tell an unsampled reuse of the same size at the same address (with the same pre-header) from the sampled allocation itself. Such an object links, exactly, to the earlier block's stack.
- An object whose shallow size counts other allocations (a `str` with a cached UTF-8 copy), or whose block was shrunk or grown in place by a `realloc` that was not recorded (for example a buffer trimmed to 512 bytes or less, below the large-object filter), fails the size check and stays unlinked: a missed exact link, never a wrong one.

**What the join needs from recorders.**
- Large-object samples whose `address` is the start of the block the allocator returned and whose `size` is the requested size, because the join compares both with the object (see above).
- Samples in time order. The writer sorts them (stably), so for two samples over the same address, the later event must have the later timestamp, or the same timestamp and a later position in recorder order.
- Timestamps in Unix-epoch nanoseconds on the same clock as the snapshot's `captured_at`, or samples after the snapshot are not recognised.
- `address` and `size` per kind: an arena is the base the `mmap` or `VirtualAlloc` call returned and the full mapped length. A pool is its base and the pool size (16 KiB). A large object is the pointer the allocator returned and the requested size, not the size class. A `realloc` that returns a new pointer is a new large-object sample at that pointer, with the new size.
- `event_kind` set to `large_object` only for single allocations, since those links are reported as exact. Anything else that covers many objects is `arena`, `pool` or `other`.

**Report additions** (schema v1, additive): `allocations` on `AnalyzeReport` and `allocated_at` on retainer entries and on `query --type` instances. Older consumers ignore both. Defined in [docs/json-schema.md](json-schema.md#allocations).

**Flame graph.** `heapspy flamegraph --allocations app.hpya` draws the stacks as a classic flame graph: frames are `function (file:line)`, outermost at the root, width is estimated bytes. `--retained app.hpy` uses linked bytes as the width instead, which shows where the memory still alive was allocated.

**Not built yet.**
- `diff --allocations` only checks the profile against AFTER. Adding allocating stacks to growth sites needs the diff to keep each site's member objects, so it is left for later.

**MCP.** The `allocation_sites` tool lists the top stacks, and `heap_summary` passes `allocated_at` through when a sidecar is given. A contract test records a live process and checks that the tool returns the known allocating stack (`python/heapspy-mcp/tests/test_contract_real.py`).

## Decisions

Settled while building the shared contracts, before the recorders.

**Crates.**
- `heapspy-alloc` is the format: types, `AllocWriter`, `Profile`, the line-table decoder and `ProfileBuilder` for tests. It depends only on `heapspy-snapshot` (for `PythonVersion`, `Os`, `Arch`), so the analyzer can read profiles without pulling in recorders.
- `heapspy-record` holds the recorders and what they share: `RecordOptions`, the `Recorder` trait, `Target`, `SampleSink`, and `record` / `record_with`, which own the header, the overhead fields and the file. It depends on `heapspy-reader` and `heapspy-alloc`. Platform dependencies go here, behind `cfg`: `libc` and `object` on Linux (no `aya`, see [Linux: eBPF](#linux-ebpf)), `windows-sys` on Windows.
- The join lives in `heapspy-analyzer::allocations` (`analyze_with_allocations`, `query_type_with_allocations`), next to the dominator tree it needs.

**CPython offsets for recorders.** A recorder calls `Target::locate`, which runs `heapspy_reader::cpython::locate_runtime` and `cpython::frame_offsets` on a reader of the running process. That is the same code and the same per-version tables the snapshot walker uses, with `_Py_DebugOffsets` applied on 3.13+. `FrameOffsets` is the subset needed to go from `_PyRuntime` to each thread state, along the frame chain, and into code objects. It is plain `Copy` data, so the eBPF recorder copies it into a map. `cpython::frames::{thread_states, read_stack, read_code}` are the user-space reference for the same walk; the ptrace, debugger and ETW-sampler paths use them directly. Two fields were added to the offset table for this: `instr_ptr` (`prev_instr` on 3.12, 56 on all three versions) and `co_code_adaptive` (192, 200, 208). An ignored test reads the stack of running 3.12, 3.13 and 3.14 processes and checks every frame's function and line.

**Reading a running process.** `heapspy dump`'s live sources stop the target, which a recorder must not do. `heapspy_record::live::open` is a reader that never stops it: `LiveProcess::open_running` (`process_vm_readv`, no block cache) on Linux, `ReadProcessMemory` on Windows.

**Code objects.**
- Frames are recorded as (code object address, instruction offset).
- `SampleSink` reads each code object the first time its address appears, while the frame using it is executing and the object is alive. This replaces "after recording stops" above: by then a short-lived code object (a lambda, exec'd code) may be gone. The snapshot's `source_loc` extras remain a fallback for entries left unresolved.
- Code entries are keyed by address but not unique: an address can be reused during the window, and a recorder that notices this starts a new entry (`SampleSink::refresh_code`). Frames refer to entries by id.

**Shim frames.** On 3.13 and 3.14 a call to a Python class with a Python `__init__`, once its call site is specialized (`CALL_ALLOC_AND_ENTER_INIT`), runs `__init__` above a frame of `_Py_InitCleanup`, a static code object named `__init__` in file `__init__` that checks that `__init__` returned `None`. Its owner is `FRAME_OWNED_BY_THREAD`, like an ordinary frame, so the owner test does not skip it, and recorded stacks showed `Session.__init__ <- __init__ (__init__:?) <- login`. CPython's tracebacks hide it because its instruction pointer is before `_co_firsttraceable`. heapspy recognises the code object instead: `co_flags` (offset 48 on all three versions) has `CO_NO_MONITORING_EVENTS` (0x2000000), which the compiler never sets. `read_stack` skips such frames, and the eBPF recorder's user-space decoding applies the same test to the kernel's frames (the BPF program is unchanged; it copies the shim frame like any other, with its code pointer). 3.12 pushes no such frame, and its entry frames are already skipped by owner. Profiles recorded before this change still contain the shim frame.

**Instruction offsets and lines.**
- The offset is `instr_ptr - _PyCode_CODE(code)` in bytes, which is `f_lasti` on every supported version.
- The code table stores raw `co_linetable` bytes with a format code. Format 1, the 3.11 to 3.14 location table, is decoded in `heapspy_alloc::linetable` and checked against `co_positions()` of real code objects from 3.12, 3.13 and 3.14.
- A frame that has not started (3.12 `prev_instr` before the code) has no offset and resolves to `co_firstlineno`, as `PyCode_Addr2Line` does.

**Samples.**
- Timestamps are Unix-epoch nanoseconds.
- The file is sorted by time, so "a later sample covers this address" in the join is "a sample with a higher index".
- Arena and pool samples weigh their size. Large objects use a Poisson byte sampler: keep with probability `1 - exp(-size / interval)` and weigh `size / p` (`heapspy_alloc::sampled_weight`).
- Frames are innermost first, with flags for approximate frames (ETW), a truncated stack, and a native thread with no thread state.

**Defaults.** `--events arena,large`, `--interval 512K`, `--max-frames 64` (at most 1024; eBPF copies at most 128). The interval stays at 512K after measuring. The overhead is the trap on every allocator call, and it does not depend on the interval (see [Measurements](#measurements)). The interval only sets the sample count, which is the accuracy and the file size: at 512K the benchmark writes about 9,000 samples a second (about 1 MB/s). That is plenty to rank stacks, and a smaller interval buys accuracy at no extra cost to the target.

**Mechanism selection.**
- `--mechanism auto` on Linux tries eBPF, then ptrace. Each recorder's `probe` returns `Unsupported` or `PermissionDenied` to move on.
- On Windows, `auto` runs ETW and debugger breakpoints together. `etw` or `debugger` runs one; with `debugger` alone, only arenas are recorded.
- The ptrace fallback records arenas only. It notes the event kinds it skipped in the `heapspy.skipped_events` meta key instead of failing.

**Failure handling.** A recording that fails writes no file; the writer only renames its temporary file into place on success. SIGINT and SIGTERM (Ctrl-C, Ctrl-Break on Windows) end the window early: the recorder detaches and writes a valid profile flagged `truncated`. A recording that dropped samples or outlived its target is also flagged `truncated`.

**Joining.**
- `--allocations` opens and validates the profile. It then checks the profile against the snapshot (`AFTER` for diff): the pid (for live-process snapshots), the CPython version, and that the snapshot was not taken before recording started.
- A mismatch is a warning on stderr and a note in the report (`allocations_pid_mismatch`, `allocations_python_mismatch`, `allocations_after_snapshot`). A joined report with a mismatch links nothing and adds `allocations_not_linked`.
- `analyze` and `query --type` join the profile with the snapshot (M7c, see [Joining with a snapshot](#joining-with-a-snapshot)) and add the `allocations_sampled` note. `allocations_not_joined`, the note printed before the join existed, is no longer emitted. `diff` and `--retaining-path` have no allocation fields and only check the profile.
- A missing profile is error code `io`. A corrupt one is `invalid_allocations`.

**Report fields.** The new fields are always present in new documents (`null` without `--allocations`), as the schema rules require. They deserialize to `null` when missing, so documents from older versions still parse.

## Milestones

| | Deliverable |
|---|---|
| M7a | Linux eBPF recorder: arena and large-object probes, Python stack capture, `.hpya` writer, overhead measurement |
| M7b | Windows recorder: ETW session, debugger-breakpoint path, approximate stack correlation |
| M7c | Analyzer join, report fields, text output, MCP tool, e2e fixtures with a known allocating call chain on both OSes |

## Measurements

Victim: one loop per iteration allocating a 64 KiB `bytes`, eight 2 KiB `bytearray`s and a list of 200 small tuples (about 900,000 allocator calls above 512 bytes per second, an extreme rate). Throughput is the median of 0.5 s windows over 4 s, unrecorded and then recorded, in the same process. Linux 6.18, 4 vCPUs. Unrecorded runs vary by about ±10%, so single-digit differences are noise.

| events, mechanism | 3.12 (Debian, libc probes) | 3.13 (`_PyMem_Raw*`) | 3.14 (`_PyMem_Raw*`) |
|---|---|---|---|
| arena, eBPF | 4% | 3% | 6% |
| large, eBPF, interval 64K | 43% | 49% | 38% |
| large, eBPF, interval 512K (default) | 45% | 50% | 35% |
| large, eBPF, interval 4M | 46% | 43% | 29% |
| arena + large, eBPF, 512K (default) | 44% | 45% | 38% |
| arena, ptrace | noise | noise | noise |

- **Large objects cost per call, not per sample.** At 64K and at 4M the slowdown is the same. It is the uprobe trap on each of the ~900k calls a second, about 0.5 µs each with uprobe sessions. Before sessions (uprobe + uretprobe on every call), the default cost 56% on 3.13. Before skipping `endbr64`, Debian 3.12's libc probes cost 98%. A process that allocates large objects at a tenth of this rate pays about a tenth of the cost. Record arenas alone (`--events arena`) when that is too much.
- **Arenas are nearly free with eBPF.** On a leaking victim that maps about 190 arenas a second, arena recording cost about 5%, the same as an unrecorded run drifts.
- **ptrace costs per syscall.** On the benchmark (few syscalls), ptrace was within noise. With an `os.stat` per iteration (25,000 syscalls a second), it cost 86% (101k stops in 4 s, 0.9 s of tracer handling).
- **Dropped samples.** With uprobe sessions and the sized ring buffer, none in these runs at any interval.

## Spike results

- **Pool carving.** None of the builds tested (Debian 3.12, python-build-standalone 3.12, 3.13 and 3.14, a local 3.13) has an out-of-line pool-carving function: it is inlined into `pymalloc_alloc`. Pools are not recorded.
- **Symbols.** All but Debian 3.12 (dynamic symbols only) have `_PyObject_Malloc` and `_PyMem_Raw*` in `.symtab`, and all are statically linked. Debian 3.12 uses the libc probes.
- **Arenas** are 1 MiB anonymous `mmap`s on every version, with no hugepages.
- **Large-object uprobe overhead and the default interval:** see [Measurements](#measurements).
- **Thread state in eBPF.** The walk fits the verifier on 3.12, 3.13 and 3.14 (6.18 kernel) once the frame count is kept in map memory. The ignored tests `crates/heapspy/tests/record_live.rs` check the stacks against known `file:line`s on all three.
- **Lost uretprobes.** The spike saw entry and return counts disagree in blocks. Two causes: nested probes (`_PyObject_Malloc` over `_PyMem_RawMalloc`) overwriting a tid-keyed pending entry, fixed by not probing both layers and keying by (tid, stack pointer); and returns that never arrived for about 4% of sampled calls on 6.18 while the return program was slow (it reserved and filled a 3 KiB ring buffer record). With the scratch-map program, 1 in 180,000 was lost. With uprobe sessions, none. Lost returns are counted (meta `heapspy.ebpf.orphaned_entries`) as dropped samples.
- **Still open (Windows):** whether ETW events and 5 ms stack samples land within 20 ms of each other, and whether the debugger path works with Windows Defender and other EDR software running. Both are steps in the [test plan](windows-record-test-plan.md).

## Spike checklist (original)

Answered in [Spike results](#spike-results).

- Find out which builds (Debian, python.org, python-build-standalone, Windows python.org) expose a probe-able pool-carving function, and which inline it.
- Measure the overhead of the large-object uprobe with the byte sampler on an allocation-heavy benchmark. Pick the default interval.
- On 3.12, 3.13 and 3.14, verify that eBPF can find the current `PyThreadState` within the verifier's instruction limits.
- Confirm that ETW heap tracing can attach to a running process, and measure how far apart ETW events and Python stack samples land in time.
- Confirm that the breakpoint path works with Windows Defender and other EDR software running, since attaching a debugger can trigger them.
