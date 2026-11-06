# Allocation sampling (M7): design

Status: proposed. Nothing here is implemented. This document fixes the goals and the mechanisms before the spike, and lists what the spike has to verify.

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

This uses the same container conventions as `.hpy`: magic `HPYA`, a versioned header, and a section table. It holds:

- **header:** pid, python version, start and end time, the mechanisms used, sampling parameters, and the measured overhead
- **string table** and **code table:** code address → qualname, filename, first line, and the line table bytes needed to map instruction offsets to lines
- **samples:** fixed-size records with a frame-chain offset
- **frames:** `(code_id, instr_offset, approximate: bool)`

## Joining with a snapshot

- **By address.** If an object's address falls inside a sampled pool or large allocation, and no later sample covers that range, the object is linked to that sample. This gives a per-object `allocated_at` for some objects. Only some get one, because only a sample of allocations is recorded.
- **By site.** Sampled growth bytes are aggregated by Python stack, and the stacks that produced the most growth are shown next to the top retainers. For each retainer, the stacks of the linked objects in its dominator subtree are summed.
- **Report additions** (schema v1, additive): `allocations` on `AnalyzeReport` (top growth stacks, sampling parameters, the approximate flag) and `allocated_at` on retainer entries. Older consumers ignore both.
- **MCP:** a new `allocation_sites` tool, and `heap_summary` passes `allocated_at` through when a sidecar is given.

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
