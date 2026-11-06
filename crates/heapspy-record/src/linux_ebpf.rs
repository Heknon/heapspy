//! Linux eBPF recorder (M7a). **Status: stub.** [`EbpfRecorder::probe`]
//! and [`EbpfRecorder::run`] return [`Error::Unimplemented`].
//!
//! Design: `docs/allocation-sampling.md`, "Linux: eBPF". What it has to do:
//!
//! # Probes
//!
//! - **Arenas.** `tracepoint:syscalls:sys_enter_mmap` / `sys_exit_mmap`,
//!   filtered in the kernel by tgid and by length == arena size (1 MiB on
//!   3.10+; 256 KiB before). Needs no symbols. The address comes from
//!   `sys_exit_mmap`'s return value; match enter and exit per tid in a hash
//!   map. Event kind [`heapspy_alloc::EventKind::Arena`], weight = size.
//! - **Pools** (only with `--events pool`). A uprobe on the pool-carving
//!   function where the symbol exists and is not inlined. Which builds
//!   expose it is a spike item; [`Recorder::probe`] must return
//!   [`Error::Unsupported`] naming the build when it is missing. Kind
//!   `Pool`, weight = size (16 KiB).
//! - **Large objects.** A uprobe on `PyMem_RawMalloc` / `malloc` (and the
//!   matching uretprobe for the address), with an in-kernel size filter
//!   (> 512 bytes) and a byte-interval sampler: keep an allocation when the
//!   bytes accumulated since the last kept one pass the next random
//!   threshold, drawn from an exponential distribution with mean
//!   `sampling.byte_interval`. Kind `LargeObject`, weight
//!   [`heapspy_alloc::sampled_weight`]`(size, interval)`. With an interval
//!   of 0, keep every call.
//!
//! Count every probe firing in a per-CPU counter (`probe_hits`), including
//! the ones the sampler skips, and every ring buffer reservation failure
//! (`samples_dropped`).
//!
//! # Python stack capture in the BPF program
//!
//! Pass [`heapspy_reader::cpython::FrameOffsets`] (from
//! [`crate::Target::offsets`], which already has `_Py_DebugOffsets` applied
//! on 3.13+) and the `_PyRuntime` address to the program in an array map.
//! Then, per event:
//!
//! 1. Find the current thread's `PyThreadState`: walk
//!    `runtime->interpreters.head->threads.head` and `->next`, comparing
//!    `native_thread_id` with the current tid (`bpf_get_current_pid_tgid()
//!    as u32`). Bound the loop (`MAX_THREADS`-style constant the verifier
//!    accepts). Cache tid -> tstate in an LRU hash map, and invalidate on a
//!    mismatch. Reading the thread-local `_Py_tss_tstate` through the
//!    task's `fsbase` is faster but needs the TLS offset; leave it for later.
//! 2. Follow `current_frame` (through `cframe` on 3.12) and `previous`,
//!    skipping frames whose `owner >= owner_first_shim`, copying for each
//!    frame `f_executable` (mask `& !3` on 3.14) and `instr_ptr`. Stop at
//!    `max_frames` (clamp to what the verifier allows and document it; set
//!    `STACK_TRUNCATED` when frames remain).
//! 3. The instruction offset is `instr_ptr - (code + co_code_adaptive)`.
//!    Either compute it in the kernel or send `instr_ptr` and compute it in
//!    user space. Out-of-range values become `None`.
//! 4. No thread state found: emit the sample with no frames through
//!    [`crate::SampleSink::add_native`].
//!
//! [`heapspy_reader::cpython::frames::read_stack`] is the user-space
//! reference for steps 1-3, and its tests pin the layout; an ignored test in
//! `tests/live_stack.rs` checks it against real 3.12, 3.13 and 3.14
//! processes. This is the technique Parca and Pyroscope use for Python CPU
//! profiling. Verifying that it fits the verifier's instruction limits on
//! each version is a spike item.
//!
//! # User space
//!
//! - Samples arrive through a BPF ring buffer (kernel 5.8+). Convert
//!   `bpf_ktime_get_ns` to Unix-epoch ns with an offset measured at start
//!   (`CLOCK_REALTIME - CLOCK_MONOTONIC`), and pass each sample to
//!   [`crate::SampleSink::add`] with [`heapspy_reader::cpython::frames::RawFrame`]s.
//!   The sink reads each new code object through the non-stopping reader
//!   ([`crate::live`]) while it is still alive.
//! - Poll [`crate::RecordContext::should_stop`] at least every 100 ms,
//!   then detach every probe before returning, on error paths too.
//! - eBPF does not stop the target: `total_pause_ns` is 0.
//!
//! # Build and permissions
//!
//! - Crate: `aya`, pure Rust, no clang at runtime. Build the BPF object at
//!   compile time and embed it. Gate the dependency with
//!   `[target.'cfg(target_os = "linux")'.dependencies]`.
//! - `CAP_BPF` + `CAP_PERFMON` (or root) and kernel 5.8+. In containers,
//!   the capabilities and access to the host's tracefs. Map a missing
//!   capability to [`Error::PermissionDenied`] and a missing kernel feature
//!   to [`Error::Unsupported`] in `probe`, so `auto` falls back to ptrace.

use heapspy_alloc::{Mechanism, Mechanisms};

use crate::error::{Error, Result};
use crate::options::RecordOptions;
use crate::recorder::{RecordContext, Recorder, RunOutcome};

/// Linux eBPF recorder. See the module docs.
#[derive(Debug, Default)]
pub struct EbpfRecorder {}

impl EbpfRecorder {
    pub fn new() -> Self {
        Self {}
    }
}

const UNIMPLEMENTED: &str = "the Linux eBPF recorder (M7a)";

impl Recorder for EbpfRecorder {
    fn name(&self) -> &'static str {
        "linux-ebpf"
    }

    fn mechanisms(&self) -> Mechanisms {
        Mechanisms::of(&[Mechanism::Ebpf])
    }

    fn probe(&self, _opts: &RecordOptions) -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Err(Error::Unsupported("eBPF needs Linux".into()));
        }
        Err(Error::Unimplemented(UNIMPLEMENTED))
    }

    fn run(&mut self, _ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
        Err(Error::Unimplemented(UNIMPLEMENTED))
    }
}
