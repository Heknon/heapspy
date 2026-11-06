//! Linux ptrace fallback recorder (M7a). **Status: stub.**
//! [`PtraceRecorder::probe`] and [`PtraceRecorder::run`] return
//! [`Error::Unimplemented`].
//!
//! Used by `--mechanism auto` when eBPF is unavailable (no `CAP_BPF`, old
//! kernel, locked-down container), or with `--mechanism ptrace`. Design:
//! `docs/allocation-sampling.md`, "Fallback when eBPF is unavailable".
//!
//! # What it records
//!
//! Arenas only. An arena is allocated rarely (once per MiB of pymalloc
//! growth), so stopping the allocating thread for each one costs little in
//! total. Pool and large-object events are far too frequent for a trap per
//! event: when `--events` asks for them, record arenas, and add a meta entry
//! `heapspy.skipped_events` naming the kinds that were skipped, rather than
//! failing. (The analyzer reports the sampling parameters it finds in the
//! header, so recording the enabled set as only `arena` is also fine.)
//!
//! # How
//!
//! - `PTRACE_SEIZE` every thread of the target (new threads via
//!   `PTRACE_O_TRACECLONE`), without stopping them.
//! - Break on the arena path. Two options, decide in the spike: a software
//!   breakpoint (`int3`) at the `mmap` call site inside the arena allocator
//!   (`_PyObject_ArenaMmap` when the symbol is there), or syscall-stops
//!   (`PTRACE_O_TRACESYSGOOD` + `PTRACE_SYSCALL`) filtered to `mmap` with
//!   the arena length. Syscall-stops need no symbols but stop every syscall
//!   of every thread, which is not acceptable for long; prefer the
//!   breakpoint, and use a seccomp filter (`PTRACE_O_TRACESECCOMP`) only if
//!   it can be installed without running code in the target, which it
//!   cannot today.
//! - On each hit: read the stopped thread's registers for the size and
//!   return address, find its `PyThreadState` with
//!   [`heapspy_reader::cpython::frames::thread_state_for`] (tid ==
//!   `native_thread_id`), read the stack with
//!   [`heapspy_reader::cpython::frames::read_stack`] through the
//!   non-stopping reader (the thread itself is stopped, which is what
//!   matters), single-step past the breakpoint, and continue. Take the
//!   arena address from the return value at the next stop.
//! - Time every stop with `CLOCK_MONOTONIC` and add it to
//!   `total_pause_ns`.
//! - On exit, error or panic: remove every breakpoint (restore the original
//!   bytes) and `PTRACE_DETACH` every thread, in `Drop`. ptrace binds a
//!   tracee to the tracer *thread*: run the whole recorder on one thread.
//!
//! # Permissions
//!
//! `CAP_SYS_PTRACE`, or `kernel.yama.ptrace_scope` 0 (1 only for a child).
//! Map `EPERM` to [`Error::PermissionDenied`] with the same hint
//! `heapspy dump` gives.

use heapspy_alloc::{Mechanism, Mechanisms};

use crate::error::{Error, Result};
use crate::options::RecordOptions;
use crate::recorder::{RecordContext, Recorder, RunOutcome};

/// Linux ptrace recorder. See the module docs.
#[derive(Debug, Default)]
pub struct PtraceRecorder {}

impl PtraceRecorder {
    pub fn new() -> Self {
        Self {}
    }
}

const UNIMPLEMENTED: &str = "the Linux ptrace recorder (M7a)";

impl Recorder for PtraceRecorder {
    fn name(&self) -> &'static str {
        "linux-ptrace"
    }

    fn mechanisms(&self) -> Mechanisms {
        Mechanisms::of(&[Mechanism::Ptrace])
    }

    fn probe(&self, _opts: &RecordOptions) -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Err(Error::Unsupported("ptrace recording needs Linux".into()));
        }
        Err(Error::Unimplemented(UNIMPLEMENTED))
    }

    fn run(&mut self, _ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
        Err(Error::Unimplemented(UNIMPLEMENTED))
    }
}
