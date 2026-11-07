//! `heapspy record`: sample allocations of a running CPython process,
//! with their Python stacks, from outside the process, for a bounded
//! window, and write them to an allocation profile (`.hpya`, see
//! `heapspy-alloc` and `docs/alloc-format.md`).
//!
//! Design: `docs/allocation-sampling.md`. This crate holds the contract the
//! recorders are built against, and the recorders.
//!
//! | piece | where | status |
//! |---|---|---|
//! | options, validation, `60s` / `512K` parsing | [`options`] | done |
//! | [`Recorder`] trait, [`Target`], [`RecordContext`] | [`recorder`] | done |
//! | [`SampleSink`]: code addresses to code entries, `max_frames` | [`sink`] | done |
//! | [`record`] / [`record_with`]: header, overhead, file, `--then-dump` | [`session`] | done |
//! | Python stack offsets and reference readers | `heapspy_reader::cpython::frames` | done |
//! | non-stopping reader of a running process | [`live`] | done |
//! | Linux eBPF recorder: arenas, large objects | [`linux_ebpf`] | done |
//! | Linux ptrace fallback: arenas | [`linux_ptrace`] | done |
//! | Windows ETW + debugger recorder | [`windows`] | done, tested on `windows-latest`; not safe against being killed |
//!
//! # Flow
//!
//! 1. [`RecordOptions::validate`], then, on Linux, check that the pid
//!    exists (`NoSuchProcess` otherwise). Nothing reads the target before
//!    a recorder's probe succeeds; probes only check this machine.
//! 2. [`select`] the recorders for `--mechanism` on this OS and call
//!    [`Recorder::probe`] on each in order; the first that succeeds runs.
//!    `Unsupported`, `PermissionDenied` and `Unimplemented` move on to the
//!    next; if none succeeds, the first error is returned.
//! 3. [`live::open`] a reader that does not stop the target, and
//!    [`Target::locate`] the runtime in it. This reuses
//!    `heapspy_reader::cpython::locate_runtime` and the per-version offset
//!    tables (with `_Py_DebugOffsets` on 3.13+), so the recorder and the
//!    snapshot walker agree on every layout.
//! 4. [`record_with`] fills the header (pid, Python version, OS, arch,
//!    start time, sampling parameters), wraps an
//!    [`heapspy_alloc::AllocWriter`] in a [`SampleSink`], and calls
//!    [`Recorder::run`] until the window ends. Then it writes the end time,
//!    the mechanisms that ran and the measured overhead, and finishes the
//!    file atomically. A failed run writes nothing.
//! 5. With `--then-dump`, take a snapshot at once through the usual
//!    `heapspy dump` path.
//!
//! # How a recorder gets CPython offsets
//!
//! [`Target::offsets`] is a [`heapspy_reader::cpython::FrameOffsets`]: the
//! fields needed to go from `_PyRuntime` to each thread's
//! `PyThreadState` (`interpreters.head`, `threads.head`, `next`,
//! `native_thread_id`), from there to the frame chain (`current_frame`,
//! via `cframe` on 3.12; `previous`, `f_executable`, `instr_ptr`, `owner`),
//! and to a code object's `co_qualname`, `co_filename`, `co_firstlineno`,
//! `co_linetable` and bytecode start (`co_code_adaptive`). It is plain
//! `Copy` data: an eBPF recorder copies it into a map, user-space recorders
//! pass it to `heapspy_reader::cpython::frames::{thread_states,
//! read_stack, read_code}`.

mod common;
pub mod error;
pub mod linux_ebpf;
pub mod linux_ptrace;
pub mod live;
pub mod options;
pub mod recorder;
pub mod session;
pub mod signals;
pub mod sink;
pub mod windows;

pub use error::{Error, Result};
pub use options::{
    parse_bytes, parse_duration, MechanismChoice, RecordOptions, MAX_DURATION, MAX_FRAMES_LIMIT,
};
pub use recorder::{RecordContext, Recorder, RunOutcome, Target};
pub use session::{host_os, now_ns, record, record_with, select, RecordStats};
pub use signals::stop_on_signals;
pub use sink::{SampleSink, SinkStats};
