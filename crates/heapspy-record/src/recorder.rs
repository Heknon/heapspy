//! The interface every recorder implements, and what it is given.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use heapspy_alloc::{Mechanisms, Overhead};
use heapspy_reader::cpython::{self, FrameOffsets, RuntimeLocation};
use heapspy_reader::{MemorySource, TargetInfo};

use crate::error::Result;
use crate::options::RecordOptions;
use crate::sink::SampleSink;

/// The target process as a recorder sees it: where the runtime is, and the
/// offsets for reading its Python stacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub pid: u32,
    /// OS, architecture, pointer size, byte order.
    pub info: TargetInfo,
    /// The module exporting `_PyRuntime`, its address, version and build.
    pub runtime: RuntimeLocation,
    /// Frame-walking offsets for this version, with `_Py_DebugOffsets`
    /// applied on 3.13+.
    pub offsets: FrameOffsets,
}

impl Target {
    /// Find the runtime in `src` and compute the frame offsets. Uses
    /// [`cpython::locate_runtime`] and [`cpython::frame_offsets`], the same
    /// code the snapshot walker uses, so the two agree on every layout.
    pub fn locate(src: &dyn MemorySource, pid: u32) -> Result<Target> {
        let runtime = cpython::locate_runtime(src)?;
        let offsets = cpython::frame_offsets(src, &runtime)?;
        Ok(Target {
            pid,
            info: src.target(),
            runtime,
            offsets,
        })
    }
}

/// What a recorder reports when it stops. [`crate::record_with`] adds the
/// sample count it saw and writes these into the profile header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunOutcome {
    /// Mechanisms that actually ran. For Windows `auto`, the debugger may
    /// fail to attach (EDR software) and leave only ETW.
    pub mechanisms: Mechanisms,
    /// `samples_dropped`, `probe_hits`, `total_pause_ns`. `samples_taken`
    /// is filled in from the sink.
    pub overhead: Overhead,
    /// Recording stopped before the window ended (the target exited, a
    /// probe was detached) or lost samples in a way `overhead` does not
    /// describe.
    pub truncated: bool,
}

/// Everything a recorder works with while it runs.
pub struct RecordContext<'a> {
    pub target: &'a Target,
    /// A reader of the target's memory that does **not** stop it (see
    /// [`crate::live`]). Use it for user-space stack reads and for code
    /// objects; the sink already uses it to resolve code addresses.
    pub src: &'a dyn MemorySource,
    pub opts: &'a RecordOptions,
    /// Where samples go.
    pub sink: SampleSink<'a>,
    /// When the window ends.
    pub deadline: Instant,
    /// Set from outside (Ctrl-C) to stop early.
    pub stop: &'a AtomicBool,
}

impl RecordContext<'_> {
    /// The window has ended or a stop was requested. Recorders poll this
    /// at least every 100 ms.
    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }
}

/// One way of recording allocations. Implementations live in
/// [`crate::linux_ebpf`], [`crate::linux_ptrace`] and [`crate::windows`].
///
/// Contract:
///
/// - [`Recorder::probe`] checks that the recorder can run on this machine
///   (OS, kernel features, privileges) without touching the target. It
///   returns [`crate::Error::Unsupported`] or
///   [`crate::Error::PermissionDenied`] so that `auto` can move on to the
///   next recorder.
/// - [`Recorder::run`] attaches, records until
///   [`RecordContext::should_stop`], detaches, and returns. It must leave
///   the target running and unmodified on every path, including errors and
///   panics in heapspy (detach in `Drop`). No code is ever run inside the
///   target.
/// - Every sample goes through [`SampleSink`], which turns code addresses
///   into code entries (reading each code object once, while it is alive)
///   and applies `max_frames`.
/// - Frames are innermost first. An instruction offset is the byte offset
///   of the executing instruction from the start of the code object's
///   bytecode (see [`heapspy_reader::cpython::frames`]).
/// - Timestamps are nanoseconds since the Unix epoch. A recorder whose
///   clock is monotonic (`bpf_ktime_get_ns`, QPC) converts with an offset
///   measured once at start.
/// - Weights: arena and pool events weigh their size. Large objects are
///   sampled by byte interval and weigh [`heapspy_alloc::sampled_weight`].
/// - Overhead is measured, not estimated: count every probe hit and every
///   dropped sample, and sum the time each thread was stopped.
pub trait Recorder {
    /// Short name for messages and the profile's meta (`linux-ebpf`).
    fn name(&self) -> &'static str;

    /// Mechanisms this recorder uses when everything works.
    fn mechanisms(&self) -> Mechanisms;

    /// Can this recorder run here? See the trait docs.
    fn probe(&self, opts: &RecordOptions) -> Result<()>;

    /// Record. See the trait docs.
    fn run(&mut self, ctx: &mut RecordContext<'_>) -> Result<RunOutcome>;
}
