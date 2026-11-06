//! Windows recorder: ETW plus debugger breakpoints (M7b). **Status: stub.**
//! [`WindowsRecorder::probe`] and [`WindowsRecorder::run`] return
//! [`Error::Unimplemented`].
//!
//! Design: `docs/allocation-sampling.md`, "Windows: ETW plus debugger
//! breakpoints". ETW records native stacks cheaply but cannot run code at
//! event time, so it cannot read `PyThreadState` while the allocating thread
//! is still at the allocation site. The recorder uses two mechanisms, each
//! where it is good; `--mechanism auto` runs both, `etw` or `debugger` runs
//! one.
//!
//! # 1. ETW: counts and native context, without stopping the target
//!
//! - A real-time kernel session with `EVENT_TRACE_FLAG_VIRTUAL_ALLOC` and
//!   stack walk on VirtualAlloc catches arenas (`MEM_COMMIT|MEM_RESERVE`,
//!   arena size, from `python3XY.dll`).
//! - The heap provider, with heap tracing enabled for the target pid and
//!   stack walk on `HeapAlloc` / `HeapRealloc`, catches large objects.
//!   Apply the byte-interval sampler in the consumer (events above 512
//!   bytes); weight [`heapspy_alloc::sampled_weight`]. Whether heap tracing
//!   can attach to an already running process on the supported Windows
//!   versions is a spike item; if it cannot, record arenas only and say so
//!   in meta `heapspy.skipped_events`.
//! - Python frames are **approximate**: a side thread samples each Python
//!   thread's frame chain at a fixed rate (py-spy style) with
//!   [`heapspy_reader::cpython::frames::thread_states`] and
//!   [`heapspy_reader::cpython::frames::read_stack`] through the
//!   non-stopping reader ([`crate::live`]), and each ETW event is matched to
//!   the nearest stack sample of the same thread by timestamp. Pass
//!   `approximate = true` to [`crate::SampleSink::add`], which sets
//!   `APPROXIMATE_FRAMES` on the sample and `approximate` on each frame.
//!   Keep the distance to the matched stack sample bounded (drop the frames
//!   rather than attach a stack from seconds away); how far apart they land
//!   is a spike measurement.
//! - Native return address: the first stack-walk frame outside the
//!   allocator, into [`heapspy_alloc::SampleInput::native_return_address`].
//! - Convert ETW timestamps (QPC or FILETIME, per session clock) to
//!   Unix-epoch ns once, at session start.
//! - `samples_dropped` includes ETW's `EventsLost` and `BuffersLost`.
//!
//! # 2. Debugger breakpoints: exact Python stacks on rare events
//!
//! - `DebugActiveProcess(pid)`, then `DebugSetProcessKillOnExit(FALSE)`
//!   immediately, so the target survives heapspy exiting or crashing.
//! - A breakpoint on the arena allocation path: `VirtualAlloc` called from
//!   `python3XY.dll` (check the return address), or the internal arena
//!   function when PDB symbols are available (python.org publishes PDBs).
//! - On each hit (`EXCEPTION_BREAKPOINT` in `WaitForDebugEvent`): read the
//!   thread's stack with `read_stack` using its `PyThreadState`
//!   ([`heapspy_reader::cpython::frames::thread_state_for`] with the
//!   event's thread id), record the sample with `approximate = false`,
//!   restore the byte, single-step, re-arm, `ContinueDebugEvent`. Time each
//!   stop into `total_pause_ns`.
//! - Arena events are rare, so the pause per event costs little in total.
//! - Detach with `DebugActiveProcessStop` on every exit path (`Drop`),
//!   after removing the breakpoints. The target is never killed.
//! - Attaching a debugger can trigger Windows Defender or other EDR
//!   software; if `DebugActiveProcess` fails with access denied while ETW
//!   works, run ETW alone and return only `Etw` in
//!   [`RunOutcome::mechanisms`]. Confirming behavior under EDR is a spike
//!   item.
//! - When both run, an arena seen by the debugger and by ETW is one sample:
//!   keep the debugger's (exact) one.
//!
//! # Permissions
//!
//! An elevated process with `SeDebugPrivilege` for both. Map
//! `ERROR_ACCESS_DENIED` to [`Error::PermissionDenied`].
//!
//! # Dependencies
//!
//! `windows-sys` features for ETW (`Win32_System_Diagnostics_Etw`) and the
//! debug API (`Win32_System_Diagnostics_Debug`, already enabled), behind
//! `cfg(windows)`. Keep this module compiling on every target, as it does
//! now, so `cargo check --target x86_64-pc-windows-gnu` and Linux builds
//! both cover it.

use heapspy_alloc::{Mechanism, Mechanisms};

use crate::error::{Error, Result};
use crate::options::RecordOptions;
use crate::recorder::{RecordContext, Recorder, RunOutcome};

/// Windows recorder. See the module docs.
#[derive(Debug)]
pub struct WindowsRecorder {
    etw: bool,
    debugger: bool,
}

impl WindowsRecorder {
    /// `etw`: run the ETW session. `debugger`: set arena breakpoints.
    pub fn new(etw: bool, debugger: bool) -> Self {
        Self { etw, debugger }
    }
}

const UNIMPLEMENTED: &str = "the Windows ETW and debugger recorder (M7b)";

impl Recorder for WindowsRecorder {
    fn name(&self) -> &'static str {
        match (self.etw, self.debugger) {
            (true, false) => "windows-etw",
            (false, true) => "windows-debugger",
            _ => "windows-etw-debugger",
        }
    }

    fn mechanisms(&self) -> Mechanisms {
        let mut m = Mechanisms::NONE;
        if self.etw {
            m.insert(Mechanism::Etw);
        }
        if self.debugger {
            m.insert(Mechanism::Debugger);
        }
        m
    }

    fn probe(&self, _opts: &RecordOptions) -> Result<()> {
        if !cfg!(windows) {
            return Err(Error::Unsupported(
                "ETW and debugger recording need Windows".into(),
            ));
        }
        Err(Error::Unimplemented(UNIMPLEMENTED))
    }

    fn run(&mut self, _ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
        Err(Error::Unimplemented(UNIMPLEMENTED))
    }
}
