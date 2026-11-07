//! Windows recorder: ETW plus debugger breakpoints (M7b).
//!
//! **Status: runs on `windows-latest`** with CPython 3.12 to 3.14, in the
//! `record.yml` workflow (`crates/heapspy/tests/record_live_windows.rs`).
//! The pure parts ([`clock`], [`matcher`], [`debug`]) are unit-tested
//! everywhere. Known gap: if heapspy is killed while recording, the
//! debugger's `int3` stays in `VirtualAlloc` and the target dies at its next
//! call, and the ETW session stays running. The test plan and results are
//! in `docs/windows-record-test-plan.md`.
//!
//! What differs from the design below, as built:
//!
//! - Large objects are not recorded: heap tracing (`TracingFlags` in
//!   Image File Execution Options) applies only to processes started after
//!   it is set, so it cannot attach to a running one. Asked for, they are
//!   listed in meta `heapspy.skipped_events`. Arenas only, on both paths.
//! - The ETW session is the classic "NT Kernel Logger" with
//!   `EVENT_TRACE_FLAG_VIRTUAL_ALLOC`; no ETW stack walks (native return
//!   addresses come from the debugger path only). A real-time consumer
//!   gets FILETIME timestamps, converted by [`clock`].
//! - The side sampler reads every Python thread's stack every 5 ms; an
//!   ETW event takes the same thread's nearest sample within 20 ms
//!   ([`matcher`]), else no frames. ETW events are held 2 s before they
//!   are written, so an arena the debugger also saw is written once, with
//!   the debugger's exact frames.
//! - The debugger breaks on `VirtualAlloc` in `kernelbase.dll` (exports,
//!   no PDBs needed), filters arena calls from the Python DLL, and sets a
//!   one-shot breakpoint at the return address for the result. See
//!   [`debug`] for the state machine and how it leaves no `int3` behind.
//!
//! The original design notes follow.
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

pub mod clock;
pub mod debug;
pub mod guardian;
#[cfg(windows)]
mod guardian_sys;
#[cfg(windows)]
pub mod live;
pub mod matcher;
#[cfg(windows)]
mod sys;

use heapspy_alloc::{Mechanism, Mechanisms};

#[cfg(not(windows))]
use crate::error::Error;
use crate::error::Result;
use crate::options::RecordOptions;
use crate::recorder::{RecordContext, Recorder, RunOutcome};

/// If this process was started as the recorder's guardian
/// (`heapspy __guardian <recorder pid>`), run it and return its exit code;
/// otherwise `None`. heapspy's `main` calls this first. See [`guardian`].
pub fn guardian_main_if_requested() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some(guardian::GUARDIAN_ARG) {
        return None;
    }
    #[cfg(windows)]
    {
        Some(guardian_sys::main(&args[1..]))
    }
    #[cfg(not(windows))]
    {
        eprintln!("heapspy: the recorder's guardian runs on Windows only");
        Some(2)
    }
}

/// pymalloc arena size on Windows (3.10+).
pub const ARENA_SIZE: u64 = 1 << 20;

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
        #[cfg(windows)]
        {
            if cfg!(target_arch = "x86_64") {
                Ok(())
            } else {
                Err(crate::error::Error::Unsupported(
                    "Windows recording needs x86_64".into(),
                ))
            }
        }
        #[cfg(not(windows))]
        {
            Err(Error::Unsupported(
                "ETW and debugger recording need Windows".into(),
            ))
        }
    }

    fn run(&mut self, ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
        #[cfg(windows)]
        {
            imp::run(self.etw, self.debugger, ctx)
        }
        #[cfg(not(windows))]
        {
            let _ = ctx;
            Err(Error::Unsupported(
                "ETW and debugger recording need Windows".into(),
            ))
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Mutex};
    use std::time::{Duration, Instant};

    use heapspy_alloc::{
        EventKind, EventKinds, Mechanism, Mechanisms, Overhead, SampleFlags, SampleInput,
    };
    use heapspy_reader::cpython::frames::{self, RawStack};

    use super::debug::Machine;
    use super::guardian::{self, Msg};
    use super::guardian_sys::Link;
    use super::matcher::{StackHistory, StackSample};
    use super::sys::{Debugger, EtwAlloc, EtwSession};
    use super::ARENA_SIZE;
    use crate::common;
    use crate::error::{Error, Result};
    use crate::recorder::{RecordContext, RunOutcome};
    use crate::session::now_ns;

    const SAMPLE_EVERY: Duration = Duration::from_millis(5);
    const MAX_DISTANCE_NS: u64 = 20_000_000;
    const HOLD_NS: u64 = 2_000_000_000;

    struct Exact {
        ts: u64,
        tid: u32,
        addr: u64,
        size: u64,
        ret: u64,
        stack: Option<RawStack>,
    }

    pub fn run(etw: bool, debugger: bool, ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
        let pid = ctx.target.pid;
        let want = ctx.opts.sampling.events;
        let mut skipped = Vec::new();
        if want.contains(EventKind::LargeObject) {
            skipped.push((
                EventKind::LargeObject,
                "heap tracing cannot attach to a running process on Windows".to_string(),
            ));
        }
        if want.contains(EventKind::Pool) {
            skipped.push((
                EventKind::Pool,
                "pool carving is inlined in every supported build".to_string(),
            ));
        }
        if !want.contains(EventKind::Arena) {
            return Err(Error::Unsupported(
                "on Windows only arena events can be recorded".into(),
            ));
        }
        common::note_events(&mut ctx.sink, EventKinds::of(&[EventKind::Arena]), &skipped)?;
        let src = ctx.src;
        let fo = ctx.target.offsets;
        let rt = ctx.target.runtime.runtime_addr;
        let max_frames = ctx.opts.sampling.max_frames as usize;
        let mut ran = Mechanisms::NONE;
        let mut first_err = None;

        // The guardian first, so it is watching before anything is changed;
        // declared first, it is dropped (told `done`) last.
        let link = match Link::start(pid, &guardian::log_path(&ctx.opts.output)) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!(
                    "heapspy: warning: no guardian ({e}); if heapspy is killed while recording, \
                     the target and the ETW session are not cleaned up"
                );
                None
            }
        };
        let (tx, rx) = mpsc::channel::<EtwAlloc>();
        let session = if etw {
            match EtwSession::start(pid, ARENA_SIZE, tx) {
                Ok(s) => {
                    if let Some(l) = &link {
                        l.send(&Msg::Etw(s.name.clone()));
                    }
                    ran.insert(Mechanism::Etw);
                    Some(s)
                }
                Err(e) => {
                    first_err = Some(e);
                    None
                }
            }
        } else {
            drop(tx);
            None
        };

        let exact: RefCell<Vec<Exact>> = RefCell::new(Vec::new());
        let entries: RefCell<HashMap<u32, Exact>> = RefCell::new(HashMap::new());
        let mut dbg = None;
        let mut dbg_pause = Duration::ZERO;
        if debugger {
            let va = [
                "KERNELBASE.dll",
                "kernelbase.dll",
                "KERNEL32.DLL",
                "kernel32.dll",
            ]
            .iter()
            .find_map(|n| {
                let mods = src.modules().ok()?;
                let m = mods.iter().find(|m| m.name.eq_ignore_ascii_case(n))?;
                src.find_symbol(m, "VirtualAlloc").ok().flatten()
            });
            let py = &ctx.target.runtime.module;
            match va {
                None => {
                    first_err.get_or_insert(Error::Unsupported(
                        "VirtualAlloc not found in kernelbase.dll".into(),
                    ));
                }
                Some(va) => {
                    let machine = Machine::new(va, ARENA_SIZE, (py.base, py.base + py.size));
                    let on_entry = Box::new(|tid: u32, size: u64, ret: u64| {
                        let stack = frames::thread_state_for(src, &fo, rt, tid as u64)
                            .ok()
                            .flatten()
                            .and_then(|t| frames::read_stack(src, &fo, t.addr, max_frames).ok());
                        entries.borrow_mut().insert(
                            tid,
                            Exact {
                                ts: now_ns(),
                                tid,
                                addr: 0,
                                size,
                                ret,
                                stack,
                            },
                        );
                    });
                    let on_exit = Box::new(|tid: u32, addr: u64| {
                        if let Some(mut e) = entries.borrow_mut().remove(&tid) {
                            if addr != 0 {
                                e.addr = addr;
                                exact.borrow_mut().push(e);
                            }
                        }
                    });
                    match Debugger::attach(pid, machine, link.as_ref(), on_entry, on_exit) {
                        Ok(d) => {
                            ran.insert(Mechanism::Debugger);
                            dbg = Some(d);
                        }
                        Err(e) => {
                            first_err.get_or_insert(e);
                        }
                    }
                }
            }
        }
        if ran == Mechanisms::NONE {
            return Err(first_err
                .unwrap_or_else(|| Error::Unsupported("no Windows mechanism could start".into())));
        }

        let history = Mutex::new(StackHistory::new(HOLD_NS * 2, MAX_DISTANCE_NS));
        let sampling = AtomicBool::new(session.is_some());
        let mut queue: VecDeque<EtwAlloc> = VecDeque::new();
        let mut seen_exact: HashSet<u64> = HashSet::new();
        let mut hits = 0u64;
        let mut exited = false;

        std::thread::scope(|scope| -> Result<()> {
            if session.is_some() {
                scope.spawn(|| {
                    while sampling.load(Ordering::Relaxed) {
                        let t0 = Instant::now();
                        if let Ok(ts) = frames::thread_states(src, &fo, rt) {
                            for t in ts {
                                if let Ok(st) = frames::read_stack(src, &fo, t.addr, max_frames) {
                                    let s = StackSample {
                                        ts_ns: now_ns(),
                                        frames: st.frames,
                                        truncated: st.truncated,
                                    };
                                    history
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .push(t.native_thread_id, s);
                                }
                            }
                        }
                        std::thread::sleep(SAMPLE_EVERY.saturating_sub(t0.elapsed()));
                    }
                });
            }
            let result = (|| -> Result<()> {
                loop {
                    let stop = ctx.should_stop();
                    if let Some(d) = dbg.as_mut() {
                        let t0 = Instant::now();
                        match d.pump(if stop { 0 } else { 50 }) {
                            Some(false) => exited = true,
                            Some(true) => dbg_pause += t0.elapsed(),
                            None => {}
                        }
                    } else if !stop {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    for e in exact.borrow_mut().drain(..) {
                        seen_exact.insert(e.addr);
                        let mut s = SampleInput {
                            timestamp_ns: e.ts,
                            tid: e.tid as u64,
                            kind: EventKind::Arena,
                            address: e.addr,
                            size: e.size,
                            weight: e.size,
                            native_return_address: Some(e.ret),
                            flags: SampleFlags::NONE,
                        };
                        match e.stack {
                            Some(st) => {
                                if st.truncated {
                                    s.flags = s.flags | SampleFlags::STACK_TRUNCATED;
                                }
                                ctx.sink.add(&s, &st.frames, false)?;
                            }
                            None => ctx.sink.add_native(&s)?,
                        }
                    }
                    queue.extend(rx.try_iter());
                    let cutoff = if stop || exited {
                        u64::MAX
                    } else {
                        now_ns().saturating_sub(HOLD_NS)
                    };
                    while queue.front().is_some_and(|e| e.ts_ns <= cutoff) {
                        let e = queue.pop_front().unwrap();
                        hits += 1;
                        if seen_exact.contains(&e.addr) {
                            continue;
                        }
                        let mut s = SampleInput {
                            timestamp_ns: e.ts_ns,
                            tid: e.tid as u64,
                            kind: EventKind::Arena,
                            address: e.addr,
                            size: e.size,
                            weight: e.size,
                            native_return_address: None,
                            flags: SampleFlags::NONE,
                        };
                        let h = history.lock().unwrap_or_else(|e| e.into_inner());
                        match h.nearest(e.tid as u64, e.ts_ns) {
                            Some(st) => {
                                if st.truncated {
                                    s.flags = s.flags | SampleFlags::STACK_TRUNCATED;
                                }
                                let frames = st.frames.clone();
                                drop(h);
                                ctx.sink.add(&s, &frames, true)?;
                            }
                            None => {
                                drop(h);
                                ctx.sink.add(&s, &[], true)?;
                            }
                        }
                    }
                    if stop || exited {
                        break;
                    }
                }
                Ok(())
            })();
            sampling.store(false, Ordering::Relaxed);
            result
        })?;

        let breakpoint_hits = dbg.as_ref().map_or(0, |d| d.machine.hits);
        if let Some(mut d) = dbg.take() {
            d.detach();
        }
        let lost = session.map_or(0, |s| {
            let n = s.lost;
            drop(s);
            n
        });
        if let Some(e) = &first_err {
            ctx.sink
                .writer_mut()
                .add_meta("heapspy.windows.mechanism_failed", &e.to_string())?;
        }
        Ok(RunOutcome {
            mechanisms: ran,
            overhead: Overhead {
                samples_taken: 0,
                samples_dropped: lost,
                probe_hits: hits + breakpoint_hits,
                total_pause_ns: dbg_pause.as_nanos() as u64,
            },
            truncated: exited || lost > 0,
        })
    }
}
