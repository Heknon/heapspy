//! The guardian: what puts the target and the machine back when the
//! Windows recorder dies without finishing (`TerminateProcess`, a crash).
//! This module is the part that needs no Windows API, unit-tested on every
//! platform: the protocol between the recorder and the guardian, the state
//! the guardian keeps from it, the "is this still our patch" check, the
//! cleanup plan, the per-thread repair decision, the report, and the
//! naming of heapspy's ETW sessions. `guardian_sys.rs` is the Win32 side.
//!
//! # How it works
//!
//! The recorder starts `heapspy __guardian <recorder pid>` before it
//! touches anything, in its own process group (Ctrl-Break to the recorder
//! does not reach it) and broken away from the recorder's job when the job
//! allows it. The guardian opens the recorder's and the target's process
//! handles and answers `ready`; the recorder only goes on after that. The
//! recorder then tells it, on its stdin, one line per change:
//!
//! | line | sent | meaning |
//! |---|---|---|
//! | `target <pid>` | first | the process being recorded |
//! | `log <path>` | first | the log file to write if it has to act |
//! | `etw <name>` | after `StartTraceW` succeeded | heapspy's ETW session |
//! | `debug <handle>` | after the attach | the debug object, duplicated into the guardian |
//! | `patch <addr> <orig>` | **before** writing `int3` | the byte heapspy is about to replace |
//! | `unpatch <addr>` | after writing the byte back | that address is clean again |
//! | `done` | at the end of a clean finish | nothing to do: exit without acting |
//!
//! `patch` goes out before the write, so a recorder killed between the two
//! leaves at most a patch the guardian knows about but that was never
//! written; the check below skips it.
//!
//! When the recorder's process handle is signalled, or its stdin ends,
//! without `done`, the guardian acts:
//!
//! 1. It installs the duplicated debug object as its own thread's debug
//!    object. Because the guardian holds a handle to it, the debug object
//!    outlived the recorder, so the target is still being debugged, with
//!    the recorder's pending state intact, and the guardian is now its
//!    debugger.
//! 2. Every known patch whose byte is still `int3` gets its original byte
//!    back ([`still_ours`]); one that holds anything else is skipped and
//!    reported.
//! 3. Every thread of the target is suspended and repaired by
//!    [`thread_fix`]: a thread stopped just after one of our `int3`s is
//!    rewound onto the restored instruction, a trap flag is cleared, and
//!    the debug event the dead recorder had read but not continued is
//!    continued (`DBG_CONTINUE` for ours, `DBG_EXCEPTION_NOT_HANDLED`
//!    otherwise, as the target would have seen it without a debugger).
//! 4. Debug events still queued are handled the same way until the target
//!    is quiet, then the guardian detaches (`DebugActiveProcessStop`).
//! 5. heapspy's ETW session, if one was started, is stopped by name.
//! 6. One line goes to stderr, and the details to `<profile>.guardian.log`.
//!
//! It never runs code inside the target: it only writes the bytes heapspy
//! wrote, changes registers of suspended threads, and answers debug events.
//!
//! When the target exits, there is nothing left to restore in it: the
//! guardian exits, unless an ETW session is registered, in which case it
//! keeps watching the recorder only for that.

use std::fmt;

/// The byte heapspy writes for a breakpoint.
pub const INT3: u8 = 0xcc;
/// The x86 trap flag in `EFlags`.
pub const TRAP_FLAG: u32 = 0x100;
/// First argument of `heapspy` that starts the guardian.
pub const GUARDIAN_ARG: &str = "__guardian";
/// Prefix of heapspy's ETW sessions: `heapspy-<recorder pid>`.
pub const SESSION_PREFIX: &str = "heapspy-";

/// One line of the recorder-to-guardian protocol. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    Target(u32),
    Log(String),
    Etw(String),
    Debug(u64),
    Patch { addr: u64, orig: u8 },
    Unpatch(u64),
    Done,
}

impl Msg {
    /// The line, without its `\n`.
    pub fn encode(&self) -> String {
        match self {
            Msg::Target(p) => format!("target {p}"),
            Msg::Log(p) => format!("log {p}"),
            Msg::Etw(n) => format!("etw {n}"),
            Msg::Debug(h) => format!("debug {h:x}"),
            Msg::Patch { addr, orig } => format!("patch {addr:x} {orig:02x}"),
            Msg::Unpatch(a) => format!("unpatch {a:x}"),
            Msg::Done => "done".into(),
        }
    }

    /// Parse one line (a trailing `\r` or `\n` is ignored). `None` for
    /// anything malformed, which the guardian ignores.
    pub fn decode(line: &str) -> Option<Msg> {
        let line = line.trim_end_matches(['\r', '\n']);
        let (verb, rest) = line.split_once(' ').unwrap_or((line, ""));
        let hex = |s: &str| u64::from_str_radix(s, 16).ok();
        match verb {
            "target" => rest.parse().ok().map(Msg::Target),
            "log" if !rest.is_empty() => Some(Msg::Log(rest.into())),
            "etw" if !rest.is_empty() && !rest.contains(['\r', '\n']) => {
                Some(Msg::Etw(rest.into()))
            }
            "debug" => hex(rest).map(Msg::Debug),
            "patch" => {
                let (a, o) = rest.split_once(' ')?;
                let orig = u8::from_str_radix(o, 16).ok()?;
                Some(Msg::Patch {
                    addr: hex(a)?,
                    orig,
                })
            }
            "unpatch" => hex(rest).map(Msg::Unpatch),
            "done" if rest.is_empty() => Some(Msg::Done),
            _ => None,
        }
    }
}

/// A byte heapspy replaced with `int3`, and what was there before.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Patch {
    pub addr: u64,
    pub orig: u8,
}

/// What the guardian knows, built from the messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub target: Option<u32>,
    pub log: Option<String>,
    pub etw: Option<String>,
    pub debug: Option<u64>,
    /// Outstanding patches, in the order they were made.
    pub patches: Vec<Patch>,
    pub done: bool,
}

impl State {
    pub fn apply(&mut self, m: Msg) {
        match m {
            Msg::Target(p) => self.target = Some(p),
            Msg::Log(p) => self.log = Some(p),
            Msg::Etw(n) => self.etw = Some(n),
            Msg::Debug(h) => self.debug = Some(h),
            Msg::Patch { addr, orig } => {
                // A second patch of one address keeps the first original:
                // the byte read the second time may be our own int3.
                if !self.patches.iter().any(|p| p.addr == addr) {
                    self.patches.push(Patch { addr, orig });
                }
            }
            Msg::Unpatch(a) => self.patches.retain(|p| p.addr != a),
            Msg::Done => self.done = true,
        }
    }

    /// Whether anything at all would need cleaning up.
    pub fn is_empty(&self) -> bool {
        self.etw.is_none() && self.debug.is_none() && self.patches.is_empty()
    }
}

/// The byte at a patched address still is heapspy's patch. Anything else
/// means someone else wrote there since (the code was unloaded and the
/// page reused, another tool, the recorder restored it but died before
/// saying so), and writing our original byte would corrupt it.
pub fn still_ours(current: u8) -> bool {
    current == INT3
}

/// What to do with one patch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchAction {
    /// The `int3` is there: write `orig` back.
    Restore(Patch),
    /// The byte is something else now: leave it.
    Skip { patch: Patch, found: u8 },
    /// The byte could not be read (unmapped): leave it.
    Unreadable(Patch),
}

/// The cleanup plan for the patches, given a way to read the target.
pub fn plan_patches(
    patches: &[Patch],
    mut read: impl FnMut(u64) -> Option<u8>,
) -> Vec<PatchAction> {
    patches
        .iter()
        .map(|&p| match read(p.addr) {
            Some(b) if still_ours(b) => PatchAction::Restore(p),
            Some(found) => PatchAction::Skip { patch: p, found },
            None => PatchAction::Unreadable(p),
        })
        .collect()
}

/// How to repair one thread of the target, from its registers, once the
/// patches are restored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThreadFix {
    /// Set `rip` to this: the thread trapped on our `int3` here.
    pub rewind_to: Option<u64>,
    /// Clear the trap flag the dead recorder set.
    pub clear_trap: bool,
}

impl ThreadFix {
    pub fn is_noop(&self) -> bool {
        self.rewind_to.is_none() && !self.clear_trap
    }

    /// How to continue a debug event of this thread the dead recorder may
    /// have read and left pending: ours is handled, anything else goes to
    /// the target as it would without a debugger.
    pub fn handled(&self) -> bool {
        !self.is_noop()
    }
}

/// `int3` leaves `rip` one past the breakpoint. A thread whose `rip - 1`
/// is one of our patched addresses is stopped at that breakpoint's
/// exception: put it back on the (restored) instruction. A trap flag is
/// only ever set by the recorder, to step over a breakpoint.
pub fn thread_fix(rip: u64, eflags: u32, patched: &[u64]) -> ThreadFix {
    ThreadFix {
        rewind_to: rip.checked_sub(1).filter(|a| patched.contains(a)),
        clear_trap: eflags & TRAP_FLAG != 0,
    }
}

/// A debug event the guardian receives after taking over, reduced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TakeoverEvent {
    Breakpoint { addr: u64 },
    SingleStep,
    OtherException,
    ExitProcess,
    Other,
}

/// What to do with such an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TakeoverReply {
    /// Set `rip` to the address, then `DBG_CONTINUE`.
    Rewind(u64),
    /// Clear the trap flag, then `DBG_CONTINUE`.
    ClearTrap,
    /// `DBG_CONTINUE`.
    Continue,
    /// `DBG_EXCEPTION_NOT_HANDLED`.
    NotHandled,
    /// The target is gone.
    Exited,
}

/// A hit on one of our (now restored) breakpoints is rewound; a single
/// step is the recorder's step over a breakpoint; any other exception is
/// the target's own.
pub fn takeover_reply(ev: TakeoverEvent, patched: &[u64]) -> TakeoverReply {
    match ev {
        TakeoverEvent::Breakpoint { addr } if patched.contains(&addr) => {
            TakeoverReply::Rewind(addr)
        }
        TakeoverEvent::Breakpoint { .. } | TakeoverEvent::OtherException => {
            TakeoverReply::NotHandled
        }
        TakeoverEvent::SingleStep => TakeoverReply::ClearTrap,
        TakeoverEvent::ExitProcess => TakeoverReply::Exited,
        TakeoverEvent::Other => TakeoverReply::Continue,
    }
}

/// What the guardian did, for the stderr line and the log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub recorder: u32,
    pub target: Option<u32>,
    pub restored: Vec<Patch>,
    pub skipped: Vec<(Patch, Option<u8>)>,
    /// (thread id, what was done).
    pub threads: Vec<(u32, ThreadFix)>,
    /// Queued debug events handled after the takeover.
    pub events_rewound: u32,
    pub events_stepped: u32,
    pub detached: bool,
    pub etw_stopped: Option<String>,
    pub etw_gone: Option<String>,
    /// Steps that failed, in words.
    pub errors: Vec<String>,
    /// Extra facts for the log only.
    pub notes: Vec<String>,
}

impl Report {
    /// The one stderr line.
    pub fn line(&self) -> String {
        let mut parts = Vec::new();
        if !self.restored.is_empty() {
            let at: Vec<String> = self
                .restored
                .iter()
                .map(|p| format!("{:#x}", p.addr))
                .collect();
            parts.push(format!(
                "restored {} breakpoint byte{} ({})",
                self.restored.len(),
                plural(self.restored.len()),
                at.join(", ")
            ));
        }
        if !self.skipped.is_empty() {
            parts.push(format!(
                "skipped {} address{} no longer holding heapspy's int3",
                self.skipped.len(),
                if self.skipped.len() == 1 { "" } else { "es" }
            ));
        }
        let rewound = self
            .threads
            .iter()
            .filter(|t| t.1.rewind_to.is_some())
            .count()
            + self.events_rewound as usize;
        if rewound > 0 {
            parts.push(format!(
                "released {rewound} thread{} stopped at a breakpoint",
                plural(rewound)
            ));
        }
        let traps =
            self.threads.iter().filter(|t| t.1.clear_trap).count() + self.events_stepped as usize;
        if traps > 0 {
            parts.push(format!("cleared {traps} trap flag{}", plural(traps)));
        }
        if self.detached {
            parts.push("detached the debugger".into());
        }
        if let Some(n) = &self.etw_stopped {
            parts.push(format!("stopped ETW session {n}"));
        }
        if !self.errors.is_empty() {
            parts.push(format!(
                "{} step{} failed",
                self.errors.len(),
                plural(self.errors.len())
            ));
        }
        let what = if parts.is_empty() {
            "nothing needed cleaning up".to_string()
        } else {
            parts.join(", ")
        };
        let target = self
            .target
            .map_or(String::new(), |t| format!(" (target pid {t})"));
        format!(
            "heapspy guardian: recorder pid {} ended without finishing{target}; {what}",
            self.recorder
        )
    }

    /// The log file's content: the line, then one line per fact.
    pub fn log(&self) -> String {
        let mut s = self.line();
        s.push('\n');
        for p in &self.restored {
            s.push_str(&format!(
                "restored {:#x}: int3 -> {:#04x}\n",
                p.addr, p.orig
            ));
        }
        for (p, found) in &self.skipped {
            match found {
                Some(b) => s.push_str(&format!(
                    "skipped {:#x}: holds {b:#04x}, not heapspy's int3 (original {:#04x})\n",
                    p.addr, p.orig
                )),
                None => s.push_str(&format!("skipped {:#x}: unreadable\n", p.addr)),
            }
        }
        for (tid, f) in &self.threads {
            s.push_str(&format!("thread {tid}:"));
            if let Some(a) = f.rewind_to {
                s.push_str(&format!(" stopped at the breakpoint at {a:#x}, rewound"));
            }
            if f.clear_trap {
                s.push_str(" trap flag set, cleared");
            }
            s.push('\n');
        }
        if self.events_rewound > 0 || self.events_stepped > 0 {
            s.push_str(&format!(
                "queued debug events handled: {} breakpoint hits rewound, {} single steps\n",
                self.events_rewound, self.events_stepped
            ));
        }
        if self.detached {
            s.push_str("detached from the target\n");
        }
        if let Some(n) = &self.etw_stopped {
            s.push_str(&format!("stopped ETW session {n}\n"));
        }
        if let Some(n) = &self.etw_gone {
            s.push_str(&format!("ETW session {n} was already gone\n"));
        }
        for e in &self.errors {
            s.push_str(&format!("error: {e}\n"));
        }
        for n in &self.notes {
            s.push_str(&format!("note: {n}\n"));
        }
        s
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.line())
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// The log file next to the profile.
pub fn log_path(profile: &std::path::Path) -> std::path::PathBuf {
    let mut s = profile.as_os_str().to_owned();
    s.push(".guardian.log");
    s.into()
}

// ---- ETW session names ----------------------------------------------------

/// heapspy's ETW session for the recorder `pid`.
pub fn session_name(pid: u32) -> String {
    format!("{SESSION_PREFIX}{pid}")
}

/// The recorder pid of a session name of heapspy's, `heapspy-<digits>`
/// exactly; `None` for every other name.
pub fn session_pid(name: &str) -> Option<u32> {
    let digits = name.strip_prefix(SESSION_PREFIX)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The sessions to stop at start: heapspy's, of a recorder that is not
/// this one and not a running heapspy. Never a session of another name.
pub fn stale_sessions(
    names: &[String],
    me: u32,
    mut live_heapspy: impl FnMut(u32) -> bool,
) -> Vec<&str> {
    names
        .iter()
        .filter_map(|n| {
            let pid = session_pid(n)?;
            (pid != me && !live_heapspy(pid)).then_some(n.as_str())
        })
        .collect()
}

/// Whether an executable's file name is a heapspy recorder (`heapspy`,
/// `heapspy.exe`, any case), or the same program as this one
/// (`current_stem`, for a library embedding the recorder).
pub fn is_heapspy_image(file_name: &str, current_stem: Option<&str>) -> bool {
    let stem = file_name.rsplit(['\\', '/']).next().unwrap_or(file_name);
    let stem = stem
        .strip_suffix(".exe")
        .or_else(|| stem.strip_suffix(".EXE"))
        .unwrap_or(stem);
    stem.eq_ignore_ascii_case("heapspy")
        || current_stem.is_some_and(|c| stem.eq_ignore_ascii_case(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn messages_round_trip() {
        let all = [
            Msg::Target(4242),
            Msg::Log(r"C:\Users\a b\out.hpya.guardian.log".into()),
            Msg::Etw("heapspy-17".into()),
            Msg::Debug(0x1a4),
            Msg::Patch {
                addr: 0x7ffd_1234_5678,
                orig: 0x4c,
            },
            Msg::Unpatch(0x7ffd_1234_5678),
            Msg::Done,
        ];
        for m in all {
            let line = m.encode();
            assert!(!line.contains('\n'));
            assert_eq!(Msg::decode(&line), Some(m.clone()), "{line}");
            assert_eq!(Msg::decode(&format!("{line}\r\n")), Some(m));
        }
    }

    #[test]
    fn malformed_lines_are_ignored() {
        for l in [
            "",
            "target",
            "target -1",
            "patch 10",
            "patch zz 10",
            "patch 10 100",
            "debug",
            "unpatch x",
            "done now",
            "log",
            "etw",
            "hello 1",
        ] {
            assert_eq!(Msg::decode(l), None, "{l:?}");
        }
    }

    #[test]
    fn state_tracks_outstanding_patches() {
        let mut s = State::default();
        assert!(s.is_empty());
        for l in [
            "target 9",
            "patch 100 4c",
            "patch 200 48",
            "patch 100 cc",
            "unpatch 200",
            "patch 300 c3",
        ] {
            s.apply(Msg::decode(l).unwrap());
        }
        assert_eq!(s.target, Some(9));
        assert_eq!(
            s.patches,
            [
                Patch {
                    addr: 0x100,
                    orig: 0x4c
                },
                Patch {
                    addr: 0x300,
                    orig: 0xc3
                }
            ]
        );
        assert!(!s.is_empty() && !s.done);
        s.apply(Msg::Done);
        assert!(s.done);
    }

    #[test]
    fn only_our_int3_is_restored() {
        let p = |addr, orig| Patch { addr, orig };
        let mem: HashMap<u64, u8> = [(0x10, INT3), (0x20, 0x48), (0x30, INT3)].into();
        let plan = plan_patches(
            &[p(0x10, 0x4c), p(0x20, 0x4c), p(0x30, 0xc3), p(0x40, 1)],
            |a| mem.get(&a).copied(),
        );
        assert_eq!(
            plan,
            [
                PatchAction::Restore(p(0x10, 0x4c)),
                PatchAction::Skip {
                    patch: p(0x20, 0x4c),
                    found: 0x48
                },
                PatchAction::Restore(p(0x30, 0xc3)),
                PatchAction::Unreadable(p(0x40, 1)),
            ]
        );
        assert!(still_ours(0xcc));
        assert!(!still_ours(0x4c));
    }

    #[test]
    fn thread_repair() {
        let patched = [0x1000, 0x2000];
        // Stopped at our breakpoint: rip is one past it.
        let f = thread_fix(0x1001, 0x246, &patched);
        assert_eq!(f.rewind_to, Some(0x1000));
        assert!(!f.clear_trap && f.handled());
        // Stepping over one: trap flag set, rip anywhere.
        let f = thread_fix(0x1004, 0x346, &patched);
        assert_eq!(
            f,
            ThreadFix {
                rewind_to: None,
                clear_trap: true
            }
        );
        // Untouched thread: continue a pending event as not handled.
        let f = thread_fix(0x5000, 0x246, &patched);
        assert!(f.is_noop() && !f.handled());
        assert!(thread_fix(0, 0, &patched).is_noop());
    }

    #[test]
    fn takeover_events() {
        let patched = [0x1000];
        use TakeoverEvent as E;
        use TakeoverReply as R;
        assert_eq!(
            takeover_reply(E::Breakpoint { addr: 0x1000 }, &patched),
            R::Rewind(0x1000)
        );
        assert_eq!(
            takeover_reply(E::Breakpoint { addr: 0x9 }, &patched),
            R::NotHandled
        );
        assert_eq!(takeover_reply(E::SingleStep, &patched), R::ClearTrap);
        assert_eq!(takeover_reply(E::OtherException, &patched), R::NotHandled);
        assert_eq!(takeover_reply(E::Other, &patched), R::Continue);
        assert_eq!(takeover_reply(E::ExitProcess, &patched), R::Exited);
    }

    #[test]
    fn report_line_and_log() {
        let r = Report {
            recorder: 10,
            target: Some(20),
            restored: vec![Patch {
                addr: 0x7ff0,
                orig: 0x4c,
            }],
            threads: vec![(
                5,
                ThreadFix {
                    rewind_to: Some(0x7ff0),
                    clear_trap: false,
                },
            )],
            detached: true,
            etw_stopped: Some("heapspy-10".into()),
            ..Report::default()
        };
        let line = r.line();
        assert!(!line.contains('\n'));
        assert_eq!(
            line,
            "heapspy guardian: recorder pid 10 ended without finishing (target pid 20); \
             restored 1 breakpoint byte (0x7ff0), released 1 thread stopped at a breakpoint, \
             detached the debugger, stopped ETW session heapspy-10"
        );
        let log = r.log();
        assert!(log.starts_with(&line));
        assert!(log.contains("restored 0x7ff0: int3 -> 0x4c"));
        assert!(log.contains("thread 5: stopped at the breakpoint at 0x7ff0, rewound"));
        let empty = Report {
            recorder: 1,
            ..Report::default()
        };
        assert!(empty.line().ends_with("nothing needed cleaning up"));
    }

    #[test]
    fn log_next_to_profile() {
        assert_eq!(
            log_path(std::path::Path::new("out/a.hpya")),
            std::path::PathBuf::from("out/a.hpya.guardian.log")
        );
    }

    #[test]
    fn session_names() {
        assert_eq!(session_name(4321), "heapspy-4321");
        assert_eq!(session_pid("heapspy-4321"), Some(4321));
        for n in [
            "heapspy-",
            "heapspy-12a",
            "heapspy-foreign",
            "Heapspy-12",
            "xheapspy-12",
            "heapspy-1-2",
            "heapspy-99999999999",
            "NT Kernel Logger",
            "heapspy",
        ] {
            assert_eq!(session_pid(n), None, "{n}");
        }
    }

    #[test]
    fn only_dead_heapspy_sessions_are_stale() {
        let names: Vec<String> = [
            "heapspy-1",        // dead recorder: stale
            "heapspy-2",        // running heapspy: kept
            "heapspy-3",        // this recorder: kept
            "heapspy-foreign",  // not ours
            "NT Kernel Logger", // not ours
            "Circular Kernel Context Logger",
            "myheapspy-4", // not ours
        ]
        .map(String::from)
        .into();
        let mut asked = Vec::new();
        let stale = stale_sessions(&names, 3, |p| {
            asked.push(p);
            p == 2
        });
        assert_eq!(stale, ["heapspy-1"]);
        assert_eq!(asked, [1, 2], "only heapspy's sessions are looked up");
    }

    #[test]
    fn heapspy_images() {
        assert!(is_heapspy_image(r"C:\tools\heapspy.exe", None));
        assert!(is_heapspy_image(r"C:\tools\HEAPSPY.EXE", None));
        assert!(is_heapspy_image("heapspy", None));
        assert!(!is_heapspy_image(r"C:\Python\python.exe", None));
        assert!(!is_heapspy_image(r"C:\x\heapspy-old.exe", None));
        assert!(is_heapspy_image(
            r"C:\t\deps\record_live_windows-ab12.exe",
            Some("record_live_windows-ab12")
        ));
    }
}
