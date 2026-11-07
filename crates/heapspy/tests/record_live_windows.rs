//! `heapspy record` against real CPython processes on Windows, through
//! ETW and through the debugger, then `--then-dump` and `analyze
//! --allocations`; and the safety checks of
//! `docs/windows-record-test-plan.md` that can run unattended.
//!
//! Needs an elevated process (the ETW kernel session and
//! `SeDebugPrivilege`) and specific interpreters, so it is ignored by
//! default. GitHub's Windows runners are elevated. Run it with:
//!
//! ```text
//! cargo test -p heapspy --test record_live_windows -- --ignored --test-threads 1 --nocapture
//! ```
//!
//! Interpreters: `HEAPSPY_PY312` / `HEAPSPY_PY313` / `HEAPSPY_PY314`, else
//! `uv python find --python-preference only-managed 3.1X`. A missing
//! interpreter fails the test. Windows only.
//!
//! The victim is the one of `record_live.rs` (same lines): `handler() ->
//! build_payload() -> bytes(64 KiB)` kept in a rotating list of 200, a small
//! list leaked per call (which grows pymalloc arenas from inside
//! `build_payload`, at line 5), and `noise() -> bytes(16 KiB)` as a second
//! chain. It also rewrites a heartbeat file every 1000 iterations, so a
//! test can tell that it still runs.
//!
//! On Windows only arenas are recorded (`VirtualAlloc` of 1 MiB from the
//! Python DLL). What the two mechanisms can promise differs:
//!
//! - **Debugger**: the stack is read while the thread is stopped at the
//!   `VirtualAlloc` call, so it is exact: `build_payload` at line 5.
//! - **ETW**: the event carries no Python stack. Each event takes the
//!   nearest 5 ms stack sample of the same thread, so the stack is where
//!   the thread happened to be within a few milliseconds of the arena call,
//!   not the call itself: any point of the loop, weighted by the time spent
//!   there. On windows-latest the top stack was `build_payload:6 <-
//!   handler:8` in seven runs out of nine, and `handler:8` or `main:20`
//!   in the other two; line 5, where arenas are carved, is rarely matched
//!   because the
//!   thread spends little time there. Twice, in about twenty runs, no top-5
//!   stack had `build_payload` under `handler:8` at all: the samples split
//!   across `handler:7`, `handler:8` and `handler:10`. So the ETW checks
//!   are statistical and hold whatever the order of the top stacks: one of
//!   the five top stacks runs through `handler`, more samples fall in the
//!   leak's chain (`handler`) than in the noise's (`noise`), nearly every
//!   sample matched a stack, and every frame is flagged approximate.
//!   Requiring an exact line would fail some runs for reasons that are not
//!   bugs. The debugger tests check the exact stack.
//!
//! Every test prints a `RESULT` line (sample counts, top stack) for the
//! CI log, and `SKIPPED` when a check could not run on this machine.

#![cfg(windows)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use heapspy_alloc::{Mechanism, Profile, SampleFlags};
use heapspy_analyzer::report::{AnalyzeReport, StackFrame};
use heapspy_record::{MechanismChoice, RecordOptions};

// Line numbers matter: see the constants below. Lines 1-12 are the same as
// in record_live.rs.
const VICTIM: &str = r#"import os, sys, time
keep = []
leaked = []
def build_payload(i):
    leaked.append([i] * 16)
    return bytes(64 * 1024)
def handler(i):
    keep.append(build_payload(i))
    if len(keep) > 200:
        del keep[0]
def noise():
    return bytes(16 * 1024)
def main(ready, beat):
    tmp = ready + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(os.getpid()))
    os.rename(tmp, ready)
    i = 0
    while True:
        handler(i)
        noise()
        i += 1
        if i % 1000 == 0:
            with open(beat, "w") as f:
                f.write(str(i))
main(sys.argv[1], sys.argv[2])
"#;
/// `leaked.append(...)`: arenas are carved here.
const ARENA_LINE: u32 = 5;
/// `keep.append(build_payload(i))`.
const HANDLER_LINE: u32 = 8;

/// The ETW sessions the recorder may start: its own `heapspy-<pid>`
/// (system logger mode), or this one where that mode is not supported.
const KERNEL_LOGGER: &str = "NT Kernel Logger";

// ---- Win32, for the checks only ---------------------------------------

#[allow(non_snake_case)]
#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn CheckRemoteDebuggerPresent(h: *mut c_void, present: *mut i32) -> i32;
    fn ReadProcessMemory(
        h: *mut c_void,
        addr: *const c_void,
        buf: *mut c_void,
        len: usize,
        read: *mut usize,
    ) -> i32;
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
    fn GetLastError() -> u32;
    fn GetCurrentProcess() -> *mut c_void;
}

#[allow(non_snake_case)]
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        info: *mut c_void,
        len: u32,
        ret: *mut u32,
    ) -> i32;
}

const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION: u32 = 20;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const CTRL_BREAK_EVENT: u32 = 1;

struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: closing a handle we opened.
        unsafe { CloseHandle(self.0) };
    }
}

fn open(pid: u32, access: u32) -> Handle {
    // SAFETY: plain OpenProcess.
    let h = unsafe { OpenProcess(access, 0, pid) };
    assert!(!h.is_null(), "OpenProcess({pid}) failed: {}", unsafe {
        GetLastError()
    });
    Handle(h)
}

/// The runner is elevated; heapspy needs that for ETW and the debugger.
fn assert_elevated() {
    // SAFETY: querying our own token.
    unsafe {
        let mut tok = std::ptr::null_mut();
        assert!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) != 0);
        let tok = Handle(tok);
        let mut elevated = 0u32;
        let mut n = 0u32;
        assert!(
            GetTokenInformation(
                tok.0,
                TOKEN_ELEVATION,
                (&mut elevated as *mut u32).cast(),
                4,
                &mut n,
            ) != 0
        );
        assert!(
            elevated != 0,
            "these tests need an elevated process (Run as administrator)"
        );
    }
}

/// A debugger is attached to `pid`.
fn debugger_attached(pid: u32) -> bool {
    // CheckRemoteDebuggerPresent needs the full query right.
    let h = open(pid, PROCESS_QUERY_INFORMATION);
    let mut present = 0i32;
    // SAFETY: valid handle and out pointer.
    assert!(unsafe { CheckRemoteDebuggerPresent(h.0, &mut present) } != 0);
    present != 0
}

/// The first bytes of `KERNELBASE!VirtualAlloc`, where the debugger sets
/// its breakpoint, in `pid` and in this process. System DLLs are mapped at
/// the same address in every process of a boot, so the two must match.
fn virtual_alloc_bytes(pid: u32) -> ([u8; 16], [u8; 16]) {
    // SAFETY: reading our own loaded module and the target's memory at the
    // same address.
    unsafe {
        let m = GetModuleHandleA(c"kernelbase.dll".as_ptr().cast());
        assert!(!m.is_null());
        let f = GetProcAddress(m, c"VirtualAlloc".as_ptr().cast());
        assert!(!f.is_null());
        let mut ours = [0u8; 16];
        std::ptr::copy_nonoverlapping(f as *const u8, ours.as_mut_ptr(), 16);
        let h = open(pid, PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION);
        let mut theirs = [0u8; 16];
        let mut n = 0usize;
        assert!(
            ReadProcessMemory(h.0, f, theirs.as_mut_ptr().cast(), 16, &mut n) != 0 && n == 16,
            "ReadProcessMemory failed: {}",
            GetLastError()
        );
        (theirs, ours)
    }
}

// ---- ETW sessions --------------------------------------------------------

fn etw_sessions() -> String {
    let o = Command::new("logman")
        .args(["query", "-ets"])
        .output()
        .expect("run logman");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Names of the running ETW sessions, from `logman query -ets`.
fn session_names() -> Vec<String> {
    etw_sessions()
        .lines()
        .filter_map(|l| {
            let l = l.trim_end();
            // Rows are "<name>   <type>   <status>"; names may have spaces.
            let cut = l.find("  ")?;
            Some(l[..cut].trim().to_string())
        })
        .filter(|n| !n.is_empty())
        .collect()
}

/// heapspy's own session name: `heapspy-<digits>`.
fn is_heapspy_session(n: &str) -> bool {
    n.strip_prefix("heapspy-")
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// A recorder's ETW session is running (heapspy's own, or the kernel
/// logger it falls back to).
fn kernel_logger_running() -> bool {
    session_names()
        .iter()
        .any(|n| n == KERNEL_LOGGER || is_heapspy_session(n))
}

/// Stops a recorder session left behind by a failed test, so the next
/// test does not fail for that reason too. Created only after checking that
/// no other tool had one.
struct LoggerGuard;

impl LoggerGuard {
    fn new() -> LoggerGuard {
        assert!(
            !kernel_logger_running(),
            "a recorder ETW session is already running before the test:\n{}",
            etw_sessions()
        );
        LoggerGuard
    }
}

impl Drop for LoggerGuard {
    fn drop(&mut self) {
        for n in session_names() {
            if n == KERNEL_LOGGER || is_heapspy_session(&n) {
                eprintln!("cleanup: stopping a leftover {n} session");
                let _ = Command::new("logman").args(["stop", &n, "-ets"]).output();
            }
        }
    }
}

/// Start a real-time ETW session of any provider under `name` with
/// logman, as another tool (or a killed heapspy) would leave one.
fn start_foreign_session(name: &str) {
    let o = Command::new("logman")
        .args([
            "start",
            name,
            "-p",
            "Microsoft-Windows-Kernel-Process",
            "-rt",
            "-ets",
        ])
        .output()
        .expect("run logman");
    assert!(
        o.status.success(),
        "logman start {name}: {}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
}

fn stop_named_session(name: &str) {
    let _ = Command::new("logman").args(["stop", name, "-ets"]).output();
}

fn python(minor: u8) -> PathBuf {
    if let Ok(p) = std::env::var(format!("HEAPSPY_PY3{minor}")) {
        return p.into();
    }
    let out = Command::new("uv")
        .args([
            "python",
            "find",
            "--python-preference",
            "only-managed",
            &format!("3.{minor}"),
        ])
        .stderr(Stdio::null())
        .output()
        .unwrap_or_else(|e| {
            panic!("run `uv python find 3.{minor}` (or set HEAPSPY_PY3{minor}): {e}")
        });
    assert!(out.status.success(), "uv found no Python 3.{minor}");
    String::from_utf8(out.stdout).unwrap().trim().into()
}

struct Victim {
    child: Child,
    pid: u32,
    beat: PathBuf,
}

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Victim {
    /// `Some(exit status)` if it is no longer running.
    fn exited(&mut self) -> Option<String> {
        self.child
            .try_wait()
            .unwrap()
            .map(|s| format!("{s} ({:#x})", s.code().unwrap_or(0) as u32))
    }

    fn beat(&self) -> Option<u64> {
        std::fs::read_to_string(&self.beat)
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// The victim still runs Python code: its heartbeat advances within
    /// 10 s. `Err` says why not.
    fn responsive(&mut self) -> Result<(), String> {
        let t0 = Instant::now();
        let mut first = None;
        while t0.elapsed() < Duration::from_secs(10) {
            if let Some(s) = self.exited() {
                return Err(format!("the target exited: {s}"));
            }
            match (first, self.beat()) {
                (None, Some(b)) => first = Some(b),
                (Some(a), Some(b)) if b > a => return Ok(()),
                _ => {}
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(format!(
            "the target's heartbeat did not advance in 10 s (last {:?})",
            first
        ))
    }
}

fn start(py: &Path, dir: &Path) -> Victim {
    let script = dir.join("victim.py");
    std::fs::write(&script, VICTIM).unwrap();
    let ready = dir.join("ready");
    let beat = dir.join("beat");
    let child = Command::new(py)
        .arg(&script)
        .arg(&ready)
        .arg(&beat)
        .stdout(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("start {}: {e}", py.display()));
    let t0 = Instant::now();
    while !ready.exists() {
        assert!(t0.elapsed() < Duration::from_secs(30), "victim not ready");
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = child.id();
    let mut v = Victim { child, pid, beat };
    // Let it reach a steady state.
    std::thread::sleep(Duration::from_millis(500));
    v.responsive().expect("victim running");
    v
}

// ---- heapspy -------------------------------------------------------------

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_heapspy")
}

fn heapspy(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn ok_json(o: &Output, what: &str) -> serde_json::Value {
    assert!(
        o.status.success(),
        "{what} failed ({}):\nstdout: {}\nstderr: {}",
        o.status,
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    serde_json::from_slice(&o.stdout).unwrap()
}

fn in_victim(f: &StackFrame) -> bool {
    f.file.as_deref().is_some_and(|p| p.ends_with("victim.py"))
}

fn has(frames: &[StackFrame], func: &str, lines: &[u32]) -> bool {
    frames
        .iter()
        .any(|f| f.function == func && f.line.is_some_and(|l| lines.contains(&l)) && in_victim(f))
}

fn show(frames: &[StackFrame]) -> String {
    frames
        .iter()
        .map(|f| format!("{} ({})", f.function, f.location))
        .collect::<Vec<_>>()
        .join(" <- ")
}

/// Record ~3 s with `--then-dump`, check the record report, the profile,
/// and the join.
fn run(minor: u8, mechanism: &str) {
    assert_elevated();
    let _logger = (mechanism != "debugger").then(LoggerGuard::new);
    let dir = tempfile::tempdir().unwrap();
    let mut v = start(&python(minor), dir.path());
    let prof = dir.path().join("a.hpya");
    let snap = dir.path().join("a.hpy");
    let pid = v.pid.to_string();
    let o = heapspy(&[
        "record",
        "--json",
        "--pid",
        &pid,
        "--duration",
        "3s",
        "--mechanism",
        mechanism,
        "-o",
        s(&prof),
        "--then-dump",
        s(&snap),
    ]);
    if !o.status.success() {
        let state = v.exited().unwrap_or_else(|| "still running".into());
        panic!(
            "record failed ({}); the target: {state}\nstdout: {}\nstderr: {}",
            o.status,
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
    }
    let rec = ok_json(&o, "record");
    eprintln!("{}", String::from_utf8_lossy(&o.stderr).trim_end());
    let want: Vec<&str> = match mechanism {
        // auto is ETW alone on Windows.
        "auto" => vec!["etw"],
        m => vec![m],
    };
    assert_eq!(rec["kind"], "record", "{rec}");
    assert_eq!(rec["mechanisms"], serde_json::json!(want), "{rec}");
    let samples = rec["samples"].as_u64().unwrap();
    assert!(samples > 0, "no samples: {rec}");
    if mechanism == "debugger" {
        assert!(
            rec["overhead"]["total_pause_ns"].as_u64().unwrap() > 0,
            "the debugger stopped no thread: {rec}"
        );
    }

    // The profile itself.
    let p = Profile::open(&prof).expect("a valid profile");
    let skipped = p
        .meta_value("heapspy.skipped_events")
        .unwrap()
        .unwrap_or("");
    assert!(skipped.contains("large_object"), "skipped: {skipped:?}");
    let all: Vec<_> = p.samples().collect();
    let framed = all.iter().filter(|s| s.frame_count > 0).count();
    let approx = all
        .iter()
        .filter(|s| s.flags.contains(SampleFlags::APPROXIMATE_FRAMES))
        .count();
    let with_ret = all
        .iter()
        .filter(|s| s.native_return_address.is_some())
        .count();
    let in_chain = |func: &str| {
        all.iter()
            .filter(|s| p.stack(s).any(|f| f.qualname == Some(func)))
            .count()
    };
    let (leak_chain, noise_chain) = (in_chain("handler"), in_chain("noise"));

    // The join.
    let o = heapspy(&["analyze", s(&snap), "--allocations", s(&prof), "--json"]);
    ok_json(&o, "analyze");
    let r: AnalyzeReport = serde_json::from_slice(&o.stdout).unwrap();
    let a = r.allocations.as_ref().expect("allocations in the report");
    assert_eq!(a.mechanisms, want);
    assert_eq!(a.samples, samples);
    assert_eq!(a.sampling.events, ["arena"]);
    let top = &a.top_stacks[0];
    eprintln!(
        "RESULT python3.{minor} {mechanism}: {samples} samples ({framed} with frames, \
         {approx} approximate, {with_ret} with a native return address; \
         {leak_chain} under handler, {noise_chain} under noise), probe_hits {}, paused {:.1} ms, dropped {}, truncated {}, linked objects {}; \
         top stack ({} samples, {} bytes): {}",
        rec["overhead"]["probe_hits"],
        rec["overhead"]["total_pause_ns"].as_u64().unwrap() as f64 / 1e6,
        rec["overhead"]["samples_dropped"],
        rec["truncated"],
        a.coverage.linked_objects,
        top.samples,
        top.estimated_bytes,
        show(&top.frames)
    );
    for t in a.top_stacks.iter().take(5).skip(1) {
        eprintln!(
            "       #{} ({} samples): {}",
            t.rank,
            t.samples,
            show(&t.frames)
        );
    }

    match mechanism {
        "etw" | "auto" => {
            assert!(a.approximate, "ETW frames not flagged approximate");
            // ETW alone has no exact sample: every framed one is approximate.
            assert_eq!(approx, all.len(), "samples not flagged approximate");
            assert!(
                top.approximate && top.frames.iter().all(|f| f.approximate),
                "top stack frames not approximate: {top:?}"
            );
            // A stack sample within 20 ms of nearly every arena event:
            // fewer than half with frames means the matching is broken
            // (thread ids or clocks disagree), not unlucky.
            assert!(
                framed * 2 >= all.len(),
                "only {framed} of {} ETW samples matched a stack",
                all.len()
            );
            // Statistical, see the module docs: the frames are where the
            // thread was within a few ms of the event, so which line of
            // `handler` (and whether `build_payload` is below it) varies
            // from run to run. That the leak's chain dominates does not.
            assert!(
                a.top_stacks.iter().take(5).any(|t| t
                    .frames
                    .iter()
                    .any(|f| f.function == "handler" && in_victim(f))),
                "no top-5 stack runs through handler"
            );
            assert!(
                leak_chain > noise_chain,
                "{leak_chain} samples under handler, {noise_chain} under noise"
            );
        }
        _ => {
            if mechanism == "debugger" {
                assert!(!a.approximate, "debugger frames flagged approximate");
                assert_eq!(approx, 0);
                // Read at the breakpoint: exact, at the arena call.
                assert!(
                    !top.approximate && top.frames.iter().all(|f| !f.approximate),
                    "top stack approximate: {top:?}"
                );
            } else {
                // auto: the debugger's samples are exact; the few the ETW
                // side wrote alone are approximate, and an ETW sample on the
                // same stack marks the merged stack approximate.
                assert!(
                    approx * 2 < all.len(),
                    "{approx} of {} approximate",
                    all.len()
                );
            }
            assert!(
                has(&top.frames, "build_payload", &[ARENA_LINE])
                    && has(&top.frames, "handler", &[HANDLER_LINE]),
                "top stack is not build_payload:{ARENA_LINE} <- handler:{HANDLER_LINE}: {}",
                show(&top.frames)
            );
            let exact: Vec<_> = all
                .iter()
                .filter(|s| !s.flags.contains(SampleFlags::APPROXIMATE_FRAMES))
                .collect();
            assert!(!exact.is_empty(), "no exact samples");
            assert!(
                exact.iter().all(|s| s.native_return_address.is_some()),
                "debugger samples without a native return address"
            );
            assert!(
                exact.iter().filter(|s| s.frame_count > 0).count() * 10 >= exact.len() * 9,
                "fewer than 90% of the debugger samples have frames"
            );
            // `leaked` grows from arenas carved in build_payload.
            let leak = r.top_retainers.iter().find(|t| {
                let p = heapspy_analyzer::root_path_string(&t.path);
                p.ends_with("['leaked']")
                    || (p.starts_with("frame __main__:build_payload")
                        && t.type_name == "builtins.list")
            });
            let leak = leak.unwrap_or_else(|| {
                let paths: Vec<String> = r
                    .top_retainers
                    .iter()
                    .map(|t| heapspy_analyzer::root_path_string(&t.path))
                    .collect();
                panic!("no retainer for 'leaked' in {paths:?}")
            });
            let at = leak.allocated_at.as_ref().expect("allocated_at on leaked");
            assert!(
                at.stacks
                    .iter()
                    .any(|st| has(&st.frames, "build_payload", &[ARENA_LINE])),
                "'leaked' is not linked to build_payload:{ARENA_LINE}: {at:?}"
            );
        }
    }
    assert!(a.coverage.linked_objects > 0, "nothing linked");

    // The target is left as it was.
    v.responsive().expect("target responsive after recording");
    assert!(!debugger_attached(v.pid), "a debugger is still attached");
    let (theirs, ours) = virtual_alloc_bytes(v.pid);
    assert_eq!(theirs, ours, "VirtualAlloc's code differs in the target");
    if mechanism != "debugger" {
        assert!(!kernel_logger_running(), "{KERNEL_LOGGER} left running");
    }
}

macro_rules! live {
    ($name:ident, $minor:expr, $mech:expr) => {
        #[test]
        #[ignore = "needs an elevated prompt and specific interpreters"]
        fn $name() {
            run($minor, $mech);
        }
    };
}

live!(python312_etw, 12, "etw");
live!(python313_etw, 13, "etw");
live!(python314_etw, 14, "etw");
live!(python312_debugger, 12, "debugger");
live!(python313_debugger, 13, "debugger");
live!(python314_debugger, 14, "debugger");
live!(python313_auto, 13, "auto");

// ---- safety --------------------------------------------------------------

/// Everything that must hold for the target after a recording ended,
/// however it ended. Collects every failure, so a report shows them all.
fn target_left_clean(v: &mut Victim, mechanism: &str) -> Vec<String> {
    let mut bad = Vec::new();
    if let Err(e) = v.responsive() {
        bad.push(e);
    }
    if v.exited().is_none() {
        if debugger_attached(v.pid) {
            bad.push("a debugger is still attached".into());
        }
        let (theirs, ours) = virtual_alloc_bytes(v.pid);
        if theirs != ours {
            bad.push(format!(
                "VirtualAlloc's code differs in the target: {theirs:02x?} vs {ours:02x?}"
            ));
        }
    }
    if mechanism != "debugger" && kernel_logger_running() {
        bad.push(format!(
            "the {KERNEL_LOGGER} session was left running:\n{}",
            etw_sessions()
        ));
    }
    bad
}

/// `TerminateProcess` on the recorder mid-run (what `taskkill /F` does):
/// the target keeps running, no debugger stays attached, no `int3` stays
/// in `VirtualAlloc`, and no ETW session is left behind.
fn killed(mechanism: &str) {
    assert_elevated();
    let _logger = (mechanism != "debugger").then(LoggerGuard::new);
    let dir = tempfile::tempdir().unwrap();
    let mut v = start(&python(13), dir.path());
    let out = dir.path().join("k.hpya");
    let mut rec = Command::new(bin())
        .args([
            "record",
            "--pid",
            &v.pid.to_string(),
            "--duration",
            "60s",
            "--mechanism",
            mechanism,
            "-o",
            s(&out),
        ])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    assert!(
        rec.try_wait().unwrap().is_none(),
        "the recorder exited before it was killed"
    );
    if mechanism != "debugger" {
        assert!(
            kernel_logger_running(),
            "the recorder started no ETW session"
        );
    } else {
        assert!(
            debugger_attached(v.pid),
            "the recorder attached no debugger"
        );
    }
    rec.kill().unwrap();
    rec.wait().unwrap();
    std::thread::sleep(Duration::from_millis(500));
    // What the guardian found and did, for the CI log.
    let log = dir.path().join("k.hpya.guardian.log");
    match std::fs::read_to_string(&log) {
        Ok(t) => eprintln!("GUARDIAN {mechanism}:\n{}", t.trim_end()),
        Err(e) => eprintln!("GUARDIAN {mechanism}: no log ({e})"),
    }
    let mut bad = target_left_clean(&mut v, mechanism);
    if out.exists() {
        bad.push("a killed recording left a profile".into());
    }
    eprintln!(
        "RESULT kill mid-run, {mechanism}: {}",
        if bad.is_empty() {
            "target clean".to_string()
        } else {
            bad.join("; ")
        }
    );
    assert!(bad.is_empty(), "after killing the recorder: {bad:#?}");
}

#[test]
#[ignore = "needs an elevated prompt and specific interpreters"]
fn kill_mid_run_etw() {
    killed("etw");
}

#[test]
#[ignore = "needs an elevated prompt and specific interpreters"]
fn kill_mid_run_debugger() {
    killed("debugger");
}

/// Ctrl-Break on the console (the handler treats Ctrl-C and Ctrl-Break the
/// same way) ends the recording early with a valid profile flagged
/// truncated, and leaves the target clean.
///
/// `CTRL_C_EVENT` cannot be sent to one process group, only to every
/// process on the console (this test included), so the recorder is started
/// in its own group and sent `CTRL_BREAK_EVENT`. That needs a console
/// shared with the recorder; without one the check is reported as
/// `SKIPPED` and the stop flag is covered by `stop_flag_*` below.
fn interrupted(mechanism: &str) {
    use std::os::windows::process::CommandExt;
    assert_elevated();
    let _logger = (mechanism != "debugger").then(LoggerGuard::new);
    let dir = tempfile::tempdir().unwrap();
    let mut v = start(&python(13), dir.path());
    let out = dir.path().join("i.hpya");
    let mut rec = Command::new(bin())
        .args([
            "record",
            "--json",
            "--pid",
            &v.pid.to_string(),
            "--duration",
            "60s",
            "--mechanism",
            mechanism,
            "-o",
            s(&out),
        ])
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    let t0 = Instant::now();
    // SAFETY: sending a console event to the recorder's process group.
    if unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, rec.id()) } == 0 {
        let e = unsafe { GetLastError() };
        let _ = rec.kill();
        let _ = rec.wait();
        eprintln!(
            "SKIPPED ctrl-break, {mechanism}: GenerateConsoleCtrlEvent failed \
             (error {e}); this process has no console to share"
        );
        return;
    }
    let o = rec.wait_with_output().unwrap();
    let took = t0.elapsed();
    let doc = ok_json(&o, "record after Ctrl-Break");
    assert!(took < Duration::from_secs(5), "slow to stop: {took:?}");
    assert_eq!(doc["kind"], "record");
    assert_eq!(doc["truncated"], true, "{doc}");
    let p = Profile::open(&out).expect("a valid profile");
    assert!(p.info().truncated);
    let bad = target_left_clean(&mut v, mechanism);
    eprintln!(
        "RESULT ctrl-break, {mechanism}: stopped in {:.1} s, {} samples, truncated; {}",
        took.as_secs_f64(),
        doc["samples"],
        if bad.is_empty() {
            "target clean".to_string()
        } else {
            bad.join("; ")
        }
    );
    assert!(bad.is_empty(), "after Ctrl-Break: {bad:#?}");
}

#[test]
#[ignore = "needs an elevated prompt and specific interpreters"]
fn ctrl_break_etw() {
    interrupted("etw");
}

#[test]
#[ignore = "needs an elevated prompt and specific interpreters"]
fn ctrl_break_debugger() {
    interrupted("debugger");
}

/// The flag Ctrl-C sets, through the library: `record` returns early with
/// a profile flagged truncated, and the target is left clean.
fn stop_flag(mechanism: Mechanism) {
    assert_elevated();
    let name = mechanism.as_str();
    let _logger = (mechanism == Mechanism::Etw).then(LoggerGuard::new);
    let dir = tempfile::tempdir().unwrap();
    let mut v = start(&python(13), dir.path());
    let out = dir.path().join("f.hpya");
    let mut opts = RecordOptions::new(v.pid, Duration::from_secs(60), &out);
    opts.mechanism = MechanismChoice::Only(mechanism);
    let stop = AtomicBool::new(false);
    let t0 = Instant::now();
    let stats = std::thread::scope(|sc| {
        sc.spawn(|| {
            std::thread::sleep(Duration::from_millis(2500));
            stop.store(true, Ordering::SeqCst);
        });
        heapspy_record::record(&opts, &stop)
    })
    .unwrap_or_else(|e| panic!("record with {name}: {e}"));
    let took = t0.elapsed();
    assert!(took < Duration::from_secs(8), "slow to stop: {took:?}");
    assert!(stats.truncated);
    let p = Profile::open(&out).expect("a valid profile");
    assert!(p.info().truncated);
    let bad = target_left_clean(&mut v, name);
    eprintln!(
        "RESULT stop flag, {name}: returned after {:.1} s, {} samples, truncated; {}",
        took.as_secs_f64(),
        stats.samples,
        if bad.is_empty() {
            "target clean".to_string()
        } else {
            bad.join("; ")
        }
    );
    assert!(bad.is_empty(), "after the stop flag: {bad:#?}");
}

#[test]
#[ignore = "needs an elevated prompt and specific interpreters"]
fn stop_flag_etw() {
    stop_flag(Mechanism::Etw);
}

#[test]
#[ignore = "needs an elevated prompt and specific interpreters"]
fn stop_flag_debugger() {
    stop_flag(Mechanism::Debugger);
}

// ---- guardian and ETW sessions -----------------------------------------------

/// A pid no process has: a process that ran and exited.
fn dead_pid() -> u32 {
    let mut c = Command::new("cmd").args(["/c", "exit"]).spawn().unwrap();
    let pid = c.id();
    c.wait().unwrap();
    pid
}

/// A `heapspy-<pid>` session of a recorder that is gone (killed, so its
/// guardian could not act either) is stopped by the next recording.
#[test]
#[ignore = "needs an elevated prompt and specific interpreters"]
fn stale_session_is_cleaned_up() {
    assert_elevated();
    let _logger = LoggerGuard::new();
    let stale = format!("heapspy-{}", dead_pid());
    start_foreign_session(&stale);
    assert!(session_names().contains(&stale), "{}", etw_sessions());
    let dir = tempfile::tempdir().unwrap();
    let mut v = start(&python(13), dir.path());
    let prof = dir.path().join("s.hpya");
    let o = heapspy(&[
        "record",
        "--pid",
        &v.pid.to_string(),
        "--duration",
        "1s",
        "--mechanism",
        "etw",
        "-o",
        s(&prof),
    ]);
    let err = String::from_utf8_lossy(&o.stderr);
    let left = session_names().contains(&stale);
    if left {
        stop_named_session(&stale);
    }
    eprintln!(
        "RESULT stale session {stale}: {}",
        if left { "left running" } else { "stopped" }
    );
    assert!(o.status.success(), "record failed: {err}");
    assert!(!left, "the stale {stale} session was not stopped: {err}");
    assert!(err.contains(&stale), "the stop is not reported: {err}");
    let bad = target_left_clean(&mut v, "etw");
    assert!(bad.is_empty(), "{bad:#?}");
}

/// Sessions whose names are not exactly `heapspy-<pid of a dead
/// recorder>` are never touched: other names, names that only look like
/// heapspy's, and a heapspy name whose pid is a running process.
#[test]
#[ignore = "needs an elevated prompt and specific interpreters"]
fn foreign_sessions_are_untouched() {
    assert_elevated();
    let _logger = LoggerGuard::new();
    let dir = tempfile::tempdir().unwrap();
    let mut v = start(&python(13), dir.path());
    let foreign = [
        "heapspy-foreign".to_string(),
        format!("heapspyx-{}", dead_pid()),
        format!("other-{}", dead_pid()),
    ];
    for n in &foreign {
        start_foreign_session(n);
    }
    let prof = dir.path().join("f.hpya");
    let o = heapspy(&[
        "record",
        "--pid",
        &v.pid.to_string(),
        "--duration",
        "1s",
        "--mechanism",
        "etw",
        "-o",
        s(&prof),
    ]);
    let names = session_names();
    let missing: Vec<&String> = foreign.iter().filter(|n| !names.contains(n)).collect();
    for n in &foreign {
        stop_named_session(n);
    }
    eprintln!(
        "RESULT foreign sessions: {}",
        if missing.is_empty() {
            "untouched".to_string()
        } else {
            format!("stopped {missing:?}")
        }
    );
    assert!(
        o.status.success(),
        "record failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(missing.is_empty(), "heapspy stopped {missing:?}");
    let bad = target_left_clean(&mut v, "etw");
    assert!(bad.is_empty(), "{bad:#?}");
}

/// After a clean finish the guardian is told there is nothing to do: it
/// exits without a word and without writing its log (the recorder's
/// stderr pipe closing, which `output()` waits for, shows it has exited).
fn guardian_idle(mechanism: &str) {
    assert_elevated();
    let _logger = (mechanism != "debugger").then(LoggerGuard::new);
    let dir = tempfile::tempdir().unwrap();
    let mut v = start(&python(13), dir.path());
    let prof = dir.path().join("g.hpya");
    let t0 = Instant::now();
    let o = heapspy(&[
        "record",
        "--pid",
        &v.pid.to_string(),
        "--duration",
        "2s",
        "--mechanism",
        mechanism,
        "-o",
        s(&prof),
    ]);
    let took = t0.elapsed();
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "record failed: {err}");
    assert!(!err.contains("guardian:"), "the guardian acted: {err}");
    assert!(!err.contains("no guardian"), "no guardian ran: {err}");
    let log = dir.path().join("g.hpya.guardian.log");
    assert!(!log.exists(), "the guardian wrote {}", log.display());
    assert!(took < Duration::from_secs(20), "took {took:?}");
    let bad = target_left_clean(&mut v, mechanism);
    eprintln!(
        "RESULT guardian after a clean finish, {mechanism}: {}",
        if bad.is_empty() {
            "did nothing".to_string()
        } else {
            bad.join("; ")
        }
    );
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
#[ignore = "needs an elevated prompt and specific interpreters"]
fn guardian_idle_after_clean_finish_etw() {
    guardian_idle("etw");
}

#[test]
#[ignore = "needs an elevated prompt and specific interpreters"]
fn guardian_idle_after_clean_finish_debugger() {
    guardian_idle("debugger");
}
