//! Win32 side of the guardian (see [`super::guardian`]): starting it from
//! the recorder ([`Link`]), and the guardian process itself ([`main`]).

use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, DUPLICATE_SAME_ACCESS,
    EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcessStop, FlushInstructionCache, GetThreadContext,
    ReadProcessMemory, SetThreadContext, WaitForDebugEvent, WriteProcessMemory,
    CONTEXT_CONTROL_AMD64, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT,
    EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenThread, ResumeThread, SuspendThread,
    WaitForMultipleObjects, CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME,
};

use super::guardian::{
    plan_patches, takeover_reply, thread_fix, Msg, PatchAction, Report, State, TakeoverEvent,
    TakeoverReply, GUARDIAN_ARG,
};
use super::live::Handle;
use super::sys::{stop_session, AlignedContext, StopSession};

#[link(name = "ntdll")]
extern "system" {
    fn DbgUiGetThreadDebugObject() -> HANDLE;
    fn DbgUiSetThreadDebugObject(h: HANDLE);
}

// ---- recorder side ----------------------------------------------------------

/// The executable to run as the guardian: `HEAPSPY_GUARDIAN_EXE`, else
/// this program when it is heapspy, else a `heapspy.exe` next to it or one
/// directory up (a test binary in `target/debug/deps`).
fn guardian_exe() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("HEAPSPY_GUARDIAN_EXE") {
        return Some(p.into());
    }
    let me = std::env::current_exe().ok()?;
    let stem = me.file_stem()?.to_string_lossy().to_ascii_lowercase();
    if stem == "heapspy" {
        return Some(me);
    }
    let dir = me.parent()?;
    [dir.join("heapspy.exe"), dir.parent()?.join("heapspy.exe")]
        .into_iter()
        .find(|p| p.is_file())
}

/// The recorder's connection to its guardian.
pub struct Link {
    child: Child,
    stdin: Mutex<Option<ChildStdin>>,
}

impl Link {
    /// Start the guardian for `target` and wait for it to be ready.
    pub fn start(target: u32, log: &Path) -> Result<Link, String> {
        let exe = guardian_exe().ok_or("no heapspy executable found to run the guardian")?;
        let spawn = |flags: u32| {
            Command::new(&exe)
                .arg(GUARDIAN_ARG)
                .arg(std::process::id().to_string())
                .creation_flags(flags)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
        };
        // Out of the recorder's job if the job allows it, so closing the
        // job does not take the guardian down with the recorder.
        let mut child = spawn(CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
            .or_else(|_| spawn(CREATE_NEW_PROCESS_GROUP))
            .map_err(|e| format!("starting {}: {e}", exe.display()))?;
        let mut out = BufReader::new(child.stdout.take().expect("piped"));
        let mut line = String::new();
        let _ = out.read_line(&mut line);
        if line.trim() != "ready" {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("the guardian did not start ({:?})", line.trim()));
        }
        let link = Link {
            stdin: Mutex::new(child.stdin.take()),
            child,
        };
        link.send(&Msg::Target(target));
        link.send(&Msg::Log(log.display().to_string()));
        Ok(link)
    }

    /// Send one message; a guardian that is gone is ignored.
    pub fn send(&self, m: &Msg) {
        let mut g = self.stdin.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(w) = g.as_mut() {
            let ok = writeln!(w, "{}", m.encode()).and_then(|_| w.flush());
            if ok.is_err() {
                *g = None;
            }
        }
    }

    /// Hand the calling thread's debug object (the one `DebugActiveProcess`
    /// just created) to the guardian, so it outlives this process.
    pub fn share_debug_object(&self) {
        // SAFETY: duplicating our own handle into the guardian process,
        // which we hold a full handle to.
        unsafe {
            let h = DbgUiGetThreadDebugObject();
            if h.is_null() {
                return;
            }
            let mut out: HANDLE = std::ptr::null_mut();
            if DuplicateHandle(
                GetCurrentProcess(),
                h,
                self.child.as_raw_handle() as HANDLE,
                &mut out,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            ) != 0
            {
                self.send(&Msg::Debug(out as u64));
            }
        }
    }
}

/// Dropped on every way out of the recorder that runs code (a clean
/// finish, an error, a panic's unwinding), after the debugger detached and
/// the ETW session stopped, which are dropped first: the guardian is told
/// there is nothing to do, and exits without acting.
impl Drop for Link {
    fn drop(&mut self) {
        self.send(&Msg::Done);
        *self.stdin.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(2) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

// ---- the guardian process ---------------------------------------------------

/// `heapspy __guardian <recorder pid>`. Returns the exit code.
pub fn main(args: &[String]) -> i32 {
    let Some(recorder) = args.first().and_then(|a| a.parse::<u32>().ok()) else {
        eprintln!("heapspy guardian: usage: heapspy {GUARDIAN_ARG} <recorder pid>");
        return 2;
    };
    // SAFETY: plain OpenProcess.
    let rec = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, recorder) };
    if rec.is_null() {
        eprintln!("heapspy guardian: cannot open the recorder (pid {recorder})");
        return 1;
    }
    let rec = Handle(rec);
    let (tx, rx) = mpsc::channel::<Option<Msg>>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            if let Some(m) = Msg::decode(&line) {
                if tx.send(Some(m)).is_err() {
                    return;
                }
            }
        }
        let _ = tx.send(None);
    });
    println!("ready");
    let _ = std::io::stdout().flush();

    let mut st = State::default();
    let mut target: Option<Handle> = None;
    let mut target_gone = false;
    let mut eof = false;
    loop {
        while let Ok(m) = rx.try_recv() {
            match m {
                Some(m) => {
                    if let Msg::Target(pid) = m {
                        // SAFETY: plain OpenProcess.
                        let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
                        if !h.is_null() {
                            target = Some(Handle(h));
                        }
                    }
                    st.apply(m);
                }
                None => eof = true,
            }
        }
        if st.done {
            return 0;
        }
        if eof {
            break;
        }
        let mut hs = vec![rec.0];
        if let Some(t) = &target {
            hs.push(t.0);
        }
        // SAFETY: valid handles.
        let w = unsafe { WaitForMultipleObjects(hs.len() as u32, hs.as_ptr(), 0, 20) };
        if w == WAIT_OBJECT_0 {
            break;
        }
        if w == WAIT_OBJECT_0 + 1 {
            // The target exited: nothing to restore in it any more.
            target = None;
            target_gone = true;
            if st.etw.is_none() {
                return 0;
            }
        } else if w != WAIT_TIMEOUT {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    // The recorder is gone. Take what it wrote before it died.
    let deadline = Instant::now() + Duration::from_millis(200);
    while !eof && Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(Some(m)) => st.apply(m),
            Ok(None) => eof = true,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => break,
        }
    }
    if st.done {
        return 0;
    }
    let report = cleanup(recorder, &st, target_gone);
    eprintln!("{}", report.line());
    if let Some(p) = &st.log {
        let _ = std::fs::write(p, report.log());
    }
    0
}

fn cleanup(recorder: u32, st: &State, target_gone: bool) -> Report {
    let mut r = Report {
        recorder,
        target: st.target,
        ..Report::default()
    };
    if let (Some(pid), false) = (st.target, target_gone) {
        repair_target(pid, st, &mut r);
    }
    if let Some(name) = &st.etw {
        match stop_session(name) {
            StopSession::Stopped => r.etw_stopped = Some(name.clone()),
            StopSession::NotFound => r.etw_gone = Some(name.clone()),
            StopSession::Failed(e) => r
                .errors
                .push(format!("stopping ETW session {name}: error {e}")),
        }
    }
    r
}

fn repair_target(pid: u32, st: &State, r: &mut Report) {
    let debug = st.debug.map(|h| h as HANDLE);
    if let Some(h) = debug {
        // SAFETY: the handle was duplicated into this process for us.
        unsafe { DbgUiSetThreadDebugObject(h) };
    }
    if st.patches.is_empty() && debug.is_none() {
        return;
    }
    // SAFETY: plain OpenProcess.
    let p = unsafe {
        OpenProcess(
            PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    if p.is_null() {
        r.errors.push(format!(
            "OpenProcess({pid}): error {}",
            std::io::Error::last_os_error()
        ));
        return;
    }
    let p = Handle(p);
    let read = |a: u64| {
        let mut b = 0u8;
        let mut n = 0usize;
        // SAFETY: one byte into `b`.
        let ok =
            unsafe { ReadProcessMemory(p.0, a as *const _, (&mut b as *mut u8).cast(), 1, &mut n) };
        (ok != 0 && n == 1).then_some(b)
    };
    for a in plan_patches(&st.patches, read) {
        match a {
            PatchAction::Restore(pt) => {
                let mut n = 0usize;
                // SAFETY: writing back the byte heapspy replaced.
                let ok = unsafe {
                    let ok = WriteProcessMemory(
                        p.0,
                        pt.addr as *const _,
                        (&pt.orig as *const u8).cast(),
                        1,
                        &mut n,
                    );
                    FlushInstructionCache(p.0, pt.addr as *const _, 1);
                    ok != 0 && n == 1
                };
                if ok {
                    r.restored.push(pt);
                } else {
                    r.errors.push(format!("writing {:#x} back failed", pt.addr));
                }
            }
            PatchAction::Skip { patch, found } => r.skipped.push((patch, Some(found))),
            PatchAction::Unreadable(patch) => r.skipped.push((patch, None)),
        }
    }
    let patched: Vec<u64> = st.patches.iter().map(|p| p.addr).collect();
    if debug.is_none() {
        sweep_threads(pid, &patched, false, r);
        return;
    }
    sweep_threads(pid, &patched, true, r);
    // Events queued before the bytes went back: handle them until quiet.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut quiet_since = Instant::now();
    while Instant::now() < deadline && quiet_since.elapsed() < Duration::from_millis(250) {
        // SAFETY: DEBUG_EVENT is plain data filled by the call.
        let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        if unsafe { WaitForDebugEvent(&mut ev, 50) } == 0 {
            continue;
        }
        quiet_since = Instant::now();
        let tid = ev.dwThreadId;
        // SAFETY: the union member read matches dwDebugEventCode.
        let e = unsafe {
            match ev.dwDebugEventCode {
                EXCEPTION_DEBUG_EVENT => {
                    let x = &ev.u.Exception.ExceptionRecord;
                    match x.ExceptionCode {
                        EXCEPTION_BREAKPOINT => TakeoverEvent::Breakpoint {
                            addr: x.ExceptionAddress as u64,
                        },
                        EXCEPTION_SINGLE_STEP => TakeoverEvent::SingleStep,
                        _ => TakeoverEvent::OtherException,
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => TakeoverEvent::ExitProcess,
                CREATE_PROCESS_DEBUG_EVENT => {
                    let i = &ev.u.CreateProcessInfo;
                    for h in [i.hFile, i.hThread, i.hProcess] {
                        if !h.is_null() {
                            CloseHandle(h);
                        }
                    }
                    TakeoverEvent::Other
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    if !ev.u.CreateThread.hThread.is_null() {
                        CloseHandle(ev.u.CreateThread.hThread);
                    }
                    TakeoverEvent::Other
                }
                LOAD_DLL_DEBUG_EVENT => {
                    if !ev.u.LoadDll.hFile.is_null() {
                        CloseHandle(ev.u.LoadDll.hFile);
                    }
                    TakeoverEvent::Other
                }
                _ => TakeoverEvent::Other,
            }
        };
        let reply = takeover_reply(e, &patched);
        let status = match reply {
            TakeoverReply::Rewind(a) => {
                with_thread(tid, |c| c.0.Rip = a);
                r.events_rewound += 1;
                DBG_CONTINUE
            }
            TakeoverReply::ClearTrap => {
                with_thread(tid, |c| c.0.EFlags &= !super::guardian::TRAP_FLAG);
                r.events_stepped += 1;
                DBG_CONTINUE
            }
            TakeoverReply::NotHandled => DBG_EXCEPTION_NOT_HANDLED,
            TakeoverReply::Continue | TakeoverReply::Exited => DBG_CONTINUE,
        };
        // SAFETY: continuing the event we just received.
        unsafe { ContinueDebugEvent(ev.dwProcessId, tid, status) };
        if reply == TakeoverReply::Exited {
            r.notes.push("the target exited during the cleanup".into());
            break;
        }
    }
    // SAFETY: detaching; the target keeps running.
    r.detached = unsafe { DebugActiveProcessStop(pid) } != 0;
    if !r.detached {
        r.notes.push(format!(
            "DebugActiveProcessStop: {} (not attached any more?)",
            std::io::Error::last_os_error()
        ));
    }
}

/// Read, change and write back a (stopped) thread's control registers.
fn with_thread(tid: u32, f: impl FnOnce(&mut AlignedContext)) -> bool {
    // SAFETY: plain OpenThread; the context is aligned and flagged.
    unsafe {
        let h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, tid);
        if h.is_null() {
            return false;
        }
        let h = Handle(h);
        let mut c: AlignedContext = std::mem::zeroed();
        c.0.ContextFlags = CONTEXT_CONTROL_AMD64;
        if GetThreadContext(h.0, &mut c.0) == 0 {
            return false;
        }
        f(&mut c);
        SetThreadContext(h.0, &c.0) != 0
    }
}

/// Suspend each thread of `pid`, repair it ([`thread_fix`]), continue the
/// debug event the dead recorder may have left pending on it, resume it.
fn sweep_threads(pid: u32, patched: &[u64], attached: bool, r: &mut Report) {
    // SAFETY: toolhelp snapshot of threads, walked as documented.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap.is_null() || snap as isize == -1 {
            r.errors.push("listing the target's threads failed".into());
            return;
        }
        let snap = Handle(snap);
        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut ok = Thread32First(snap.0, &mut te) != 0;
        let mut seen = 0u32;
        while ok {
            if te.th32OwnerProcessID == pid {
                seen += 1;
                let tid = te.th32ThreadID;
                let h = OpenThread(
                    THREAD_GET_CONTEXT
                        | THREAD_SET_CONTEXT
                        | THREAD_SUSPEND_RESUME
                        | THREAD_QUERY_LIMITED_INFORMATION,
                    0,
                    tid,
                );
                if !h.is_null() {
                    let h = Handle(h);
                    let suspended = SuspendThread(h.0) != u32::MAX;
                    let mut c: AlignedContext = std::mem::zeroed();
                    c.0.ContextFlags = CONTEXT_CONTROL_AMD64;
                    let mut fix = None;
                    if GetThreadContext(h.0, &mut c.0) != 0 {
                        let f = thread_fix(c.0.Rip, c.0.EFlags, patched);
                        if !f.is_noop() {
                            if let Some(a) = f.rewind_to {
                                c.0.Rip = a;
                            }
                            if f.clear_trap {
                                c.0.EFlags &= !super::guardian::TRAP_FLAG;
                            }
                            if SetThreadContext(h.0, &c.0) == 0 {
                                r.errors
                                    .push(format!("SetThreadContext on thread {tid} failed"));
                            }
                            r.threads.push((tid, f));
                        }
                        fix = Some(f);
                    }
                    if attached {
                        let status = if fix.is_some_and(|f| f.handled()) {
                            DBG_CONTINUE
                        } else {
                            DBG_EXCEPTION_NOT_HANDLED
                        };
                        // Fails (harmlessly) unless the dead recorder had
                        // read an event of this thread and not continued it.
                        if ContinueDebugEvent(pid, tid, status) != 0 {
                            r.notes.push(format!(
                                "thread {tid}: continued a debug event the recorder had left pending"
                            ));
                        }
                    }
                    if suspended {
                        ResumeThread(h.0);
                    }
                }
            }
            ok = Thread32Next(snap.0, &mut te) != 0;
        }
        r.notes
            .push(format!("{seen} threads checked in the target"));
    }
}
