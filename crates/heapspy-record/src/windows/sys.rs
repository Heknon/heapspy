//! Win32 glue of the Windows recorder: `SeDebugPrivilege`, the ETW kernel
//! session for `VirtualAlloc`, and the debugger driving
//! [`super::debug::Machine`]. Compiled on Windows only; the logic it
//! drives is tested on every platform.

use std::collections::HashMap;
use std::sync::mpsc::Sender;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_ACCESS_DENIED,
    ERROR_ALREADY_EXISTS, ERROR_INVALID_PARAMETER, ERROR_NO_SYSTEM_RESOURCES, ERROR_SUCCESS,
    ERROR_WMI_INSTANCE_NOT_FOUND, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE, LUID,
    STILL_ACTIVE,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    FlushInstructionCache, GetThreadContext, ReadProcessMemory, SetThreadContext,
    WaitForDebugEvent, WriteProcessMemory, CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_INTEGER_AMD64,
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, OpenTraceW, PageFaultGuid, ProcessTrace, QueryAllTracesW,
    StartTraceW, SystemTraceControlGuid, TraceSetInformation, TraceSystemTraceEnableFlagsInfo,
    CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_VIRTUAL_ALLOC,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    EVENT_TRACE_SYSTEM_LOGGER_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use super::clock::filetime_to_unix_ns;
use super::debug::{DebugIo, Event, Machine, Regs, Reply, INT3};
use super::guardian::{self, Msg};
use super::guardian_sys::Link;
use super::live::{access_error, Handle};
use crate::error::{Error, Result};

/// Enable `SeDebugPrivilege` in this process's token if it holds it
/// (an elevated prompt). Failure is silent: opening the target reports it.
pub fn enable_debug_privilege() {
    // SAFETY: token query and adjustment on our own process.
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut tok,
        ) == 0
        {
            return;
        }
        let tok = Handle(tok);
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(std::ptr::null(), SE_DEBUG_NAME, &mut luid) == 0 {
            return;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(tok.0, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut());
    }
}

// ---- ETW ------------------------------------------------------------------

/// One `PageFault_VirtualAlloc` event of the target.
#[derive(Clone, Copy, Debug)]
pub struct EtwAlloc {
    pub ts_ns: u64,
    pub tid: u32,
    pub addr: u64,
    pub size: u64,
}

/// `PageFault_VirtualAlloc` (MOF class `PageFault_VirtualAlloc`, opcode 98):
/// `BaseAddress`, `RegionSize` (pointers), `ProcessId`, `Flags` (u32).
const OPCODE_VIRTUAL_ALLOC: u8 = 98;
const MEM_COMMIT_RESERVE: u32 = 0x3000;

struct EtwContext {
    pid: u32,
    arena_size: u64,
    tx: Sender<EtwAlloc>,
}

fn same_guid(a: &windows_sys::core::GUID, b: &windows_sys::core::GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    // SAFETY: ETW passes a valid record; UserContext is our EtwContext,
    // alive until ProcessTrace returns.
    unsafe {
        let r = &*rec;
        let h = &r.EventHeader;
        if !same_guid(&h.ProviderId, &PageFaultGuid)
            || h.EventDescriptor.Opcode != OPCODE_VIRTUAL_ALLOC
        {
            return;
        }
        let ctx = &*(r.UserContext as *const EtwContext);
        if (r.UserDataLength as usize) < 24 || r.UserData.is_null() {
            return;
        }
        let d = std::slice::from_raw_parts(r.UserData as *const u8, r.UserDataLength as usize);
        let base = u64::from_le_bytes(d[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(d[8..16].try_into().unwrap());
        let pid = u32::from_le_bytes(d[16..20].try_into().unwrap());
        let flags = u32::from_le_bytes(d[20..24].try_into().unwrap());
        if pid != ctx.pid
            || size != ctx.arena_size
            || flags & MEM_COMMIT_RESERVE != MEM_COMMIT_RESERVE
        {
            return;
        }
        let _ = ctx.tx.send(EtwAlloc {
            ts_ns: filetime_to_unix_ns(h.TimeStamp as u64),
            tid: h.ThreadId,
            addr: base,
            size,
        });
    }
}

/// The kernel session; stopped on drop.
pub struct EtwSession {
    /// The session's name: `heapspy-<pid>`, or `NT Kernel Logger` where a
    /// system logger session cannot be started.
    pub name: String,
    control: CONTROLTRACE_HANDLE,
    trace: PROCESSTRACE_HANDLE,
    thread: Option<std::thread::JoinHandle<()>>,
    ctx: *mut EtwContext,
    /// `EventsLost + RealTimeBuffersLost` at stop.
    pub lost: u64,
}

fn props_buffer(system_logger: bool) -> Vec<u8> {
    let name_bytes = 1024 * 2;
    let size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes;
    let mut v = vec![0u8; size];
    // SAFETY: the buffer is large enough and zeroed.
    let p = unsafe { &mut *(v.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
    p.Wnode.BufferSize = size as u32;
    p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p.Wnode.ClientContext = 1; // QPC session clock; consumers get FILETIME
    if system_logger {
        // Any GUID but SystemTraceControlGuid names a new session; the
        // system logger mode makes it receive kernel events.
        p.Wnode.Guid = session_guid();
        p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    } else {
        p.Wnode.Guid = SystemTraceControlGuid;
        p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    }
    p.EnableFlags = EVENT_TRACE_FLAG_VIRTUAL_ALLOC;
    p.BufferSize = 64;
    p.MinimumBuffers = 16;
    p.MaximumBuffers = 64;
    p.FlushTimer = 1;
    p.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    v
}

/// A bare properties block for control calls (stop, query): sizes and
/// name offsets only. Passing a start block (a GUID, kernel flags) to stop
/// a system logger session fails with ERROR_INVALID_PARAMETER.
fn control_buffer() -> Vec<u8> {
    let head = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let names = 1024 * 2;
    let size = head + 2 * names;
    let mut v = vec![0u8; size];
    // SAFETY: the buffer is large enough and zeroed.
    let p = unsafe { &mut *(v.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
    p.Wnode.BufferSize = size as u32;
    p.LoggerNameOffset = head as u32;
    p.LogFileNameOffset = (head + names) as u32;
    v
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A GUID for one session: unique enough from the pid and the clock.
fn session_guid() -> windows_sys::core::GUID {
    let t = crate::session::now_ns();
    windows_sys::core::GUID {
        data1: std::process::id(),
        data2: (t >> 48) as u16,
        data3: 0x4000 | ((t >> 32) as u16 & 0x0fff),
        data4: (t as u32 as u64 | 0x8000_0000_0000_0000 | (0x6865_6170u64 << 32)).to_be_bytes(),
    }
}

fn start_trace(name: &str, system_logger: bool, control: &mut CONTROLTRACE_HANDLE) -> u32 {
    let mut props = props_buffer(system_logger);
    let w = wide(name);
    // SAFETY: props is a properly sized EVENT_TRACE_PROPERTIES block.
    let e = unsafe {
        StartTraceW(
            control,
            w.as_ptr(),
            props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
        )
    };
    if e == ERROR_SUCCESS && system_logger {
        // The documented way to select kernel events of a system logger:
        // the group mask, whose first word is the classic EnableFlags.
        let mut mask = [0u32; 8];
        mask[0] = EVENT_TRACE_FLAG_VIRTUAL_ALLOC;
        // SAFETY: an 8-word mask, as TraceSystemTraceEnableFlagsInfo takes.
        unsafe {
            TraceSetInformation(
                *control,
                TraceSystemTraceEnableFlagsInfo,
                mask.as_ptr().cast(),
                std::mem::size_of_val(&mask) as u32,
            )
        };
    }
    e
}

/// What stopping a session by name did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopSession {
    Stopped,
    NotFound,
    Failed(u32),
}

/// Stop the ETW session `name`.
pub fn stop_session(name: &str) -> StopSession {
    let mut props = control_buffer();
    let w = wide(name);
    // SAFETY: stopping by name with a sized properties buffer.
    let e = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            w.as_ptr(),
            props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        )
    };
    match e {
        ERROR_SUCCESS => StopSession::Stopped,
        ERROR_WMI_INSTANCE_NOT_FOUND => StopSession::NotFound,
        e => StopSession::Failed(e),
    }
}

/// Names of the running ETW sessions.
pub fn list_sessions() -> Vec<String> {
    const N: usize = 64;
    let mut bufs: Vec<Vec<u8>> = (0..N).map(|_| control_buffer()).collect();
    let mut ptrs: Vec<*mut EVENT_TRACE_PROPERTIES> =
        bufs.iter_mut().map(|b| b.as_mut_ptr().cast()).collect();
    let mut count = 0u32;
    // SAFETY: N sized property blocks with their name offsets set.
    let e = unsafe { QueryAllTracesW(ptrs.as_mut_ptr(), N as u32, &mut count) };
    if e != ERROR_SUCCESS && e != windows_sys::Win32::Foundation::ERROR_MORE_DATA {
        return Vec::new();
    }
    bufs.iter()
        .take(count as usize)
        .filter_map(|b| {
            // SAFETY: filled by QueryAllTracesW; the name is NUL-terminated
            // within the buffer.
            let p = unsafe { &*(b.as_ptr() as *const EVENT_TRACE_PROPERTIES) };
            let off = p.LoggerNameOffset as usize;
            if off == 0 || off >= b.len() {
                return None;
            }
            let w: Vec<u16> = b[off..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            Some(String::from_utf16_lossy(&w))
        })
        .collect()
}

/// `pid` is a running heapspy recorder (or this same program).
fn is_live_heapspy(pid: u32) -> bool {
    // SAFETY: plain OpenProcess / queries on the handle.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            // Access denied: something runs there that we cannot see;
            // leave its session alone.
            return GetLastError() == ERROR_ACCESS_DENIED;
        }
        let h = Handle(h);
        let mut code = 0u32;
        if GetExitCodeProcess(h.0, &mut code) != 0 && code != STILL_ACTIVE as u32 {
            return false;
        }
        let mut buf = [0u16; 1024];
        let mut n = buf.len() as u32;
        if QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) == 0 {
            return true;
        }
        let image = String::from_utf16_lossy(&buf[..n as usize]);
        let me = std::env::current_exe().ok();
        let stem = me
            .as_deref()
            .and_then(|p| p.file_stem())
            .map(|s| s.to_string_lossy().into_owned());
        guardian::is_heapspy_image(&image, stem.as_deref())
    }
}

/// Stop the `heapspy-<pid>` sessions of recorders that are gone. Returns
/// their names. Sessions of any other name are never touched.
pub fn stop_stale_sessions() -> Vec<String> {
    let names = list_sessions();
    guardian::stale_sessions(&names, std::process::id(), is_live_heapspy)
        .into_iter()
        .filter(|n| stop_session(n) == StopSession::Stopped)
        .map(String::from)
        .collect()
}

impl EtwSession {
    /// Start heapspy's own kernel session, `heapspy-<this pid>`, in
    /// system logger mode (Windows 8 / Server 2012 and later) with
    /// VirtualAlloc events, and consume it on a thread. Sessions of dead
    /// heapspy recorders are stopped first. Where the system logger mode is
    /// refused (older Windows), the classic "NT Kernel Logger" is used.
    /// Errors: access denied (not elevated), or a conflicting session,
    /// named in the message.
    pub fn start(pid: u32, arena_size: u64, tx: Sender<EtwAlloc>) -> Result<EtwSession> {
        for n in stop_stale_sessions() {
            eprintln!(
                "heapspy: stopped ETW session {n} left by a heapspy that is no longer running"
            );
        }
        let own = guardian::session_name(std::process::id());
        let mut name = own.clone();
        let mut control = CONTROLTRACE_HANDLE { Value: 0 };
        let mut e = start_trace(&name, true, &mut control);
        if e == ERROR_INVALID_PARAMETER {
            name = "NT Kernel Logger".into();
            e = start_trace(&name, false, &mut control);
        }
        match e {
            ERROR_SUCCESS => {}
            ERROR_ACCESS_DENIED => {
                return Err(Error::PermissionDenied(
                    "starting the ETW kernel session was refused: run heapspy from an elevated prompt".into(),
                ))
            }
            ERROR_ALREADY_EXISTS if name == own => {
                return Err(Error::Unsupported(format!(
                    "the ETW session {name} already exists and belongs to a running process; stop it (logman stop {name} -ets) and retry"
                )))
            }
            ERROR_ALREADY_EXISTS => {
                return Err(Error::Unsupported(format!(
                    "the ETW session \"{name}\" is in use by another tool (xperf, WPR, Process Monitor); stop it and retry"
                )))
            }
            ERROR_NO_SYSTEM_RESOURCES => {
                return Err(Error::Unsupported(format!(
                    "no ETW system logger session is free for {name} (other tools hold them all; see logman query -ets)"
                )))
            }
            e => return Err(Error::Io(std::io::Error::from_raw_os_error(e as i32))),
        }
        let ctx = Box::into_raw(Box::new(EtwContext {
            pid,
            arena_size,
            tx,
        }));
        let mut wname = wide(&name);
        // SAFETY: zeroed EVENT_TRACE_LOGFILEW, filled as documented.
        let trace = unsafe {
            let mut lf: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            lf.LoggerName = wname.as_mut_ptr();
            lf.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            lf.Anonymous2.EventRecordCallback = Some(on_event);
            lf.Context = ctx.cast();
            OpenTraceW(&mut lf)
        };
        let mut s = EtwSession {
            name,
            control,
            trace,
            thread: None,
            ctx,
            lost: 0,
        };
        if trace.Value == u64::MAX {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        let h = trace.Value;
        s.thread = Some(std::thread::spawn(move || {
            let t = PROCESSTRACE_HANDLE { Value: h };
            // SAFETY: blocks until the session stops or CloseTrace.
            unsafe { ProcessTrace(&t, 1, std::ptr::null(), std::ptr::null()) };
        }));
        Ok(s)
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        // SAFETY: stopping the session we started, then joining the consumer
        // before freeing the context it uses.
        unsafe {
            let mut props = control_buffer();
            ControlTraceW(
                self.control,
                std::ptr::null(),
                props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_CONTROL_STOP,
            );
            let p = &*(props.as_ptr() as *const EVENT_TRACE_PROPERTIES);
            self.lost = p.EventsLost as u64 + p.RealTimeBuffersLost as u64;
            CloseTrace(self.trace);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            drop(Box::from_raw(self.ctx));
        }
    }
}

// ---- debugger -------------------------------------------------------------

#[repr(C, align(16))]
pub(super) struct AlignedContext(pub CONTEXT);

/// What the debugger produced: arena entries waiting for their return,
/// and finished samples for the main loop.
pub struct DebugTarget<'a> {
    pid: u32,
    process: Handle,
    threads: HashMap<u32, HANDLE>,
    /// Told of every byte before it is patched and after it is restored.
    guardian: Option<&'a Link>,
    /// Called at an arena entry with the thread id; reads the stack.
    pub on_entry: Box<dyn FnMut(u32, u64, u64) + 'a>,
    /// Called at the matching return with the arena address.
    pub on_exit: Box<dyn FnMut(u32, u64) + 'a>,
}

impl DebugTarget<'_> {
    fn context(&self, tid: u32) -> Option<AlignedContext> {
        let h = *self.threads.get(&tid)?;
        // SAFETY: zeroed CONTEXT with its flags set; aligned to 16.
        unsafe {
            let mut c: AlignedContext = std::mem::zeroed();
            c.0.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
            (GetThreadContext(h, &mut c.0) != 0).then_some(c)
        }
    }

    fn write_raw(&mut self, addr: u64, b: u8) -> bool {
        let mut n = 0usize;
        // SAFETY: one byte from `b`. Code pages are copy-on-write; the
        // kernel makes them writable for a debugger with PROCESS_VM_OPERATION.
        unsafe {
            let ok = WriteProcessMemory(
                self.process.0,
                addr as *const _,
                (&b as *const u8).cast(),
                1,
                &mut n,
            );
            FlushInstructionCache(self.process.0, addr as *const _, 1);
            ok != 0 && n == 1
        }
    }

    fn set_context(&self, tid: u32, c: &AlignedContext) -> bool {
        let Some(&h) = self.threads.get(&tid) else {
            return false;
        };
        // SAFETY: as above.
        unsafe { SetThreadContext(h, &c.0) != 0 }
    }
}

impl DebugIo for DebugTarget<'_> {
    fn read_byte(&mut self, addr: u64) -> Option<u8> {
        let mut b = 0u8;
        let mut n = 0usize;
        // SAFETY: one byte into `b`.
        let ok = unsafe {
            ReadProcessMemory(
                self.process.0,
                addr as *const _,
                (&mut b as *mut u8).cast(),
                1,
                &mut n,
            )
        };
        (ok != 0 && n == 1).then_some(b)
    }

    fn write_byte(&mut self, addr: u64, b: u8) -> bool {
        // The guardian learns of a patch before it is written, and of a
        // restore after, so it never misses an int3 of ours.
        if let (Some(g), INT3) = (self.guardian, b) {
            match self.read_byte(addr) {
                Some(orig) if orig != INT3 => g.send(&Msg::Patch { addr, orig }),
                _ => {}
            }
        }
        let ok = self.write_raw(addr, b);
        if let (Some(g), true) = (self.guardian, ok && b != INT3) {
            g.send(&Msg::Unpatch(addr));
        }
        ok
    }

    fn read_u64(&mut self, addr: u64) -> Option<u64> {
        let mut v = 0u64;
        let mut n = 0usize;
        // SAFETY: eight bytes into `v`.
        let ok = unsafe {
            ReadProcessMemory(
                self.process.0,
                addr as *const _,
                (&mut v as *mut u64).cast(),
                8,
                &mut n,
            )
        };
        (ok != 0 && n == 8).then_some(v)
    }

    fn regs(&mut self, tid: u32) -> Option<Regs> {
        let c = self.context(tid)?.0;
        Some(Regs {
            rip: c.Rip,
            rsp: c.Rsp,
            rax: c.Rax,
            rcx: c.Rcx,
            rdx: c.Rdx,
            r8: c.R8,
        })
    }

    fn set_rip(&mut self, tid: u32, rip: u64) -> bool {
        let Some(mut c) = self.context(tid) else {
            return false;
        };
        c.0.Rip = rip;
        self.set_context(tid, &c)
    }

    fn set_trap(&mut self, tid: u32, on: bool) -> bool {
        let Some(mut c) = self.context(tid) else {
            return false;
        };
        if on {
            c.0.EFlags |= 0x100;
        } else {
            c.0.EFlags &= !0x100;
        }
        self.set_context(tid, &c)
    }

    fn arena_entry(&mut self, tid: u32, size: u64, ret: u64) {
        (self.on_entry)(tid, size, ret)
    }

    fn arena_exit(&mut self, tid: u32, addr: u64) {
        (self.on_exit)(tid, addr)
    }
}

/// An attached debugger with its breakpoint machine. Detaches on drop,
/// after disarming, so even a panic leaves no `int3` in the target.
pub struct Debugger<'a> {
    pub io: DebugTarget<'a>,
    pub machine: Machine,
    attached: bool,
}

impl<'a> Debugger<'a> {
    pub fn attach(
        pid: u32,
        machine: Machine,
        guardian: Option<&'a Link>,
        on_entry: Box<dyn FnMut(u32, u64, u64) + 'a>,
        on_exit: Box<dyn FnMut(u32, u64) + 'a>,
    ) -> Result<Debugger<'a>> {
        enable_debug_privilege();
        // SAFETY: plain OpenProcess.
        let h = unsafe {
            OpenProcess(
                PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION
                    | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if h.is_null() {
            return Err(access_error(pid, "OpenProcess for writing breakpoints"));
        }
        let process = Handle(h);
        // SAFETY: attaching as a debugger; kill-on-exit off right away so the
        // target survives heapspy exiting or crashing.
        unsafe {
            if DebugActiveProcess(pid) == 0 {
                let e = GetLastError();
                return Err(if e == ERROR_ACCESS_DENIED {
                    access_error(pid, "DebugActiveProcess")
                } else {
                    Error::Io(std::io::Error::from_raw_os_error(e as i32))
                });
            }
            DebugSetProcessKillOnExit(0);
        }
        // From here on the guardian holds the debug object too: if heapspy
        // dies, the target stays attached to it and the guardian takes over.
        if let Some(g) = guardian {
            g.share_debug_object();
        }
        let mut d = Debugger {
            io: DebugTarget {
                pid,
                process,
                threads: HashMap::new(),
                guardian,
                on_entry,
                on_exit,
            },
            machine,
            attached: true,
        };
        // The attach sends a create event per existing thread, then the
        // attach breakpoint; collect the thread handles before arming.
        while let Some(true) = d.pump(200) {
            if d.machine.attach_break_seen() {
                break;
            }
        }
        if !d.machine.start(&mut d.io) {
            return Err(Error::Unsupported(
                "could not set a breakpoint on VirtualAlloc (another debugger's breakpoint is there?)".into(),
            ));
        }
        Ok(d)
    }

    /// Wait up to `ms` for one debug event, hand it to the machine,
    /// continue it. `None` on timeout, `Some(false)` when the process exited.
    pub fn pump(&mut self, ms: u32) -> Option<bool> {
        // SAFETY: DEBUG_EVENT is plain data filled by the call.
        let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { WaitForDebugEvent(&mut ev, ms) } == 0 {
            return None;
        }
        let tid = ev.dwThreadId;
        // SAFETY: the union member read matches dwDebugEventCode.
        let e = unsafe {
            match ev.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    self.io.threads.insert(tid, ev.u.CreateProcessInfo.hThread);
                    if !ev.u.CreateProcessInfo.hFile.is_null() {
                        CloseHandle(ev.u.CreateProcessInfo.hFile);
                    }
                    Event::Other
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    self.io.threads.insert(tid, ev.u.CreateThread.hThread);
                    Event::Other
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    self.io.threads.remove(&tid);
                    Event::Other
                }
                LOAD_DLL_DEBUG_EVENT => {
                    if !ev.u.LoadDll.hFile.is_null() {
                        CloseHandle(ev.u.LoadDll.hFile);
                    }
                    Event::Other
                }
                EXIT_PROCESS_DEBUG_EVENT => Event::ExitProcess,
                EXCEPTION_DEBUG_EVENT => {
                    let r = &ev.u.Exception.ExceptionRecord;
                    match r.ExceptionCode {
                        EXCEPTION_BREAKPOINT => Event::Breakpoint {
                            tid,
                            addr: r.ExceptionAddress as u64,
                        },
                        EXCEPTION_SINGLE_STEP => Event::SingleStep { tid },
                        _ => Event::Exception { tid },
                    }
                }
                _ => Event::Other,
            }
        };
        let reply = self.machine.handle(&mut self.io, e);
        let status = match reply {
            Reply::NotHandled => DBG_EXCEPTION_NOT_HANDLED,
            _ => DBG_CONTINUE,
        };
        // SAFETY: continuing the event we just received.
        unsafe { ContinueDebugEvent(ev.dwProcessId, tid, status) };
        Some(reply != Reply::Exited)
    }

    /// Disarm, drain late events, detach. Idempotent.
    pub fn detach(&mut self) {
        if !self.attached {
            return;
        }
        self.machine.disarm(&mut self.io);
        // Hits already queued on removed breakpoints are rewound, and the
        // single steps of threads that were stepping over one are handled.
        // Wait for those steps (a stepping thread may not have run yet),
        // but not forever.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match self.pump(50) {
                Some(true) => {}
                Some(false) => break,
                None => {
                    if !self.machine.steps_pending() || std::time::Instant::now() >= deadline {
                        break;
                    }
                }
            }
        }
        // SAFETY: detaching; the target keeps running.
        unsafe { DebugActiveProcessStop(self.io.pid) };
        self.attached = false;
    }
}

impl Drop for Debugger<'_> {
    fn drop(&mut self) {
        self.detach();
    }
}
