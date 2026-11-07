//! Win32 glue of the Windows recorder: `SeDebugPrivilege`, the ETW kernel
//! session for `VirtualAlloc`, and the debugger driving
//! [`super::debug::Machine`]. Compiled on Windows only; the logic it
//! drives is tested on every platform.

use std::collections::HashMap;
use std::sync::mpsc::Sender;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, ERROR_ACCESS_DENIED,
    ERROR_ALREADY_EXISTS, ERROR_SUCCESS, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE, LUID,
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
    CloseTrace, ControlTraceW, OpenTraceW, PageFaultGuid, ProcessTrace, StartTraceW,
    SystemTraceControlGuid, CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_FLAG_VIRTUAL_ALLOC, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, KERNEL_LOGGER_NAMEW, PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use super::clock::filetime_to_unix_ns;
use super::debug::{DebugIo, Event, Machine, Regs, Reply};
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
    control: CONTROLTRACE_HANDLE,
    trace: PROCESSTRACE_HANDLE,
    thread: Option<std::thread::JoinHandle<()>>,
    ctx: *mut EtwContext,
    /// `EventsLost + RealTimeBuffersLost` at stop.
    pub lost: u64,
}

fn props_buffer() -> Vec<u8> {
    let name_bytes = 1024 * 2;
    let size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes;
    let mut v = vec![0u8; size];
    // SAFETY: the buffer is large enough and zeroed.
    let p = unsafe { &mut *(v.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
    p.Wnode.BufferSize = size as u32;
    p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p.Wnode.Guid = SystemTraceControlGuid;
    p.Wnode.ClientContext = 1; // QPC session clock; consumers get FILETIME
    p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p.EnableFlags = EVENT_TRACE_FLAG_VIRTUAL_ALLOC;
    p.BufferSize = 64;
    p.MinimumBuffers = 16;
    p.MaximumBuffers = 64;
    p.FlushTimer = 1;
    p.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    v
}

impl EtwSession {
    /// Start the "NT Kernel Logger" with VirtualAlloc events and consume
    /// it on a thread. Errors: access denied (not elevated), or the kernel
    /// logger already in use by another tool.
    pub fn start(pid: u32, arena_size: u64, tx: Sender<EtwAlloc>) -> Result<EtwSession> {
        let mut props = props_buffer();
        let mut control = CONTROLTRACE_HANDLE { Value: 0 };
        // SAFETY: props is a properly sized EVENT_TRACE_PROPERTIES block.
        let e = unsafe {
            StartTraceW(
                &mut control,
                KERNEL_LOGGER_NAMEW,
                props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            )
        };
        match e {
            ERROR_SUCCESS => {}
            ERROR_ACCESS_DENIED => {
                return Err(Error::PermissionDenied(
                    "starting the ETW kernel session was refused: run heapspy from an elevated prompt".into(),
                ))
            }
            ERROR_ALREADY_EXISTS => {
                return Err(Error::Unsupported(
                    "the NT Kernel Logger ETW session is in use by another tool (xperf, WPR, Process Monitor); stop it and retry".into(),
                ))
            }
            e => return Err(Error::Io(std::io::Error::from_raw_os_error(e as i32))),
        }
        let ctx = Box::into_raw(Box::new(EtwContext {
            pid,
            arena_size,
            tx,
        }));
        let mut name: Vec<u16> = "NT Kernel Logger\0".encode_utf16().collect();
        // SAFETY: zeroed EVENT_TRACE_LOGFILEW, filled as documented.
        let trace = unsafe {
            let mut lf: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            lf.LoggerName = name.as_mut_ptr();
            lf.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            lf.Anonymous2.EventRecordCallback = Some(on_event);
            lf.Context = ctx.cast();
            OpenTraceW(&mut lf)
        };
        drop(props);
        let mut s = EtwSession {
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
            let mut props = props_buffer();
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
struct AlignedContext(CONTEXT);

/// What the debugger produced: arena entries waiting for their return,
/// and finished samples for the main loop.
pub struct DebugTarget<'a> {
    pid: u32,
    process: Handle,
    threads: HashMap<u32, HANDLE>,
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
        let mut d = Debugger {
            io: DebugTarget {
                pid,
                process,
                threads: HashMap::new(),
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
