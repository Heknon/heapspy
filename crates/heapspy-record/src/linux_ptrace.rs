//! Linux ptrace fallback recorder (M7a).
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
//! Syscall stops, the least invasive option that needs no symbols and no
//! code changes in the target (a software breakpoint would write `int3`
//! into its text; the spike found no out-of-line arena function to break
//! on anyway).
//!
//! - `PTRACE_SEIZE` every thread with `PTRACE_O_TRACESYSGOOD |
//!   PTRACE_O_TRACECLONE` (new threads are traced automatically), one
//!   `PTRACE_INTERRUPT` to get each into a stop, then `PTRACE_SYSCALL`.
//! - At each syscall-entry stop (`PTRACE_GET_SYSCALL_INFO`, kernel 5.3+):
//!   an `mmap(NULL, 1 MiB, ..., MAP_ANONYMOUS, -1, ...)` is remembered for
//!   the thread. At its exit stop, if it succeeded, the thread is still
//!   stopped in the allocating call chain: its thread state is found with
//!   [`heapspy_reader::cpython::frames::thread_state_for`] and its stack read
//!   with [`heapspy_reader::cpython::frames::read_stack`] through the
//!   non-stopping reader, and the arena sample is added with exact frames.
//!   Every other stop is resumed at once.
//! - The tracer sleeps in `sigtimedwait(SIGCHLD)` with a 100 ms timeout, so
//!   a stop is handled as soon as it is reported and the window is checked
//!   at least every 100 ms.
//! - Group stops (the target was sent `SIGSTOP`) are kept with
//!   `PTRACE_LISTEN`; other signals are re-injected.
//!
//! # Pause per hit
//!
//! Every system call of every thread stops twice (entry and exit), not
//! only `mmap`: seccomp filtering would avoid that but needs code run in
//! the target. Each stop costs two context switches plus the tracer's
//! handling, measured from the stop being reported to the restart and
//! summed into `total_pause_ns`; `probe_hits` counts the stops. An arena
//! hit additionally pays for the stack read (a few `process_vm_readv`
//! calls). Numbers are in `docs/allocation-sampling.md`.
//!
//! # Cleanup
//!
//! On every exit path ([`Drop`] of the tracee set): each running thread is
//! interrupted and every thread detached, re-injecting a pending signal.
//! ptrace binds tracees to the tracer *thread*, so the whole recording runs
//! on the thread that calls [`Recorder::run`]. If heapspy is killed, the
//! kernel detaches the tracees and they continue. No memory of the target
//! is written.
//!
//! # Permissions
//!
//! `CAP_SYS_PTRACE`, or `kernel.yama.ptrace_scope` 0 (1 only for a child).
//! `EPERM` maps to [`Error::PermissionDenied`].

use heapspy_alloc::{Mechanism, Mechanisms};

#[cfg(not(target_os = "linux"))]
use crate::error::Error;
use crate::error::Result;
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

impl Recorder for PtraceRecorder {
    fn name(&self) -> &'static str {
        "linux-ptrace"
    }

    fn mechanisms(&self) -> Mechanisms {
        Mechanisms::of(&[Mechanism::Ptrace])
    }

    fn probe(&self, _opts: &RecordOptions) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Unsupported("ptrace recording needs Linux".into()))
        }
    }

    fn run(&mut self, ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
        #[cfg(target_os = "linux")]
        {
            imp::run(ctx)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = ctx;
            Err(Error::Unsupported("ptrace recording needs Linux".into()))
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::HashMap;
    use std::io;
    use std::time::Instant;

    use heapspy_alloc::{
        EventKind, EventKinds, Mechanism, Mechanisms, Overhead, SampleFlags, SampleInput,
    };
    use heapspy_reader::cpython::frames;

    use crate::common;
    use crate::error::{Error, Result};
    use crate::linux_ebpf::ARENA_SIZE;
    use crate::recorder::{RecordContext, RunOutcome};

    const NR_MMAP: u64 = 9;
    const MAP_ANONYMOUS: u64 = 0x20;
    const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
    const OP_ENTRY: u8 = 1;
    const OP_EXIT: u8 = 2;

    fn errno() -> i32 {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn perm(pid: u32) -> Error {
        Error::PermissionDenied(format!(
            "ptrace(PTRACE_SEIZE) on pid {pid} was refused. Run heapspy as root or with \
             CAP_SYS_PTRACE, and check /proc/sys/kernel/yama/ptrace_scope. The process may \
             already be traced by a debugger."
        ))
    }

    /// What we know about one traced thread.
    #[derive(Default)]
    struct Thread {
        /// We hold it in a stop and must restart it.
        stopped: bool,
        /// A pending arena `mmap`: (length, entry time).
        arena: Option<(u64, u64)>,
    }

    /// The traced threads. Dropping it detaches every one.
    struct Tracees {
        threads: HashMap<i32, Thread>,
    }

    impl Drop for Tracees {
        fn drop(&mut self) {
            for (&tid, t) in &mut self.threads {
                // SAFETY: plain ptrace/waitpid calls on our tracees.
                unsafe {
                    let mut sig = 0;
                    if !t.stopped && libc::ptrace(libc::PTRACE_INTERRUPT, tid, 0, 0) == 0 {
                        loop {
                            let mut st = 0;
                            let r = libc::waitpid(tid, &mut st, libc::__WALL);
                            if r < 0 {
                                if errno() == libc::EINTR {
                                    continue;
                                }
                                break;
                            }
                            if !libc::WIFSTOPPED(st) {
                                break;
                            }
                            let ev = (st >> 16) & 0xff;
                            let s = libc::WSTOPSIG(st);
                            if ev == 0 && s != (libc::SIGTRAP | 0x80) {
                                sig = s;
                            }
                            break;
                        }
                    }
                    libc::ptrace(libc::PTRACE_DETACH, tid, 0, sig as libc::c_long);
                }
            }
        }
    }

    fn list_tids(pid: u32) -> Result<Vec<i32>> {
        let mut v = Vec::new();
        for e in std::fs::read_dir(format!("/proc/{pid}/task"))? {
            if let Some(t) = e?.file_name().to_str().and_then(|s| s.parse().ok()) {
                v.push(t);
            }
        }
        Ok(v)
    }

    /// Restores the thread's signal mask on drop.
    struct SigMask(libc::sigset_t);

    impl SigMask {
        fn block_sigchld() -> SigMask {
            // SAFETY: plain signal mask manipulation on this thread.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGCHLD);
                let mut old: libc::sigset_t = std::mem::zeroed();
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
                SigMask(old)
            }
        }

        /// Wait up to 100 ms for a SIGCHLD.
        fn wait(&self) {
            // SAFETY: as above; the timespec lives for the call.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGCHLD);
                let ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 100_000_000,
                };
                libc::sigtimedwait(&set, std::ptr::null_mut(), &ts);
            }
        }
    }

    impl Drop for SigMask {
        fn drop(&mut self) {
            // SAFETY: restoring the mask saved in `block_sigchld`.
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut());
            }
        }
    }

    fn syscall_info(tid: i32) -> Option<[u8; 88]> {
        let mut b = [0u8; 88];
        // SAFETY: the kernel writes at most `b.len()` bytes into `b`.
        // `as _`: glibc's ptrace takes the request as c_uint, musl's as c_int.
        let r = unsafe { libc::ptrace(PTRACE_GET_SYSCALL_INFO as _, tid, b.len(), b.as_mut_ptr()) };
        (r > 0).then_some(b)
    }

    fn u64_at(b: &[u8], o: usize) -> u64 {
        u64::from_ne_bytes(b[o..o + 8].try_into().unwrap())
    }

    fn resume(tid: i32, sig: i32) {
        // SAFETY: restarting our stopped tracee.
        unsafe {
            libc::ptrace(libc::PTRACE_SYSCALL, tid, 0, sig as libc::c_long);
        }
    }

    pub fn run(ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
        let pid = ctx.target.pid;
        let want = ctx.opts.sampling.events;
        let mut skipped = Vec::new();
        for k in [EventKind::Pool, EventKind::LargeObject] {
            if want.contains(k) {
                skipped.push((k, "the ptrace recorder records arenas only".to_string()));
            }
        }
        common::note_events(&mut ctx.sink, EventKinds::of(&[EventKind::Arena]), &skipped)?;
        let arenas = want.contains(EventKind::Arena);
        let offset = common::monotonic_to_epoch_offset();
        let mask = SigMask::block_sigchld();
        let mut tr = Tracees {
            threads: HashMap::new(),
        };
        let opts = (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACECLONE) as libc::c_long;
        // Seize until a pass finds no new thread.
        loop {
            let new: Vec<i32> = list_tids(pid)?
                .into_iter()
                .filter(|t| !tr.threads.contains_key(t))
                .collect();
            if new.is_empty() {
                break;
            }
            for tid in new {
                // SAFETY: seizing a thread of the target; the guard detaches it.
                unsafe {
                    if libc::ptrace(libc::PTRACE_SEIZE, tid, 0, opts) != 0 {
                        match errno() {
                            libc::ESRCH => continue,
                            libc::EPERM | libc::EACCES => return Err(perm(pid)),
                            e => return Err(Error::Io(io::Error::from_raw_os_error(e))),
                        }
                    }
                    tr.threads.insert(tid, Thread::default());
                    libc::ptrace(libc::PTRACE_INTERRUPT, tid, 0, 0);
                }
            }
        }
        let fo = ctx.target.offsets;
        let rt = ctx.target.runtime.runtime_addr;
        let max_frames = ctx.opts.sampling.max_frames as usize;
        let mut hits = 0u64;
        let mut pause_ns = 0u64;
        let mut exited = false;
        loop {
            if ctx.should_stop() {
                break;
            }
            let mut st = 0;
            // SAFETY: waiting for our tracees.
            let tid = unsafe { libc::waitpid(-1, &mut st, libc::__WALL | libc::WNOHANG) };
            if tid == 0 {
                mask.wait();
                continue;
            }
            if tid < 0 {
                if errno() == libc::ECHILD {
                    exited = true;
                    break;
                }
                continue;
            }
            let t0 = Instant::now();
            if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
                tr.threads.remove(&tid);
                if tr.threads.is_empty() {
                    exited = true;
                    break;
                }
                continue;
            }
            if !libc::WIFSTOPPED(st) {
                continue;
            }
            hits += 1;
            let th = tr.threads.entry(tid).or_default();
            th.stopped = true;
            let sig = libc::WSTOPSIG(st);
            let ev = (st >> 16) & 0xff;
            let mut inject = 0;
            if sig == libc::SIGTRAP | 0x80 {
                if let Some(info) = syscall_info(tid) {
                    match info[0] {
                        OP_ENTRY if arenas => {
                            let nr = u64_at(&info, 24);
                            let a = |i: usize| u64_at(&info, 32 + i * 8);
                            if nr == NR_MMAP
                                && a(0) == 0
                                && a(1) == ARENA_SIZE
                                && a(3) & MAP_ANONYMOUS != 0
                                && a(4) as u32 == u32::MAX
                            {
                                th.arena = Some((a(1), common::monotonic_ns()));
                            }
                        }
                        OP_EXIT => {
                            if let Some((len, ts)) = th.arena.take() {
                                let rval = u64_at(&info, 24) as i64;
                                let is_err = info[32] != 0;
                                if !is_err && rval != 0 {
                                    let s = SampleInput {
                                        timestamp_ns: common::to_epoch(ts, offset),
                                        tid: tid as u64,
                                        kind: EventKind::Arena,
                                        address: rval as u64,
                                        size: len,
                                        weight: len,
                                        native_return_address: None,
                                        flags: SampleFlags::NONE,
                                    };
                                    match frames::thread_state_for(ctx.src, &fo, rt, tid as u64)? {
                                        Some(ts) => {
                                            let stack = frames::read_stack(
                                                ctx.src, &fo, ts.addr, max_frames,
                                            )?;
                                            let mut s = s;
                                            if stack.truncated {
                                                s.flags = s.flags | SampleFlags::STACK_TRUNCATED;
                                            }
                                            ctx.sink.add(&s, &stack.frames, false)?;
                                        }
                                        None => ctx.sink.add_native(&s)?,
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                resume(tid, 0);
            } else if ev == libc::PTRACE_EVENT_STOP {
                if matches!(
                    sig,
                    libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
                ) {
                    // A group stop: keep the thread stopped, as without us.
                    // SAFETY: PTRACE_LISTEN on our tracee in a group stop.
                    unsafe { libc::ptrace(libc::PTRACE_LISTEN, tid, 0, 0) };
                } else {
                    resume(tid, 0);
                }
            } else if ev != 0 {
                // PTRACE_EVENT_CLONE and friends.
                resume(tid, 0);
            } else {
                inject = sig;
                resume(tid, inject);
            }
            let _ = inject;
            th.stopped = false;
            pause_ns += t0.elapsed().as_nanos() as u64;
        }
        drop(tr);
        drop(mask);
        Ok(RunOutcome {
            mechanisms: Mechanisms::of(&[Mechanism::Ptrace]),
            overhead: Overhead {
                samples_taken: 0,
                samples_dropped: 0,
                probe_hits: hits,
                total_pause_ns: pause_ns,
            },
            truncated: exited,
        })
    }
}
