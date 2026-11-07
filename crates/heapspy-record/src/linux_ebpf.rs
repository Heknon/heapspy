//! Linux eBPF recorder (M7a).
//!
//! Design: `docs/allocation-sampling.md`, "Linux: eBPF". The kernel side is
//! `bpf/heapspy.bpf.c`; [`abi`] mirrors its structs, `sys` loads and
//! attaches it.
//!
//! # Probes
//!
//! - **Arenas.** Raw tracepoints `sys_enter` / `sys_exit`, filtered in the
//!   kernel to the target's tgid and to `mmap(NULL, arena_size, ...,
//!   MAP_ANONYMOUS, -1, ...)`; enter and exit are paired per tid. Raw
//!   tracepoints need neither symbols nor tracefs. Kind
//!   [`heapspy_alloc::EventKind::Arena`], weight = size. No native return
//!   address (the syscall's user IP is inside libc's `mmap`).
//! - **Pools.** Not recorded: no build tested has an out-of-line
//!   pool-carving function (it is inlined into `pymalloc_alloc`). Asked
//!   for, they are listed in meta `heapspy.skipped_events`.
//! - **Large objects.** Uprobes on `_PyMem_RawMalloc`, `_PyMem_RawCalloc`
//!   and `_PyMem_RawRealloc` when the interpreter's `.symtab` has them
//!   (their first argument is the allocator context, so the size is the
//!   second or third), otherwise on libc `malloc`, `calloc` and `realloc`.
//!   pymalloc hands every request above 512 bytes to the raw allocator, so
//!   either set sees every large object. `_PyObject_Malloc` is
//!   deliberately *not* probed: it calls the raw allocator, and probing
//!   both layers nests the probes. The kernel filters `size > 512` and
//!   applies the byte-interval sampler: a per-CPU countdown of bytes,
//!   refilled from 256 quantiles of an exponential distribution with mean
//!   `byte_interval` ([`abi::thresholds`]); interval 0 keeps every call.
//!   The uretprobe takes the returned pointer. Kind `LargeObject`, weight
//!   [`heapspy_alloc::sampled_weight`]. A `realloc` that moves is a new
//!   sample at the new pointer.
//!
//! **Pairing entry and return.** A sampled entry is stored under (tid,
//! stack pointer at entry); the uretprobe looks it up under (tid, its stack
//! pointer − 8), because `ret` popped the return address. Keying by tid
//! alone loses samples whenever probed calls nest (glibc `realloc(NULL)`
//! calls `malloc`, and the spike probed `_PyObject_Malloc` on top of the
//! raw functions): the inner entry overwrites the outer one and the counts
//! of entries and returns disagree in blocks, which is what the spike saw
//! on 6.18. Entries whose return never comes (longjmp) age out of an LRU
//! map; overwritten entries are counted (`orphans`, as dropped samples).
//!
//! # Python stack in the kernel
//!
//! At each kept event the program finds the thread's `PyThreadState` (LRU
//! cache tid → tstate, checked against `native_thread_id`, else a walk of
//! at most 4 interpreters × 256 threads) and follows the frame chain like
//! [`heapspy_reader::cpython::frames::read_stack`]: `current_frame` (through
//! `cframe` on 3.12), skip `owner >= owner_first_shim`, `f_executable`
//! masked `& !3` on 3.14 (tagged ints skipped), `instr_ptr`, `previous`.
//! It follows at most 256 links and copies at most [`abi::KMAX_FRAMES`]
//! (128) frames: `--max-frames` above 128 is clamped and such samples are
//! marked `STACK_TRUNCATED`. For each frame it sends the code pointer, the
//! instruction pointer and the object's type; user space keeps frames whose
//! type is `code` and whose code object is not CPython's shim code (the
//! `tp_name` and `co_flags` tests of `read_stack`, see
//! [`heapspy_reader::cpython::frames`], "Shim frames") and computes the
//! instruction offset. The `_Py_InitCleanup` frame of 3.13 and 3.14 is
//! told apart in user space only: the kernel program copies it like any
//! other frame. A thread with no thread state gives a sample without
//! frames (`NO_THREAD_STATE`).
//!
//! # User space
//!
//! A BPF ring buffer (16 MiB, events sized to their frames), drained every 10 ms; reservation failures
//! are counted in the kernel and reported as `samples_dropped`. Event times
//! are `bpf_ktime_get_ns` (`CLOCK_MONOTONIC`), converted with
//! `CLOCK_REALTIME − CLOCK_MONOTONIC` measured at start; the writer sorts
//! samples by time. eBPF does not stop the target: `total_pause_ns` is 0.
//! `probe_hits` counts every probe firing for the target, sampled or not.
//!
//! # Cleanup
//!
//! Every map, program and attachment is a file descriptor: uprobes are
//! perf events opened for the target pid, tracepoints are raw tracepoint
//! links. Nothing is registered in tracefs, so whatever ends heapspy (Ctrl-C,
//! an error, a panic, SIGKILL) the kernel removes the probes when the
//! descriptors close. Uprobes do change the target's code pages (an `int3`
//! in the kernel's copy-on-write page), and the kernel restores them when
//! the last probe goes.
//!
//! # Build and permissions
//!
//! - The BPF object `bpf/heapspy.bpf.o` is committed and embedded with
//!   `include_bytes!`, so `cargo build` needs no clang (release wheels in
//!   manylinux containers included). `bpf/build.sh` rebuilds it with clang
//!   (18 tested) and `bpf/build.sh --check` verifies the committed copy.
//!   The loader is ~300 lines on top of the `object` crate; no libbpf, no
//!   BTF, no CO-RE (the program reads only user memory, laid out by
//!   offsets passed in a map, and `pt_regs`, which is stable on x86_64).
//! - x86_64 only (register offsets); other architectures report
//!   `Unsupported` and `auto` falls back to ptrace.
//! - Root, or `CAP_BPF` + `CAP_PERFMON` (and `CAP_SYS_PTRACE` for the
//!   reader), kernel 5.8+ (ring buffer; bounded loops need 5.3). A missing
//!   capability is `PermissionDenied` and a missing feature `Unsupported`,
//!   so `auto` falls back to ptrace.

pub mod abi;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod sys;

use heapspy_alloc::{Mechanism, Mechanisms};

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
use crate::error::Error;
use crate::error::Result;
use crate::options::RecordOptions;
use crate::recorder::{RecordContext, Recorder, RunOutcome};

/// Size of a pymalloc arena (3.10+).
pub const ARENA_SIZE: u64 = 1 << 20;
/// Allocations above this are large objects (pymalloc's `SMALL_REQUEST_THRESHOLD`).
pub const LARGE_THRESHOLD: u64 = 512;

/// Linux eBPF recorder. See the module docs.
#[derive(Debug, Default)]
pub struct EbpfRecorder {}

impl EbpfRecorder {
    pub fn new() -> Self {
        Self {}
    }
}

impl Recorder for EbpfRecorder {
    fn name(&self) -> &'static str {
        "linux-ebpf"
    }

    fn mechanisms(&self) -> Mechanisms {
        Mechanisms::of(&[Mechanism::Ebpf])
    }

    fn probe(&self, _opts: &RecordOptions) -> Result<()> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            sys::check_bpf()
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            Err(Error::Unsupported(
                "eBPF recording needs Linux on x86_64".into(),
            ))
        }
    }

    fn run(&mut self, ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            imp::run(ctx)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = ctx;
            Err(Error::Unsupported(
                "eBPF recording needs Linux on x86_64".into(),
            ))
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use std::time::Duration;

    use heapspy_alloc::{
        sampled_weight, EventKind, EventKinds, Mechanism, Mechanisms, Overhead, SampleFlags,
        SampleInput,
    };
    use heapspy_reader::Module;

    use super::abi::{self, Config, Event};
    use super::sys::{self, Fd};
    use super::{ARENA_SIZE, LARGE_THRESHOLD};
    use crate::common::{self, CodeTypes};
    use crate::error::{Error, Result};
    use crate::recorder::{RecordContext, RunOutcome};

    /// Where the large-object probes go.
    struct Site {
        path: String,
        offset: u64,
        /// Address of the probe in the target (after any `endbr64`).
        addr: u64,
        section: &'static str,
        /// Which function, for the session program's cookie.
        variant: u64,
    }

    const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

    const RAW: [(&str, &str); 3] = [
        ("_PyMem_RawMalloc", "uprobe/malloc_ctx"),
        ("_PyMem_RawCalloc", "uprobe/calloc_ctx"),
        ("_PyMem_RawRealloc", "uprobe/realloc_ctx"),
    ];
    const LIBC: [(&str, &str); 3] = [
        ("malloc", "uprobe/malloc"),
        ("calloc", "uprobe/calloc"),
        ("realloc", "uprobe/realloc"),
    ];

    /// File path (through `/proc/<pid>/root`) and file offset of a mapped address.
    fn file_offset(pid: u32, addr: u64) -> Option<(String, u64)> {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
        for line in maps.lines() {
            let mut it = line.split_whitespace();
            let (Some(range), Some(_), Some(off), Some(_), Some(_), Some(path)) = (
                it.next(),
                it.next(),
                it.next(),
                it.next(),
                it.next(),
                it.next(),
            ) else {
                continue;
            };
            let (s, e) = range.split_once('-')?;
            let (s, e) = (
                u64::from_str_radix(s, 16).ok()?,
                u64::from_str_radix(e, 16).ok()?,
            );
            if (s..e).contains(&addr) && path.starts_with('/') {
                let off = u64::from_str_radix(off, 16).ok()?;
                return Some((format!("/proc/{pid}/root{path}"), addr - s + off));
            }
        }
        None
    }

    fn sites(
        ctx: &RecordContext<'_>,
        module: &Module,
        set: &[(&str, &'static str); 3],
        first_variant: u64,
    ) -> Option<Vec<Site>> {
        set.iter()
            .zip(first_variant..)
            .map(|(&(name, section), variant)| {
                let mut addr = ctx.src.find_symbol(module, name).ok()??;
                // Skip `endbr64` (CET builds of glibc): the kernel must
                // single-step it out of line, which made each hit tens of
                // microseconds; the next instruction (`push %rbp`) is
                // emulated. Registers and the stack are the same there.
                let mut head = [0u8; 4];
                if ctx.src.read(addr, &mut head).is_ok() && head == ENDBR64 {
                    addr += 4;
                }
                let (path, offset) = file_offset(ctx.target.pid, addr)?;
                Some(Site {
                    path,
                    offset,
                    addr,
                    section,
                    variant,
                })
            })
            .collect()
    }

    fn large_sites(ctx: &RecordContext<'_>) -> Result<(Vec<Site>, &'static str)> {
        if let Some(s) = sites(ctx, &ctx.target.runtime.module, &RAW, 0) {
            return Ok((s, "_PyMem_Raw*"));
        }
        let mods = ctx.src.modules()?;
        let libc = mods
            .iter()
            .find(|m| m.name.starts_with("libc.so") || m.name.starts_with("libc-"));
        if let Some(s) = libc.and_then(|m| sites(ctx, m, &LIBC, 3)) {
            return Ok((s, "libc malloc"));
        }
        Err(Error::Unsupported(
            "found neither _PyMem_RawMalloc/Calloc/Realloc in the interpreter's symbols nor libc malloc".into(),
        ))
    }

    /// Everything attached; dropping it detaches.
    struct Attached {
        _links: Vec<Fd>,
    }

    pub fn run(ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
        let pid = ctx.target.pid;
        let want = ctx.opts.sampling.events;
        let mut recorded = EventKinds::NONE;
        let mut skipped = Vec::new();
        if want.contains(EventKind::Pool) {
            skipped.push((
                EventKind::Pool,
                "pool carving is inlined in every supported build".to_string(),
            ));
        }
        if want.contains(EventKind::Native) {
            skipped.push((
                EventKind::Native,
                "native heap tracing is a Windows (ETW) mechanism".to_string(),
            ));
        }
        let arenas = want.contains(EventKind::Arena);
        let mut large = want.contains(EventKind::LargeObject);
        let mut large_sites_found = Vec::new();
        let mut large_via = "";
        if large {
            match large_sites(ctx) {
                Ok((s, via)) => {
                    large_sites_found = s;
                    large_via = via;
                }
                Err(e) => {
                    skipped.push((EventKind::LargeObject, e.to_string()));
                    large = false;
                }
            }
        }
        if arenas {
            recorded.insert(EventKind::Arena);
        }
        if large {
            recorded.insert(EventKind::LargeObject);
        }
        if recorded.is_empty() {
            return Err(Error::Unsupported(format!(
                "none of the requested event kinds can be recorded: {}",
                skipped
                    .iter()
                    .map(|(k, w)| format!("{k} ({w})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            )));
        }

        let mut loaded = sys::load()?;
        if arenas {
            loaded.load_program("raw_tracepoint/sys_enter", 0)?;
            loaded.load_program("raw_tracepoint/sys_exit", 0)?;
        }

        let interval = ctx.opts.sampling.byte_interval;
        let cfg = Config {
            tgid: pid as u64,
            arena_size: if arenas { ARENA_SIZE } else { 0 },
            large_on: large,
            min_large: LARGE_THRESHOLD,
            interval,
            runtime_addr: ctx.target.runtime.runtime_addr,
            max_frames: ctx.opts.sampling.max_frames as u64,
            fo: Some(ctx.target.offsets),
        };
        loaded
            .map("cfg")
            .update(&0u32.to_ne_bytes(), &cfg.to_bytes())?;
        for (i, t) in abi::thresholds(interval.max(1)).iter().enumerate() {
            loaded
                .map("thresholds")
                .update(&(i as u32).to_ne_bytes(), &t.to_ne_bytes())?;
        }
        let mut ring = sys::RingBuf::new(loaded.map("events"))?;
        let offset = common::monotonic_to_epoch_offset();

        // Attach. Each link is a descriptor; an error drops the ones made.
        let mut links = Vec::new();
        if arenas {
            for (sec, tp) in [
                ("raw_tracepoint/sys_exit", "sys_exit"),
                ("raw_tracepoint/sys_enter", "sys_enter"),
            ] {
                links.push(sys::attach_raw_tracepoint(
                    loaded.program(sec).unwrap(),
                    tp,
                )?);
            }
        }
        // Large objects: one uprobe session where the kernel has them
        // (unsampled calls skip the return probe), else a uprobe and a
        // uretprobe per function.
        let mut large_mode = "none";
        if large {
            let path = &large_sites_found[0].path;
            let offsets: Vec<u64> = large_sites_found.iter().map(|s| s.offset).collect();
            let cookies: Vec<u64> = large_sites_found
                .iter()
                .map(|s| (s.addr << 8) | s.variant)
                .collect();
            let session = loaded
                .load_program("uprobe.session/alloc", sys::BPF_TRACE_UPROBE_SESSION)
                .and_then(|()| {
                    let p = loaded.program("uprobe.session/alloc").unwrap();
                    sys::attach_uprobe_session(p, path, &offsets, &cookies, pid)
                });
            match session {
                Ok(link) => {
                    links.push(link);
                    large_mode = "session";
                }
                Err(Error::PermissionDenied(m)) => return Err(Error::PermissionDenied(m)),
                Err(_) => {
                    loaded.load_program("uretprobe/alloc_ret", 0)?;
                    for s in &large_sites_found {
                        loaded.load_program(s.section, 0)?;
                    }
                    let ret = loaded.program("uretprobe/alloc_ret").unwrap();
                    for s in &large_sites_found {
                        // Return probe first, so no sampled entry waits for
                        // a return probe that is not there yet.
                        links.push(sys::attach_uprobe(ret, &s.path, s.offset, pid, true)?);
                        links.push(sys::attach_uprobe(
                            loaded.program(s.section).unwrap(),
                            &s.path,
                            s.offset,
                            pid,
                            false,
                        )?);
                    }
                    large_mode = "uprobe+uretprobe";
                }
            }
        }
        let attached = Attached { _links: links };
        {
            let w = ctx.sink.writer_mut();
            w.add_meta(
                "heapspy.ebpf.large_object_probes",
                if large { large_via } else { "none" },
            )?;
            w.add_meta("heapspy.ebpf.large_object_attach", large_mode)?;
        }
        common::note_events(&mut ctx.sink, recorded, &skipped)?;

        let mut st = State {
            types: CodeTypes::default(),
            offset,
            interval,
            max_frames: ctx.opts.sampling.max_frames as usize,
            err: None,
        };
        let mut exited = false;
        loop {
            let stop = ctx.should_stop();
            let n = ring.drain(|rec| st.handle(ctx, rec));
            if let Some(e) = st.err.take() {
                return Err(e);
            }
            if stop {
                break;
            }
            if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
                exited = true;
                break;
            }
            if n == 0 {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        drop(attached);
        // Events committed before the probes went.
        ring.drain(|rec| st.handle(ctx, rec));
        if let Some(e) = st.err.take() {
            return Err(e);
        }
        let c = loaded.map("counters");
        let dropped = sys::percpu_sum(c, abi::C_DROPPED as u32);
        let orphans = sys::percpu_sum(c, abi::C_ORPHANS as u32);
        let hits = sys::percpu_sum(c, abi::C_HITS as u32);
        let misses = sys::percpu_sum(c, abi::C_TSTATE_MISS as u32);
        {
            let w = ctx.sink.writer_mut();
            w.add_meta("heapspy.ebpf.orphaned_entries", &orphans.to_string())?;
            w.add_meta("heapspy.ebpf.no_thread_state", &misses.to_string())?;
            w.add_meta(
                "heapspy.ebpf.refired_entries",
                &sys::percpu_sum(c, abi::C_REFIRES as u32).to_string(),
            )?;
        }
        Ok(RunOutcome {
            mechanisms: Mechanisms::of(&[Mechanism::Ebpf]),
            overhead: Overhead {
                samples_taken: 0,
                samples_dropped: dropped + orphans,
                probe_hits: hits,
                total_pause_ns: 0,
            },
            truncated: exited || dropped + orphans > 0,
        })
    }

    struct State {
        types: CodeTypes,
        offset: i128,
        interval: u64,
        max_frames: usize,
        err: Option<Error>,
    }

    impl State {
        fn handle(&mut self, ctx: &mut RecordContext<'_>, rec: &[u8]) {
            if self.err.is_some() {
                return;
            }
            if let Some(e) = abi::parse_event(rec) {
                if let Err(e) = self.add(ctx, &e) {
                    self.err = Some(e);
                }
            }
        }

        fn add(&mut self, ctx: &mut RecordContext<'_>, e: &Event) -> Result<()> {
            let (kind, weight) = match e.kind {
                abi::KIND_ARENA => (EventKind::Arena, e.size),
                abi::KIND_LARGE => (
                    EventKind::LargeObject,
                    sampled_weight(e.size, self.interval),
                ),
                _ => return Ok(()),
            };
            let mut s = SampleInput {
                timestamp_ns: common::to_epoch(e.ts, self.offset),
                tid: e.tid as u64,
                kind,
                address: e.addr,
                size: e.size,
                weight,
                native_return_address: (e.flags & abi::EF_HAS_RET != 0).then_some(e.ret_addr),
                flags: SampleFlags::NONE,
            };
            if e.flags & abi::EF_NO_TSTATE != 0 {
                return ctx.sink.add_native(&s);
            }
            let fo = ctx.target.offsets;
            let mut frames = Vec::with_capacity(e.frames.len());
            for f in &e.frames {
                if self.types.keep(ctx.src, &fo, f.ob_type, f.executable) {
                    frames.push(common::raw_frame(&fo, f.executable, f.instr_ptr));
                }
            }
            if e.flags & abi::EF_TRUNCATED != 0 || frames.len() > self.max_frames {
                s.flags = s.flags | SampleFlags::STACK_TRUNCATED;
            }
            frames.truncate(self.max_frames);
            ctx.sink.add(&s, &frames, false)
        }
    }
}
