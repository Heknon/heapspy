//! Linux system interface of the eBPF recorder: the `bpf(2)` calls, a
//! small loader for `bpf/heapspy.bpf.o`, uprobe and raw tracepoint
//! attachment through file descriptors, and the ring buffer consumer.
//!
//! Every kernel object is owned by a file descriptor ([`Fd`]): maps,
//! programs, uprobe perf events and raw tracepoint links. Closing the
//! descriptor removes the object, so whichever way heapspy ends (return,
//! error, panic unwinding, SIGTERM, SIGKILL) the kernel detaches every
//! probe; nothing is registered in tracefs, nothing outlives the process.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

use crate::error::{Error, Result};

/// The BPF object built by `bpf/build.sh` from `bpf/heapspy.bpf.c`.
/// ELF parsing needs 8-byte alignment, which `include_bytes!` alone does
/// not give.
pub static OBJECT: &[u8] = &ALIGNED.0;

#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);
static ALIGNED: &Aligned<[u8]> = &Aligned(*include_bytes!("../../bpf/heapspy.bpf.o"));

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_PROG_LOAD: u32 = 5;
const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;
const BPF_LINK_CREATE: u32 = 28;
/// `enum bpf_attach_type`: uprobe sessions, kernel 6.13+.
pub const BPF_TRACE_UPROBE_SESSION: u32 = 57;

const PROG_KPROBE: u32 = 2;
const PROG_RAW_TRACEPOINT: u32 = 17;
const BPF_PSEUDO_MAP_FD: u8 = 1;
const MAP_PERCPU_ARRAY: u32 = 6;
const MAP_RINGBUF: u32 = 27;

const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 8;

pub type Fd = OwnedFd;

fn bpf(cmd: u32, attr: &mut [u8; 128]) -> io::Result<i64> {
    // SAFETY: `attr` is a zero-initialized bpf_attr of the size passed.
    let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.as_mut_ptr(), attr.len()) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn put32(a: &mut [u8], o: usize, v: u32) {
    a[o..o + 4].copy_from_slice(&v.to_ne_bytes());
}
fn put64(a: &mut [u8], o: usize, v: u64) {
    a[o..o + 8].copy_from_slice(&v.to_ne_bytes());
}

fn fd_from(r: i64) -> Fd {
    // SAFETY: `r` is a new descriptor returned by the kernel, owned by no one else.
    unsafe { OwnedFd::from_raw_fd(r as RawFd) }
}

/// Map an errno from a privileged call to the recorder's errors.
pub fn privilege_error(what: &str, e: &io::Error) -> Error {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => Error::PermissionDenied(format!(
            "{what}: {e}. eBPF recording needs root or CAP_BPF + CAP_PERFMON \
             (in a container: --cap-add BPF --cap-add PERFMON, or --privileged); \
             use --mechanism ptrace otherwise"
        )),
        Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) | Some(libc::ENOENT) => {
            Error::Unsupported(format!(
                "{what}: {e} (kernel 5.8+ with BPF ring buffers needed)"
            ))
        }
        _ => Error::Io(io::Error::new(e.kind(), format!("{what}: {e}"))),
    }
}

/// A BPF map.
pub struct Map {
    pub fd: Fd,
    pub kind: u32,
    pub max_entries: u32,
}

impl Map {
    pub fn create(kind: u32, key_size: u32, value_size: u32, max_entries: u32) -> Result<Map> {
        let mut a = [0u8; 128];
        put32(&mut a, 0, kind);
        put32(&mut a, 4, key_size);
        put32(&mut a, 8, value_size);
        put32(&mut a, 12, max_entries);
        let r =
            bpf(BPF_MAP_CREATE, &mut a).map_err(|e| privilege_error("bpf(BPF_MAP_CREATE)", &e))?;
        Ok(Map {
            fd: fd_from(r),
            kind,
            max_entries,
        })
    }

    fn elem(&self, cmd: u32, key: &[u8], value: *mut u8) -> io::Result<()> {
        let mut a = [0u8; 128];
        put32(&mut a, 0, self.fd.as_raw_fd() as u32);
        put64(&mut a, 8, key.as_ptr() as u64);
        put64(&mut a, 16, value as u64);
        bpf(cmd, &mut a).map(|_| ())
    }

    pub fn update(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.elem(BPF_MAP_UPDATE_ELEM, key, value.as_ptr() as *mut u8)
            .map_err(|e| Error::Io(io::Error::new(e.kind(), format!("bpf map update: {e}"))))
    }

    /// For per-CPU maps the value is one 8-byte-aligned slot per possible CPU.
    pub fn lookup(&self, key: &[u8], value: &mut [u8]) -> io::Result<()> {
        self.elem(BPF_MAP_LOOKUP_ELEM, key, value.as_mut_ptr())
    }
}

/// Number of possible CPUs, for per-CPU map values.
pub fn possible_cpus() -> usize {
    let s = std::fs::read_to_string("/sys/devices/system/cpu/possible").unwrap_or_default();
    s.trim()
        .split(',')
        .filter_map(|r| {
            let mut it = r.split('-');
            let a: usize = it.next()?.trim().parse().ok()?;
            let b: usize = it.next().map_or(Some(a), |b| b.trim().parse().ok())?;
            Some(b + 1)
        })
        .max()
        .unwrap_or(1)
}

/// Sum a per-CPU array of `u64` at `index`.
pub fn percpu_sum(map: &Map, index: u32) -> u64 {
    let n = possible_cpus();
    let mut v = vec![0u8; n * 8];
    if map.lookup(&index.to_ne_bytes(), &mut v).is_err() {
        return 0;
    }
    v.chunks_exact(8)
        .map(|c| u64::from_ne_bytes(c.try_into().unwrap()))
        .fold(0u64, u64::wrapping_add)
}

/// A loaded program, by its section name (`uprobe/malloc_ctx`).
pub struct Program {
    pub section: String,
    pub fd: Fd,
}

/// The maps of [`OBJECT`], and its programs as loaded so far.
pub struct Loaded {
    pub maps: HashMap<String, Map>,
    pub programs: Vec<Program>,
    /// Section name -> instructions with map references patched in.
    insns: HashMap<String, Vec<u8>>,
}

impl Loaded {
    pub fn map(&self, name: &str) -> &Map {
        &self.maps[name]
    }
    pub fn program(&self, section: &str) -> Option<&Program> {
        self.programs.iter().find(|p| p.section == section)
    }

    /// Load the program in `section` with `expected_attach_type` (0 for
    /// none). Errors leave the other programs as they are.
    pub fn load_program(&mut self, section: &str, expected_attach_type: u32) -> Result<()> {
        if self.program(section).is_some() {
            return Ok(());
        }
        let insns = self
            .insns
            .get(section)
            .ok_or_else(|| Error::Unsupported(format!("BPF object has no program {section}")))?;
        let kind = if section.starts_with("raw_tracepoint/") {
            PROG_RAW_TRACEPOINT
        } else {
            PROG_KPROBE
        };
        let license = CString::new("GPL").unwrap();
        let fd = load_prog(kind, expected_attach_type, insns, &license, section)?;
        self.programs.push(Program {
            section: section.to_string(),
            fd,
        });
        Ok(())
    }
}

/// Read [`OBJECT`]: create its maps (legacy `maps` section, no BTF) and
/// patch map references into each program's instructions. Programs are
/// loaded with [`Loaded::load_program`].
pub fn load() -> Result<Loaded> {
    let fmt = |e: object::Error| Error::Unsupported(format!("bad BPF object: {e}"));
    let obj = object::File::parse(OBJECT).map_err(fmt)?;
    let maps_sec = obj
        .section_by_name("maps")
        .ok_or_else(|| Error::Unsupported("BPF object has no maps section".into()))?;
    let maps_data = maps_sec.data().map_err(fmt)?;
    let mut maps = HashMap::new();
    let mut by_symbol = HashMap::new();
    for sym in obj.symbols() {
        if sym.section_index() != Some(maps_sec.index()) {
            continue;
        }
        let name = sym.name().map_err(fmt)?.to_string();
        let o = sym.address() as usize;
        let w =
            |i: usize| u32::from_ne_bytes(maps_data[o + i * 4..o + i * 4 + 4].try_into().unwrap());
        let mut entries = w(3);
        if w(0) == MAP_RINGBUF {
            entries = entries.next_power_of_two();
        }
        let m = Map::create(w(0), w(1), w(2), entries)?;
        by_symbol.insert(sym.index(), m.fd.as_raw_fd());
        maps.insert(name, m);
    }
    let mut insns_by = HashMap::new();
    for sec in obj.sections() {
        let Ok(name) = sec.name() else { continue };
        if ![
            "raw_tracepoint/",
            "uprobe/",
            "uretprobe/",
            "uprobe.session/",
        ]
        .iter()
        .any(|p| name.starts_with(p))
        {
            continue;
        }
        let mut insns = sec.data().map_err(fmt)?.to_vec();
        for (off, rel) in sec.relocations() {
            let RelocationTarget::Symbol(si) = rel.target() else {
                continue;
            };
            let Some(&fd) = by_symbol.get(&si) else {
                return Err(Error::Unsupported(format!(
                    "BPF object: unsupported relocation in {name}"
                )));
            };
            let o = off as usize;
            insns[o + 1] = (insns[o + 1] & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
            insns[o + 4..o + 8].copy_from_slice(&(fd as u32).to_ne_bytes());
        }
        insns_by.insert(name.to_string(), insns);
    }
    Ok(Loaded {
        maps,
        programs: Vec::new(),
        insns: insns_by,
    })
}

fn load_prog(kind: u32, expected: u32, insns: &[u8], license: &CString, name: &str) -> Result<Fd> {
    let attempt = |log: &mut [u8]| {
        let mut a = [0u8; 128];
        put32(&mut a, 0, kind);
        put32(&mut a, 4, (insns.len() / 8) as u32);
        put64(&mut a, 8, insns.as_ptr() as u64);
        put64(&mut a, 16, license.as_ptr() as u64);
        put32(&mut a, 68, expected);
        if !log.is_empty() {
            put32(&mut a, 24, 1);
            put32(&mut a, 28, log.len() as u32);
            put64(&mut a, 32, log.as_mut_ptr() as u64);
        }
        bpf(BPF_PROG_LOAD, &mut a)
    };
    match attempt(&mut []) {
        Ok(fd) => Ok(fd_from(fd)),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) => {
            Err(privilege_error("bpf(BPF_PROG_LOAD)", &e))
        }
        Err(e) => {
            let mut log = vec![0u8; 1 << 20];
            let _ = attempt(&mut log);
            let text =
                String::from_utf8_lossy(&log[..log.iter().position(|&b| b == 0).unwrap_or(0)])
                    .lines()
                    .rev()
                    .take(8)
                    .collect::<Vec<_>>()
                    .join(" | ");
            Err(Error::Unsupported(format!(
                "the kernel rejected BPF program {name}: {e} ({text})"
            )))
        }
    }
}

/// Attach a raw tracepoint program (`sys_enter`). The returned descriptor
/// is the attachment.
pub fn attach_raw_tracepoint(prog: &Program, tp: &str) -> Result<Fd> {
    let name = CString::new(tp).unwrap();
    let mut a = [0u8; 128];
    put64(&mut a, 0, name.as_ptr() as u64);
    put32(&mut a, 8, prog.fd.as_raw_fd() as u32);
    let r = bpf(BPF_RAW_TRACEPOINT_OPEN, &mut a)
        .map_err(|e| privilege_error(&format!("attaching to raw tracepoint {tp}"), &e))?;
    Ok(fd_from(r))
}

/// Attach a uprobe session program to `offsets` of `path`, for `pid`, with
/// one cookie per offset (kernel 6.13+). The descriptor is the link.
pub fn attach_uprobe_session(
    prog: &Program,
    path: &str,
    offsets: &[u64],
    cookies: &[u64],
    pid: u32,
) -> Result<Fd> {
    let cpath = CString::new(path).map_err(|_| Error::Unsupported("bad module path".into()))?;
    let mut a = [0u8; 128];
    put32(&mut a, 0, prog.fd.as_raw_fd() as u32);
    put32(&mut a, 8, BPF_TRACE_UPROBE_SESSION);
    put64(&mut a, 16, cpath.as_ptr() as u64);
    put64(&mut a, 24, offsets.as_ptr() as u64);
    put64(&mut a, 40, cookies.as_ptr() as u64);
    put32(&mut a, 48, offsets.len() as u32);
    put32(&mut a, 56, pid);
    let r = bpf(BPF_LINK_CREATE, &mut a)
        .map_err(|e| privilege_error(&format!("uprobe session on {path}"), &e))?;
    Ok(fd_from(r))
}

fn read_sys(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// The uprobe PMU type and the `config` bit that makes a uretprobe.
pub fn uprobe_pmu() -> Result<(u32, u32)> {
    let t = read_sys("/sys/bus/event_source/devices/uprobe/type")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            Error::Unsupported(
                "the kernel has no uprobe PMU (/sys/bus/event_source/devices/uprobe)".into(),
            )
        })?;
    let bit = read_sys("/sys/bus/event_source/devices/uprobe/format/retprobe")
        .and_then(|s| s.strip_prefix("config:").and_then(|b| b.parse().ok()))
        .unwrap_or(0);
    Ok((t, bit))
}

/// Attach `prog` as a uprobe (or uretprobe) on `path` at file offset
/// `offset`, for the threads of `pid` only. The returned descriptor is
/// the probe: closing it removes it.
pub fn attach_uprobe(prog: &Program, path: &str, offset: u64, pid: u32, ret: bool) -> Result<Fd> {
    let (pmu, bit) = uprobe_pmu()?;
    let cpath = CString::new(path).map_err(|_| Error::Unsupported("bad module path".into()))?;
    let mut attr = [0u8; 128];
    put32(&mut attr, 0, pmu);
    put32(&mut attr, 4, 128);
    put64(&mut attr, 8, if ret { 1u64 << bit } else { 0 });
    put64(&mut attr, 16, 1); // sample_period
    put64(&mut attr, 56, cpath.as_ptr() as u64); // uprobe_path
    put64(&mut attr, 64, offset); // probe_offset
                                  // SAFETY: `attr` is a perf_event_attr of the size it declares; the
                                  // path it points to outlives the call.
    let r = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr.as_ptr(),
            pid as libc::pid_t,
            -1 as libc::c_int,
            -1 as libc::c_int,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        return Err(privilege_error(
            &format!("uprobe on {path}+{offset:#x}"),
            &e,
        ));
    }
    let fd = fd_from(r);
    // SAFETY: ioctls on the perf event descriptor we own.
    unsafe {
        if libc::ioctl(
            fd.as_raw_fd(),
            PERF_EVENT_IOC_SET_BPF as _,
            prog.fd.as_raw_fd(),
        ) != 0
        {
            let e = io::Error::last_os_error();
            return Err(privilege_error("PERF_EVENT_IOC_SET_BPF", &e));
        }
        if libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_ENABLE as _, 0) != 0 {
            let e = io::Error::last_os_error();
            return Err(privilege_error("PERF_EVENT_IOC_ENABLE", &e));
        }
    }
    Ok(fd)
}

/// Consumer side of a BPF ring buffer map.
pub struct RingBuf {
    consumer: *mut u8,
    producer: *mut u8,
    page: usize,
    size: usize,
}

impl RingBuf {
    pub fn new(map: &Map) -> Result<RingBuf> {
        if map.kind != MAP_RINGBUF {
            return Err(Error::Unsupported("not a ring buffer".into()));
        }
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let size = map.max_entries as usize;
        let fd = map.fd.as_raw_fd();
        // SAFETY: mapping the ring buffer as the kernel documents: one
        // writable consumer page at offset 0, then the producer page and the
        // data area twice (read-only) at offset `page`.
        unsafe {
            let c = libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            if c == libc::MAP_FAILED {
                return Err(Error::Io(io::Error::last_os_error()));
            }
            let p = libc::mmap(
                std::ptr::null_mut(),
                page + 2 * size,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                page as libc::off_t,
            );
            if p == libc::MAP_FAILED {
                let e = io::Error::last_os_error();
                libc::munmap(c, page);
                return Err(Error::Io(e));
            }
            Ok(RingBuf {
                consumer: c.cast(),
                producer: p.cast(),
                page,
                size,
            })
        }
    }

    /// Hand every committed record to `f`; returns how many were read.
    pub fn drain(&mut self, mut f: impl FnMut(&[u8])) -> usize {
        use std::sync::atomic::{AtomicU64, Ordering};
        // SAFETY: both positions are 8-byte aligned u64s at the start of
        // their pages, shared with the kernel and accessed atomically.
        let (cons, prod) = unsafe {
            (
                &*(self.consumer as *const AtomicU64),
                &*(self.producer as *const AtomicU64),
            )
        };
        let mut n = 0;
        let mut c = cons.load(Ordering::Acquire);
        loop {
            let p = prod.load(Ordering::Acquire);
            if c >= p {
                break;
            }
            let off = (c as usize) & (self.size - 1);
            // SAFETY: the data area is mapped twice, so a record that wraps
            // is contiguous; `off + 8 + len` stays inside the double mapping.
            let data = unsafe { self.producer.add(self.page) };
            let hdr = unsafe {
                (*(data.add(off) as *const std::sync::atomic::AtomicU32)).load(Ordering::Acquire)
            };
            let (len, busy, discard) = super::abi::record_header(hdr);
            if busy {
                break;
            }
            if !discard {
                let rec = unsafe { std::slice::from_raw_parts(data.add(off + 8), len) };
                f(rec);
                n += 1;
            }
            c += super::abi::record_span(len) as u64;
            cons.store(c, Ordering::Release);
        }
        n
    }
}

impl Drop for RingBuf {
    fn drop(&mut self) {
        // SAFETY: unmapping exactly what `new` mapped.
        unsafe {
            libc::munmap(self.consumer.cast(), self.page);
            libc::munmap(self.producer.cast(), self.page + 2 * self.size);
        }
    }
}

/// Can this process create BPF maps at all? Cheap capability check.
pub fn check_bpf() -> Result<()> {
    Map::create(MAP_PERCPU_ARRAY, 4, 8, 1).map(|_| ())?;
    uprobe_pmu().map(|_| ())
}
