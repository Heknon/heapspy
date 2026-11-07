//! Linux implementation of [`super::LiveProcess`]. See the parent module docs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use heapspy_snapshot::{MemoryRegion, RegionKind};

use crate::error::{Error, Result};
use crate::source::{
    MappedRange, MemorySource, MemorySummary, Module, Perms, TargetInfo, ThreadInfo,
};
use crate::symbols;

const BLOCK: u64 = 64 * 1024;
const MAX_BLOCKS: usize = 4096;
/// Passes over `/proc/<pid>/task` looking for threads created while stopping.
const MAX_ATTACH_PASSES: usize = 50;

#[derive(Clone, Debug)]
struct MapEntry {
    start: u64,
    end: u64,
    perms: Perms,
    offset: u64,
    inode: u64,
    path: Option<String>,
}

struct Tracees {
    /// TID and the signal to re-inject on detach (0 for none).
    tids: Vec<(i32, i32)>,
    stopped_at: Instant,
}

#[derive(Default)]
struct Cache {
    blocks: HashMap<u64, Option<Arc<[u8]>>>,
    order: VecDeque<u64>,
}

pub(super) struct Inner {
    pid: u32,
    target: TargetInfo,
    mem: Option<File>,
    maps: Vec<MapEntry>,
    modules: Vec<Module>,
    threads: Vec<ThreadInfo>,
    summary: Option<MemorySummary>,
    captured_at: u64,
    attach_time: Duration,
    tracees: Mutex<Option<Tracees>>,
    cache: Mutex<Cache>,
    /// Reads go through the block cache. Only valid while the target is
    /// stopped; [`Inner::open_running`] turns it off.
    cached: bool,
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn ptrace_scope() -> String {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "not present".into())
}

fn permission_error(pid: u32, what: &str) -> Error {
    Error::PermissionDenied(format!(
        "{what} on pid {pid} was refused. Run heapspy as root or with CAP_SYS_PTRACE \
         (in a container: --cap-add SYS_PTRACE and a shared PID namespace), and check \
         /proc/sys/kernel/yama/ptrace_scope (currently {}; 0 lets a user trace its own \
         processes, 1 only descendants, 2 needs CAP_SYS_PTRACE, 3 forbids tracing). \
         The process may also already be traced by a debugger.",
        ptrace_scope()
    ))
}

fn list_tids(pid: u32) -> Result<Vec<i32>> {
    let mut tids = Vec::new();
    for e in std::fs::read_dir(format!("/proc/{pid}/task"))? {
        if let Some(t) = e?.file_name().to_str().and_then(|s| s.parse().ok()) {
            tids.push(t);
        }
    }
    tids.sort_unstable();
    Ok(tids)
}

/// Seize and interrupt one thread, then wait for it to stop. Returns the
/// signal to re-inject on detach, or `None` if the thread is gone.
fn stop_thread(pid: u32, tid: i32) -> Result<Option<i32>> {
    // SAFETY: plain ptrace/waitpid system calls on a TID; no memory is shared.
    unsafe {
        if libc::ptrace(libc::PTRACE_SEIZE, tid, 0, 0) != 0 {
            return match errno() {
                libc::ESRCH => Ok(None),
                libc::EPERM | libc::EACCES => Err(permission_error(pid, "ptrace(PTRACE_SEIZE)")),
                e => Err(Error::Io(io::Error::from_raw_os_error(e))),
            };
        }
        if libc::ptrace(libc::PTRACE_INTERRUPT, tid, 0, 0) != 0 {
            let e = errno();
            libc::ptrace(libc::PTRACE_DETACH, tid, 0, 0);
            return if e == libc::ESRCH {
                Ok(None)
            } else {
                Err(Error::Io(io::Error::from_raw_os_error(e)))
            };
        }
        loop {
            let mut status = 0;
            let r = libc::waitpid(tid, &mut status, libc::__WALL);
            if r < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                return if e == libc::ECHILD {
                    Ok(None)
                } else {
                    Err(Error::Io(io::Error::from_raw_os_error(e)))
                };
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Ok(None);
            }
            if libc::WIFSTOPPED(status) {
                let event = (status >> 16) & 0xff;
                let sig = libc::WSTOPSIG(status);
                // PTRACE_EVENT_STOP: our interrupt (or a group stop).
                // Otherwise a signal-delivery stop: keep the signal.
                return Ok(Some(if event == libc::PTRACE_EVENT_STOP {
                    0
                } else {
                    sig
                }));
            }
        }
    }
}

fn detach_all(t: &Tracees) {
    for &(tid, sig) in &t.tids {
        // SAFETY: detaching a tracee we seized; errors (thread exited) are ignored.
        unsafe {
            libc::ptrace(libc::PTRACE_DETACH, tid, 0, sig as libc::c_long);
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn regs(tid: i32) -> (Option<u64>, Option<u64>) {
    // SAFETY: PTRACE_GETREGS writes one user_regs_struct into `r`.
    unsafe {
        let mut r: libc::user_regs_struct = std::mem::zeroed();
        if libc::ptrace(libc::PTRACE_GETREGS, tid, 0, &mut r as *mut _) == 0 {
            (Some(r.rsp), Some(r.fs_base).filter(|&b| b != 0))
        } else {
            (None, None)
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn regs(_tid: i32) -> (Option<u64>, Option<u64>) {
    (None, None)
}

fn parse_maps(text: &str) -> Vec<MapEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.splitn(6, ' ');
        let (Some(range), Some(perms), Some(off), Some(_dev), Some(inode)) =
            (it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        let path = it.next().map(str::trim).filter(|s| !s.is_empty());
        let Some((s, e)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end), Ok(offset)) = (
            u64::from_str_radix(s, 16),
            u64::from_str_radix(e, 16),
            u64::from_str_radix(off, 16),
        ) else {
            continue;
        };
        let p = perms.as_bytes();
        out.push(MapEntry {
            start,
            end,
            perms: Perms {
                read: p.first() == Some(&b'r'),
                write: p.get(1) == Some(&b'w'),
                exec: p.get(2) == Some(&b'x'),
            },
            offset,
            inode: inode.trim().parse().unwrap_or(0),
            path: path.map(str::to_string),
        });
    }
    out.sort_by_key(|m| m.start);
    out
}

fn kib_field(line: &str, key: &str) -> Option<u64> {
    let rest = line.strip_prefix(key)?.trim();
    rest.strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()
        .map(|k| k * 1024)
}

impl Inner {
    pub(super) fn attach(pid: u32) -> Result<Inner> {
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return Err(Error::NoSuchProcess(format!("no process with pid {pid}")));
        }
        if pid == std::process::id() {
            return Err(Error::Unsupported("heapspy cannot dump itself".into()));
        }
        let t0 = Instant::now();
        let mut tracees = Tracees {
            tids: Vec::new(),
            stopped_at: t0,
        };
        // On any error below, the guard detaches what was already stopped.
        struct Guard(Option<Tracees>);
        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(t) = self.0.take() {
                    detach_all(&t);
                }
            }
        }
        let mut seen: HashSet<i32> = HashSet::new();
        let mut guard = Guard(None);
        for pass in 0.. {
            let new: Vec<i32> = list_tids(pid)?
                .into_iter()
                .filter(|t| !seen.contains(t))
                .collect();
            if new.is_empty() {
                break;
            }
            if pass >= MAX_ATTACH_PASSES {
                guard.0 = Some(tracees);
                return Err(Error::Unsupported(format!(
                    "pid {pid} keeps creating threads; could not stop all of them"
                )));
            }
            for tid in new {
                seen.insert(tid);
                let r = stop_thread(pid, tid);
                match r {
                    Ok(Some(sig)) => tracees.tids.push((tid, sig)),
                    Ok(None) => {}
                    Err(e) => {
                        guard.0 = Some(tracees);
                        return Err(e);
                    }
                }
            }
        }
        if tracees.tids.is_empty() {
            return Err(Error::NoSuchProcess(format!(
                "pid {pid} has no threads left to stop"
            )));
        }
        guard.0 = Some(tracees);
        let attach_time = t0.elapsed();

        // Everything below runs with the target stopped.
        let maps_text = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
        let maps = parse_maps(&maps_text);
        let mem = File::open(format!("/proc/{pid}/mem")).ok();
        let captured_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let tracees = guard.0.take().expect("set above");
        let threads = tracees
            .tids
            .iter()
            .map(|&(tid, _)| {
                let (sp, tls) = regs(tid);
                ThreadInfo {
                    tid: tid as u64,
                    name: std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm"))
                        .ok()
                        .map(|s| s.trim_end().to_string()),
                    tls_base: tls,
                    stack_pointer: sp,
                }
            })
            .collect::<Vec<_>>();
        let mut inner = Inner {
            pid,
            target: TargetInfo::LINUX_X86_64,
            mem,
            maps,
            modules: Vec::new(),
            threads,
            summary: None,
            captured_at,
            attach_time,
            tracees: Mutex::new(Some(tracees)),
            cache: Mutex::new(Cache::default()),
            cached: true,
        };
        if cfg!(target_arch = "aarch64") {
            inner.target.arch = heapspy_snapshot::Arch::Aarch64;
        }
        inner.modules = inner.build_modules();
        inner.summary = inner.build_summary();
        Ok(inner)
    }

    /// Prepare to read `pid` without stopping it: no ptrace, no block
    /// cache, no memory summary. Threads are listed without registers.
    pub(super) fn open_running(pid: u32) -> Result<Inner> {
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return Err(Error::NoSuchProcess(format!("no process with pid {pid}")));
        }
        let maps = parse_maps(&std::fs::read_to_string(format!("/proc/{pid}/maps"))?);
        let threads = list_tids(pid)?
            .into_iter()
            .map(|tid| ThreadInfo {
                tid: tid as u64,
                name: std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm"))
                    .ok()
                    .map(|s| s.trim_end().to_string()),
                tls_base: None,
                stack_pointer: None,
            })
            .collect();
        let mut inner = Inner {
            pid,
            target: TargetInfo::LINUX_X86_64,
            mem: File::open(format!("/proc/{pid}/mem")).ok(),
            maps,
            modules: Vec::new(),
            threads,
            summary: None,
            captured_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            attach_time: Duration::ZERO,
            tracees: Mutex::new(None),
            cache: Mutex::new(Cache::default()),
            cached: false,
        };
        if cfg!(target_arch = "aarch64") {
            inner.target.arch = heapspy_snapshot::Arch::Aarch64;
        }
        // One probe read: a permission problem shows up here, not later.
        let mut b = [0u8; 1];
        if let Some(m) = inner.maps.iter().find(|m| m.perms.read) {
            if let Err(e @ Error::PermissionDenied(_)) = inner.read_direct(m.start, &mut b) {
                return Err(e);
            }
        }
        inner.modules = inner.build_modules();
        Ok(inner)
    }

    /// [`Inner::open_running`] with the memory summary: for a snapshot
    /// taken without stopping the target.
    pub(super) fn open_running_with_summary(pid: u32) -> Result<Inner> {
        let mut inner = Inner::open_running(pid)?;
        inner.summary = inner.build_summary();
        Ok(inner)
    }

    pub(super) fn target(&self) -> TargetInfo {
        self.target
    }

    pub(super) fn attach_time(&self) -> Duration {
        self.attach_time
    }

    pub(super) fn captured_at(&self) -> u64 {
        self.captured_at
    }

    pub(super) fn detach(&self) -> Option<Duration> {
        let mut g = self.tracees.lock().unwrap_or_else(|e| e.into_inner());
        let t = g.take()?;
        detach_all(&t);
        Some(t.stopped_at.elapsed())
    }

    fn build_modules(&self) -> Vec<Module> {
        let exe = std::fs::read_link(format!("/proc/{}/exe", self.pid))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let mut by_path: Vec<(String, Option<u64>, u64)> = Vec::new();
        for m in &self.maps {
            let Some(p) = m
                .path
                .as_ref()
                .filter(|p| p.starts_with('/') && m.inode != 0)
            else {
                continue;
            };
            let i = match by_path.iter().position(|e| &e.0 == p) {
                Some(i) => i,
                None => {
                    by_path.push((p.clone(), None, 0));
                    by_path.len() - 1
                }
            };
            let e = &mut by_path[i];
            if m.offset == 0 && e.1.is_none() {
                e.1 = Some(m.start);
            }
            e.2 = e.2.max(m.end);
        }
        let mut mods: Vec<Module> = by_path
            .into_iter()
            .filter_map(|(path, base, end)| {
                let base = base?;
                let mut magic = [0u8; 4];
                self.read(base, &mut magic).ok()?;
                (magic == symbols::elf::ELF_MAGIC).then(|| Module {
                    name: path.rsplit('/').next().unwrap_or(&path).to_string(),
                    build_id: symbols::elf::read_build_id(self, base),
                    path,
                    base,
                    size: end.saturating_sub(base),
                })
            })
            .collect();
        if let Some(i) = exe.and_then(|e| mods.iter().position(|m| m.path == e)) {
            let m = mods.remove(i);
            mods.insert(0, m);
        }
        mods
    }

    fn build_summary(&self) -> Option<MemorySummary> {
        let smaps = std::fs::read_to_string(format!("/proc/{}/smaps", self.pid)).ok()?;
        let module_paths: HashSet<&str> = self.modules.iter().map(|m| m.path.as_str()).collect();
        let stacks: Vec<u64> = self
            .threads
            .iter()
            .filter_map(|t| t.stack_pointer)
            .collect();
        let mut totals: Vec<(RegionKind, u64, u64)> = Vec::new();
        let mut cur: Option<(RegionKind, u64)> = None;
        let mut flush = |cur: &mut Option<(RegionKind, u64)>, rss: u64| {
            if let Some((k, size)) = cur.take() {
                match totals.iter_mut().find(|t| t.0 == k) {
                    Some(t) => {
                        t.1 += size;
                        t.2 += rss;
                    }
                    None => totals.push((k, size, rss)),
                }
            }
        };
        let mut rss = 0;
        for line in smaps.lines() {
            let first = line.split(' ').next().unwrap_or("");
            if first.contains('-') && !first.ends_with(':') {
                flush(&mut cur, rss);
                rss = 0;
                let Some(e) = parse_maps(line).into_iter().next() else {
                    continue;
                };
                let kind = match e.path.as_deref() {
                    Some("[heap]") => RegionKind::Heap,
                    Some(p) if p.starts_with("[stack") => RegionKind::Stack,
                    Some(p) if module_paths.contains(p) => RegionKind::Image,
                    Some(p) if p.starts_with('/') => RegionKind::MappedFile,
                    Some(p) if p.starts_with('[') => RegionKind::Other,
                    _ if stacks.iter().any(|&sp| sp >= e.start && sp < e.end) => RegionKind::Stack,
                    _ => RegionKind::Anonymous,
                };
                cur = Some((kind, e.end - e.start));
            } else if let Some(v) = kib_field(line, "Rss:") {
                rss = v;
            }
        }
        flush(&mut cur, rss);
        let rss_total = std::fs::read_to_string(format!("/proc/{}/smaps_rollup", self.pid))
            .ok()
            .and_then(|s| s.lines().find_map(|l| kib_field(l, "Rss:")));
        Some(MemorySummary {
            regions: totals
                .into_iter()
                .map(|(kind, mapped, res)| MemoryRegion {
                    kind,
                    mapped_bytes: mapped,
                    resident_bytes: Some(res),
                })
                .collect(),
            rss_bytes: rss_total,
        })
    }

    pub(super) fn mapped_ranges(&self) -> Vec<MappedRange> {
        self.maps
            .iter()
            .filter(|m| m.perms.read)
            .map(|m| MappedRange {
                start: m.start,
                size: m.end - m.start,
                perms: m.perms,
                file: m.path.clone().filter(|p| p.starts_with('/')),
            })
            .collect()
    }

    pub(super) fn modules(&self) -> Vec<Module> {
        self.modules.clone()
    }

    /// The brk heap: the `[heap]` lines of `maps`, first start to last end
    /// (the kernel may list it in pieces).
    pub(super) fn brk_range(&self) -> Option<(u64, u64)> {
        let mut heap = self
            .maps
            .iter()
            .filter(|m| m.path.as_deref() == Some("[heap]"));
        let first = heap.next()?;
        let end = heap.fold(first.end, |e, m| e.max(m.end));
        Some((first.start, end))
    }

    pub(super) fn threads(&self) -> Vec<ThreadInfo> {
        self.threads.clone()
    }

    pub(super) fn memory_summary(&self) -> Option<MemorySummary> {
        self.summary.clone()
    }

    /// Read exactly `buf.len()` bytes, uncached.
    fn read_direct(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: `local` points into `buf`, which outlives the call and is
        // `iov_len` bytes long. The remote side is only read by the kernel.
        let n = unsafe { libc::process_vm_readv(self.pid as i32, &local, 1, &remote, 1, 0) };
        if n >= 0 && n as usize == buf.len() {
            return Ok(());
        }
        if n < 0 && errno() == libc::EPERM {
            return Err(permission_error(self.pid, "process_vm_readv"));
        }
        // Fall back to /proc/<pid>/mem (it can read some mappings that
        // process_vm_readv refuses).
        if let (Some(f), Ok(_)) = (&self.mem, i64::try_from(addr)) {
            if f.read_exact_at(buf, addr).is_ok() {
                return Ok(());
            }
        }
        Err(Error::Unmapped {
            addr,
            len: buf.len(),
        })
    }

    fn block(&self, start: u64) -> Option<Arc<[u8]>> {
        {
            let c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(b) = c.blocks.get(&start) {
                return b.clone();
            }
        }
        let mut v = vec![0u8; BLOCK as usize];
        let b: Option<Arc<[u8]>> = self.read_direct(start, &mut v).ok().map(|()| Arc::from(v));
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if c.order.len() >= MAX_BLOCKS {
            if let Some(old) = c.order.pop_front() {
                c.blocks.remove(&old);
            }
        }
        c.order.push_back(start);
        c.blocks.insert(start, b.clone());
        b
    }

    pub(super) fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let Some(end) = addr.checked_add(buf.len() as u64) else {
            return Err(Error::Unmapped {
                addr,
                len: buf.len(),
            });
        };
        if !self.cached || buf.len() as u64 > BLOCK {
            return self.read_direct(addr, buf);
        }
        let mut cur = addr;
        while cur < end {
            let bstart = cur & !(BLOCK - 1);
            let bend = bstart.saturating_add(BLOCK).min(end);
            let dst = &mut buf[(cur - addr) as usize..(bend - addr) as usize];
            match self.block(bstart) {
                Some(b) => {
                    let o = (cur - bstart) as usize;
                    dst.copy_from_slice(&b[o..o + dst.len()]);
                }
                // The block is not fully readable: read just this piece.
                None => self.read_direct(cur, dst)?,
            }
            cur = bend;
        }
        Ok(())
    }

    pub(super) fn find_symbol<S: MemorySource + ?Sized>(
        &self,
        src: &S,
        module: &Module,
        name: &str,
    ) -> Result<Option<u64>> {
        let mut paths = vec![PathBuf::from(&module.path)];
        paths.push(PathBuf::from(format!(
            "/proc/{}/root{}",
            self.pid, module.path
        )));
        if let Some(m) = self.maps.iter().find(|m| m.start == module.base) {
            paths.push(PathBuf::from(format!(
                "/proc/{}/map_files/{:x}-{:x}",
                self.pid, m.start, m.end
            )));
        }
        symbols::elf::find_with_files(src, module, name, &paths)
    }
}

/// Lets the module scan use the generic helpers (build ids) before the
/// [`super::LiveProcess`] wrapper exists.
impl MemorySource for Inner {
    fn target(&self) -> TargetInfo {
        self.target
    }
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        Inner::read(self, addr, buf)
    }
    fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
        Ok(Inner::mapped_ranges(self))
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Ok(Inner::modules(self))
    }
    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Ok(Inner::threads(self))
    }
    fn memory_summary(&self) -> Option<MemorySummary> {
        Inner::memory_summary(self)
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maps_lines() {
        let m = parse_maps(
            "00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/python3.12\n\
             7ffd1000-7ffd2000 rw-p 00000000 00:00 0           [stack]\n\
             7f00-7f10 rw-p 00000000 00:00 0\n\
             garbage line\n",
        );
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].start, 0x7f00);
        assert!(m[0].path.is_none());
        assert_eq!(m[1].path.as_deref(), Some("/usr/bin/python3.12"));
        assert!(m[1].perms.exec && !m[1].perms.write);
        assert_eq!(m[1].inode, 173521);
        assert_eq!(m[2].path.as_deref(), Some("[stack]"));
        assert_eq!(
            kib_field("Rss:                 128 kB", "Rss:"),
            Some(128 * 1024)
        );
    }

    #[test]
    fn attach_to_missing_pid_fails_cleanly() {
        assert!(matches!(
            Inner::attach(u32::MAX - 7),
            Err(Error::NoSuchProcess(_))
        ));
        assert!(matches!(
            Inner::attach(std::process::id()),
            Err(Error::Unsupported(_))
        ));
    }

    /// Attach to a child we spawn, read its memory, and resume it. Needs
    /// ptrace permission over our own children, which `ptrace_scope` 0 or 1
    /// allows; skipped otherwise.
    #[test]
    fn attach_read_and_resume_child() {
        let mut child = match std::process::Command::new("sleep").arg("30").spawn() {
            Ok(c) => c,
            Err(_) => return,
        };
        let pid = child.id();
        let r = Inner::attach(pid);
        let inner = match r {
            Ok(i) => i,
            Err(Error::PermissionDenied(_)) => {
                let _ = child.kill();
                return;
            }
            Err(e) => panic!("{e}"),
        };
        // The child is stopped: its state in /proc is 't' (tracing stop).
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let state = stat
            .rsplit(')')
            .next()
            .unwrap()
            .trim()
            .chars()
            .next()
            .unwrap();
        assert_eq!(state, 't', "{stat}");
        let mods = inner.modules();
        assert!(!mods.is_empty());
        let mut magic = [0u8; 4];
        inner.read(mods[0].base, &mut magic).unwrap();
        assert_eq!(&magic, b"\x7fELF");
        assert!(inner.read(0, &mut magic).is_err());
        assert!(!inner.threads().is_empty());
        assert!(inner.memory_summary().unwrap().rss_bytes.unwrap() > 0);
        assert!(inner.detach().is_some());
        assert!(inner.detach().is_none());
        drop(inner);
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let state = stat
            .rsplit(')')
            .next()
            .unwrap()
            .trim()
            .chars()
            .next()
            .unwrap();
        assert_ne!(state, 't', "{stat}");
        let _ = child.kill();
        let _ = child.wait();
    }
}
