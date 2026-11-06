//! Linux ELF core files (`gcore`, kernel core dumps).
//!
//! - Memory: `PT_LOAD` program headers, indexed in a sorted range map. The
//!   kernel and gdb leave out mappings they do not dump: unmodified
//!   file-backed mappings (code, `.rodata`, the rest of a library after its
//!   first page) get `p_filesz == 0`, or `p_filesz` of one page when only
//!   the ELF header page was kept. Those bytes are read from the mapped file
//!   on disk, at the path and offset the `NT_FILE` note gives, if the file
//!   is there. Otherwise they read as [`Error::Unmapped`], never as zeros.
//!   This is what makes static type objects' `tp_name` strings, `.dynsym`
//!   and the like readable from a default `gcore`. It assumes the files on
//!   disk are the ones the process had mapped.
//! - Modules: the `NT_FILE` note lists file-backed mappings; they are
//!   grouped by path, `base` is the mapping at file offset 0, and only
//!   files with an ELF header there count. The main executable (the one
//!   holding `AT_ENTRY` from `NT_AUXV`) comes first. Build ids come from the
//!   `NT_GNU_BUILD_ID` note inside each mapped image.
//! - Threads: `NT_PRSTATUS` notes (one per thread; `pr_pid` is the TID).
//!   On x86_64 the stack pointer and `fs_base` come from `pr_reg`.
//! - Memory summary: mapped totals by region kind; a core has no residency
//!   information, so `resident_bytes` is `None`.
//! - `captured_at`: the core file's mtime.
//!
//! The core is memory-mapped; nothing is copied up front. Corrupt input is
//! reported as [`Error::Format`], never a panic.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use heapspy_snapshot::{Arch, MemoryRegion, Os, RegionKind};
use memmap2::Mmap;

use super::{MappedRange, MemorySource, MemorySummary, Module, Perms, TargetInfo, ThreadInfo};
use crate::error::{Error, Result};
use crate::symbols;

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const ET_CORE: u16 = 4;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const NT_PRSTATUS: u32 = 1;
const NT_AUXV: u32 = 6;
const NT_FILE: u32 = 0x4649_4c45;
const AT_ENTRY: u64 = 9;
/// Offset of `pr_pid` and `pr_reg` in the 64-bit `elf_prstatus`.
const PRSTATUS_PID: usize = 32;
const PRSTATUS_REG: usize = 112;

/// One `PT_LOAD` segment.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Segment {
    vaddr: u64,
    memsz: u64,
    offset: u64,
    filesz: u64,
    perms: Perms,
}

/// One `NT_FILE` entry: `[start, end)` maps `path` from byte `offset`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileMapping {
    start: u64,
    end: u64,
    offset: u64,
    path: usize,
}

/// An opened ELF core file.
pub struct ElfCore {
    target: TargetInfo,
    path: PathBuf,
    data: Mmap,
    /// Sorted by `vaddr`, non-overlapping (overlaps are dropped on open).
    segments: Vec<Segment>,
    /// Sorted by `start`.
    files: Vec<FileMapping>,
    paths: Vec<String>,
    modules: Vec<Module>,
    threads: Vec<ThreadInfo>,
    captured_at: Option<u64>,
    /// Bytes of `PT_LOAD` data that the program headers place past the end of
    /// the file (a core cut short by `RLIMIT_CORE`, a full disk, or a copy).
    missing_bytes: u64,
    /// Mapped module files, opened on first use. `None`: missing or unreadable.
    file_cache: Mutex<HashMap<usize, Option<Arc<Mmap>>>>,
}

impl std::fmt::Debug for ElfCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElfCore")
            .field("path", &self.path)
            .field("target", &self.target)
            .field("segments", &self.segments.len())
            .field("files", &self.files.len())
            .field("modules", &self.modules.len())
            .field("threads", &self.threads.len())
            .finish()
    }
}

fn fmt_err(msg: impl Into<String>) -> Error {
    Error::Format(msg.into())
}

/// Little-endian field readers over a byte slice that fail instead of panicking.
fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o.checked_add(2).ok_or_else(|| fmt_err("offset overflow"))?)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| fmt_err(format!("truncated at {o:#x}")))
}
fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o.checked_add(4).ok_or_else(|| fmt_err("offset overflow"))?)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| fmt_err(format!("truncated at {o:#x}")))
}
fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    b.get(o..o.checked_add(8).ok_or_else(|| fmt_err("offset overflow"))?)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| fmt_err(format!("truncated at {o:#x}")))
}

/// A parsed note: type and descriptor bytes.
struct Note<'a> {
    ntype: u32,
    name: &'a [u8],
    desc: &'a [u8],
}

fn parse_notes(seg: &[u8]) -> Vec<Note<'_>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 12 <= seg.len() {
        let (Ok(namesz), Ok(descsz), Ok(ntype)) =
            (u32_at(seg, pos), u32_at(seg, pos + 4), u32_at(seg, pos + 8))
        else {
            break;
        };
        let (namesz, descsz) = (namesz as usize, descsz as usize);
        let name_start = pos + 12;
        let Some(desc_start) = namesz
            .checked_add(3)
            .map(|n| name_start + (n & !3))
            .filter(|&d| d <= seg.len())
        else {
            break;
        };
        let Some(next) = descsz
            .checked_add(3)
            .and_then(|n| desc_start.checked_add(n & !3))
        else {
            break;
        };
        let (Some(name), Some(desc)) = (
            seg.get(name_start..name_start + namesz),
            desc_start
                .checked_add(descsz)
                .and_then(|e| seg.get(desc_start..e)),
        ) else {
            break;
        };
        out.push(Note { ntype, name, desc });
        pos = next;
    }
    out
}

fn parse_nt_file(desc: &[u8]) -> Result<(Vec<FileMapping>, Vec<String>)> {
    let count = u64_at(desc, 0)? as usize;
    let page = u64_at(desc, 8)?;
    if count > desc.len() / 24 {
        return Err(fmt_err(format!("NT_FILE claims {count} entries")));
    }
    let mut maps = Vec::with_capacity(count);
    let mut names_at = 16 + count * 24;
    let mut paths: Vec<String> = Vec::new();
    let mut path_ids: HashMap<String, usize> = HashMap::new();
    for i in 0..count {
        let e = 16 + i * 24;
        let (start, end, pgoff) = (
            u64_at(desc, e)?,
            u64_at(desc, e + 8)?,
            u64_at(desc, e + 16)?,
        );
        let rest = desc
            .get(names_at..)
            .ok_or_else(|| fmt_err("NT_FILE names truncated"))?;
        let nul = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| fmt_err("NT_FILE name not terminated"))?;
        let name = String::from_utf8_lossy(&rest[..nul]).into_owned();
        names_at += nul + 1;
        if end <= start {
            continue;
        }
        let id = *path_ids.entry(name.clone()).or_insert_with(|| {
            paths.push(name);
            paths.len() - 1
        });
        maps.push(FileMapping {
            start,
            end,
            offset: pgoff.saturating_mul(page),
            path: id,
        });
    }
    maps.sort_by_key(|m| m.start);
    Ok((maps, paths))
}

impl ElfCore {
    /// Open and index a core file.
    pub fn open(path: &Path) -> Result<ElfCore> {
        let file = File::open(path)?;
        let captured_at = file
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        // SAFETY: read-only mapping of a regular file that we do not modify.
        // A core being truncated by someone else while we read it would fault;
        // that is the documented contract of memory-mapped readers.
        let data = unsafe { Mmap::map(&file)? };
        Self::from_mmap(path, data, captured_at)
    }

    fn from_mmap(path: &Path, data: Mmap, captured_at: Option<u64>) -> Result<ElfCore> {
        let b: &[u8] = &data;
        if b.len() < 64 || b[..4] != symbols::elf::ELF_MAGIC {
            return Err(fmt_err(format!("{} is not an ELF file", path.display())));
        }
        if b[4] != 2 {
            return Err(Error::Unsupported("32-bit ELF cores".into()));
        }
        if b[5] != 1 {
            return Err(Error::Unsupported("big-endian ELF cores".into()));
        }
        let e_type = u16_at(b, 0x10)?;
        if e_type != ET_CORE {
            return Err(fmt_err(format!(
                "{} is an ELF file but not a core (e_type {e_type})",
                path.display()
            )));
        }
        let arch = match u16_at(b, 0x12)? {
            EM_X86_64 => Arch::X86_64,
            EM_AARCH64 => Arch::Aarch64,
            m => return Err(Error::Unsupported(format!("ELF machine {m}"))),
        };
        let target = TargetInfo {
            os: Os::Linux,
            arch,
            pointer_size: 8,
            little_endian: true,
        };
        let phoff = u64_at(b, 0x20)? as usize;
        let phentsize = u16_at(b, 0x36)? as usize;
        let mut phnum = u16_at(b, 0x38)? as usize;
        if phnum == 0xffff {
            // PN_XNUM: the real count is in section header 0's sh_info.
            let shoff = u64_at(b, 0x28)? as usize;
            phnum = u32_at(b, shoff.saturating_add(0x2c))? as usize;
        }
        if phentsize < 56 {
            return Err(fmt_err(format!("program header size {phentsize}")));
        }

        let mut segments = Vec::new();
        let mut files = Vec::new();
        let mut paths = Vec::new();
        let mut threads = Vec::new();
        let mut entry = None;
        let mut missing_bytes = 0u64;
        for i in 0..phnum {
            let ph = phoff
                .checked_add(i.checked_mul(phentsize).ok_or_else(|| fmt_err("phdr"))?)
                .ok_or_else(|| fmt_err("phdr offset overflow"))?;
            let p_type = u32_at(b, ph)?;
            let p_flags = u32_at(b, ph + 4)?;
            let p_offset = u64_at(b, ph + 8)?;
            let p_vaddr = u64_at(b, ph + 0x10)?;
            let p_filesz = u64_at(b, ph + 0x20)?;
            let p_memsz = u64_at(b, ph + 0x28)?;
            match p_type {
                PT_LOAD if p_memsz > 0 => {
                    // Clamp to what is really in the file (truncated cores),
                    // and remember how much is missing.
                    let avail = (b.len() as u64).saturating_sub(p_offset);
                    let want = p_filesz.min(p_memsz);
                    missing_bytes += want.saturating_sub(avail);
                    segments.push(Segment {
                        vaddr: p_vaddr,
                        memsz: p_memsz,
                        offset: p_offset,
                        filesz: want.min(avail),
                        perms: Perms {
                            read: p_flags & 4 != 0,
                            write: p_flags & 2 != 0,
                            exec: p_flags & 1 != 0,
                        },
                    });
                }
                PT_NOTE => {
                    let start = usize::try_from(p_offset).map_err(|_| fmt_err("note offset"))?;
                    let end = start
                        .checked_add(usize::try_from(p_filesz).map_err(|_| fmt_err("note"))?)
                        .ok_or_else(|| fmt_err("note size overflow"))?;
                    let seg = b
                        .get(start..end)
                        .ok_or_else(|| fmt_err("PT_NOTE outside the file"))?;
                    for n in parse_notes(seg) {
                        if n.name != b"CORE\0" && n.name != b"CORE" {
                            continue;
                        }
                        match n.ntype {
                            NT_PRSTATUS => threads.push(parse_prstatus(n.desc, arch)?),
                            NT_FILE => (files, paths) = parse_nt_file(n.desc)?,
                            NT_AUXV => {
                                for kv in n.desc.chunks_exact(16) {
                                    let k = u64::from_le_bytes(kv[..8].try_into().unwrap());
                                    if k == AT_ENTRY {
                                        entry =
                                            Some(u64::from_le_bytes(kv[8..].try_into().unwrap()));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        segments.sort_by_key(|s| s.vaddr);
        // Drop segments that overlap an earlier one; reads must be unambiguous.
        let mut clean: Vec<Segment> = Vec::with_capacity(segments.len());
        for s in segments {
            if let Some(prev) = clean.last() {
                if s.vaddr < prev.vaddr.saturating_add(prev.memsz) {
                    continue;
                }
            }
            clean.push(s);
        }

        let mut core = ElfCore {
            target,
            path: path.to_path_buf(),
            data,
            segments: clean,
            files,
            paths,
            modules: Vec::new(),
            threads,
            captured_at,
            missing_bytes,
            file_cache: Mutex::new(HashMap::new()),
        };
        core.modules = core.build_modules(entry);
        Ok(core)
    }

    fn build_modules(&self, entry: Option<u64>) -> Vec<Module> {
        let mut by_path: HashMap<usize, (Option<u64>, u64)> = HashMap::new();
        for f in &self.files {
            let e = by_path.entry(f.path).or_insert((None, 0));
            if f.offset == 0 {
                e.0 = Some(e.0.map_or(f.start, |b: u64| b.min(f.start)));
            }
            e.1 = e.1.max(f.end);
        }
        let mut mods: Vec<Module> = by_path
            .into_iter()
            .filter_map(|(pid, (base, end))| {
                let base = base?;
                let mut magic = [0u8; 4];
                self.read(base, &mut magic).ok()?;
                if magic != symbols::elf::ELF_MAGIC {
                    return None;
                }
                let path = self.paths[pid].clone();
                Some(Module {
                    name: path.rsplit('/').next().unwrap_or(&path).to_string(),
                    build_id: symbols::elf::read_build_id(self, base),
                    path,
                    base,
                    size: end.saturating_sub(base),
                })
            })
            .collect();
        mods.sort_by_key(|m| m.base);
        if let Some(e) = entry {
            if let Some(i) = mods.iter().position(|m| m.contains(e)) {
                let m = mods.remove(i);
                mods.insert(0, m);
            }
        }
        mods
    }

    /// The core file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn segment_for(&self, addr: u64) -> Option<&Segment> {
        let i = self.segments.partition_point(|s| s.vaddr <= addr);
        let s = self.segments.get(i.checked_sub(1)?)?;
        (addr - s.vaddr < s.memsz).then_some(s)
    }

    fn file_for(&self, addr: u64) -> Option<&FileMapping> {
        let i = self.files.partition_point(|f| f.start <= addr);
        let f = self.files.get(i.checked_sub(1)?)?;
        (addr < f.end).then_some(f)
    }

    fn mapped_file(&self, id: usize) -> Option<Arc<Mmap>> {
        let mut cache = self.file_cache.lock().unwrap_or_else(|e| e.into_inner());
        cache
            .entry(id)
            .or_insert_with(|| {
                let f = File::open(&self.paths[id]).ok()?;
                // SAFETY: read-only mapping of a module file on disk; see
                // the module docs for the assumption that it is unchanged.
                unsafe { Mmap::map(&f) }.ok().map(Arc::new)
            })
            .clone()
    }

    /// Copy what is available at `addr` into `buf`, returning how many bytes
    /// were copied (0 if `addr` is not readable). Never crosses a segment or
    /// file mapping boundary.
    fn read_chunk(&self, addr: u64, buf: &mut [u8]) -> usize {
        let seg = self.segment_for(addr);
        if let Some(s) = seg {
            let rel = addr - s.vaddr;
            if rel < s.filesz {
                let n = ((s.filesz - rel) as usize).min(buf.len());
                let Some(off) = s.offset.checked_add(rel) else {
                    return 0;
                };
                let Some(src) = usize::try_from(off)
                    .ok()
                    .and_then(|o| self.data.get(o..o.checked_add(n)?))
                else {
                    return 0;
                };
                buf[..n].copy_from_slice(src);
                return n;
            }
        }
        // Not dumped: use the backing file if there is one.
        let Some(f) = self.file_for(addr) else {
            return 0;
        };
        let mut limit = f.end - addr;
        if let Some(s) = seg {
            limit = limit.min(s.vaddr + s.memsz - addr);
        } else if let Some(next) = self
            .segments
            .get(self.segments.partition_point(|s| s.vaddr <= addr))
        {
            limit = limit.min(next.vaddr.saturating_sub(addr));
        }
        let Some(m) = self.mapped_file(f.path) else {
            return 0;
        };
        let Some(off) = f.offset.checked_add(addr - f.start) else {
            return 0;
        };
        let Ok(off) = usize::try_from(off) else {
            return 0;
        };
        let n = (limit as usize)
            .min(buf.len())
            .min(m.len().saturating_sub(off));
        if n == 0 {
            return 0;
        }
        buf[..n].copy_from_slice(&m[off..off + n]);
        n
    }

    fn region_kind(&self, start: u64, end: u64) -> RegionKind {
        if let Some(f) = self.file_for(start) {
            let p = &self.paths[f.path];
            return if self.modules.iter().any(|m| &m.path == p) {
                RegionKind::Image
            } else {
                RegionKind::MappedFile
            };
        }
        let on_stack = self
            .threads
            .iter()
            .filter_map(|t| t.stack_pointer)
            .any(|sp| sp >= start && sp < end);
        if on_stack {
            RegionKind::Stack
        } else {
            RegionKind::Anonymous
        }
    }
}

fn parse_prstatus(desc: &[u8], arch: Arch) -> Result<ThreadInfo> {
    let tid = u32_at(desc, PRSTATUS_PID)? as u64;
    let reg = |i: usize| u64_at(desc, PRSTATUS_REG + i * 8).ok();
    let (sp, tls) = match arch {
        // user_regs_struct: rsp is register 19, fs_base 21.
        Arch::X86_64 => (reg(19), reg(21)),
        // user_pt_regs: x0..x30, then sp. TLS is in a separate note.
        Arch::Aarch64 => (reg(31), None),
        _ => (None, None),
    };
    Ok(ThreadInfo {
        tid,
        name: None,
        tls_base: tls.filter(|&t| t != 0),
        stack_pointer: sp,
    })
}

impl MemorySource for ElfCore {
    fn target(&self) -> TargetInfo {
        self.target
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        let unmapped = Error::Unmapped {
            addr,
            len: buf.len(),
        };
        if buf.is_empty() {
            return Ok(());
        }
        if addr.checked_add(buf.len() as u64).is_none() {
            return Err(unmapped);
        }
        let mut done = 0usize;
        while done < buf.len() {
            let n = self.read_chunk(addr + done as u64, &mut buf[done..]);
            if n == 0 {
                return Err(unmapped);
            }
            done += n;
        }
        Ok(())
    }

    fn missing_bytes(&self) -> u64 {
        self.missing_bytes
    }

    fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
        let mut out = Vec::with_capacity(self.segments.len());
        for s in &self.segments {
            let file = self.file_for(s.vaddr).map(|f| self.paths[f.path].clone());
            // Without the file, only the dumped prefix is readable.
            let size =
                if s.filesz < s.memsz && file.as_ref().is_none_or(|p| !Path::new(p).is_file()) {
                    s.filesz
                } else {
                    s.memsz
                };
            if size == 0 {
                continue;
            }
            out.push(MappedRange {
                start: s.vaddr,
                size,
                perms: s.perms,
                file,
            });
        }
        Ok(out)
    }

    fn modules(&self) -> Result<Vec<Module>> {
        Ok(self.modules.clone())
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Ok(self.threads.clone())
    }

    fn memory_summary(&self) -> Option<MemorySummary> {
        if self.segments.is_empty() {
            return None;
        }
        let mut totals: Vec<(RegionKind, u64)> = Vec::new();
        for s in &self.segments {
            let kind = self.region_kind(s.vaddr, s.vaddr.saturating_add(s.memsz));
            match totals.iter_mut().find(|(k, _)| *k == kind) {
                Some((_, n)) => *n += s.memsz,
                None => totals.push((kind, s.memsz)),
            }
        }
        Some(MemorySummary {
            regions: totals
                .into_iter()
                .map(|(kind, mapped_bytes)| MemoryRegion {
                    kind,
                    mapped_bytes,
                    resident_bytes: None,
                })
                .collect(),
            rss_bytes: None,
        })
    }

    fn captured_at(&self) -> Option<u64> {
        self.captured_at
    }

    fn find_symbol(&self, module: &Module, name: &str) -> Result<Option<u64>> {
        symbols::elf::find_with_files(self, module, name, &[PathBuf::from(&module.path)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySourceExt;

    /// Builds a small ELF core in memory: PT_NOTE + PT_LOAD segments.
    struct CoreBuilder {
        loads: Vec<(u64, u64, Vec<u8>)>, // vaddr, memsz, dumped bytes
        notes: Vec<(u32, Vec<u8>)>,
    }

    impl CoreBuilder {
        fn new() -> Self {
            Self {
                loads: Vec::new(),
                notes: Vec::new(),
            }
        }

        fn note_bytes(&self) -> Vec<u8> {
            let mut out = Vec::new();
            for (t, desc) in &self.notes {
                out.extend_from_slice(&5u32.to_le_bytes());
                out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
                out.extend_from_slice(&t.to_le_bytes());
                out.extend_from_slice(b"CORE\0\0\0\0");
                out.extend_from_slice(desc);
                while out.len() % 4 != 0 {
                    out.push(0);
                }
            }
            out
        }

        fn build(&self) -> Vec<u8> {
            let phnum = 1 + self.loads.len();
            let mut f = vec![0u8; 64];
            f[..4].copy_from_slice(b"\x7fELF");
            f[4] = 2;
            f[5] = 1;
            f[6] = 1;
            f[0x10..0x12].copy_from_slice(&ET_CORE.to_le_bytes());
            f[0x12..0x14].copy_from_slice(&EM_X86_64.to_le_bytes());
            f[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
            f[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
            f[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
            f[0x38..0x3a].copy_from_slice(&(phnum as u16).to_le_bytes());
            let notes = self.note_bytes();
            let mut data_off = 64 + 56 * phnum as u64;
            let mut ph = Vec::new();
            let mut body = Vec::new();
            let mut push_ph = |t: u32, off: u64, vaddr: u64, filesz: u64, memsz: u64| {
                let mut p = [0u8; 56];
                p[..4].copy_from_slice(&t.to_le_bytes());
                p[4..8].copy_from_slice(&6u32.to_le_bytes());
                p[8..16].copy_from_slice(&off.to_le_bytes());
                p[16..24].copy_from_slice(&vaddr.to_le_bytes());
                p[32..40].copy_from_slice(&filesz.to_le_bytes());
                p[40..48].copy_from_slice(&memsz.to_le_bytes());
                ph.extend_from_slice(&p);
            };
            push_ph(PT_NOTE, data_off, 0, notes.len() as u64, 0);
            body.extend_from_slice(&notes);
            data_off += notes.len() as u64;
            for (vaddr, memsz, bytes) in &self.loads {
                push_ph(PT_LOAD, data_off, *vaddr, bytes.len() as u64, *memsz);
                body.extend_from_slice(bytes);
                data_off += bytes.len() as u64;
            }
            f.extend_from_slice(&ph);
            f.extend_from_slice(&body);
            f
        }
    }

    fn open_bytes(bytes: &[u8]) -> Result<ElfCore> {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("core");
        std::fs::write(&p, bytes).unwrap();
        ElfCore::open(&p)
    }

    fn prstatus(tid: u32, rsp: u64, fs_base: u64) -> Vec<u8> {
        let mut d = vec![0u8; PRSTATUS_REG + 27 * 8 + 8];
        d[PRSTATUS_PID..PRSTATUS_PID + 4].copy_from_slice(&tid.to_le_bytes());
        d[PRSTATUS_REG + 19 * 8..PRSTATUS_REG + 20 * 8].copy_from_slice(&rsp.to_le_bytes());
        d[PRSTATUS_REG + 21 * 8..PRSTATUS_REG + 22 * 8].copy_from_slice(&fs_base.to_le_bytes());
        d
    }

    fn nt_file(entries: &[(u64, u64, u64, &str)]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        d.extend_from_slice(&4096u64.to_le_bytes());
        for (s, e, pg, _) in entries {
            d.extend_from_slice(&s.to_le_bytes());
            d.extend_from_slice(&e.to_le_bytes());
            d.extend_from_slice(&pg.to_le_bytes());
        }
        for (_, _, _, p) in entries {
            d.extend_from_slice(p.as_bytes());
            d.push(0);
        }
        d
    }

    #[test]
    fn reads_segments_threads_and_modules() {
        let dir = tempfile::tempdir().unwrap();
        // A fake "library": an ELF header page followed by data that the core omits.
        let lib = dir.path().join("libfake.so");
        let mut lib_bytes = vec![0u8; 8192];
        lib_bytes[..4].copy_from_slice(b"\x7fELF");
        lib_bytes[4096..4100].copy_from_slice(b"ROD!");
        std::fs::write(&lib, &lib_bytes).unwrap();
        let lib_s = lib.to_str().unwrap();

        let mut b = CoreBuilder::new();
        b.notes
            .push((NT_PRSTATUS, prstatus(101, 0x7000_0010, 0x1234)));
        b.notes.push((NT_PRSTATUS, prstatus(102, 0x5000, 0)));
        b.notes.push((
            NT_FILE,
            nt_file(&[
                (0x40_0000, 0x40_2000, 0, lib_s),
                (0x9000_0000, 0x9000_1000, 0, "/nonexistent/data"),
            ]),
        ));
        // Header page dumped, rest of the library mapping omitted.
        b.loads
            .push((0x40_0000, 0x2000, lib_bytes[..4096].to_vec()));
        b.loads.push((0x7000_0000, 0x20, (0u8..0x20).collect()));
        b.loads.push((0x7000_0020, 0x10, vec![0xaa; 0x10]));
        // Not dumped and the file is missing: must read as unmapped.
        b.loads.push((0x9000_0000, 0x1000, Vec::new()));
        let core = open_bytes(&b.build()).unwrap();

        assert_eq!(core.read_u8(0x7000_0003).unwrap(), 3);
        // Spans two adjacent segments.
        let v = core.read_vec(0x7000_001e, 4).unwrap();
        assert_eq!(v, [0x1e, 0x1f, 0xaa, 0xaa]);
        assert!(matches!(
            core.read_vec(0x7000_002e, 4),
            Err(Error::Unmapped { .. })
        ));
        assert!(core.read_vec(0x6fff_ffff, 2).is_err());
        assert!(core.read_vec(u64::MAX - 1, 4).is_err());
        // Omitted file-backed bytes come from the file on disk.
        assert_eq!(core.read_vec(0x40_1000, 4).unwrap(), b"ROD!");
        assert!(core.read_u8(0x9000_0000).is_err());

        let th = core.threads().unwrap();
        assert_eq!(th.len(), 2);
        assert_eq!(th[0].tid, 101);
        assert_eq!(th[0].stack_pointer, Some(0x7000_0010));
        assert_eq!(th[0].tls_base, Some(0x1234));

        let mods = core.modules().unwrap();
        assert_eq!(mods.len(), 1, "{mods:?}");
        assert_eq!(mods[0].name, "libfake.so");
        assert_eq!(mods[0].base, 0x40_0000);
        assert_eq!(mods[0].size, 0x2000);

        let s = core.memory_summary().unwrap();
        let get = |k| {
            s.regions
                .iter()
                .find(|r| r.kind == k)
                .map(|r| r.mapped_bytes)
        };
        assert_eq!(get(RegionKind::Image), Some(0x2000));
        assert_eq!(get(RegionKind::Stack), Some(0x20));
        assert_eq!(get(RegionKind::MappedFile), Some(0x1000));
        assert!(s.regions.iter().all(|r| r.resident_bytes.is_none()));

        let ranges = core.mapped_ranges().unwrap();
        assert!(ranges.windows(2).all(|w| w[0].start < w[1].start));
        assert!(!ranges.iter().any(|r| r.start == 0x9000_0000));
        assert!(core.captured_at().is_some());
    }

    #[test]
    fn a_cut_core_reports_its_missing_bytes() {
        let mut b = CoreBuilder::new();
        b.notes.push((NT_PRSTATUS, prstatus(1, 0, 0)));
        b.loads.push((0x1000, 0x100, vec![1; 0x100]));
        b.loads.push((0x2000, 0x100, vec![2; 0x100]));
        let full = b.build();
        let core = open_bytes(&full).unwrap();
        assert_eq!(core.missing_bytes(), 0);

        // Cut 0x30 bytes into the second segment: 0xd0 of it are gone.
        let cut = &full[..full.len() - 0xd0];
        let core = open_bytes(cut).unwrap();
        assert_eq!(core.missing_bytes(), 0xd0);
        assert_eq!(core.read_u8(0x202f).unwrap(), 2);
        assert!(core.read_u8(0x2030).is_err());

        // Cut before the second segment starts: all of it is gone.
        let core = open_bytes(&full[..full.len() - 0x100]).unwrap();
        assert_eq!(core.missing_bytes(), 0x100);
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        assert!(open_bytes(b"").is_err());
        assert!(open_bytes(
            b"not an elf file at all, just some bytes padding out to 64 bytes......"
        )
        .is_err());
        let good = {
            let mut b = CoreBuilder::new();
            b.notes.push((NT_PRSTATUS, prstatus(1, 0, 0)));
            b.notes
                .push((NT_FILE, nt_file(&[(0x1000, 0x2000, 0, "/x")])));
            b.loads.push((0x1000, 0x10, vec![1; 0x10]));
            b.build()
        };
        assert!(open_bytes(&good).is_ok());
        // Truncate and corrupt at every position: never panic.
        for cut in 0..good.len() {
            let _ = open_bytes(&good[..cut]);
        }
        let mut x: u32 = 12345;
        for i in 0..good.len() {
            let mut bad = good.clone();
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            bad[i] ^= (x >> 16) as u8 | 1;
            if let Ok(c) = open_bytes(&bad) {
                let _ = c.read_vec(0x1000, 0x10);
                let _ = c.modules();
                let _ = c.memory_summary();
            }
        }
    }
}
