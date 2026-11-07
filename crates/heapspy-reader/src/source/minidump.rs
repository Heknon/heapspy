//! Windows minidumps (`.dmp`), as written by `MiniDumpWriteDump`, procdump,
//! Task Manager ("Create dump file") and WER.
//!
//! The parser is pure Rust and runs on any host, so a dump taken on Windows
//! can be converted to a snapshot on Linux. The file is memory-mapped; only
//! the stream directory and the small metadata streams are decoded at open
//! time. Memory reads copy straight out of the mapping.
//!
//! # Streams used
//!
//! | stream | used for |
//! |---|---|
//! | `Memory64ListStream` (9) | target memory for [`MemorySource::read`]. Present in full-memory dumps only. |
//! | `MemoryListStream` (5) | fallback memory source; see below |
//! | `ModuleListStream` (4) | [`MemorySource::modules`]: name, path, base, size, CodeView build id, file version |
//! | `ThreadListStream` (3) | [`MemorySource::threads`]: TID, TEB (as `tls_base`), stack pointer |
//! | `ThreadNamesStream` (24) | thread names (`SetThreadDescription`), if present |
//! | `MemoryInfoListStream` (16) | protection and type of each region, for [`MemorySource::mapped_ranges`] and [`MemorySource::memory_summary`] |
//! | `SystemInfoStream` (7) | CPU architecture and OS |
//! | `MiscInfoStream` (15) | process id and creation time |
//!
//! The header's `TimeDateStamp` is [`MemorySource::captured_at`].
//!
//! # Full and partial dumps
//!
//! Only a full-memory dump (`MiniDumpWithFullMemory`, `procdump -ma`)
//! contains the Python heap. Such a dump has a `Memory64ListStream`.
//! Smaller dumps (`procdump -mp`, default WER dumps) carry a
//! `MemoryListStream` with thread stacks and a few referenced pages, which
//! is not enough to walk the object graph. [`Minidump::open`] rejects them
//! with an error that says so; [`Minidump::open_with`] and
//! [`MinidumpOptions::allow_partial_memory`] open them anyway, for looking at
//! modules and threads.
//!
//! # Robustness
//!
//! Every offset, size and count in the file is bounds-checked. A truncated
//! or corrupt file produces [`Error::Format`]; nothing in this module
//! panics on malformed input.

use std::fmt;
use std::fs::File;
use std::path::Path;

use heapspy_snapshot::{Arch, MemoryRegion, Os, RegionKind};

use super::{
    MappedRange, MemorySource, MemorySourceExt, MemorySummary, Module, Perms, TargetInfo,
    ThreadInfo,
};
use crate::error::{Error, Result};

#[cfg(test)]
mod core_convert;
mod parse;
#[cfg(test)]
pub(crate) mod synth;
#[cfg(test)]
mod tests;

use parse::{bad, cpu, stream, Bytes};

/// Options for [`Minidump::open_with`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinidumpOptions {
    /// Accept a dump without a `Memory64ListStream` and read memory from its
    /// `MemoryListStream` instead. Such dumps do not contain the heap, so a
    /// CPython walk over them fails or finds almost nothing. Off by default.
    pub allow_partial_memory: bool,
}

/// `MEMORY_BASIC_INFORMATION` constants used in [`MemoryInfo`].
pub mod mem {
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_FREE: u32 = 0x1_0000;
    pub const MEM_PRIVATE: u32 = 0x2_0000;
    pub const MEM_MAPPED: u32 = 0x4_0000;
    pub const MEM_IMAGE: u32 = 0x100_0000;

    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_WRITECOPY: u32 = 0x08;
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    pub const PAGE_GUARD: u32 = 0x100;
}

/// One region from `MemoryInfoListStream` (the target's `VirtualQueryEx`
/// view at capture time). See [`mem`] for the constant values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryInfo {
    pub base: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub size: u64,
    /// `MEM_COMMIT`, `MEM_RESERVE` or `MEM_FREE`.
    pub state: u32,
    /// `PAGE_*` protection of the region.
    pub protect: u32,
    /// `MEM_PRIVATE`, `MEM_MAPPED` or `MEM_IMAGE` (0 for free regions).
    pub kind: u32,
}

impl MemoryInfo {
    pub fn is_committed(&self) -> bool {
        self.state == mem::MEM_COMMIT
    }

    pub fn perms(&self) -> Perms {
        use mem::*;
        let p = self.protect;
        if p & (PAGE_GUARD | PAGE_NOACCESS) != 0 {
            return Perms::default();
        }
        Perms {
            read: p
                & (PAGE_READONLY
                    | PAGE_READWRITE
                    | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY)
                != 0,
            write: p
                & (PAGE_READWRITE
                    | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY)
                != 0,
            exec: p
                & (PAGE_EXECUTE
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY)
                != 0,
        }
    }

    fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }
}

/// Committed-memory totals from `MemoryInfoListStream`, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryTotals {
    /// All committed memory (`MEM_COMMIT`).
    pub committed: u64,
    /// Reserved but not committed (`MEM_RESERVE`).
    pub reserved: u64,
    /// Committed `MEM_PRIVATE` memory (heaps, pymalloc arenas, stacks, ...).
    pub private: u64,
    /// Committed `MEM_IMAGE` memory (the EXE and DLLs).
    pub image: u64,
    /// Committed `MEM_MAPPED` memory (file and section views).
    pub mapped: u64,
    /// Bytes of memory the dump actually contains.
    pub captured: u64,
}

/// A module entry with the minidump-specific fields that [`Module`] does not
/// carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinidumpModule {
    pub module: Module,
    /// `VS_FIXEDFILEINFO` file version as `[major, minor, build, revision]`,
    /// e.g. `[3, 12, 4150, 1013]` for `python312.dll` 3.12.4. See
    /// [`crate::symbols::pe::python_version_from_file_version`].
    pub file_version: Option<[u16; 4]>,
    /// PE `TimeDateStamp` of the image.
    pub timestamp: u32,
    /// PE checksum of the image.
    pub checksum: u32,
    /// PDB file name from the CodeView record.
    pub pdb_name: Option<String>,
}

/// The fields of `SystemInfoStream` that heapspy exposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemInfo {
    /// `PROCESSOR_ARCHITECTURE_*`: 9 for AMD64, 12 for ARM64.
    pub processor_architecture: u16,
    pub number_of_processors: u8,
    /// OS version, e.g. 10.0.22631.
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    /// 2 (`VER_PLATFORM_WIN32_NT`) for Windows.
    pub platform_id: u32,
}

/// A captured memory range, validated at open: `start + size` does not
/// overflow and `file_off + size` is within the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Range {
    start: u64,
    size: u64,
    file_off: usize,
}

impl Range {
    fn end(&self) -> u64 {
        self.start + self.size
    }
}

enum Data {
    /// `_file` keeps the file open for as long as the mapping lives (the
    /// Windows live backend relies on this for delete-on-close temp files).
    Mapped {
        map: memmap2::Mmap,
        _file: File,
    },
    Owned(Vec<u8>),
}

impl Data {
    fn bytes(&self) -> &[u8] {
        match self {
            Data::Mapped { map, .. } => map,
            Data::Owned(v) => v,
        }
    }
}

/// An opened minidump. See the module docs.
pub struct Minidump {
    data: Data,
    target: TargetInfo,
    full_memory: bool,
    /// Sorted by start, non-overlapping, non-empty.
    ranges: Vec<Range>,
    modules: Vec<MinidumpModule>,
    threads: Vec<ThreadInfo>,
    /// Start address of each thread's captured stack, for classifying regions.
    stack_starts: Vec<u64>,
    /// Sorted by base address.
    memory_info: Vec<MemoryInfo>,
    system: SystemInfo,
    process_id: Option<u32>,
    process_create_time: Option<u32>,
    timestamp: u32,
    flags: u64,
    /// Working set of the process when it was dumped, if whoever captured it
    /// also asked the OS (see [`Minidump::set_rss_bytes`]). A minidump file
    /// does not record residency itself.
    rss_bytes: Option<u64>,
}

impl fmt::Debug for Minidump {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Minidump")
            .field("bytes", &self.data.bytes().len())
            .field("target", &self.target)
            .field("full_memory", &self.full_memory)
            .field("ranges", &self.ranges.len())
            .field("modules", &self.modules.len())
            .field("threads", &self.threads.len())
            .field("process_id", &self.process_id)
            .finish_non_exhaustive()
    }
}

impl Minidump {
    /// Record the process's working set at capture time, which the dump file
    /// itself does not carry. Live capture knows it; a dump opened from disk
    /// does not.
    pub fn set_rss_bytes(&mut self, rss: Option<u64>) {
        self.rss_bytes = rss;
    }

    /// Open a full-memory minidump. Fails with [`Error::Format`] if the dump
    /// has no `Memory64ListStream` (it was not written with full memory).
    pub fn open(path: &Path) -> Result<Minidump> {
        Self::open_with(path, MinidumpOptions::default())
    }

    /// Open a minidump with explicit options.
    pub fn open_with(path: &Path, opts: MinidumpOptions) -> Result<Minidump> {
        Self::from_file(File::open(path)?, opts)
    }

    /// Map and parse an already opened file. The file must stay unmodified
    /// while the `Minidump` lives.
    pub fn from_file(file: File, opts: MinidumpOptions) -> Result<Minidump> {
        let len = file.metadata()?.len();
        if len < parse::HEADER_SIZE {
            return Err(bad(format_args!(
                "file is {len} bytes, shorter than the 32-byte header"
            )));
        }
        // SAFETY: the mapping is read-only. As with any file mapping, another
        // process truncating or rewriting the file while it is mapped is
        // undefined behaviour; heapspy only maps dumps it was pointed at or
        // wrote itself, and documents that they must not change while open.
        #[allow(unsafe_code)]
        let map = unsafe { memmap2::Mmap::map(&file)? };
        Self::parse(Data::Mapped { map, _file: file }, opts)
    }

    /// Parse a minidump held in memory.
    pub fn from_bytes(bytes: Vec<u8>, opts: MinidumpOptions) -> Result<Minidump> {
        Self::parse(Data::Owned(bytes), opts)
    }

    fn parse(data: Data, opts: MinidumpOptions) -> Result<Minidump> {
        let file = Bytes(data.bytes());
        let header = parse::header(file)?;
        let dir = parse::directory(file, &header)?;
        // If a stream type appears more than once, the first entry wins.
        let find = |ty: u32| dir.iter().find(|e| e.stream_type == ty).map(|e| e.loc);

        let sys_loc = find(stream::SYSTEM_INFO)
            .ok_or_else(|| bad("no SystemInfoStream; cannot tell the CPU architecture"))?;
        let sys = parse::system_info(file, sys_loc)?;
        let target = target_info(&sys)?;

        let (raw_ranges, full_memory) =
            match find(stream::MEMORY64_LIST) {
                Some(loc) => (parse::memory64_list(file, loc)?, true),
                None if opts.allow_partial_memory => match find(stream::MEMORY_LIST) {
                    Some(loc) => (parse::memory_list(file, loc)?, false),
                    None => (Vec::new(), false),
                },
                None => return Err(bad(
                    "no Memory64ListStream: this is not a full-memory dump, so the Python heap \
                     is not in it. Capture with `procdump -ma <pid>` (or MiniDumpWriteDump with \
                     MiniDumpWithFullMemory); see docs/windows.md",
                )),
            };
        let ranges = normalize_ranges(raw_ranges)?;

        let modules = match find(stream::MODULE_LIST) {
            Some(loc) => parse::module_list(file, loc)?
                .into_iter()
                .map(module_from_raw)
                .collect(),
            None => Vec::new(),
        };

        let names = match find(stream::THREAD_NAMES) {
            Some(loc) => parse::thread_names(file, loc)?,
            None => Vec::new(),
        };
        let (threads, stack_starts) = match find(stream::THREAD_LIST) {
            Some(loc) => {
                let raw = parse::thread_list(file, loc)?;
                let starts = raw.iter().map(|t| t.stack_start).collect();
                let threads = raw
                    .into_iter()
                    .map(|t| {
                        let ctx = t.context.data(file, "thread context")?;
                        Ok(ThreadInfo {
                            tid: t.tid.into(),
                            name: names
                                .iter()
                                .find(|(tid, n)| *tid == t.tid && !n.is_empty())
                                .map(|(_, n)| n.clone()),
                            tls_base: (t.teb != 0).then_some(t.teb),
                            stack_pointer: parse::context_stack_pointer(
                                ctx,
                                sys.processor_architecture,
                            ),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                (threads, starts)
            }
            None => (Vec::new(), Vec::new()),
        };

        let mut memory_info: Vec<MemoryInfo> = match find(stream::MEMORY_INFO_LIST) {
            Some(loc) => parse::memory_info_list(file, loc)?
                .into_iter()
                .map(|r| MemoryInfo {
                    base: r.base,
                    allocation_base: r.allocation_base,
                    allocation_protect: r.allocation_protect,
                    size: r.size,
                    state: r.state,
                    protect: r.protect,
                    kind: r.kind,
                })
                .collect(),
            None => Vec::new(),
        };
        memory_info.sort_by_key(|m| m.base);

        let (process_id, process_create_time) = match find(stream::MISC_INFO) {
            Some(loc) => parse::misc_info(file, loc)?,
            None => (None, None),
        };

        Ok(Minidump {
            rss_bytes: None,
            data,
            target,
            full_memory,
            ranges,
            modules,
            threads,
            stack_starts,
            memory_info,
            system: SystemInfo {
                processor_architecture: sys.processor_architecture,
                number_of_processors: sys.number_of_processors,
                major_version: sys.major_version,
                minor_version: sys.minor_version,
                build_number: sys.build_number,
                platform_id: sys.platform_id,
            },
            process_id,
            process_create_time,
            timestamp: header.timestamp,
            flags: header.flags,
        })
    }

    /// Whether memory came from `Memory64ListStream` (a full-memory dump).
    /// `false` only for dumps opened with
    /// [`MinidumpOptions::allow_partial_memory`].
    pub fn is_full_memory(&self) -> bool {
        self.full_memory
    }

    /// Modules with their minidump-specific fields (file version, PDB name).
    pub fn module_details(&self) -> &[MinidumpModule] {
        &self.modules
    }

    /// Regions from `MemoryInfoListStream`, sorted by base. Empty if the dump
    /// has no such stream.
    pub fn memory_info(&self) -> &[MemoryInfo] {
        &self.memory_info
    }

    /// Committed-memory totals, or `None` without `MemoryInfoListStream`.
    pub fn memory_totals(&self) -> Option<MemoryTotals> {
        if self.memory_info.is_empty() {
            return None;
        }
        let mut t = MemoryTotals {
            captured: self.ranges.iter().map(|r| r.size).sum(),
            ..MemoryTotals::default()
        };
        for m in &self.memory_info {
            match m.state {
                mem::MEM_COMMIT => {
                    t.committed = t.committed.saturating_add(m.size);
                    match m.kind {
                        mem::MEM_PRIVATE => t.private = t.private.saturating_add(m.size),
                        mem::MEM_IMAGE => t.image = t.image.saturating_add(m.size),
                        mem::MEM_MAPPED => t.mapped = t.mapped.saturating_add(m.size),
                        _ => {}
                    }
                }
                mem::MEM_RESERVE => t.reserved = t.reserved.saturating_add(m.size),
                _ => {}
            }
        }
        Some(t)
    }

    pub fn system_info(&self) -> SystemInfo {
        self.system
    }

    /// Process id from `MiscInfoStream`.
    pub fn process_id(&self) -> Option<u32> {
        self.process_id
    }

    /// Process creation time (Unix seconds) from `MiscInfoStream`.
    pub fn process_create_time(&self) -> Option<u32> {
        self.process_create_time
    }

    /// `MINIDUMP_HEADER.Flags`: the `MINIDUMP_TYPE` the dump was written with.
    pub fn dump_flags(&self) -> u64 {
        self.flags
    }

    fn info_at(&self, addr: u64) -> Option<&MemoryInfo> {
        let i = self.memory_info.partition_point(|m| m.base <= addr);
        let m = self.memory_info.get(i.checked_sub(1)?)?;
        (addr < m.end()).then_some(m)
    }

    /// Allocation bases of the process heaps, read from the PEB through the
    /// first thread's TEB. Empty if anything along the way is not readable.
    fn process_heaps(&self) -> Vec<u64> {
        // 64-bit TEB.ProcessEnvironmentBlock, PEB.NumberOfHeaps and
        // PEB.ProcessHeaps (same layout on AMD64 and ARM64).
        const TEB_PEB: u64 = 0x60;
        const PEB_NUMBER_OF_HEAPS: u64 = 0xe8;
        const PEB_PROCESS_HEAPS: u64 = 0xf0;
        const MAX_HEAPS: u32 = 4096;
        if self.target.os != Os::Windows || self.target.pointer_size != 8 {
            return Vec::new();
        }
        let Some(teb) = self.threads.iter().find_map(|t| t.tls_base) else {
            return Vec::new();
        };
        let heaps = || -> Result<Vec<u64>> {
            let peb = self.read_ptr(teb.checked_add(TEB_PEB).ok_or(bad("TEB"))?)?;
            let n = self.read_u32(peb.wrapping_add(PEB_NUMBER_OF_HEAPS))?;
            let list = self.read_ptr(peb.wrapping_add(PEB_PROCESS_HEAPS))?;
            self.read_ptrs(list, n.min(MAX_HEAPS) as usize)
        };
        heaps().unwrap_or_default()
    }
}

fn target_info(sys: &parse::RawSystemInfo) -> Result<TargetInfo> {
    // Breakpad uses these PlatformId values for non-Windows dumps.
    const PLATFORM_MAC: u32 = 0x8101;
    const PLATFORM_LINUX: u32 = 0x8201;
    let arch = match sys.processor_architecture {
        cpu::AMD64 => Arch::X86_64,
        cpu::ARM64 => Arch::Aarch64,
        cpu::INTEL => return Err(Error::Unsupported("32-bit x86 minidumps".into())),
        cpu::ARM => return Err(Error::Unsupported("32-bit ARM minidumps".into())),
        other => {
            return Err(Error::Unsupported(format!(
                "minidump processor architecture {other}"
            )))
        }
    };
    let os = match sys.platform_id {
        PLATFORM_LINUX => Os::Linux,
        PLATFORM_MAC => Os::Macos,
        _ => Os::Windows,
    };
    Ok(TargetInfo {
        os,
        arch,
        pointer_size: 8,
        little_endian: true,
    })
}

/// Sort ranges, drop empty ones, and trim overlaps (the earlier range wins),
/// so that `read` can binary-search them.
fn normalize_ranges(mut raw: Vec<parse::RawRange>) -> Result<Vec<Range>> {
    raw.sort_by_key(|r| r.start);
    let mut out: Vec<Range> = Vec::with_capacity(raw.len());
    for r in raw {
        let (mut start, mut size, mut off) = (r.start, r.size, r.file_off);
        if let Some(prev) = out.last() {
            let prev_end = prev.end();
            if start < prev_end {
                let skip = prev_end - start;
                if skip >= size {
                    continue;
                }
                start += skip;
                size -= skip;
                off += skip;
            }
        }
        if size == 0 {
            continue;
        }
        let file_off = usize::try_from(off).map_err(|_| bad("memory range offset too large"))?;
        out.push(Range {
            start,
            size,
            file_off,
        });
    }
    Ok(out)
}

fn module_from_raw(m: parse::RawModule) -> MinidumpModule {
    let name = m
        .name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&m.name)
        .to_string();
    let file_version = m
        .file_version
        .map(|(ms, ls)| [(ms >> 16) as u16, ms as u16, (ls >> 16) as u16, ls as u16]);
    let (build_id, pdb_name) = match m.codeview {
        Some(cv) => (Some(cv.build_id), cv.pdb_name),
        None => (None, None),
    };
    MinidumpModule {
        module: Module {
            name,
            path: m.name,
            base: m.base,
            size: m.size.into(),
            build_id,
        },
        file_version,
        timestamp: m.timestamp,
        checksum: m.checksum,
        pdb_name,
    }
}

impl MemorySource for Minidump {
    fn target(&self) -> TargetInfo {
        self.target
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let len = buf.len();
        let unmapped = || Error::Unmapped { addr, len };
        let end = addr.checked_add(len as u64).ok_or_else(unmapped)?;
        let data = self.data.bytes();
        // Plan the copy first so a failed read leaves `buf` untouched.
        let first = self.ranges.partition_point(|r| r.end() <= addr);
        let mut cur = addr;
        let mut last = first;
        while cur < end {
            match self.ranges.get(last) {
                Some(r) if r.start <= cur => {
                    cur = end.min(r.end());
                    last += 1;
                }
                _ => return Err(unmapped()),
            }
        }
        let mut cur = addr;
        for r in &self.ranges[first..last] {
            let take_end = end.min(r.end());
            let n = (take_end - cur) as usize;
            let off = r.file_off + (cur - r.start) as usize;
            let src = data.get(off..off + n).ok_or_else(unmapped)?;
            let dst = (cur - addr) as usize;
            buf[dst..dst + n].copy_from_slice(src);
            cur = take_end;
        }
        Ok(())
    }

    fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
        Ok(self
            .ranges
            .iter()
            .map(|r| {
                let info = self.info_at(r.start);
                let perms = info.map(MemoryInfo::perms).unwrap_or(Perms {
                    read: true,
                    write: false,
                    exec: false,
                });
                let file = info
                    .filter(|i| i.kind == mem::MEM_IMAGE)
                    .and_then(|_| self.modules.iter().find(|m| m.module.contains(r.start)))
                    .map(|m| m.module.path.clone());
                MappedRange {
                    start: r.start,
                    size: r.size,
                    perms,
                    file,
                }
            })
            .collect())
    }

    fn modules(&self) -> Result<Vec<Module>> {
        Ok(self.modules.iter().map(|m| m.module.clone()).collect())
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Ok(self.threads.clone())
    }

    /// Committed bytes by kind: `image` (`MEM_IMAGE`), `mapped_file`
    /// (`MEM_MAPPED`), `stack` (private allocations holding a thread stack),
    /// `heap` (private allocations whose base is a process heap listed in the
    /// PEB; this is the first segment of each NT heap), and `anonymous` (all
    /// other private memory, which includes pymalloc arenas). Minidumps do
    /// not record residency, so `resident_bytes` and `rss_bytes` are `None`.
    fn memory_summary(&self) -> Option<MemorySummary> {
        if self.memory_info.is_empty() {
            return None;
        }
        let stack_allocs: Vec<u64> = self
            .stack_starts
            .iter()
            .filter_map(|&s| self.info_at(s).map(|i| i.allocation_base))
            .collect();
        let heaps = self.process_heaps();
        let mut totals = [0u64; 5];
        let kinds = [
            RegionKind::Image,
            RegionKind::MappedFile,
            RegionKind::Stack,
            RegionKind::Heap,
            RegionKind::Anonymous,
        ];
        for m in self.memory_info.iter().filter(|m| m.is_committed()) {
            let slot = match m.kind {
                mem::MEM_IMAGE => 0,
                mem::MEM_MAPPED => 1,
                _ if stack_allocs.contains(&m.allocation_base) => 2,
                _ if heaps.contains(&m.allocation_base) => 3,
                _ => 4,
            };
            totals[slot] = totals[slot].saturating_add(m.size);
        }
        Some(MemorySummary {
            regions: kinds
                .into_iter()
                .zip(totals)
                .map(|(kind, mapped_bytes)| MemoryRegion {
                    kind,
                    mapped_bytes,
                    resident_bytes: None,
                })
                .collect(),
            rss_bytes: self.rss_bytes,
        })
    }

    fn captured_at(&self) -> Option<u64> {
        (self.timestamp != 0).then_some(self.timestamp.into())
    }
}
