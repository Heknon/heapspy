//! Memory sources: where the target's memory comes from.
//!
//! A [`MemorySource`] is a read-only view of one process's address space at
//! one point in time, plus the metadata a CPython walker needs to find its
//! way in (loaded modules, threads, memory map). Backends:
//!
//! | module | source | status |
//! |---|---|---|
//! | [`elf_core`] | Linux ELF core file (`gcore`, kernel core dump) | implemented |
//! | [`linux_live`] | live Linux process via `process_vm_readv` | implemented |
//! | [`minidump`] | Windows full-memory minidump | stub |
//! | [`mem`] | in-memory segments, for tests | implemented |
//!
//! # Contract for implementers
//!
//! - **Consistency.** All reads must observe one consistent image. File
//!   backends get this for free. A live backend must stop the target (all
//!   threads) before the first read and keep it stopped until the source is
//!   dropped.
//! - **Reads are all-or-nothing.** [`MemorySource::read`] fills the whole
//!   buffer or returns an error, normally [`Error::Unmapped`] with the
//!   requested range. Never return a partially filled buffer as success.
//!   Reads may span adjacent mapped regions; join them.
//! - **No panics on bad addresses.** The walker follows pointers from target
//!   memory, which may be garbage. Any `addr`/`len` (including ones that
//!   overflow `u64`) must produce an error, not a panic.
//! - **Thread safety.** The trait requires `Send + Sync` so a future walker
//!   can read in parallel. Use interior locking or `OnceLock` for caches.
//! - **Cheap metadata.** `modules`, `threads`, `mapped_ranges` may be called
//!   more than once; cache them if they are expensive to compute.
//! - **Addresses are target virtual addresses.** Not file offsets.
//! - **Byte order.** `read` returns raw target bytes. [`MemorySourceExt`]
//!   decodes integers using [`TargetInfo::little_endian`].

use heapspy_snapshot::{Arch, MemoryRegion, Os, SourceKind};

use crate::error::{Error, Result};

pub mod elf_core;
pub mod linux_live;
pub mod mem;
pub mod minidump;

/// Static facts about the target, known as soon as the source is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetInfo {
    pub os: Os,
    pub arch: Arch,
    /// 8 on x86_64 and aarch64. 4 would be a 32-bit target (not supported in v1).
    pub pointer_size: u8,
    pub little_endian: bool,
}

impl TargetInfo {
    pub const LINUX_X86_64: TargetInfo = TargetInfo {
        os: Os::Linux,
        arch: Arch::X86_64,
        pointer_size: 8,
        little_endian: true,
    };
    pub const WINDOWS_X86_64: TargetInfo = TargetInfo {
        os: Os::Windows,
        arch: Arch::X86_64,
        pointer_size: 8,
        little_endian: true,
    };
}

/// A loaded executable image: the main program or a shared library / DLL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// File name only, e.g. `libpython3.12.so.1.0`, `python312.dll`, `python3.12`.
    pub name: String,
    /// Full path as recorded in the image (it may refer to another machine).
    pub path: String,
    /// Load address: where the image's first byte (ELF header / PE `MZ`) is mapped.
    pub base: u64,
    /// Size of the mapped image in bytes (from lowest to highest mapped segment).
    pub size: u64,
    /// GNU build-id note (ELF), or CodeView GUID+age (PE), if known. Used to
    /// pick per-build offset tables and to find matching debug files.
    pub build_id: Option<Vec<u8>>,
}

impl Module {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr - self.base < self.size
    }
}

/// One OS thread of the target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadInfo {
    /// Linux TID or Windows thread id.
    pub tid: u64,
    /// Thread name if the image records it (`/proc/.../comm`, minidump thread names).
    pub name: Option<String>,
    /// Thread pointer: `fs_base` on x86_64 Linux, `tpidr_el0` on aarch64, the
    /// TEB address on Windows. CPython 3.12+ keeps the current thread state in
    /// thread-local storage, so the walker may need it.
    pub tls_base: Option<u64>,
    /// Stack pointer at capture time.
    pub stack_pointer: Option<u64>,
}

/// Protection bits of a mapping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

/// One contiguous mapped range whose bytes can be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedRange {
    pub start: u64,
    pub size: u64,
    pub perms: Perms,
    /// Backing file path, if the mapping is file-backed.
    pub file: Option<String>,
}

/// Memory totals by region kind, for "N% of RSS is outside the Python graph".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemorySummary {
    pub regions: Vec<MemoryRegion>,
    /// Resident set size of the whole process, if known.
    pub rss_bytes: Option<u64>,
}

/// A read-only view of one process's memory. See the module docs for the
/// rules every implementation must follow.
pub trait MemorySource: Send + Sync {
    /// OS, architecture, pointer size and byte order of the target.
    fn target(&self) -> TargetInfo;

    /// Read exactly `buf.len()` bytes starting at target address `addr`.
    ///
    /// Returns [`Error::Unmapped`] if any byte of the range is not present in
    /// the image. A zero-length read succeeds.
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()>;

    /// Readable ranges, sorted by start address, non-overlapping.
    fn mapped_ranges(&self) -> Result<Vec<MappedRange>>;

    /// Loaded executable images. The main executable comes first when known.
    fn modules(&self) -> Result<Vec<Module>>;

    /// OS threads at capture time.
    fn threads(&self) -> Result<Vec<ThreadInfo>>;

    /// Mapped / resident totals by region kind, or `None` if the source cannot
    /// tell (for example a core file without `/proc/<pid>/smaps` data).
    fn memory_summary(&self) -> Option<MemorySummary>;

    /// When the image was taken, in Unix seconds, if the source records it
    /// (minidump header timestamp, core file mtime). `dump` falls back to the
    /// current time.
    fn captured_at(&self) -> Option<u64> {
        None
    }

    /// Resolve an exported (dynamic) symbol of `module`, such as `_PyRuntime`
    /// in libpython or `python3XX.dll`, to its target address.
    ///
    /// The default reads the module's ELF dynamic symbol table or PE export
    /// directory out of target memory through [`MemorySource::read`] (see
    /// [`crate::symbols`]), which works for any source where the image headers
    /// are mapped. Override it when the backend has a better way, for example
    /// reading the module file from disk, or when headers are not in the dump.
    ///
    /// Returns `Ok(None)` if the module has no such export.
    fn find_symbol(&self, module: &Module, name: &str) -> Result<Option<u64>> {
        crate::symbols::find_exported(self, module, name)
    }

    /// The walker has finished reading. A live backend resumes the target
    /// here instead of waiting for drop, so the pause does not include
    /// writing the snapshot. Returns how long the target was stopped, or
    /// `None` for file sources and if it was already resumed. Reads after
    /// this may fail or see a changing image. The default does nothing.
    fn release(&self) -> Option<std::time::Duration> {
        None
    }
}

/// Typed read helpers, available on every [`MemorySource`] (including
/// `dyn MemorySource`). Integers are decoded in the target's byte order.
pub trait MemorySourceExt: MemorySource {
    /// Read `len` bytes into a new vector.
    fn read_vec(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut v = vec![0u8; len];
        self.read(addr, &mut v)?;
        Ok(v)
    }

    fn read_array<const N: usize>(&self, addr: u64) -> Result<[u8; N]> {
        let mut a = [0u8; N];
        self.read(addr, &mut a)?;
        Ok(a)
    }

    fn read_u8(&self, addr: u64) -> Result<u8> {
        Ok(self.read_array::<1>(addr)?[0])
    }

    fn read_u16(&self, addr: u64) -> Result<u16> {
        let a = self.read_array::<2>(addr)?;
        Ok(if self.target().little_endian {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        })
    }

    fn read_u32(&self, addr: u64) -> Result<u32> {
        let a = self.read_array::<4>(addr)?;
        Ok(if self.target().little_endian {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }

    fn read_u64(&self, addr: u64) -> Result<u64> {
        let a = self.read_array::<8>(addr)?;
        Ok(if self.target().little_endian {
            u64::from_le_bytes(a)
        } else {
            u64::from_be_bytes(a)
        })
    }

    fn read_i64(&self, addr: u64) -> Result<i64> {
        Ok(self.read_u64(addr)? as i64)
    }

    /// Read a pointer-sized unsigned integer.
    fn read_ptr(&self, addr: u64) -> Result<u64> {
        match self.target().pointer_size {
            8 => self.read_u64(addr),
            4 => self.read_u32(addr).map(u64::from),
            n => Err(Error::Unsupported(format!("pointer size {n}"))),
        }
    }

    /// Read `count` consecutive pointers.
    fn read_ptrs(&self, addr: u64, count: usize) -> Result<Vec<u64>> {
        let ps = self.target().pointer_size as usize;
        let bytes = self.read_vec(
            addr,
            count.checked_mul(ps).ok_or(Error::Unmapped {
                addr,
                len: usize::MAX,
            })?,
        )?;
        let le = self.target().little_endian;
        Ok(bytes
            .chunks_exact(ps)
            .map(|c| match (ps, le) {
                (8, true) => u64::from_le_bytes(c.try_into().unwrap()),
                (8, false) => u64::from_be_bytes(c.try_into().unwrap()),
                (_, true) => u32::from_le_bytes(c.try_into().unwrap()) as u64,
                (_, false) => u32::from_be_bytes(c.try_into().unwrap()) as u64,
            })
            .collect())
    }

    /// Read a NUL-terminated byte string of at most `max` bytes (not counting
    /// the NUL). Reads in chunks that do not cross 4 KiB boundaries, so a
    /// string that ends just before an unmapped page is still read. Returns
    /// the bytes without the NUL; if no NUL is found within `max` bytes, the
    /// first `max` bytes are returned.
    fn read_cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>> {
        const PAGE: u64 = 4096;
        let mut out = Vec::new();
        let mut cur = addr;
        while out.len() < max {
            let to_page_end = (PAGE - (cur % PAGE)) as usize;
            let n = to_page_end.min(max - out.len());
            let mut chunk = vec![0u8; n];
            if self.read(cur, &mut chunk).is_err() {
                // The mapping may end inside this page (sources are not
                // required to be page-granular). Fall back to byte reads
                // until the NUL or the first unreadable byte.
                for i in 0..n as u64 {
                    let b = self.read_u8(cur + i)?;
                    if b == 0 {
                        return Ok(out);
                    }
                    out.push(b);
                }
                cur += n as u64;
                continue;
            }
            if let Some(nul) = chunk.iter().position(|&b| b == 0) {
                out.extend_from_slice(&chunk[..nul]);
                return Ok(out);
            }
            out.extend_from_slice(&chunk);
            cur = cur
                .checked_add(n as u64)
                .ok_or(Error::Unmapped { addr: cur, len: n })?;
        }
        Ok(out)
    }
}

impl<T: MemorySource + ?Sized> MemorySourceExt for T {}

/// What the user asked `heapspy dump` to read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceSpec {
    Pid(u32),
    Core(std::path::PathBuf),
    Minidump(std::path::PathBuf),
}

impl SourceSpec {
    pub fn kind(&self) -> SourceKind {
        match self {
            SourceSpec::Pid(_) => SourceKind::Pid,
            SourceSpec::Core(_) => SourceKind::Core,
            SourceSpec::Minidump(_) => SourceKind::Minidump,
        }
    }

    /// The text recorded as the snapshot's source reference.
    pub fn reference(&self) -> String {
        match self {
            SourceSpec::Pid(p) => p.to_string(),
            SourceSpec::Core(p) | SourceSpec::Minidump(p) => p.display().to_string(),
        }
    }
}

/// Open the backend for `spec`.
///
/// `--pid` maps to [`linux_live`] on Linux. On Windows a live backend
/// (`ReadProcessMemory`) is planned; until then it returns
/// [`Error::Unimplemented`].
pub fn open(spec: &SourceSpec) -> Result<Box<dyn MemorySource>> {
    Ok(match spec {
        SourceSpec::Core(p) => Box::new(elf_core::ElfCore::open(p)?),
        SourceSpec::Minidump(p) => Box::new(minidump::Minidump::open(p)?),
        SourceSpec::Pid(pid) => {
            if cfg!(windows) {
                return Err(Error::Unimplemented(
                    "live process reading on Windows (use --minidump)",
                ));
            }
            Box::new(linux_live::LiveProcess::attach(*pid)?)
        }
    })
}
