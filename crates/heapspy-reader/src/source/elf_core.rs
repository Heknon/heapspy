//! Linux ELF core files (`gcore`, kernel core dumps). **Stub.**
//!
//! Implementation notes for whoever fills this in:
//!
//! - Memory: `PT_LOAD` program headers. Segments with `p_filesz < p_memsz`
//!   have a zero-filled tail; segments with `p_filesz == 0` were not dumped
//!   (gcore omits read-only file mappings unless `coredump_filter` says
//!   otherwise) and must read as [`Error::Unmapped`], not zeros.
//! - Modules: the `NT_FILE` note lists file-backed mappings; group them by
//!   path, take the lowest start as `base`. Build ids come from the
//!   `NT_GNU_BUILD_ID` note inside each mapped image.
//! - Threads: `NT_PRSTATUS` notes (one per thread; `pr_pid` is the TID,
//!   registers give the stack pointer; `fs_base` is in the x86_64 register set).
//! - Memory summary: a core has no residency info. Return mapped totals with
//!   `resident_bytes: None`, or `None` overall.
//! - `captured_at`: file mtime is the best available.
//! - Map the core with `memmap2`; cores are multi-gigabyte.

use std::path::Path;

use super::{MappedRange, MemorySource, MemorySummary, Module, TargetInfo, ThreadInfo};
use crate::error::{Error, Result};

/// An opened ELF core file.
#[derive(Debug)]
pub struct ElfCore {
    target: TargetInfo,
}

impl ElfCore {
    /// Open and index a core file.
    pub fn open(_path: &Path) -> Result<ElfCore> {
        Err(Error::Unimplemented("ELF core reader"))
    }
}

impl MemorySource for ElfCore {
    fn target(&self) -> TargetInfo {
        self.target
    }
    fn read(&self, _addr: u64, _buf: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented("ELF core reader"))
    }
    fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
        Err(Error::Unimplemented("ELF core reader"))
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Err(Error::Unimplemented("ELF core reader"))
    }
    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Err(Error::Unimplemented("ELF core reader"))
    }
    fn memory_summary(&self) -> Option<MemorySummary> {
        None
    }
}
