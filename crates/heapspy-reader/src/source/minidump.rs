//! Windows full-memory minidumps. **Stub.**
//!
//! Implementation notes:
//!
//! - Only full-memory dumps are useful (`MiniDumpWithFullMemory`): memory
//!   comes from the `Memory64ListStream`. A dump with only `MemoryListStream`
//!   lacks the heap; report that clearly as [`Error::Format`].
//! - Modules: `ModuleListStream` (base, size, name; CodeView record for the
//!   build id). Threads: `ThreadListStream` (TEB address goes in `tls_base`)
//!   plus `ThreadNamesStream` if present.
//! - Memory summary: `MemoryInfoListStream` gives state/type/protection per
//!   region; there is no residency, so `resident_bytes` is `None`.
//! - `captured_at`: `MINIDUMP_HEADER.TimeDateStamp`.
//! - Parsing must be pure Rust and work on any host OS, so Windows dumps can
//!   be converted on Linux. Map the file with `memmap2`.

use std::path::Path;

use super::{MappedRange, MemorySource, MemorySummary, Module, TargetInfo, ThreadInfo};
use crate::error::{Error, Result};

/// An opened minidump.
#[derive(Debug)]
pub struct Minidump {
    target: TargetInfo,
}

impl Minidump {
    pub fn open(_path: &Path) -> Result<Minidump> {
        Err(Error::Unimplemented("Windows minidump reader"))
    }
}

impl MemorySource for Minidump {
    fn target(&self) -> TargetInfo {
        self.target
    }
    fn read(&self, _addr: u64, _buf: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented("Windows minidump reader"))
    }
    fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
        Err(Error::Unimplemented("Windows minidump reader"))
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Err(Error::Unimplemented("Windows minidump reader"))
    }
    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Err(Error::Unimplemented("Windows minidump reader"))
    }
    fn memory_summary(&self) -> Option<MemorySummary> {
        None
    }
}
