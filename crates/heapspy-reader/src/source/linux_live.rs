//! Live Linux process via `process_vm_readv`. **Stub.**
//!
//! Implementation notes:
//!
//! - Consistency: stop every thread before the first read (`PTRACE_SEIZE` +
//!   `PTRACE_INTERRUPT` on each TID in `/proc/<pid>/task`, or `SIGSTOP`) and
//!   resume them on drop. The pause must be as short as possible; for large
//!   heaps the recommended path is still `gcore` + [`super::elf_core`].
//! - Memory: `process_vm_readv`, falling back to `/proc/<pid>/mem` for ranges
//!   that `process_vm_readv` refuses. Split reads at mapping boundaries from
//!   `/proc/<pid>/maps` so one unmapped page does not fail a whole read.
//! - Modules and ranges: `/proc/<pid>/maps`. Threads: `/proc/<pid>/task`.
//! - Memory summary: `/proc/<pid>/smaps_rollup` for RSS, `/proc/<pid>/smaps`
//!   for per-kind totals (`[heap]`, `[stack]`, anonymous, file-backed).
//! - Errors: `EPERM` maps to [`Error::PermissionDenied`] with a hint about
//!   `CAP_SYS_PTRACE` and `kernel.yama.ptrace_scope`.
//! - Platform code must be behind `#[cfg(target_os = "linux")]`; on other
//!   platforms `attach` returns [`Error::Unsupported`].

use super::{MappedRange, MemorySource, MemorySummary, Module, TargetInfo, ThreadInfo};
use crate::error::{Error, Result};

/// A stopped live process.
#[derive(Debug)]
pub struct LiveProcess {
    pid: u32,
    target: TargetInfo,
}

impl LiveProcess {
    /// Stop `pid` and prepare to read it.
    pub fn attach(pid: u32) -> Result<LiveProcess> {
        if !cfg!(target_os = "linux") {
            return Err(Error::Unsupported(format!(
                "reading a live process (pid {pid}) is only implemented on Linux"
            )));
        }
        Err(Error::Unimplemented("live Linux process reader"))
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
}

impl MemorySource for LiveProcess {
    fn target(&self) -> TargetInfo {
        self.target
    }
    fn read(&self, _addr: u64, _buf: &mut [u8]) -> Result<()> {
        Err(Error::Unimplemented("live Linux process reader"))
    }
    fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
        Err(Error::Unimplemented("live Linux process reader"))
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Err(Error::Unimplemented("live Linux process reader"))
    }
    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Err(Error::Unimplemented("live Linux process reader"))
    }
    fn memory_summary(&self) -> Option<MemorySummary> {
        None
    }
}
