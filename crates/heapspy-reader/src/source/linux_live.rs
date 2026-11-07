//! Live Linux process via `process_vm_readv`.
//!
//! - Consistency: every thread is stopped before the first read with
//!   `PTRACE_SEIZE` + `PTRACE_INTERRUPT` on each TID in `/proc/<pid>/task`,
//!   repeated until a pass finds no new threads (a thread can be created
//!   while earlier ones are being stopped). This was chosen over `SIGSTOP`
//!   because it is invisible to the target and its parent: no job-control
//!   stop is reported to a shell or supervisor, no `SIGCONT` is needed, and
//!   signals that arrive meanwhile stay queued. A signal that was being
//!   delivered when a thread stopped is re-injected on detach.
//! - Threads are resumed by [`MemorySource::release`] (which `dump` calls as
//!   soon as the walk is done, before the snapshot is written) or on drop,
//!   including when attaching fails halfway. ptrace ties a tracee to the
//!   tracer *thread*, so release or drop must happen on the thread that
//!   called [`LiveProcess::attach`]. If that thread has gone away, the
//!   kernel detaches the tracees when the tracer exits.
//! - Memory: `process_vm_readv`, falling back to `/proc/<pid>/mem` for
//!   ranges it refuses. Reads go through a cache of 64 KiB blocks (up to
//!   256 MiB), valid because the target is stopped; it turns the walker's
//!   many small reads into few system calls.
//! - Modules and ranges: `/proc/<pid>/maps`. Threads: `/proc/<pid>/task`,
//!   names from `comm`, stack pointer and `fs_base` from `PTRACE_GETREGS`.
//! - Memory summary: `/proc/<pid>/smaps` for per-kind mapped and resident
//!   totals, `/proc/<pid>/smaps_rollup` for RSS.
//! - Native heap: glibc malloc's chunks, walked by [`super::glibc_heap`]
//!   from the image like everything else, with the brk heap located by its
//!   `[heap]` line in `maps`. Checked on synthetic images and by the ignored
//!   test `tests/native_heap_live.rs`, which the e2e workflow runs; it has
//!   not been run against a real process from this repository's checks yet.
//! - Errors: `EPERM` maps to [`Error::PermissionDenied`] with a hint about
//!   `CAP_SYS_PTRACE` and `kernel.yama.ptrace_scope`.
//!
//! On other platforms [`LiveProcess::attach`] returns [`Error::Unsupported`].

use std::time::Duration;

use super::{MappedRange, MemorySource, MemorySummary, Module, TargetInfo, ThreadInfo};
#[cfg(not(target_os = "linux"))]
use crate::error::Error;
use crate::error::Result;

#[cfg(target_os = "linux")]
mod imp;

/// A stopped live process.
pub struct LiveProcess {
    pid: u32,
    target: TargetInfo,
    heap_stats: std::sync::Mutex<Option<super::NativeHeapStats>>,
    #[cfg(target_os = "linux")]
    inner: imp::Inner,
}

impl std::fmt::Debug for LiveProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveProcess")
            .field("pid", &self.pid)
            .field("target", &self.target)
            .finish()
    }
}

impl LiveProcess {
    /// Stop `pid` and prepare to read it.
    pub fn attach(pid: u32) -> Result<LiveProcess> {
        #[cfg(target_os = "linux")]
        {
            let inner = imp::Inner::attach(pid)?;
            Ok(LiveProcess {
                pid,
                target: inner.target(),
                heap_stats: Default::default(),
                inner,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Unsupported(format!(
                "reading a live process (pid {pid}) is only implemented on Linux"
            )))
        }
    }

    /// Read `pid` **without** stopping it, for allocation recorders: no
    /// ptrace, no block cache (memory changes under the reader), no memory
    /// summary, threads without registers. [`MemorySource::release`] does
    /// nothing. Reads may observe a changing image.
    pub fn open_running(pid: u32) -> Result<LiveProcess> {
        #[cfg(target_os = "linux")]
        {
            let inner = imp::Inner::open_running(pid)?;
            Ok(LiveProcess {
                pid,
                target: inner.target(),
                heap_stats: Default::default(),
                inner,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Unsupported(format!(
                "reading a running process (pid {pid}) this way is only implemented on Linux"
            )))
        }
    }

    /// Read `pid` without stopping it, for an approximate snapshot: as
    /// [`LiveProcess::open_running`], plus the memory summary from
    /// `/proc/<pid>/smaps`. The walk races with the target, so objects can
    /// be missed or half-read and the GC lists can change under it.
    pub fn open_unstopped(pid: u32) -> Result<LiveProcess> {
        #[cfg(target_os = "linux")]
        {
            let inner = imp::Inner::open_running_with_summary(pid)?;
            Ok(LiveProcess {
                pid,
                target: inner.target(),
                heap_stats: Default::default(),
                inner,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Unsupported(format!(
                "a snapshot without stopping pid {pid} is only implemented on Linux"
            )))
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// How long stopping all threads took.
    pub fn attach_time(&self) -> Duration {
        #[cfg(target_os = "linux")]
        {
            self.inner.attach_time()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Duration::ZERO
        }
    }

    /// Resume the target now. Later reads still work for cached blocks and
    /// may otherwise see a changing image. Returns how long the target was
    /// stopped, or `None` if it was already resumed.
    pub fn resume(&self) -> Option<Duration> {
        #[cfg(target_os = "linux")]
        {
            self.inner.detach()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

#[cfg(target_os = "linux")]
impl MemorySource for LiveProcess {
    fn native_blocks(&self) -> Result<Option<Vec<super::NativeBlock>>> {
        let walked = super::glibc_heap::walk_heap(
            self,
            &super::glibc_heap::HeapHints {
                brk: self.inner.brk_range(),
            },
        )?;
        let (blocks, stats) = walked.unzip();
        *self.heap_stats.lock().unwrap_or_else(|e| e.into_inner()) = stats;
        Ok(blocks)
    }
    fn native_heap_stats(&self) -> Option<super::NativeHeapStats> {
        *self.heap_stats.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn target(&self) -> TargetInfo {
        self.target
    }
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read(addr, buf)
    }
    fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
        Ok(self.inner.mapped_ranges())
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Ok(self.inner.modules())
    }
    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Ok(self.inner.threads())
    }
    fn memory_summary(&self) -> Option<MemorySummary> {
        self.inner.memory_summary()
    }
    fn captured_at(&self) -> Option<u64> {
        Some(self.inner.captured_at())
    }
    fn find_symbol(&self, module: &Module, name: &str) -> Result<Option<u64>> {
        self.inner.find_symbol(self, module, name)
    }
    fn release(&self) -> Option<Duration> {
        self.resume()
    }
}

#[cfg(not(target_os = "linux"))]
impl MemorySource for LiveProcess {
    fn target(&self) -> TargetInfo {
        self.target
    }
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        Err(Error::Unmapped {
            addr,
            len: buf.len(),
        })
    }
    fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
        Ok(Vec::new())
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Ok(Vec::new())
    }
    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Ok(Vec::new())
    }
    fn memory_summary(&self) -> Option<MemorySummary> {
        None
    }
}
