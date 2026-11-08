//! Reading a running target's memory without stopping it.
//!
//! `heapspy dump` reads through a [`MemorySource`] that stops every thread
//! first (`linux_live::LiveProcess`, or a minidump on Windows), because a
//! heap walk needs one consistent image. A recorder must not do that: the
//! target keeps running for the whole window, and only individual reads
//! (code objects, and stacks in the ptrace, debugger and ETW-sampler paths)
//! touch its memory. [`open`] returns a source with these properties:
//!
//! - It never stops the target. Reads may observe memory that changes
//!   between two calls; callers treat a failed or odd read as "unknown".
//! - `modules()` and `find_symbol()` work, so [`crate::Target::locate`] can
//!   find `_PyRuntime` and `_Py_DebugOffsets` with the snapshot code.
//! - No caching of memory contents (they change); module lists may be cached.
//! - `release()` does nothing.
//!
//! # Implementation
//!
//! - **Linux (M7a).** `process_vm_readv` with a `/proc/<pid>/mem` fallback,
//!   modules from `/proc/<pid>/maps`, as `heapspy_reader::source::linux_live`
//!   does, minus the `PTRACE_SEIZE` / `PTRACE_INTERRUPT` stop and minus the
//!   64 KiB block cache (valid only for a stopped target). The least churn
//!   is a second constructor in `linux_live` (for example
//!   `LiveProcess::open_running(pid)`) that skips the stop and the cache;
//!   keep that change additive. `process_vm_readv` needs the same ptrace
//!   access check as attaching (`CAP_SYS_PTRACE` or `ptrace_scope` 0/1 with
//!   a parent relationship).
//! - **Windows (M7b).** `OpenProcess(PROCESS_VM_READ |
//!   PROCESS_QUERY_LIMITED_INFORMATION)` and `ReadProcessMemory`; modules
//!   from `EnumProcessModulesEx` + `GetModuleInformation`; exports resolved
//!   through the default [`MemorySource::find_symbol`], which reads the PE
//!   export directory from target memory. `windows_live` today goes through
//!   a full minidump, which is far too slow to repeat; this is a separate,
//!   direct reader.

use heapspy_reader::MemorySource;

use crate::error::Result;

/// A reader of the running process `pid` that does not stop it. See the
/// module docs.
pub fn open(pid: u32) -> Result<Box<dyn MemorySource>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(
            heapspy_reader::source::linux_live::LiveProcess::open_running(pid)?,
        ))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(crate::windows::live::RunningProcess::open(pid)?))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(crate::error::Error::Unsupported(format!(
            "reading a running process (pid {pid}) needs Linux or Windows"
        )))
    }
}

/// The OS's memory numbers for `pid` on Windows: the working set and the
/// private commit (`PROCESS_MEMORY_COUNTERS_EX.PrivateUsage`), in bytes.
/// Cheap: no reads of the target's memory. `None` on other systems, or
/// when the process cannot be opened.
pub fn windows_memory(pid: u32) -> Option<(u64, u64)> {
    #[cfg(windows)]
    {
        crate::windows::live::process_memory(pid)
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        None
    }
}

/// Every process on Windows: (pid, executable file name). Empty elsewhere
/// (Linux callers read `/proc`).
pub fn windows_processes() -> Vec<(u32, String)> {
    #[cfg(windows)]
    {
        crate::windows::live::processes()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}
