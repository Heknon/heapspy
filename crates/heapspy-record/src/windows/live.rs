//! Windows reader of a running process: `ReadProcessMemory` on a handle
//! opened with `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`.
//! Nothing is suspended. Modules from `EnumProcessModulesEx`, threads from
//! a Toolhelp snapshot; symbols through the default
//! [`MemorySource::find_symbol`] (the PE export directory in memory).

use std::time::{SystemTime, UNIX_EPOCH};

use heapspy_reader::{MappedRange, MemorySource, MemorySummary, Module, TargetInfo, ThreadInfo};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, HANDLE, HMODULE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

use crate::error::{Error, Result};

/// A handle closed on drop.
pub struct Handle(pub HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: closing a handle we own.
            unsafe { CloseHandle(self.0) };
        }
    }
}

// SAFETY: a process handle may be used from any thread.
unsafe impl Send for Handle {}
// SAFETY: as above; ReadProcessMemory is thread-safe.
unsafe impl Sync for Handle {}

/// The running process. See the module docs.
pub struct RunningProcess {
    pid: u32,
    h: Handle,
    modules: Vec<Module>,
}

pub fn access_error(pid: u32, what: &str) -> Error {
    Error::PermissionDenied(format!(
        "{what} on pid {pid} was refused. Run heapspy from an elevated prompt \
         (SeDebugPrivilege) to record another user's or a protected process."
    ))
}

impl RunningProcess {
    pub fn open(pid: u32) -> Result<RunningProcess> {
        super::sys::enable_debug_privilege();
        // SAFETY: plain OpenProcess; the handle is owned by `Handle`.
        let h = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            // SAFETY: no preconditions.
            let e = unsafe { GetLastError() };
            return Err(match e {
                ERROR_ACCESS_DENIED => access_error(pid, "OpenProcess"),
                ERROR_INVALID_PARAMETER => Error::Reader(heapspy_reader::Error::NoSuchProcess(
                    format!("no process with pid {pid}"),
                )),
                _ => Error::Io(std::io::Error::from_raw_os_error(e as i32)),
            });
        }
        let mut p = RunningProcess {
            pid,
            h: Handle(h),
            modules: Vec::new(),
        };
        p.modules = p.list_modules();
        Ok(p)
    }

    pub fn handle(&self) -> HANDLE {
        self.h.0
    }

    fn list_modules(&self) -> Vec<Module> {
        let mut mods = vec![std::ptr::null_mut(); 1024];
        let mut needed = 0u32;
        // SAFETY: the buffer holds `mods.len()` HMODULEs.
        let ok = unsafe {
            EnumProcessModulesEx(
                self.h.0,
                mods.as_mut_ptr(),
                (mods.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
        };
        if ok == 0 {
            return Vec::new();
        }
        let n = (needed as usize / std::mem::size_of::<HMODULE>()).min(mods.len());
        mods[..n]
            .iter()
            .filter_map(|&m| {
                let mut name = [0u16; 1024];
                let mut info = MODULEINFO {
                    lpBaseOfDll: std::ptr::null_mut(),
                    SizeOfImage: 0,
                    EntryPoint: std::ptr::null_mut(),
                };
                // SAFETY: buffers sized as passed.
                unsafe {
                    let len =
                        GetModuleFileNameExW(self.h.0, m, name.as_mut_ptr(), name.len() as u32);
                    if GetModuleInformation(
                        self.h.0,
                        m,
                        &mut info,
                        std::mem::size_of::<MODULEINFO>() as u32,
                    ) == 0
                    {
                        return None;
                    }
                    let path = String::from_utf16_lossy(&name[..len as usize]);
                    Some(Module {
                        name: path.rsplit('\\').next().unwrap_or(&path).to_string(),
                        path,
                        base: info.lpBaseOfDll as u64,
                        size: info.SizeOfImage as u64,
                        build_id: None,
                    })
                }
            })
            .collect()
    }
}

impl MemorySource for RunningProcess {
    fn target(&self) -> TargetInfo {
        TargetInfo::WINDOWS_X86_64
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> heapspy_reader::Result<()> {
        let mut got = 0usize;
        // SAFETY: `buf` is writable for its length.
        let ok = unsafe {
            ReadProcessMemory(
                self.h.0,
                addr as *const _,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut got,
            )
        };
        if ok != 0 && got == buf.len() {
            Ok(())
        } else {
            Err(heapspy_reader::Error::Unmapped {
                addr,
                len: buf.len(),
            })
        }
    }

    fn mapped_ranges(&self) -> heapspy_reader::Result<Vec<MappedRange>> {
        Ok(Vec::new())
    }

    fn modules(&self) -> heapspy_reader::Result<Vec<Module>> {
        Ok(self.modules.clone())
    }

    fn threads(&self) -> heapspy_reader::Result<Vec<ThreadInfo>> {
        Ok(threads_of(self.pid)
            .into_iter()
            .map(|tid| ThreadInfo {
                tid: tid as u64,
                ..ThreadInfo::default()
            })
            .collect())
    }

    fn memory_summary(&self) -> Option<MemorySummary> {
        None
    }

    fn captured_at(&self) -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs())
    }
}

/// Thread ids of `pid`, from a Toolhelp snapshot.
pub fn threads_of(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    // SAFETY: Toolhelp snapshot iteration with a correctly sized entry.
    unsafe {
        let snap = Handle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if snap.0 == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: THREADENTRY32 = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut ok = Thread32First(snap.0, &mut e);
        while ok != 0 {
            if e.th32OwnerProcessID == pid {
                out.push(e.th32ThreadID);
            }
            ok = Thread32Next(snap.0, &mut e);
        }
    }
    out
}
