//! `heapspy dump --pid` on Windows: write a full-memory minidump of the
//! target with `MiniDumpWriteDump`, then read it as a [`Minidump`].
//!
//! Going through a dump rather than calling `ReadProcessMemory` per object
//! gives one consistent image: `MiniDumpWriteDump` suspends the target's
//! threads while it copies memory and resumes them when it returns, so the
//! target is paused only for the copy, not for the whole heap walk.
//!
//! The dump is written to a temporary file opened with
//! `FILE_FLAG_DELETE_ON_CLOSE`. The [`Minidump`] keeps that handle and the
//! mapping, so the file disappears when the source is dropped, or when
//! heapspy exits for any reason. Use [`write_dump`] to keep a dump instead.
//!
//! Access: the process is opened with `PROCESS_QUERY_INFORMATION |
//! PROCESS_VM_READ` (plus `PROCESS_DUP_HANDLE`, which `MiniDumpWriteDump`
//! needs for handle data; without it the dump is written without handles).
//! heapspy enables `SeDebugPrivilege` if the token has it, which is the case
//! in an elevated prompt. See `docs/windows.md`.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, GENERIC_READ,
    GENERIC_WRITE, HANDLE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_FLAG_DELETE_ON_CLOSE, FILE_SHARE_DELETE, FILE_SHARE_READ,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    MiniDumpIgnoreInaccessibleMemory, MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo,
    MiniDumpWithHandleData, MiniDumpWithThreadInfo, MiniDumpWriteDump, MINIDUMP_TYPE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use super::minidump::{Minidump, MinidumpOptions};
use crate::error::{Error, Result};

/// The dump type heapspy writes. `MiniDumpIgnoreInaccessibleMemory` lets the
/// dump succeed when a few pages cannot be read (they are left out).
const DUMP_TYPE: MINIDUMP_TYPE = MiniDumpWithFullMemory
    | MiniDumpWithHandleData
    | MiniDumpWithThreadInfo
    | MiniDumpWithFullMemoryInfo
    | MiniDumpIgnoreInaccessibleMemory;

/// Capture `pid` into a temporary minidump in `scratch_dir` and open it.
/// The file is deleted when the returned [`Minidump`] is dropped.
///
/// `scratch_dir` should be on a volume with room for the whole committed
/// memory of the target; the output directory of the snapshot is a good
/// choice.
pub fn capture(pid: u32, scratch_dir: &Path) -> Result<Minidump> {
    let file = create_temp(pid, scratch_dir)?;
    write_to(pid, &file)?;
    Minidump::from_file(file, MinidumpOptions::default())
}

/// Write a full-memory minidump of `pid` to `path` and keep it. `path` must
/// not exist yet.
pub fn write_dump(pid: u32, path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    if let Err(e) = write_to(pid, &file) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

fn create_temp(pid: u32, dir: &Path) -> Result<File> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let mut last = None;
    for attempt in 0..16u32 {
        let path: PathBuf = dir.join(format!(
            ".heapspy-{pid}-{}-{nanos:08x}-{attempt}.dmp",
            std::process::id()
        ));
        let r = OpenOptions::new()
            // std rejects create_new without write(true), even though
            // access_mode below replaces the access rights it implies.
            .read(true)
            .write(true)
            // DELETE access is required for FILE_FLAG_DELETE_ON_CLOSE.
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .create_new(true)
            .open(&path);
        match r {
            Ok(f) => return Ok(f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => {
                return Err(Error::Io(io::Error::new(
                    e.kind(),
                    format!("cannot create temporary dump in {}: {e}", dir.display()),
                )))
            }
        }
    }
    Err(Error::Io(last.unwrap_or_else(|| {
        io::Error::other("cannot create temporary dump file")
    })))
}

/// An owned process or token handle.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful Open* call and is closed
        // exactly once, here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn last_error() -> u32 {
    // SAFETY: no preconditions.
    unsafe { GetLastError() }
}

fn permission_hint(pid: u32, what: &str) -> Error {
    Error::PermissionDenied(format!(
        "{what} process {pid}: access denied. Reading another process's memory needs \
         SeDebugPrivilege: run heapspy from an elevated prompt (Run as administrator), \
         or as the same user as the target. Protected processes (PPL) cannot be dumped."
    ))
}

/// Turn on SeDebugPrivilege in our own token if it is there (elevated
/// administrators have it, disabled). Failure is not an error: opening the
/// target may still work, for example when it runs as the same user.
fn enable_debug_privilege() {
    // SAFETY: plain Win32 calls with valid out-pointers; the token handle is
    // owned and closed by OwnedHandle.
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return;
        }
        let token = OwnedHandle(token);
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(ptr::null(), SE_DEBUG_NAME, &mut luid) == 0 {
            return;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token.0, 0, &tp, 0, ptr::null_mut(), ptr::null_mut());
    }
}

/// Open `pid` for dumping. Returns the handle and whether it has
/// `PROCESS_DUP_HANDLE` (needed for handle data).
fn open_process(pid: u32) -> Result<(OwnedHandle, bool)> {
    enable_debug_privilege();
    let base = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    for (access, dup) in [(base | PROCESS_DUP_HANDLE, true), (base, false)] {
        // SAFETY: no pointers involved; a null return means failure.
        let h = unsafe { OpenProcess(access, 0, pid) };
        if !h.is_null() {
            return Ok((OwnedHandle(h), dup));
        }
        match last_error() {
            // Retry without PROCESS_DUP_HANDLE before giving up.
            ERROR_ACCESS_DENIED if dup => continue,
            ERROR_ACCESS_DENIED => return Err(permission_hint(pid, "cannot open")),
            ERROR_INVALID_PARAMETER => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no process with id {pid}"),
                )))
            }
            code => return Err(Error::Io(io::Error::from_raw_os_error(code as i32))),
        }
    }
    Err(permission_hint(pid, "cannot open"))
}

/// `MiniDumpWriteDump` reports failures as an HRESULT through
/// `GetLastError`. Map `HRESULT_FROM_WIN32` values back to the Win32 code.
fn dump_error(pid: u32, code: u32) -> Error {
    let win32 = if code & 0xffff_0000 == 0x8007_0000 {
        code & 0xffff
    } else {
        code
    };
    if win32 == ERROR_ACCESS_DENIED {
        return permission_hint(pid, "cannot dump");
    }
    let os = io::Error::from_raw_os_error(win32 as i32);
    Error::Io(io::Error::new(
        os.kind(),
        format!("MiniDumpWriteDump of process {pid} failed ({code:#010x}): {os}"),
    ))
}

fn write_to(pid: u32, file: &File) -> Result<()> {
    let (process, dup) = open_process(pid)?;
    let ty = if dup {
        DUMP_TYPE
    } else {
        DUMP_TYPE & !MiniDumpWithHandleData
    };
    // SAFETY: `process` and `file` are valid open handles for the duration
    // of the call; the optional parameters are null, which the API allows.
    let ok = unsafe {
        MiniDumpWriteDump(
            process.0,
            pid,
            file.as_raw_handle(),
            ty,
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    if ok == 0 {
        return Err(dump_error(pid, last_error()));
    }
    Ok(())
}
