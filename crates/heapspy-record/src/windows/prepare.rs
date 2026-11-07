//! Opt a program into Windows heap ETW tracing, and out again.
//!
//! Heap tracing (the events `--events native` consumes) is a property of a
//! process that the heap manager reads *at startup*, so it cannot be turned
//! on for a process that is already running. Windows takes it from the
//! image's Image File Execution Options key, the `TracingFlags` DWORD:
//!
//! ```text
//! HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
//!     Image File Execution Options\<image.exe>\TracingFlags = 1
//! ```
//!
//! `heapspy record --prepare <image.exe>` sets it (the same value
//! `wpr -heaptracingconfig <image> enable` writes), `--unprepare` removes
//! it. The key is named by the executable's file name only, so preparing
//! `python.exe` enables heap tracing for every `python.exe` started
//! afterwards; filtering by pid happens in the recorder.
//!
//! This setting is global and persists across reboots, so heapspy never
//! sets it as a silent side effect of recording: `--prepare` is an explicit
//! command that prints what it changed and how to undo it, and `--unprepare`
//! removes exactly what heapspy would have added, leaving any other IFEO
//! settings (a `Debugger`, say) and any key heapspy did not create in place.
//!
//! Only the pure part ([`image_leaf`]) is tested here; the registry calls
//! are exercised by `--prepare`/`--unprepare` on Windows.

#[cfg(windows)]
use std::os::raw::c_void;

use crate::error::{Error, Result};

/// The IFEO key, under `HKEY_LOCAL_MACHINE`.
pub const IFEO: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
/// The value heap tracing is turned on with.
pub const TRACING_FLAGS: &str = "TracingFlags";

/// The IFEO subkey name for an executable: its file name only. A path is
/// reduced to its last component, so `C:\Python\python.exe` and
/// `python.exe` name the same key, as the loader matches it.
pub fn image_leaf(exe: &str) -> &str {
    let leaf = exe.rsplit(['\\', '/']).next().unwrap_or(exe);
    leaf.trim()
}

/// What `--prepare` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// The IFEO subkey name (the image file name).
    pub image: String,
    /// Full registry path of the key.
    pub key_path: String,
    /// The key did not exist and heapspy created it. `--unprepare` then
    /// removes the whole key; otherwise it removes only the value.
    pub created_key: bool,
    /// `TracingFlags` was already 1 before this call.
    pub already_enabled: bool,
}

/// What `--unprepare` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unprepared {
    pub image: String,
    pub key_path: String,
    /// The key was not there at all.
    pub key_absent: bool,
    /// `TracingFlags` was present and removed.
    pub value_removed: bool,
    /// The key was left empty and heapspy deleted it.
    pub key_removed: bool,
}

fn key_path(image: &str) -> String {
    format!("{IFEO}\\{image}")
}

#[cfg(not(windows))]
pub fn prepare(_exe: &str) -> Result<Prepared> {
    Err(Error::Unsupported(
        "heap tracing (--prepare) is a Windows feature".into(),
    ))
}

#[cfg(not(windows))]
pub fn unprepare(_exe: &str) -> Result<Unprepared> {
    Err(Error::Unsupported(
        "heap tracing (--unprepare) is a Windows feature".into(),
    ))
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW, RegOpenKeyExW,
        RegQueryInfoKeyW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        KEY_WRITE, REG_CREATED_NEW_KEY, REG_DWORD, REG_OPTION_NON_VOLATILE,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn os_err(code: u32, what: &str) -> Error {
        if code == windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED {
            Error::PermissionDenied(format!("{what} needs an elevated prompt (Administrator)"))
        } else {
            Error::Io(std::io::Error::from_raw_os_error(code as i32))
        }
    }

    /// A closed-on-drop HKEY.
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: a handle we opened; closed once.
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    pub fn prepare(exe: &str) -> Result<Prepared> {
        let image = image_leaf(exe).to_string();
        if image.is_empty() {
            return Err(Error::InvalidOption("empty image name".into()));
        }
        let path = key_path(&image);
        let wpath = wide(&path);
        let mut hkey: HKEY = std::ptr::null_mut();
        let mut disp = 0u32;
        // SAFETY: create-or-open under HKLM with a NUL-terminated path.
        let e = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wpath.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                std::ptr::null(),
                &mut hkey,
                &mut disp,
            )
        };
        if e != ERROR_SUCCESS {
            return Err(os_err(e, "opening the Image File Execution Options key"));
        }
        let key = Key(hkey);
        let already_enabled = read_dword(&key, TRACING_FLAGS) == Some(1);
        let one = 1u32.to_le_bytes();
        // SAFETY: writing a 4-byte DWORD value.
        let e = unsafe {
            RegSetValueExW(
                key.0,
                wide(TRACING_FLAGS).as_ptr(),
                0,
                REG_DWORD,
                one.as_ptr(),
                one.len() as u32,
            )
        };
        if e != ERROR_SUCCESS {
            return Err(os_err(e, "setting TracingFlags"));
        }
        Ok(Prepared {
            image,
            key_path: path,
            created_key: disp == REG_CREATED_NEW_KEY,
            already_enabled,
        })
    }

    pub fn unprepare(exe: &str) -> Result<Unprepared> {
        let image = image_leaf(exe).to_string();
        let path = key_path(&image);
        let wpath = wide(&path);
        let mut hkey: HKEY = std::ptr::null_mut();
        // SAFETY: open under HKLM with a NUL-terminated path.
        let e = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wpath.as_ptr(),
                0,
                KEY_READ | KEY_WRITE,
                &mut hkey,
            )
        };
        if e == ERROR_FILE_NOT_FOUND {
            return Ok(Unprepared {
                image,
                key_path: path,
                key_absent: true,
                value_removed: false,
                key_removed: false,
            });
        }
        if e != ERROR_SUCCESS {
            return Err(os_err(e, "opening the Image File Execution Options key"));
        }
        let key = Key(hkey);
        // SAFETY: deleting a value of a key we hold open.
        let e = unsafe { RegDeleteValueW(key.0, wide(TRACING_FLAGS).as_ptr()) };
        if e != ERROR_SUCCESS && e != ERROR_FILE_NOT_FOUND {
            return Err(os_err(e, "removing TracingFlags"));
        }
        let value_removed = e == ERROR_SUCCESS;
        let empty = key_is_empty(&key);
        drop(key);
        // Delete the key only when heapspy left it empty: never touch a key
        // that still holds other IFEO settings (a Debugger, say).
        let key_removed = if empty {
            // SAFETY: deleting an empty subkey by path under HKLM.
            unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, wpath.as_ptr()) == ERROR_SUCCESS }
        } else {
            false
        };
        Ok(Unprepared {
            image,
            key_path: path,
            key_absent: false,
            value_removed,
            key_removed,
        })
    }

    fn read_dword(key: &Key, name: &str) -> Option<u32> {
        let mut ty = 0u32;
        let mut buf = [0u8; 4];
        let mut len = buf.len() as u32;
        // SAFETY: querying a value into a 4-byte buffer.
        let e = unsafe {
            RegQueryValueExW(
                key.0,
                wide(name).as_ptr(),
                std::ptr::null(),
                &mut ty,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        (e == ERROR_SUCCESS && ty == REG_DWORD && len == 4).then(|| u32::from_le_bytes(buf))
    }

    /// No values and no subkeys.
    fn key_is_empty(key: &Key) -> bool {
        let mut subkeys = 0u32;
        let mut values = 0u32;
        // SAFETY: all out-params optional but the two counts; rest null.
        let e = unsafe {
            RegQueryInfoKeyW(
                key.0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut subkeys,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut values,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut::<c_void>() as *mut _,
            )
        };
        e == ERROR_SUCCESS && subkeys == 0 && values == 0
    }
}

#[cfg(windows)]
pub use imp::{prepare, unprepare};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_leaf_takes_the_file_name() {
        assert_eq!(image_leaf("python.exe"), "python.exe");
        assert_eq!(image_leaf(r"C:\Python\python.exe"), "python.exe");
        assert_eq!(image_leaf("/usr/bin/app.exe"), "app.exe");
        assert_eq!(image_leaf("  python.exe  "), "python.exe");
    }

    #[test]
    fn key_path_is_under_ifeo() {
        assert_eq!(
            key_path("python.exe"),
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\python.exe"
        );
    }
}
