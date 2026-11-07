//! CPython heap walker.
//!
//! 1. [`locate_runtime`] picks the Python module
//!    ([`crate::symbols::find_python_module`], then every other module as a
//!    fallback), resolves `_PyRuntime` with [`MemorySource::find_symbol`], and
//!    reads the version from the exported `Py_Version` constant (or, on 3.13+,
//!    from `_Py_DebugOffsets.version` at the start of the runtime). Free-threaded
//!    and debug builds are refused with [`Error::UnsupportedPython`].
//! 2. [`walk`] picks the offset table for (version, OS) ([`offsets`]) and, on
//!    3.13+, overrides it with the target's own `_Py_DebugOffsets`. It then
//!    walks every interpreter's GC generation lists (including the permanent
//!    generation) to collect the tracked objects, and emits each one with the
//!    edges its `tp_traverse` would visit, labelled per the snapshot format.
//!    Untracked objects reached from them (str, bytes, int, float, and
//!    containers the GC untracked) are emitted once each, without
//!    `GC_TRACKED`. Roots: `sys.modules` entries (`ModuleDict`), builtins and
//!    the sys dict (`Interp`), thread dicts and current exceptions
//!    (`ThreadLocals`), and the locals of every thread's frame chain
//!    (`FrameLocal`).
//!
//! The walker only reads. A bad pointer skips that edge, counts a read error
//! and marks the object `PARTIAL`. A corrupt GC list ends the walk with
//! `truncated` set, never a hang. Objects are streamed into the writer; the
//! walker itself keeps the sorted list of tracked addresses (8 bytes each), the
//! set of emitted untracked addresses, and a type cache.
//!
//! The per-version layouts are documented in `docs/cpython-internals.md`.
//!
//! [`frames`] exposes the subset of those layouts that allocation recorders
//! need to read Python stacks of a running target ([`frames::FrameOffsets`]),
//! with reference readers that work on any [`MemorySource`].

use heapspy_snapshot::{PythonVersion, SnapshotWriter};

use crate::dump::DumpOptions;
use crate::error::{Error, Result};
use crate::source::{MemorySource, MemorySourceExt, Module};
use crate::symbols;

pub mod frames;
pub mod offsets;
mod pagecache;
pub mod text;
mod walker;

#[cfg(test)]
mod tests;

pub use frames::{frame_offsets, FrameOffsets};
pub use offsets::Offsets;

/// Where the runtime lives and which version it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeLocation {
    /// The module that exports `_PyRuntime`.
    pub module: Module,
    /// Address of `_PyRuntime`.
    pub runtime_addr: u64,
    pub version: PythonVersion,
    pub free_threaded: bool,
    pub debug_build: bool,
}

/// Counters from one walk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalkStats {
    pub objects: u64,
    pub edges: u64,
    pub roots: u64,
    /// Reads that failed; affected objects carry `ObjectFlags::PARTIAL`.
    pub read_errors: u64,
    /// The walk stopped before visiting everything.
    pub truncated: bool,
}

/// Lowest and highest supported minor versions of CPython 3.
pub const MIN_MINOR: u8 = 12;
pub const MAX_MINOR: u8 = 14;

/// Decode `PY_VERSION_HEX`.
pub fn version_from_hex(hex: u32) -> PythonVersion {
    PythonVersion {
        major: (hex >> 24) as u8,
        minor: (hex >> 16) as u8,
        micro: (hex >> 8) as u8,
        release_level: ((hex >> 4) & 0xf) as u8,
        release_serial: (hex & 0xf) as u8,
    }
}

/// Build flags implied by a module file name: `libpython3.13t.so`,
/// `libpython3.12d.so`, `python313t_d.dll`.
fn name_flags(name: &str) -> (bool, bool) {
    if let Some(d) = symbols::pe::python_dll(name) {
        return (d.free_threaded, d.debug);
    }
    let lower = name.to_ascii_lowercase();
    let stem = lower
        .strip_prefix("libpython3.")
        .or_else(|| lower.strip_prefix("python3."))
        .unwrap_or("");
    let abi: String = stem
        .trim_start_matches(|c: char| c.is_ascii_digit())
        .chars()
        .take_while(|c| *c != '.')
        .collect();
    (abi.contains('t'), abi.contains('d'))
}

/// Find `_PyRuntime` and the CPython version.
pub fn locate_runtime(src: &dyn MemorySource) -> Result<RuntimeLocation> {
    let modules = src.modules()?;
    let first = symbols::find_python_module(&modules).cloned();
    let mut candidates: Vec<Module> = first.iter().cloned().collect();
    candidates.extend(
        modules
            .iter()
            .filter(|m| Some(*m) != first.as_ref())
            .cloned(),
    );

    let mut found = None;
    let mut last_err = None;
    for (i, m) in candidates.iter().enumerate() {
        match src.find_symbol(m, "_PyRuntime") {
            Ok(Some(addr)) => {
                found = Some((m.clone(), addr));
                break;
            }
            Ok(None) => {}
            // Only the preferred module's errors are interesting; the others
            // are often not images at all.
            Err(e) if i == 0 => last_err = Some(e),
            Err(_) => {}
        }
    }
    let Some((module, runtime_addr)) = found else {
        let why = match last_err {
            Some(e) => format!("no _PyRuntime symbol found ({e})"),
            None => "no module exports _PyRuntime".to_string(),
        };
        if symbols::is_windows_launcher(&modules) {
            return Err(Error::NotPython(format!(
                "{why}; {} loads no python3XY.dll, so it is probably a venv launcher: \
                 read the python.exe it started (its child process) instead",
                modules[0].name
            )));
        }
        return Err(Error::NotPython(why));
    };

    // Version: `Py_Version` (3.11+), else `_Py_DebugOffsets.version`.
    let mut hex = match src.find_symbol(&module, "Py_Version") {
        Ok(Some(a)) => src.read_u32(a).ok(),
        _ => None,
    };
    let cookie = src.read_array::<8>(runtime_addr).ok();
    let has_debug_offsets = cookie.as_ref() == Some(offsets::DEBUG_COOKIE);
    if hex.is_none() && has_debug_offsets {
        hex = src.read_u64(runtime_addr + 8).ok().map(|v| v as u32);
    }
    let Some(hex) = hex else {
        return Err(Error::NotPython(format!(
            "found _PyRuntime in {} but could not read the version",
            module.name
        )));
    };
    let version = version_from_hex(hex);

    let (mut free_threaded, mut debug_build) = name_flags(&module.name);
    if has_debug_offsets && version.minor >= 13 {
        // `_Py_DebugOffsets.free_threaded` (uint64 at +16) on 3.13+.
        if let Ok(v) = src.read_u64(runtime_addr + 16) {
            free_threaded |= v == 1;
        }
    }
    if let Ok(Some(_)) = src.find_symbol(&module, "_Py_NegativeRefcount") {
        debug_build = true;
    }

    let loc = RuntimeLocation {
        module,
        runtime_addr,
        version,
        free_threaded,
        debug_build,
    };
    check_supported(&loc)?;
    Ok(loc)
}

fn check_supported(rt: &RuntimeLocation) -> Result<()> {
    let v = rt.version;
    if v.major != 3 || !(MIN_MINOR..=MAX_MINOR).contains(&v.minor) {
        return Err(Error::UnsupportedPython(format!(
            "CPython {v} (supported: 3.{MIN_MINOR} to 3.{MAX_MINOR})"
        )));
    }
    if rt.free_threaded {
        return Err(Error::UnsupportedPython(format!(
            "CPython {v} free-threaded build (only the default GIL build is supported)"
        )));
    }
    if rt.debug_build {
        return Err(Error::UnsupportedPython(format!(
            "CPython {v} debug build (Py_DEBUG changes object layouts)"
        )));
    }
    Ok(())
}

/// The offsets to use for `rt` in `src`: the shipped table, overridden by the
/// target's `_Py_DebugOffsets` on 3.13+.
pub fn offsets_for(src: &dyn MemorySource, rt: &RuntimeLocation) -> Result<Offsets> {
    let os = src.target().os;
    let mut o = Offsets::table(rt.version.minor, os).ok_or_else(|| {
        Error::UnsupportedPython(format!("no offset table for CPython {}", rt.version))
    })?;
    if rt.version.minor >= 13 {
        // A missing cookie means the image is odd, not that the table is
        // wrong; keep the table in that case.
        if let Ok(true) = o.apply_debug_offsets(src, rt.runtime_addr) {
            return Err(Error::UnsupportedPython(format!(
                "CPython {} free-threaded build",
                rt.version
            )));
        }
    }
    Ok(o)
}

/// Walk the heap and stream objects, edges, types and roots into `out`.
pub fn walk(
    src: &dyn MemorySource,
    rt: &RuntimeLocation,
    opts: &DumpOptions,
    out: &mut SnapshotWriter,
) -> Result<WalkStats> {
    check_supported(rt)?;
    if src.target().pointer_size != 8 {
        return Err(Error::Unsupported(format!(
            "{}-byte pointers (only 64-bit targets are supported)",
            src.target().pointer_size
        )));
    }
    let o = offsets_for(src, rt)?;
    let cached = pagecache::PageCache::new(src);
    let stats = walker::Walker::new(&cached, o, opts, out).run(rt.runtime_addr)?;
    Ok(stats)
}
