//! CPython heap walker. **Stub.**
//!
//! Planned flow (see README "How it works"):
//!
//! 1. [`locate_runtime`]: pick the Python module
//!    ([`crate::symbols::find_python_module`]), resolve `_PyRuntime` with
//!    [`MemorySource::find_symbol`], and determine the version. On 3.14+ the
//!    runtime starts with `_Py_DebugOffsets` (cookie `xdebugpy`, then
//!    `version` as `PY_VERSION_HEX`) which also gives struct offsets. On
//!    3.12 / 3.13 use shipped per-version offset tables, or DWARF / PDB when
//!    available.
//! 2. [`walk`]: for each interpreter, walk the GC generation lists to find
//!    tracked containers; for each object, emit it with the edges its
//!    `tp_traverse` would visit, labelled per the snapshot format's edge-label
//!    rules. Emit referenced untracked leaves (str, bytes, int, float) as
//!    objects without `GC_TRACKED`. Emit roots: `sys.modules` entries
//!    (`ModuleDict`), thread states and their frames (`ThreadLocals`,
//!    `FrameLocal`), interpreter-level state (`Interp`).
//!
//! Labelling and redaction rules the walker must follow are in
//! `docs/snapshot-format.md`, section "Edge labels" and "Redaction policy".
//! In short: identifiers (attribute names, keys of module / type / instance
//! `__dict__`s, local variable names) are always stored; keys of ordinary
//! dicts are stored as repr text only when `DumpOptions::capture_contents`
//! is set, and otherwise as a [`heapspy_snapshot::redacted_key_placeholder`].

use heapspy_snapshot::{PythonVersion, SnapshotWriter};

use crate::dump::DumpOptions;
use crate::error::{Error, Result};
use crate::source::{MemorySource, Module};

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

/// Find `_PyRuntime` and the CPython version. **Stub.**
pub fn locate_runtime(_src: &dyn MemorySource) -> Result<RuntimeLocation> {
    Err(Error::Unimplemented("locating _PyRuntime"))
}

/// Walk the heap and stream objects, edges, types and roots into `out`. **Stub.**
pub fn walk(
    _src: &dyn MemorySource,
    _runtime: &RuntimeLocation,
    _opts: &DumpOptions,
    _out: &mut SnapshotWriter,
) -> Result<WalkStats> {
    Err(Error::Unimplemented("CPython heap walker"))
}
