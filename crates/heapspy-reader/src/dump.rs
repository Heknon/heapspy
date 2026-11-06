//! `heapspy dump`: memory source -> snapshot file.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use heapspy_snapshot::{
    PythonVersion, SnapshotInfo, SnapshotWriter, SourceInfo, SourceKind, FORMAT_VERSION,
};

use crate::cpython;
use crate::error::Result;
use crate::source::MemorySource;

/// Default cap on captured string / bytes / key text, in characters.
pub const DEFAULT_MAX_STR: usize = 128;

/// Options for [`dump`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DumpOptions {
    /// Capture str / bytes contents and ordinary dict keys as text. Off by
    /// default: contents often hold credentials and user data.
    pub capture_contents: bool,
    /// Cap, in characters, for any captured text (contents and key reprs).
    /// Longer values are cut and marked truncated.
    pub max_str: usize,
    /// Recorded in the snapshot header.
    pub source_kind: SourceKind,
    /// Recorded in the snapshot header: PID as text, or the input path.
    pub source_ref: String,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self {
            capture_contents: false,
            max_str: DEFAULT_MAX_STR,
            source_kind: SourceKind::Pid,
            source_ref: String::new(),
        }
    }
}

/// Result of a successful [`dump`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DumpStats {
    /// CPython version found in the target.
    pub python: PythonVersion,
    pub objects: u64,
    pub edges: u64,
    pub types: u64,
    pub roots: u64,
    pub bytes_written: u64,
    pub read_errors: u64,
    /// The snapshot is marked truncated: the walk did not finish, or the
    /// image is missing memory its headers describe.
    pub truncated: bool,
    /// [`MemorySource::missing_bytes`] of the source.
    pub image_missing_bytes: u64,
    /// How long a live target was stopped ([`MemorySource::release`]);
    /// `None` for file sources and backends that do not measure it.
    pub pause: Option<Duration>,
}

/// Read the CPython heap from `source` and write a snapshot to `out`.
///
/// The output is written to a temporary file next to `out` and renamed into
/// place on success, so a failed dump never leaves a partial snapshot.
pub fn dump(source: &dyn MemorySource, opts: &DumpOptions, out: &Path) -> Result<DumpStats> {
    let runtime = cpython::locate_runtime(source)?;
    let target = source.target();
    let captured_at = source.captured_at().unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    let info = SnapshotInfo {
        format_version: FORMAT_VERSION,
        python: runtime.version,
        pointer_size: target.pointer_size,
        target_little_endian: target.little_endian,
        os: target.os,
        arch: target.arch,
        captured_at,
        source: SourceInfo {
            kind: opts.source_kind,
            reference: opts.source_ref.clone(),
        },
        contents_captured: opts.capture_contents,
        truncated: false,
        free_threaded: runtime.free_threaded,
        debug_build: runtime.debug_build,
    };

    let spill_dir = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut writer = SnapshotWriter::with_spill_dir(info, spill_dir)?;
    writer.add_meta("heapspy.version", env!("CARGO_PKG_VERSION"))?;
    if let Some(summary) = source.memory_summary() {
        for r in summary.regions {
            writer.add_memory_region(r);
        }
        if let Some(rss) = summary.rss_bytes {
            writer.add_meta("process.rss_bytes", &rss.to_string())?;
        }
    }

    let walk = cpython::walk(source, &runtime, opts, &mut writer)?;
    // Resume a live target before the snapshot is written.
    let pause = source.release();
    // An image that is missing part of its own memory (a cut core) can make
    // the walk skip objects without noticing, so it is never complete.
    let image_missing_bytes = source.missing_bytes();
    let truncated = walk.truncated || image_missing_bytes > 0;
    writer.info_mut().truncated = truncated;
    if image_missing_bytes > 0 {
        writer.add_meta("image.missing_bytes", &image_missing_bytes.to_string())?;
    }
    let w = writer.finish_to_path(out)?;
    Ok(DumpStats {
        python: runtime.version,
        objects: w.objects,
        edges: w.edges,
        types: w.types,
        roots: w.roots,
        bytes_written: w.bytes_written,
        read_errors: walk.read_errors,
        truncated,
        image_missing_bytes,
        pause,
    })
}
