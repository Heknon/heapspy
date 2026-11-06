//! Analysis of heapspy snapshots: dominators, retained sizes, type
//! histograms, retaining paths and diffs.
//!
//! The report types in [`report`] are the stable JSON schema (version 1).
//! The analysis functions are **stubs** that return [`Error::Unimplemented`];
//! [`snapshot_summary`] is implemented.

mod dominators;
mod graph;
pub mod render;
pub mod report;

use heapspy_snapshot::Snapshot;

use report::{
    Address, AnalyzeReport, DiffReport, RetainingPathReport, SnapshotSummary, SourceRef,
    TypeQueryReport,
};

/// Errors from analysis.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not implemented yet: {0}")]
    Unimplemented(&'static str),

    /// The requested address or type is not in the snapshot.
    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error(transparent)]
    Snapshot(#[from] heapspy_snapshot::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Default length of ranked lists (`--top`).
pub const DEFAULT_TOP: usize = 20;

/// Options for [`analyze`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalyzeOptions {
    /// Length of `top_retainers` and `type_histogram`.
    pub top: usize,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self { top: DEFAULT_TOP }
    }
}

/// Options for [`query_type`] and [`retaining_path`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryOptions {
    /// Length of `top_instances`, `holders`, and `targets` for type path queries.
    pub top: usize,
    /// Maximum number of paths per target in a retaining-path query.
    pub max_paths: usize,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            top: DEFAULT_TOP,
            max_paths: 3,
        }
    }
}

/// Options for [`diff`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffOptions {
    /// Length of `by_type` and `by_site`.
    pub top: usize,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self { top: DEFAULT_TOP }
    }
}

/// What a retaining-path query is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathTarget {
    Address(u64),
    /// A type name, full (`app.session.Session`) or unqualified (`Session`).
    Type(String),
}

/// Build the `snapshot` block of a report. `path` is the file path as given
/// by the user.
pub fn snapshot_summary(snap: &Snapshot, path: &str) -> SnapshotSummary {
    let i = snap.info();
    SnapshotSummary {
        path: path.to_string(),
        format_version: i.format_version,
        python_version: i.python.to_string(),
        os: i.os.as_str().to_string(),
        arch: i.arch.as_str().to_string(),
        pointer_size: i.pointer_size,
        captured_at: i.captured_at,
        source: SourceRef {
            kind: i.source.kind.as_str().to_string(),
            reference: i.source.reference.clone(),
        },
        contents_captured: i.contents_captured,
        truncated: i.truncated,
    }
}

/// Format an address the way reports do: `0x7f3a2c41b0d0`.
pub fn format_address(addr: u64) -> String {
    Address(addr).to_string()
}

/// Dominator tree, retained sizes, top retainers, type histogram. **Stub.**
pub fn analyze(_snap: &Snapshot, _path: &str, _opts: &AnalyzeOptions) -> Result<AnalyzeReport> {
    Err(Error::Unimplemented("analyze"))
}

/// Instances of one type with sizes and sample holders. **Stub.**
pub fn query_type(
    _snap: &Snapshot,
    _path: &str,
    _type_name: &str,
    _opts: &QueryOptions,
) -> Result<TypeQueryReport> {
    Err(Error::Unimplemented("query --type"))
}

/// Shortest retaining paths for an address or a type's instances. **Stub.**
pub fn retaining_path(
    _snap: &Snapshot,
    _path: &str,
    _target: &PathTarget,
    _opts: &QueryOptions,
) -> Result<RetainingPathReport> {
    Err(Error::Unimplemented("query --retaining-path"))
}

/// Growth by type and by retaining site between two snapshots. **Stub.**
pub fn diff(
    _before: &Snapshot,
    _before_path: &str,
    _after: &Snapshot,
    _after_path: &str,
    _opts: &DiffOptions,
) -> Result<DiffReport> {
    Err(Error::Unimplemented("diff"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapspy_snapshot::SnapshotBuilder;

    #[test]
    fn summary_from_snapshot() {
        let mut b = SnapshotBuilder::new();
        b.python(3, 13, 2).captured_at(42);
        let s = b.build().unwrap();
        let sum = snapshot_summary(&s, "a.hpy");
        assert_eq!(sum.python_version, "3.13.2");
        assert_eq!(sum.os, "linux");
        assert_eq!(sum.source.kind, "pid");
        assert_eq!(sum.captured_at, 42);
    }

    #[test]
    fn stubs_are_unimplemented() {
        let s = SnapshotBuilder::new().build().unwrap();
        assert!(matches!(
            analyze(&s, "a", &Default::default()),
            Err(Error::Unimplemented(_))
        ));
        assert!(matches!(
            retaining_path(&s, "a", &PathTarget::Address(1), &Default::default()),
            Err(Error::Unimplemented(_))
        ));
    }
}
