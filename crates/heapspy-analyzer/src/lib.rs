//! Analysis of heapspy snapshots: dominators, retained sizes, type
//! histograms, retaining paths and diffs.
//!
//! The report types in [`report`] are the stable JSON schema (version 1).
//!
//! Pipeline: the snapshot's objects and edges are loaded into a CSR graph
//! with a synthetic super-root pointing at every root object; Lengauer–Tarjan
//! gives the dominator tree; retained sizes are dominator-subtree sums; a BFS
//! from the super-root gives shortest retaining paths. All per-object state
//! is flat `u32`/`u64` arrays indexed by object index.
//!
//! [`folded_stacks`] and [`folded_diff`] turn the dominator tree into folded
//! stacks for a retention flame graph; see the [`flame`] module.

mod analysis;
mod diff;
mod dominators;
pub mod flame;
mod graph;
mod notes;
mod query;
pub mod render;
pub mod report;

use heapspy_snapshot::Snapshot;

use analysis::Analysis;
pub use flame::{
    folded_diff, folded_stacks, DiffLine, FlameOptions, FoldedDiff, FoldedLine, FoldedStacks,
    MinWidth,
};
use report::{
    Address, AnalyzeKind, AnalyzeReport, DiffReport, MemoryTotals, Retainer, RetainingPathReport,
    SchemaVersion, SnapshotSummary, SourceRef, Totals, TypeQueryReport,
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

/// Append one rendered edge label to a root path: `.x` and `[k]` attach
/// directly, anything else (`local 'x'`, `<key ...>`) after a space.
pub fn push_edge(out: &mut String, edge: &str) {
    if !(edge.starts_with('.') || edge.starts_with('[')) {
        out.push(' ');
    }
    out.push_str(edge);
}

/// Join a path's root label and edge labels into one string, e.g.
/// `sys.modules['app.cache'].__dict__['CACHE']`. This is the `site` format
/// of a diff (see `docs/json-schema.md`, "Path hop").
pub fn root_path_string(path: &[report::PathHop]) -> String {
    let mut s = String::new();
    for hop in path {
        if let Some(r) = &hop.root_label {
            s.push_str(r);
        }
        if let Some(e) = &hop.edge {
            push_edge(&mut s, e);
        }
    }
    s
}

/// `part / whole * 100`, rounded to two decimals; 0 when `whole` is 0.
fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    (part as f64 / whole as f64 * 10_000.0).round() / 100.0
}

/// Process RSS: the `process.rss_bytes` meta value if present, else the sum
/// of the memory summary's resident bytes when every region knows them.
fn rss_bytes(snap: &Snapshot) -> Result<Option<u64>> {
    if let Some(v) = snap.meta_value("process.rss_bytes")? {
        if let Ok(n) = v.trim().parse::<u64>() {
            return Ok(Some(n));
        }
    }
    Ok(snap.memory_summary().and_then(|regions| {
        if regions.is_empty() {
            return None;
        }
        regions
            .iter()
            .map(|r| r.resident_bytes)
            .sum::<Option<u64>>()
    }))
}

fn memory_totals(snap: &Snapshot, graph_bytes: u64) -> Result<MemoryTotals> {
    let rss = rss_bytes(snap)?;
    let outside = rss.map(|r| r.saturating_sub(graph_bytes));
    Ok(MemoryTotals {
        rss_bytes: rss,
        graph_bytes,
        outside_graph_bytes: outside,
        outside_graph_pct: rss.zip(outside).map(|(r, o)| pct(o, r)),
    })
}

/// Dominator tree, retained sizes, top retainers, type histogram.
pub fn analyze(snap: &Snapshot, path: &str, opts: &AnalyzeOptions) -> Result<AnalyzeReport> {
    let a = Analysis::new(snap)?;
    let reachable_bytes = a.reachable_bytes();
    let reachable_objects = a.reachable_objects();
    let totals = Totals {
        objects: snap.object_count() as u64,
        edges: snap.edge_count() as u64,
        types: a.types.names.len() as u64 - 1,
        roots: snap.root_count() as u64,
        shallow_bytes: a.shallow_total,
        reachable_objects,
        reachable_bytes,
        unreachable_objects: snap.object_count() as u64 - reachable_objects,
        unreachable_bytes: a.shallow_total - reachable_bytes,
        dangling_edges: a.g.dangling_edges,
    };
    let memory = memory_totals(snap, a.shallow_total)?;

    let mut top_retainers = Vec::new();
    for (i, v) in a.top_retainers(opts.top)?.into_iter().enumerate() {
        let o = snap.object(v);
        let bytes = a.retained[v as usize];
        top_retainers.push(Retainer {
            rank: i as u32 + 1,
            address: Address(o.addr),
            type_name: a.type_name(v).to_string(),
            shallow_bytes: o.shallow_size,
            retained_bytes: bytes,
            retained_objects: a.retained_count[v as usize] as u64,
            retained_pct: pct(bytes, reachable_bytes),
            path: a.path(v)?.unwrap_or_default(),
        });
    }

    let mut type_histogram = a.type_rows();
    type_histogram.sort_by(|x, y| {
        (y.retained_bytes, y.shallow_bytes)
            .cmp(&(x.retained_bytes, x.shallow_bytes))
            .then_with(|| x.type_name.cmp(&y.type_name))
    });
    type_histogram.truncate(opts.top);

    let mut notes = vec![notes::untracked_objects()];
    if let (Some(rss), Some(out)) = (memory.rss_bytes, memory.outside_graph_bytes) {
        if out > rss / 2 {
            notes.push(notes::outside_graph(memory.graph_bytes, rss));
        }
    }
    notes::header_notes(snap, &mut notes);
    if a.g.dangling_edges > 0 {
        notes.push(notes::dangling_edges(a.g.dangling_edges));
    }
    if a.g.missing_roots > 0 {
        notes.push(notes::missing_roots(a.g.missing_roots));
    }

    Ok(AnalyzeReport {
        schema_version: SchemaVersion,
        kind: AnalyzeKind::Kind,
        snapshot: snapshot_summary(snap, path),
        totals,
        memory,
        top_retainers,
        type_histogram,
        notes,
    })
}

/// Instances of one type with sizes and sample holders. Fails with
/// [`Error::NotFound`] if no type matches.
pub fn query_type(
    snap: &Snapshot,
    path: &str,
    type_name: &str,
    opts: &QueryOptions,
) -> Result<TypeQueryReport> {
    query::query_type(snap, path, type_name, opts)
}

/// Shortest retaining paths for an address or a type's instances. Fails
/// with [`Error::NotFound`] if the address is not an object or no type
/// matches.
pub fn retaining_path(
    snap: &Snapshot,
    path: &str,
    target: &PathTarget,
    opts: &QueryOptions,
) -> Result<RetainingPathReport> {
    query::retaining_path(snap, path, target, opts)
}

/// Growth by type and by retaining site between two snapshots. Objects are
/// matched by type name and by site (a label path through the dominator
/// tree), never by address; see the `diff` module docs for the site rule.
pub fn diff(
    before: &Snapshot,
    before_path: &str,
    after: &Snapshot,
    after_path: &str,
    opts: &DiffOptions,
) -> Result<DiffReport> {
    diff::diff(before, before_path, after, after_path, opts)
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
    fn missing_address_is_not_found() {
        let s = SnapshotBuilder::new().build().unwrap();
        assert!(matches!(
            retaining_path(&s, "a", &PathTarget::Address(1), &Default::default()),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(
            query_type(&s, "a", "builtins.dict", &Default::default()),
            Err(Error::NotFound(_))
        ));
    }
}
