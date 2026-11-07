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

pub mod allocations;
mod analysis;
mod diff;
mod dominators;
pub mod flame;
mod graph;
mod locate;
mod notes;
mod query;
pub mod render;
pub mod report;
pub mod source;

use heapspy_snapshot::{ObjectFlags, RegionKind, Snapshot};

use analysis::Analysis;
pub use flame::{
    folded_diff, folded_stacks, DiffLine, FlameOptions, FoldedDiff, FoldedLine, FoldedStacks,
    MinWidth,
};
use report::{
    Address, AnalyzeKind, AnalyzeReport, DiffReport, MemoryPart, MemoryTotals, NativeAllocator,
    Retainer, RetainingPathReport, SchemaVersion, SizeGroup, SnapshotSummary, SourceRef, Totals,
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

/// Native heap blocks in the graph: all of them, and those nothing reaches.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativeCounts {
    pub blocks: u64,
    pub bytes: u64,
    pub lost_blocks: u64,
    pub lost_bytes: u64,
}

fn native_counts(a: &Analysis) -> NativeCounts {
    let mut c = NativeCounts::default();
    for i in 0..a.snap.object_count() as u32 {
        let o = a.snap.object(i);
        if !o.flags.contains(ObjectFlags::NATIVE) {
            continue;
        }
        c.blocks += 1;
        c.bytes += o.shallow_size;
        if !a.reachable(i) {
            c.lost_blocks += 1;
            c.lost_bytes += o.shallow_size;
        }
    }
    c
}

/// `graph_bytes` is the Python objects' bytes; native blocks are counted in
/// the breakdown, from `native`.
fn memory_totals(snap: &Snapshot, graph_bytes: u64, native: &NativeCounts) -> Result<MemoryTotals> {
    let rss = rss_bytes(snap)?;
    let outside = rss.map(|r| r.saturating_sub(graph_bytes));
    let native_allocator = native_allocator(snap)?;
    let (breakdown, breakdown_basis) =
        memory_breakdown(snap, graph_bytes, native, native_allocator.as_ref())?;
    Ok(MemoryTotals {
        rss_bytes: rss,
        graph_bytes,
        outside_graph_bytes: outside,
        outside_graph_pct: rss.zip(outside).map(|(r, o)| pct(o, r)),
        breakdown,
        breakdown_basis,
        native_lost_by_size: Vec::new(),
        native_allocator,
    })
}

/// `memory.native_allocator`, from the `native.*` meta the heap walk wrote.
fn native_allocator(snap: &Snapshot) -> Result<Option<NativeAllocator>> {
    let Some(free_bytes) = meta_u64(snap, "native.free_bytes")? else {
        return Ok(None);
    };
    Ok(Some(NativeAllocator {
        arenas: meta_u64(snap, "native.arenas")?.unwrap_or(0),
        free_chunks: meta_u64(snap, "native.free_chunks")?.unwrap_or(0),
        free_bytes,
        top_bytes: meta_u64(snap, "native.top_bytes")?.unwrap_or(0),
    }))
}

/// Leaked native blocks grouped by size, most bytes first, at most `top`.
fn lost_by_size(a: &Analysis, top: usize) -> Vec<SizeGroup> {
    let mut by: std::collections::HashMap<u64, (u64, u64)> = std::collections::HashMap::new();
    for i in 0..a.snap.object_count() as u32 {
        let o = a.snap.object(i);
        if o.flags.contains(ObjectFlags::NATIVE) && !a.reachable(i) {
            let e = by.entry(o.shallow_size).or_default();
            e.0 += 1;
            e.1 += o.shallow_size;
        }
    }
    let mut v: Vec<SizeGroup> = by
        .into_iter()
        .map(|(size, (blocks, bytes))| SizeGroup {
            size,
            blocks,
            bytes,
        })
        .collect();
    v.sort_by(|x, y| y.bytes.cmp(&x.bytes).then(x.size.cmp(&y.size)));
    v.truncate(top);
    v
}

/// Per node, the bytes of native heap blocks in its dominator subtree.
pub(crate) fn native_retained(a: &Analysis) -> Vec<u64> {
    let n = a.root() as usize;
    let mut acc = vec![0u64; n + 1];
    for i in 0..n as u32 {
        let o = a.snap.object(i);
        if o.flags.contains(ObjectFlags::NATIVE) {
            acc[i as usize] = o.shallow_size;
        }
    }
    // Children come after their idom in `order`, so a reverse sweep adds
    // every subtree into its parent before the parent is added upward.
    for &v in a.order.iter().rev() {
        let p = a.idom[v as usize];
        if p != dominators::NONE && (v as usize) < acc.len() {
            acc[p as usize] += acc[v as usize];
        }
    }
    acc
}

fn meta_u64(snap: &Snapshot, key: &str) -> Result<Option<u64>> {
    Ok(snap
        .meta_value(key)?
        .and_then(|v| v.trim().parse::<u64>().ok()))
}

/// What the process's memory is: the memory map's regions by kind, with
/// private memory split by what the walk learned about it.
///
/// - Images, mapped files and thread stacks come from the map as they are.
/// - Private memory (heaps and anonymous mappings) holds pymalloc's arenas,
///   whose pool headers say how much is handed out (`python_small_objects`)
///   and how much is held in reserve (`pymalloc_free`); Python objects too
///   large for pymalloc, which come from `malloc` (`python_large_objects`:
///   the object graph's bytes beyond what pymalloc holds); and the rest,
///   which is memory C code allocated. When the heaps were walked, that rest
///   splits into heap blocks something points to (`native_heap`), heap
///   blocks nothing points to (`native_lost`), and private memory outside
///   any heap block (`native_other`: allocator overhead and free space, and
///   memory C code mapped itself). Otherwise it is one `native_unknown`.
///
/// Counts resident bytes where every region knows them, committed bytes
/// otherwise (a minidump does not record residency).
fn memory_breakdown(
    snap: &Snapshot,
    graph_bytes: u64,
    native_blocks: &NativeCounts,
    allocator: Option<&NativeAllocator>,
) -> Result<(Vec<MemoryPart>, Option<String>)> {
    let Some(regions) = snap.memory_summary() else {
        return Ok((Vec::new(), None));
    };
    let resident = regions.iter().all(|r| r.resident_bytes.is_some());
    let by = |kinds: &[RegionKind]| -> u64 {
        regions
            .iter()
            .filter(|r| kinds.contains(&r.kind))
            .map(|r| {
                if resident {
                    r.resident_bytes.unwrap_or(0)
                } else {
                    r.mapped_bytes
                }
            })
            .sum()
    };
    let images = by(&[RegionKind::Image]);
    let mapped = by(&[RegionKind::MappedFile]);
    let stacks = by(&[RegionKind::Stack]);
    let private = by(&[
        RegionKind::Heap,
        RegionKind::Anonymous,
        RegionKind::PythonArena,
        RegionKind::Other,
    ]);
    let used = meta_u64(snap, "pymalloc.used_bytes")?.unwrap_or(0);
    let arenas = meta_u64(snap, "pymalloc.arena_bytes")?
        .unwrap_or(0)
        .max(used);
    let large = graph_bytes.saturating_sub(used);
    let native = private.saturating_sub(arenas).saturating_sub(large);
    let part = |part: &str, bytes: u64| MemoryPart {
        part: part.to_string(),
        bytes,
    };
    let mut parts = vec![
        part("images", images),
        part("mapped_files", mapped),
        part("stacks", stacks),
        part("python_small_objects", used),
        part("pymalloc_free", arenas - used),
        part("python_large_objects", large),
    ];
    if native_blocks.blocks > 0 {
        let lost = native_blocks.lost_bytes;
        let held = native_blocks.bytes - lost;
        parts.push(part("native_heap", held));
        parts.push(part("native_lost", lost));
        let other = native.saturating_sub(native_blocks.bytes);
        // Free chunks and top chunks are counted from headers, which can
        // include pages that are not resident: never more than what is left.
        let free = allocator.map_or(0, |f| (f.free_bytes + f.top_bytes).min(other));
        if allocator.is_some() {
            parts.push(part("native_free", free));
        }
        parts.push(part("native_other", other - free));
    } else {
        parts.push(part("native_unknown", native));
    }
    let basis = if resident { "resident" } else { "committed" };
    Ok((parts, Some(basis.to_string())))
}

/// Dominator tree, retained sizes, top retainers, type histogram.
pub fn analyze(snap: &Snapshot, path: &str, opts: &AnalyzeOptions) -> Result<AnalyzeReport> {
    let a = Analysis::new(snap)?;
    Ok(analyze_with(&a, path, opts)?.0)
}

/// The analyze report of an analysed snapshot, and the node of each entry
/// of `top_retainers`, in order.
pub(crate) fn analyze_with(
    a: &Analysis,
    path: &str,
    opts: &AnalyzeOptions,
) -> Result<(AnalyzeReport, Vec<u32>)> {
    let snap = a.snap;
    // Everything the super-root reaches, external roots included: the base
    // for percentages, since that is all the memory something holds.
    let reachable_bytes = a.reachable_bytes();
    let held_objects = a.reachable_objects();
    let rec = a.g.reconciliation;
    let native = native_counts(a);
    let totals = Totals {
        objects: snap.object_count() as u64,
        edges: snap.edge_count() as u64,
        types: a.types.names.len() as u64 - 1,
        roots: snap.root_count() as u64,
        shallow_bytes: a.shallow_total,
        reachable_objects: held_objects - a.external_objects,
        reachable_bytes: reachable_bytes - a.external_bytes,
        external_objects: a.external_objects,
        external_bytes: a.external_bytes,
        unreachable_objects: snap.object_count() as u64 - held_objects - native.lost_blocks,
        unreachable_bytes: a.shallow_total - reachable_bytes - native.lost_bytes,
        dangling_edges: a.g.dangling_edges,
        refcounts_checked: rec.refcounts,
        borrowed_edges_dropped: rec.scanned_dropped,
        stale_edges_dropped: rec.speculative_dropped,
        out_of_line_edges: rec.speculative_kept,
        native_blocks: native.blocks,
        native_bytes: native.bytes,
        native_lost_blocks: native.lost_blocks,
        native_lost_bytes: native.lost_bytes,
    };
    let mut memory = memory_totals(snap, a.shallow_total - native.bytes, &native)?;
    if native.lost_blocks > 0 {
        memory.native_lost_by_size = lost_by_size(a, opts.top);
    }

    let mut top_retainers = Vec::new();
    let nodes = a.top_retainers(opts.top)?;
    let native_ret = if native.blocks > 0 {
        native_retained(a)
    } else {
        Vec::new()
    };
    for (i, &v) in nodes.iter().enumerate() {
        let o = snap.object(v);
        let bytes = a.retained[v as usize];
        let (type_location, type_location_reason) = a.type_location(v)?;
        top_retainers.push(Retainer {
            rank: i as u32 + 1,
            address: Address(o.addr),
            type_name: a.type_name(v).to_string(),
            shallow_bytes: o.shallow_size,
            retained_bytes: bytes,
            retained_objects: a.retained_count[v as usize] as u64,
            retained_pct: pct(bytes, reachable_bytes),
            path: a.path(v)?.unwrap_or_default(),
            native_retained_bytes: Some(native_ret.get(v as usize).copied().unwrap_or(0)),
            allocated_at: None,
            type_location,
            type_location_reason,
        });
    }

    let mut type_histogram = a.type_rows();
    type_histogram.sort_by(|x, y| {
        (y.retained_bytes, y.shallow_bytes)
            .cmp(&(x.retained_bytes, x.shallow_bytes))
            .then_with(|| x.type_name.cmp(&y.type_name))
    });
    type_histogram.truncate(opts.top);
    for row in &mut type_histogram {
        let g = a
            .types
            .find(&row.type_name)
            .expect("row from the type table");
        (row.type_location, row.type_location_reason) = a.group_location(g)?;
    }

    let mut notes = vec![notes::untracked_objects()];
    if let (Some(rss), Some(out)) = (memory.rss_bytes, memory.outside_graph_bytes) {
        if out > rss / 2 {
            notes.push(notes::outside_graph(memory.graph_bytes, rss));
        }
    }
    if totals.native_lost_blocks > 0 {
        notes.push(notes::native_lost(
            totals.native_lost_blocks,
            totals.native_lost_bytes,
        ));
    }
    notes::header_notes(snap, &mut notes);
    if a.g.dangling_edges > 0 {
        notes.push(notes::dangling_edges(a.g.dangling_edges));
    }
    if a.g.missing_roots > 0 {
        notes.push(notes::missing_roots(a.g.missing_roots));
    }

    let report = AnalyzeReport {
        schema_version: SchemaVersion,
        kind: AnalyzeKind::Kind,
        snapshot: snapshot_summary(snap, path),
        totals,
        memory,
        top_retainers,
        type_histogram,
        notes,
        allocations: None,
    };
    Ok((report, nodes))
}

/// Instances of one type with sizes and sample holders. Fails with
/// [`Error::NotFound`] if no type matches.
pub fn query_type(
    snap: &Snapshot,
    path: &str,
    type_name: &str,
    opts: &QueryOptions,
) -> Result<TypeQueryReport> {
    let a = Analysis::new(snap)?;
    Ok(query::query_type(&a, path, type_name, opts)?.0)
}

/// Where the type, function or module named `module.qualname` is defined.
/// Fails with [`Error::NotFound`] if nothing has that name.
pub fn locate(
    snap: &Snapshot,
    path: &str,
    name: &str,
    opts: &QueryOptions,
) -> Result<report::LocateReport> {
    locate::locate(snap, path, name, opts)
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
