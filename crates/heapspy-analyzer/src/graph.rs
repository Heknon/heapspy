//! Load a snapshot's objects and edges into a [`Csr`] indexed by object index.

use heapspy_snapshot::{EdgeOrigin, ObjectFlags, Root, RootKind, Snapshot};

use crate::dominators::{Csr, NONE};
use crate::Result;

/// Root label for an object nothing in the graph accounts for, whose
/// refcount says something outside it holds a reference: native code, a C
/// global, memory the walker could not lay out.
pub const EXTERNAL_ROOT_LABEL: &str = "held outside the Python graph";
/// `root_kind` of such a root in reports.
pub const EXTERNAL_ROOT_KIND: &str = "external";

/// What reconciling edges against refcounts did. All zero for a snapshot
/// without refcounts, where every edge is taken as it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Whether the snapshot had refcounts to reconcile against.
    pub refcounts: bool,
    /// Scanned edges dropped because their target had more of them than
    /// owners: fields that borrow rather than own.
    pub scanned_dropped: u64,
    /// Speculative (out-of-line) edges kept, and dropped as stale.
    pub speculative_kept: u64,
    pub speculative_dropped: u64,
}

/// The object graph plus a synthetic super-root.
///
/// Nodes `0..n` are the snapshot's objects by index; node `n` is the
/// super-root, with one edge to every distinct root object. For `e < edge_count`
/// (the snapshot's edge count), CSR edge `e` *is* snapshot edge `e`: dangling
/// edges are kept as [`NONE`] placeholders so the positions line up, and the
/// edge label is read back from the snapshot when a path is rendered.
pub struct ObjectGraph {
    pub csr: Csr,
    /// Number of objects; also the super-root's node id.
    pub n: u32,
    /// Number of snapshot edges. CSR edges at or above this index are
    /// super-root edges.
    pub snapshot_edges: u32,
    /// Edges whose target address is not an object in the snapshot.
    pub dangling_edges: u64,
    /// Root entries whose address is not an object in the snapshot.
    pub missing_roots: u64,
    /// For each super-root edge `snapshot_edges + k`, the root entry chosen to
    /// describe that root object (see [`primary_root`]).
    pub root_entries: Vec<Root>,
    pub reconciliation: Reconciliation,
    /// Super-root edges by BFS phase: stable roots (modules, interpreter
    /// state), then transient ones (frames, thread state), then external.
    /// Each is a range of CSR edge indices.
    pub root_phases: [std::ops::Range<u32>; 3],
}

impl ObjectGraph {
    /// The root entry for a super-root edge, or `None` for an ordinary edge
    /// or an external root.
    pub fn root_entry(&self, e: u32) -> Option<&Root> {
        e.checked_sub(self.snapshot_edges)
            .and_then(|k| self.root_entries.get(k as usize))
    }

    /// Whether `e` is a super-root edge to an external root.
    pub fn is_external_root(&self, e: u32) -> bool {
        e.checked_sub(self.snapshot_edges)
            .is_some_and(|k| k as usize >= self.root_entries.len())
    }

    /// Label and kind of the root a super-root edge leads to. `None` for an
    /// ordinary edge.
    pub fn root_label(&self, snap: &Snapshot, e: u32) -> Result<Option<(String, String)>> {
        if self.is_external_root(e) {
            return Ok(Some((
                EXTERNAL_ROOT_LABEL.to_string(),
                EXTERNAL_ROOT_KIND.to_string(),
            )));
        }
        match self.root_entry(e) {
            Some(r) => Ok(Some((
                snap.string(r.label)?.to_string(),
                r.kind.as_str().to_string(),
            ))),
            None => Ok(None),
        }
    }
}

/// Rank used to pick one root entry when an object is listed as a root more
/// than once: module first, then frame locals, thread state, interpreter
/// state, other; ties broken by label text. The choice is stable across dumps
/// of the same program, which the diff relies on.
fn root_rank(kind: RootKind) -> u8 {
    match kind {
        RootKind::ModuleDict => 0,
        RootKind::FrameLocal => 1,
        RootKind::ThreadLocals => 2,
        RootKind::Interp => 3,
        RootKind::Other => 4,
        RootKind::Unknown(_) => 5,
    }
}

/// Exact-match lookup in the sorted object addresses.
///
/// A plain binary search over tens of millions of addresses misses the cache
/// on almost every probe. This keeps every [`BLOCK`]th address in a small
/// array (n / 64 entries, a few MiB at most, so it stays cached), searches
/// that first, then searches one 64-entry block of the full array. That is
/// two or three cache misses per lookup instead of about twenty, and it does
/// not depend on how addresses are distributed.
struct AddrIndex {
    addrs: Vec<u64>,
    sample: Vec<u64>,
}

const BLOCK: usize = 64;

impl AddrIndex {
    fn new(addrs: Vec<u64>) -> AddrIndex {
        let sample = addrs.iter().step_by(BLOCK).copied().collect();
        AddrIndex { addrs, sample }
    }

    #[inline]
    fn find(&self, a: u64) -> Option<u32> {
        // Block b holds addrs[b * BLOCK ..]; pick the last block starting <= a.
        let b = self.sample.partition_point(|&s| s <= a).checked_sub(1)?;
        let start = b * BLOCK;
        let end = (start + BLOCK).min(self.addrs.len());
        self.addrs[start..end]
            .binary_search(&a)
            .ok()
            .map(|i| (start + i) as u32)
    }
}

fn limit(what: &'static str) -> crate::Error {
    crate::Error::Snapshot(heapspy_snapshot::Error::LimitExceeded(what))
}

/// Resolve every edge target and build the graph.
///
/// Targets are resolved with [`AddrIndex`]; it is dropped before returning.
pub fn build(snap: &Snapshot) -> Result<ObjectGraph> {
    let n = snap.object_count();
    let e = snap.edge_count();
    if n >= NONE as usize {
        return Err(limit("more than 2^32 - 2 objects"));
    }
    let index = AddrIndex::new((0..n as u32).map(|i| snap.object_addr(i)).collect());
    let find = |a: u64| index.find(a);

    // Roots: one super-root edge per distinct root object.
    let mut missing_roots = 0u64;
    let mut roots: Vec<(u32, Root)> = Vec::with_capacity(snap.root_count());
    for r in snap.roots() {
        match find(r.addr) {
            Some(i) => roots.push((i, r)),
            None => missing_roots += 1,
        }
    }
    let mut keyed = Vec::with_capacity(roots.len());
    for (i, r) in roots {
        let label = snap.string(r.label)?.to_string();
        keyed.push((i, root_rank(r.kind), label, r));
    }
    keyed.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
    keyed.dedup_by_key(|k| k.0);
    // Super-root edges go out in root-rank order (modules first), then by
    // label. BFS visits roots in this order, so when an object is equally
    // close to several roots its shortest path starts at the best-ranked
    // one: a global is reported under `sys.modules[...]`, not under a frame
    // local that happens to hold a function whose `__globals__` is the same
    // module dict. Ordering by object index would make that choice depend on
    // addresses, which change from one dump to the next.
    //
    // Stable roots (modules, interpreter state) go before transient ones
    // (frame locals, thread state), and the BFS finishes the stable ones
    // before it starts the others (see `ObjectGraph::root_phases`). A path
    // then starts at a frame only when nothing longer-lived holds the object.
    keyed.sort_by(|a, b| {
        (transient(a.3.kind), a.1, &a.2, a.0).cmp(&(transient(b.3.kind), b.1, &b.2, b.0))
    });
    let stable_roots = keyed.iter().filter(|k| !transient(k.3.kind)).count() as u32;
    let root_nodes: Vec<u32> = keyed.iter().map(|k| k.0).collect();
    let root_entries: Vec<Root> = keyed.into_iter().map(|k| k.3).collect();

    e.checked_add(root_nodes.len())
        .filter(|&t| t < NONE as usize)
        .ok_or_else(|| limit("more than 2^32 - 2 edges"))?;

    let mut offsets = Vec::with_capacity(n + 2);
    let mut targets = Vec::with_capacity(e + root_nodes.len());
    let mut dangling = 0u64;
    for i in 0..n as u32 {
        offsets.push(targets.len() as u32);
        for a in snap.edge_targets(i) {
            match find(a) {
                Some(t) => targets.push(t),
                None => {
                    dangling += 1;
                    targets.push(NONE);
                }
            }
        }
    }
    debug_assert_eq!(targets.len(), e);
    offsets.push(targets.len() as u32);
    drop(index);

    let (reconciliation, unexplained) = reconcile(snap, &mut targets);

    // External roots: objects no root reaches that something outside the
    // graph holds. Found before the super-root's edges are appended, so the
    // reachability below is from the real roots only.
    let external = external_roots(&offsets, &targets, &root_nodes, &unexplained);

    targets.extend_from_slice(&root_nodes);
    targets.extend_from_slice(&external);
    offsets.push(targets.len() as u32);

    let first = e as u32;
    let transient_start = first + stable_roots;
    let external_start = first + root_nodes.len() as u32;
    let end = external_start + external.len() as u32;
    Ok(ObjectGraph {
        csr: Csr { offsets, targets },
        n: n as u32,
        snapshot_edges: e as u32,
        dangling_edges: dangling,
        missing_roots,
        root_entries,
        reconciliation,
        root_phases: [
            first..transient_start,
            transient_start..external_start,
            external_start..end,
        ],
    })
}

/// Roots that exist only while a thread is running a function.
fn transient(kind: RootKind) -> bool {
    matches!(kind, RootKind::FrameLocal | RootKind::ThreadLocals)
}

/// The refcount of object `i`, if it can be compared with edge counts:
/// recorded, and not immortal (an immortal object's count is a sentinel).
fn owners(snap: &Snapshot, i: u32) -> Option<u64> {
    if snap.object(i).flags.contains(ObjectFlags::IMMORTAL) {
        return None;
    }
    snap.refcount(i)
}

/// Check the edges the walker was unsure of against the targets' refcounts.
///
/// A refcount is the number of references that own an object. Edges read
/// from a known layout ([`EdgeOrigin::Exact`]) are references. The others
/// are kept only as far as the refcount leaves room for them:
///
/// - A target with more scanned edges than owners left over has scanned
///   fields that borrow. Scanned edges past the count are dropped.
/// - A speculative edge (a pointer found out of line) is kept only while the
///   target still has owners nothing else explains. A stale slot's target
///   is fully explained by its real owners, so its edge is dropped.
///
/// Dropped edges become [`NONE`] placeholders, like dangling ones, so CSR
/// edge `e` stays snapshot edge `e`. Returns what was done and, per object,
/// the owners still unexplained. Without refcounts nothing is checked:
/// scanned edges are kept and speculative ones dropped, since there is
/// nothing to tell a stale pointer from a real one.
fn reconcile(snap: &Snapshot, targets: &mut [u32]) -> (Reconciliation, Vec<u32>) {
    let n = snap.object_count();
    let mut r = Reconciliation {
        refcounts: snap.has_refcounts(),
        ..Reconciliation::default()
    };
    let origin = |g: usize| snap.edge_origin(g as u64);
    if !r.refcounts {
        for (g, t) in targets.iter_mut().enumerate() {
            if *t != NONE && origin(g) == EdgeOrigin::Speculative {
                *t = NONE;
                r.speculative_dropped += 1;
            }
        }
        return (r, Vec::new());
    }

    // Owners left after the exact edges, then after the scanned ones.
    let mut left: Vec<u64> = (0..n as u32)
        .map(|i| owners(snap, i).unwrap_or(u64::MAX))
        .collect();
    for (g, &t) in targets.iter().enumerate() {
        if t != NONE && origin(g) == EdgeOrigin::Exact {
            left[t as usize] = left[t as usize].saturating_sub(1);
        }
    }
    for (g, t) in targets.iter_mut().enumerate() {
        if *t == NONE || origin(g) != EdgeOrigin::Scanned {
            continue;
        }
        let l = &mut left[*t as usize];
        if *l == 0 {
            *t = NONE;
            r.scanned_dropped += 1;
        } else {
            *l = l.saturating_sub(1);
        }
    }
    for (g, t) in targets.iter_mut().enumerate() {
        if *t == NONE || origin(g) != EdgeOrigin::Speculative {
            continue;
        }
        let l = &mut left[*t as usize];
        // u64::MAX: no usable refcount, so nothing to vouch for the pointer.
        if *l == 0 || *l == u64::MAX {
            *t = NONE;
            r.speculative_dropped += 1;
        } else {
            *l -= 1;
            r.speculative_kept += 1;
        }
    }
    let unexplained = left
        .into_iter()
        .map(|l| {
            if l == u64::MAX {
                0
            } else {
                l.min(u32::MAX as u64) as u32
            }
        })
        .collect();
    (r, unexplained)
}

/// Objects to treat as roots because something outside the graph holds
/// them: not reachable from `roots`, with owners `unexplained` by any edge.
///
/// Among such objects, those that others of them point at are left to be
/// reached through those others where possible, so a native-held container
/// is the root and its contents hang below it, not beside it.
fn external_roots(
    offsets: &[u32],
    targets: &[u32],
    roots: &[u32],
    unexplained: &[u32],
) -> Vec<u32> {
    if unexplained.is_empty() {
        return Vec::new();
    }
    let n = unexplained.len();
    let mut seen = vec![false; n];
    let mut stack: Vec<u32> = Vec::new();
    let mark = |from: u32, seen: &mut Vec<bool>, stack: &mut Vec<u32>| {
        if !seen[from as usize] {
            seen[from as usize] = true;
            stack.push(from);
        }
        while let Some(v) = stack.pop() {
            let v = v as usize;
            for &w in &targets[offsets[v] as usize..offsets[v + 1] as usize] {
                if w != NONE && !seen[w as usize] {
                    seen[w as usize] = true;
                    stack.push(w);
                }
            }
        }
    };
    for &r in roots {
        mark(r, &mut seen, &mut stack);
    }
    // In-degree within the part no root reaches.
    let mut indeg = vec![0u32; n];
    for v in 0..n {
        if seen[v] {
            continue;
        }
        for &w in &targets[offsets[v] as usize..offsets[v + 1] as usize] {
            if w != NONE && !seen[w as usize] {
                indeg[w as usize] += 1;
            }
        }
    }
    let candidates: Vec<u32> = (0..n as u32)
        .filter(|&v| !seen[v as usize] && unexplained[v as usize] > 0)
        .collect();
    let mut out = Vec::new();
    for top_only in [true, false] {
        for &v in &candidates {
            if seen[v as usize] || (top_only && indeg[v as usize] > 0) {
                continue;
            }
            out.push(v);
            mark(v, &mut seen, &mut stack);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapspy_snapshot::SnapshotBuilder;

    #[test]
    fn addr_index_matches_binary_search() {
        let addrs: Vec<u64> = (0..1000u64).map(|i| 0x1000 + i * i * 16 + i).collect();
        let idx = AddrIndex::new(addrs.clone());
        for probe in [0, 0x1000, 0x1001, u64::MAX]
            .into_iter()
            .chain(addrs.iter().copied())
            .chain(addrs.iter().map(|a| a + 1))
        {
            assert_eq!(
                idx.find(probe),
                addrs.binary_search(&probe).ok().map(|i| i as u32),
                "{probe:#x}"
            );
        }
        assert_eq!(AddrIndex::new(Vec::new()).find(5), None);
    }

    #[test]
    fn resolves_edges_and_counts_misses() {
        let mut b = SnapshotBuilder::new();
        let t = b.ty("builtins", "dict");
        b.object(0x30, t, 8)
            .dict_value(0x10, "'a'")
            .dict_value(0x99, "'b'");
        b.object(0x10, t, 8).attr(0x10, "self");
        b.root(0x30, RootKind::Other, "z");
        b.root(0x30, RootKind::ModuleDict, "a");
        b.root(0x77, RootKind::Other, "gone");
        let s = b.build().unwrap();
        let g = build(&s).unwrap();
        assert_eq!(g.n, 2);
        assert_eq!(g.dangling_edges, 1);
        assert_eq!(g.missing_roots, 1);
        // Object 0 is 0x10 (self loop), object 1 is 0x30.
        assert_eq!(g.csr.offsets, vec![0, 1, 3, 4]);
        assert_eq!(g.csr.targets, vec![0, 0, NONE, 1]);
        let r = g.root_entry(3).unwrap();
        assert_eq!(r.kind, RootKind::ModuleDict);
        assert!(g.root_entry(2).is_none());
    }
}
