//! Load a snapshot's objects and edges into a [`Csr`] indexed by object index.

use heapspy_snapshot::{Root, RootKind, Snapshot};

use crate::dominators::{Csr, NONE};
use crate::Result;

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
}

impl ObjectGraph {
    /// The root entry for a super-root edge.
    pub fn root_entry(&self, e: u32) -> Option<&Root> {
        e.checked_sub(self.snapshot_edges)
            .and_then(|k| self.root_entries.get(k as usize))
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

fn limit(what: &'static str) -> crate::Error {
    crate::Error::Snapshot(heapspy_snapshot::Error::LimitExceeded(what))
}

/// Resolve every edge target and build the graph.
///
/// Targets are resolved by binary search over a copy of the (sorted) object
/// addresses. The copy is contiguous, so the top levels of the search stay
/// in cache; it is dropped before returning.
pub fn build(snap: &Snapshot) -> Result<ObjectGraph> {
    let n = snap.object_count();
    let e = snap.edge_count();
    if n >= NONE as usize {
        return Err(limit("more than 2^32 - 2 objects"));
    }
    let addrs: Vec<u64> = (0..n as u32).map(|i| snap.object_addr(i)).collect();
    let find = |a: u64| addrs.binary_search(&a).ok().map(|i| i as u32);

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
    // Super-root edges go out in object-index order, which is deterministic.
    let root_nodes: Vec<u32> = keyed.iter().map(|k| k.0).collect();
    let root_entries: Vec<Root> = keyed.into_iter().map(|k| k.3).collect();

    let total = e
        .checked_add(root_nodes.len())
        .filter(|&t| t < NONE as usize)
        .ok_or_else(|| limit("more than 2^32 - 2 edges"))?;

    let mut offsets = Vec::with_capacity(n + 2);
    let mut targets = Vec::with_capacity(total);
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
    targets.extend_from_slice(&root_nodes);
    offsets.push(targets.len() as u32);

    Ok(ObjectGraph {
        csr: Csr { offsets, targets },
        n: n as u32,
        snapshot_edges: e as u32,
        dangling_edges: dangling,
        missing_roots,
        root_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapspy_snapshot::SnapshotBuilder;

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
