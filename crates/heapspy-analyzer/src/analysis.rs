//! One analysed snapshot: graph, dominator tree, retained sizes, shortest
//! paths, type table. Everything the report builders need, as flat arrays
//! indexed by node id (object index; the super-root is node `n`).

use std::collections::HashMap;

use heapspy_snapshot::{EdgeLabel, ObjectFlags, Snapshot, TypeId};

use crate::dominators::{self, NONE};
use crate::graph::{self, ObjectGraph};
use crate::report::{Address, PathHop, RetainingPath, SourceLocation, TypeRow};
use crate::source::Locator;
use crate::Result;

/// Types grouped by display name (`module.qualname`). Two type objects with
/// the same name (a class defined twice, or reloaded) count as one type in
/// every report.
pub struct TypeTable {
    /// Display name per group. The last group is `<unknown>`.
    pub names: Vec<String>,
    /// Group of each type id.
    group_of: Vec<u32>,
    /// `(qualname, group)` for every type entry, for unqualified lookups.
    qualnames: Vec<(String, u32)>,
}

impl TypeTable {
    pub(crate) fn new(snap: &Snapshot) -> Result<TypeTable> {
        let mut names = Vec::new();
        let mut by_name: HashMap<String, u32> = HashMap::new();
        let mut group_of = Vec::with_capacity(snap.type_count());
        let mut qualnames = Vec::with_capacity(snap.type_count());
        for t in 0..snap.type_count() as u32 {
            let name = snap.type_name(TypeId(t))?;
            let g = *by_name.entry(name.clone()).or_insert_with(|| {
                names.push(name);
                names.len() as u32 - 1
            });
            group_of.push(g);
            let entry = snap.type_entry(TypeId(t)).expect("type id in range");
            qualnames.push((snap.string(entry.qualname)?.to_string(), g));
        }
        names.push("<unknown>".to_string());
        Ok(TypeTable {
            names,
            group_of,
            qualnames,
        })
    }

    #[inline]
    pub fn group(&self, t: TypeId) -> u32 {
        self.group_of
            .get(t.0 as usize)
            .copied()
            .unwrap_or(self.names.len() as u32 - 1)
    }

    /// The type ids in group `g`, in id order.
    pub fn type_ids(&self, g: u32) -> impl Iterator<Item = TypeId> + '_ {
        self.group_of
            .iter()
            .enumerate()
            .filter(move |&(_, &x)| x == g)
            .map(|(t, _)| TypeId(t as u32))
    }

    pub fn find(&self, name: &str) -> Option<u32> {
        self.names.iter().position(|n| n == name).map(|g| g as u32)
    }

    /// Groups matching a full name or an unqualified one (`Session` matches
    /// `app.session.Session` and `tests.Session`). Sorted, deduplicated.
    pub fn matching(&self, query: &str) -> Vec<u32> {
        let mut out: Vec<u32> = self
            .qualnames
            .iter()
            .filter(|(q, g)| q == query || self.names[*g as usize] == query)
            .map(|(_, g)| *g)
            .collect();
        if query == "<unknown>" {
            out.push(self.names.len() as u32 - 1);
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// Retained size ratio at which a dominator-tree child "restates" its
/// parent. See [`Analysis::top_retainers`].
pub const CHAIN_RATIO: f64 = 0.9;
/// Longest run of restating wrappers collapsed into one top-retainer entry.
pub const CHAIN_MAX_HOPS: u8 = 8;

pub struct Analysis<'s> {
    pub snap: &'s Snapshot,
    pub g: ObjectGraph,
    pub types: TypeTable,
    /// Immediate dominator per node; [`NONE`] for the super-root and
    /// unreachable objects.
    pub idom: Vec<u32>,
    /// Reachable nodes in DFS preorder, super-root first. A node's idom always
    /// comes before it.
    pub order: Vec<u32>,
    pub retained: Vec<u64>,
    pub retained_count: Vec<u32>,
    /// Dominator-tree preorder number; [`NONE`] if unreachable. The dominator
    /// subtree of `v` is exactly the nodes with `tin` in
    /// `tin[v] .. tin[v] + retained_count[v]`.
    pub tin: Vec<u32>,
    /// CSR edge by which BFS first reached each node (the last hop of one
    /// shortest path); [`NONE`] if unreachable and for the super-root.
    pub via: Vec<u32>,
    /// BFS distance from the super-root in edges; [`NONE`] if unreachable.
    pub dist: Vec<u32>,
    pub shallow_total: u64,
    /// Source locations, computed on demand for what a report shows.
    pub(crate) loc: Locator<'s>,
}

impl<'s> Analysis<'s> {
    pub fn new(snap: &'s Snapshot) -> Result<Analysis<'s>> {
        let g = graph::build(snap)?;
        let types = TypeTable::new(snap)?;
        let n = g.n;
        let d = dominators::dominators(&g.csr, n);
        let (retained, retained_count) = dominators::retained(&d, |v| {
            if v == n {
                0
            } else {
                snap.object(v).shallow_size
            }
        });
        let shallow_total = (0..n).map(|i| snap.object(i).shallow_size).sum();

        // Dominator-tree preorder numbers from subtree sizes: each node hands
        // out consecutive ranges to its children in the order they appear.
        let mut tin = vec![NONE; n as usize + 1];
        let mut next = vec![0u32; n as usize + 1];
        tin[n as usize] = 0;
        next[n as usize] = 1;
        for &v in &d.order[1..] {
            let p = d.idom[v as usize] as usize;
            tin[v as usize] = next[p];
            next[p] += retained_count[v as usize];
            next[v as usize] = tin[v as usize] + 1;
        }
        drop(next);

        let (via, dist) = bfs(&g);
        Ok(Analysis {
            snap,
            g,
            types,
            idom: d.idom,
            order: d.order,
            retained,
            retained_count,
            tin,
            via,
            dist,
            shallow_total,
            loc: Locator::new(snap)?,
        })
    }

    /// `(source_loc, source_loc_reason)` of object `v` itself.
    pub fn source_loc(&self, v: u32) -> Result<(Option<SourceLocation>, Option<String>)> {
        Ok(self.loc.object(v)?.split())
    }

    /// `(type_location, type_location_reason)` of type group `g`.
    pub fn group_location(&self, g: u32) -> Result<(Option<SourceLocation>, Option<String>)> {
        Ok(self.loc.types(self.types.type_ids(g))?.split())
    }

    /// `(type_location, type_location_reason)` of the type of object `v`.
    pub fn type_location(&self, v: u32) -> Result<(Option<SourceLocation>, Option<String>)> {
        self.group_location(self.group(v))
    }

    #[inline]
    pub fn root(&self) -> u32 {
        self.g.n
    }

    #[inline]
    pub fn reachable(&self, v: u32) -> bool {
        self.tin[v as usize] != NONE
    }

    pub fn reachable_bytes(&self) -> u64 {
        self.retained[self.root() as usize]
    }

    /// Objects reachable from a root (the super-root excluded).
    pub fn reachable_objects(&self) -> u64 {
        self.retained_count[self.root() as usize] as u64 - 1
    }

    /// Whether `a` dominates `x` (reflexive).
    #[inline]
    pub fn dominates(&self, a: u32, x: u32) -> bool {
        let (ta, tx) = (self.tin[a as usize], self.tin[x as usize]);
        ta != NONE && tx != NONE && ta <= tx && tx < ta + self.retained_count[a as usize]
    }

    #[inline]
    pub fn group(&self, v: u32) -> u32 {
        self.types.group(self.snap.object(v).type_id)
    }

    pub fn type_name(&self, v: u32) -> &str {
        &self.types.names[self.group(v) as usize]
    }

    /// The snapshot's label for CSR edge `e`, or `None` for super-root edges.
    pub fn edge_label(&self, e: u32) -> Option<EdgeLabel> {
        (e < self.g.snapshot_edges).then(|| self.snap.edge(e as u64).label)
    }

    /// One hop: object `v` entered by CSR edge `e`.
    fn hop(&self, v: u32, e: u32) -> Result<PathHop> {
        let o = self.snap.object(v);
        let (source_loc, source_loc_reason) = self.source_loc(v)?;
        let mut hop = PathHop {
            address: Address(o.addr),
            type_name: self.types.names[self.types.group(o.type_id) as usize].clone(),
            shallow_bytes: o.shallow_size,
            edge: None,
            root_label: None,
            root_kind: None,
            source_loc,
            source_loc_reason,
        };
        match self.edge_label(e) {
            Some(l) => hop.edge = Some(self.snap.render_label(l)?),
            None => {
                let r = self.g.root_entry(e).expect("super-root edge");
                hop.root_label = Some(self.snap.string(r.label)?.to_string());
                hop.root_kind = Some(r.kind.as_str().to_string());
            }
        }
        Ok(hop)
    }

    /// Nodes on the BFS path to `v`, root object first, with the edge used to
    /// enter each. Empty if `v` is unreachable or the super-root.
    pub(crate) fn bfs_chain(&self, v: u32) -> Vec<(u32, u32)> {
        let mut chain = Vec::new();
        let mut x = v;
        while x != self.root() && self.via[x as usize] != NONE {
            let e = self.via[x as usize];
            chain.push((x, e));
            x = self.g.csr.source_of(e);
        }
        chain.reverse();
        chain
    }

    /// A shortest retaining path to `v`, or `None` if unreachable.
    pub fn path(&self, v: u32) -> Result<Option<RetainingPath>> {
        if !self.reachable(v) || v == self.root() {
            return Ok(None);
        }
        self.render_chain(&self.bfs_chain(v)).map(Some)
    }

    /// Shortest path to the referrer `u`, then the edge `e` into `v`.
    /// `None` if that path would visit `v` twice.
    pub fn path_via(&self, u: u32, e: u32, v: u32) -> Result<Option<RetainingPath>> {
        let mut chain = if u == self.root() {
            Vec::new()
        } else {
            self.bfs_chain(u)
        };
        if chain.iter().any(|&(x, _)| x == v) {
            return Ok(None);
        }
        chain.push((v, e));
        self.render_chain(&chain).map(Some)
    }

    fn render_chain(&self, chain: &[(u32, u32)]) -> Result<RetainingPath> {
        chain.iter().map(|&(x, e)| self.hop(x, e)).collect()
    }

    /// Count, shallow bytes and retained bytes per type, for every type with
    /// at least one instance, unsorted.
    ///
    /// Retained bytes of a type count only instances that are not dominated
    /// by another instance of the same type, so nested instances (a dict
    /// holding dicts, a linked list of nodes) are not counted twice. The rule
    /// is applied in one sweep over the dominator tree in preorder: per type
    /// we remember where the subtree of the last counted instance ends, and an
    /// instance inside that range is nested.
    pub fn type_rows(&self) -> Vec<TypeRow> {
        let groups = self.types.names.len();
        let mut count = vec![0u64; groups];
        let mut shallow = vec![0u64; groups];
        let mut retained = vec![0u64; groups];
        for i in 0..self.g.n {
            let o = self.snap.object(i);
            let g = self.types.group(o.type_id) as usize;
            count[g] += 1;
            shallow[g] += o.shallow_size;
        }
        let mut end = vec![0u32; groups];
        for v in self.by_tin().into_iter().skip(1) {
            let g = self.group(v) as usize;
            let t = self.tin[v as usize];
            if t >= end[g] {
                retained[g] += self.retained[v as usize];
                end[g] = t + self.retained_count[v as usize];
            }
        }
        (0..groups)
            .filter(|&g| count[g] > 0)
            .map(|g| TypeRow {
                type_name: self.types.names[g].clone(),
                count: count[g],
                shallow_bytes: shallow[g],
                retained_bytes: retained[g],
                // Filled in by the report builder for the rows it keeps.
                type_location: None,
                type_location_reason: None,
            })
            .collect()
    }

    /// Retained bytes of a set of nodes, not counting members dominated by
    /// another member.
    pub fn set_retained(&self, nodes: &[u32]) -> u64 {
        let mut v: Vec<u32> = nodes
            .iter()
            .copied()
            .filter(|&x| self.reachable(x))
            .collect();
        v.sort_unstable_by_key(|&x| self.tin[x as usize]);
        let (mut end, mut sum) = (0u32, 0u64);
        for x in v {
            let t = self.tin[x as usize];
            if t >= end {
                sum += self.retained[x as usize];
                end = t + self.retained_count[x as usize];
            }
        }
        sum
    }

    /// Reachable nodes ordered by dominator-tree preorder.
    fn by_tin(&self) -> Vec<u32> {
        let mut out = vec![0u32; self.order.len()];
        for &v in &self.order {
            out[self.tin[v as usize] as usize] = v;
        }
        out
    }

    /// Namespace objects: modules, frames and type objects, and the
    /// `__dict__` of each. They hold program variables rather than data, so
    /// they are never listed as top retainers themselves; the variables
    /// inside them are.
    ///
    /// The `__dict__` counts whether or not its owner dominates it. A module's
    /// dict is also reachable as `__globals__` of every function defined in
    /// the module, so as soon as a running frame or thread holds one of those
    /// functions, the dict's immediate dominator is the super-root, not the
    /// module. It is still the module's namespace.
    fn namespaces(&self) -> Result<Vec<bool>> {
        let n = self.g.n;
        let mut ns = vec![false; n as usize + 1];
        let module = self.types.find("builtins.module");
        let frame = self.types.find("builtins.frame");
        for i in 0..n {
            let o = self.snap.object(i);
            let g = Some(self.types.group(o.type_id));
            if !(o.flags.contains(ObjectFlags::IS_TYPE) || g == module || g == frame) {
                continue;
            }
            ns[i as usize] = true;
            let r = self.g.csr.range(i);
            for e in r.clone() {
                let t = self.g.csr.targets[e];
                if t == NONE {
                    continue;
                }
                if let EdgeLabel::Attr(s) = self.snap.edge(e as u64).label {
                    if self.snap.string(s)? == "__dict__" {
                        ns[t as usize] = true;
                    }
                }
            }
        }
        Ok(ns)
    }

    /// The objects to report as top retainers, best first.
    ///
    /// 1. The super-root and namespace objects (see [`Self::namespaces`]) are
    ///    never listed.
    /// 2. Restating wrappers are collapsed. Start at an object A and follow
    ///    its largest dominator-tree child while that child still retains at
    ///    least [`CHAIN_RATIO`] of A's retained bytes, for at most
    ///    [`CHAIN_MAX_HOPS`] steps. Only the last object of such a chain is a
    ///    candidate: `module -> __dict__ -> CACHE` reports `CACHE`, and
    ///    `function -> cell -> big object` reports the big object. Its path
    ///    still shows the wrappers. The ratio is measured against the top of
    ///    the chain, not the previous step, so a long linked list is not
    ///    collapsed down to its tail.
    /// 3. Candidates are ranked by retained bytes (ties by address), and a
    ///    candidate dominated by an already listed object is skipped, so the
    ///    entries are disjoint parts of the heap.
    pub fn top_retainers(&self, top: usize) -> Result<Vec<u32>> {
        if top == 0 {
            return Ok(Vec::new());
        }
        let n = self.g.n as usize;
        let root = self.root();
        let mut big = vec![NONE; n + 1];
        for &v in &self.order[1..] {
            let p = self.idom[v as usize] as usize;
            if big[p] == NONE || self.retained[v as usize] > self.retained[big[p] as usize] {
                big[p] = v;
            }
        }
        let mut skip = self.namespaces()?;
        skip[root as usize] = true;
        let mut anchor = vec![NONE; n + 1];
        let mut hops = vec![0u8; n + 1];
        for &v in &self.order[1..] {
            let (vi, p) = (v as usize, self.idom[v as usize] as usize);
            let a = anchor[p];
            if p != root as usize
                && big[p] == v
                && hops[p] < CHAIN_MAX_HOPS
                && self.retained[vi] as f64 >= CHAIN_RATIO * self.retained[a as usize] as f64
            {
                anchor[vi] = a;
                hops[vi] = hops[p] + 1;
                skip[p] = true;
            } else {
                anchor[vi] = v;
            }
        }
        drop((big, anchor, hops));

        let mut cands: Vec<u32> = self.order[1..]
            .iter()
            .copied()
            .filter(|&v| !skip[v as usize])
            .collect();
        drop(skip);
        let cmp = |a: &u32, b: &u32| {
            self.retained[*b as usize]
                .cmp(&self.retained[*a as usize])
                .then(a.cmp(b))
        };
        let mut k = (top * 8).max(256);
        loop {
            let prefix = if k < cands.len() {
                cands.select_nth_unstable_by(k, cmp);
                let p = &mut cands[..k];
                p.sort_unstable_by(cmp);
                &*p
            } else {
                cands.sort_unstable_by(cmp);
                &cands[..]
            };
            let mut listed: Vec<u32> = Vec::with_capacity(top);
            for &c in prefix {
                if listed.iter().any(|&a| self.dominates(a, c)) {
                    continue;
                }
                listed.push(c);
                if listed.len() == top {
                    break;
                }
            }
            if listed.len() == top || k >= cands.len() {
                return Ok(listed);
            }
            k = k.saturating_mul(4);
        }
    }
}

/// Breadth-first search from the super-root over forward edges. Returns the
/// entering edge and the distance of each node.
fn bfs(g: &ObjectGraph) -> (Vec<u32>, Vec<u32>) {
    let n = g.n as usize + 1;
    let mut via = vec![NONE; n];
    let mut dist = vec![NONE; n];
    let mut queue: Vec<u32> = Vec::new();
    dist[g.n as usize] = 0;
    queue.push(g.n);
    let mut head = 0;
    while head < queue.len() {
        let v = queue[head];
        head += 1;
        let d = dist[v as usize] + 1;
        for e in g.csr.range(v) {
            let w = g.csr.targets[e];
            if w != NONE && dist[w as usize] == NONE {
                dist[w as usize] = d;
                via[w as usize] = e as u32;
                queue.push(w);
            }
        }
    }
    (via, dist)
}
