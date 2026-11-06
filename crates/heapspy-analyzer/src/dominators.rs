//! A compact CSR graph and the Lengauer–Tarjan dominator algorithm.
//!
//! Everything here works on dense `u32` node ids and flat `Vec<u32>` arrays:
//! no per-node allocation and no recursion, so it scales to tens of millions
//! of nodes and survives arbitrarily deep reference chains.

/// "No node" / "no value" in every `u32` array of this crate.
pub const NONE: u32 = u32::MAX;

/// A directed graph in compressed sparse row form.
///
/// The out-edges of node `v` are `targets[offsets[v]..offsets[v + 1]]`. A
/// target of [`NONE`] is a placeholder for an edge that could not be resolved
/// (a dangling reference); traversals skip it. Keeping the placeholder means
/// an edge's position in `targets` can equal its position in some external
/// edge list (the snapshot's edges section), so labels can be looked up later
/// without storing them here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Csr {
    pub offsets: Vec<u32>,
    pub targets: Vec<u32>,
}

impl Csr {
    /// Build from an adjacency list. For tests and small graphs.
    pub fn from_adjacency(adj: &[Vec<u32>]) -> Csr {
        let mut offsets = Vec::with_capacity(adj.len() + 1);
        let mut targets = Vec::new();
        offsets.push(0);
        for out in adj {
            targets.extend_from_slice(out);
            offsets.push(targets.len() as u32);
        }
        Csr { offsets, targets }
    }

    pub fn node_count(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    /// Edge index range of `v`.
    #[inline]
    pub fn range(&self, v: u32) -> std::ops::Range<usize> {
        self.offsets[v as usize] as usize..self.offsets[v as usize + 1] as usize
    }

    /// Resolved out-neighbours of `v` (placeholders skipped).
    #[inline]
    pub fn out(&self, v: u32) -> impl Iterator<Item = u32> + '_ {
        self.targets[self.range(v)]
            .iter()
            .copied()
            .filter(|&t| t != NONE)
    }

    /// The node that owns edge index `e`. Binary search over `offsets`.
    pub fn source_of(&self, e: u32) -> u32 {
        // Last v with offsets[v] <= e; nodes with no edges share an offset
        // with their successor, so take the last one.
        (self.offsets.partition_point(|&o| o <= e) - 1) as u32
    }
}

/// Result of [`dominators`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dominators {
    /// Immediate dominator of each node. [`NONE`] for the root and for nodes
    /// the root does not reach.
    pub idom: Vec<u32>,
    /// Reachable nodes in depth-first preorder from the root (`order[0]` is the
    /// root). Every node's immediate dominator appears before it, so iterating
    /// in reverse visits children of the dominator tree before their parents.
    pub order: Vec<u32>,
}

/// Iterative depth-first preorder from `root`. Returns `(order, parent)` with
/// `parent[i]` the preorder number of the DFS-tree parent of `order[i]`, and
/// fills `dfn[v]` with the preorder number of `v` ([`NONE`] if unreached).
fn dfs(g: &Csr, root: u32, dfn: &mut [u32]) -> (Vec<u32>, Vec<u32>) {
    let mut order = Vec::new();
    let mut parent = Vec::new();
    // (node, next edge index) pairs. This is a real DFS (a node is numbered
    // when it is first entered, not when it is pushed), which Lengauer–Tarjan
    // needs: the semidominator theory is stated for a DFS spanning tree.
    let mut stack: Vec<(u32, usize)> = Vec::new();
    dfn[root as usize] = 0;
    order.push(root);
    parent.push(NONE);
    stack.push((root, g.range(root).start));
    while let Some(top) = stack.last_mut() {
        let (v, ref mut cursor) = *top;
        let end = g.range(v).end;
        let mut next = None;
        while *cursor < end {
            let w = g.targets[*cursor];
            *cursor += 1;
            if w != NONE && dfn[w as usize] == NONE {
                next = Some(w);
                break;
            }
        }
        match next {
            Some(w) => {
                let n = order.len() as u32;
                dfn[w as usize] = n;
                order.push(w);
                parent.push(dfn[v as usize]);
                stack.push((w, g.range(w).start));
            }
            None => {
                stack.pop();
            }
        }
    }
    (order, parent)
}

/// Immediate dominators of every node reachable from `root`.
///
/// This is the "simple" Lengauer–Tarjan algorithm: semidominators computed
/// with a link-eval forest that uses path compression but not balanced
/// linking, so it runs in O(E log V) rather than O(E α(E, V)). The simple
/// version is the usual choice in practice. On real graphs it is as fast or
/// faster than the balanced version (Lengauer and Tarjan's own measurements,
/// and later studies by Georgiadis et al. and Cooper et al.), and it needs two
/// fewer per-node arrays (`size` and `child`), which matters at tens of
/// millions of nodes. The O(log V) bound is never close to being hit on heap
/// graphs.
///
/// All work is done in DFS-preorder space so the hot arrays are dense. The
/// path compression in `eval` is done with an explicit stack instead of
/// recursion.
pub fn dominators(g: &Csr, root: u32) -> Dominators {
    let n = g.node_count();
    let mut dfn = vec![NONE; n];
    let (order, parent) = dfs(g, root, &mut dfn);
    let m = order.len();

    // Predecessors in preorder space, reachable sources only, no self-loops.
    let mut pred_off = vec![0u32; m + 1];
    for &v in &order {
        for w in g.out(v) {
            let dw = dfn[w as usize];
            if w != v && dw != NONE {
                pred_off[dw as usize + 1] += 1;
            }
        }
    }
    for i in 0..m {
        pred_off[i + 1] += pred_off[i];
    }
    let mut fill = pred_off.clone();
    let mut preds = vec![0u32; pred_off[m] as usize];
    for (i, &v) in order.iter().enumerate() {
        for w in g.out(v) {
            let dw = dfn[w as usize];
            if w != v && dw != NONE {
                preds[fill[dw as usize] as usize] = i as u32;
                fill[dw as usize] += 1;
            }
        }
    }
    drop(fill);
    drop(dfn);

    let mut semi: Vec<u32> = (0..m as u32).collect();
    let mut label: Vec<u32> = (0..m as u32).collect();
    let mut ancestor = vec![NONE; m];
    let mut idom = vec![NONE; m];
    // Buckets as intrusive singly linked lists: every vertex is in at most one
    // bucket (that of its semidominator) at a time.
    let mut bucket_head = vec![NONE; m];
    let mut bucket_next = vec![NONE; m];
    let mut stack: Vec<u32> = Vec::new();

    // eval(v): the vertex with minimum semi on the forest path above v.
    let eval = |v: u32,
                ancestor: &mut [u32],
                label: &mut [u32],
                semi: &[u32],
                stack: &mut Vec<u32>|
     -> u32 {
        if ancestor[v as usize] == NONE {
            return v;
        }
        // compress(v), iteratively: collect the path, then apply the
        // recursive version's updates from the top down.
        let mut x = v;
        while ancestor[ancestor[x as usize] as usize] != NONE {
            stack.push(x);
            x = ancestor[x as usize];
        }
        while let Some(x) = stack.pop() {
            let a = ancestor[x as usize] as usize;
            if semi[label[a] as usize] < semi[label[x as usize] as usize] {
                label[x as usize] = label[a];
            }
            ancestor[x as usize] = ancestor[a];
        }
        label[v as usize]
    };

    for w in (1..m).rev() {
        for &v in &preds[pred_off[w] as usize..pred_off[w + 1] as usize] {
            let u = eval(v, &mut ancestor, &mut label, &semi, &mut stack);
            if semi[u as usize] < semi[w] {
                semi[w] = semi[u as usize];
            }
        }
        let s = semi[w] as usize;
        bucket_next[w] = bucket_head[s];
        bucket_head[s] = w as u32;
        let p = parent[w];
        ancestor[w] = p; // link(parent(w), w)
        let mut v = std::mem::replace(&mut bucket_head[p as usize], NONE);
        while v != NONE {
            let u = eval(v, &mut ancestor, &mut label, &semi, &mut stack);
            idom[v as usize] = if semi[u as usize] < semi[v as usize] {
                u
            } else {
                p
            };
            v = bucket_next[v as usize];
        }
    }
    for w in 1..m {
        if idom[w] != semi[w] {
            idom[w] = idom[idom[w] as usize];
        }
    }

    let mut idom_node = vec![NONE; n];
    for w in 1..m {
        idom_node[order[w] as usize] = order[idom[w] as usize];
    }
    Dominators {
        idom: idom_node,
        order,
    }
}

/// Retained size and retained object count of every node: the sum over its
/// dominator subtree. `sizes[v]` is the node's own (shallow) size. Unreachable
/// nodes get 0. One pass over `order` in reverse (children before parents).
pub fn retained(d: &Dominators, sizes: impl Fn(u32) -> u64) -> (Vec<u64>, Vec<u32>) {
    let n = d.idom.len();
    let mut bytes = vec![0u64; n];
    let mut count = vec![0u32; n];
    for &v in &d.order {
        bytes[v as usize] = sizes(v);
        count[v as usize] = 1;
    }
    for &v in d.order.iter().skip(1).rev() {
        let p = d.idom[v as usize] as usize;
        bytes[p] += bytes[v as usize];
        count[p] += count[v as usize];
    }
    (bytes, count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Reachability from `root` with `removed` deleted (`NONE` deletes nothing).
    fn reach(adj: &[Vec<u32>], root: u32, removed: u32) -> Vec<bool> {
        let mut seen = vec![false; adj.len()];
        if root == removed {
            return seen;
        }
        let mut stack = vec![root];
        seen[root as usize] = true;
        while let Some(v) = stack.pop() {
            for &w in &adj[v as usize] {
                if w != removed && !seen[w as usize] {
                    seen[w as usize] = true;
                    stack.push(w);
                }
            }
        }
        seen
    }

    /// Brute force: `dom[x]` = set of nodes that become unreachable when `x`
    /// is removed (so `x` dominates them), plus `x` itself.
    fn brute_dominates(adj: &[Vec<u32>], root: u32) -> (Vec<bool>, Vec<Vec<bool>>) {
        let n = adj.len();
        let base = reach(adj, root, NONE);
        let mut dom = vec![vec![false; n]; n];
        for x in 0..n as u32 {
            if !base[x as usize] {
                continue;
            }
            let r = reach(adj, root, x);
            for y in 0..n {
                dom[x as usize][y] = base[y] && !r[y];
            }
        }
        (base, dom)
    }

    /// The immediate dominator of `y` is its strict dominator that is
    /// dominated by every other strict dominator of `y`, i.e. the one with
    /// the most dominators of its own.
    fn brute_idom(adj: &[Vec<u32>], root: u32) -> Vec<u32> {
        let n = adj.len();
        let (base, dom) = brute_dominates(adj, root);
        let depth: Vec<usize> = (0..n)
            .map(|x| (0..n).filter(|&d| dom[d][x]).count())
            .collect();
        (0..n)
            .map(|y| {
                if !base[y] || y as u32 == root {
                    return NONE;
                }
                (0..n)
                    .filter(|&x| x != y && dom[x][y])
                    .max_by_key(|&x| depth[x])
                    .map_or(NONE, |x| x as u32)
            })
            .collect()
    }

    /// Random graphs with a super-root (node `n`) pointing at a random set of
    /// roots. Self-loops, cycles, multi-edges and unreachable nodes all occur.
    fn graph_strategy() -> impl Strategy<Value = (Vec<Vec<u32>>, Vec<u64>)> {
        (1usize..24).prop_flat_map(|n| {
            let edges = prop::collection::vec((0..n as u32, 0..n as u32), 0..n * 3);
            let roots = prop::collection::vec(0..n as u32, 0..4);
            let sizes = prop::collection::vec(0u64..1000, n);
            (edges, roots, sizes).prop_map(move |(edges, roots, sizes)| {
                let mut adj = vec![Vec::new(); n + 1];
                for (a, b) in edges {
                    adj[a as usize].push(b);
                }
                adj[n] = roots;
                (adj, sizes)
            })
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn lengauer_tarjan_matches_brute_force((adj, sizes) in graph_strategy()) {
            let n = adj.len() as u32 - 1;
            let g = Csr::from_adjacency(&adj);
            let d = dominators(&g, n);
            prop_assert_eq!(&d.idom, &brute_idom(&adj, n));

            // Retained sizes: shallow sizes of everything x dominates.
            let size = |v: u32| if v == n { 0 } else { sizes[v as usize] };
            let (bytes, count) = retained(&d, size);
            let (base, dom) = brute_dominates(&adj, n);
            for x in 0..=n as usize {
                let (eb, ec) = if base[x] {
                    (0..=n as usize)
                        .filter(|&y| dom[x][y])
                        .fold((0, 0), |(b, c), y| (b + size(y as u32), c + 1))
                } else {
                    (0, 0)
                };
                prop_assert_eq!(bytes[x], eb, "retained bytes of {}", x);
                prop_assert_eq!(count[x], ec, "retained count of {}", x);
            }
        }
    }

    #[test]
    fn diamond_and_unreachable() {
        // 0 -> {1, 2} -> 3 -> 1; 4 -> 0 is unreachable from 0.
        let adj = vec![vec![1, 2], vec![3], vec![3], vec![1], vec![0]];
        let d = dominators(&Csr::from_adjacency(&adj), 0);
        assert_eq!(d.idom, vec![NONE, 0, 0, 0, NONE]);
        assert_eq!(d.order[0], 0);
        assert_eq!(d.order.len(), 4);
    }

    #[test]
    fn deep_chain_does_not_overflow_the_stack() {
        let n = 1_000_000u32;
        // i -> i + 1, and the tail points back at the head.
        let offsets: Vec<u32> = (0..=n).collect();
        let mut targets: Vec<u32> = (1..n).collect();
        targets.push(0);
        let g = Csr { offsets, targets };
        let d = dominators(&g, 0);
        assert_eq!(d.order.len(), n as usize);
        assert_eq!(d.idom[n as usize - 1], n - 2);
        let (bytes, _) = retained(&d, |_| 1);
        assert_eq!(bytes[0], n as u64);
    }

    #[test]
    fn source_of_handles_empty_nodes() {
        let g = Csr::from_adjacency(&[vec![1], vec![], vec![], vec![0, 1]]);
        assert_eq!(g.source_of(0), 0);
        assert_eq!(g.source_of(1), 3);
        assert_eq!(g.source_of(2), 3);
    }

    #[test]
    fn placeholders_are_skipped() {
        let g = Csr {
            offsets: vec![0, 2, 2],
            targets: vec![NONE, 1],
        };
        let d = dominators(&g, 0);
        assert_eq!(d.idom, vec![NONE, 0]);
    }
}
