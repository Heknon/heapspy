//! Property test through the public API: random snapshots, with the
//! analyzer's retained sizes and type histogram checked against a brute-force
//! "remove the object and see what becomes unreachable" computation.

use heapspy_analyzer::{analyze, AnalyzeOptions};
use heapspy_snapshot::{RootKind, SnapshotBuilder};
use proptest::prelude::*;

const TYPES: [&str; 3] = ["A", "B", "C"];

#[derive(Debug, Clone)]
struct G {
    types: Vec<usize>,
    sizes: Vec<u64>,
    edges: Vec<(usize, usize)>,
    roots: Vec<usize>,
    dangling: usize,
}

fn strategy() -> impl Strategy<Value = G> {
    (1usize..16).prop_flat_map(|n| {
        (
            prop::collection::vec(0..TYPES.len(), n),
            prop::collection::vec(1u64..500, n),
            prop::collection::vec((0..n, 0..n), 0..n * 3),
            prop::collection::vec(0..n, 0..4),
            0usize..3,
        )
            .prop_map(|(types, sizes, edges, roots, dangling)| G {
                types,
                sizes,
                edges,
                roots,
                dangling,
            })
    })
}

fn addr(i: usize) -> u64 {
    0x1000 + 0x10 * i as u64
}

/// Reachable set from the roots with `removed` taken out.
fn reach(g: &G, removed: Option<usize>) -> Vec<bool> {
    let n = g.types.len();
    let mut seen = vec![false; n];
    let mut stack: Vec<usize> = g
        .roots
        .iter()
        .copied()
        .filter(|&r| Some(r) != removed)
        .collect();
    for &r in &stack {
        seen[r] = true;
    }
    while let Some(v) = stack.pop() {
        for &(a, b) in &g.edges {
            if a == v && Some(b) != removed && !seen[b] {
                seen[b] = true;
                stack.push(b);
            }
        }
    }
    seen
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn retained_and_histogram_match_brute_force(g in strategy()) {
        let n = g.types.len();
        let mut b = SnapshotBuilder::new();
        let tids: Vec<_> = TYPES.iter().map(|t| b.ty("m", t)).collect();
        for i in 0..n {
            let o = b.object(addr(i), tids[g.types[i]], g.sizes[i]);
            for (k, &(_, t)) in g.edges.iter().filter(|e| e.0 == i).enumerate() {
                o.list_item(addr(t), k as u32);
            }
            if i < g.dangling {
                o.attr(0xdead_0000, "gone");
            }
        }
        for &r in &g.roots {
            b.root(addr(r), RootKind::Other, &format!("r{r}"));
        }
        let snap = b.build().unwrap();
        let rep = analyze(&snap, "p", &AnalyzeOptions { top: 100 }).unwrap();

        let base = reach(&g, None);
        // dom[x][y]: x dominates y (reflexive) among reachable objects.
        let dom: Vec<Vec<bool>> = (0..n)
            .map(|x| {
                let r = reach(&g, Some(x));
                (0..n).map(|y| base[x] && base[y] && !r[y]).collect()
            })
            .collect();
        let retained = |x: usize| (0..n).filter(|&y| dom[x][y]).map(|y| g.sizes[y]).sum::<u64>();

        let reachable: u64 = (0..n).filter(|&i| base[i]).map(|i| g.sizes[i]).sum();
        prop_assert_eq!(rep.totals.reachable_bytes, reachable);
        prop_assert_eq!(rep.totals.reachable_objects, base.iter().filter(|&&r| r).count() as u64);
        prop_assert_eq!(rep.totals.dangling_edges, g.dangling.min(n) as u64);

        for t in &rep.top_retainers {
            let i = ((t.address.0 - 0x1000) / 0x10) as usize;
            prop_assert_eq!(t.retained_bytes, retained(i));
            prop_assert_eq!(
                t.retained_objects,
                (0..n).filter(|&y| dom[i][y]).count() as u64
            );
        }
        // Top retainers are disjoint.
        for (k, a) in rep.top_retainers.iter().enumerate() {
            for b2 in &rep.top_retainers[k + 1..] {
                let ia = ((a.address.0 - 0x1000) / 0x10) as usize;
                let ib = ((b2.address.0 - 0x1000) / 0x10) as usize;
                prop_assert!(!dom[ia][ib] && !dom[ib][ia]);
            }
        }

        for row in &rep.type_histogram {
            let t = TYPES.iter().position(|x| format!("m.{x}") == row.type_name).unwrap();
            let inst: Vec<usize> = (0..n).filter(|&i| g.types[i] == t).collect();
            prop_assert_eq!(row.count, inst.len() as u64);
            // The set's retained size: everything dominated by any instance.
            let expect: u64 = (0..n)
                .filter(|&y| inst.iter().any(|&x| dom[x][y]))
                .map(|y| g.sizes[y])
                .sum();
            prop_assert_eq!(row.retained_bytes, expect, "type {}", &row.type_name);
        }
    }
}
