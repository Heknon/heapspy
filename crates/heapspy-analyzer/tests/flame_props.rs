//! Property test for folded stacks: on random graphs, the folded lines sum to
//! the reachable bytes, and each top-level frame is as wide as the retained
//! bytes of the objects merged into it (checked by brute force).

use std::collections::BTreeMap;

use heapspy_analyzer::{folded_diff, folded_stacks, FlameOptions, MinWidth};
use heapspy_snapshot::{RootKind, Snapshot, SnapshotBuilder};
use proptest::prelude::*;

const TYPES: [&str; 3] = ["A", "B", "C"];

#[derive(Debug, Clone)]
struct G {
    types: Vec<usize>,
    sizes: Vec<u64>,
    edges: Vec<(usize, usize)>,
    roots: Vec<usize>,
}

fn strategy() -> impl Strategy<Value = G> {
    (1usize..16).prop_flat_map(|n| {
        (
            prop::collection::vec(0..TYPES.len(), n),
            prop::collection::vec(1u64..500, n),
            prop::collection::vec((0..n, 0..n), 0..n * 3),
            prop::collection::vec(0..n, 0..4),
        )
            .prop_map(|(types, sizes, edges, roots)| G {
                types,
                sizes,
                edges,
                roots,
            })
    })
}

fn addr(i: usize) -> u64 {
    0x1000 + 0x10 * i as u64
}

fn build(g: &G) -> Snapshot {
    let mut b = SnapshotBuilder::new();
    let tids: Vec<_> = TYPES.iter().map(|t| b.ty("m", t)).collect();
    for i in 0..g.types.len() {
        let o = b.object(addr(i), tids[g.types[i]], g.sizes[i]);
        for (k, &(_, t)) in g.edges.iter().filter(|e| e.0 == i).enumerate() {
            // Mix label kinds so that both merged and unmerged siblings occur.
            if k % 2 == 0 {
                o.list_item(addr(t), k as u32);
            } else {
                o.attr(addr(t), if t % 2 == 0 { "x" } else { "y" });
            }
        }
    }
    for &r in &g.roots {
        b.root(addr(r), RootKind::Other, &format!("r{r}"));
    }
    b.build().unwrap()
}

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

/// Expected width per top-level frame text.
fn expected_tops(g: &G) -> (u64, BTreeMap<String, u64>) {
    let n = g.types.len();
    let base = reach(g, None);
    let dom: Vec<Vec<bool>> = (0..n)
        .map(|x| {
            let r = reach(g, Some(x));
            (0..n).map(|y| base[x] && base[y] && !r[y]).collect()
        })
        .collect();
    let mut tops = BTreeMap::new();
    for x in (0..n).filter(|&x| base[x]) {
        // Dominated only by the super-root.
        if (0..n).any(|y| y != x && dom[y][x]) {
            continue;
        }
        let text = if g.roots.contains(&x) {
            format!("r{x}")
        } else {
            // Shared: entered through some ordinary edge. The label depends
            // on which edge BFS took, so only the type is known here.
            format!("...? m.{}", TYPES[g.types[x]])
        };
        let retained: u64 = (0..n).filter(|&y| dom[x][y]).map(|y| g.sizes[y]).sum();
        *tops.entry(text).or_insert(0) += retained;
    }
    let reachable = (0..n).filter(|&i| base[i]).map(|i| g.sizes[i]).sum();
    (reachable, tops)
}

/// Top-level widths from folded lines, with shared frames' labels replaced
/// by `?` to match [`expected_tops`].
fn actual_tops<'a>(lines: impl Iterator<Item = (&'a str, u64)>) -> BTreeMap<String, u64> {
    let mut tops = BTreeMap::new();
    for (stack, bytes) in lines {
        let top = stack.split(';').next().unwrap();
        let key = match top.strip_prefix("...") {
            Some(rest) => format!("...? {}", rest.rsplit(' ').next().unwrap()),
            None => top.to_string(),
        };
        *tops.entry(key).or_insert(0) += bytes;
    }
    tops
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn folded_widths_match_retained(g in strategy(), depth in 1u32..6) {
        let snap = build(&g);
        let (reachable, tops) = expected_tops(&g);
        let opts = FlameOptions { max_depth: depth, min_width: MinWidth::Bytes(0) };
        let f = folded_stacks(&snap, &opts).unwrap();
        prop_assert_eq!(f.reachable_bytes, reachable);
        prop_assert_eq!(f.lines.iter().map(|l| l.bytes).sum::<u64>(), reachable);
        prop_assert!(f.lines.iter().all(|l| l.stack.split(';').count() <= depth as usize + 1));
        prop_assert!(f.lines.iter().all(|l| l.bytes > 0));
        let actual = actual_tops(f.lines.iter().map(|l| (l.stack.as_str(), l.bytes)));
        prop_assert_eq!(actual, tops);
    }

    #[test]
    fn cutoff_preserves_totals(g in strategy(), min in 0u64..2000) {
        let snap = build(&g);
        let reachable = expected_tops(&g).0;
        let exact = top_widths(&folded_stacks(&snap, &FlameOptions {
            max_depth: 32,
            min_width: MinWidth::Bytes(0),
        }).unwrap());
        let opts = FlameOptions { max_depth: 32, min_width: MinWidth::Bytes(min) };
        let f = folded_stacks(&snap, &opts).unwrap();
        prop_assert_eq!(f.lines.iter().map(|l| l.bytes).sum::<u64>(), reachable);
        for (k, v) in &top_widths(&f) {
            if k != "[other]" {
                prop_assert!(*v >= min);
                prop_assert_eq!(Some(v), exact.get(k));
            }
        }
    }

    #[test]
    fn diff_sides_sum_to_each_snapshot(g1 in strategy(), g2 in strategy(), min in 0u64..2000) {
        let (s1, s2) = (build(&g1), build(&g2));
        let exact = |s: &Snapshot| top_widths(&folded_stacks(s, &FlameOptions {
            max_depth: 32,
            min_width: MinWidth::Bytes(0),
        }).unwrap());
        let (e1, e2) = (exact(&s1), exact(&s2));
        let opts = FlameOptions { max_depth: 32, min_width: MinWidth::Bytes(min) };
        let d = folded_diff(&s1, &s2, &opts).unwrap();
        prop_assert_eq!(d.lines.iter().map(|l| l.before).sum::<u64>(), expected_tops(&g1).0);
        prop_assert_eq!(d.lines.iter().map(|l| l.after).sum::<u64>(), expected_tops(&g2).0);
        let mut before: BTreeMap<String, u64> = BTreeMap::new();
        let mut after: BTreeMap<String, u64> = BTreeMap::new();
        for l in &d.lines {
            let top = l.stack.split(';').next().unwrap().to_string();
            *before.entry(top.clone()).or_default() += l.before;
            *after.entry(top).or_default() += l.after;
        }
        for k in before.keys().filter(|k| *k != "[other]") {
            let (b, a) = (e1.get(k).copied().unwrap_or(0), e2.get(k).copied().unwrap_or(0));
            prop_assert!(b.max(a) >= min);
            prop_assert_eq!(before[k], b);
            prop_assert_eq!(after[k], a);
        }
    }
}

/// Width of each top-level frame, by exact text.
fn top_widths(f: &heapspy_analyzer::FoldedStacks) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for l in &f.lines {
        *m.entry(l.stack.split(';').next().unwrap().to_string())
            .or_insert(0) += l.bytes;
    }
    m
}
