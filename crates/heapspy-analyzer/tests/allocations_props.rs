//! Property test for the allocation join: random snapshots and random
//! profiles, checked against brute force.
//!
//! - Each object is linked to the latest sample whose range contains its
//!   address, unless that sample is a large-object sample the object does
//!   not match (start at a pre-header offset of 0, 16 or 32 bytes, not 0
//!   for a GC-tracked object; requested size within 16 bytes of the
//!   shallow size, or at most 16 above it for a type object). Then it is
//!   not linked at all, and counted as reused if reachable.
//! - Linked bytes are reachable bytes, so never more than the reachable
//!   total, and the stacks' linked bytes add up to the coverage.
//! - `allocated_at` of a retainer or instance sums the linked objects of
//!   its dominator subtree ("removing it makes them unreachable"), per
//!   stack.

use std::collections::HashMap;

use heapspy_alloc::{EventKind, ProfileBuilder};
use heapspy_analyzer::allocations::{
    analyze_with_allocations, object_links, query_type_with_allocations, NO_LINK,
};
use heapspy_analyzer::report::AllocatedAt;
use heapspy_analyzer::{AnalyzeOptions, QueryOptions};
use heapspy_snapshot::{ObjectFlags, RootKind, SnapshotBuilder};
use proptest::prelude::*;

const TYPES: [&str; 2] = ["A", "B"];
const STACKS: usize = 4;
const KINDS: [EventKind; 4] = [
    EventKind::Arena,
    EventKind::Pool,
    EventKind::LargeObject,
    EventKind::Other,
];

/// Object flags: GC-tracked, untracked, or a (tracked) type object.
const FLAGS: [ObjectFlags; 3] = [
    ObjectFlags::GC_TRACKED,
    ObjectFlags::NONE,
    ObjectFlags(ObjectFlags::GC_TRACKED.0 | ObjectFlags::IS_TYPE.0),
];

#[derive(Debug, Clone)]
struct Case {
    types: Vec<usize>,
    sizes: Vec<u64>,
    flags: Vec<usize>,
    edges: Vec<(usize, usize)>,
    roots: Vec<usize>,
    /// (kind, start address, size, stack)
    samples: Vec<(usize, u64, u64, usize)>,
}

/// A sample: a random range, or a large-object sample aimed at object
/// `j` (start `addr(j) - pre`, size `sizes[j] + delta`) so that matches and
/// near misses are common.
type RawSample = (usize, u64, u64, usize, Option<(usize, u64, i64)>);

fn strategy() -> impl Strategy<Value = Case> {
    (1usize..14).prop_flat_map(|n| {
        let span = 0x10 * n as u64 + 0x40;
        let aimed = (
            0..n,
            prop::sample::select(vec![0u64, 8, 16, 32, 48]),
            -24i64..24,
        );
        (
            prop::collection::vec(0..TYPES.len(), n),
            prop::collection::vec(1u64..500, n),
            prop::collection::vec(0..FLAGS.len(), n),
            prop::collection::vec((0..n, 0..n), 0..n * 3),
            prop::collection::vec(0..n, 1..4),
            prop::collection::vec(
                (
                    0..KINDS.len(),
                    0..span,
                    0u64..0x60,
                    0..STACKS,
                    prop::option::of(aimed),
                ),
                0..12,
            ),
        )
            .prop_map(|(types, sizes, flags, edges, roots, raw)| {
                let samples = raw
                    .into_iter()
                    .map(|(kind, off, size, stack, aim): RawSample| match aim {
                        Some((j, pre, delta)) => (
                            2, // LargeObject
                            addr(j) - pre,
                            (sizes[j] as i64 + delta).max(0) as u64,
                            stack,
                        ),
                        None => (kind, sample_start(off), size, stack),
                    })
                    .collect();
                Case {
                    types,
                    sizes,
                    flags,
                    edges,
                    roots,
                    samples,
                }
            })
    })
}

/// The large-object rule, written out on its own.
fn matches(c: &Case, i: usize, start: u64, size: u64) -> bool {
    let a = addr(i);
    if a < start {
        return false;
    }
    let pre = a - start;
    let f = FLAGS[c.flags[i]];
    let tracked = f.contains(ObjectFlags::GC_TRACKED);
    let is_type = f.contains(ObjectFlags::IS_TYPE);
    let start_ok = pre == 16 || pre == 32 || (pre == 0 && !tracked);
    let shallow = c.sizes[i] as i64;
    let d = size as i64 - shallow;
    let size_ok = d <= 16 && (is_type || d >= -16);
    start_ok && size_ok
}

const BASE: u64 = 0x1000;

fn addr(i: usize) -> u64 {
    BASE + 0x10 * i as u64
}

/// Sample ranges start up to 0x20 below the first object.
fn sample_start(off: u64) -> u64 {
    BASE - 0x20 + off
}

fn reach(c: &Case, removed: Option<usize>) -> Vec<bool> {
    let n = c.types.len();
    let mut seen = vec![false; n];
    let mut stack: Vec<usize> = c
        .roots
        .iter()
        .copied()
        .filter(|&r| Some(r) != removed)
        .collect();
    for &r in &stack {
        seen[r] = true;
    }
    while let Some(v) = stack.pop() {
        for &(a, b) in &c.edges {
            if a == v && Some(b) != removed && !seen[b] {
                seen[b] = true;
                stack.push(b);
            }
        }
    }
    seen
}

fn index_of(a: u64) -> usize {
    ((a - BASE) / 0x10) as usize
}

/// Check one `allocated_at` against the brute-force sums over the objects
/// `x` dominates.
fn check_allocated_at(
    at: &AllocatedAt,
    x: usize,
    dom: &[Vec<bool>],
    link: &[Option<usize>],
    c: &Case,
) -> Result<(), TestCaseError> {
    let n = c.types.len();
    // stack -> (objects, bytes, exact bytes)
    let mut want: HashMap<usize, (u64, u64, u64)> = HashMap::new();
    for y in 0..n {
        if let (true, Some(s)) = (dom[x][y], link[y]) {
            let (kind, _, _, stack) = c.samples[s];
            let e = want.entry(stack).or_default();
            e.0 += 1;
            e.1 += c.sizes[y];
            if KINDS[kind] == EventKind::LargeObject {
                e.2 += c.sizes[y];
            }
        }
    }
    let objects: u64 = want.values().map(|v| v.0).sum();
    let bytes: u64 = want.values().map(|v| v.1).sum();
    let exact: u64 = want.values().map(|v| v.2).sum();
    prop_assert_eq!(at.linked_objects, objects);
    prop_assert_eq!(at.linked_bytes, bytes);
    prop_assert_eq!(at.exact_linked_bytes, exact);
    // At most STACKS (< 5) stacks, so all of them are listed.
    prop_assert_eq!(at.stacks.len(), want.len());
    for st in &at.stacks {
        let k: usize = st.frames[0].function[1..].parse().unwrap();
        let w = want[&k];
        prop_assert_eq!(
            (st.linked_objects, st.linked_bytes, st.exact_linked_bytes),
            w
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn join_matches_brute_force(c in strategy()) {
        let n = c.types.len();
        let mut b = SnapshotBuilder::new();
        let tids: Vec<_> = TYPES.iter().map(|t| b.ty("m", t)).collect();
        for i in 0..n {
            let o = b.object(addr(i), tids[c.types[i]], c.sizes[i]);
            o.flags(FLAGS[c.flags[i]]);
            for (k, &(_, t)) in c.edges.iter().filter(|e| e.0 == i).enumerate() {
                o.list_item(addr(t), k as u32);
            }
        }
        for &r in &c.roots {
            b.root(addr(r), RootKind::Other, &format!("r{r}"));
        }
        let snap = b.build().unwrap();

        let mut pb = ProfileBuilder::new();
        let code: Vec<_> = (0..STACKS)
            .map(|k| pb.code_with_lines(0x9000 + k as u64 * 0x100, &format!("f{k}"), "m.py", 1, &[(8, 1)]))
            .collect();
        for &(kind, start, size, stack) in &c.samples {
            pb.sample(KINDS[kind], start, size).frame(code[stack], 0);
        }
        let prof = pb.build().unwrap();

        // Latest covering sample per object, and whether it is a
        // large-object sample the object does not match.
        let covering: Vec<Option<usize>> = (0..n)
            .map(|i| {
                let a = addr(i);
                c.samples
                    .iter()
                    .enumerate()
                    .rev()
                    .find(|(_, &(_, s, size, _))| s <= a && a < s + size)
                    .map(|(j, _)| j)
            })
            .collect();
        let reused: Vec<bool> = (0..n)
            .map(|i| {
                covering[i].is_some_and(|j| {
                    let (kind, start, size, _) = c.samples[j];
                    KINDS[kind] == EventKind::LargeObject && !matches(&c, i, start, size)
                })
            })
            .collect();
        let link: Vec<Option<usize>> = (0..n)
            .map(|i| covering[i].filter(|_| !reused[i]))
            .collect();
        let got = object_links(&snap, &prof).unwrap();
        let got: Vec<Option<usize>> = got
            .iter()
            .map(|&l| (l != NO_LINK).then_some(l as usize))
            .collect();
        prop_assert_eq!(&got, &link);

        let base = reach(&c, None);
        let dom: Vec<Vec<bool>> = (0..n)
            .map(|x| {
                let r = reach(&c, Some(x));
                (0..n).map(|y| base[x] && base[y] && !r[y]).collect()
            })
            .collect();

        let rep = analyze_with_allocations(&snap, "s", &AnalyzeOptions { top: 100 }, &prof, "p")
            .unwrap();
        let a = rep.allocations.as_ref().unwrap();
        let linked: u64 = (0..n)
            .filter(|&i| base[i] && link[i].is_some())
            .map(|i| c.sizes[i])
            .sum();
        prop_assert_eq!(a.coverage.linked_bytes, linked);
        let reused_bytes: u64 = (0..n)
            .filter(|&i| base[i] && reused[i])
            .map(|i| c.sizes[i])
            .sum();
        let reused_objects = (0..n).filter(|&i| base[i] && reused[i]).count() as u64;
        prop_assert_eq!(a.coverage.unlinked_reused_objects, reused_objects);
        prop_assert_eq!(a.coverage.unlinked_reused_bytes, reused_bytes);
        let noted = rep.notes.iter().any(|n| n.code == "allocations_unlinked_reused");
        prop_assert_eq!(noted, reused_objects > 0);
        prop_assert!(a.coverage.linked_bytes <= rep.totals.reachable_bytes);
        prop_assert!(a.coverage.exact_linked_bytes <= a.coverage.linked_bytes);
        prop_assert!(a.coverage.linked_pct <= 100.0);
        let by_stacks: u64 = a.top_stacks.iter().map(|t| t.linked_bytes).sum();
        prop_assert_eq!(by_stacks, linked);
        let estimated: u64 = c.samples.iter().map(|s| s.2).sum();
        prop_assert_eq!(a.estimated_bytes, estimated);

        for t in &rep.top_retainers {
            let at = t.allocated_at.as_ref().unwrap();
            check_allocated_at(at, index_of(t.address.0), &dom, &link, &c)?;
            for st in &at.stacks {
                let rank = st.top_stack_rank.unwrap() as usize;
                prop_assert_eq!(&a.top_stacks[rank - 1].frames, &st.frames);
            }
        }

        // Type query instances can nest; each is checked on its own.
        if c.types.contains(&0) {
            let q = query_type_with_allocations(&snap, "s", "A", &QueryOptions { top: 100, max_paths: 1 }, &prof)
                .unwrap();
            for i in &q.top_instances {
                check_allocated_at(i.allocated_at.as_ref().unwrap(), index_of(i.address.0), &dom, &link, &c)?;
            }
        }
    }
}
