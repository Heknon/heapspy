//! Folded stacks for retention flame graphs, on synthetic snapshots.

mod common;

use common::*;
use heapspy_analyzer::{
    analyze, folded_diff, folded_stacks, AnalyzeOptions, FlameOptions, FoldedLine, FoldedStacks,
    MinWidth,
};
use heapspy_snapshot::RootKind;

fn exact() -> FlameOptions {
    FlameOptions {
        max_depth: 1000,
        min_width: MinWidth::Bytes(0),
    }
}

fn fold(h: &Heap, opts: &FlameOptions) -> FoldedStacks {
    folded_stacks(&h.build(), opts).unwrap()
}

/// Width of a frame: the sum of every line at or below `stack`.
fn width(lines: &[FoldedLine], stack: &str) -> u64 {
    let below = format!("{stack};");
    lines
        .iter()
        .filter(|l| l.stack == stack || l.stack.starts_with(&below))
        .map(|l| l.bytes)
        .sum()
}

fn total(lines: &[FoldedLine]) -> u64 {
    lines.iter().map(|l| l.bytes).sum()
}

const CACHE: &str = "sys.modules['app.cache'];.__dict__ dict;['CACHE'] dict";

#[test]
fn unbounded_cache_is_one_wide_frame() {
    let n = 200u64;
    let (h, _) = unbounded_cache(n as u32, 1000);
    let retained = (36 * n + 232) + n * (56 + 1000);
    for opts in [exact(), FlameOptions::default()] {
        let f = fold(&h, &opts);
        assert_eq!(width(&f.lines, CACHE), retained, "{:#?}", f.lines);
        // The CACHE dict's own shallow size is its self bytes.
        let own = f.lines.iter().find(|l| l.stack == CACHE).unwrap();
        assert_eq!(own.bytes, 36 * n + 232);
        // 200 sessions under three redacted-key placeholders, not 200 frames.
        let sessions: Vec<&FoldedLine> = f
            .lines
            .iter()
            .filter(|l| l.stack.starts_with(&format!("{CACHE};")))
            .collect();
        assert_eq!(sessions.len(), 6, "{sessions:#?}");
        let s9 = format!("{CACHE};[<str len=9>] app.session.Session");
        assert!(f.lines.iter().any(|l| l.stack == s9));
        let p9 = f
            .lines
            .iter()
            .find(|l| l.stack == format!("{s9};.payload bytes"))
            .unwrap();
        // Keys cycle through lengths 9, 10, 11: 67 sessions have length 9.
        assert_eq!(p9.bytes, 67 * 1000);
        assert_eq!(total(&f.lines), f.reachable_bytes);
    }
}

#[test]
fn list_items_merge_under_index() {
    let mut h = Heap::new();
    let (_, d) = h.module("app");
    let items = h.obj("builtins.list", 456);
    h.key(d, items, "ITEMS");
    for i in 0..50 {
        let x = h.obj("builtins.bytes", 100 + i as u64);
        h.untracked(x);
        h.item(items, x, i);
    }
    let f = fold(&h, &exact());
    let item = "sys.modules['app'];.__dict__ dict;['ITEMS'] list;[<index>] bytes";
    let lines: Vec<&FoldedLine> = f.lines.iter().filter(|l| l.stack == item).collect();
    assert_eq!(lines.len(), 1, "{:#?}", f.lines);
    assert_eq!(lines[0].bytes, (0..50).map(|i| 100 + i).sum::<u64>());
    assert_eq!(f.lines.len(), 4);
}

#[test]
fn root_frames_sum_to_reachable_bytes() {
    let (mut h, _) = unbounded_cache(30, 500);
    // Unreachable garbage is not drawn.
    let lost = h.obj("builtins.dict", 99_999);
    let lost2 = h.obj("builtins.list", 5);
    h.key(lost, lost2, "x");
    let snap = h.build();
    let f = folded_stacks(&snap, &exact()).unwrap();
    let r = analyze(&snap, "s", &AnalyzeOptions::default()).unwrap();
    assert_eq!(f.reachable_bytes, r.totals.reachable_bytes);
    assert_eq!(f.reachable_objects, r.totals.reachable_objects);
    let mut roots: Vec<&str> = f
        .lines
        .iter()
        .map(|l| l.stack.split(';').next().unwrap())
        .collect();
    roots.sort();
    roots.dedup();
    assert_eq!(
        roots,
        ["sys.modules['__main__']", "sys.modules['app.cache']"]
    );
    let sum: u64 = roots.iter().map(|r| width(&f.lines, r)).sum();
    assert_eq!(sum, r.totals.reachable_bytes);
    assert!(f.lines.iter().all(|l| !l.stack.contains("99999")));
}

#[test]
fn object_shared_by_two_roots_is_a_top_level_frame() {
    let mut h = Heap::new();
    let (_, a) = h.module("app.a");
    let (_, b) = h.module("app.b");
    let shared = h.obj("builtins.list", 64);
    h.key(a, shared, "SHARED");
    h.key(b, shared, "SHARED");
    for i in 0..10 {
        let x = h.obj("builtins.bytes", 1000);
        h.item(shared, x, i);
    }
    let f = fold(&h, &exact());
    assert_eq!(width(&f.lines, "...['SHARED'] list"), 64 + 10_000);
    assert!(f
        .lines
        .iter()
        .any(|l| l.stack == "...['SHARED'] list;[<index>] bytes" && l.bytes == 10_000));
    assert_eq!(total(&f.lines), f.reachable_bytes);
}

#[test]
fn object_reached_through_siblings_gets_dots() {
    // PENDING owns two lists that both hold `x`; x's dominator is PENDING,
    // but BFS enters it from the first list.
    let mut h = Heap::new();
    let (_, d) = h.module("app");
    let pending = h.obj("builtins.dict", 200);
    h.key(d, pending, "PENDING");
    let l1 = h.obj("builtins.list", 72);
    let l2 = h.obj("builtins.list", 72);
    h.key(pending, l1, "a");
    h.key(pending, l2, "b");
    let x = h.obj("builtins.bytearray", 5000);
    h.item(l1, x, 3);
    h.item(l2, x, 7);
    let f = fold(&h, &exact());
    let s = "sys.modules['app'];.__dict__ dict;['PENDING'] dict;...[<index>] bytearray";
    assert!(
        f.lines.iter().any(|l| l.stack == s && l.bytes == 5000),
        "{:#?}",
        f.lines
    );
}

/// `app.LIST` -> a linked list of `n` nodes of 64 bytes.
fn chain(n: u32) -> Heap {
    let mut h = Heap::new();
    let (_, d) = h.module("app");
    let mut prev = h.obj("app.Node", 64);
    h.key(d, prev, "LIST");
    for _ in 1..n {
        let x = h.obj("app.Node", 64);
        h.attr(prev, x, "next");
        prev = x;
    }
    h
}

#[test]
fn depth_cap_folds_into_other_and_keeps_widths() {
    let h = chain(100);
    let opts = FlameOptions {
        max_depth: 5,
        min_width: MinWidth::Bytes(0),
    };
    let f = fold(&h, &opts);
    let depth = |l: &FoldedLine| l.stack.split(';').count();
    assert!(f.lines.iter().all(|l| depth(l) <= 6), "{:#?}", f.lines);
    let deepest: Vec<&FoldedLine> = f.lines.iter().filter(|l| depth(l) == 6).collect();
    assert_eq!(deepest.len(), 1);
    assert!(deepest[0].stack.ends_with(";[other]"));
    // Frames 3 to 5 are LIST and two `.next` hops; the other 97 nodes are
    // folded.
    assert_eq!(deepest[0].bytes, 97 * 64);
    assert_eq!(width(&f.lines, "sys.modules['app']"), f.reachable_bytes);
    let full = fold(&h, &exact());
    assert_eq!(
        width(
            &f.lines,
            "sys.modules['app'];.__dict__ dict;['LIST'] app.Node"
        ),
        width(
            &full.lines,
            "sys.modules['app'];.__dict__ dict;['LIST'] app.Node"
        ),
    );
}

#[test]
fn very_deep_chain_does_not_recurse() {
    let f = fold(&chain(300_000), &FlameOptions::default());
    assert_eq!(total(&f.lines), f.reachable_bytes);
    assert!(f.lines.iter().all(|l| l.stack.split(';').count() <= 33));
}

#[test]
fn narrow_frames_fold_into_other() {
    // Captured keys: every entry is its own frame unless the cutoff folds it.
    let mut h = Heap::new();
    let (_, d) = h.module("app");
    let cache = h.obj("builtins.dict", 1000);
    h.key(d, cache, "CACHE");
    let big = h.obj("builtins.bytes", 50_000);
    h.untracked(big);
    h.key(cache, big, "big");
    for i in 0..100 {
        let x = h.obj("builtins.str", 50);
        h.untracked(x);
        h.key(cache, x, &format!("k{i}"));
    }
    let cache_frame = "sys.modules['app'];.__dict__ dict;['CACHE'] dict";
    let full = fold(&h, &exact());
    assert_eq!(full.lines.len(), 3 + 101);
    let cut = fold(
        &h,
        &FlameOptions {
            max_depth: 32,
            min_width: MinWidth::Bytes(1000),
        },
    );
    assert_eq!(cut.min_bytes, 1000);
    let other = cut
        .lines
        .iter()
        .find(|l| l.stack == format!("{cache_frame};[other]"))
        .unwrap_or_else(|| panic!("{:#?}", cut.lines));
    assert_eq!(other.bytes, 100 * 50);
    assert!(cut
        .lines
        .iter()
        .any(|l| l.stack == format!("{cache_frame};['big'] bytes")));
    assert_eq!(cut.lines.len(), 3 + 2);
    for frame in [
        "sys.modules['app']",
        "sys.modules['app'];.__dict__ dict",
        cache_frame,
    ] {
        assert_eq!(width(&cut.lines, frame), width(&full.lines, frame));
    }
    // A percentage cutoff: 1% of ~60 KiB folds the same keys.
    let pct = fold(
        &h,
        &FlameOptions {
            max_depth: 32,
            min_width: MinWidth::Pct(1.0),
        },
    );
    assert_eq!(pct.lines.len(), 5);
    assert_eq!(total(&pct.lines), full.reachable_bytes);
}

#[test]
fn redacted_keys_with_the_same_placeholder_merge() {
    let mut h = Heap::new();
    let (_, d) = h.module("app");
    let cache = h.obj("builtins.dict", 1000);
    h.key(d, cache, "CACHE");
    for _ in 0..20 {
        let x = h.obj("builtins.bytes", 10);
        h.untracked(x);
        h.edge(cache, x, L::Redacted(9));
    }
    let f = fold(&h, &exact());
    let s = "sys.modules['app'];.__dict__ dict;['CACHE'] dict;[<str len=9>] bytes";
    assert!(f.lines.iter().any(|l| l.stack == s && l.bytes == 200));
}

#[test]
fn closures_and_cells_are_labelled() {
    let mut h = Heap::new();
    let (_, d) = h.module("__main__");
    let bus = h.obj("app.Bus", 56);
    h.key(d, bus, "BUS");
    let listeners = h.obj("builtins.list", 88);
    h.attr(bus, listeners, "listeners");
    for i in 0..3 {
        let f = h.obj("builtins.function", 160);
        h.item(listeners, f, i);
        let cell = h.obj("builtins.cell", 24);
        h.edge(f, cell, L::Closure(0));
        let data = h.obj("builtins.bytearray", 10_000);
        h.untracked(data);
        h.edge(cell, data, L::Cell);
    }
    let f = fold(&h, &exact());
    let s = "sys.modules['__main__'];.__dict__ dict;['BUS'] app.Bus;.listeners list;\
             [<index>] function;.__closure__[0] cell;.cell_contents bytearray";
    assert!(
        f.lines.iter().any(|l| l.stack == s && l.bytes == 30_000),
        "{:#?}",
        f.lines
    );
}

#[test]
fn root_labels_are_root_frames() {
    let mut h = Heap::new();
    let x = h.obj("builtins.list", 100);
    h.root(x, RootKind::FrameLocal, "frame app:run local 'pending'");
    let f = fold(&h, &exact());
    assert_eq!(f.lines.len(), 1);
    assert_eq!(f.lines[0].stack, "frame app:run local 'pending'");
}

#[test]
fn output_is_deterministic() {
    let (h, _) = unbounded_cache(50, 100);
    let a = fold(&h, &FlameOptions::default());
    let b = fold(&h, &FlameOptions::default());
    assert_eq!(a, b);
    let mut out = Vec::new();
    a.write_to(&mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text
        .lines()
        .any(|l| l == format!("{CACHE} {}", 36 * 50 + 232)));
    let mut sorted: Vec<&str> = text.lines().collect();
    sorted.sort();
    assert_eq!(sorted, text.lines().collect::<Vec<_>>());
}

#[test]
fn differential_sums_match_each_snapshot() {
    let (before, _) = unbounded_cache(10, 1000);
    let (after, _) = unbounded_cache(100, 1000);
    for opts in [exact(), FlameOptions::default()] {
        let d = folded_diff(&before.build(), &after.build(), &opts).unwrap();
        let b: u64 = d.lines.iter().map(|l| l.before).sum();
        let a: u64 = d.lines.iter().map(|l| l.after).sum();
        assert_eq!(b, d.before_reachable_bytes);
        assert_eq!(a, d.after_reachable_bytes);
        let cache = d.lines.iter().find(|l| l.stack == CACHE).unwrap();
        assert_eq!((cache.before, cache.after), (36 * 10 + 232, 36 * 100 + 232));
        // Same frame paths as the single-snapshot output.
        let single = fold(&after, &opts);
        let mut keys: Vec<&str> = single.lines.iter().map(|l| l.stack.as_str()).collect();
        keys.sort();
        for k in keys {
            assert!(d.lines.iter().any(|l| l.stack == k), "{k}");
        }
        let mut out = Vec::new();
        d.write_to(&mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text
            .lines()
            .any(|l| l == format!("{CACHE} {} {}", 36 * 10 + 232, 36 * 100 + 232)));
    }
}

#[test]
fn differential_cutoff_uses_the_wider_side() {
    // `GONE` is wide before and absent after; `NEW` is the reverse. Both
    // must survive a cutoff that each would fail on one side.
    let build = |gone: bool| {
        let mut h = Heap::new();
        let (_, d) = h.module("app");
        let name = if gone { "GONE" } else { "NEW" };
        let x = h.obj("builtins.bytes", 10_000);
        h.untracked(x);
        h.key(d, x, name);
        let small = h.obj("builtins.bytes", 10);
        h.untracked(small);
        h.key(d, small, "SMALL");
        h
    };
    let d = folded_diff(
        &build(true).build(),
        &build(false).build(),
        &FlameOptions {
            max_depth: 32,
            min_width: MinWidth::Bytes(5000),
        },
    )
    .unwrap();
    let get = |s: &str| {
        d.lines
            .iter()
            .find(|l| l.stack == format!("sys.modules['app'];.__dict__ dict;{s}"))
            .map(|l| (l.before, l.after))
    };
    assert_eq!(get("['GONE'] bytes"), Some((10_000, 0)));
    assert_eq!(get("['NEW'] bytes"), Some((0, 10_000)));
    assert_eq!(get("[other]"), Some((10, 10)));
}

#[test]
fn invalid_options_are_rejected() {
    let (h, _) = unbounded_cache(1, 1);
    let s = h.build();
    for opts in [
        FlameOptions {
            max_depth: 0,
            ..Default::default()
        },
        FlameOptions {
            min_width: MinWidth::Pct(-1.0),
            ..Default::default()
        },
    ] {
        assert!(matches!(
            folded_stacks(&s, &opts),
            Err(heapspy_analyzer::Error::InvalidArgument(_))
        ));
    }
}
