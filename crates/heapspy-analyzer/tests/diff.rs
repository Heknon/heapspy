//! `diff` between synthetic snapshots.

mod common;

use common::*;
use heapspy_analyzer::report::DiffReport;
use heapspy_analyzer::{diff, DiffOptions};

fn run(before: &Heap, after: &Heap) -> DiffReport {
    let r = diff(
        &before.build(),
        "before.hpy",
        &after.build(),
        "after.hpy",
        &DiffOptions::default(),
    )
    .unwrap();
    let back: DiffReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
    r
}

#[test]
fn growing_cache_is_the_top_site() {
    let (before, _) = unbounded_cache(10, 1000);
    let (after, _) = unbounded_cache(100, 1000);
    let r = run(&before, &after);
    assert!(r.identity_approximate);
    assert_eq!(r.before.path, "before.hpy");
    assert_eq!(r.notes[0].code, "identity_approximate");

    let s = &r.by_site[0];
    assert_eq!(s.site, "sys.modules['app.cache'].__dict__['CACHE']");
    assert_eq!(s.type_name, "builtins.dict");
    let cache = |n: u64| (36 * n + 232) + n * (56 + 1000);
    assert_eq!(s.before_retained_bytes, cache(10));
    assert_eq!(s.after_retained_bytes, cache(100));
    assert_eq!(s.delta_retained_bytes, (cache(100) - cache(10)) as i64);
    assert_eq!(s.delta_retained_objects, 180);
    // The module and its dict grew by the same amount; they only restate
    // CACHE and are not listed.
    assert!(r
        .by_site
        .iter()
        .all(|x| x.site != "sys.modules['app.cache']"
            && x.site != "sys.modules['app.cache'].__dict__"));
    // Unchanged sites are not listed.
    assert!(r.by_site.iter().all(|x| !x.site.contains("__main__")));

    let t = &r.by_type[0];
    assert_eq!(t.type_name, "builtins.bytes");
    assert_eq!(
        (t.before_count, t.after_count, t.delta_count),
        (10, 100, 90)
    );
    assert_eq!(t.delta_bytes, 90_000);
    assert!(r
        .by_type
        .windows(2)
        .all(|w| w[0].delta_bytes >= w[1].delta_bytes));
    assert!(r.by_type.iter().all(|t| t.type_name != "builtins.module"));

    let objs = |h: &Heap| h.build().object_count() as i64;
    assert_eq!(r.totals.delta_objects, objs(&after) - objs(&before));
    assert_eq!(
        r.totals.delta_reachable_bytes,
        r.totals.after.reachable_bytes as i64 - r.totals.before.reachable_bytes as i64
    );
}

#[test]
fn entries_with_redacted_keys_share_one_site() {
    // Payloads small enough that a session does not just restate its payload.
    let (before, _) = unbounded_cache(10, 100);
    let (after, _) = unbounded_cache(100, 100);
    let r = diff(
        &before.build(),
        "b",
        &after.build(),
        "a",
        &DiffOptions { top: 100 },
    )
    .unwrap();
    // Keys are redacted to three placeholder lengths, so the sessions
    // collapse into three sites under CACHE.
    let under: Vec<_> = r
        .by_site
        .iter()
        .filter(|s| {
            s.site
                .starts_with("sys.modules['app.cache'].__dict__['CACHE'][<str len=")
        })
        .filter(|s| s.site.ends_with(']'))
        .collect();
    assert_eq!(under.len(), 3, "{:#?}", r.by_site);
    let total: i64 = under.iter().map(|s| s.delta_retained_bytes).sum();
    assert_eq!(total, 90 * (56 + 100));
    assert!(under.iter().all(|s| s.type_name == "app.session.Session"));
}

#[test]
fn a_site_that_restates_its_child_is_not_listed() {
    // Each session is 56 bytes over a 1000-byte payload, so the session
    // sites only restate their `.payload` sites.
    let (before, _) = unbounded_cache(10, 1000);
    let (after, _) = unbounded_cache(100, 1000);
    let r = diff(
        &before.build(),
        "b",
        &after.build(),
        "a",
        &DiffOptions { top: 100 },
    )
    .unwrap();
    let under: Vec<&str> = r
        .by_site
        .iter()
        .map(|s| s.site.as_str())
        .filter(|s| s.starts_with("sys.modules['app.cache'].__dict__['CACHE'][<str len="))
        .collect();
    assert_eq!(under.len(), 3, "{under:?}");
    assert!(under.iter().all(|s| s.ends_with("].payload")), "{under:?}");
}

#[test]
fn shrinking_and_vanished_sites() {
    let mut before = Heap::new();
    let (_, md) = before.module("__main__");
    let big = before.obj("builtins.list", 5000);
    before.key(md, big, "GONE");
    let mut after = Heap::new();
    after.module("__main__");
    let r = run(&before, &after);
    let s = r
        .by_site
        .iter()
        .find(|s| s.site == "sys.modules['__main__'].__dict__['GONE']")
        .unwrap();
    assert_eq!(s.after_retained_bytes, 0);
    assert_eq!(s.delta_retained_bytes, -5000);
    assert_eq!(s.type_name, "builtins.list");
    let t = r
        .by_type
        .iter()
        .find(|t| t.type_name == "builtins.list")
        .unwrap();
    assert_eq!(t.delta_count, -1);
}

#[test]
fn list_items_are_generalised_and_indirect_hops_marked() {
    let build = |n: u32| {
        let mut h = Heap::new();
        let (_, md) = h.module("__main__");
        let l = h.obj("builtins.list", 64);
        h.key(md, l, "PENDING");
        // Two references into each item from inside the list's subtree, so
        // the item's dominator is the list but its BFS parent is not.
        for i in 0..n {
            let a = h.obj("builtins.tuple", 48);
            h.item(l, a, i);
            let x = h.obj("app.Job", 100);
            h.item(a, x, 0);
            let b = h.obj("builtins.tuple", 48);
            h.item(l, b, i + 1000);
            h.item(b, x, 1);
        }
        h
    };
    let r = diff(
        &build(2).build(),
        "b",
        &build(5).build(),
        "a",
        &DiffOptions { top: 100 },
    )
    .unwrap();
    let sites: Vec<&str> = r.by_site.iter().map(|s| s.site.as_str()).collect();
    assert!(
        sites.contains(&"sys.modules['__main__'].__dict__['PENDING'][<index>]"),
        "{sites:?}"
    );
    assert!(
        sites.contains(&"sys.modules['__main__'].__dict__['PENDING']...[<index>]"),
        "{sites:?}"
    );
}
