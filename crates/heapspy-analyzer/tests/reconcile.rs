//! Edges the walker was unsure of, checked against refcounts.
//!
//! A refcount is how many references own an object. Scanned edges (fields of
//! an unknown layout) are kept only up to that count, speculative edges
//! (pointers found out of line) only where the count has owners nothing else
//! explains, and objects no root reaches but something outside the graph
//! still owns become roots of their own.

use heapspy_analyzer::report::AnalyzeReport;
use heapspy_analyzer::{analyze, root_path_string, AnalyzeOptions};
use heapspy_snapshot::{RootKind, SnapshotBuilder};

fn run(b: &SnapshotBuilder) -> AnalyzeReport {
    let r = analyze(&b.build().unwrap(), "t.hpy", &AnalyzeOptions::default()).unwrap();
    let json = serde_json::to_string(&r).unwrap();
    let back: AnalyzeReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
    r
}

fn retained_of(r: &AnalyzeReport, type_name: &str) -> u64 {
    r.type_histogram
        .iter()
        .find(|t| t.type_name == type_name)
        .unwrap_or_else(|| panic!("no {type_name} in the histogram"))
        .retained_bytes
}

#[test]
fn scanned_field_past_the_refcount_is_dropped_as_borrowed() {
    let mut b = SnapshotBuilder::new();
    let dict = b.ty("builtins", "dict");
    let holder = b.ty("ext", "Holder");
    let blob = b.ty("builtins", "bytes");
    // The module owns the blob; the extension object only borrows it.
    b.object(0x100, dict, 64)
        .dict_value(0x200, "'BLOB'")
        .dict_value(0x300, "'H'")
        .refcount(1);
    b.object(0x200, blob, 10_000).refcount(1);
    b.object(0x300, holder, 32).scanned(0x200, 16).refcount(1);
    b.root(0x100, RootKind::ModuleDict, "sys.modules['m']");
    let r = run(&b);
    assert!(r.totals.refcounts_checked);
    assert_eq!(r.totals.borrowed_edges_dropped, 1);
    // The holder does not retain the blob it borrows.
    assert_eq!(retained_of(&r, "ext.Holder"), 32);
}

#[test]
fn scanned_field_within_the_refcount_is_kept() {
    let mut b = SnapshotBuilder::new();
    let dict = b.ty("builtins", "dict");
    let holder = b.ty("ext", "Holder");
    let blob = b.ty("builtins", "bytes");
    b.object(0x100, dict, 64)
        .dict_value(0x300, "'H'")
        .refcount(1);
    b.object(0x300, holder, 32).scanned(0x200, 16).refcount(1);
    b.object(0x200, blob, 10_000).refcount(1);
    b.root(0x100, RootKind::ModuleDict, "sys.modules['m']");
    let r = run(&b);
    assert_eq!(r.totals.borrowed_edges_dropped, 0);
    assert_eq!(retained_of(&r, "ext.Holder"), 32 + 10_000);
}

#[test]
fn out_of_line_pointer_is_kept_only_for_an_unexplained_owner() {
    let mut b = SnapshotBuilder::new();
    let dict = b.ty("builtins", "dict");
    let deque = b.ty("collections", "deque");
    let item = b.ty("builtins", "bytes");
    b.object(0x100, dict, 64)
        .dict_value(0x300, "'Q'")
        .dict_value(0x500, "'OTHER'")
        .refcount(1);
    // 0x400 is owned by the deque's block and nothing else; 0x500 is a stale
    // slot: its one owner is the module dict.
    b.object(0x300, deque, 48)
        .speculative(0x400, 16, 1)
        .speculative(0x500, 16, 2)
        .refcount(1);
    b.object(0x400, item, 5_000).refcount(1);
    b.object(0x500, item, 7_000).refcount(1);
    b.root(0x100, RootKind::ModuleDict, "sys.modules['m']");
    let r = run(&b);
    assert_eq!(r.totals.out_of_line_edges, 1);
    assert_eq!(r.totals.stale_edges_dropped, 1);
    assert_eq!(retained_of(&r, "collections.deque"), 48 + 5_000);
}

#[test]
fn natively_held_objects_get_their_own_root_and_cycles_are_garbage() {
    let mut b = SnapshotBuilder::new();
    let dict = b.ty("builtins", "dict");
    let list = b.ty("builtins", "list");
    let obj = b.ty("app", "Node");
    b.object(0x100, dict, 64).refcount(1);
    b.root(0x100, RootKind::ModuleDict, "sys.modules['m']");
    // A list only C code holds (refcount 1, no edge in), and what it holds.
    b.object(0x200, list, 56).list_item(0x210, 0).refcount(1);
    b.object(0x210, obj, 4_000).refcount(1);
    // A cycle whose owners are each other: garbage.
    b.object(0x300, obj, 100).attr(0x310, "next").refcount(1);
    b.object(0x310, obj, 100).attr(0x300, "next").refcount(1);
    let r = run(&b);
    assert_eq!(r.totals.external_objects, 2);
    assert_eq!(r.totals.external_bytes, 56 + 4_000);
    assert_eq!(r.totals.unreachable_objects, 2);
    assert_eq!(r.totals.unreachable_bytes, 200);
    assert_eq!(r.totals.reachable_objects, 1);

    // The list only wraps the node, so the node is reported (see
    // `CHAIN_RATIO`); its path starts at the list, under the external root.
    let top = &r.top_retainers[0];
    assert_eq!(top.address.0, 0x210);
    assert_eq!(top.path[0].address.0, 0x200);
    assert_eq!(
        root_path_string(&top.path),
        "held outside the Python graph[0]"
    );
    assert_eq!(top.path[0].root_kind.as_deref(), Some("external"));
}

#[test]
fn a_native_container_is_the_root_not_its_contents() {
    // Both the list and its item have an owner no edge explains (the item is
    // also held by C code), but the item hangs below the list.
    let mut b = SnapshotBuilder::new();
    let list = b.ty("builtins", "list");
    let obj = b.ty("app", "Node");
    b.object(0x200, list, 56).list_item(0x210, 0).refcount(1);
    b.object(0x210, obj, 4_000).refcount(2);
    let r = run(&b);
    assert_eq!(r.totals.external_objects, 2);
    assert_eq!(r.top_retainers[0].path[0].address.0, 0x200);
    assert_eq!(r.top_retainers[0].path.len(), 2);
}

#[test]
fn without_refcounts_nothing_is_checked() {
    let mut b = SnapshotBuilder::new();
    let dict = b.ty("builtins", "dict");
    let deque = b.ty("collections", "deque");
    let item = b.ty("builtins", "bytes");
    b.object(0x100, dict, 64).dict_value(0x300, "'Q'");
    b.object(0x300, deque, 48).speculative(0x400, 16, 1);
    b.object(0x400, item, 5_000);
    b.root(0x100, RootKind::ModuleDict, "sys.modules['m']");
    let r = run(&b);
    assert!(!r.totals.refcounts_checked);
    // A stale pointer cannot be told from a real one, so none is trusted.
    assert_eq!(r.totals.out_of_line_edges, 0);
    assert_eq!(r.totals.stale_edges_dropped, 1);
    assert_eq!(r.totals.external_objects, 0);
    assert_eq!(r.totals.unreachable_objects, 1);
}

#[test]
fn stable_roots_win_over_a_shorter_path_from_a_frame() {
    // A running function's local reaches the cache in one hop; the module
    // global reaches it in two. The path names the module.
    let mut b = SnapshotBuilder::new();
    let dict = b.ty("builtins", "dict");
    let module = b.ty("builtins", "module");
    let cache = b.ty("builtins", "list");
    b.object(0x100, module, 72).attr(0x110, "__dict__");
    b.object(0x110, dict, 64).dict_value(0x300, "'CACHE'");
    b.object(0x300, cache, 9_000);
    b.object(0x400, dict, 64);
    b.root(0x100, RootKind::ModuleDict, "sys.modules['m']");
    b.root(0x300, RootKind::FrameLocal, "frame m:work local 'c'");
    let r = run(&b);
    let top = r
        .top_retainers
        .iter()
        .find(|t| t.address.0 == 0x300)
        .unwrap();
    assert_eq!(
        root_path_string(&top.path),
        "sys.modules['m'].__dict__['CACHE']"
    );
}
