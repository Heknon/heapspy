//! `analyze` on synthetic snapshots shaped like the end-to-end fixtures.

mod common;

use common::*;
use heapspy_analyzer::report::{AnalyzeReport, Retainer};
use heapspy_analyzer::{analyze, root_path_string, AnalyzeOptions};
use heapspy_snapshot::{RegionKind, RootKind, SnapshotBuilder};

fn run(h: &Heap) -> AnalyzeReport {
    let r = analyze(&h.build(), "t.hpy", &AnalyzeOptions::default()).unwrap();
    // JSON from real analysis must parse back into the report types.
    let json = serde_json::to_string(&r).unwrap();
    let back: AnalyzeReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
    r
}

fn site(r: &Retainer) -> String {
    root_path_string(&r.path)
}

#[test]
fn unbounded_cache_dict_is_the_top_retainer() {
    let n = 500;
    let (h, cache) = unbounded_cache(n, MIB);
    let r = run(&h);
    let top = &r.top_retainers[0];
    assert_eq!(top.address.0, cache);
    assert_eq!(top.type_name, "builtins.dict");
    assert_eq!(site(top), "sys.modules['app.cache'].__dict__['CACHE']");
    let expect = (36 * n as u64 + 232) + n as u64 * (56 + MIB);
    assert_eq!(top.retained_bytes, expect);
    assert_eq!(top.retained_objects, 1 + 2 * n as u64);
    assert!(top.retained_pct > 99.0, "{}", top.retained_pct);
    assert_eq!(top.rank, 1);

    // The path is root first: module, its dict, the cache.
    let p = &top.path;
    assert_eq!(p.len(), 3);
    assert_eq!(p[0].type_name, "builtins.module");
    assert_eq!(p[0].edge, None);
    assert_eq!(p[0].root_label.as_deref(), Some("sys.modules['app.cache']"));
    assert_eq!(p[0].root_kind.as_deref(), Some("module_dict"));
    assert_eq!(p[1].edge.as_deref(), Some(".__dict__"));
    assert_eq!(p[2].edge.as_deref(), Some("['CACHE']"));
    assert_eq!(p[2].root_label, None);

    // Entries are disjoint: no session inside CACHE is listed.
    assert!(r.top_retainers[1..]
        .iter()
        .all(|t| !site(t).starts_with("sys.modules['app.cache'].__dict__['CACHE']")));
    // Modules and module dicts are namespaces, never listed.
    assert!(r
        .top_retainers
        .iter()
        .all(|t| t.type_name != "builtins.module" && site(t).contains('[')));

    assert_eq!(r.totals.objects, h.build().object_count() as u64);
    assert_eq!(r.totals.unreachable_objects, 0);
    assert_eq!(r.totals.reachable_bytes, r.totals.shallow_bytes);
    assert_eq!(r.totals.dangling_edges, 0);
    assert_eq!(r.totals.types, 6);
    let codes: Vec<&str> = r.notes.iter().map(|n| n.code.as_str()).collect();
    assert_eq!(codes, ["untracked_objects", "keys_redacted"]);
    assert_eq!(r.memory.rss_bytes, None);
    assert_eq!(r.memory.outside_graph_bytes, None);
}

#[test]
fn histogram_counts_nested_instances_once() {
    let (h, _) = unbounded_cache(100, 1000);
    let r = run(&h);
    let row = |t: &str| r.type_histogram.iter().find(|x| x.type_name == t).unwrap();
    let bytes = row("builtins.bytes");
    assert_eq!((bytes.count, bytes.shallow_bytes), (100, 100_000));
    assert_eq!(bytes.retained_bytes, 100_000);
    let sess = row("app.session.Session");
    assert_eq!(sess.count, 100);
    assert_eq!(sess.retained_bytes, 100 * (56 + 1000));
    // Dicts: two module dicts, the class dict and CACHE. The class dict and
    // CACHE sit inside a module dict, so only the module dicts count, and
    // they retain everything except the module objects themselves.
    let d = row("builtins.dict");
    assert_eq!(d.count, 4);
    assert_eq!(d.retained_bytes, r.totals.reachable_bytes - 2 * 72);
    // Sorted by retained bytes.
    assert!(r
        .type_histogram
        .windows(2)
        .all(|w| w[0].retained_bytes >= w[1].retained_bytes));
    assert_eq!(r.type_histogram[0].type_name, "builtins.module");
}

#[test]
fn partial_retention_counts_only_kept_blobs() {
    // A batch of 3000 blobs was built; a global list keeps every 1000th. The
    // batch list itself is garbage (unreachable). One kept blob is also
    // referenced from another global, so KEEP does not retain it.
    let mut h = Heap::new();
    let (_, md) = h.module("__main__");
    let keep = h.obj("builtins.list", 88);
    h.key(md, keep, "KEEP");
    let other = h.obj("builtins.list", 64);
    h.key(md, other, "OTHER");
    let batch = h.obj("builtins.list", 8 * 3000 + 56);
    let mut kept = Vec::new();
    for i in 0..3000u32 {
        let blob = h.obj("builtins.bytes", 10_000);
        h.untracked(blob);
        h.item(batch, blob, i);
        if i % 1000 == 0 {
            h.item(keep, blob, kept.len() as u32);
            kept.push(blob);
        }
    }
    h.item(other, kept[2], 0);
    let r = run(&h);

    let top = &r.top_retainers[0];
    assert_eq!(site(top), "sys.modules['__main__'].__dict__['KEEP']");
    assert_eq!(top.retained_bytes, 88 + 2 * 10_000);
    assert_eq!(top.retained_objects, 3);
    // The shared blob is reported on its own, reached through the shorter
    // or first-found path.
    let shared = r
        .top_retainers
        .iter()
        .find(|t| t.address.0 == kept[2])
        .unwrap();
    assert_eq!(shared.retained_bytes, 10_000);

    assert_eq!(r.totals.unreachable_objects, 1 + 2997);
    assert_eq!(r.totals.unreachable_bytes, 8 * 3000 + 56 + 2997 * 10_000);
    let bytes = r
        .type_histogram
        .iter()
        .find(|x| x.type_name == "builtins.bytes")
        .unwrap();
    assert_eq!(bytes.count, 3000);
    assert_eq!(bytes.retained_bytes, 30_000);
}

#[test]
fn closure_capturing_a_large_object() {
    let mut h = Heap::new();
    let (_, md) = h.module("app.handlers");
    let f = h.obj("builtins.function", 160);
    h.key(md, f, "HANDLER");
    let code = h.obj("builtins.code", 400);
    h.attr(f, code, "__code__");
    let cell = h.obj("builtins.cell", 40);
    h.edge(f, cell, L::Closure(0));
    let big = h.obj("builtins.bytearray", 50 * MIB);
    h.edge(cell, big, L::Cell);
    let r = run(&h);
    let top = &r.top_retainers[0];
    // function -> cell -> bytearray restate each other; the accumulation
    // point is reported and the path shows the closure.
    assert_eq!(top.type_name, "builtins.bytearray");
    assert_eq!(
        site(top),
        "sys.modules['app.handlers'].__dict__['HANDLER'].__closure__[0].cell_contents"
    );
    assert_eq!(top.retained_bytes, 50 * MIB);
    assert_eq!(top.path[2].type_name, "builtins.function");
    assert!(r
        .top_retainers
        .iter()
        .all(|t| t.type_name != "builtins.function"));
}

#[test]
fn listener_registry() {
    let mut h = Heap::new();
    let (_, md) = h.module("app.events");
    let reg = h.obj("app.events.Registry", 48);
    h.key(md, reg, "REGISTRY");
    let lst = h.obj("builtins.list", 8 * 200 + 56);
    h.attr(reg, lst, "listeners");
    let name = h.obj("builtins.str", 60);
    h.attr(reg, name, "name");
    for i in 0..200 {
        let l = h.obj("app.events.Listener", 48);
        h.item(lst, l, i);
        let buf = h.obj("builtins.bytes", 64 * 1024);
        h.attr(l, buf, "buffer");
    }
    let r = run(&h);
    let top = &r.top_retainers[0];
    assert_eq!(top.type_name, "builtins.list");
    assert_eq!(
        site(top),
        "sys.modules['app.events'].__dict__['REGISTRY'].listeners"
    );
    assert_eq!(top.retained_bytes, 8 * 200 + 56 + 200 * (48 + 64 * 1024));
    assert_eq!(top.path[2].type_name, "app.events.Registry");
}

#[test]
fn linked_list_is_not_collapsed_to_its_tail() {
    let mut h = Heap::new();
    let (_, md) = h.module("__main__");
    let mut prev = h.obj("app.Node", 1000);
    h.key(md, prev, "HEAD");
    for _ in 0..10_000 {
        let n = h.obj("app.Node", 1000);
        h.attr(prev, n, "next");
        prev = n;
    }
    let r = run(&h);
    let top = &r.top_retainers[0];
    assert_eq!(top.type_name, "app.Node");
    // Within a few hops of the head and holding nearly all of the list.
    assert!(top.path.len() <= 3 + 9, "{}", top.path.len());
    assert!(top.retained_bytes >= 9_990 * 1000);
    assert_eq!(r.top_retainers.len(), 1);
}

#[test]
fn memory_accounting_and_notes() {
    let mut b = SnapshotBuilder::new();
    let m = b.ty("builtins", "module");
    b.object(0x1000, m, 1000).dict_value(0x9999, "'x'");
    b.object(0x2000, m, 500); // unreachable
    b.root(0x1000, RootKind::ModuleDict, "sys.modules['a']");
    b.root(0x5555, RootKind::Other, "gone");
    b.memory_region(RegionKind::Heap, 10_000, Some(6_000));
    b.memory_region(RegionKind::Anonymous, 10_000, Some(4_000));
    b.truncated(true).contents_captured(true);
    let r = analyze(&b.build().unwrap(), "x", &AnalyzeOptions::default()).unwrap();
    assert_eq!(r.memory.rss_bytes, Some(10_000));
    assert_eq!(r.memory.graph_bytes, 1500);
    assert_eq!(r.memory.outside_graph_bytes, Some(8500));
    assert_eq!(r.memory.outside_graph_pct, Some(85.0));
    assert_eq!(r.totals.dangling_edges, 1);
    assert_eq!(r.totals.reachable_objects, 1);
    assert_eq!(r.totals.unreachable_bytes, 500);
    let codes: Vec<&str> = r.notes.iter().map(|n| n.code.as_str()).collect();
    assert_eq!(
        codes,
        [
            "untracked_objects",
            "outside_graph",
            "truncated_snapshot",
            "dangling_edges",
            "missing_roots"
        ]
    );

    // The meta value wins over the region sum.
    b.meta("process.rss_bytes", "2000");
    let r = analyze(&b.build().unwrap(), "x", &AnalyzeOptions::default()).unwrap();
    assert_eq!(r.memory.rss_bytes, Some(2000));
    assert_eq!(r.memory.outside_graph_bytes, Some(500));
    assert!(r.notes.iter().all(|n| n.code != "outside_graph"));
}

#[test]
fn empty_snapshot_and_top_limit() {
    let r = analyze(
        &SnapshotBuilder::new().build().unwrap(),
        "e",
        &AnalyzeOptions::default(),
    )
    .unwrap();
    assert!(r.top_retainers.is_empty() && r.type_histogram.is_empty());
    assert_eq!(r.totals.objects, 0);

    let (h, _) = unbounded_cache(50, 100);
    let r = analyze(&h.build(), "t", &AnalyzeOptions { top: 2 }).unwrap();
    assert!(r.top_retainers.len() <= 2);
    assert_eq!(r.type_histogram.len(), 2);
}
