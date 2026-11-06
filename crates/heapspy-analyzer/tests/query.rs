//! `query --type` and `query --retaining-path` on synthetic snapshots.

mod common;

use common::*;
use heapspy_analyzer::report::{PathQueryBy, RetainingPathReport, TypeQueryReport};
use heapspy_analyzer::{
    query_type, retaining_path, root_path_string, Error, PathTarget, QueryOptions,
};

fn opts() -> QueryOptions {
    QueryOptions::default()
}

#[test]
fn type_query_on_the_cache() {
    let n = 300;
    let (h, _) = unbounded_cache(n, 4096);
    let s = h.build();
    let r = query_type(&s, "t.hpy", "Session", &opts()).unwrap();
    let back: TypeQueryReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);

    assert_eq!(r.query, "Session");
    assert_eq!(r.matched_types, ["app.session.Session"]);
    assert_eq!(r.instances, n as u64);
    assert_eq!(r.shallow_bytes, 56 * n as u64);
    assert_eq!(r.retained_bytes, (56 + 4096) * n as u64);
    assert_eq!(r.top_instances.len(), 20);
    let i = &r.top_instances[0];
    assert_eq!(i.retained_bytes, 56 + 4096);
    assert_eq!(i.length, None);
    let p = i.path.as_ref().unwrap();
    assert_eq!(p.last().unwrap().address, i.address);
    assert!(root_path_string(p).starts_with("sys.modules['app.cache'].__dict__['CACHE'][<str len="));

    // The cache holds every instance under one generalised row.
    assert_eq!(r.holders[0].type_name, "builtins.dict");
    assert_eq!(r.holders[0].edge, "[<key>]");
    assert_eq!(r.holders[0].count, n as u64);
    assert_eq!(r.notes[0].code, "keys_redacted");

    // Full names work too; unknown names are not_found.
    let full = query_type(&s, "t.hpy", "app.session.Session", &opts()).unwrap();
    assert_eq!(full.instances, n as u64);
    assert!(matches!(
        query_type(&s, "t.hpy", "Nope", &opts()),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn type_query_length_and_nested_retained() {
    let mut h = Heap::new();
    let (_, md) = h.module("__main__");
    let outer = h.obj("builtins.list", 100);
    h.key(md, outer, "L");
    h.length(outer, 1);
    let inner = h.obj("builtins.list", 50);
    h.item(outer, inner, 0);
    h.length(inner, 0);
    let r = query_type(&h.build(), "t", "list", &opts()).unwrap();
    assert_eq!(r.instances, 2);
    // The inner list is inside the outer one: counted once.
    assert_eq!(r.retained_bytes, 150);
    assert_eq!(r.top_instances[0].length, Some(1));
    assert_eq!(r.top_instances[1].length, Some(0));
}

#[test]
fn retaining_path_by_address_with_several_paths() {
    let mut h = Heap::new();
    let (_, md) = h.module("app");
    let a = h.obj("builtins.list", 64);
    h.key(md, a, "A");
    let b = h.obj("builtins.dict", 64);
    h.key(md, b, "B");
    let target = h.obj("app.Thing", 1000);
    h.item(a, target, 3);
    h.key(b, target, "t");
    h.attr(target, target, "me"); // self-loop: never a path
    let s = h.build();
    let r = retaining_path(&s, "t", &PathTarget::Address(target), &opts()).unwrap();
    let back: RetainingPathReport =
        serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
    assert_eq!(r.query.by, PathQueryBy::Address);
    assert_eq!(r.query.value, format!("{target:#x}"));
    let t = &r.targets[0];
    assert!(t.reachable);
    assert_eq!(t.retained_bytes, 1000);
    let sites: Vec<String> = t.paths.iter().map(|p| root_path_string(p)).collect();
    assert_eq!(
        sites,
        [
            "sys.modules['app'].__dict__['A'][3]",
            "sys.modules['app'].__dict__['B']['t']"
        ]
    );
    assert!(r.notes.iter().all(|n| n.code != "unreachable_target"));

    let one = retaining_path(
        &s,
        "t",
        &PathTarget::Address(target),
        &QueryOptions {
            max_paths: 1,
            ..opts()
        },
    )
    .unwrap();
    assert_eq!(one.targets[0].paths.len(), 1);
}

#[test]
fn retaining_path_of_a_root_and_of_garbage() {
    let mut h = Heap::new();
    let (m, _) = h.module("app");
    let junk = h.obj("builtins.list", 64);
    let s = h.build();
    let r = retaining_path(&s, "t", &PathTarget::Address(m), &opts()).unwrap();
    let p = &r.targets[0].paths[0];
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].root_label.as_deref(), Some("sys.modules['app']"));
    assert_eq!(p[0].edge, None);

    let r = retaining_path(&s, "t", &PathTarget::Address(junk), &opts()).unwrap();
    assert!(!r.targets[0].reachable);
    assert!(r.targets[0].paths.is_empty());
    assert_eq!(r.targets[0].retained_bytes, 0);
    assert_eq!(r.notes[0].code, "unreachable_target");

    assert!(matches!(
        retaining_path(&s, "t", &PathTarget::Address(0x1), &opts()),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn retaining_path_by_type_returns_largest_instances() {
    let (h, _) = unbounded_cache(30, 100);
    let s = h.build();
    let r = retaining_path(
        &s,
        "t",
        &PathTarget::Type("builtins.bytes".into()),
        &QueryOptions {
            top: 5,
            max_paths: 3,
        },
    )
    .unwrap();
    assert_eq!(r.query.by, PathQueryBy::Type);
    assert_eq!(r.targets.len(), 5);
    for t in &r.targets {
        assert_eq!(t.type_name, "builtins.bytes");
        assert_eq!(t.paths.len(), 1);
        let site = root_path_string(&t.paths[0]);
        assert!(site.ends_with(".payload"), "{site}");
    }
}
