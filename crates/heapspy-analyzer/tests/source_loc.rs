//! Source locations in reports (`source_loc`, `type_location`) and
//! `query --locate`, on a synthetic snapshot laid out the way the walker
//! records functions, code objects, methods, classes and modules.

use heapspy_analyzer::report::{
    AnalyzeReport, LocateReport, RetainingPathReport, SourceLocation, TypeQueryReport,
};
use heapspy_analyzer::{
    analyze, locate, query_type, render, retaining_path, AnalyzeOptions, Error, PathTarget,
    QueryOptions,
};
use heapspy_snapshot::{ObjectFlags, RootKind, Snapshot, SnapshotBuilder};

const MODULE: u64 = 0x1000;
const MDICT: u64 = 0x1100;
const FILE_STR: u64 = 0x1200;
const HANDLER: u64 = 0x2000;
const HANDLER_CODE: u64 = 0x2001;
const BOUND: u64 = 0x2100;
const WRAPPER: u64 = 0x2200;
const SESSION: u64 = 0x5000;
const INIT: u64 = 0x5110;
const EMPTY: u64 = 0x6000;
const MIXED: u64 = 0x7000;
const INSTANCE: u64 = 0x8000;

fn loc(file: &str, line: Option<u32>, exact: bool, via: &str) -> Option<SourceLocation> {
    Some(SourceLocation {
        file: file.into(),
        line,
        exact,
        via: via.into(),
    })
}

/// `sys.modules['app.s']` with:
/// - `handler`, a function compiled at app/h.py:12;
/// - `BOUND`, a bound method of `Session.__init__`;
/// - `wrapped`, a `functools.wraps` wrapper with `__qualname__` "handler";
/// - class `Session` with `__init__` (line 20), `close` (line 14), a
///   staticmethod `make` (line 30) and `helper`, the module's `handler`
///   assigned as a class attribute (not part of the class);
/// - class `Empty` with only a data attribute;
/// - class `Mixed` with methods from two files;
/// - `S`, a `Session` instance holding two 10 000-byte bytes objects.
fn heap(contents: bool) -> Snapshot {
    let mut b = SnapshotBuilder::new();
    b.contents_captured(contents);
    let module = b.ty("builtins", "module");
    let dict = b.ty("builtins", "dict");
    let func = b.ty("builtins", "function");
    let code = b.ty("builtins", "code");
    let method = b.ty("builtins", "method");
    let smethod = b.ty("builtins", "staticmethod");
    let ty = b.ty("builtins", "type");
    let int = b.ty("builtins", "int");
    let bytes = b.ty("builtins", "bytes");
    let s = b.ty("builtins", "str");
    let session = b.ty_at(SESSION, "app.s", "Session");
    b.ty_at(EMPTY, "app.s", "Empty");
    b.ty_at(MIXED, "app.s", "Mixed");
    let is_type = ObjectFlags::GC_TRACKED | ObjectFlags::IS_TYPE;

    b.object(MODULE, module, 72)
        .attr(MDICT, "__dict__")
        .qualname("app.s");
    b.object(MDICT, dict, 2272)
        .dict_value(FILE_STR, "'__file__'")
        .dict_value(HANDLER, "'handler'")
        .dict_value(BOUND, "'BOUND'")
        .dict_value(WRAPPER, "'wrapped'")
        .dict_value(SESSION, "'Session'")
        .dict_value(EMPTY, "'Empty'")
        .dict_value(MIXED, "'Mixed'")
        .dict_value(INSTANCE, "'S'");
    let f = b.object(FILE_STR, s, 57).untracked().length(8);
    if contents {
        f.content("app/s.py", false);
    }

    let function = |b: &mut SnapshotBuilder, addr: u64, q: &str, cq: &str, at: &str| {
        b.object(addr, func, 160)
            .attr(addr + 1, "__code__")
            .attr(MDICT, "__globals__")
            .qualname(q)
            .source_loc(at);
        b.object(addr + 1, code, 200).qualname(cq).source_loc(at);
    };
    function(&mut b, HANDLER, "handler", "handler", "app/h.py:12");
    // A wrapper keeps the wrapped function's __qualname__, not its code.
    function(
        &mut b,
        WRAPPER,
        "handler",
        "deco.<locals>.wrapper",
        "app/deco.py:3",
    );
    b.object(BOUND, method, 48).attr(INIT, "__func__");

    b.object(SESSION, ty, 1704)
        .flags(is_type)
        .attr(0x5100, "__dict__")
        .qualname("Session");
    b.object(0x5100, dict, 648)
        .dict_value(INIT, "'__init__'")
        .dict_value(0x5120, "'close'")
        .dict_value(0x5130, "'make'")
        .dict_value(HANDLER, "'helper'");
    function(
        &mut b,
        INIT,
        "Session.__init__",
        "Session.__init__",
        "app/s.py:20",
    );
    function(
        &mut b,
        0x5120,
        "Session.close",
        "Session.close",
        "app/s.py:14",
    );
    b.object(0x5130, smethod, 40).attr(0x5140, "__func__");
    function(
        &mut b,
        0x5140,
        "Session.make",
        "Session.make",
        "app/s.py:30",
    );

    b.object(EMPTY, ty, 1704)
        .flags(is_type)
        .attr(0x6100, "__dict__")
        .qualname("Empty");
    b.object(0x6100, dict, 648).dict_value(0x6110, "'x'");
    b.object(0x6110, int, 28).untracked();

    b.object(MIXED, ty, 1704)
        .flags(is_type)
        .attr(0x7100, "__dict__")
        .qualname("Mixed");
    b.object(0x7100, dict, 648)
        .dict_value(0x7110, "'a'")
        .dict_value(0x7120, "'b'");
    function(&mut b, 0x7110, "Mixed.a", "Mixed.a", "a.py:1");
    function(&mut b, 0x7120, "Mixed.b", "Mixed.b", "b.py:2");

    b.object(INSTANCE, session, 56)
        .attr(0x8100, "a")
        .attr(0x8200, "b");
    b.object(0x8100, bytes, 10_000).untracked();
    b.object(0x8200, bytes, 10_000).untracked();

    b.root(MODULE, RootKind::ModuleDict, "sys.modules['app.s']");
    b.build().unwrap()
}

fn path_to(s: &Snapshot, addr: u64) -> RetainingPathReport {
    let r = retaining_path(
        s,
        "t.hpy",
        &PathTarget::Address(addr),
        &QueryOptions::default(),
    )
    .unwrap();
    let back: RetainingPathReport =
        serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
    r
}

#[test]
fn function_through_its_code_object() {
    let s = heap(false);
    let r = path_to(&s, HANDLER);
    let p = &r.targets[0].paths[0];
    let last = p.last().unwrap();
    assert_eq!(last.edge.as_deref(), Some("['handler']"));
    assert_eq!(last.source_loc, loc("app/h.py", Some(12), true, "function"));
    assert_eq!(last.source_loc_reason, None);
    // The module dict is not a function: no location and no reason.
    assert_eq!(p[1].source_loc, None);
    assert_eq!(p[1].source_loc_reason, None);
    // The module is, but its __file__ text needs contents capture.
    assert_eq!(p[0].source_loc, None);
    assert_eq!(
        p[0].source_loc_reason.as_deref(),
        Some("contents_not_captured")
    );

    let c = path_to(&s, HANDLER_CODE);
    let last = c.targets[0].paths[0].last().unwrap();
    assert_eq!(last.edge.as_deref(), Some(".__code__"));
    assert_eq!(
        last.source_loc,
        loc("app/h.py", Some(12), true, "code_object")
    );
}

#[test]
fn method_through_func() {
    let s = heap(false);
    let r = path_to(&s, BOUND);
    let last = r.targets[0].paths[0].last().unwrap();
    assert_eq!(last.type_name, "builtins.method");
    assert_eq!(last.source_loc, loc("app/s.py", Some(20), true, "method"));
}

#[test]
fn class_from_its_methods() {
    let s = heap(false);
    let r = path_to(&s, SESSION);
    let last = r.targets[0].paths[0].last().unwrap();
    // close (14), __init__ (20) and the staticmethod make (30) count; the
    // module-level handler stored as Session.helper (app/h.py) does not.
    assert_eq!(last.source_loc, loc("app/s.py", Some(14), false, "methods"));
    // The type of a class is `type`, a C type that is not in the snapshot.
    assert_eq!(r.targets[0].type_location, None);
    assert_eq!(
        r.targets[0].type_location_reason.as_deref(),
        Some("type_not_in_snapshot")
    );

    let e = path_to(&s, EMPTY);
    let last = e.targets[0].paths[0].last().unwrap();
    assert_eq!(last.source_loc, None);
    assert_eq!(last.source_loc_reason.as_deref(), Some("no_python_methods"));

    let m = path_to(&s, MIXED);
    let last = m.targets[0].paths[0].last().unwrap();
    assert_eq!(last.source_loc, None);
    assert_eq!(last.source_loc_reason.as_deref(), Some("methods_disagree"));
}

#[test]
fn instance_type_location_in_analyze() {
    let s = heap(false);
    let r = analyze(&s, "t.hpy", &AnalyzeOptions::default()).unwrap();
    let back: AnalyzeReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);

    let top = &r.top_retainers[0];
    assert_eq!(top.address.0, INSTANCE);
    assert_eq!(top.type_name, "app.s.Session");
    assert_eq!(
        top.type_location,
        loc("app/s.py", Some(14), false, "methods")
    );
    assert_eq!(top.type_location_reason, None);

    let row = |name: &str| {
        r.type_histogram
            .iter()
            .find(|t| t.type_name == name)
            .unwrap_or_else(|| panic!("{name} in histogram"))
    };
    assert_eq!(row("app.s.Session").type_location, top.type_location);
    let bytes = row("builtins.bytes");
    assert_eq!(bytes.type_location, None);
    assert_eq!(
        bytes.type_location_reason.as_deref(),
        Some("type_not_in_snapshot")
    );
}

#[test]
fn type_query_locations_and_text() {
    let s = heap(false);
    let r = query_type(&s, "t.hpy", "Session", &QueryOptions::default()).unwrap();
    let back: TypeQueryReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
    assert_eq!(r.matched_types, ["app.s.Session"]);
    assert_eq!(r.matched_type_locations.len(), 1);
    let t = &r.matched_type_locations[0];
    assert_eq!(t.type_name, "app.s.Session");
    assert_eq!(t.type_location, loc("app/s.py", Some(14), false, "methods"));
    // An instance of a class has no location of its own.
    assert_eq!(r.top_instances[0].source_loc, None);
    assert_eq!(r.top_instances[0].source_loc_reason, None);

    // Instances that are functions do.
    let f = query_type(&s, "t.hpy", "builtins.function", &QueryOptions::default()).unwrap();
    let h = f
        .top_instances
        .iter()
        .find(|i| i.address.0 == HANDLER)
        .unwrap();
    assert_eq!(h.source_loc, loc("app/h.py", Some(12), true, "function"));
}

#[test]
fn module_file_needs_contents() {
    let s = heap(true);
    let p = path_to(&s, HANDLER);
    let root = &p.targets[0].paths[0][0];
    assert_eq!(root.source_loc, loc("app/s.py", None, true, "module_file"));
}

#[test]
fn locate_types_functions_and_modules() {
    let s = heap(false);
    let o = QueryOptions::default();
    let one = |name: &str| -> LocateReport {
        let r = locate(&s, "t.hpy", name, &o).unwrap();
        let back: LocateReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        r
    };

    let r = one("app.s.Session");
    assert_eq!(r.matches.len(), 1);
    let m = &r.matches[0];
    assert_eq!((m.kind.as_str(), m.module.as_str()), ("type", "app.s"));
    assert_eq!(m.qualname, "Session");
    assert_eq!(m.address.0, SESSION);
    assert_eq!(m.source_loc, loc("app/s.py", Some(14), false, "methods"));

    let r = one("app.s.Session.__init__");
    assert_eq!(r.matches.len(), 1);
    assert_eq!(r.matches[0].kind, "function");
    assert_eq!(r.matches[0].address.0, INIT);
    assert_eq!(
        r.matches[0].source_loc,
        loc("app/s.py", Some(20), true, "function")
    );

    // The wrapper shares the name but not the code: only the real one.
    let r = one("app.s.handler");
    assert_eq!(r.matches.len(), 1, "{:?}", r.matches);
    assert_eq!(r.matches[0].address.0, HANDLER);

    let r = one("app.s");
    assert_eq!(r.matches[0].kind, "module");
    assert_eq!(r.matches[0].qualname, "");
    assert_eq!(
        r.matches[0].source_loc_reason.as_deref(),
        Some("contents_not_captured")
    );
    let with = locate(&heap(true), "t.hpy", "app.s", &o).unwrap();
    assert_eq!(
        with.matches[0].source_loc,
        loc("app/s.py", None, true, "module_file")
    );

    assert!(matches!(
        locate(&s, "t.hpy", "app.s.nothing", &o),
        Err(Error::NotFound(_))
    ));
    // Only full names: an unqualified one does not match.
    assert!(matches!(
        locate(&s, "t.hpy", "Session", &o),
        Err(Error::NotFound(_))
    ));

    let text = render::locate(&one("app.s.Session.__init__")).unwrap();
    assert!(
        text.contains("function") && text.contains("app/s.py:20"),
        "{text}"
    );
}

#[test]
fn reports_without_location_fields_still_parse() {
    // A document from a heapspy without these fields (schema v1 consumers
    // read both).
    let s = heap(false);
    let r = analyze(&s, "t.hpy", &AnalyzeOptions::default()).unwrap();
    let mut v = serde_json::to_value(&r).unwrap();
    for t in v["top_retainers"].as_array_mut().unwrap() {
        let t = t.as_object_mut().unwrap();
        t.remove("type_location");
        t.remove("type_location_reason");
        for h in t["path"].as_array_mut().unwrap() {
            let h = h.as_object_mut().unwrap();
            h.remove("source_loc");
            h.remove("source_loc_reason");
        }
    }
    let old: AnalyzeReport = serde_json::from_value(v).unwrap();
    assert_eq!(old.top_retainers[0].type_location, None);
    assert_eq!(old.top_retainers[0].path[0].source_loc, None);
}
