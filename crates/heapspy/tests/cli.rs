use std::path::Path;
use std::process::{Command, Output};

use heapspy_analyzer::report::{
    AnalyzeReport, DiffReport, LocateReport, RetainingPathReport, TypeQueryReport,
};
use heapspy_snapshot::{RootKind, SnapshotBuilder};

fn heapspy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_heapspy"))
        .args(args)
        .output()
        .expect("run heapspy")
}

/// `app` module with `CACHE = {<key>: bytes}` holding `n` 1 KiB blobs.
fn write_cache(path: &Path, n: u64) {
    let mut b = SnapshotBuilder::new();
    let m = b.ty("builtins", "module");
    let d = b.ty("builtins", "dict");
    let by = b.ty("builtins", "bytes");
    b.object(0x1000, m, 72).attr(0x2000, "__dict__");
    b.object(0x2000, d, 1000).dict_value(0x3000, "'CACHE'");
    let c = b.object(0x3000, d, 100 + 8 * n);
    for i in 0..n {
        c.redacted_dict_value(0x10_0000 + 0x100 * i, "str", 9);
    }
    for i in 0..n {
        b.object(0x10_0000 + 0x100 * i, by, 1024).untracked();
    }
    b.root(0x1000, RootKind::ModuleDict, "sys.modules['app']");
    b.write_to(path).unwrap();
}

fn write_snapshot(path: &Path) {
    write_cache(path, 3);
}

fn ok_stdout(args: &[&str]) -> String {
    let out = heapspy(args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn version_flag() {
    let out = heapspy(&["--version"]);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("heapspy "), "{s}");
}

#[test]
fn analyze_text_and_json() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.hpy");
    write_cache(&p, 40);
    let ps = p.to_str().unwrap();

    let text = ok_stdout(&["analyze", ps]);
    assert!(text.contains("Who holds it"), "{text}");
    // Holders read like code: sys.modules['app'].__dict__['CACHE'] is app.CACHE.
    assert!(text.contains("app.CACHE"), "{text}");
    assert!(text.contains("What the memory is"), "{text}");
    assert!(text.contains("dict · "), "{text}");

    let json = ok_stdout(&["analyze", ps, "--json", "--top=1"]);
    let r: AnalyzeReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r.snapshot.path, ps);
    assert_eq!(r.top_retainers.len(), 1);
    assert_eq!(r.type_histogram.len(), 1);
    let top = &r.top_retainers[0];
    assert_eq!(top.retained_bytes, 100 + 8 * 40 + 40 * 1024);
    assert_eq!(
        top.path[0].root_label.as_deref(),
        Some("sys.modules['app']")
    );
    assert_eq!(top.path[1].edge.as_deref(), Some(".__dict__"));
    assert_eq!(top.path[2].edge.as_deref(), Some("['CACHE']"));
}

#[test]
fn query_modes() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.hpy");
    write_cache(&p, 10);
    let ps = p.to_str().unwrap();

    let json = ok_stdout(&["query", ps, "--type=bytes", "--json", "--top=2"]);
    let r: TypeQueryReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r.instances, 10);
    assert_eq!(r.top_instances.len(), 2);
    // All ten payloads are kept by the cache, through one generalised path.
    let k = &r.kept_by[0];
    assert_eq!((k.kind.as_str(), k.instances), ("holder", 10));
    assert_eq!(
        k.holder.as_deref(),
        Some("sys.modules['app'].__dict__['CACHE']")
    );
    assert_eq!(k.through_pct, Some(100));
    assert_eq!(r.by_size.iter().map(|g| g.blocks).sum::<u64>(), 10);
    let text = ok_stdout(&["query", ps, "--type", "builtins.bytes"]);
    assert!(text.contains("Kept alive by"), "{text}");
    assert!(text.contains("app.CACHE"), "{text}");
    assert!(text.contains("Referenced by"), "{text}");

    let json = ok_stdout(&["query", ps, "--retaining-path=0x100000", "--json"]);
    let r: RetainingPathReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r.targets[0].paths.len(), 1);
    let text = ok_stdout(&["query", ps, "--retaining-path", "0x100000"]);
    assert!(text.contains("  ['CACHE']"), "{text}");
    assert!(text.contains("[<str len=9>]"), "{text}");

    let json = ok_stdout(&[
        "query",
        ps,
        "--retaining-path-type=builtins.bytes",
        "--top=3",
        "--max-paths=1",
        "--json",
    ]);
    let r: RetainingPathReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r.targets.len(), 3);
    assert!(r.targets.iter().all(|t| t.paths.len() == 1));
}

#[test]
fn query_locate() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.hpy");
    let mut b = SnapshotBuilder::new();
    let m = b.ty("builtins", "module");
    let d = b.ty("builtins", "dict");
    let f = b.ty("builtins", "function");
    let c = b.ty("builtins", "code");
    b.object(0x1000, m, 72)
        .attr(0x2000, "__dict__")
        .qualname("app");
    b.object(0x2000, d, 1000).dict_value(0x3000, "'run'");
    b.object(0x3000, f, 160)
        .attr(0x4000, "__code__")
        .attr(0x2000, "__globals__")
        .qualname("run");
    b.object(0x4000, c, 200)
        .qualname("run")
        .source_loc("app/__init__.py:7");
    b.root(0x1000, RootKind::ModuleDict, "sys.modules['app']");
    b.write_to(&p).unwrap();
    let ps = p.to_str().unwrap();

    let json = ok_stdout(&["query", ps, "--locate=app.run", "--json"]);
    let r: LocateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r.query, "app.run");
    let l = r.matches[0].source_loc.as_ref().unwrap();
    assert_eq!((l.file.as_str(), l.line), ("app/__init__.py", Some(7)));
    let text = ok_stdout(&["query", ps, "--locate", "app.run"]);
    assert!(text.contains("app/__init__.py:7"), "{text}");
}

#[test]
fn diff_text_and_json() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.hpy");
    let b = dir.path().join("b.hpy");
    write_cache(&a, 5);
    write_cache(&b, 50);
    let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());
    let json = ok_stdout(&["diff", a, b, "--json", "--top=1"]);
    let r: DiffReport = serde_json::from_str(&json).unwrap();
    assert!(r.identity_approximate);
    assert_eq!(r.by_site.len(), 1);
    assert_eq!(r.by_site[0].site, "sys.modules['app'].__dict__['CACHE']");
    assert_eq!(r.by_type[0].delta_count, 45);
    let text = ok_stdout(&["diff", a, b]);
    assert!(text.contains("Growth by retaining site"), "{text}");
    assert!(
        text.contains("sys.modules['app'].__dict__['CACHE']"),
        "{text}"
    );
}

#[test]
fn json_errors_are_error_reports() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.hpy");
    write_snapshot(&p);
    let ps = p.to_str().unwrap();
    for args in [
        vec!["query", ps, "--type", "no.such.Type", "--json"],
        vec!["query", ps, "--retaining-path", "0x1", "--json"],
        vec!["query", ps, "--retaining-path-type", "Nope", "--json"],
        vec!["query", ps, "--locate", "app.nothing", "--json"],
    ] {
        let out = heapspy(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["kind"], "error");
        assert_eq!(v["error"]["code"], "not_found", "{args:?}");
    }
}

#[test]
fn bad_inputs_have_specific_codes() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("bogus.hpy");
    std::fs::write(&bogus, b"not a snapshot at all").unwrap();
    let out = heapspy(&["analyze", bogus.to_str().unwrap(), "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "invalid_snapshot");

    let missing = dir.path().join("missing.hpy");
    let out = heapspy(&["analyze", missing.to_str().unwrap(), "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "io");

    let out = heapspy(&["query", "x.hpy", "--retaining-path", "1234", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "invalid_argument");
}

#[test]
fn dump_of_missing_core_fails_without_output() {
    let dir = tempfile::tempdir().unwrap();
    let core = dir.path().join("core.1");
    let out_path = dir.path().join("o.hpy");
    let out = heapspy(&[
        "dump",
        "--core",
        core.to_str().unwrap(),
        "-o",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("cannot open core"), "stderr: {stderr}");
    assert!(!out_path.exists());
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(heapspy(&["dump", "-o", "x"]).status.code(), Some(2));
    assert_eq!(heapspy(&["frobnicate"]).status.code(), Some(2));
}

#[test]
fn flamegraph_svg_and_folded() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.hpy");
    write_cache(&p, 40);
    let snap = p.to_str().unwrap();
    let svg_path = dir.path().join("a.svg");
    ok_stdout(&["flamegraph", snap, "-o", svg_path.to_str().unwrap()]);
    let svg = std::fs::read_to_string(&svg_path).unwrap();
    assert!(svg.starts_with("<?xml"), "{}", &svg[..100]);
    assert!(svg.contains("heapspy retention flame graph"));
    assert!(svg.contains("CPython 3.12.0"));
    assert!(svg.contains("CACHE"));
    assert!(svg.contains(" bytes, "));
    // Deterministic, colors included.
    let again = dir.path().join("b.svg");
    ok_stdout(&["flamegraph", snap, "-o", again.to_str().unwrap()]);
    assert_eq!(svg, std::fs::read_to_string(&again).unwrap());

    let titled = dir.path().join("t.svg");
    ok_stdout(&[
        "flamegraph",
        snap,
        "--title",
        "my service",
        "-o",
        titled.to_str().unwrap(),
    ]);
    assert!(std::fs::read_to_string(&titled)
        .unwrap()
        .contains("my service"));

    let folded = ok_stdout(&["flamegraph", snap, "--folded", "--min-bytes", "0"]);
    let total: u64 = folded
        .lines()
        .map(|l| l.rsplit(' ').next().unwrap().parse::<u64>().unwrap())
        .sum();
    assert_eq!(total, 72 + 1000 + 100 + 8 * 40 + 40 * 1024);
    assert!(folded
        .contains("sys.modules['app'];.__dict__ dict;['CACHE'] dict;[<str len=9>] bytes 40960\n"));
    let shallow = ok_stdout(&["flamegraph", snap, "--folded", "--max-depth", "1"]);
    assert_eq!(
        shallow,
        format!(
            "sys.modules['app'] 72\nsys.modules['app'];[other] {}\n",
            total - 72
        )
    );
}

#[test]
fn flamegraph_diff() {
    let dir = tempfile::tempdir().unwrap();
    let (b, a) = (dir.path().join("b.hpy"), dir.path().join("a.hpy"));
    write_cache(&b, 3);
    write_cache(&a, 30);
    let (b, a) = (b.to_str().unwrap(), a.to_str().unwrap());
    let folded = ok_stdout(&["flamegraph", "--diff", b, a, "--folded"]);
    assert!(
        folded.contains("['CACHE'] dict;[<str len=9>] bytes 3072 30720\n"),
        "{folded}"
    );
    let svg_path = dir.path().join("d.svg");
    ok_stdout(&[
        "flamegraph",
        "--diff",
        b,
        a,
        "-o",
        svg_path.to_str().unwrap(),
    ]);
    let svg = std::fs::read_to_string(&svg_path).unwrap();
    assert!(svg.contains("heapspy retention flame graph (diff)"));
    assert!(svg.contains("approximate"));
    assert!(svg.contains("Red grew, blue shrank"));
    assert!(svg.contains("Width is the after snapshot"));
}

#[test]
fn flamegraph_errors() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("x.svg");
    let out = heapspy(&[
        "flamegraph",
        "missing.hpy",
        "-o",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("cannot open snapshot missing.hpy"));
    assert!(!out_path.exists());
    assert_eq!(heapspy(&["flamegraph"]).status.code(), Some(2));
    assert_eq!(
        heapspy(&["flamegraph", "--diff", "a.hpy"]).status.code(),
        Some(2)
    );
    assert_eq!(
        heapspy(&["flamegraph", "s.hpy", "--min-pct", "x"])
            .status
            .code(),
        Some(2)
    );
}
