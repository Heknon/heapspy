use std::path::Path;
use std::process::{Command, Output};

use heapspy_analyzer::report::{AnalyzeReport, DiffReport, RetainingPathReport, TypeQueryReport};
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
    assert!(text.contains("Top retainers by retained size"), "{text}");
    assert!(
        text.contains("builtins.dict  sys.modules['app'].__dict__['CACHE']"),
        "{text}"
    );

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
    let text = ok_stdout(&["query", ps, "--type", "builtins.bytes"]);
    assert!(text.contains("Held by"), "{text}");

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
fn dump_is_unimplemented_and_fails() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("o.hpy");
    let out = heapspy(&["dump", "--core", "core.1", "-o", out_path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("not implemented yet"));
    assert!(!out_path.exists());
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(heapspy(&["dump", "-o", "x"]).status.code(), Some(2));
    assert_eq!(heapspy(&["frobnicate"]).status.code(), Some(2));
}
