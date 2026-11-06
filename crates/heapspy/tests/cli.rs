use std::path::Path;
use std::process::{Command, Output};

use heapspy_snapshot::{RootKind, SnapshotBuilder};

fn heapspy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_heapspy"))
        .args(args)
        .output()
        .expect("run heapspy")
}

fn write_snapshot(path: &Path) {
    let mut b = SnapshotBuilder::new();
    let m = b.ty("builtins", "module");
    b.object(0x1000, m, 72);
    b.root(0x1000, RootKind::ModuleDict, "sys.modules['app']");
    b.write_to(path).unwrap();
}

#[test]
fn version_flag() {
    let out = heapspy(&["--version"]);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("heapspy "), "{s}");
}

#[test]
fn analyze_is_unimplemented_and_fails() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.hpy");
    write_snapshot(&p);
    let out = heapspy(&["analyze", p.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("not implemented yet"), "{err}");
}

#[test]
fn json_errors_are_error_reports() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.hpy");
    write_snapshot(&p);
    let ps = p.to_str().unwrap();
    for args in [
        vec!["analyze", ps, "--json"],
        vec!["query", ps, "--type", "builtins.dict", "--json"],
        vec!["query", ps, "--retaining-path", "0x1000", "--json"],
        vec!["diff", ps, ps, "--json"],
    ] {
        let out = heapspy(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["kind"], "error");
        assert_eq!(v["error"]["code"], "unimplemented", "{args:?}");
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
