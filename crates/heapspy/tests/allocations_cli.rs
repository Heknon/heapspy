//! `heapspy record` and `--allocations` on the command line.

use std::path::Path;
use std::process::{Command, Output};

use heapspy_alloc::{EventKind, ProfileBuilder, PythonVersion};
use heapspy_analyzer::report::{AnalyzeReport, DiffReport, RetainingPathReport, TypeQueryReport};
use heapspy_snapshot::{RootKind, SnapshotBuilder};

fn heapspy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_heapspy"))
        .args(args)
        .output()
        .expect("run heapspy")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A snapshot of pid 4242 on CPython 3.12.0, captured at Unix second 2000.
fn write_snapshot(path: &Path) {
    let mut b = SnapshotBuilder::new();
    b.info_mut().source.reference = "4242".into();
    b.info_mut().captured_at = 2000;
    let m = b.ty("builtins", "module");
    let d = b.ty("builtins", "dict");
    let by = b.ty("builtins", "bytes");
    b.object(0x1000, m, 72).attr(0x2000, "__dict__");
    b.object(0x2000, d, 1000).dict_value(0x3000, "'CACHE'");
    b.object(0x3000, d, 200).dict_value(0x4000, "'k'");
    b.object(0x4000, by, 4096).untracked();
    b.root(0x1000, RootKind::ModuleDict, "sys.modules['app']");
    b.write_to(path).unwrap();
}

/// A profile recorded from `pid` on 3.12.`micro`, starting at second 1000.
fn write_profile(path: &Path, pid: u32, micro: u8) {
    let mut b = ProfileBuilder::new();
    b.info_mut().pid = pid;
    b.info_mut().python = PythonVersion::new(3, 12, micro);
    b.info_mut().start_ns = 1000 * 1_000_000_000;
    b.info_mut().end_ns = 1060 * 1_000_000_000;
    let f = b.code_with_lines(0x7f00_1000, "fill", "app.py", 3, &[(16, 4)]);
    b.sample(EventKind::LargeObject, 0x4000, 4096).frame(f, 2);
    b.write_to(path).unwrap();
}

fn notes(v: &[heapspy_analyzer::report::Note]) -> Vec<&str> {
    v.iter().map(|n| n.code.as_str()).collect()
}

/// A pid that is not CPython: a recorder probes fine (eBPF, or ptrace
/// when eBPF is not permitted), then finding the runtime fails before
/// anything attaches, and nothing is written.
#[cfg(target_os = "linux")]
#[test]
fn record_on_a_non_python_pid_fails() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("a.hpya");
    let out = heapspy(&[
        "record",
        "--pid",
        &std::process::id().to_string(),
        "--duration",
        "1s",
        "-o",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let e = stderr(&out);
    assert!(e.contains("cannot record pid"), "{e}");
    assert!(!out_path.exists());
}

/// `record --json ARGS` with `-o` in a fresh directory. Returns the exit
/// status, the parsed stdout (`Null` when empty) and whether the profile
/// exists afterwards.
fn record_json(args: &[&str]) -> (Option<i32>, serde_json::Value, bool) {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("a.hpya");
    let mut argv = vec!["record", "--json", "-o", out_path.to_str().unwrap()];
    argv.extend_from_slice(args);
    let out = heapspy(&argv);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc = if stdout.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"))
    };
    (out.status.code(), doc, out_path.exists())
}

fn error_code(doc: &serde_json::Value) -> &str {
    assert_eq!(doc["schema_version"], 1, "{doc}");
    assert_eq!(doc["kind"], "error", "{doc}");
    doc["error"]["code"].as_str().unwrap()
}

/// A child process that is not CPython, killed on drop.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
fn sleeper() -> Child {
    Child(Command::new("sleep").arg("60").spawn().expect("run sleep"))
}

/// `--json` on a pid that is not CPython reports `not_python` and writes
/// nothing: the recorders check the target before attaching.
#[cfg(target_os = "linux")]
#[test]
fn record_json_on_a_non_python_pid_is_not_python() {
    let child = sleeper();
    let pid = child.0.id().to_string();
    let (status, doc, written) = record_json(&["--pid", &pid, "--duration", "1s"]);
    assert_eq!(status, Some(1));
    assert_eq!(error_code(&doc), "not_python", "{doc}");
    let msg = doc["error"]["message"].as_str().unwrap();
    assert!(msg.contains("cannot record pid"), "{msg}");
    assert!(!written);
}

#[cfg(target_os = "linux")]
#[test]
fn record_json_missing_pid() {
    // Above the default pid_max (4194304), so no process has it.
    let (status, doc, written) = record_json(&["--pid", "999999999", "--duration", "1s"]);
    assert_eq!(status, Some(1));
    assert_eq!(error_code(&doc), "no_such_process");
    assert!(!written);
}

#[test]
fn record_json_option_errors() {
    let pid = std::process::id().to_string();
    let pid = pid.as_str();
    for args in [
        &["--pid", pid, "--duration", "0s"][..],
        &["--pid", pid, "--duration", "1s", "--max-frames", "0"],
        &["--pid", "0", "--duration", "1s"],
    ] {
        let (status, doc, written) = record_json(args);
        assert_eq!(status, Some(1), "{args:?}");
        assert_eq!(error_code(&doc), "invalid_argument", "{args:?}");
        assert!(!written);
    }
    // A mechanism of the other OS.
    let other = if cfg!(windows) { "ebpf" } else { "etw" };
    let (status, doc, _) = record_json(&["--pid", pid, "--duration", "1s", "--mechanism", other]);
    assert_eq!(status, Some(1));
    assert_eq!(error_code(&doc), "unsupported");
}

#[test]
fn record_json_usage_errors_exit_2_without_json() {
    for args in [
        &["--pid", "1"][..],
        &["--pid", "1", "--duration", "later"],
        &["--pid", "1", "--duration", "1s", "--events", "heap"],
        &["--duration", "1s"],
    ] {
        let (status, doc, written) = record_json(args);
        assert_eq!(status, Some(2), "{args:?}");
        assert_eq!(doc, serde_json::Value::Null, "{args:?}");
        assert!(!written);
    }
}

#[test]
fn record_argument_errors() {
    // Missing --duration and malformed values are usage errors.
    for args in [
        &["record", "--pid", "1", "-o", "a.hpya"][..],
        &[
            "record",
            "--pid",
            "1",
            "-o",
            "a.hpya",
            "--duration",
            "later",
        ],
        &[
            "record",
            "--pid",
            "1",
            "-o",
            "a.hpya",
            "--duration",
            "1s",
            "--events",
            "heap",
        ],
        &[
            "record",
            "--pid",
            "1",
            "-o",
            "a.hpya",
            "--duration",
            "1s",
            "--mechanism",
            "x",
        ],
    ] {
        assert_eq!(heapspy(args).status.code(), Some(2), "{args:?}");
    }
    // Out-of-range values are checked before anything is attached.
    let out = heapspy(&["record", "--pid", "1", "-o", "a.hpya", "--duration", "0s"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("duration must be greater than zero"));
    let out = heapspy(&[
        "record",
        "--pid",
        "1",
        "-o",
        "a.hpya",
        "--duration",
        "1s",
        "--max-frames",
        "0",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("max frames"));
}

#[test]
fn allocations_file_errors_are_clean() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("a.hpy");
    write_snapshot(&snap);
    let s = snap.to_str().unwrap();
    let bogus = dir.path().join("bogus.hpya");
    std::fs::write(&bogus, b"definitely not a profile").unwrap();
    let missing = dir.path().join("missing.hpya");
    // A snapshot is not an allocation profile.
    for (file, code) in [
        (missing.to_str().unwrap(), "io"),
        (bogus.to_str().unwrap(), "invalid_allocations"),
        (s, "invalid_allocations"),
    ] {
        for cmd in [
            vec!["analyze", s, "--json", "--allocations", file],
            vec![
                "query",
                s,
                "--type",
                "dict",
                "--json",
                "--allocations",
                file,
            ],
            vec!["diff", s, s, "--json", "--allocations", file],
        ] {
            let out = heapspy(&cmd);
            assert_eq!(out.status.code(), Some(1), "{cmd:?}");
            let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(v["kind"], "error");
            assert_eq!(v["error"]["code"], code, "{cmd:?}");
            let e = stderr(&out);
            assert!(e.contains("cannot open allocation profile"), "{e}");
            assert!(!e.contains("panicked"), "{e}");
        }
    }
    // Text mode: same failure, no JSON.
    let out = heapspy(&["analyze", s, "--allocations", bogus.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("bad magic"));
}

#[test]
fn matching_allocations_are_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("a.hpy");
    let prof = dir.path().join("a.hpya");
    write_snapshot(&snap);
    write_profile(&prof, 4242, 0);
    let (s, p) = (snap.to_str().unwrap(), prof.to_str().unwrap());

    let out = heapspy(&["analyze", s, "--json", "--allocations", p]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let r: AnalyzeReport = serde_json::from_slice(&out.stdout).unwrap();
    let codes = notes(&r.notes);
    assert_eq!(codes.last(), Some(&"allocations_sampled"));
    assert!(!codes.contains(&"allocations_not_joined"), "{codes:?}");
    assert!(!codes.contains(&"allocations_not_linked"), "{codes:?}");
    assert!(!codes.iter().any(|c| c.ends_with("_mismatch")));
    assert!(!stderr(&out).contains("warning"), "{}", stderr(&out));
    let a = r.allocations.as_ref().unwrap();
    assert_eq!(a.path, p);
    assert_eq!(a.samples, 1);
    assert_eq!(a.coverage.linked_objects, 1);
    assert_eq!(a.coverage.exact_linked_bytes, 4096);
    assert_eq!(a.top_stacks[0].frames[0].location, "app.py:4");
    let at = r.top_retainers[0].allocated_at.as_ref().unwrap();
    assert_eq!(at.linked_bytes, 4096);
    assert_eq!(at.stacks[0].top_stack_rank, Some(1));

    let out = heapspy(&["query", s, "--type", "bytes", "--json", "--allocations", p]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let r: TypeQueryReport = serde_json::from_slice(&out.stdout).unwrap();
    assert!(notes(&r.notes).contains(&"allocations_sampled"));
    let at = r.top_instances[0].allocated_at.as_ref().unwrap();
    assert_eq!(at.stacks[0].frames[0].function, "fill");
    assert_eq!(at.stacks[0].top_stack_rank, None);

    // Without --allocations the fields are null.
    let out = heapspy(&["analyze", s, "--json"]);
    let r: AnalyzeReport = serde_json::from_slice(&out.stdout).unwrap();
    assert!(r.allocations.is_none());
    assert!(r.top_retainers.iter().all(|t| t.allocated_at.is_none()));

    let out = heapspy(&[
        "query",
        s,
        "--retaining-path",
        "0x4000",
        "--json",
        "--allocations",
        p,
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let _: RetainingPathReport = serde_json::from_slice(&out.stdout).unwrap();
    assert!(stderr(&out).contains("not used by --retaining-path"));

    let out = heapspy(&["diff", s, s, "--json", "--allocations", p]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let _: DiffReport = serde_json::from_slice(&out.stdout).unwrap();
    assert!(stderr(&out).contains("not used by diff"));

    // Text output.
    let out = heapspy(&["analyze", s, "--allocations", p]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    println!("{text}");
    assert!(text.contains("Top retainers"));
    assert!(
        text.contains("Allocated by (sampled while recording)"),
        "{text}"
    );
    assert!(
        text.contains("only allocations made while recording"),
        "{text}"
    );
    assert!(
        text.contains("Arena and pool links are approximate"),
        "{text}"
    );
    assert!(
        text.contains("allocated at: 4.0 KiB (exact, stack #1) fill (app.py:4)"),
        "{text}"
    );
    assert!(
        text.contains("#1  4.0 KiB estimated, 4.0 KiB linked (exact)"),
        "{text}"
    );
    assert!(text.contains("      fill  app.py:4"), "{text}");
    // The caveat is in the section, not repeated as a note.
    assert!(!text.contains("note: Allocation stacks cover"), "{text}");

    let out = heapspy(&["query", s, "--type", "bytes", "--allocations", p]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    println!("{text}");
    assert!(
        text.contains("allocated at: 4.0 KiB (exact) fill (app.py:4)"),
        "{text}"
    );
    assert!(text.contains("note: Allocation stacks cover only allocations made while recording"));
}

#[test]
fn allocation_flame_graph() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("a.hpy");
    let prof = dir.path().join("a.hpya");
    write_snapshot(&snap);
    write_profile(&prof, 4242, 0);
    let (s, p) = (snap.to_str().unwrap(), prof.to_str().unwrap());

    let out = heapspy(&["flamegraph", "--allocations", p, "--folded"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "fill (app.py:4) 4096\n"
    );

    let svg_path = dir.path().join("alloc.svg");
    let out = heapspy(&[
        "flamegraph",
        "--allocations",
        p,
        "-o",
        svg_path.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let svg = std::fs::read_to_string(&svg_path).unwrap();
    assert!(svg.starts_with("<?xml"));
    assert!(svg.contains("heapspy allocation flame graph"));
    assert!(
        svg.contains("60.0 s, 1 samples (ebpf), 4.0 KiB estimated, approximate: no"),
        "{}",
        &svg[..2000.min(svg.len())]
    );
    assert!(svg.contains("fill (app.py:4)"));
    // Deterministic.
    let again = dir.path().join("again.svg");
    heapspy(&[
        "flamegraph",
        "--allocations",
        p,
        "-o",
        again.to_str().unwrap(),
    ]);
    assert_eq!(svg, std::fs::read_to_string(&again).unwrap());

    // Weighted by what is still alive in the snapshot.
    let out = heapspy(&[
        "flamegraph",
        "--allocations",
        p,
        "--retained",
        s,
        "--folded",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "fill (app.py:4) 4096\n"
    );
    let out = heapspy(&[
        "flamegraph",
        "--allocations",
        p,
        "--retained",
        s,
        "-o",
        svg_path.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let svg = std::fs::read_to_string(&svg_path).unwrap();
    assert!(svg.contains(&format!("4.0 KiB live in {s}")));

    // A profile from another process links nothing.
    let other = dir.path().join("other.hpya");
    write_profile(&other, 77, 0);
    let out = heapspy(&[
        "flamegraph",
        "--allocations",
        other.to_str().unwrap(),
        "--retained",
        s,
    ]);
    assert_eq!(out.status.code(), Some(1));
    let e = stderr(&out);
    assert!(
        e.contains("warning: The allocation profile was recorded from pid 77"),
        "{e}"
    );
    assert!(e.contains("no sampled allocation is linked"), "{e}");

    // Usage errors.
    for args in [
        &["flamegraph", s, "--allocations", p][..],
        &["flamegraph", "--allocations", p, "--diff", s, s],
        &["flamegraph", s, "--retained", s],
    ] {
        assert_eq!(heapspy(args).status.code(), Some(2), "{args:?}");
    }
    let out = heapspy(&["flamegraph", "--allocations", s]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("cannot open allocation profile"));
}

#[test]
fn mismatched_allocations_warn() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("a.hpy");
    let prof = dir.path().join("other.hpya");
    write_snapshot(&snap);
    write_profile(&prof, 77, 9);
    let (s, p) = (snap.to_str().unwrap(), prof.to_str().unwrap());

    let out = heapspy(&["analyze", s, "--json", "--allocations", p]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let e = stderr(&out);
    assert!(
        e.contains("warning: The allocation profile was recorded from pid 77"),
        "{e}"
    );
    assert!(e.contains("CPython 3.12.9"), "{e}");
    let r: AnalyzeReport = serde_json::from_slice(&out.stdout).unwrap();
    let codes = notes(&r.notes);
    assert!(codes.contains(&"allocations_pid_mismatch"), "{codes:?}");
    assert!(codes.contains(&"allocations_python_mismatch"), "{codes:?}");
    assert!(codes.contains(&"allocations_not_linked"), "{codes:?}");
    let a = r.allocations.as_ref().unwrap();
    assert_eq!(a.coverage.linked_objects, 0);
    assert_eq!(a.top_stacks.len(), 1);

    let out = heapspy(&["diff", s, s, "--json", "--allocations", p]);
    let r: DiffReport = serde_json::from_slice(&out.stdout).unwrap();
    assert!(notes(&r.notes).contains(&"allocations_pid_mismatch"));
}
