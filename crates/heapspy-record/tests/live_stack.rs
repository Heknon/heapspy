//! Read the Python stack of real CPython processes with the recorder
//! offsets and the reference readers, and resolve it to `file:line` with
//! the `.hpya` line-table decoder.
//!
//! Needs ptrace permission and specific interpreters, so it is ignored by
//! default, like `crates/heapspy/tests/cpython_live.rs`. Run it with:
//!
//! ```text
//! cargo test -p heapspy-record --test live_stack -- --ignored --test-threads 1
//! ```
//!
//! Interpreters: `/usr/bin/python3.12`, `/usr/local/bin/python3.13`, and
//! `$(uv python find 3.14)`; override with `HEAPSPY_PY312`, `HEAPSPY_PY313`,
//! `HEAPSPY_PY314`. Linux only.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use heapspy_alloc::{linetable, LineTableFormat};
use heapspy_reader::cpython::frames;
use heapspy_reader::source::linux_live::LiveProcess;
use heapspy_record::Target;

// Line numbers matter: the test expects inner:9, outer:12, <module>:14.
const VICTIM: &str = r#"import os, sys, time

def inner(ready):
    tmp = ready + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(os.getpid()))
    os.rename(tmp, ready)
    while True:
        time.sleep(1)

def outer(ready):
    inner(ready)

outer(sys.argv[1])
"#;

fn python(minor: u8) -> PathBuf {
    if let Ok(p) = std::env::var(format!("HEAPSPY_PY3{minor}")) {
        return p.into();
    }
    match minor {
        12 => "/usr/bin/python3.12".into(),
        13 => "/usr/local/bin/python3.13".into(),
        _ => {
            let out = Command::new("uv")
                .args(["python", "find", "3.14"])
                .stderr(Stdio::null())
                .output()
                .expect("run `uv python find 3.14` (or set HEAPSPY_PY314)");
            assert!(out.status.success(), "uv found no Python 3.14");
            String::from_utf8(out.stdout).unwrap().trim().into()
        }
    }
}

struct Victim(Child);

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(py: &Path, dir: &Path) -> Victim {
    let script = dir.join("victim.py");
    std::fs::write(&script, VICTIM).unwrap();
    let ready = dir.join("ready");
    let child = Command::new(py)
        .arg(&script)
        .arg(&ready)
        .stdout(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("start {}: {e}", py.display()));
    let t = Instant::now();
    while !ready.exists() {
        assert!(
            t.elapsed() < Duration::from_secs(60),
            "victim never got ready"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // Let it reach time.sleep.
    std::thread::sleep(Duration::from_millis(200));
    Victim(child)
}

fn check(minor: u8) {
    let dir = tempfile::tempdir().unwrap();
    let v = start(&python(minor), dir.path());
    let pid = v.0.id();
    let src = LiveProcess::attach(pid).expect("attach (needs ptrace permission)");
    let target = Target::locate(&src, pid).unwrap();
    assert_eq!(target.runtime.version.minor, minor);
    let fo = target.offsets;

    let threads = frames::thread_states(&src, &fo, target.runtime.runtime_addr).unwrap();
    let main = threads
        .iter()
        .find(|t| t.native_thread_id == pid as u64)
        .unwrap_or_else(|| panic!("3.{minor}: no thread state for tid {pid}: {threads:?}"));
    let stack = frames::read_stack(&src, &fo, main.addr, 64).unwrap();
    assert!(!stack.broken && !stack.truncated, "3.{minor}: {stack:?}");

    let format = LineTableFormat::for_python(target.runtime.version).unwrap();
    let got: Vec<(String, String, Option<u32>)> = stack
        .frames
        .iter()
        .map(|f| {
            let c = frames::read_code(&src, &fo, f.code).unwrap();
            let file = c.filename.unwrap_or_default();
            let file = file.rsplit('/').next().unwrap_or("").to_string();
            let line = linetable::line_for(
                format,
                c.linetable.as_deref().unwrap_or(&[]),
                c.firstlineno,
                f.instr_offset,
            );
            (c.qualname.unwrap_or_default(), file, line)
        })
        .collect();
    let want = [("inner", 9), ("outer", 12), ("<module>", 14)];
    assert_eq!(got.len(), want.len(), "3.{minor}: {got:?}");
    for ((q, file, line), (wq, wl)) in got.iter().zip(want) {
        assert_eq!(q, wq, "3.{minor}: {got:?}");
        assert_eq!(file, "victim.py");
        assert_eq!(*line, Some(wl), "3.{minor} {q}: {got:?}");
    }
}

#[test]
#[ignore = "needs ptrace and CPython 3.12"]
fn live_stack_312() {
    check(12);
}

#[test]
#[ignore = "needs ptrace and CPython 3.13"]
fn live_stack_313() {
    check(13);
}

#[test]
#[ignore = "needs ptrace and CPython 3.14"]
fn live_stack_314() {
    check(14);
}
