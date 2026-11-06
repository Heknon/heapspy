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

/// The same stack through a class instantiation. The call site runs often
/// enough to be specialized (`CALL_ALLOC_AND_ENTER_INIT` on 3.13 and
/// 3.14), so `__init__` runs above CPython's `_Py_InitCleanup` shim frame,
/// which `read_stack` must skip. Line numbers: inner:9, Box.__init__:14,
/// outer:18, <module>:20.
const CLASS_VICTIM: &str = r#"import os, sys, time

def inner(ready):
    tmp = ready + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(os.getpid()))
    os.rename(tmp, ready)
    while True:
        time.sleep(1)

class Box:
    def __init__(self, ready, n):
        if n == 0:
            inner(ready)

def outer(ready):
    for n in range(50, -1, -1):
        Box(ready, n)

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

fn start(py: &Path, dir: &Path, victim: &str) -> Victim {
    let script = dir.join("victim.py");
    std::fs::write(&script, victim).unwrap();
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

/// Shim code objects on the raw frame chain of `tstate`, walked without
/// any filtering: the frames `read_stack` has to skip.
fn raw_shims(
    src: &dyn heapspy_reader::MemorySource,
    fo: &frames::FrameOffsets,
    tstate: u64,
) -> usize {
    use heapspy_reader::MemorySourceExt;
    let mut f = frames::current_frame(src, fo, tstate).unwrap();
    let mut n = 0;
    for _ in 0..256 {
        if f == 0 {
            break;
        }
        let owner = src.read_u8(f + fo.if_owner).unwrap();
        if owner < fo.owner_first_shim {
            let raw = src.read_ptr(f + fo.if_executable).unwrap();
            let code = if fo.executable_is_stackref {
                raw & !3
            } else {
                raw
            };
            if code != 0 && frames::is_shim_code(src, fo, code) {
                n += 1;
            }
        }
        f = src.read_ptr(f + fo.if_previous).unwrap();
    }
    n
}

fn check(minor: u8) {
    check_victim(
        minor,
        VICTIM,
        &[("inner", 9), ("outer", 12), ("<module>", 14)],
    );
}

fn check_class(minor: u8) {
    check_victim(
        minor,
        CLASS_VICTIM,
        &[
            ("inner", 9),
            ("Box.__init__", 14),
            ("outer", 18),
            ("<module>", 20),
        ],
    );
}

fn check_victim(minor: u8, victim: &str, want: &[(&str, u32)]) {
    let dir = tempfile::tempdir().unwrap();
    let v = start(&python(minor), dir.path(), victim);
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
    // The class victim runs under the init shim on 3.13+ (3.12 has none);
    // a stack without it is then the filter's doing.
    let shims = raw_shims(&src, &fo, main.addr);
    let class = victim == CLASS_VICTIM;
    assert_eq!(
        shims,
        usize::from(class && minor >= 13),
        "3.{minor}: shim frames on the raw chain"
    );

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
    assert_eq!(got.len(), want.len(), "3.{minor}: {got:?}");
    for ((q, file, line), &(wq, wl)) in got.iter().zip(want) {
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

#[test]
#[ignore = "needs ptrace and CPython 3.12"]
fn live_stack_class_312() {
    check_class(12);
}

#[test]
#[ignore = "needs ptrace and CPython 3.13"]
fn live_stack_class_313() {
    check_class(13);
}

#[test]
#[ignore = "needs ptrace and CPython 3.14"]
fn live_stack_class_314() {
    check_class(14);
}
