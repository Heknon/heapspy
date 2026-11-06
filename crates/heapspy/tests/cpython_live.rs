//! End-to-end dumps of real CPython processes.
//!
//! These need ptrace permission, `gcore` (from gdb) and specific interpreters,
//! so they are ignored by default. Run them with:
//!
//! ```text
//! cargo test -p heapspy --test cpython_live -- --ignored --test-threads 1
//! ```
//!
//! Interpreters: `/usr/bin/python3.12`, `/usr/local/bin/python3.13`, and
//! `$(uv python find 3.14)`. Override any of them with `HEAPSPY_PY312`,
//! `HEAPSPY_PY313`, `HEAPSPY_PY314`. A missing interpreter fails the test (the
//! point of running ignored tests is to exercise them).
//!
//! The victim builds `CACHE = {}` holding 1000 `Session` instances, each with a
//! 1 KiB `payload`, writes a ready file and sleeps.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use heapspy_analyzer::report::AnalyzeReport;
use heapspy_snapshot::{EdgeLabel, KeyLabel, RootKind, Snapshot};

const VICTIM: &str = r#"
import os, sys, time

class Session:
    def __init__(self, i):
        self.id = i
        self.payload = os.urandom(1024)

CACHE = {}
for i in range(1000):
    CACHE[f"session-{i}"] = Session(i)

def main():
    tmp = sys.argv[1] + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(os.getpid()))
    os.rename(tmp, sys.argv[1])
    while True:
        time.sleep(1)

main()
"#;

const SESSIONS: usize = 1000;
const PAYLOAD: u64 = 1024;

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

/// A victim process, killed on drop.
struct Victim {
    child: Child,
    pid: u32,
}

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_victim(py: &Path, dir: &Path) -> Victim {
    let script = dir.join("victim.py");
    std::fs::write(&script, VICTIM).unwrap();
    let ready = dir.join("ready");
    let child = Command::new(py)
        .arg(&script)
        .arg(&ready)
        .stdout(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("start {}: {e}", py.display()));
    let start = Instant::now();
    while !ready.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "victim never got ready"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let pid = child.id();
    Victim { child, pid }
}

fn heapspy(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_heapspy"))
        .args(args)
        .output()
        .expect("run heapspy")
}

/// `heapspy dump` with `source` args; checks the summary line and returns the path.
fn dump(source: &[&str], out: &Path) {
    let mut args = vec!["dump"];
    args.extend_from_slice(source);
    args.extend_from_slice(&["-o", out.to_str().unwrap()]);
    let o = heapspy(&args);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "dump failed: {stderr}");
    let line = stderr.lines().last().unwrap_or_default();
    let prefix = format!("wrote {}: ", out.display());
    let rest = line
        .strip_prefix(&prefix)
        .unwrap_or_else(|| panic!("unexpected summary line: {line}"));
    let parts: Vec<&str> = rest.split(", ").collect();
    assert_eq!(parts.len(), 4, "{line}");
    for (p, unit) in parts.iter().zip(["objects", "edges", "roots", "bytes"]) {
        let (n, u) = p.split_once(' ').unwrap();
        assert!(n.parse::<u64>().is_ok() && u == unit, "{line}");
    }
}

fn check_snapshot(path: &Path, minor: u8) {
    let s = Snapshot::open(path).unwrap();
    assert_eq!(s.info().python.minor, minor);
    assert!(!s.info().truncated, "walk was truncated");

    // Root sys.modules['__main__'] -> .__dict__ -> ['CACHE'] -> dict.
    let main = s
        .roots()
        .find(|r| {
            r.kind == RootKind::ModuleDict
                && s.string(r.label).unwrap() == "sys.modules['__main__']"
        })
        .expect("root sys.modules['__main__']");
    let mi = s.find_object(main.addr).expect("module object");
    let attr = |i: u32, name: &str| {
        s.edges(i).find_map(|e| match e.label {
            EdgeLabel::Attr(a) if s.string(a).unwrap() == name => Some(e.target),
            _ => None,
        })
    };
    let mdict = attr(mi, "__dict__").expect("module .__dict__");
    let di = s.find_object(mdict).expect("module dict object");
    let cache = s
        .edges(di)
        .find_map(|e| match e.label {
            EdgeLabel::DictValue(KeyLabel::Repr(k)) if s.string(k).unwrap() == "'CACHE'" => {
                Some(e.target)
            }
            _ => None,
        })
        .expect("['CACHE']");
    let ci = s.find_object(cache).expect("CACHE object");
    assert_eq!(s.type_name(s.object(ci).type_id).unwrap(), "builtins.dict");

    // 1000 Sessions, each reaching >= 1 KiB of bytes through .payload.
    let sessions: Vec<_> = s
        .objects()
        .filter(|o| s.type_name(o.type_id).unwrap() == "__main__.Session")
        .collect();
    assert_eq!(sessions.len(), SESSIONS);
    for o in &sessions {
        let p = attr(o.index, "payload").expect(".payload edge");
        let po = s.object(s.find_object(p).expect("payload object"));
        assert_eq!(s.type_name(po.type_id).unwrap(), "builtins.bytes");
        assert!(po.shallow_size >= PAYLOAD, "{}", po.shallow_size);
    }
}

fn check_analyze(path: &Path) {
    let o = heapspy(&["analyze", "--json", path.to_str().unwrap()]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let r: AnalyzeReport = serde_json::from_slice(&o.stdout).unwrap();
    let top = &r.top_retainers[0];
    let last = top.path.last().unwrap();
    assert_eq!(last.edge.as_deref(), Some("['CACHE']"), "{top:#?}");
    assert_eq!(top.type_name, "builtins.dict");
    assert!(
        top.retained_bytes >= SESSIONS as u64 * PAYLOAD,
        "{}",
        top.retained_bytes
    );
}

fn run_pid(minor: u8) {
    let dir = tempfile::tempdir().unwrap();
    let v = start_victim(&python(minor), dir.path());
    let out = dir.path().join("pid.hpy");
    dump(&["--pid", &v.pid.to_string()], &out);
    drop(v);
    check_snapshot(&out, minor);
    check_analyze(&out);
}

fn run_core(minor: u8) {
    let dir = tempfile::tempdir().unwrap();
    let v = start_victim(&python(minor), dir.path());
    let prefix = dir.path().join("core");
    let g = Command::new("gcore")
        .arg("-o")
        .arg(&prefix)
        .arg(v.pid.to_string())
        .output()
        .expect("run gcore");
    assert!(g.status.success(), "{}", String::from_utf8_lossy(&g.stderr));
    drop(v);
    let core = PathBuf::from(format!("{}.{}", prefix.display(), g_pid(&g, &prefix)));
    let out = dir.path().join("core.hpy");
    dump(&["--core", core.to_str().unwrap()], &out);
    check_snapshot(&out, minor);
    check_analyze(&out);
}

/// gcore names the file `<prefix>.<pid>`; find it.
fn g_pid(_g: &std::process::Output, prefix: &Path) -> String {
    let dir = prefix.parent().unwrap();
    let stem = prefix.file_name().unwrap().to_str().unwrap();
    for e in std::fs::read_dir(dir).unwrap() {
        let n = e.unwrap().file_name().into_string().unwrap();
        if let Some(pid) = n.strip_prefix(&format!("{stem}.")) {
            return pid.to_string();
        }
    }
    panic!("gcore wrote no core file");
}

#[test]
#[ignore = "needs ptrace and /usr/bin/python3.12"]
fn python312_pid() {
    run_pid(12);
}

#[test]
#[ignore = "needs ptrace, gcore and /usr/bin/python3.12"]
fn python312_core() {
    run_core(12);
}

#[test]
#[ignore = "needs ptrace and /usr/local/bin/python3.13"]
fn python313_pid() {
    run_pid(13);
}

#[test]
#[ignore = "needs ptrace, gcore and /usr/local/bin/python3.13"]
fn python313_core() {
    run_core(13);
}

#[test]
#[ignore = "needs ptrace and uv's Python 3.14"]
fn python314_pid() {
    run_pid(14);
}

#[test]
#[ignore = "needs ptrace, gcore and uv's Python 3.14"]
fn python314_core() {
    run_core(14);
}
