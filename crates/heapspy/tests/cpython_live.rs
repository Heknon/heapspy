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

use heapspy_analyzer::report::{AnalyzeReport, LocateReport, TypeQueryReport};
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

/// A victim for source locations. `Session` is defined at line
/// [`SESSION_LINE`] and `Registry` at [`REGISTRY_LINE`] (the text starts with
/// a newline, so line 1 is empty). The leak is one `Registry` holding two
/// lists of `Session`s; neither list holds 90% of it, so the `Registry`
/// instance itself is the top retainer.
const LOC_VICTIM: &str = r#"
import os, sys, time


class Session:
    kind = "web"

    def __init__(self, i):
        self.id = i
        self.payload = os.urandom(1024)

    @staticmethod
    def make(i):
        return Session(i)


class Registry:
    def __init__(self):
        self.a = [Session.make(i) for i in range(500)]
        self.b = [Session(i) for i in range(500)]


def handler():
    return 1


REG = Registry()
H = handler

tmp = sys.argv[1] + ".tmp"
with open(tmp, "w") as f:
    f.write(str(os.getpid()))
os.rename(tmp, sys.argv[1])
while True:
    time.sleep(1)
"#;
const SESSION_LINE: u32 = 5;
const SESSION_INIT_LINE: u32 = 8;
const REGISTRY_LINE: u32 = 17;
const HANDLER_LINE: u32 = 23;

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
    start_script(py, dir, VICTIM)
}

fn start_script(py: &Path, dir: &Path, text: &str) -> Victim {
    let script = dir.join("victim.py");
    std::fs::write(&script, text).unwrap();
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

fn json_of<T: serde::de::DeserializeOwned>(args: &[&str]) -> T {
    let o = heapspy(args);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap()
}

/// `type_location` of `__main__.Session` and of the top retainer, the
/// location of a function, and a module's `__file__` with contents capture.
fn run_locations(minor: u8) {
    let dir = tempfile::tempdir().unwrap();
    let v = start_script(&python(minor), dir.path(), LOC_VICTIM);
    let script = dir.path().join("victim.py");
    let script = script.to_str().unwrap();
    let out = dir.path().join("loc.hpy");
    let contents = dir.path().join("contents.hpy");
    dump(&["--pid", &v.pid.to_string()], &out);
    dump(
        &["--pid", &v.pid.to_string(), "--capture-contents"],
        &contents,
    );
    drop(v);
    let snap = out.to_str().unwrap();

    let q: TypeQueryReport = json_of(&["query", snap, "--type", "__main__.Session", "--json"]);
    assert_eq!(q.instances, SESSIONS as u64);
    let t = q.matched_type_locations[0].type_location.as_ref().unwrap();
    // Started with an absolute path, so co_filename is that path.
    assert_eq!(t.file, script);
    let line = t.line.unwrap();
    assert!(line >= SESSION_LINE, "{t:?}");
    assert_eq!(line, SESSION_INIT_LINE, "{t:?}");
    assert!(!t.exact);
    assert_eq!(t.via, "methods");

    let r: AnalyzeReport = json_of(&["analyze", snap, "--json", "--top", "100"]);
    let top = &r.top_retainers[0];
    assert_eq!(top.type_name, "__main__.Registry", "{top:#?}");
    let t = top.type_location.as_ref().expect("Registry location");
    assert_eq!(t.file, script);
    assert!(t.line.unwrap() >= REGISTRY_LINE, "{t:?}");
    assert_eq!(t.line, Some(REGISTRY_LINE + 1), "{t:?}");
    let row = r
        .type_histogram
        .iter()
        .find(|x| x.type_name == "__main__.Session")
        .expect("Session row");
    assert_eq!(row.type_location.as_ref().unwrap().file, script);

    let l: LocateReport = json_of(&["query", snap, "--locate", "__main__.handler", "--json"]);
    let f = l.matches[0].source_loc.as_ref().unwrap();
    assert_eq!((f.file.as_str(), f.line), (script, Some(HANDLER_LINE)));
    assert!(f.exact);
    let l: LocateReport = json_of(&["query", snap, "--locate", "__main__", "--json"]);
    assert_eq!(
        l.matches[0].source_loc_reason.as_deref(),
        Some("contents_not_captured")
    );
    let l: LocateReport = json_of(&[
        "query",
        contents.to_str().unwrap(),
        "--locate",
        "__main__",
        "--json",
    ]);
    let m = l.matches[0].source_loc.as_ref().expect("__file__");
    assert_eq!((m.file.as_str(), m.line), (script, None));
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

#[test]
#[ignore = "needs ptrace and /usr/bin/python3.12"]
fn python312_locations() {
    run_locations(12);
}

#[test]
#[ignore = "needs ptrace and /usr/local/bin/python3.13"]
fn python313_locations() {
    run_locations(13);
}

#[test]
#[ignore = "needs ptrace and uv's Python 3.14"]
fn python314_locations() {
    run_locations(14);
}

/// `analyze --pid`, `watch` and `dump --no-stop` against a live process.
fn run_live_commands(minor: u8) {
    let py = python(minor);
    let dir = tempfile::tempdir().unwrap();
    let v = start_victim(&py, dir.path());
    let pid = v.pid.to_string();

    let r: AnalyzeReport = json_of(&["analyze", "--pid", &pid, "--json"]);
    assert!(
        r.snapshot.path.starts_with(&format!("pid {pid}")),
        "{}",
        r.snapshot.path
    );
    let top = &r.top_retainers[0];
    assert!(
        crate_path(top).ends_with("['CACHE']"),
        "{}",
        crate_path(top)
    );
    assert!(top.native_retained_bytes.is_some());

    let keep = dir.path().join("kept.hpy");
    let out = heapspy(&["analyze", "--pid", &pid, "--keep", keep.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Who holds it"), "{text}");
    assert!(text.contains("Threads"), "{text}");
    assert!(keep.exists());

    let wdir = dir.path().join("w");
    let out = heapspy(&[
        "watch",
        "--pid",
        &pid,
        "--every",
        "500ms",
        "--rounds",
        "3",
        "--dir",
        wdir.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Growth over"), "{text}");
    assert!(wdir.join("first.hpy").exists() && wdir.join("last.hpy").exists());
    assert!(!wdir.join(".next.hpy").exists());

    let approx = dir.path().join("approx.hpy");
    let out = heapspy(&[
        "dump",
        "--pid",
        &pid,
        "--no-stop",
        "-o",
        approx.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    check_analyze(&approx);

    // Counters, without snapshots: one `sample` per line, then a summary.
    let out = heapspy(&[
        "watch",
        "--pid",
        &pid,
        "--counters",
        "--every",
        "100ms",
        "--rounds",
        "4",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 5, "{lines:?}");
    for (i, l) in lines[..4].iter().enumerate() {
        assert_eq!(l["kind"], "sample");
        assert_eq!(l["seq"], i as u64 + 1);
        assert_eq!(l["approximate"], true);
        assert!(l["os"]["rss_bytes"].as_u64().unwrap() > 0, "{l}");
        let a = &l["python"]["allocator"];
        // 1000 sessions of 1 KiB payloads are in bytes objects above
        // pymalloc's 512-byte limit, but each Session and its dict is small.
        assert!(a["blocks"].as_u64().unwrap() > 5000, "{l}");
        assert!(a["arena_bytes"].as_u64().unwrap() >= a["block_bytes"].as_u64().unwrap());
        let g = &l["python"]["gc"]["generations"];
        assert_eq!(g.as_array().unwrap().len(), 3, "{l}");
        assert!(g[0]["threshold"].as_i64().unwrap() > 0, "{l}");
        assert!(l["native"]["heap_bytes"].as_u64().unwrap() > 0, "{l}");
    }
    assert_eq!(lines[4]["kind"], "watch_counters_summary");
    assert_eq!(lines[4]["samples"], 4);
    assert!(lines[4]["python_bytes"]["last"].as_u64().unwrap() > 0);

    // Snapshots without stopping: rounds and summary say so.
    let wdir = dir.path().join("w2");
    let out = heapspy(&[
        "watch",
        "--pid",
        &pid,
        "--no-stop",
        "--every",
        "500ms",
        "--rounds",
        "2",
        "--dir",
        wdir.to_str().unwrap(),
        "--json",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["kind"], "watch_round");
    assert_eq!(lines[0]["approximate"], true);
    assert!(lines[0]["pause_ms"].is_null());
    assert_eq!(lines[2]["kind"], "watch_summary");
    assert_eq!(lines[2]["approximate"], true);

    let r: AnalyzeReport = json_of(&["analyze", "--pid", &pid, "--no-stop", "--json"]);
    assert!(
        r.snapshot.path.contains("not stopped"),
        "{}",
        r.snapshot.path
    );
    assert!(crate_path(&r.top_retainers[0]).ends_with("['CACHE']"));
}

/// `agent --dry-run --once`: one profile of each kind asked for, written
/// with its labels, from a --pid and from --discover.
fn run_agent(minor: u8) {
    let py = python(minor);
    let dir = tempfile::tempdir().unwrap();
    let v = start_victim(&py, dir.path());
    let pid = v.pid.to_string();
    let out = dir.path().join("profiles");
    let o = heapspy(&[
        "agent",
        "--dry-run",
        out.to_str().unwrap(),
        "--pid",
        &pid,
        "--memory",
        "--retained",
        "--tag",
        "env=test",
        "--once",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("sent 2 profiles"), "{stderr}");
    let mut names: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            format!("000001-{pid}-memory.json"),
            format!("000001-{pid}-memory.pprof"),
            format!("000002-{pid}-retained.json"),
            format!("000002-{pid}-retained.pprof"),
        ]
    );
    let labels = |n: &str| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(out.join(n)).unwrap()).unwrap()
    };
    let m = labels(&names[0]);
    assert_eq!(m["__name__"], "heapspy_memory");
    assert_eq!(m["service_name"], "victim");
    assert_eq!(m["pid"], pid.as_str());
    assert_eq!(m["env"], "test");
    let r = labels(&names[2]);
    assert_eq!(r["__name__"], "memory");
    assert_eq!(r["heapspy_snapshot"], "approximate");
    let has = |n: &str, what: &str| {
        let b = std::fs::read(out.join(n)).unwrap();
        b.windows(what.len()).any(|w| w == what.as_bytes())
    };
    assert!(has(&names[1], "inuse_space") && has(&names[1], "pymalloc free"));
    assert!(has(&names[3], "inuse_space") && has(&names[3], "['CACHE']"));

    // --discover finds it by its command line.
    let out2 = dir.path().join("discovered");
    let o = heapspy(&[
        "agent",
        "--dry-run",
        out2.to_str().unwrap(),
        "--discover",
        "victim.py",
        "--once",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(out2.join(format!("000001-{pid}-memory.pprof")).exists());

    // A pid that is not CPython is an error, not a silent no-op.
    let o = heapspy(&[
        "agent",
        "--dry-run",
        out2.to_str().unwrap(),
        "--pid",
        &std::process::id().to_string(),
        "--once",
    ]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("cannot watch pid"));
}

#[test]
#[ignore = "needs ptrace and /usr/bin/python3.12"]
fn python312_agent() {
    run_agent(12);
}

#[test]
#[ignore = "needs ptrace and uv's Python 3.14"]
fn python314_agent() {
    run_agent(14);
}

fn crate_path(r: &heapspy_analyzer::report::Retainer) -> String {
    heapspy_analyzer::root_path_string(&r.path)
}

#[test]
#[ignore = "needs ptrace and /usr/bin/python3.12"]
fn python312_live_commands() {
    run_live_commands(12);
}

#[test]
#[ignore = "needs ptrace and /usr/local/bin/python3.13"]
fn python313_live_commands() {
    run_live_commands(13);
}
