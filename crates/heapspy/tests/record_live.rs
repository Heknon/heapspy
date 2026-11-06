//! `heapspy record` against real CPython processes, through eBPF and
//! through ptrace, then `--then-dump` and `analyze --allocations`.
//!
//! Needs root (or CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE) and specific
//! interpreters, so it is ignored by default. Run it with:
//!
//! ```text
//! cargo test -p heapspy --test record_live -- --ignored --test-threads 1
//! ```
//!
//! Interpreters as in `cpython_live.rs`: `/usr/bin/python3.12`,
//! `/usr/local/bin/python3.13`, `$(uv python find 3.14)`, or
//! `HEAPSPY_PY312` / `HEAPSPY_PY313` / `HEAPSPY_PY314`. Linux only.
//!
//! The victim's known chain is `handler() -> build_payload() -> bytes(64
//! KiB)` in a loop, kept in a rotating list of 200 (the "leak"), and
//! `build_payload` also leaks a small list per call, which grows pymalloc
//! arenas from inside it. The noise, `noise() -> bytes(16 KiB)`, is a
//! different chain; it makes no small objects, so it does not compete for
//! arena growth. `bytes` rather than `bytearray` for the payload: a
//! bytearray's buffer is a separate allocation from the object, and the
//! snapshot does not record buffer pointers, so the join can link a
//! bytes object (one allocation) exactly but not a bytearray.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use heapspy_analyzer::report::{AnalyzeReport, StackFrame};

// Line numbers matter: see the constants below.
const VICTIM: &str = r#"import os, sys, time
keep = []
leaked = []
def build_payload(i):
    leaked.append([i] * 16)
    return bytes(64 * 1024)
def handler(i):
    keep.append(build_payload(i))
    if len(keep) > 200:
        del keep[0]
def noise():
    return bytes(16 * 1024)
def main(ready):
    tmp = ready + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(os.getpid()))
    os.rename(tmp, ready)
    i = 0
    while True:
        handler(i)
        noise()
        i += 1
main(sys.argv[1])
"#;
/// `leaked.append(...)`: arenas are carved here.
const ARENA_LINE: u32 = 5;
/// `bytes(64 * 1024)`: the large objects.
const PAYLOAD_LINE: u32 = 6;

/// A leak whose payload is allocated on memory that churn just freed.
/// `render_page` allocates and drops 20 KB buffers; each `Session` keeps
/// an 8 KB blob, which glibc often places where a freed buffer was. Most
/// blobs are not sampled, so the latest sample over a blob's address is
/// often a `render_page` buffer, which the join must not link to it.
/// `Session(uid)` runs often enough to be specialized, so on 3.13 and 3.14
/// `__init__` runs above CPython's `_Py_InitCleanup` shim frame, which
/// recorded stacks must not show.
const REUSE_VICTIM: &str = r#"import os, sys, time

class Session:
    def __init__(self, uid):
        self.uid = uid
        self.blob = os.urandom(8192)          # line 6: the leak's payload

SESSIONS = {}

def login(uid):
    SESSIONS[uid] = Session(uid)              # line 11: never evicted

def render_page(n):
    return b"x" * 20000                        # line 14: churn, freed right away

def main():
    open(sys.argv[1], "w").write(str(os.getpid()))
    i = 0
    while True:
        login(i); i += 1
        for _ in range(3):
            render_page(i)
        time.sleep(0.0005)

main()
"#;
/// `os.urandom(8192)` in `Session.__init__`.
const BLOB_LINE: u32 = 6;
/// `Session(uid)` in `login`.
const LOGIN_LINE: u32 = 11;

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

fn start(py: &Path, dir: &Path) -> Victim {
    start_victim(py, dir, VICTIM)
}

fn start_victim(py: &Path, dir: &Path, victim: &str) -> Victim {
    let script = dir.join("victim.py");
    std::fs::write(&script, victim).unwrap();
    let ready = dir.join("ready");
    let child = Command::new(py)
        .arg(&script)
        .arg(&ready)
        .stdout(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("start {}: {e}", py.display()));
    let t0 = Instant::now();
    while !ready.exists() {
        assert!(t0.elapsed() < Duration::from_secs(30), "victim not ready");
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = child.id();
    // Let it reach a steady state.
    std::thread::sleep(Duration::from_millis(500));
    Victim { child, pid }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_heapspy")
}

fn heapspy(args: &[&str]) -> std::process::Output {
    Command::new(bin()).args(args).output().unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn has(frames: &[StackFrame], func: &str, line: u32) -> bool {
    frames.iter().any(|f| {
        f.function == func
            && f.line == Some(line)
            && f.file.as_deref().is_some_and(|p| p.ends_with("victim.py"))
    })
}

/// Record ~3 s with `--then-dump`, then check the top stack and the join.
fn run(minor: u8, mechanism: &str) {
    let dir = tempfile::tempdir().unwrap();
    let v = start(&python(minor), dir.path());
    let prof = dir.path().join("a.hpya");
    let snap = dir.path().join("a.hpy");
    let pid = v.pid.to_string();
    let o = heapspy(&[
        "record",
        "--pid",
        &pid,
        "--duration",
        "3s",
        "--mechanism",
        mechanism,
        // A small interval keeps the test quick to converge: with every
        // payload sampled, no unsampled payload sits on memory an older
        // sample still covers.
        "--interval",
        "64K",
        "-o",
        s(&prof),
        "--then-dump",
        s(&snap),
    ]);
    assert!(
        o.status.success(),
        "record failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let o = heapspy(&["analyze", s(&snap), "--allocations", s(&prof), "--json"]);
    assert!(
        o.status.success(),
        "analyze failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let r: AnalyzeReport = serde_json::from_slice(&o.stdout).unwrap();
    let a = r.allocations.expect("allocations in the report");
    assert_eq!(a.mechanisms, [mechanism]);
    assert!(a.samples > 0, "no samples");
    let line = if mechanism == "ptrace" {
        ARENA_LINE
    } else {
        PAYLOAD_LINE
    };
    let top = &a.top_stacks[0];
    assert!(
        has(&top.frames, "build_payload", line) && has(&top.frames, "handler", 8),
        "top stack is not build_payload:{line} <- handler: {:?}",
        top.frames
    );
    // The top retainer is the growing leak, `leaked`: small lists carved
    // from arenas inside build_payload, so linked (approximately, through
    // arena samples) to build_payload:ARENA_LINE by both mechanisms.
    let name = "'leaked'";
    if mechanism == "ebpf" {
        // The payloads kept alive in `keep` link exactly to the top stack.
        assert!(top.exact_linked_bytes > 0, "payloads not linked: {top:?}");
    }
    let line = ARENA_LINE;
    let leak = r
        .top_retainers
        .iter()
        .find(|t| {
            let p = heapspy_analyzer::root_path_string(&t.path);
            // A snapshot taken while build_payload runs reaches the list
            // through its frame first.
            p.ends_with(&format!("[{name}]"))
                || (p.starts_with("frame __main__:build_payload") && t.type_name == "builtins.list")
        })
        .unwrap_or_else(|| {
            let paths: Vec<String> = r
                .top_retainers
                .iter()
                .map(|t| heapspy_analyzer::root_path_string(&t.path))
                .collect();
            panic!("no retainer for {name} in {paths:?}")
        });
    let at = leak
        .allocated_at
        .as_ref()
        .expect("allocated_at on the leak");
    assert!(
        at.stacks
            .iter()
            .any(|st| has(&st.frames, "build_payload", line)),
        "{name} is not linked to build_payload:{line}: {at:?}"
    );
    assert!(a.coverage.linked_objects > 0);
    if mechanism == "ebpf" {
        assert!(a.coverage.exact_linked_objects > 0, "no exact links");
    }
}

macro_rules! live {
    ($name:ident, $minor:expr, $mech:expr) => {
        #[test]
        #[ignore = "needs root and specific interpreters"]
        fn $name() {
            run($minor, $mech);
        }
    };
}

live!(python312_ebpf, 12, "ebpf");
live!(python313_ebpf, 13, "ebpf");
live!(python314_ebpf, 14, "ebpf");
live!(python312_ptrace, 12, "ptrace");
live!(python313_ptrace, 13, "ptrace");
live!(python314_ptrace, 14, "ptrace");

/// CPython's `_Py_InitCleanup` frame as it resolves: `__init__` in file
/// `__init__`, no line.
fn is_shim(f: &StackFrame) -> bool {
    f.function == "__init__" && f.file.as_deref() == Some("__init__")
}

/// Record [`REUSE_VICTIM`] through eBPF, then check that the reused
/// addresses are not linked to the churn and that no stack shows the
/// init shim.
fn run_reuse(minor: u8) {
    let dir = tempfile::tempdir().unwrap();
    let v = start_victim(&python(minor), dir.path(), REUSE_VICTIM);
    let prof = dir.path().join("a.hpya");
    let snap = dir.path().join("a.hpy");
    let pid = v.pid.to_string();
    let o = heapspy(&[
        "record",
        "--pid",
        &pid,
        "--duration",
        "3s",
        "--mechanism",
        "ebpf",
        // 64K keeps about one blob in eight (and one buffer in four), so
        // most blobs are unsampled and sit where a sampled buffer was: the
        // case the join must reject. The sampled blobs, several hundred,
        // then outweigh the arena links of the small objects by far.
        "--interval",
        "64K",
        "-o",
        s(&prof),
        "--then-dump",
        s(&snap),
    ]);
    assert!(
        o.status.success(),
        "record failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let o = heapspy(&["analyze", s(&snap), "--allocations", s(&prof), "--json"]);
    assert!(
        o.status.success(),
        "analyze failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let r: AnalyzeReport = serde_json::from_slice(&o.stdout).unwrap();
    let a = r.allocations.as_ref().expect("allocations in the report");

    // The churn was sampled, its memory was reused under unsampled blobs,
    // and none of that is linked.
    let render = a
        .top_stacks
        .iter()
        .find(|t| has(&t.frames, "render_page", 14))
        .unwrap_or_else(|| panic!("render_page was not sampled: {:?}", a.top_stacks));
    assert_eq!(render.linked_bytes, 0, "render_page linked: {render:?}");
    assert!(
        a.coverage.unlinked_reused_objects > 0,
        "no reused address seen, the test proves nothing: {:?}",
        a.coverage
    );

    let sessions = r
        .top_retainers
        .iter()
        .find(|t| heapspy_analyzer::root_path_string(&t.path).ends_with("['SESSIONS']"))
        .unwrap_or_else(|| {
            let paths: Vec<String> = r
                .top_retainers
                .iter()
                .map(|t| heapspy_analyzer::root_path_string(&t.path))
                .collect();
            panic!("no SESSIONS retainer in {paths:?}")
        });
    let at = sessions.allocated_at.as_ref().expect("allocated_at");
    let top = at.stacks.first().expect("SESSIONS has linked objects");
    assert!(
        has(&top.frames, "Session.__init__", BLOB_LINE),
        "SESSIONS' top stack is not Session.__init__:{BLOB_LINE}: {at:?}"
    );
    assert_eq!(top.exact_linked_bytes, top.linked_bytes, "{top:?}");
    // The caller of __init__ is login, with no shim frame in between.
    let i = top
        .frames
        .iter()
        .position(|f| f.function == "Session.__init__")
        .unwrap();
    assert!(
        has(&top.frames[i + 1..i + 2], "login", LOGIN_LINE),
        "{:?}",
        top.frames
    );
    for st in &at.stacks {
        assert!(
            !st.frames.iter().any(|f| f.function == "render_page"),
            "SESSIONS linked to render_page: {at:?}"
        );
    }
    for st in r
        .top_retainers
        .iter()
        .filter_map(|t| t.allocated_at.as_ref())
        .flat_map(|at| &at.stacks)
    {
        assert!(!st.frames.iter().any(|f| f.function == "render_page"));
    }
    for t in &a.top_stacks {
        assert!(!t.frames.iter().any(is_shim), "shim frame: {:?}", t.frames);
    }
}

#[test]
#[ignore = "needs root and specific interpreters"]
fn python312_reused_addresses() {
    run_reuse(12);
}

#[test]
#[ignore = "needs root and specific interpreters"]
fn python313_reused_addresses() {
    run_reuse(13);
}

#[test]
#[ignore = "needs root and specific interpreters"]
fn python314_reused_addresses() {
    run_reuse(14);
}

/// SHA-256-free fingerprint of the target's executable mappings.
fn code_bytes(pid: u32) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    let mut mem = std::fs::File::open(format!("/proc/{pid}/mem")).unwrap();
    let mut out = Vec::new();
    for l in maps.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() > 5 && f[1].contains('x') && f[5].starts_with('/') {
            let (a, b) = f[0].split_once('-').unwrap();
            let (a, b) = (
                u64::from_str_radix(a, 16).unwrap(),
                u64::from_str_radix(b, 16).unwrap(),
            );
            let mut buf = vec![0u8; (b - a) as usize];
            mem.seek(SeekFrom::Start(a)).unwrap();
            if mem.read_exact(&mut buf).is_ok() {
                out.extend(buf);
            }
        }
    }
    out
}

fn status(pid: u32, key: &str) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find(|l| l.starts_with(key))
        .unwrap_or("")
        .to_string()
}

/// Number of BPF programs loaded in the kernel.
fn bpf_programs() -> usize {
    let mut n = 0;
    let mut id: u32 = 0;
    loop {
        let mut attr = [0u8; 128];
        attr[0..4].copy_from_slice(&id.to_ne_bytes());
        // SAFETY: BPF_PROG_GET_NEXT_ID (11) reads start_id and writes next_id.
        let r = unsafe { libc::syscall(libc::SYS_bpf, 11, attr.as_mut_ptr(), attr.len()) };
        if r != 0 {
            break;
        }
        id = u32::from_ne_bytes(attr[4..8].try_into().unwrap());
        n += 1;
    }
    n
}

/// SIGKILL the recorder mid-run: the target keeps running, untraced, with
/// its code unchanged, and no probe or program is left in the kernel.
fn killed(mechanism: &str) {
    let dir = tempfile::tempdir().unwrap();
    let v = start(&python(13), dir.path());
    let before = code_bytes(v.pid);
    let progs = bpf_programs();
    let out = dir.path().join("k.hpya");
    let mut rec = Command::new(bin())
        .args([
            "record",
            "--pid",
            &v.pid.to_string(),
            "--duration",
            "60s",
            "--mechanism",
            mechanism,
            "-o",
            s(&out),
        ])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    if mechanism == "ebpf" {
        assert!(bpf_programs() > progs, "recorder loaded no program");
    }
    rec.kill().unwrap();
    rec.wait().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        Path::new(&format!("/proc/{}", v.pid)).exists(),
        "target died"
    );
    assert_eq!(
        status(v.pid, "TracerPid:").split_whitespace().nth(1),
        Some("0")
    );
    let state = status(v.pid, "State:");
    assert!(
        !state.contains("t (tracing stop)") && !state.contains("T (stopped)"),
        "{state}"
    );
    for t in std::fs::read_dir(format!("/proc/{}/task", v.pid)).unwrap() {
        let p = t.unwrap().path().join("status");
        let st = std::fs::read_to_string(p).unwrap_or_default();
        assert!(!st.contains("tracing stop"), "a thread was left stopped");
    }
    assert!(code_bytes(v.pid) == before, "code bytes changed");
    assert_eq!(bpf_programs(), progs, "BPF programs left loaded");
    let uprobes = std::fs::read_to_string("/sys/kernel/tracing/uprobe_events").unwrap_or_default();
    assert!(!uprobes.contains("heapspy"), "{uprobes}");
    assert!(!out.exists(), "a killed recording left a profile");
}

#[test]
#[ignore = "needs root and specific interpreters"]
fn sigkill_mid_run_ebpf() {
    killed("ebpf");
}

#[test]
#[ignore = "needs root and specific interpreters"]
fn sigkill_mid_run_ptrace() {
    killed("ptrace");
}

/// SIGINT (Ctrl-C) ends the recording early with a valid profile flagged
/// truncated, and leaves the target unmodified.
fn interrupted(mechanism: &str) {
    let dir = tempfile::tempdir().unwrap();
    let v = start(&python(13), dir.path());
    let before = code_bytes(v.pid);
    let out = dir.path().join("i.hpya");
    let rec = Command::new(bin())
        .args([
            "record",
            "--json",
            "--pid",
            &v.pid.to_string(),
            "--duration",
            "60s",
            "--mechanism",
            mechanism,
            "-o",
            s(&out),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    let t0 = Instant::now();
    // SAFETY: sending SIGINT to our child.
    unsafe { libc::kill(rec.id() as i32, libc::SIGINT) };
    let o = rec.wait_with_output().unwrap();
    assert!(t0.elapsed() < Duration::from_secs(5), "slow to stop");
    assert!(o.status.success());
    let doc: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(doc["kind"], "record");
    assert_eq!(doc["truncated"], true);
    let p = heapspy_alloc::Profile::open(&out).expect("a valid profile");
    assert!(p.info().truncated);
    assert!(code_bytes(v.pid) == before, "code bytes changed");
    assert_eq!(
        status(v.pid, "TracerPid:").split_whitespace().nth(1),
        Some("0")
    );
}

#[test]
#[ignore = "needs root and specific interpreters"]
fn sigint_ebpf() {
    interrupted("ebpf");
}

#[test]
#[ignore = "needs root and specific interpreters"]
fn sigint_ptrace() {
    interrupted("ptrace");
}
