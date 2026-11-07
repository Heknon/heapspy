//! The glibc heap walker against a real CPython process, live and as a
//! `gcore` core.
//!
//! Needs Linux, ptrace permission over a child (`kernel.yama.ptrace_scope`
//! 0 or 1), `gcore` from gdb, and a glibc-linked CPython, so it is ignored
//! by default. The e2e workflow runs it for each Python it tests:
//!
//! ```text
//! HEAPSPY_PY=$(uv python find 3.13) \
//!     cargo test -p heapspy-reader --test native_heap_live -- --ignored --test-threads 1
//! ```
//!
//! `HEAPSPY_PY` defaults to `python3`. The victim `malloc`s buffers through
//! ctypes, from the main thread (brk heap and mmapped chunks) and from a
//! second thread (its own arena), fills them, writes their addresses and
//! sleeps. Every one must be inside a busy block of the right kind.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use heapspy_reader::source::elf_core::ElfCore;
use heapspy_reader::source::linux_live::LiveProcess;
use heapspy_reader::source::{MemorySource, NativeBlock, NativeBlockKind};

const VICTIM: &str = r#"
import ctypes, os, sys, threading, time

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
lines = []

def grab(size, where):
    p = libc.malloc(size)
    ctypes.memset(p, 0xAB, size)
    lines.append(f"{p} {size} {where}")

# brk heap (below the 128 KiB mmap threshold), then mmapped chunks.
for size in (24, 200, 5000, 100000):
    grab(size, "main")
for size in (1 << 20, 8 << 20):
    grab(size, "mmap")

ready, hold = threading.Event(), threading.Event()
def worker():
    grab(3000, "thread")
    ready.set()
    hold.wait()
threading.Thread(target=worker, daemon=True).start()
ready.wait()

tmp = sys.argv[1] + ".tmp"
with open(tmp, "w") as f:
    f.write("\n".join(lines) + "\n")
os.rename(tmp, sys.argv[1])
while True:
    time.sleep(1)
"#;

struct Victim {
    child: Child,
    allocs: Vec<(u64, u64, String)>,
}

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(dir: &Path) -> Victim {
    let py: PathBuf = std::env::var_os("HEAPSPY_PY")
        .map(Into::into)
        .unwrap_or_else(|| "python3".into());
    let script = dir.join("victim.py");
    std::fs::write(&script, VICTIM).unwrap();
    let ready = dir.join("ready");
    let child = Command::new(&py)
        .arg(&script)
        .arg(&ready)
        .stdout(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("start {}: {e}", py.display()));
    let t0 = Instant::now();
    while !ready.exists() {
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "victim never got ready"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let allocs = std::fs::read_to_string(&ready)
        .unwrap()
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            (
                f[0].parse().unwrap(),
                f[1].parse().unwrap(),
                f[2].to_string(),
            )
        })
        .collect();
    Victim { child, allocs }
}

fn check(src: &dyn MemorySource, allocs: &[(u64, u64, String)], what: &str) {
    let blocks: Vec<NativeBlock> = src
        .native_blocks()
        .unwrap()
        .unwrap_or_else(|| panic!("{what}: no native blocks (allocator not recognised?)"));
    eprintln!("{what}: {} native blocks", blocks.len());
    assert!(blocks.len() > 100, "{what}: only {} blocks", blocks.len());
    for w in blocks.windows(2) {
        assert!(w[0].start + w[0].size <= w[1].start, "{what}: {w:?}");
    }
    for (p, size, kind) in allocs {
        let b = blocks
            .iter()
            .find(|b| b.start <= *p && *p < b.start + b.size)
            .unwrap_or_else(|| panic!("{what}: {kind} malloc({size}) at {p:#x} is in no block"));
        // The user pointer is the chunk plus 16, and the chunk holds it. A
        // busy chunk's data also runs into the next chunk's `prev_size`
        // word (8 bytes), so malloc(24) fits a 32-byte chunk.
        let spill = if b.kind == NativeBlockKind::Allocation {
            8
        } else {
            0
        };
        assert!(
            b.start + b.size + spill >= p + size,
            "{what}: {b:?} too small for {size}"
        );
        match kind.as_str() {
            "mmap" => assert_eq!(b.kind, NativeBlockKind::Large, "{what}: {b:?}"),
            _ => {
                assert_eq!(b.kind, NativeBlockKind::Allocation, "{what}: {b:?}");
                assert_eq!(*p, b.start + 16, "{what}: {b:?}");
            }
        }
        match kind.as_str() {
            "thread" => assert_ne!(b.heap, 0, "{what}: thread malloc in the main arena"),
            "main" => assert_eq!(b.heap, 0, "{what}: {b:?}"),
            _ => {}
        }
    }
}

#[test]
#[ignore = "needs Linux, ptrace, gcore and CPython; see the module docs"]
fn native_blocks_of_a_live_cpython_and_its_core() {
    let dir = tempfile::tempdir().unwrap();
    let v = start(dir.path());
    let pid = v.child.id();
    {
        let live = LiveProcess::attach(pid).expect("attach (ptrace permission?)");
        check(&live, &v.allocs, "live");
        live.release();
    }
    let prefix = dir.path().join("core");
    let out = Command::new("gcore")
        .arg("-o")
        .arg(&prefix)
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .output()
        .expect("run gcore (install gdb)");
    assert!(
        out.status.success(),
        "gcore: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let core = ElfCore::open(&dir.path().join(format!("core.{pid}"))).unwrap();
    check(&core, &v.allocs, "core");
}
