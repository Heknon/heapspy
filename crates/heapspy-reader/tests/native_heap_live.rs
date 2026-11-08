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
//!
//! `HEAPSPY_VICTIM` names a built victim to run instead, given the file to
//! write: `victims/glibc_heap.c` does the same in C, for glibc releases
//! CPython no longer runs on. The glibc workflow builds it and this test
//! (statically, for musl) inside old distro images. `HEAPSPY_SKIP_CORE`
//! skips the `gcore` half where no gdb can be had.
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
    let ready = dir.join("ready");
    // A built victim (victims/glibc_heap.c) if given, else the Python one.
    let mut cmd = match std::env::var_os("HEAPSPY_VICTIM") {
        Some(exe) => Command::new(exe),
        None => {
            let py: PathBuf = std::env::var_os("HEAPSPY_PY")
                .map(Into::into)
                .unwrap_or_else(|| "python3".into());
            let script = dir.join("victim.py");
            std::fs::write(&script, VICTIM).unwrap();
            let mut cmd = Command::new(py);
            cmd.arg(script);
            cmd
        }
    };
    let child = cmd
        .arg(&ready)
        .stdout(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("start {cmd:?}: {e}"));
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
    let blocks: Vec<NativeBlock> = src.native_blocks().unwrap().unwrap_or_else(|| {
        // What the walker had to go on: libc, and the anonymous memory
        // a heap could be in.
        let modules: Vec<String> = src
            .modules()
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.path)
            .filter(|p| p.contains("libc"))
            .collect();
        let maps: Vec<String> = src
            .mapped_ranges()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.perms.write)
            .map(|r| format!("{:#x}+{:#x} {:?}", r.start, r.size, r.file))
            .collect();
        // libc's mappings, and whether the ELF header at each reads.
        let libc: Vec<String> = src
            .mapped_ranges()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.file.as_deref().is_some_and(|f| f.contains("libc")))
            .map(|r| {
                let mut b = [0u8; 4];
                let head = src.read(r.start, &mut b).map(|()| b);
                format!(
                    "{:#x}+{:#x} {:?} {:?}: {head:x?}",
                    r.start, r.size, r.perms, r.file
                )
            })
            .collect();
        panic!(
            "{what}: no native blocks (allocator not recognised?)\n\
             libc modules: {modules:?}\nlibc mappings: {libc:#?}\n\
             writable mappings: {maps:#?}"
        )
    });
    eprintln!("{what}: {} native blocks", blocks.len());
    // A CPython has thousands; the C victim only what it asked for, and its
    // stdio buffers.
    let least = if std::env::var_os("HEAPSPY_VICTIM").is_some() {
        allocs.len()
    } else {
        100
    };
    assert!(
        blocks.len() >= least,
        "{what}: only {} blocks",
        blocks.len()
    );
    for w in blocks.windows(2) {
        assert!(w[0].start + w[0].size <= w[1].start, "{what}: {w:?}");
    }
    let all_blocks = &blocks;
    for (p, size, kind) in allocs {
        let b = blocks
            .iter()
            .find(|b| b.start <= *p && *p < b.start + b.size)
            .unwrap_or_else(|| {
                // What is around it, to tell a missed header from a
                // neighbour that swallowed it.
                let near = |a: u64, b: u64| a.abs_diff(b) < 64 << 20;
                let blocks: Vec<_> = blocks.iter().filter(|b| near(b.start, *p)).collect();
                let maps: Vec<String> = src
                    .mapped_ranges()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|r| near(r.start, *p))
                    .map(|r| format!("{:#x}+{:#x} {:?} {:?}", r.start, r.size, r.perms, r.file))
                    .collect();
                let sps: Vec<String> = src
                    .threads()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|t| t.stack_pointer)
                    .map(|sp| format!("{sp:#x}"))
                    .collect();
                let all: Vec<_> = all_blocks.iter().filter(|b| b.kind == NativeBlockKind::Large).collect();
                let mut heaps: std::collections::BTreeMap<u32, (u64, u64, usize)> = Default::default();
                for b in all_blocks.iter().filter(|b| b.kind == NativeBlockKind::Allocation) {
                    let e = heaps.entry(b.heap).or_insert((u64::MAX, 0, 0));
                    e.0 = e.0.min(b.start);
                    e.1 = e.1.max(b.start + b.size);
                    e.2 += 1;
                }
                let anon: Vec<String> = src
                    .mapped_ranges()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|r| r.file.is_none() && r.perms.read && r.perms.write && r.size > (16 << 20))
                    .map(|r| format!("{:#x}+{:#x}", r.start, r.size))
                    .collect();
                let mut hdr = [0u8; 16];
                let hdr = src.read(*p - 16, &mut hdr).map(|()| {
                    (
                        u64::from_le_bytes(hdr[..8].try_into().unwrap()),
                        u64::from_le_bytes(hdr[8..].try_into().unwrap()),
                    )
                });
                let mut page = vec![0u8; 4096];
                let page = src.read((*p - 16) & !4095, &mut page).map(|()| "ok");
                let mut wide = vec![0u8; 64 << 10];
                let wide = src.read((*p - 16) & !0xffff, &mut wide).map(|()| "ok");
                eprintln!("header at p-16: {hdr:x?}; its page: {page:?}; its 64K block: {wide:?}");
                panic!(
                    "{what}: {kind} malloc({size}) at {p:#x} is in no block\n\
                     blocks near: {blocks:#x?}\nmaps near: {maps:#?}\nstack pointers: {sps:?}\n\
                     large blocks: {all:#x?}\nheaps (start, end, n): {heaps:#x?}\nbig anon: {anon:?}"
                )
            });
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
    if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
        let heap: Vec<&str> = maps.lines().filter(|l| l.ends_with("[heap]")).collect();
        eprintln!("victim [heap]: {heap:?}");
    }
    {
        let live = LiveProcess::attach(pid).expect("attach (ptrace permission?)");
        check(&live, &v.allocs, "live");
        live.release();
    }
    if std::env::var_os("HEAPSPY_SKIP_CORE").is_some() {
        eprintln!("HEAPSPY_SKIP_CORE is set: not checking a gcore core");
        return;
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
