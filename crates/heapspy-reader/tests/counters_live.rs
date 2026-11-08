//! The counter reader against real CPython processes, which print what
//! `gc` and `sys` say about themselves and then sleep.
//!
//! Needs ptrace permission and the interpreters, so it is ignored by
//! default:
//!
//! ```text
//! cargo test -p heapspy-reader --test counters_live -- --ignored --test-threads 1
//! ```
//!
//! Interpreters: `/usr/bin/python3.12`, `/usr/local/bin/python3.13` and
//! `$(uv python find 3.14)`, or `HEAPSPY_PY312`, `HEAPSPY_PY313`,
//! `HEAPSPY_PY314`. A missing interpreter fails the test. `counters_heapspy_py`
//! runs the interpreter in `HEAPSPY_PY` instead (the e2e workflow's).

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use heapspy_reader::cpython::counters::CounterReader;
use heapspy_reader::cpython::locate_runtime;
use heapspy_reader::source::linux_live::LiveProcess;

const VICTIM: &str = r#"
import gc, json, sys, time
gc.set_threshold(1234, 11, 12)
KEEP = [{"i": i, "s": "x" * (i % 300)} for i in range(50000)]
gc.collect()
gc.disable()
stats = gc.get_stats()
print(json.dumps({
    "count": gc.get_count(),
    "threshold": gc.get_threshold(),
    "collections": [s["collections"] for s in stats],
    "blocks": sys.getallocatedblocks(),
}), flush=True)
while True:
    time.sleep(1)
"#;

struct Victim(Child);

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn interpreter(minor: u8) -> String {
    if let Ok(p) = std::env::var(format!("HEAPSPY_PY3{minor}")) {
        return p;
    }
    match minor {
        12 => "/usr/bin/python3.12".into(),
        13 => "/usr/local/bin/python3.13".into(),
        _ => {
            let out = Command::new("uv")
                .args(["python", "find", "3.14"])
                .output()
                .expect("uv python find 3.14");
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        }
    }
}

fn check(minor: u8) {
    check_with(&interpreter(minor), &format!("{minor}"));
}

fn check_with(py: &str, minor: &str) {
    let mut child = Command::new(py)
        .args(["-c", VICTIM])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start {py}: {e}"));
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let victim = Victim(child);
    let said: serde_like::Said = serde_like::parse(&line);

    let src = LiveProcess::open_running(victim.0.id()).unwrap();
    let rt = locate_runtime(&src).unwrap();
    let reader = CounterReader::new(&src, &rt).unwrap();
    let c = reader.read(&src).unwrap();
    assert_eq!(c.interpreters, 1, "{minor}");
    assert!(c.threads >= 1, "{minor}");

    let gc = c.gc.unwrap_or_else(|| panic!("{minor}: no gc counters"));
    assert!(!gc.enabled, "{minor}: gc.disable() was called");
    let thresholds: Vec<i64> = gc.generations.iter().map(|g| g.threshold).collect();
    assert_eq!(thresholds, said.threshold, "{minor}");
    let collections: Vec<u64> = gc.generations.iter().map(|g| g.collections).collect();
    assert_eq!(collections, said.collections, "{minor}");
    // The count moved a little while `print` and `json` ran.
    assert!(
        (gc.generations[0].count - said.count[0]).abs() < 200,
        "{minor}: gen0 count {} vs {}",
        gc.generations[0].count,
        said.count[0]
    );
    // Dicts of atomic values are untracked on 3.12 and 3.13, so this is
    // well below the 50000 dicts.
    assert!(gc.long_lived_total > 1000, "{minor}: {gc:?}");

    let a = c
        .allocator
        .unwrap_or_else(|| panic!("{minor}: no allocator counters"));
    assert_eq!(a.skipped_pools, 0, "{minor}");
    assert!(a.arenas >= 1 && a.arena_bytes >= a.block_bytes, "{minor}");
    let diff = (a.blocks as i64 - said.blocks).abs();
    assert!(
        diff * 100 < said.blocks,
        "{minor}: {} blocks read, sys.getallocatedblocks() said {}",
        a.blocks,
        said.blocks
    );
    assert_eq!(
        a.size_classes.iter().map(|c| c.blocks).sum::<u64>(),
        a.blocks
    );

    let t = src
        .heap_totals()
        .unwrap_or_else(|| panic!("{minor}: no glibc heap totals"));
    assert!(t.brk_bytes > 0, "{minor}: {t:?}");
}

/// Just enough JSON for the victim's one line.
mod serde_like {
    pub struct Said {
        pub count: Vec<i64>,
        pub threshold: Vec<i64>,
        pub collections: Vec<u64>,
        pub blocks: i64,
    }

    fn list(s: &str, key: &str) -> Vec<i64> {
        let i = s.find(&format!("\"{key}\": [")).expect(key) + key.len() + 5;
        let j = i + s[i..].find(']').unwrap();
        s[i..j]
            .split(',')
            .map(|x| x.trim().parse().unwrap())
            .collect()
    }

    pub fn parse(s: &str) -> Said {
        let i = s.find("\"blocks\": ").unwrap() + 10;
        let j = i + s[i..].find('}').unwrap();
        Said {
            count: list(s, "count"),
            threshold: list(s, "threshold"),
            collections: list(s, "collections")
                .into_iter()
                .map(|x| x as u64)
                .collect(),
            blocks: s[i..j].trim().parse().unwrap(),
        }
    }
}

#[test]
#[ignore]
fn counters_heapspy_py() {
    let Ok(py) = std::env::var("HEAPSPY_PY") else {
        eprintln!("HEAPSPY_PY is not set: nothing to check");
        return;
    };
    check_with(&py, &py);
}

#[test]
#[ignore]
fn counters_python312() {
    check(12);
}

#[test]
#[ignore]
fn counters_python313() {
    check(13);
}

#[test]
#[ignore]
fn counters_python314() {
    check(14);
}
