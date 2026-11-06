//! Scale smoke test, ignored by default. Run with
//!
//! ```sh
//! cargo test --release -p heapspy-analyzer --test scale -- --ignored --nocapture
//! ```
//!
//! `HEAPSPY_SCALE_OBJECTS` sets the object count (default 10 million).

use std::time::Instant;

use heapspy_analyzer::{analyze, AnalyzeOptions};
use heapspy_snapshot::{
    Edge, EdgeLabel, KeyLabel, ObjectInput, RootKind, Snapshot, SnapshotInfo, SnapshotWriter,
};

/// Peak and current resident set size in KiB, from /proc (Linux only).
fn rss_kib() -> Option<(u64, u64)> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let field = |name: &str| {
        s.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
    };
    Some((field("VmHWM:")?, field("VmRSS:")?))
}

/// Reset the peak RSS counter (Linux 4.0+; ignored elsewhere).
fn reset_peak() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

/// A heap shaped like a leaking service: one module whose CACHE dict holds
/// a quarter of all objects as entry -> payload pairs, a long linked list,
/// and a random graph with cycles among the rest. About 2.5 edges per object.
fn write(n: u64, path: &std::path::Path, spill: &std::path::Path) -> u64 {
    let mut w = SnapshotWriter::with_spill_dir(SnapshotInfo::new_for_test(), spill).unwrap();
    let t_mod = w.add_type(0, "builtins", "module").unwrap();
    let t_dict = w.add_type(0, "builtins", "dict").unwrap();
    let t_sess = w.add_type(0, "app", "Session").unwrap();
    let t_bytes = w.add_type(0, "builtins", "bytes").unwrap();
    let t_node = w.add_type(0, "app", "Node").unwrap();
    let t_obj = w.add_type(0, "app", "Obj").unwrap();
    let dict_s = w.intern("__dict__").unwrap();
    let cache_s = w.intern("'CACHE'").unwrap();
    let list_s = w.intern("'LIST'").unwrap();
    let key_s = w.intern("<str len=9>").unwrap();
    let pay_s = w.intern("payload").unwrap();
    let next_s = w.intern("next").unwrap();
    let addr = |i: u64| 0x1000 + i * 0x40;
    let e = |t: u64, label| Edge {
        target: addr(t),
        label,
    };

    // 0 module, 1 module dict, 2 CACHE; entries at 3.., payloads after them.
    let entries = n / 8;
    let chain_start = 3 + 2 * entries;
    let chain_len = n / 10;
    let rand_start = chain_start + chain_len;
    w.add_object(
        &ObjectInput::new(addr(0), t_mod, 72),
        [e(1, EdgeLabel::Attr(dict_s))],
    )
    .unwrap();
    w.add_object(
        &ObjectInput::new(addr(1), t_dict, 4096),
        [
            e(2, EdgeLabel::DictValue(KeyLabel::Repr(cache_s))),
            e(chain_start, EdgeLabel::DictValue(KeyLabel::Repr(list_s))),
            e(rand_start, EdgeLabel::DictValue(KeyLabel::Repr(list_s))),
        ],
    )
    .unwrap();
    w.add_object(
        &ObjectInput::new(addr(2), t_dict, 40 * entries),
        (0..entries).map(|k| e(3 + k, EdgeLabel::DictValue(KeyLabel::Redacted(key_s)))),
    )
    .unwrap();
    for k in 0..entries {
        w.add_object(
            &ObjectInput::new(addr(3 + k), t_sess, 56),
            [e(3 + entries + k, EdgeLabel::Attr(pay_s))],
        )
        .unwrap();
        w.add_object(&ObjectInput::new(addr(3 + entries + k), t_bytes, 1000), [])
            .unwrap();
    }
    for k in 0..chain_len {
        let i = chain_start + k;
        let next = if k + 1 < chain_len {
            vec![e(i + 1, EdgeLabel::Attr(next_s))]
        } else {
            vec![]
        };
        w.add_object(&ObjectInput::new(addr(i), t_node, 64), next)
            .unwrap();
    }
    let mut rng = Lcg(42);
    let rand_n = n - rand_start;
    for i in rand_start..n {
        let deg = 3 + rng.next() % 4;
        let mut out = Vec::with_capacity(deg as usize + 1);
        // A spanning backbone so most of the random part is reachable.
        if i + 1 < n && rng.next() % 10 != 0 {
            out.push(e(i + 1, EdgeLabel::ListItem(0)));
        }
        for j in 0..deg {
            let t = if rng.next() % 50 == 0 {
                rng.next() % n // occasionally into the cache or the chain
            } else {
                rand_start + rng.next() % rand_n
            };
            out.push(e(t, EdgeLabel::ListItem(j as u32 + 1)));
        }
        if rng.next() % 1000 == 0 {
            out.push(Edge {
                target: 0xdead,
                label: EdgeLabel::Other(None),
            });
        }
        w.add_object(
            &ObjectInput::new(addr(i), t_obj, 48 + rng.next() % 200),
            out,
        )
        .unwrap();
    }
    let root_label = w.intern("sys.modules['app']").unwrap();
    w.add_root(addr(0), RootKind::ModuleDict, root_label)
        .unwrap();
    let stats = w.finish_to_path(path).unwrap();
    stats.edges
}

#[test]
#[ignore]
fn ten_million_objects() {
    let n: u64 = std::env::var("HEAPSPY_SCALE_OBJECTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000_000);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scale.hpy");
    let t = Instant::now();
    let edges = write(n, &path, dir.path());
    let file_mib = std::fs::metadata(&path).unwrap().len() >> 20;
    eprintln!(
        "wrote {n} objects, {edges} edges, {file_mib} MiB in {:.1}s",
        t.elapsed().as_secs_f64()
    );

    reset_peak();
    let base = rss_kib();
    let t = Instant::now();
    let snap = Snapshot::open(&path).unwrap();
    let opened = t.elapsed();
    let r = analyze(&snap, "scale.hpy", &AnalyzeOptions::default()).unwrap();
    let total = t.elapsed();
    let peak = rss_kib();
    eprintln!(
        "open {:.2}s, open+analyze {:.2}s",
        opened.as_secs_f64(),
        total.as_secs_f64()
    );
    if let (Some((_, base_rss)), Some((hwm, _))) = (base, peak) {
        eprintln!(
            "RSS before {} MiB, peak during analyze {} MiB (includes mapped snapshot pages, {} MiB file)",
            base_rss >> 10,
            hwm >> 10,
            file_mib
        );
    }
    eprintln!(
        "reachable {} of {} objects, {} dangling edges",
        r.totals.reachable_objects, r.totals.objects, r.totals.dangling_edges
    );
    for t in r.top_retainers.iter().take(3) {
        eprintln!(
            "  {:>12} {:>6.2}% {} {}",
            t.retained_bytes,
            t.retained_pct,
            t.type_name,
            heapspy_analyzer::root_path_string(&t.path)
        );
    }

    assert_eq!(r.totals.objects, n);
    let top = &r.top_retainers[0];
    assert_eq!(
        heapspy_analyzer::root_path_string(&top.path),
        "sys.modules['app'].__dict__['CACHE']"
    );
    let entries = n / 8;
    // Random references into the cache make a few entries shared.
    assert!(top.retained_bytes as f64 >= 0.8 * (40 * entries + entries * 1056) as f64);
}

/// Folded stacks on the same generated heap, 5 million objects by default
/// (`HEAPSPY_FLAME_OBJECTS`). Run with
///
/// ```sh
/// cargo test --release -p heapspy-analyzer --test scale flame -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn flame_five_million_objects() {
    use heapspy_analyzer::{folded_stacks, FlameOptions};

    let n: u64 = std::env::var("HEAPSPY_FLAME_OBJECTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000_000);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scale.hpy");
    let edges = write(n, &path, dir.path());
    let file_mib = std::fs::metadata(&path).unwrap().len() >> 20;
    eprintln!("wrote {n} objects, {edges} edges, {file_mib} MiB");

    reset_peak();
    let base = rss_kib();
    let t = Instant::now();
    let snap = Snapshot::open(&path).unwrap();
    let f = folded_stacks(&snap, &FlameOptions::default()).unwrap();
    let elapsed = t.elapsed();
    let peak = rss_kib();
    let mut out = Vec::new();
    f.write_to(&mut out).unwrap();
    eprintln!(
        "open+fold {:.2}s, {} lines, {} bytes of folded text, cutoff {} bytes",
        elapsed.as_secs_f64(),
        f.lines.len(),
        out.len(),
        f.min_bytes
    );
    if let (Some((_, base_rss)), Some((hwm, _))) = (base, peak) {
        eprintln!(
            "RSS before {} MiB, peak during fold {} MiB (includes mapped snapshot pages, {} MiB file)",
            base_rss >> 10,
            hwm >> 10,
            file_mib
        );
    }
    for l in f.lines.iter().take(5) {
        eprintln!("  {} {}", l.stack, l.bytes);
    }
    assert_eq!(
        f.lines.iter().map(|l| l.bytes).sum::<u64>(),
        f.reachable_bytes
    );
    assert!(f.lines.iter().all(|l| l.stack.split(';').count() <= 33));
    assert!(out.len() < 1 << 20, "folded output should stay small");
}
