//! The committed BPF object (`bpf/heapspy.bpf.o`) matches its source and
//! has every program the recorder loads.

use std::path::Path;
use std::process::Command;

const PROGRAMS: [&str; 9] = [
    "raw_tracepoint/sys_enter",
    "raw_tracepoint/sys_exit",
    "uprobe/malloc_ctx",
    "uprobe/calloc_ctx",
    "uprobe/realloc_ctx",
    "uprobe/malloc",
    "uprobe/calloc",
    "uprobe/realloc",
    "uretprobe/alloc_ret",
];

fn object() -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("bpf/heapspy.bpf.o")).unwrap()
}

#[test]
fn object_has_every_program_and_map() {
    let data = object();
    // ELF64, little endian, machine EM_BPF (247).
    assert_eq!(&data[..4], b"\x7fELF");
    assert_eq!(data[4], 2);
    assert_eq!(u16::from_le_bytes([data[18], data[19]]), 247);
    let text = String::from_utf8_lossy(&data);
    for p in PROGRAMS.iter().chain(&["uprobe.session/alloc"]) {
        assert!(text.contains(p), "missing program {p}");
    }
    for m in [
        "cfg",
        "thresholds",
        "remaining",
        "counters",
        "pending",
        "mmaps",
        "tstates",
        "events",
        "scratch",
    ] {
        assert!(text.contains(m), "missing map {m}");
    }
}

/// Rebuilds the object with clang and compares. Ignored by default because
/// the output depends on the clang version (18 is the reference); run it
/// whenever `bpf/heapspy.bpf.c` changes:
///
/// ```text
/// cargo test -p heapspy-record --test bpf_object -- --ignored
/// ```
#[test]
#[ignore = "needs clang 18 with the BPF target"]
fn committed_object_matches_source() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("bpf/build.sh");
    let out = Command::new("sh")
        .arg(&script)
        .arg("--check")
        .output()
        .expect("run bpf/build.sh");
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
