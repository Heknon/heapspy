//! Print the native heap blocks of a Windows minidump, and which block each
//! given pointer falls in. For checking the NT heap walker by hand.
//!
//! ```text
//! cargo run --release -p heapspy-reader --example native_blocks -- app.dmp [0xPTR ...]
//! cargo run --release -p heapspy-reader --example native_blocks -- --pid 1234 [0xPTR ...]
//! ```
//!
//! `--pid` (Windows only) writes a full-memory dump of the process to the
//! system temporary directory, reads it, and deletes it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use heapspy_reader::source::minidump::Minidump;
use heapspy_reader::source::MemorySource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let first = args
        .next()
        .ok_or("usage: native_blocks <dump.dmp | --pid N> [0xPTR ...]")?;
    let mut _cleanup = None;
    let path = if first == "--pid" {
        let pid: u32 = args.next().ok_or("--pid needs a pid")?.parse()?;
        capture(pid, &mut _cleanup)?
    } else {
        PathBuf::from(first)
    };
    let ptrs: Vec<u64> = args
        .map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16))
        .collect::<Result<_, _>>()?;

    let dump = Minidump::open(&path)?;
    let t = Instant::now();
    let blocks = dump.native_blocks()?;
    let elapsed = t.elapsed();
    let Some(blocks) = blocks else {
        println!("no NT heap could be walked");
        return Ok(());
    };
    let walk = dump.native_heap_walk().expect("walked above");
    println!("walk took {elapsed:.2?}");
    println!("heaps: {:x?}", walk.heaps);
    println!("{:#?}", walk.stats);

    let mut by: BTreeMap<(u32, String), (u64, u64)> = BTreeMap::new();
    for b in &blocks {
        let e = by.entry((b.heap, format!("{:?}", b.kind))).or_default();
        e.0 += 1;
        e.1 += b.size;
    }
    for ((heap, kind), (n, bytes)) in &by {
        println!("heap {heap:>2} {kind:<20} {n:>9} blocks {bytes:>14} bytes");
    }
    let total: u64 = blocks.iter().map(|b| b.size).sum();
    println!("total {} blocks, {total} bytes", blocks.len());
    for w in blocks.windows(2) {
        assert!(w[0].start + w[0].size <= w[1].start, "overlap: {:x?}", w);
    }

    let mut missing = 0;
    for p in &ptrs {
        let hits: Vec<_> = blocks
            .iter()
            .filter(|b| b.start <= *p && *p < b.start + b.size)
            .collect();
        match hits.as_slice() {
            [b] => println!(
                "{p:#x} -> {:#x} +{:#x} {:?} heap {} (ptr at +{:#x})",
                b.start,
                b.size,
                b.kind,
                b.heap,
                p - b.start
            ),
            _ => {
                missing += 1;
                println!("{p:#x} -> {} blocks", hits.len());
            }
        }
    }
    if !ptrs.is_empty() {
        println!(
            "{} of {} pointers in exactly one block",
            ptrs.len() - missing,
            ptrs.len()
        );
    }
    Ok(())
}

/// Removes the file when dropped.
struct Remove(PathBuf);

impl Drop for Remove {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(windows)]
fn capture(pid: u32, cleanup: &mut Option<Remove>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("native_blocks-{pid}-{}.dmp", std::process::id()));
    let t = Instant::now();
    heapspy_reader::source::windows_live::write_dump(pid, &path)?;
    println!("dump written in {:.2?}", t.elapsed());
    *cleanup = Some(Remove(path.clone()));
    Ok(path)
}

#[cfg(not(windows))]
fn capture(_: u32, _: &mut Option<Remove>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Err("--pid is Windows only".into())
}
