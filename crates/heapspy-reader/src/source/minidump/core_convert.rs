//! Convert a Linux ELF core (from `gcore`) into an equivalent minidump and
//! check that [`Minidump`] reads the same bytes as the core holds.
//!
//! This runs the parser on a real process layout: hundreds of ranges,
//! adjacent and with gaps, megabytes to gigabytes of data, and real module
//! paths. The core is parsed by hand (ELF64 little-endian only) so the test
//! needs no extra dependencies.
//!
//! Run it with a core of a Python process:
//!
//! ```sh
//! python3 -c 'import time; time.sleep(600)' & gcore -o /tmp/py $!
//! HEAPSPY_TEST_CORE=/tmp/py.<pid> cargo test -p heapspy-reader gcore -- --ignored --nocapture
//! ```

use std::io::Write;

use super::synth::{DumpBuilder, SynthModule, SynthThread};
use super::{mem, MemoryInfo, Minidump};
use crate::source::{MemorySource, MemorySourceExt};

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const NT_PRSTATUS: u32 = 1;
const NT_FILE: u32 = 0x4649_4c45;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[derive(Clone, Copy, Debug)]
struct Load {
    vaddr: u64,
    offset: usize,
    filesz: u64,
    memsz: u64,
    flags: u32,
}

struct Core<'a> {
    data: &'a [u8],
    loads: Vec<Load>,
    /// NT_FILE entries: (start, end, path).
    files: Vec<(u64, u64, String)>,
    /// NT_PRSTATUS: (tid, rsp, fs_base).
    threads: Vec<(u32, u64, u64)>,
}

fn parse_core(data: &[u8]) -> Core<'_> {
    assert_eq!(&data[..4], b"\x7fELF", "not an ELF file");
    assert_eq!(data[4], 2, "only ELF64 cores");
    assert_eq!(data[5], 1, "only little-endian cores");
    assert_eq!(u16_at(data, 0x10), 4, "not a core file (e_type != ET_CORE)");
    assert_eq!(u16_at(data, 0x12), 62, "only x86_64 cores");
    let phoff = u64_at(data, 0x20) as usize;
    let phentsize = u16_at(data, 0x36) as usize;
    let phnum = u16_at(data, 0x38) as usize;
    let mut core = Core {
        data,
        loads: Vec::new(),
        files: Vec::new(),
        threads: Vec::new(),
    };
    for i in 0..phnum {
        let ph = &data[phoff + i * phentsize..][..56];
        let (ty, flags) = (u32_at(ph, 0), u32_at(ph, 4));
        let offset = u64_at(ph, 8) as usize;
        let filesz = u64_at(ph, 32);
        match ty {
            PT_LOAD => core.loads.push(Load {
                vaddr: u64_at(ph, 16),
                offset,
                filesz,
                memsz: u64_at(ph, 40),
                flags,
            }),
            PT_NOTE => parse_notes(&data[offset..offset + filesz as usize], &mut core),
            _ => {}
        }
    }
    core.loads.sort_by_key(|l| l.vaddr);
    core
}

fn parse_notes(mut notes: &[u8], core: &mut Core) {
    let align = |n: usize| (n + 3) & !3;
    while notes.len() >= 12 {
        let namesz = u32_at(notes, 0) as usize;
        let descsz = u32_at(notes, 4) as usize;
        let ty = u32_at(notes, 8);
        let desc_at = 12 + align(namesz);
        let desc = &notes[desc_at..desc_at + descsz];
        match ty {
            // struct elf_prstatus (x86_64): pr_pid at 32, pr_reg at 112;
            // in user_regs_struct rsp is register 19 and fs_base 21.
            NT_PRSTATUS if descsz >= 112 + 27 * 8 => core.threads.push((
                u32_at(desc, 32),
                u64_at(desc, 112 + 19 * 8),
                u64_at(desc, 112 + 21 * 8),
            )),
            NT_FILE => {
                let count = u64_at(desc, 0) as usize;
                let mut names = desc[16 + count * 24..].split(|&b| b == 0);
                for k in 0..count {
                    let e = &desc[16 + k * 24..][..24];
                    let name = names.next().unwrap_or_default();
                    core.files.push((
                        u64_at(e, 0),
                        u64_at(e, 8),
                        String::from_utf8_lossy(name).into_owned(),
                    ));
                }
            }
            _ => {}
        }
        notes = &notes[(desc_at + align(descsz)).min(notes.len())..];
    }
}

fn protect(flags: u32) -> u32 {
    match (flags & PF_R != 0, flags & PF_W != 0, flags & PF_X != 0) {
        (_, true, true) => mem::PAGE_EXECUTE_READWRITE,
        (_, false, true) => mem::PAGE_EXECUTE_READ,
        (_, true, false) => mem::PAGE_READWRITE,
        (true, false, false) => mem::PAGE_READONLY,
        _ => mem::PAGE_NOACCESS,
    }
}

/// Write `core` as a minidump to `out`, streaming the memory.
fn convert(core: &Core, out: &mut impl Write) {
    // Modules: NT_FILE mappings grouped by path, in first-seen order.
    let mut modules: Vec<SynthModule> = Vec::new();
    for (start, end, path) in &core.files {
        match modules.iter_mut().find(|m| &m.path == path) {
            Some(m) => {
                let new_base = m.base.min(*start);
                let new_end = (m.base + u64::from(m.size)).max(*end);
                m.base = new_base;
                m.size = (new_end - new_base) as u32;
            }
            None => modules.push(SynthModule::new(*start, (end - start) as u32, path)),
        }
    }
    let in_file = |a: u64| core.files.iter().any(|(s, e, _)| a >= *s && a < *e);
    let dumped: Vec<&Load> = core.loads.iter().filter(|l| l.filesz > 0).collect();
    let b = DumpBuilder {
        memory64: None,
        memory64_external: Some(dumped.iter().map(|l| (l.vaddr, l.filesz)).collect()),
        modules: Some(modules),
        threads: Some(
            core.threads
                .iter()
                .map(|&(tid, sp, fs)| SynthThread {
                    tid,
                    teb: fs,
                    stack_start: sp,
                    stack_size: 0,
                    sp: Some(sp),
                })
                .collect(),
        ),
        memory_info: Some(
            core.loads
                .iter()
                .map(|l| MemoryInfo {
                    base: l.vaddr,
                    allocation_base: l.vaddr,
                    allocation_protect: protect(l.flags),
                    size: l.memsz,
                    state: mem::MEM_COMMIT,
                    protect: protect(l.flags),
                    kind: if in_file(l.vaddr) {
                        mem::MEM_IMAGE
                    } else {
                        mem::MEM_PRIVATE
                    },
                })
                .collect(),
        ),
        misc: Some((core.threads.first().map_or(0, |t| t.0), 0)),
        ..DumpBuilder::default()
    };
    out.write_all(&b.build()).unwrap();
    for l in dumped {
        out.write_all(&core.data[l.offset..l.offset + l.filesz as usize])
            .unwrap();
    }
}

/// The bytes the core holds at `[addr, addr + len)`, if all of them are in
/// dumped segments (the zero-filled tail of a segment does not count).
fn core_read(core: &Core, addr: u64, len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    let mut cur = addr;
    let end = addr.checked_add(len as u64)?;
    while cur < end {
        let l = core
            .loads
            .iter()
            .find(|l| l.filesz > 0 && cur >= l.vaddr && cur < l.vaddr + l.filesz)?;
        let take = (end.min(l.vaddr + l.filesz) - cur) as usize;
        let off = l.offset + (cur - l.vaddr) as usize;
        out.extend_from_slice(&core.data[off..off + take]);
        cur += take as u64;
    }
    Some(out)
}

#[test]
#[ignore = "needs HEAPSPY_TEST_CORE=<path to a gcore core file>"]
fn gcore_converted_to_minidump_reads_the_same_bytes() {
    let Some(path) = std::env::var_os("HEAPSPY_TEST_CORE") else {
        eprintln!("HEAPSPY_TEST_CORE is not set; skipping");
        return;
    };
    let file = std::fs::File::open(&path).unwrap();
    // SAFETY: test-only read-only mapping of a file nobody modifies.
    #[allow(unsafe_code)]
    let map = unsafe { memmap2::Mmap::map(&file).unwrap() };
    let core = parse_core(&map);
    assert!(!core.loads.is_empty() && !core.threads.is_empty());

    let dir = tempfile::tempdir().unwrap();
    let dmp = dir.path().join("converted.dmp");
    let mut w = std::io::BufWriter::new(std::fs::File::create(&dmp).unwrap());
    convert(&core, &mut w);
    w.into_inner().unwrap().sync_all().unwrap();
    let d = Minidump::open(&dmp).unwrap();

    // Metadata round trip.
    let threads = d.threads().unwrap();
    assert_eq!(threads.len(), core.threads.len());
    for (t, &(tid, sp, fs)) in threads.iter().zip(&core.threads) {
        assert_eq!(
            (t.tid, t.stack_pointer, t.tls_base),
            (tid.into(), Some(sp), Some(fs))
        );
    }
    let modules = d.modules().unwrap();
    assert!(modules
        .iter()
        .any(|m| m.name.starts_with("python") || m.name.starts_with("libpython")));
    let ranges = d.mapped_ranges().unwrap();
    let dumped = core.loads.iter().filter(|l| l.filesz > 0).count();
    assert_eq!(ranges.len(), dumped);
    assert!(d.memory_summary().is_some());

    // Every byte of every range, in large chunks.
    let mut total = 0u64;
    for r in &ranges {
        let mut a = r.start;
        while a < r.start + r.size {
            let n = (r.start + r.size - a).min(1 << 20) as usize;
            assert_eq!(d.read_vec(a, n).unwrap(), core_read(&core, a, n).unwrap());
            a += n as u64;
            total += n as u64;
        }
    }

    // Random reads, including ones that cross range ends and fall into gaps.
    let mut state = 0x853c_49e6_748f_ea9bu64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let (mut ok, mut unmapped) = (0, 0);
    for _ in 0..200_000 {
        let r = &ranges[(next() % ranges.len() as u64) as usize];
        let len = 1 + (next() % 8192) as usize;
        let addr = match next() % 4 {
            // Near the end, to cross into the next range or a gap.
            0 => (r.start + r.size).saturating_sub(next() % 64),
            _ => r.start + next() % r.size,
        };
        let expect = core_read(&core, addr, len);
        let got = d.read_vec(addr, len);
        match expect {
            Some(bytes) => {
                assert_eq!(got.unwrap(), bytes, "read {addr:#x}+{len}");
                ok += 1;
            }
            None => {
                assert!(got.is_err(), "read {addr:#x}+{len} should fail");
                unmapped += 1;
            }
        }
    }
    // Segments gcore did not dump read as unmapped, not zeros.
    for l in core.loads.iter().filter(|l| l.filesz == 0) {
        if core_read(&core, l.vaddr, 1).is_none() {
            assert!(d.read_u8(l.vaddr).is_err());
        }
    }
    eprintln!(
        "{} ranges, {} modules, {} threads, {total} bytes compared; \
         {ok} random reads matched, {unmapped} correctly unmapped",
        ranges.len(),
        modules.len(),
        threads.len()
    );
}
