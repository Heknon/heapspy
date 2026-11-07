use super::synth::{rsds, DumpBuilder, SynthModule, SynthThread};
use super::*;
use crate::source::{open, SourceSpec};

const TEB: u64 = 0x0000_00a0_0000_1000;
const PEB: u64 = 0x0000_00a0_0000_0000;
const HEAP: u64 = 0x0000_0200_0000_0000;
const STACK: u64 = 0x0000_00b0_0000_f000;
const DLL: u64 = 0x7ff8_1000_0000;

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn info(base: u64, size: u64, alloc: u64, protect: u32, kind: u32) -> MemoryInfo {
    MemoryInfo {
        base,
        allocation_base: alloc,
        allocation_protect: protect,
        size,
        state: mem::MEM_COMMIT,
        protect,
        kind,
    }
}

/// TEB page whose `ProcessEnvironmentBlock` points at the PEB.
fn teb_bytes() -> Vec<u8> {
    let mut t = vec![0u8; 0x100];
    t[0x30..0x38].copy_from_slice(&TEB.to_le_bytes()); // NtTib.Self
    t[0x60..0x68].copy_from_slice(&PEB.to_le_bytes());
    t
}

/// PEB with `NumberOfHeaps = 1` and `ProcessHeaps` pointing at a list
/// stored right after it (at PEB + 0x100).
fn peb_bytes() -> Vec<u8> {
    let mut p = vec![0u8; 0x108];
    p[0xe8..0xec].copy_from_slice(&1u32.to_le_bytes());
    p[0xf0..0xf8].copy_from_slice(&(PEB + 0x100).to_le_bytes());
    p[0x100..0x108].copy_from_slice(&HEAP.to_le_bytes());
    p
}

fn sample() -> DumpBuilder {
    let mut cv_guid = [0u8; 16];
    cv_guid
        .iter_mut()
        .enumerate()
        .for_each(|(i, b)| *b = i as u8);
    let mut dll = SynthModule::new(DLL, 0x1000, r"C:\Program Files\Python313\python313.dll");
    dll.codeview = Some(rsds(cv_guid, 2, "python313.pdb"));
    dll.file_version = Some(((3 << 16) | 13, (1150 << 16) | 1013));
    DumpBuilder {
        memory64: Some(vec![
            (PEB, peb_bytes()),
            (TEB, teb_bytes()),
            (STACK, pattern(0x40, 0x1000)),
            (HEAP, pattern(1, 0x100)),
            (HEAP + 0x100, pattern(2, 0x80)), // adjacent to the previous range
            (HEAP + 0x1000, pattern(3, 0x10)), // after a gap
            (DLL, pattern(4, 0x1000)),
        ]),
        modules: Some(vec![
            SynthModule::new(
                0x7ff6_0000_0000,
                0x2000,
                r"C:\Program Files\Python313\python.exe",
            ),
            dll,
            SynthModule::new(0x7ff8_2000_0000, 0x3000, r"C:\Users\Zoë\näive\ext.pyd"),
        ]),
        threads: Some(vec![
            SynthThread {
                tid: 0x1a2c,
                teb: TEB,
                stack_start: STACK,
                stack_size: 0x1000,
                sp: Some(STACK + 0x800),
            },
            SynthThread {
                tid: 77,
                teb: 0,
                stack_start: 0,
                stack_size: 0,
                sp: None,
            },
        ]),
        thread_names: Some(vec![(0x1a2c, "MainThread".into()), (77, String::new())]),
        memory_info: Some(vec![
            info(PEB, 0x1000, PEB, mem::PAGE_READONLY, mem::MEM_PRIVATE),
            info(TEB, 0x2000, TEB, mem::PAGE_READWRITE, mem::MEM_PRIVATE),
            // Reserved part of the stack, then the committed part.
            MemoryInfo {
                state: mem::MEM_RESERVE,
                ..info(STACK - 0xf000, 0xf000, STACK - 0xf000, 0, mem::MEM_PRIVATE)
            },
            info(
                STACK,
                0x1000,
                STACK - 0xf000,
                mem::PAGE_READWRITE,
                mem::MEM_PRIVATE,
            ),
            info(HEAP, 0x2000, HEAP, mem::PAGE_READWRITE, mem::MEM_PRIVATE),
            info(DLL, 0x1000, DLL, mem::PAGE_EXECUTE_READ, mem::MEM_IMAGE),
            info(
                0x7ff0_0000_0000,
                0x4000,
                0x7ff0_0000_0000,
                mem::PAGE_READONLY,
                mem::MEM_MAPPED,
            ),
            info(
                0x0000_0300_0000_0000,
                0x10_0000,
                0x0000_0300_0000_0000,
                4,
                mem::MEM_PRIVATE,
            ),
        ]),
        misc: Some((4242, 1_699_999_000)),
        ..DumpBuilder::default()
    }
}

fn open_sample() -> Minidump {
    Minidump::from_bytes(sample().build(), MinidumpOptions::default()).unwrap()
}

#[test]
fn reads_within_across_and_outside_ranges() {
    let d = open_sample();
    let mut b = [0u8; 4];
    d.read(HEAP + 2, &mut b).unwrap();
    assert_eq!(b, [3, 4, 5, 6]);

    // Across the boundary of two adjacent ranges.
    let mut b = [0u8; 4];
    d.read(HEAP + 0xfe, &mut b).unwrap();
    assert_eq!(b, [0xff, 0x00, 2, 3]);
    let whole = d.read_vec(HEAP, 0x180).unwrap();
    assert_eq!(&whole[..0x100], &pattern(1, 0x100)[..]);
    assert_eq!(&whole[0x100..], &pattern(2, 0x80)[..]);

    // Into the gap: all-or-nothing, and the buffer is not touched.
    let mut b = [0xaau8; 8];
    let err = d.read(HEAP + 0x17c, &mut b).unwrap_err();
    assert!(matches!(err, Error::Unmapped { addr, len: 8 } if addr == HEAP + 0x17c));
    assert_eq!(b, [0xaa; 8]);
    assert!(d.read(HEAP + 0x180, &mut [0u8; 1]).is_err());
    assert_eq!(d.read_vec(HEAP + 0x1000, 0x10).unwrap(), pattern(3, 0x10));
    assert!(d.read(HEAP + 0x1000, &mut [0u8; 0x11]).is_err());

    // Before the first range, after the last, at the top of the address space.
    assert!(d.read(0, &mut [0u8; 1]).is_err());
    assert!(d.read(PEB - 1, &mut [0u8; 2]).is_err());
    assert!(d.read(DLL + 0x1000, &mut [0u8; 1]).is_err());
    assert!(d.read(u64::MAX, &mut [0u8; 1]).is_err());
    assert!(d.read(u64::MAX - 1, &mut [0u8; 4]).is_err());
    d.read(u64::MAX, &mut []).unwrap();
    d.read(0x1234, &mut []).unwrap();

    // Last byte of the last range.
    assert_eq!(d.read_u8(DLL + 0xfff).unwrap(), 4u8.wrapping_add(0xff));
}

#[test]
fn native_blocks_walk_the_heaps_in_the_dump() {
    use super::nt_heap::off;
    use super::nt_heap::tests::{Img, FIRST, KEY};
    use crate::source::{NativeBlock, NativeBlockKind};

    // The sample's PEB lists HEAP; make it an NT heap, add a second heap
    // that only a scan finds, and give the first a large block in its own
    // reservation (committed and reserved parts).
    let other = HEAP + 0x10_0000;
    let res = 0x0000_0300_0000_0000u64;
    let va = res + 0x5000;
    let mut img = Img::default();
    img.region(HEAP, 0x1000)
        .region(other, 0x1000)
        .region(va, 0x100);
    img.heap(HEAP, 0x1000);
    img.blocks(HEAP + FIRST, &[(0x40, 1, 0x10), (0xdc0, 0, 0)]);
    img.heap(other, 0x1000);
    img.blocks(other + FIRST, &[(0xe00, 1, 0x10)]);
    img.u64(va + off::VA_COMMIT_SIZE, 0x1000);
    img.entry(va + off::VA_BUSY_BLOCK, 0x1000, 3, 0, 0, &KEY);
    img.list(HEAP + off::VIRTUAL_ALLOCD_BLOCKS, &[va]);

    let rw = mem::PAGE_READWRITE;
    let mut b = sample();
    b.memory64 = Some(
        [(PEB, peb_bytes()), (TEB, teb_bytes())]
            .into_iter()
            .chain(img.regions.clone())
            .collect(),
    );
    b.memory_info = Some(vec![
        info(PEB, 0x1000, PEB, mem::PAGE_READONLY, mem::MEM_PRIVATE),
        info(TEB, 0x2000, TEB, rw, mem::MEM_PRIVATE),
        info(HEAP, 0x1000, HEAP, rw, mem::MEM_PRIVATE),
        info(other, 0x1000, other, rw, mem::MEM_PRIVATE),
        info(res, 0x6000, res, rw, mem::MEM_PRIVATE),
        MemoryInfo {
            state: mem::MEM_RESERVE,
            ..info(res + 0x6000, 0x2000, res, 0, mem::MEM_PRIVATE)
        },
    ]);
    let block = |start, size, kind, heap| NativeBlock {
        start,
        size,
        kind,
        heap,
    };
    let small = [
        block(HEAP + FIRST + 8, 0x40, NativeBlockKind::Allocation, 0),
        block(other + FIRST + 8, 0xe00, NativeBlockKind::Allocation, 1),
    ];

    let d = Minidump::from_bytes(b.build(), MinidumpOptions::default()).unwrap();
    let mut want = small.to_vec();
    want.push(block(res, 0x8000, NativeBlockKind::Large, 0));
    assert_eq!(d.native_blocks().unwrap(), Some(want));
    let w = d.native_heap_walk().unwrap();
    assert_eq!(w.heaps, vec![HEAP, other]);
    // Cached: the same walk comes back.
    assert!(std::ptr::eq(w, d.native_heap_walk().unwrap()));

    // Without MemoryInfoListStream the heaps are still found (from the
    // range starts), and the large block is the entry and its commit.
    b.memory_info = None;
    let d = Minidump::from_bytes(b.build(), MinidumpOptions::default()).unwrap();
    let mut want = small.to_vec();
    want.push(block(va, 0x1000, NativeBlockKind::Large, 0));
    assert_eq!(d.native_blocks().unwrap(), Some(want));

    // No heap in the sample dump; not a Windows dump.
    assert_eq!(open_sample().native_blocks().unwrap(), None);
    b.platform_id = 0x8201;
    let d = Minidump::from_bytes(b.build(), MinidumpOptions::default()).unwrap();
    assert_eq!(d.native_blocks().unwrap(), None);
}

#[test]
fn modules_threads_and_metadata() {
    let d = open_sample();
    let mods = d.modules().unwrap();
    assert_eq!(mods.len(), 3);
    assert_eq!(mods[0].name, "python.exe");
    assert_eq!(mods[1].name, "python313.dll");
    assert_eq!(mods[1].path, r"C:\Program Files\Python313\python313.dll");
    assert_eq!(mods[1].base, DLL);
    assert_eq!(mods[1].size, 0x1000);
    let id = mods[1].build_id.as_ref().unwrap();
    assert_eq!(id.len(), 20);
    assert_eq!(&id[..16], &(0u8..16).collect::<Vec<_>>()[..]);
    assert_eq!(&id[16..], &2u32.to_le_bytes());
    assert_eq!(mods[2].name, "ext.pyd");
    assert_eq!(mods[2].path, r"C:\Users\Zoë\näive\ext.pyd");
    assert_eq!(mods[0].build_id, None);

    let det = &d.module_details()[1];
    assert_eq!(det.file_version, Some([3, 13, 1150, 1013]));
    assert_eq!(det.pdb_name.as_deref(), Some("python313.pdb"));
    assert_eq!(det.timestamp, 0x6500_0000);
    assert_eq!(d.module_details()[0].file_version, None);

    let threads = d.threads().unwrap();
    assert_eq!(
        threads[0],
        ThreadInfo {
            tid: 0x1a2c,
            name: Some("MainThread".into()),
            tls_base: Some(TEB),
            stack_pointer: Some(STACK + 0x800),
        }
    );
    assert_eq!(
        threads[1],
        ThreadInfo {
            tid: 77,
            ..ThreadInfo::default()
        }
    );

    assert_eq!(d.target(), TargetInfo::WINDOWS_X86_64);
    assert_eq!(d.captured_at(), Some(1_700_000_000));
    assert_eq!(d.process_id(), Some(4242));
    assert_eq!(d.process_create_time(), Some(1_699_999_000));
    assert_eq!(d.dump_flags(), 0x1806);
    assert!(d.is_full_memory());
    let sys = d.system_info();
    assert_eq!((sys.major_version, sys.build_number), (10, 22631));
    assert!(format!("{d:?}").contains("full_memory: true"));
}

#[test]
fn mapped_ranges_carry_perms_and_image_paths() {
    let d = open_sample();
    let r = d.mapped_ranges().unwrap();
    assert_eq!(r.len(), 7);
    assert!(r.windows(2).all(|w| w[0].start + w[0].size <= w[1].start));
    let heap = r.iter().find(|r| r.start == HEAP).unwrap();
    assert_eq!(
        heap.perms,
        Perms {
            read: true,
            write: true,
            exec: false
        }
    );
    assert_eq!(heap.file, None);
    let dll = r.iter().find(|r| r.start == DLL).unwrap();
    assert!(dll.perms.read && dll.perms.exec && !dll.perms.write);
    assert_eq!(
        dll.file.as_deref(),
        Some(r"C:\Program Files\Python313\python313.dll")
    );
}

#[test]
fn memory_summary_classifies_committed_memory() {
    let d = open_sample();
    let s = d.memory_summary().unwrap();
    let get = |k: RegionKind| {
        s.regions
            .iter()
            .filter(|r| r.kind == k)
            .map(|r| r.mapped_bytes)
            .sum::<u64>()
    };
    assert_eq!(get(RegionKind::Image), 0x1000);
    assert_eq!(get(RegionKind::MappedFile), 0x4000);
    assert_eq!(get(RegionKind::Stack), 0x1000);
    assert_eq!(get(RegionKind::Heap), 0x2000);
    assert_eq!(get(RegionKind::Anonymous), 0x1000 + 0x2000 + 0x10_0000);
    assert!(s.regions.iter().all(|r| r.resident_bytes.is_none()));
    assert_eq!(s.rss_bytes, None);

    let t = d.memory_totals().unwrap();
    assert_eq!(
        t.committed,
        0x1000 + 0x2000 + 0x1000 + 0x2000 + 0x1000 + 0x4000 + 0x10_0000
    );
    assert_eq!(t.reserved, 0xf000);
    assert_eq!(t.image, 0x1000);
    assert_eq!(t.mapped, 0x4000);
    assert_eq!(t.private, t.committed - t.image - t.mapped);
    assert_eq!(
        t.captured,
        0x108 + 0x100 + 0x1000 + 0x100 + 0x80 + 0x10 + 0x1000
    );
}

#[test]
fn optional_streams_may_be_missing() {
    let b = DumpBuilder {
        memory64: Some(vec![(0x1000, vec![1, 2])]),
        ..DumpBuilder::default()
    };
    let d = Minidump::from_bytes(b.build(), MinidumpOptions::default()).unwrap();
    assert!(d.modules().unwrap().is_empty());
    assert!(d.threads().unwrap().is_empty());
    assert!(d.memory_summary().is_none());
    assert!(d.memory_totals().is_none());
    assert_eq!(d.process_id(), None);
    assert_eq!(d.read_u16(0x1000).unwrap(), 0x0201);
    let r = d.mapped_ranges().unwrap();
    assert!(r[0].perms.read && r[0].file.is_none());
    // An empty Memory64ListStream is still a full-memory dump (of nothing).
    let d =
        Minidump::from_bytes(DumpBuilder::default().build(), MinidumpOptions::default()).unwrap();
    assert!(d.mapped_ranges().unwrap().is_empty());
}

#[test]
fn architectures() {
    let arm = DumpBuilder {
        processor_architecture: cpu::ARM64,
        threads: Some(vec![SynthThread {
            tid: 1,
            teb: TEB,
            stack_start: 0,
            stack_size: 0,
            sp: Some(0xdead_0000),
        }]),
        ..DumpBuilder::default()
    };
    let d = Minidump::from_bytes(arm.build(), MinidumpOptions::default()).unwrap();
    assert_eq!(d.target().arch, Arch::Aarch64);
    assert_eq!(d.threads().unwrap()[0].stack_pointer, Some(0xdead_0000));

    for (arch, what) in [(cpu::INTEL, "x86"), (cpu::ARM, "ARM"), (99, "99")] {
        let b = DumpBuilder {
            processor_architecture: arch,
            ..DumpBuilder::default()
        };
        let err = Minidump::from_bytes(b.build(), MinidumpOptions::default()).unwrap_err();
        assert!(
            matches!(&err, Error::Unsupported(m) if m.contains(what)),
            "{err}"
        );
    }
    let b = DumpBuilder {
        system_info: false,
        ..DumpBuilder::default()
    };
    let err = Minidump::from_bytes(b.build(), MinidumpOptions::default()).unwrap_err();
    assert!(err.to_string().contains("SystemInfoStream"), "{err}");
}

#[test]
fn partial_dumps_are_rejected_unless_allowed() {
    let b = DumpBuilder {
        memory64: None,
        memory_list: Some(vec![
            (0x5000, pattern(9, 0x20)),
            // Overlaps the first range: trimmed, the first one wins.
            (0x5010, pattern(50, 0x20)),
            // Fully inside the first: dropped.
            (0x5004, pattern(70, 4)),
            (0x4000, pattern(30, 0x10)),
            (0x9000, Vec::new()),
        ]),
        ..DumpBuilder::default()
    };
    let bytes = b.build();
    let err = Minidump::from_bytes(bytes.clone(), MinidumpOptions::default()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Memory64ListStream") && msg.contains("full-memory"),
        "{msg}"
    );
    assert!(msg.contains("procdump -ma"), "{msg}");

    let d = Minidump::from_bytes(
        bytes,
        MinidumpOptions {
            allow_partial_memory: true,
        },
    )
    .unwrap();
    assert!(!d.is_full_memory());
    let r = d.mapped_ranges().unwrap();
    let spans: Vec<_> = r.iter().map(|r| (r.start, r.size)).collect();
    assert_eq!(spans, [(0x4000, 0x10), (0x5000, 0x20), (0x5020, 0x10)]);
    assert_eq!(d.read_vec(0x5000, 0x20).unwrap(), pattern(9, 0x20));
    assert_eq!(d.read_vec(0x5020, 0x10).unwrap(), pattern(50 + 0x10, 0x10));

    // No memory stream at all, allowed: opens with no memory.
    let b = DumpBuilder {
        memory64: None,
        ..DumpBuilder::default()
    };
    let d = Minidump::from_bytes(
        b.build(),
        MinidumpOptions {
            allow_partial_memory: true,
        },
    )
    .unwrap();
    assert!(d.read(0, &mut [0u8; 1]).is_err());
}

#[test]
fn bad_headers() {
    let good = sample().build();
    assert!(Minidump::from_bytes(Vec::new(), MinidumpOptions::default()).is_err());
    let mut b = good.clone();
    b[0] = b'X';
    let err = Minidump::from_bytes(b, MinidumpOptions::default()).unwrap_err();
    assert!(err.to_string().contains("signature"), "{err}");
    let mut b = good.clone();
    b[4] = 0;
    assert!(Minidump::from_bytes(b, MinidumpOptions::default()).is_err());
    // Stream count far beyond the file.
    let mut b = good.clone();
    b[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Minidump::from_bytes(b, MinidumpOptions::default()).is_err());
    // Directory RVA past the end.
    let mut b = good;
    b[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Minidump::from_bytes(b, MinidumpOptions::default()).is_err());
}

#[test]
fn overflowing_memory_range_is_rejected() {
    let b = DumpBuilder {
        memory64: Some(vec![(u64::MAX - 1, vec![0; 4])]),
        ..DumpBuilder::default()
    };
    assert!(Minidump::from_bytes(b.build(), MinidumpOptions::default()).is_err());
    // A range must end below 2^64 (its end is stored as a u64).
    let b = DumpBuilder {
        memory64: Some(vec![(u64::MAX - 4, vec![7; 4])]),
        ..DumpBuilder::default()
    };
    let d = Minidump::from_bytes(b.build(), MinidumpOptions::default()).unwrap();
    assert_eq!(d.read_u32(u64::MAX - 4).unwrap(), 0x0707_0707);
    assert!(d.read(u64::MAX - 4, &mut [0u8; 5]).is_err());
    assert!(d.read(u64::MAX - 4, &mut [0u8; 6]).is_err());
}

#[test]
fn every_truncation_errors() {
    for data_first in [false, true] {
        let full = DumpBuilder {
            data_first,
            ..sample()
        }
        .build();
        assert!(Minidump::from_bytes(full.clone(), MinidumpOptions::default()).is_ok());
        for len in 0..full.len() {
            let r = Minidump::from_bytes(full[..len].to_vec(), MinidumpOptions::default());
            assert!(
                r.is_err(),
                "prefix of {len} bytes (data_first={data_first}) opened"
            );
        }
    }
}

#[test]
fn a_cut_minidump_is_truncated() {
    // A cut that loses the directory, a stream or captured memory is
    // Truncated. Data that only a stream points to (module names, CodeView
    // records) is checked where it is read, as Format.
    let mut truncated = 0;
    for data_first in [false, true] {
        let full = DumpBuilder {
            data_first,
            ..sample()
        }
        .build();
        for len in parse::HEADER_SIZE as usize..full.len() {
            match Minidump::from_bytes(full[..len].to_vec(), MinidumpOptions::default()) {
                Err(Error::Truncated(_)) => truncated += 1,
                Err(Error::Format(_)) => {}
                r => panic!("prefix of {len} (data_first={data_first}): {:?}", r.err()),
            }
        }
        if !data_first {
            // Captured memory comes last, as MiniDumpWriteDump writes it.
            let r =
                Minidump::from_bytes(full[..full.len() - 1].to_vec(), MinidumpOptions::default());
            assert!(matches!(r, Err(Error::Truncated(_))), "{:?}", r.err());
        }
    }
    assert!(truncated > 0);
}

#[test]
fn shrunk_streams_error_or_parse_but_never_panic() {
    let (full, layout) = sample().build_with_layout();
    for s in &layout {
        for size in 0..s.size {
            let mut b = full.clone();
            b[s.dir_entry + 4..s.dir_entry + 8].copy_from_slice(&(size as u32).to_le_bytes());
            let r = Minidump::from_bytes(b, MinidumpOptions::default());
            if let Ok(d) = &r {
                exercise(d);
            }
            // SystemInfoStream is read only up to PlatformId (24 bytes);
            // every other stream needs all of its bytes.
            if s.stream_type != parse::stream::SYSTEM_INFO || size < 24 {
                assert!(r.is_err(), "stream {} cut to {size} opened", s.stream_type);
            }
        }
    }
}

/// Call every accessor and a spread of reads. Used on fuzzed inputs that
/// happened to parse.
fn exercise(d: &Minidump) {
    let _ = d.target();
    let ranges = d.mapped_ranges().unwrap();
    let _ = d.modules().unwrap();
    let _ = d.threads().unwrap();
    let _ = d.memory_summary();
    let _ = d.memory_totals();
    let _ = d.captured_at();
    let _ = d.native_blocks().unwrap();
    let _ = format!("{d:?}");
    for r in ranges.iter().take(16) {
        let _ = d.read_vec(r.start, r.size.min(0x2000) as usize);
        let _ = d.read(r.start.wrapping_sub(1), &mut [0u8; 3]);
        let _ = d.read(r.start.wrapping_add(r.size).wrapping_sub(1), &mut [0u8; 3]);
    }
    for m in d.modules().unwrap() {
        let _ = d.find_symbol(&m, "_PyRuntime");
    }
}

#[test]
fn corrupted_bytes_never_panic() {
    let full = sample().build();
    // Only fuzz the metadata; the raw memory at the end is opaque bytes.
    let meta_len = full.len()
        - sample()
            .memory64
            .unwrap()
            .iter()
            .map(|r| r.1.len())
            .sum::<usize>();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut opened = 0;
    for _ in 0..3000 {
        let mut b = full.clone();
        for _ in 0..1 + next() % 4 {
            let pos = (next() % meta_len as u64) as usize;
            let v = match next() % 4 {
                0 => 0xff,
                1 => 0,
                2 => 0x80,
                _ => next() as u8,
            };
            b[pos] = v;
        }
        if let Ok(d) = Minidump::from_bytes(b, MinidumpOptions::default()) {
            opened += 1;
            exercise(&d);
        }
    }
    // Most single-byte changes land in data that does not affect structure.
    assert!(opened > 0);
}

#[test]
fn opens_from_disk_through_source_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.dmp");
    std::fs::write(&path, sample().build()).unwrap();
    let d = Minidump::open(&path).unwrap();
    assert_eq!(d.read_vec(HEAP, 4).unwrap(), [1, 2, 3, 4]);
    let src = open(&SourceSpec::Minidump(path.clone())).unwrap();
    assert_eq!(src.modules().unwrap().len(), 3);
    assert_eq!(src.read_u32(HEAP + 0x1000).unwrap(), 0x0605_0403);
    // Unmap before rewriting: Windows refuses to truncate a mapped file.
    drop(d);
    drop(src);

    std::fs::write(&path, b"MDMP").unwrap();
    assert!(matches!(Minidump::open(&path), Err(Error::Format(_))));
    assert!(matches!(
        Minidump::open(&dir.path().join("missing.dmp")),
        Err(Error::Io(_))
    ));
}

#[test]
fn resolves_py_runtime_from_a_pe_image_in_the_dump() {
    use crate::symbols::pe::test_image::{build, Target};
    use crate::symbols::{find_python_module, pe};

    const BASE: u64 = 0x7ffa_0000_0000;
    let image = build(
        BASE,
        "python313.dll",
        &[
            ("_PyRuntime", Target::Rva(0x2a00)),
            ("PyFwd", Target::Forward("KERNEL32.HeapAlloc")),
        ],
    );
    // Split the image over two adjacent ranges, as a dump splits regions
    // with different protections.
    let mut dll = SynthModule::new(BASE, image.len() as u32, r"C:\Python313\python313.dll");
    dll.file_version = Some(((3 << 16) | 13, (5150 << 16) | 1013));
    let b = DumpBuilder {
        memory64: Some(vec![
            (BASE, image[..0x1000].to_vec()),
            (BASE + 0x1000, image[0x1000..].to_vec()),
        ]),
        modules: Some(vec![
            SynthModule::new(0x7ff6_0000_0000, 0x1000, r"C:\Python313\python.exe"),
            SynthModule::new(0x7ff9_0000_0000, 0x1000, r"C:\Python313\python3.dll"),
            dll,
        ]),
        ..DumpBuilder::default()
    };
    let d = Minidump::from_bytes(b.build(), MinidumpOptions::default()).unwrap();
    let mods = d.modules().unwrap();
    let py = find_python_module(&mods).unwrap();
    assert_eq!(py.name, "python313.dll");
    assert_eq!(
        d.find_symbol(py, "_PyRuntime").unwrap(),
        Some(BASE + 0x2a00)
    );
    assert_eq!(d.find_symbol(py, "PyFwd").unwrap(), None);
    // python.exe has no image bytes in this dump.
    assert!(matches!(
        d.find_symbol(&mods[0], "_PyRuntime"),
        Err(Error::Unmapped { .. })
    ));

    let dll = pe::python_dll(&py.name).unwrap();
    assert_eq!((dll.major, dll.minor, dll.free_threaded), (3, 13, false));
    let fv = d.module_details()[2].file_version.unwrap();
    let v = pe::python_version_from_file_version(fv).unwrap();
    assert_eq!(v.to_string(), "3.13.5");
}
