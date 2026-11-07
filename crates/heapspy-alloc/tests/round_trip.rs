use heapspy_alloc::format::*;
use heapspy_alloc::*;

fn sample_builder() -> ProfileBuilder {
    let mut b = ProfileBuilder::new();
    {
        let i = b.info_mut();
        i.pid = 4242;
        i.python = PythonVersion::new(3, 13, 2);
        i.os = Os::Windows;
        i.start_ns = 1_700_000_000_000_000_000;
        i.end_ns = 1_700_000_060_000_000_000;
        i.mechanisms = Mechanisms::of(&[Mechanism::Etw, Mechanism::Debugger]);
        i.sampling = SamplingParams {
            events: EventKinds::of(&[EventKind::Arena, EventKind::LargeObject]),
            byte_interval: 1 << 20,
            max_frames: 32,
            native_min_size: 8192,
        };
        i.overhead = Overhead {
            samples_taken: 5,
            samples_dropped: 2,
            probe_hits: 900,
            total_pause_ns: 12_345,
        };
        i.truncated = true;
    }
    let load = b.code_with_lines(
        0x7f00_1000,
        "Cache.load",
        "app/cache.py",
        10,
        &[(8, 10), (8, 12)],
    );
    let main = b.code_with_lines(0x7f00_2000, "main", "app/main.py", 1, &[(64, 3)]);
    let gone = b.unresolved_code(0x7f00_3000);
    // Same address as `load`: a later code object reusing the memory.
    let again = b.code_with_lines(0x7f00_1000, "<lambda>", "app/cache.py", 99, &[(4, 99)]);

    let t0 = 1_700_000_001_000_000_000;
    b.sample(EventKind::Arena, 0x7f10_0000_0000, 1 << 20)
        .at(t0 + 30)
        .tid(7)
        .native_return(0x7ff8_0000_1234)
        .frame(load, 10)
        .frame(main, 4);
    b.sample(EventKind::LargeObject, 0x5555_0000, 4096)
        .at(t0 + 10)
        .tid(8)
        .weight(1 << 20)
        .approximate_frame(main, 0)
        .flags(SampleFlags::APPROXIMATE_FRAMES);
    b.sample(EventKind::Pool, 0x7f10_0000_4000, 16 << 10)
        .at(t0 + 20)
        .tid(7)
        .frame(gone, 6)
        .unknown_frame()
        .frame_no_offset(load)
        .flags(SampleFlags::STACK_TRUNCATED);
    b.sample(EventKind::Unknown(77), 0x9000, 600)
        .at(t0 + 20)
        .tid(9);
    b.sample(EventKind::Other, 0xa000, 700)
        .at(t0 + 40)
        .tid(9)
        .flags(SampleFlags::NO_THREAD_STATE)
        .frame(again, 0);
    b.meta("heapspy.version", "0.1.0");
    b
}

fn check(p: &Profile) {
    let i = p.info();
    assert_eq!(i.format_version, 1);
    assert_eq!(i.pid, 4242);
    assert_eq!(i.python, PythonVersion::new(3, 13, 2));
    assert_eq!(i.os, Os::Windows);
    assert_eq!(i.arch, Arch::X86_64);
    assert_eq!(i.pointer_size, 8);
    assert_eq!(i.duration_ns(), 60_000_000_000);
    assert_eq!(
        i.mechanisms.iter().collect::<Vec<_>>(),
        [Mechanism::Etw, Mechanism::Debugger]
    );
    assert_eq!(i.sampling.byte_interval, 1 << 20);
    assert_eq!(i.sampling.max_frames, 32);
    assert_eq!(i.sampling.native_min_size, 8192);
    assert!(i.sampling.events.contains(EventKind::LargeObject));
    assert!(!i.sampling.events.contains(EventKind::Pool));
    assert_eq!(i.overhead.samples_dropped, 2);
    assert_eq!(i.overhead.probe_hits, 900);
    assert_eq!(i.overhead.total_pause_ns, 12_345);
    assert!(i.truncated);
    assert!(p.unknown_sections().is_empty());
    assert_eq!(p.meta_value("heapspy.version").unwrap(), Some("0.1.0"));
    assert_eq!(p.meta_value("nope").unwrap(), None);

    assert_eq!(p.code_count(), 4);
    let at: Vec<_> = p.codes_at(0x7f00_1000).map(|c| c.id).collect();
    assert_eq!(at, [CodeId(0), CodeId(3)]);
    assert_eq!(p.codes_at(0x1).count(), 0);
    let gone = p.code(CodeId(2)).unwrap();
    assert!(gone.unresolved);
    assert_eq!(p.code_qualname(&gone), None);
    assert!(p.code(CodeId(4)).is_none());

    // Sorted by time; the two samples at t0+20 keep insertion order.
    assert_eq!(p.sample_count(), 5);
    let kinds: Vec<_> = p.samples().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        [
            EventKind::LargeObject,
            EventKind::Pool,
            EventKind::Unknown(77),
            EventKind::Arena,
            EventKind::Other
        ]
    );
    let ts: Vec<_> = p.samples().map(|s| s.timestamp_ns).collect();
    assert!(ts.windows(2).all(|w| w[0] <= w[1]));
    // Frames per sample, in time order: 1, 3, 0, 2, 1.
    assert_eq!(p.frame_count(), 7);

    let large = p.sample(0).unwrap();
    assert_eq!(large.weight, 1 << 20);
    assert_eq!(large.size, 4096);
    assert_eq!(large.tid, 8);
    assert_eq!(large.native_return_address, None);
    assert!(large.flags.contains(SampleFlags::APPROXIMATE_FRAMES));
    let st: Vec<_> = p.stack(&large).collect();
    assert_eq!(st.len(), 1);
    assert!(st[0].approximate);
    assert_eq!(st[0].to_string(), "main (app/main.py:3) ~");

    let pool = p.sample(1).unwrap();
    assert!(pool.flags.contains(SampleFlags::STACK_TRUNCATED));
    let st: Vec<String> = p.stack(&pool).map(|f| f.to_string()).collect();
    assert_eq!(
        st,
        [
            "<unknown> (<unknown>)",
            "<unknown> (<unknown>)",
            "Cache.load (app/cache.py:10)"
        ]
    );
    let raw: Vec<_> = p.frames(&pool).collect();
    assert_eq!(raw[0].code, Some(CodeId(2)));
    assert_eq!(raw[0].instr_offset, Some(6));
    assert_eq!(raw[1].code, None);
    assert_eq!(raw[2].instr_offset, None);
    assert_eq!(p.resolve(raw[0]).code_addr, Some(0x7f00_3000));

    let unknown = p.sample(2).unwrap();
    assert_eq!(unknown.kind.code(), 77);
    assert_eq!(p.stack(&unknown).len(), 0);

    let arena = p.sample(3).unwrap();
    assert_eq!(arena.range(), 0x7f10_0000_0000..0x7f10_0010_0000);
    assert_eq!(arena.native_return_address, Some(0x7ff8_0000_1234));
    assert_eq!(arena.weight, 1 << 20);
    let st: Vec<_> = p.stack(&arena).collect();
    assert_eq!(st[0].function(), "Cache.load");
    assert_eq!(st[0].location(), "app/cache.py:12");
    assert_eq!(st[0].code_addr, Some(0x7f00_1000));
    assert_eq!(st[1].location(), "app/main.py:3");
    assert!(!st[1].approximate);

    let other = p.sample(4).unwrap();
    assert!(other.flags.contains(SampleFlags::NO_THREAD_STATE));
    assert_eq!(
        p.stack(&other).next().unwrap().to_string(),
        "<lambda> (app/cache.py:99)"
    );
}

#[test]
fn round_trip_bytes() {
    let p = Profile::from_bytes(sample_builder().to_bytes().unwrap()).unwrap();
    check(&p);
}

#[test]
fn round_trip_file_mmap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.hpya");
    let stats = sample_builder().write_to(&path).unwrap();
    assert_eq!(stats.samples, 5);
    assert_eq!(stats.codes, 4);
    assert_eq!(stats.bytes_written, std::fs::metadata(&path).unwrap().len());
    check(&Profile::open(&path).unwrap());
}

/// Native heap samples: kind code 4, the returned pointer and the requested
/// size, a byte-sampler weight, the native caller, and the size floor in
/// the header.
#[test]
fn native_samples_round_trip() {
    let mut b = ProfileBuilder::new();
    b.info_mut().os = Os::Windows;
    b.info_mut().mechanisms = Mechanisms::of(&[Mechanism::Debugger]);
    b.info_mut().sampling.events = EventKinds::of(&[EventKind::Native]);
    b.info_mut().sampling.native_min_size = 4096;
    let pin = b.code_with_lines(0x7f00_1000, "pin_buffer", "shop/native.py", 7, &[(16, 8)]);
    b.sample(EventKind::Native, 0x2a0_0000_1040, 1 << 20)
        .weight(sampled_weight(1 << 20, 512 << 10))
        .native_return(0x7ffa_1234_5678)
        .frame(pin, 4);
    let bytes = b.to_bytes().unwrap();
    // The kind byte of the one sample record is 4.
    let samples = section_entry(&bytes, SK_SAMPLES);
    let off = u64::from_le_bytes(bytes[samples + 8..samples + 16].try_into().unwrap()) as usize;
    assert_eq!(bytes[off + RECORD_SECTION_HEADER_LEN + 60], 4);

    let p = Profile::from_bytes(bytes.clone()).unwrap();
    assert_eq!(p.info().sampling.native_min_size, 4096);
    assert_eq!(
        p.info().sampling.events.iter().collect::<Vec<_>>(),
        [EventKind::Native]
    );
    let s = p.sample(0).unwrap();
    assert_eq!(s.kind, EventKind::Native);
    assert!(s.kind.is_byte_sampled());
    assert_eq!(s.kind.as_str(), "native");
    assert_eq!(s.range(), 0x2a0_0000_1040..0x2a0_0010_1040);
    assert_eq!(s.weight, sampled_weight(1 << 20, 512 << 10));
    assert_eq!(s.native_return_address, Some(0x7ffa_1234_5678));
    let st: Vec<String> = p.stack(&s).map(|f| f.to_string()).collect();
    assert_eq!(st, ["pin_buffer (shop/native.py:8)"]);

    // A file written before the field existed has zeros there: no floor.
    let mut old = bytes;
    old[H_NATIVE_MIN_SIZE..H_NATIVE_MIN_SIZE + 4].copy_from_slice(&[0; 4]);
    let p = Profile::from_bytes(old).unwrap();
    assert_eq!(p.info().sampling.native_min_size, 0);
}

fn writer_flow(spill: Option<&std::path::Path>) -> Vec<u8> {
    let info = ProfileInfo::new_for_test();
    let mut w = match spill {
        Some(d) => AllocWriter::with_spill_dir(info, d).unwrap(),
        None => AllocWriter::new(info).unwrap(),
    };
    // Recording: only code addresses are known.
    let a = w.code_for_addr(0x1000).unwrap();
    let b = w.code_for_addr(0x2000).unwrap();
    assert_eq!(w.code_for_addr(0x1000).unwrap(), a);
    assert!(w.code_is_unresolved(a));
    for i in 0..1000u64 {
        let frames = [
            FrameInput {
                code: Some(a),
                instr_offset: Some((i % 4) as u32 * 2),
                approximate: false,
            },
            FrameInput {
                code: Some(b),
                instr_offset: Some(0),
                approximate: false,
            },
        ];
        let n = (i % 3) as usize;
        w.add_sample(
            &SampleInput {
                // Out of order on purpose.
                timestamp_ns: (i * 7919) % 1000,
                tid: i % 5,
                kind: EventKind::LargeObject,
                address: 0x10_0000 + i * 0x1000,
                size: 1000 + i,
                weight: sampled_weight(1000 + i, 4096),
                native_return_address: None,
                flags: SampleFlags::NONE,
            },
            &frames[..n],
        )
        .unwrap();
    }
    // After recording: resolve the codes.
    let lt = linetable::encode_lines(5, &[(8, Some(5)), (8, Some(6))]);
    w.set_code(a, &CodeInput::new(0x1000, "f", "m.py", 5, &lt))
        .unwrap();
    assert!(!w.code_is_unresolved(a));
    assert!(matches!(
        w.set_code(b, &CodeInput::new(0x9999, "g", "m.py", 1, &lt)),
        Err(Error::InvalidArgument(_))
    ));
    w.info_mut().end_ns = 1000;
    w.finish_to_vec().unwrap()
}

#[test]
fn spill_to_dir_matches_memory() {
    let dir = tempfile::tempdir().unwrap();
    let a = writer_flow(None);
    let b = writer_flow(Some(dir.path()));
    assert_eq!(a, b);
    let p = Profile::from_bytes(a).unwrap();
    assert_eq!(p.sample_count(), 1000);
    assert_eq!(p.info().end_ns, 1000);
    let ts: Vec<_> = p.samples().map(|s| s.timestamp_ns).collect();
    assert_eq!(ts, (0..1000).collect::<Vec<_>>());
    for s in p.samples() {
        // timestamp t came from i with i*7919 % 1000 == t.
        let i = (0..1000u64)
            .find(|i| i * 7919 % 1000 == s.timestamp_ns)
            .unwrap();
        assert_eq!(s.address, 0x10_0000 + i * 0x1000);
        assert_eq!(s.frame_count as u64, i % 3);
        let st: Vec<_> = p.stack(&s).collect();
        if let Some(f) = st.first() {
            assert_eq!(f.function(), "f");
            let want = if (i % 4) * 2 < 8 { 5 } else { 6 };
            assert_eq!(f.line, Some(want));
        }
        if let Some(g) = st.get(1) {
            assert_eq!(g.function(), "<unknown>");
            assert_eq!(g.code_addr, Some(0x2000));
            assert_eq!(g.line, None);
        }
    }
}

#[test]
fn empty_profile() {
    let p = ProfileBuilder::new().build().unwrap();
    assert_eq!(p.sample_count(), 0);
    assert_eq!(p.frame_count(), 0);
    assert_eq!(p.code_count(), 0);
    assert_eq!(p.string_count(), 0);
    assert!(p.sample(0).is_none());
}

#[test]
fn writer_rejects_bad_code_ids() {
    let mut w = AllocWriter::new(ProfileInfo::new_for_test()).unwrap();
    let r = w.add_sample(
        &SampleInput::default(),
        &[FrameInput {
            code: Some(CodeId(0)),
            ..FrameInput::default()
        }],
    );
    assert!(matches!(r, Err(Error::InvalidCode(0))));
    assert!(matches!(
        w.set_code(CodeId(3), &CodeInput::default()),
        Err(Error::InvalidCode(3))
    ));
}

#[test]
fn unknown_version_rejected() {
    let mut bytes = sample_builder().to_bytes().unwrap();
    bytes[H_VERSION..H_VERSION + 2].copy_from_slice(&2u16.to_le_bytes());
    match Profile::from_bytes(bytes) {
        Err(Error::UnsupportedVersion {
            found: 2,
            supported: 1,
        }) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn bad_magic_rejected() {
    assert!(matches!(
        Profile::from_bytes(b"HPSY\x01\x00....".to_vec()),
        Err(Error::BadMagic)
    ));
    assert!(matches!(
        Profile::from_bytes(Vec::new()),
        Err(Error::BadMagic)
    ));
}

fn section_entry(bytes: &[u8], kind: u32) -> usize {
    let n = u32::from_le_bytes(
        bytes[H_SECTION_COUNT..H_SECTION_COUNT + 4]
            .try_into()
            .unwrap(),
    );
    (0..n as usize)
        .map(|i| HEADER_LEN + i * SECTION_ENTRY_LEN)
        .find(|&e| u32::from_le_bytes(bytes[e..e + 4].try_into().unwrap()) == kind)
        .unwrap()
}

#[test]
fn unknown_sections() {
    let bytes = sample_builder().to_bytes().unwrap();
    // Relabel the meta section as an unknown optional kind: skipped.
    let e = section_entry(&bytes, SK_META);
    let mut b = bytes.clone();
    b[e..e + 4].copy_from_slice(&99u32.to_le_bytes());
    let p = Profile::from_bytes(b.clone()).unwrap();
    assert_eq!(p.unknown_sections(), [99]);
    assert_eq!(p.meta_value("heapspy.version").unwrap(), None);
    // Marked required: refused.
    b[e + 4..e + 8].copy_from_slice(&SF_REQUIRED.to_le_bytes());
    assert!(matches!(
        Profile::from_bytes(b),
        Err(Error::UnknownRequiredSection(99))
    ));
    // A required section relabelled: missing.
    let e = section_entry(&bytes, SK_CODES);
    let mut b = bytes;
    b[e..e + 4].copy_from_slice(&98u32.to_le_bytes());
    b[e + 4..e + 8].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(
        Profile::from_bytes(b),
        Err(Error::MissingSection("codes"))
    ));
}

#[test]
fn truncated_file_rejected_at_every_length() {
    let bytes = sample_builder().to_bytes().unwrap();
    for cut in 0..bytes.len() {
        let r = Profile::from_bytes(bytes[..cut].to_vec());
        assert!(
            r.is_err(),
            "accepted a file cut at {cut} of {}",
            bytes.len()
        );
    }
}

#[test]
fn truncated_with_patched_length_rejected() {
    // Cut the file and patch file_len so the header agrees; the section
    // bounds checks must still catch it.
    let bytes = sample_builder().to_bytes().unwrap();
    for cut in (HEADER_LEN..bytes.len()).step_by(3) {
        let mut b = bytes[..cut].to_vec();
        b[H_FILE_LEN..H_FILE_LEN + 8].copy_from_slice(&(cut as u64).to_le_bytes());
        assert!(Profile::from_bytes(b).is_err(), "accepted cut at {cut}");
    }
}

/// Use every accessor; none may panic on a file that opened.
fn exercise(p: &Profile) {
    let _ = p.info();
    for c in p.codes() {
        let _ = p.code_qualname(&c);
        let _ = p.code_filename(&c);
        let _ = p.code_linetable(&c);
        for off in [None, Some(0), Some(7), Some(u32::MAX)] {
            let _ = p.line(&c, off);
        }
        let _ = p.codes_at(c.addr).count();
    }
    for s in p.samples() {
        for f in p.stack(&s) {
            let _ = f.location();
        }
        let _ = p.frames(&s).count();
    }
    for i in 0..p.string_count() + 2 {
        let _ = p.string(StrId(i as u32));
    }
    for i in 0..p.blob_count() + 2 {
        let _ = p.blob(BlobId(i as u32));
    }
    let _ = p.meta_value("heapspy.version");
    // A sample from elsewhere with a wild frame range.
    let wild = Sample {
        index: 0,
        timestamp_ns: 0,
        tid: 0,
        kind: EventKind::Arena,
        address: 0,
        size: 0,
        weight: 0,
        native_return_address: None,
        frame_start: u64::MAX - 3,
        frame_count: u32::MAX,
        flags: SampleFlags::NONE,
    };
    let _ = p.stack(&wild).count();
}

#[test]
fn corrupted_bytes_never_panic() {
    let bytes = sample_builder().to_bytes().unwrap();
    for p in 0..bytes.len() {
        for v in [0x00u8, 0xff, 0x80, 0x01] {
            if bytes[p] == v {
                continue;
            }
            let mut b = bytes.clone();
            b[p] = v;
            if let Ok(prof) = Profile::from_bytes(b) {
                exercise(&prof);
            }
        }
    }
}

#[test]
fn random_corruption_never_panics() {
    let bytes = sample_builder().to_bytes().unwrap();
    // xorshift64*, fixed seed: reproducible.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    };
    let mut accepted = 0;
    for _ in 0..20_000 {
        let mut b = bytes.clone();
        let flips = 1 + next() % 8;
        for _ in 0..flips {
            let at = (next() % b.len() as u64) as usize;
            b[at] = next() as u8;
        }
        if next() % 16 == 0 {
            let cut = (next() % b.len() as u64) as usize;
            b.truncate(cut);
        }
        if let Ok(p) = Profile::from_bytes(b) {
            accepted += 1;
            exercise(&p);
        }
    }
    // Most single-byte changes inside records are still well-formed files.
    assert!(accepted > 0);
}

#[test]
fn million_sample_round_trip() {
    const N: u64 = 1_000_000;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.hpya");
    let mut info = ProfileInfo::new_for_test();
    info.start_ns = 10;
    let mut w = AllocWriter::with_spill_dir(info, dir.path()).unwrap();
    let lt = linetable::encode_lines(1, &[(16, Some(1)), (16, Some(2)), (16, Some(3))]);
    let codes: Vec<CodeId> = (0..50u64)
        .map(|c| {
            let name = format!("mod{}.func{c}", c % 7);
            w.add_code(&CodeInput::new(
                0x7f00_0000 + c * 0x100,
                &name,
                "big.py",
                1,
                &lt,
            ))
            .unwrap()
        })
        .collect();
    let mut frames = Vec::with_capacity(4);
    for i in 0..N {
        frames.clear();
        for d in 0..(i % 4) {
            frames.push(FrameInput {
                code: Some(codes[((i + d) % 50) as usize]),
                instr_offset: Some(((i + d) % 24) as u32 * 2),
                approximate: false,
            });
        }
        w.add_sample(
            &SampleInput {
                timestamp_ns: 10 + i,
                tid: i % 13,
                kind: EventKind::from_code((i % 4) as u8),
                address: 0x1_0000_0000 + i * 64,
                size: 512 + i % 1024,
                weight: 512 + i % 1024,
                native_return_address: Some(0x4000 + i % 97),
                flags: SampleFlags::NONE,
            },
            &frames,
        )
        .unwrap();
    }
    let stats = w.finish_to_path(&path).unwrap();
    assert_eq!(stats.samples, N);
    assert_eq!(stats.frames, (0..N).map(|i| i % 4).sum::<u64>());

    let p = Profile::open(&path).unwrap();
    assert_eq!(p.sample_count(), N);
    let mut weight = 0u64;
    for s in p.samples() {
        weight += s.weight;
    }
    assert_eq!(weight, (0..N).map(|i| 512 + i % 1024).sum::<u64>());
    for i in [0u64, 1, 2, 3, 77_777, 500_001, N - 1] {
        let s = p.sample(i).unwrap();
        assert_eq!(s.timestamp_ns, 10 + i);
        assert_eq!(s.address, 0x1_0000_0000 + i * 64);
        assert_eq!(s.tid, i % 13);
        assert_eq!(s.kind.code() as u64, i % 4);
        let st: Vec<_> = p.stack(&s).collect();
        assert_eq!(st.len() as u64, i % 4);
        for (d, f) in st.iter().enumerate() {
            let c = (i + d as u64) % 50;
            assert_eq!(f.qualname.unwrap(), format!("mod{}.func{c}", c % 7));
            let off = ((i + d as u64) % 24) * 2;
            assert_eq!(f.line, Some(1 + (off / 16) as u32));
            assert_eq!(f.location(), format!("big.py:{}", 1 + off / 16));
        }
    }
}
