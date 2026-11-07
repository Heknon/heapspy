use heapspy_snapshot::format::{FORMAT_VERSION, H_FILE_LEN, H_VERSION};
use heapspy_snapshot::*;

fn sample() -> SnapshotBuilder {
    let mut b = SnapshotBuilder::new();
    b.python(3, 13, 1)
        .os(Os::Windows)
        .source(SourceKind::Minidump, "C:\\dumps\\app.dmp")
        .captured_at(1_760_000_000)
        .contents_captured(true)
        .memory_region(RegionKind::Heap, 4096, Some(2048))
        .memory_region(RegionKind::Image, 8192, None)
        .meta("heapspy.version", "0.1.0");
    let module = b.ty("builtins", "module");
    let dict = b.ty("builtins", "dict");
    let list = b.ty("builtins", "list");
    let sess = b.ty_at(0x9000, "app.session", "Session");
    let bytes = b.ty("builtins", "bytes");

    // Added out of address order on purpose.
    b.object(0x5000, bytes, 1 << 20)
        .untracked()
        .length(1_048_543)
        .content("b'\\x00\\x00'", true);
    b.object(0x1000, module, 72)
        .attr(0x2000, "__dict__")
        .qualname("app.cache");
    b.object(0x3000, dict, 1024)
        .dict_value(0x4000, "'user:8812'")
        .redacted_dict_value(0x4100, "str", 9)
        .unknown_dict_value(0xdead);
    b.object(0x2000, dict, 232).dict_value(0x3000, "'CACHE'");
    b.object(0x4000, sess, 56)
        .attr(0x5000, "payload")
        .type_edge(0x9000)
        .source_loc("app/session.py:12");
    b.object(0x4100, list, 88)
        .list_item(0x4000, 0)
        .tuple_item(0x4000, 1)
        .set_item(0x4000)
        .cell_contents(0x4000)
        .closure_cell(0x4000, 2)
        .frame_local(0x4000, "pending")
        .other(0x4000, Some("weakref callback"))
        .other(0x4000, None)
        .dict_key(0x4000, "'k'")
        .length(1);
    b.root(0x1000, RootKind::ModuleDict, "sys.modules['app.cache']");
    b.root(0x4100, RootKind::FrameLocal, "frame worker:run");
    b
}

fn check_sample(s: &Snapshot) {
    let info = s.info();
    assert_eq!(info.format_version, FORMAT_VERSION);
    assert_eq!(info.python.to_string(), "3.13.1");
    assert_eq!(info.os, Os::Windows);
    assert_eq!(info.arch, Arch::X86_64);
    assert_eq!(info.pointer_size, 8);
    assert!(info.target_little_endian);
    assert_eq!(info.captured_at, 1_760_000_000);
    assert_eq!(info.source.kind, SourceKind::Minidump);
    assert_eq!(info.source.reference, "C:\\dumps\\app.dmp");
    assert!(info.contents_captured);
    assert!(!info.truncated);

    assert_eq!(s.object_count(), 6);
    let addrs: Vec<u64> = s.objects().map(|o| o.addr).collect();
    assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000, 0x4000, 0x4100, 0x5000]);
    assert_eq!(s.find_object(0x3000), Some(2));
    assert_eq!(s.find_object(0x3001), None);
    assert_eq!(s.find_object(0), None);
    assert_eq!(s.find_object(u64::MAX), None);

    let d = s.object(2);
    assert_eq!(s.type_name(d.type_id).unwrap(), "builtins.dict");
    assert_eq!(d.shallow_size, 1024);
    assert!(d.flags.contains(ObjectFlags::GC_TRACKED));
    let labels: Vec<String> = s
        .edges(2)
        .map(|e| s.render_label(e.label).unwrap())
        .collect();
    assert_eq!(labels, vec!["['user:8812']", "[<str len=9>]", "[?]"]);
    let e: Vec<Edge> = s.edges(2).collect();
    assert!(matches!(
        e[1].label,
        EdgeLabel::DictValue(KeyLabel::Redacted(_))
    ));
    assert_eq!(e[2].target, 0xdead);
    assert_eq!(s.find_object(e[2].target), None);

    let l = s.find_object(0x4100).unwrap();
    let labels: Vec<String> = s
        .edges(l)
        .map(|e| s.render_label(e.label).unwrap())
        .collect();
    assert_eq!(
        labels,
        vec![
            "[0]",
            "[1]",
            "<set item>",
            ".cell_contents",
            ".__closure__[2]",
            "local 'pending'",
            "<weakref callback>",
            "<?>",
            "<key ['k']>",
        ]
    );

    let sess = s.object(s.find_object(0x4000).unwrap());
    assert_eq!(s.type_name(sess.type_id).unwrap(), "app.session.Session");
    assert_eq!(s.type_entry(sess.type_id).unwrap().addr, 0x9000);
    let x = s.extras(sess.index).unwrap();
    assert_eq!(
        s.opt_string(x.source_loc).unwrap(),
        Some("app/session.py:12")
    );
    assert_eq!(x.length, None);

    let big = s.object(5);
    assert!(!big.flags.contains(ObjectFlags::GC_TRACKED));
    let x = s.extras(5).unwrap();
    assert_eq!(x.length, Some(1_048_543));
    assert_eq!(s.opt_string(x.content).unwrap(), Some("b'\\x00\\x00'"));
    assert!(x.content_truncated);
    assert!(s.extras(2).is_none());
    assert_eq!(s.extras_count(), 4);

    let roots: Vec<(u64, RootKind, String)> = s
        .roots()
        .map(|r| (r.addr, r.kind, s.string(r.label).unwrap().to_string()))
        .collect();
    assert_eq!(
        roots[0],
        (
            0x1000,
            RootKind::ModuleDict,
            "sys.modules['app.cache']".into()
        )
    );
    assert_eq!(roots[1].1, RootKind::FrameLocal);

    let mem = s.memory_summary().unwrap();
    assert_eq!(mem.len(), 2);
    assert_eq!(mem[0].resident_bytes, Some(2048));
    assert_eq!(mem[1].resident_bytes, None);
    assert_eq!(s.meta_value("heapspy.version").unwrap(), Some("0.1.0"));
    assert_eq!(s.edge_count(), 1 + 3 + 1 + 2 + 9);
}

#[test]
fn round_trip_bytes() {
    let s = sample().build().unwrap();
    check_sample(&s);
}

#[test]
fn round_trip_file_mmap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.hpy");
    let stats = sample().write_to(&path).unwrap();
    assert_eq!(stats.objects, 6);
    assert_eq!(stats.bytes_written, std::fs::metadata(&path).unwrap().len());
    let s = Snapshot::open(&path).unwrap();
    check_sample(&s);
}

#[test]
fn spill_to_dir_matches_memory() {
    let b = sample();
    let mem = b.to_bytes().unwrap();

    // Re-create the same content through a file-spilling writer.
    let s = Snapshot::from_bytes(mem.clone()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut w = SnapshotWriter::with_spill_dir(s.info().clone(), dir.path()).unwrap();
    // Copy strings in id order so ids line up.
    for i in 0..s.string_count() {
        w.intern(s.string(StrId(i as u32)).unwrap()).unwrap();
    }
    for t in 0..s.type_count() {
        let e = s.type_entry(TypeId(t as u32)).unwrap();
        w.add_type(
            e.addr,
            s.string(e.module).unwrap(),
            s.string(e.qualname).unwrap(),
        )
        .unwrap();
    }
    for o in s.objects().collect::<Vec<_>>().into_iter().rev() {
        let input = ObjectInput {
            addr: o.addr,
            type_id: o.type_id,
            shallow_size: o.shallow_size,
            flags: o.flags,
            extras: s.extras(o.index).unwrap_or_default(),
            refcount: s.refcount(o.index),
        };
        w.add_object(&input, s.edges(o.index)).unwrap();
    }
    for r in s.roots() {
        w.add_root(r.addr, r.kind, r.label).unwrap();
    }
    for r in s.memory_summary().unwrap() {
        w.add_memory_region(r);
    }
    for (k, v) in s.meta() {
        w.add_meta(s.string(k).unwrap(), s.string(v).unwrap())
            .unwrap();
    }
    let out = w.finish_to_vec().unwrap();
    assert_eq!(out, mem);
}

#[test]
fn empty_snapshot() {
    let s = SnapshotBuilder::new().build().unwrap();
    assert_eq!(s.object_count(), 0);
    assert_eq!(s.edge_count(), 0);
    assert_eq!(s.find_object(1), None);
    assert!(s.memory_summary().is_none());
}

#[test]
fn duplicate_address_rejected() {
    let mut b = SnapshotBuilder::new();
    let t = b.ty("builtins", "list");
    b.object(0x10, t, 1);
    b.object(0x10, t, 1);
    assert!(matches!(b.to_bytes(), Err(Error::DuplicateAddress(0x10))));
}

#[test]
fn invalid_ids_rejected_by_writer() {
    let mut w = SnapshotWriter::new(SnapshotInfo::new_for_test()).unwrap();
    let bad_type = ObjectInput::new(0x10, TypeId(5), 8);
    assert!(matches!(
        w.add_object(&bad_type, []),
        Err(Error::InvalidType(5))
    ));
    let ok = ObjectInput::new(0x10, TypeId::UNKNOWN, 8);
    let e = Edge {
        target: 1,
        label: EdgeLabel::Attr(StrId(999)),
        origin: EdgeOrigin::Exact,
    };
    assert!(matches!(
        w.add_object(&ok, [e]),
        Err(Error::InvalidString(999))
    ));
}

#[test]
fn unknown_version_rejected() {
    let mut bytes = sample().to_bytes().unwrap();
    bytes[H_VERSION..H_VERSION + 2].copy_from_slice(&2u16.to_le_bytes());
    match Snapshot::from_bytes(bytes) {
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
        Snapshot::from_bytes(b"\x7fELF....".to_vec()),
        Err(Error::BadMagic)
    ));
    assert!(matches!(
        Snapshot::from_bytes(Vec::new()),
        Err(Error::BadMagic)
    ));
}

#[test]
fn truncated_file_rejected_at_every_length() {
    let bytes = sample().to_bytes().unwrap();
    for cut in 0..bytes.len() {
        let r = Snapshot::from_bytes(bytes[..cut].to_vec());
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
    let bytes = sample().to_bytes().unwrap();
    for cut in [bytes.len() - 8, bytes.len() / 2, 100] {
        let mut b = bytes[..cut].to_vec();
        b[H_FILE_LEN..H_FILE_LEN + 8].copy_from_slice(&(cut as u64).to_le_bytes());
        assert!(Snapshot::from_bytes(b).is_err(), "accepted cut at {cut}");
    }
}

#[test]
fn corrupted_bytes_never_panic() {
    let bytes = sample().to_bytes().unwrap();
    // Flip every byte in the header and section table, and a stride through the rest.
    let positions: Vec<usize> = (0..256.min(bytes.len()))
        .chain((256..bytes.len()).step_by(7))
        .collect();
    for &p in &positions {
        for v in [0x00u8, 0xff, 0x80] {
            let mut b = bytes.clone();
            b[p] = v;
            if let Ok(s) = Snapshot::from_bytes(b) {
                // Exercise accessors; they must not panic on an accepted file.
                for o in s.objects() {
                    let _ = s.type_name(o.type_id);
                    for e in s.edges(o.index) {
                        let _ = s.render_label(e.label);
                    }
                    let _ = s.extras(o.index).map(|x| s.opt_string(x.content));
                }
                for r in s.roots() {
                    let _ = s.string(r.label);
                }
                let _ = s.memory_summary();
                let _ = s.meta_value("x");
            }
        }
    }
}

#[test]
fn large_synthetic_round_trip() {
    const N: u64 = 100_000;
    let mut b = SnapshotBuilder::new();
    let list = b.ty("builtins", "list");
    let obj = b.ty("app", "Node");
    // A list root holding every 100th node; nodes form a chain.
    let base = 0x7f00_0000_0000u64;
    let addr = |i: u64| base + i * 64;
    {
        let root = b.object(base - 64, list, 56 + (N / 100) * 8);
        for (k, i) in (0..N).step_by(100).enumerate() {
            root.list_item(addr(i), k as u32);
        }
    }
    // Insert in a scrambled order.
    for j in 0..N {
        let i = (j * 7919) % N;
        let o = b.object(addr(i), obj, 48);
        if i + 1 < N {
            o.attr(addr(i + 1), "next");
        }
        if i % 3 == 0 {
            o.dict_value(addr((i * 31) % N), "'peer'");
        }
    }
    b.root(base - 64, RootKind::ModuleDict, "sys.modules['app']");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.hpy");
    b.write_to(&path).unwrap();
    let s = Snapshot::open(&path).unwrap();
    assert_eq!(s.object_count() as u64, N + 1);
    let expected_edges = N / 100 + (N - 1) + N.div_ceil(3);
    assert_eq!(s.edge_count() as u64, expected_edges);

    let mut prev = 0;
    for o in s.objects() {
        assert!(o.addr > prev || o.index == 0);
        prev = o.addr;
    }
    for i in [0u64, 1, 2, 999, 50_000, N - 1] {
        let idx = s.find_object(addr(i)).unwrap();
        let o = s.object(idx);
        assert_eq!(o.addr, addr(i));
        let targets: Vec<u64> = s.edge_targets(idx).collect();
        let mut want = Vec::new();
        if i + 1 < N {
            want.push(addr(i + 1));
        }
        if i % 3 == 0 {
            want.push(addr((i * 31) % N));
        }
        assert_eq!(targets, want);
    }
}
