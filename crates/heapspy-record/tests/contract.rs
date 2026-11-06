//! The recorder contract, exercised with a fake recorder over an in-memory
//! image of a 3.13 target.

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use heapspy_alloc::{
    linetable, EventKind, Mechanism, Mechanisms, Overhead, Profile, PythonVersion, SampleFlags,
    SampleInput,
};
use heapspy_reader::cpython::frames::RawFrame;
use heapspy_reader::cpython::{FrameOffsets, Offsets, RuntimeLocation};
use heapspy_reader::source::mem::MemImage;
use heapspy_reader::{Module, TargetInfo};
use heapspy_record::*;
use heapspy_snapshot::Os;

const BASE: u64 = 0x20_0000;

struct Img {
    mem: Vec<u8>,
    top: u64,
}

impl Img {
    fn alloc(&mut self, n: u64) -> u64 {
        let a = self.top;
        self.top += n.div_ceil(16) * 16;
        a
    }
    fn put(&mut self, at: u64, b: &[u8]) {
        let o = (at - BASE) as usize;
        self.mem[o..o + b.len()].copy_from_slice(b);
    }
    fn u64(&mut self, at: u64, v: u64) {
        self.put(at, &v.to_le_bytes());
    }
    fn ascii(&mut self, fo: &FrameOffsets, s: &str) -> u64 {
        let a = self.alloc(fo.str_ascii_data + s.len() as u64 + 1);
        self.u64(a + fo.str_length, s.len() as u64);
        self.put(a + fo.str_state, &((1u32 << 2) | 32 | 64).to_le_bytes());
        self.put(a + fo.str_ascii_data, s.as_bytes());
        a
    }
    fn code(
        &mut self,
        fo: &FrameOffsets,
        qualname: &str,
        file: &str,
        first: i32,
        lt: &[u8],
    ) -> u64 {
        let c = self.alloc(fo.co_code_adaptive + 64);
        let q = self.ascii(fo, qualname);
        let f = self.ascii(fo, file);
        let b = self.alloc(fo.bytes_sval + lt.len() as u64 + 1);
        self.u64(b + fo.bytes_size, lt.len() as u64);
        self.put(b + fo.bytes_sval, lt);
        self.u64(c + fo.co_qualname, q);
        self.u64(c + fo.co_filename, f);
        self.u64(c + fo.co_linetable, b);
        self.put(c + fo.co_firstlineno, &first.to_le_bytes());
        c
    }
}

struct Fixture {
    src: MemImage,
    target: Target,
    load: u64,
    main: u64,
}

fn fixture() -> Fixture {
    let fo = FrameOffsets::from_offsets(&Offsets::table(13, Os::Linux).unwrap(), Os::Linux);
    let mut m = Img {
        mem: vec![0; 1 << 16],
        top: BASE + 16,
    };
    let lt_load = linetable::encode_lines(10, &[(8, Some(10)), (8, Some(12))]);
    let lt_main = linetable::encode_lines(1, &[(64, Some(3))]);
    let load = m.code(&fo, "Cache.load", "app/cache.py", 10, &lt_load);
    let main = m.code(&fo, "main", "app/main.py", 1, &lt_main);
    let mut src = MemImage::new(TargetInfo::LINUX_X86_64);
    src.map(BASE, m.mem);
    let target = Target {
        pid: 4242,
        info: TargetInfo::LINUX_X86_64,
        runtime: RuntimeLocation {
            module: Module {
                name: "libpython3.13.so.1.0".into(),
                path: "/usr/lib/libpython3.13.so.1.0".into(),
                base: 0x7f00_0000_0000,
                size: 0x40_0000,
                build_id: None,
            },
            runtime_addr: 0x7f00_0010_0000,
            version: PythonVersion::new(3, 13, 1),
            free_threaded: false,
            debug_build: false,
        },
        offsets: fo,
    };
    Fixture {
        src,
        target,
        load,
        main,
    }
}

/// Emits a fixed script of samples, as a real recorder would from probes.
struct FakeRecorder {
    load: u64,
    main: u64,
    fail: bool,
}

impl Recorder for FakeRecorder {
    fn name(&self) -> &'static str {
        "fake"
    }
    fn mechanisms(&self) -> Mechanisms {
        Mechanisms::of(&[Mechanism::Etw, Mechanism::Debugger])
    }
    fn probe(&self, _: &RecordOptions) -> Result<()> {
        Ok(())
    }
    fn run(&mut self, ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
        if self.fail {
            return Err(Error::PermissionDenied("SeDebugPrivilege".into()));
        }
        assert!(!ctx.should_stop());
        assert_eq!(ctx.target.pid, 4242);
        let t0 = now_ns();
        let stack = [
            RawFrame {
                code: self.load,
                instr_offset: Some(10),
            },
            RawFrame {
                code: self.main,
                instr_offset: Some(4),
            },
        ];
        // Exact frames from a breakpoint.
        ctx.sink.add(
            &SampleInput {
                timestamp_ns: t0 + 2,
                tid: 7,
                kind: EventKind::Arena,
                address: 0x7f10_0000_0000,
                size: 1 << 20,
                weight: 1 << 20,
                native_return_address: Some(0x7ff8_1234),
                flags: SampleFlags::NONE,
            },
            &stack,
            false,
        )?;
        // Approximate frames from ETW, with a stack deeper than max_frames (1).
        ctx.sink.add(
            &SampleInput {
                timestamp_ns: t0 + 1,
                tid: 8,
                kind: EventKind::LargeObject,
                address: 0x5555_0000,
                size: 4096,
                weight: heapspy_alloc::sampled_weight(4096, 1 << 19),
                ..SampleInput::default()
            },
            &stack,
            true,
        )?;
        // A native thread, and a code address that is not readable.
        ctx.sink.add_native(&SampleInput {
            timestamp_ns: t0 + 3,
            tid: 9,
            kind: EventKind::LargeObject,
            address: 0x6000,
            size: 1000,
            weight: 1000,
            ..SampleInput::default()
        })?;
        ctx.sink.add(
            &SampleInput {
                timestamp_ns: t0 + 4,
                tid: 7,
                kind: EventKind::Arena,
                address: 0x7f10_0010_0000,
                size: 1 << 20,
                weight: 1 << 20,
                ..SampleInput::default()
            },
            &[RawFrame {
                code: 0xdead_0000,
                instr_offset: None,
            }],
            false,
        )?;
        Ok(RunOutcome {
            mechanisms: Mechanisms::of(&[Mechanism::Etw]),
            overhead: Overhead {
                samples_taken: 0,
                samples_dropped: 3,
                probe_hits: 50,
                total_pause_ns: 777,
            },
            truncated: false,
        })
    }
}

#[test]
fn record_with_writes_a_profile() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("app.hpya");
    let mut opts = RecordOptions::new(4242, Duration::from_secs(30), &out);
    opts.sampling.max_frames = 1;
    let mut rec = FakeRecorder {
        load: f.load,
        main: f.main,
        fail: false,
    };
    let before = now_ns();
    let stats = record_with(&mut rec, &f.target, &f.src, &opts, &AtomicBool::new(false)).unwrap();
    assert_eq!(stats.recorder, "fake");
    assert_eq!(stats.python, PythonVersion::new(3, 13, 1));
    assert_eq!(stats.samples, 4);
    // `main` is past max_frames everywhere, so only `load` and the bad address.
    assert_eq!(stats.codes, 2);
    assert_eq!(stats.code_read_errors, 1);
    assert_eq!(stats.mechanisms, Mechanisms::of(&[Mechanism::Etw]));
    assert_eq!(stats.overhead.samples_taken, 4);
    assert_eq!(stats.bytes_written, std::fs::metadata(&out).unwrap().len());

    let p = Profile::open(&out).unwrap();
    let i = p.info();
    assert_eq!(i.pid, 4242);
    assert_eq!(i.python, PythonVersion::new(3, 13, 1));
    assert_eq!(i.os, Os::Linux);
    assert!(i.start_ns >= before && i.end_ns >= i.start_ns);
    assert_eq!(i.mechanisms, Mechanisms::of(&[Mechanism::Etw]));
    assert_eq!(i.sampling.max_frames, 1);
    assert_eq!(
        i.overhead,
        Overhead {
            samples_taken: 4,
            samples_dropped: 3,
            probe_hits: 50,
            total_pause_ns: 777
        }
    );
    assert!(!i.truncated);
    assert_eq!(p.meta_value("heapspy.recorder").unwrap(), Some("fake"));

    // Sorted by time: the ETW sample (t0+1) first.
    let s: Vec<_> = p.samples().collect();
    assert_eq!(s[0].kind, EventKind::LargeObject);
    assert!(s[0].flags.contains(SampleFlags::APPROXIMATE_FRAMES));
    assert!(s[0].flags.contains(SampleFlags::STACK_TRUNCATED));
    let st: Vec<String> = p.stack(&s[0]).map(|f| f.to_string()).collect();
    assert_eq!(st, ["Cache.load (app/cache.py:12) ~"]);

    assert_eq!(s[1].native_return_address, Some(0x7ff8_1234));
    assert!(s[1].flags.contains(SampleFlags::STACK_TRUNCATED));
    let st: Vec<String> = p.stack(&s[1]).map(|f| f.to_string()).collect();
    assert_eq!(st, ["Cache.load (app/cache.py:12)"]);

    assert!(s[2].flags.contains(SampleFlags::NO_THREAD_STATE));
    assert_eq!(s[2].frame_count, 0);

    let st: Vec<_> = p.stack(&s[3]).collect();
    assert_eq!(st[0].code_addr, Some(0xdead_0000));
    assert_eq!(st[0].qualname, None);
    let code = p.codes_at(0xdead_0000).next().unwrap();
    assert!(code.unresolved);
}

#[test]
fn a_failed_run_writes_nothing() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("app.hpya");
    let opts = RecordOptions::new(4242, Duration::from_secs(30), &out);
    let mut rec = FakeRecorder {
        load: f.load,
        main: f.main,
        fail: true,
    };
    let err = record_with(&mut rec, &f.target, &f.src, &opts, &AtomicBool::new(false)).unwrap_err();
    assert!(matches!(err, Error::PermissionDenied(_)), "{err}");
    assert!(!out.exists());
    // No stray temporary files either.
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn stop_flag_and_deadline() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let opts = RecordOptions::new(4242, Duration::from_millis(1), dir.path().join("a.hpya"));
    struct Waits;
    impl Recorder for Waits {
        fn name(&self) -> &'static str {
            "waits"
        }
        fn mechanisms(&self) -> Mechanisms {
            Mechanisms::of(&[Mechanism::Ebpf])
        }
        fn probe(&self, _: &RecordOptions) -> Result<()> {
            Ok(())
        }
        fn run(&mut self, ctx: &mut RecordContext<'_>) -> Result<RunOutcome> {
            while !ctx.should_stop() {
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(RunOutcome::default())
        }
    }
    let stats = record_with(
        &mut Waits,
        &f.target,
        &f.src,
        &opts,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(stats.elapsed >= Duration::from_millis(1));
    // Empty outcome mechanisms fall back to the recorder's own.
    assert_eq!(stats.mechanisms, Mechanisms::of(&[Mechanism::Ebpf]));
    let mut long = opts.clone();
    long.duration = Duration::from_secs(3600);
    let stats = record_with(&mut Waits, &f.target, &f.src, &long, &AtomicBool::new(true)).unwrap();
    assert!(stats.elapsed < Duration::from_secs(60));
}

#[test]
fn mechanism_selection() {
    let names =
        |c, os| -> Vec<&'static str> { select(c, os).unwrap().iter().map(|r| r.name()).collect() };
    assert_eq!(
        names(MechanismChoice::Auto, Some(Os::Linux)),
        ["linux-ebpf", "linux-ptrace"]
    );
    assert_eq!(
        names(MechanismChoice::Only(Mechanism::Ptrace), Some(Os::Linux)),
        ["linux-ptrace"]
    );
    assert_eq!(
        names(MechanismChoice::Auto, Some(Os::Windows)),
        ["windows-etw-debugger"]
    );
    assert_eq!(
        names(MechanismChoice::Only(Mechanism::Etw), Some(Os::Windows)),
        ["windows-etw"]
    );
    let w = select(
        MechanismChoice::Only(Mechanism::Debugger),
        Some(Os::Windows),
    )
    .unwrap();
    assert_eq!(w[0].mechanisms(), Mechanisms::of(&[Mechanism::Debugger]));
    for (c, os) in [
        (MechanismChoice::Only(Mechanism::Etw), Some(Os::Linux)),
        (MechanismChoice::Only(Mechanism::Ebpf), Some(Os::Windows)),
        (MechanismChoice::Auto, Some(Os::Macos)),
        (MechanismChoice::Auto, None),
    ] {
        assert!(matches!(select(c, os), Err(Error::Unsupported(_))));
    }
}

/// The test process is not CPython: a recorder probes fine, finding the
/// runtime fails, and nothing is written.
#[cfg(target_os = "linux")]
#[test]
fn record_on_this_process_is_not_python() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.hpya");
    let opts = RecordOptions::new(std::process::id(), Duration::from_secs(1), &out);
    let err = record(&opts, &AtomicBool::new(false)).unwrap_err();
    assert!(
        matches!(err, Error::Reader(heapspy_reader::Error::NotPython(_))),
        "{err}"
    );
    assert!(!out.exists());

    let mut bad = opts.clone();
    bad.duration = Duration::ZERO;
    assert!(matches!(
        record(&bad, &AtomicBool::new(false)),
        Err(Error::InvalidOption(_))
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn record_checks_the_pid_before_probing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.hpya");
    // Above the default pid_max (4194304), so no process has it.
    let opts = RecordOptions::new(999_999_999, Duration::from_secs(1), &out);
    let err = record(&opts, &AtomicBool::new(false)).unwrap_err();
    assert!(
        matches!(err, Error::Reader(heapspy_reader::Error::NoSuchProcess(_))),
        "{err}"
    );
    assert!(!out.exists());
}
