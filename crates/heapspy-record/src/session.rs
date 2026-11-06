//! Running a recording from options to a finished `.hpya` file.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use heapspy_alloc::{
    AllocWriter, LineTableFormat, Mechanism, Mechanisms, Overhead, ProfileInfo, FORMAT_VERSION,
};
use heapspy_reader::{DumpOptions, DumpStats, MemorySource, SourceSpec};
use heapspy_snapshot::{Os, PythonVersion};

use crate::error::{Error, Result};
use crate::options::{MechanismChoice, RecordOptions};
use crate::recorder::{RecordContext, Recorder, Target};
use crate::sink::SampleSink;
use crate::{linux_ebpf, linux_ptrace, live, windows};

/// What a recording produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordStats {
    /// [`Recorder::name`] of the recorder that ran.
    pub recorder: &'static str,
    /// CPython version found in the target (as written to the header).
    pub python: PythonVersion,
    /// Mechanisms that actually ran (as written to the header).
    pub mechanisms: Mechanisms,
    pub samples: u64,
    pub frames: u64,
    /// Code entries in the profile.
    pub codes: u64,
    /// Code objects that could not be read (their entries are unresolved).
    pub code_read_errors: u64,
    /// Size of the `.hpya` file.
    pub bytes_written: u64,
    /// Measured cost, as written to the header.
    pub overhead: Overhead,
    pub truncated: bool,
    /// Wall time from attach to detach.
    pub elapsed: Duration,
    /// The `--then-dump` snapshot, if one was taken.
    pub snapshot: Option<DumpStats>,
}

/// The OS this build runs on, as the recorders see it.
pub fn host_os() -> Option<Os> {
    if cfg!(target_os = "linux") {
        Some(Os::Linux)
    } else if cfg!(windows) {
        Some(Os::Windows)
    } else {
        None
    }
}

/// The recorders to try for `choice` on `os`, in order. `auto` on Linux is
/// eBPF then ptrace; on Windows it is one recorder using ETW and debugger
/// breakpoints together.
pub fn select(choice: MechanismChoice, os: Option<Os>) -> Result<Vec<Box<dyn Recorder>>> {
    let unsupported = |what: String| Err(Error::Unsupported(what));
    match (os, choice) {
        (Some(Os::Linux), MechanismChoice::Auto) => Ok(vec![
            Box::new(linux_ebpf::EbpfRecorder::new()),
            Box::new(linux_ptrace::PtraceRecorder::new()),
        ]),
        (Some(Os::Linux), MechanismChoice::Only(Mechanism::Ebpf)) => {
            Ok(vec![Box::new(linux_ebpf::EbpfRecorder::new())])
        }
        (Some(Os::Linux), MechanismChoice::Only(Mechanism::Ptrace)) => {
            Ok(vec![Box::new(linux_ptrace::PtraceRecorder::new())])
        }
        (Some(Os::Windows), MechanismChoice::Auto) => {
            Ok(vec![Box::new(windows::WindowsRecorder::new(true, true))])
        }
        (Some(Os::Windows), MechanismChoice::Only(Mechanism::Etw)) => {
            Ok(vec![Box::new(windows::WindowsRecorder::new(true, false))])
        }
        (Some(Os::Windows), MechanismChoice::Only(Mechanism::Debugger)) => {
            Ok(vec![Box::new(windows::WindowsRecorder::new(false, true))])
        }
        (Some(os), MechanismChoice::Only(m)) => {
            unsupported(format!("mechanism {m} is not available on {os}"))
        }
        (_, _) => unsupported("heapspy record runs on Linux and Windows only".into()),
    }
}

/// `heapspy record`: validate the options, pick a recorder, attach to the
/// running target, record for the window, write the `.hpya` file, and take
/// the `--then-dump` snapshot if asked. `stop` ends the window early.
pub fn record(opts: &RecordOptions, stop: &AtomicBool) -> Result<RecordStats> {
    opts.validate()?;
    check_exists(opts.pid)?;
    let mut first_err: Option<Error> = None;
    let mut chosen = None;
    for r in select(opts.mechanism, host_os())? {
        match r.probe(opts) {
            Ok(()) => {
                chosen = Some(r);
                break;
            }
            Err(e) if e.try_next() => {
                first_err.get_or_insert(e);
            }
            Err(e) => return Err(e),
        }
    }
    let Some(mut rec) = chosen else {
        return Err(first_err.unwrap_or_else(|| Error::Unsupported("no recorder available".into())));
    };
    let src = live::open(opts.pid)?;
    let target = Target::locate(src.as_ref(), opts.pid)?;
    let mut stats = record_with(rec.as_mut(), &target, src.as_ref(), opts, stop)?;
    drop(src);
    if let Some(path) = &opts.then_dump {
        stats.snapshot = Some(dump_now(opts.pid, path)?);
    }
    Ok(stats)
}

/// Run one recorder against an already located target and write the
/// profile. [`record`] calls this; tests call it with a fake recorder and
/// an in-memory source. Nothing is written if the recorder fails.
pub fn record_with(
    rec: &mut dyn Recorder,
    target: &Target,
    src: &dyn MemorySource,
    opts: &RecordOptions,
    stop: &AtomicBool,
) -> Result<RecordStats> {
    let info = ProfileInfo {
        format_version: FORMAT_VERSION,
        pid: target.pid,
        python: target.runtime.version,
        pointer_size: target.info.pointer_size,
        os: target.info.os,
        arch: target.info.arch,
        start_ns: now_ns(),
        end_ns: 0,
        mechanisms: rec.mechanisms(),
        sampling: opts.sampling,
        overhead: Overhead::default(),
        truncated: false,
    };
    let writer = AllocWriter::with_spill_dir(info, parent_dir(&opts.output))?;
    let sink = SampleSink::new(
        writer,
        src,
        target.offsets,
        LineTableFormat::for_python(target.runtime.version),
        opts.sampling.max_frames,
    );
    let started = Instant::now();
    let mut ctx = RecordContext {
        target,
        src,
        opts,
        sink,
        deadline: started + opts.duration,
        stop,
    };
    let outcome = rec.run(&mut ctx)?;
    let elapsed = started.elapsed();
    let (mut w, st) = ctx.sink.into_parts();
    let mechanisms = if outcome.mechanisms == Mechanisms::NONE {
        rec.mechanisms()
    } else {
        outcome.mechanisms
    };
    let overhead = Overhead {
        samples_taken: st.samples,
        ..outcome.overhead
    };
    {
        let i = w.info_mut();
        i.end_ns = now_ns();
        i.mechanisms = mechanisms;
        i.overhead = overhead;
        i.truncated = outcome.truncated;
    }
    w.add_meta("heapspy.version", env!("CARGO_PKG_VERSION"))?;
    w.add_meta("heapspy.recorder", rec.name())?;
    let codes = w.code_count() as u64;
    let ws = w.finish_to_path(&opts.output)?;
    Ok(RecordStats {
        recorder: rec.name(),
        python: target.runtime.version,
        mechanisms,
        samples: ws.samples,
        frames: ws.frames,
        codes,
        code_read_errors: st.code_read_errors,
        bytes_written: ws.bytes_written,
        overhead,
        truncated: outcome.truncated,
        elapsed,
        snapshot: None,
    })
}

/// Fail with `NoSuchProcess` before any recorder is probed when no process
/// has `pid`. Checked on Linux only (`/proc/<pid>`); on Windows the
/// recorder's probe or [`live::open`] reports it.
fn check_exists(pid: u32) -> Result<()> {
    if cfg!(target_os = "linux") && !Path::new(&format!("/proc/{pid}")).exists() {
        return Err(Error::Reader(heapspy_reader::Error::NoSuchProcess(
            format!("no process with pid {pid}"),
        )));
    }
    Ok(())
}

/// Take a snapshot of `pid` right away (the `--then-dump` step).
fn dump_now(pid: u32, path: &Path) -> Result<DumpStats> {
    let spec = SourceSpec::Pid(pid);
    let opts = DumpOptions {
        source_kind: spec.kind(),
        source_ref: spec.reference(),
        ..DumpOptions::default()
    };
    let src = heapspy_reader::source::open_in(&spec, &parent_dir(path))?;
    Ok(heapspy_reader::dump(src.as_ref(), &opts, path)?)
}

fn parent_dir(p: &Path) -> PathBuf {
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Nanoseconds since the Unix epoch.
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos().min(u64::MAX as u128) as u64)
}
