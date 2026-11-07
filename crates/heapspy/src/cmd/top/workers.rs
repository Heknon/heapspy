//! Background threads of `heapspy top`. Each sends [`Msg`]s to the UI
//! thread and stops when `quit` is set.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use heapspy_alloc::SamplingParams;
use heapspy_analyzer::report::AnalyzeReport;
use heapspy_analyzer::AnalyzeOptions;
use heapspy_reader::{DumpOptions, SourceSpec};
use heapspy_record::{MechanismChoice, RecordOptions};
use tempfile::TempPath;

use crate::live::{self, ProcMemory, PyThread, StackReader};

/// One snapshot, analysed.
pub struct Snap {
    pub at: Instant,
    pub wall: SystemTime,
    pub report: AnalyzeReport,
    /// How long the process was stopped (`None` with --no-stop).
    pub pause: Option<Duration>,
    /// Snapshot plus analysis time.
    pub took: Duration,
    pub approximate: bool,
    /// The snapshot file, deleted when the last user drops it.
    pub path: Arc<TempPath>,
}

pub enum Msg {
    Vitals {
        at: Instant,
        mem: Option<ProcMemory>,
        threads: Vec<PyThread>,
    },
    ProcessGone,
    SnapshotStarted,
    Snapshot(Box<Snap>),
    SnapshotFailed(String),
    AllocStarted {
        until: Instant,
    },
    AllocDone {
        path: PathBuf,
        samples: u64,
        mechanisms: String,
        pause_ms: f64,
    },
    AllocFailed(String),
    Detail {
        id: u64,
        lines: Result<Vec<String>, String>,
    },
}

/// Every second: the OS's memory numbers and each thread's Python stack.
pub fn vitals(pid: u32, mut reader: StackReader, tx: Sender<Msg>, quit: Arc<AtomicBool>) {
    while !quit.load(Ordering::Relaxed) {
        let t0 = Instant::now();
        let Some(mem) = live::proc_memory(pid) else {
            if cfg!(target_os = "linux") {
                let _ = tx.send(Msg::ProcessGone);
                return;
            }
            // Other systems have no cheap memory numbers yet.
            let threads = reader.read(32);
            let _ = tx.send(Msg::Vitals {
                at: t0,
                mem: None,
                threads,
            });
            sleep_until(t0 + Duration::from_secs(1), &quit);
            continue;
        };
        let threads = reader.read(32);
        if tx
            .send(Msg::Vitals {
                at: t0,
                mem: Some(mem),
                threads,
            })
            .is_err()
        {
            return;
        }
        sleep_until(t0 + Duration::from_secs(1), &quit);
    }
}

fn sleep_until(t: Instant, quit: &AtomicBool) {
    while Instant::now() < t && !quit.load(Ordering::Relaxed) {
        std::thread::sleep(
            Duration::from_millis(50).min(t.saturating_duration_since(Instant::now())),
        );
    }
}

/// What the snapshot thread is told.
pub enum SnapRequest {
    Now,
    /// Pause or resume scheduled snapshots.
    Paused(bool),
}

pub struct SnapConfig {
    pub pid: u32,
    pub every: Duration,
    pub no_stop: bool,
    pub max_pause: Option<Duration>,
    pub top: usize,
    /// An allocation profile to join with every snapshot taken after it.
    pub profile: Arc<Mutex<Option<PathBuf>>>,
}

/// Takes a snapshot every `every` (or when asked), analyses it, and sends
/// the result.
pub fn snapshots(
    cfg: SnapConfig,
    rx: Receiver<SnapRequest>,
    tx: Sender<Msg>,
    quit: Arc<AtomicBool>,
) {
    let mut next = Instant::now();
    let mut paused = false;
    let mut auto_off = false;
    loop {
        if quit.load(Ordering::Relaxed) {
            return;
        }
        let wait = next.saturating_duration_since(Instant::now());
        let forced = match rx.recv_timeout(wait.max(Duration::from_millis(1))) {
            Ok(SnapRequest::Now) => true,
            Ok(SnapRequest::Paused(p)) => {
                paused = p;
                continue;
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if !forced && (paused || auto_off || Instant::now() < next) {
            if Instant::now() >= next {
                next = Instant::now() + cfg.every;
            }
            continue;
        }
        let _ = tx.send(Msg::SnapshotStarted);
        match take(&cfg) {
            Ok(s) => {
                if let (Some(max), Some(p)) = (cfg.max_pause, s.pause) {
                    auto_off = p > max;
                }
                if tx.send(Msg::Snapshot(Box::new(s))).is_err() {
                    return;
                }
            }
            Err(e) => {
                if tx.send(Msg::SnapshotFailed(format!("{e:#}"))).is_err() {
                    return;
                }
            }
        }
        next = Instant::now() + cfg.every;
    }
}

fn take(cfg: &SnapConfig) -> anyhow::Result<Snap> {
    let t0 = Instant::now();
    let path = tempfile::Builder::new()
        .prefix(&format!("heapspy-top-{}-", cfg.pid))
        .suffix(".hpy")
        .tempfile()?
        .into_temp_path();
    let spec = SourceSpec::Pid(cfg.pid);
    let opts = DumpOptions {
        source_kind: spec.kind(),
        source_ref: spec.reference(),
        ..DumpOptions::default()
    };
    let (stats, _) = if cfg.no_stop {
        crate::cmd::dump::capture_unstopped(cfg.pid, &opts, &path)?
    } else {
        crate::cmd::capture(&spec, &opts, &path, true)?
    };
    let wall = SystemTime::now();
    let snap = crate::cmd::open_snapshot(&path)?;
    let opts = AnalyzeOptions { top: cfg.top };
    let name = format!("pid {}", cfg.pid);
    let profile = cfg
        .profile
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let report = match profile.and_then(|p| heapspy_alloc::Profile::open(&p).ok().map(|x| (p, x))) {
        Some((p, prof)) => heapspy_analyzer::allocations::analyze_with_allocations(
            &snap,
            &name,
            &opts,
            &prof,
            &p.display().to_string(),
        )?,
        None => heapspy_analyzer::analyze(&snap, &name, &opts)?,
    };
    Ok(Snap {
        at: Instant::now(),
        wall,
        report,
        pause: stats.pause,
        took: t0.elapsed(),
        approximate: cfg.no_stop,
        path: Arc::new(path),
    })
}

/// Allocation sampling for `duration`, as `heapspy record` does, through
/// eBPF on Linux and ETW on Windows only: the ptrace fallback and the
/// debugger stop the target, which a monitor must not do behind the user's
/// back.
pub fn allocations(
    pid: u32,
    duration: Duration,
    events: heapspy_alloc::EventKinds,
    stop: Arc<AtomicBool>,
    tx: Sender<Msg>,
) {
    let out = match tempfile::Builder::new()
        .prefix(&format!("heapspy-top-{pid}-"))
        .suffix(".hpya")
        .tempfile()
    {
        Ok(f) => match f.keep() {
            Ok((_, p)) => p,
            Err(e) => {
                let _ = tx.send(Msg::AllocFailed(e.to_string()));
                return;
            }
        },
        Err(e) => {
            let _ = tx.send(Msg::AllocFailed(e.to_string()));
            return;
        }
    };
    let mut opts = RecordOptions::new(pid, duration, &out);
    opts.sampling = SamplingParams {
        events,
        ..SamplingParams::DEFAULT
    };
    opts.mechanism = if cfg!(windows) {
        MechanismChoice::Only(heapspy_alloc::Mechanism::Etw)
    } else {
        MechanismChoice::Only(heapspy_alloc::Mechanism::Ebpf)
    };
    let _ = tx.send(Msg::AllocStarted {
        until: Instant::now() + duration,
    });
    match heapspy_record::record(&opts, &stop) {
        Ok(stats) => {
            let _ = tx.send(Msg::AllocDone {
                path: out,
                samples: stats.samples,
                mechanisms: stats
                    .mechanisms
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join("+"),
                pause_ms: stats.overhead.total_pause_ns as f64 / 1e6,
            });
        }
        Err(e) => {
            let _ = std::fs::remove_file(&out);
            let hint = match &e {
                heapspy_record::Error::PermissionDenied(_)
                | heapspy_record::Error::Unsupported(_) => {
                    if cfg!(windows) {
                        " (top uses ETW only; run elevated)"
                    } else {
                        " (top uses eBPF only: root or CAP_BPF+CAP_PERFMON, kernel 5.8+)"
                    }
                }
                _ => "",
            };
            let _ = tx.send(Msg::AllocFailed(format!("{e}{hint}")));
        }
    }
}
