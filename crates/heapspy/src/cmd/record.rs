use std::sync::atomic::AtomicBool;

use heapspy_alloc::SamplingParams;
use heapspy_analyzer::report::{
    OverheadInfo, RecordKind, RecordReport, SamplingInfo, SchemaVersion,
};
use heapspy_record::{RecordOptions, RecordStats};
use heapspy_snapshot::SourceKind;

use crate::cli::RecordArgs;
use crate::output::{print_json, DumpSource};

pub fn run(args: RecordArgs) -> anyhow::Result<()> {
    if let Some(image) = &args.prepare {
        return prepare(image);
    }
    if let Some(image) = &args.unprepare {
        return unprepare(image);
    }
    // clap guarantees these are present when neither prepare nor unprepare.
    let pid = args.pid.expect("pid required");
    let duration = args.duration.expect("duration required");
    let output = args.output.clone().expect("output required");
    let mut opts = RecordOptions::new(pid, duration, &output);
    opts.sampling = SamplingParams {
        events: args.events,
        byte_interval: args.interval,
        max_frames: args.max_frames,
        native_min_size: args.native_min_size.min(u32::MAX as u64) as u32,
    };
    opts.then_dump = args.then_dump;
    opts.mechanism = args.mechanism;

    if let Some(w) = debugger_warning(opts.mechanism) {
        eprintln!("{w}");
    }
    let stop: &AtomicBool = heapspy_record::stop_on_signals();
    // The source context lets error_code() treat I/O errors on the target
    // as being about the process, as for `dump --pid`.
    let stats = heapspy_record::record(&opts, stop).map_err(|e| {
        anyhow::Error::from(e).context(DumpSource {
            kind: SourceKind::Pid,
            text: format!("cannot record pid {pid}"),
        })
    })?;

    let mechanisms: Vec<&str> = stats.mechanisms.iter().map(|m| m.as_str()).collect();
    eprintln!(
        "wrote {}: {} samples, {} frames, {} code objects, {} bytes in {:.1}s via {}{}",
        output.display(),
        stats.samples,
        stats.frames,
        stats.codes,
        stats.bytes_written,
        stats.elapsed.as_secs_f64(),
        mechanisms.join("+"),
        if stats.truncated { " (truncated)" } else { "" }
    );
    eprintln!(
        "overhead: {} probe hits, {} samples dropped, threads stopped {:.1} ms in total",
        stats.overhead.probe_hits,
        stats.overhead.samples_dropped,
        stats.overhead.total_pause_ns as f64 / 1e6
    );
    if let (Some(path), Some(s)) = (&opts.then_dump, &stats.snapshot) {
        eprintln!(
            "wrote {}: {} objects, {} edges, {} roots, {} bytes{}",
            path.display(),
            s.objects,
            s.edges,
            s.roots,
            s.bytes_written,
            if s.truncated { " (truncated)" } else { "" }
        );
    }
    if args.json {
        print_json(&report(&opts, &stats))?;
    }
    Ok(())
}

/// `--prepare <image>`: turn on heap tracing for an executable.
fn prepare(image: &str) -> anyhow::Result<()> {
    let p = heapspy_record::windows::prepare::prepare(image)?;
    if p.already_enabled {
        eprintln!(
            "heap tracing was already on for {} ({})",
            p.image, p.key_path
        );
    } else {
        eprintln!("heap tracing enabled for {} ({})", p.image, p.key_path);
    }
    eprintln!(
        "this is a global, persistent setting: start the target now, record with \
         `--events native`, then undo it with `heapspy record --unprepare {}`.",
        p.image
    );
    Ok(())
}

/// `--unprepare <image>`: remove the heap-tracing setting.
fn unprepare(image: &str) -> anyhow::Result<()> {
    let u = heapspy_record::windows::prepare::unprepare(image)?;
    if u.key_absent {
        eprintln!(
            "nothing to undo for {}: no IFEO key ({})",
            u.image, u.key_path
        );
    } else if u.value_removed {
        eprintln!(
            "heap tracing disabled for {}{}",
            u.image,
            if u.key_removed {
                " (removed the key heapspy created)"
            } else {
                " (left other settings in the key in place)"
            }
        );
    } else {
        eprintln!(
            "heap tracing was not on for {} (no TracingFlags value); nothing changed",
            u.image
        );
    }
    Ok(())
}

/// The warning printed when the Windows debugger is chosen.
fn debugger_warning(m: heapspy_record::MechanismChoice) -> Option<&'static str> {
    (cfg!(windows) && m == heapspy_record::MechanismChoice::Only(heapspy_alloc::Mechanism::Debugger))
        .then_some(
            "heapspy: warning: --mechanism debugger stops every thread of the target at each \
             breakpoint; on windows-latest the target was paused for 2.5-2.9 s of a 3 s recording. \
             A guardian process puts the target back (breakpoint bytes, debugger) if heapspy is \
             killed. Without --mechanism, Windows records with etw, which does not pause the target.",
        )
}

fn report(opts: &RecordOptions, stats: &RecordStats) -> RecordReport {
    let s = &opts.sampling;
    RecordReport {
        schema_version: SchemaVersion,
        kind: RecordKind::Kind,
        path: opts.output.display().to_string(),
        pid: opts.pid,
        python_version: stats.python.to_string(),
        duration_ms: stats.elapsed.as_millis().min(u64::MAX as u128) as u64,
        mechanisms: stats
            .mechanisms
            .iter()
            .map(|m| m.as_str().to_string())
            .collect(),
        sampling: SamplingInfo {
            events: s.events.iter().map(|k| k.as_str().to_string()).collect(),
            byte_interval: s.byte_interval,
            max_frames: s.max_frames,
        },
        samples: stats.samples,
        bytes_written: stats.bytes_written,
        overhead: OverheadInfo {
            samples_taken: stats.overhead.samples_taken,
            samples_dropped: stats.overhead.samples_dropped,
            probe_hits: stats.overhead.probe_hits,
            total_pause_ns: stats.overhead.total_pause_ns,
        },
        truncated: stats.truncated,
        then_dump: stats
            .snapshot
            .as_ref()
            .and(opts.then_dump.as_ref())
            .map(|p| p.display().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapspy_alloc::{EventKind, EventKinds, Mechanism, Mechanisms, Overhead, PythonVersion};
    use std::time::Duration;

    fn stats() -> RecordStats {
        RecordStats {
            recorder: "fake",
            python: PythonVersion::new(3, 12, 4),
            mechanisms: Mechanisms::of(&[Mechanism::Ebpf]),
            samples: 1932,
            frames: 9000,
            codes: 120,
            code_read_errors: 0,
            bytes_written: 81920,
            overhead: Overhead {
                samples_taken: 1932,
                samples_dropped: 3,
                probe_hits: 1_210_443,
                total_pause_ns: 0,
            },
            truncated: false,
            elapsed: Duration::from_millis(60_004),
            snapshot: None,
        }
    }

    #[test]
    fn debugger_warning_names_the_pause_and_the_guardian() {
        use heapspy_record::MechanismChoice;
        assert_eq!(debugger_warning(MechanismChoice::Auto), None);
        assert_eq!(
            debugger_warning(MechanismChoice::Only(Mechanism::Etw)),
            None
        );
        let w = debugger_warning(MechanismChoice::Only(Mechanism::Debugger));
        if cfg!(windows) {
            let w = w.unwrap();
            assert!(
                w.contains("stops every thread") && w.contains("guardian"),
                "{w}"
            );
        } else {
            assert_eq!(w, None);
        }
    }

    #[test]
    fn report_fields() {
        let mut opts = RecordOptions::new(1234, Duration::from_secs(60), "app.hpya");
        opts.sampling.events = EventKinds::of(&[EventKind::Arena, EventKind::LargeObject]);
        opts.then_dump = Some("app.hpy".into());
        let r = report(&opts, &stats());
        assert_eq!(r.path, "app.hpya");
        assert_eq!(r.python_version, "3.12.4");
        assert_eq!(r.duration_ms, 60_004);
        assert_eq!(r.mechanisms, ["ebpf"]);
        assert_eq!(r.sampling.events, ["arena", "large_object"]);
        assert_eq!(r.overhead.samples_dropped, 3);
        // No snapshot was taken, so no then_dump path is reported.
        assert_eq!(r.then_dump, None);
    }
}
