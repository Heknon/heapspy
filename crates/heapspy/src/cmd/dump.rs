use std::path::Path;
use std::time::Duration;

use heapspy_analyzer::report::{DumpImage, DumpKind, DumpReport, Note, SchemaVersion, SourceRef};
use heapspy_reader::{source, DumpOptions, DumpStats, SourceSpec};

use crate::cli::DumpArgs;
use crate::output::{print_json, DumpSource, TruncatedImage};

pub fn run(args: DumpArgs) -> anyhow::Result<()> {
    let spec = match (args.pid, args.core, args.minidump) {
        (Some(pid), None, None) => SourceSpec::Pid(pid),
        (None, Some(p), None) => SourceSpec::Core(p),
        (None, None, Some(p)) => SourceSpec::Minidump(p),
        _ => unreachable!("clap enforces exactly one source"),
    };
    let opts = DumpOptions {
        capture_contents: args.capture_contents,
        max_str: args.max_str,
        source_kind: spec.kind(),
        source_ref: spec.reference(),
    };
    let (stats, attempt) = match (args.no_stop, args.pid) {
        (true, Some(pid)) => {
            eprintln!(
                "heapspy: --no-stop: the process keeps running during the walk, so this \
                 snapshot is approximate"
            );
            capture_unstopped(pid, &opts, &args.output)?
        }
        _ => capture(&spec, &opts, &args.output, false)?,
    };
    if stats.image_missing_bytes > 0 {
        eprintln!(
            "heapspy: warning: the image is missing {} bytes of memory its headers describe \
             (cut short?); the snapshot is marked truncated",
            stats.image_missing_bytes
        );
    }
    // heapspy-mcp and scripts parse this line; keep its format.
    eprintln!(
        "wrote {}: {} objects, {} edges, {} roots, {} bytes{}",
        args.output.display(),
        stats.objects,
        stats.edges,
        stats.roots,
        stats.bytes_written,
        if stats.truncated { " (truncated)" } else { "" }
    );
    if args.json {
        print_json(&report(
            &args.output.display().to_string(),
            &opts,
            &stats,
            attempt,
        ))?;
    }
    Ok(())
}

/// Capture `spec` into `out`, capturing a live target again when the walk
/// caught its GC lists mid-update (see [`LIVE_ATTEMPTS`]). Returns the stats
/// and the number of attempts. With `quiet`, the retry message is not
/// printed.
pub(crate) fn capture(
    spec: &SourceSpec,
    opts: &DumpOptions,
    out: &Path,
    quiet: bool,
) -> anyhow::Result<(DumpStats, u32)> {
    let context = |text: String| DumpSource {
        kind: spec.kind(),
        text,
    };
    let mut attempt = 1;
    loop {
        let stats = dump_once(spec, opts, out, &context)?;
        if !should_recapture(spec, &stats, attempt) {
            return Ok((stats, attempt));
        }
        if !quiet {
            eprintln!(
                "heapspy: this capture caught the target's GC lists mid-update, so the walk \
                 could not follow them; capturing again (attempt {} of {LIVE_ATTEMPTS})",
                attempt + 1
            );
        }
        attempt += 1;
        std::thread::sleep(RECAPTURE_DELAY);
    }
}

/// Snapshot `pid` without stopping it (`--no-stop`). The walk races with
/// the target, so the snapshot is approximate; a walk that comes back
/// truncated is tried again like a stopped one.
pub(crate) fn capture_unstopped(
    pid: u32,
    opts: &DumpOptions,
    out: &Path,
) -> anyhow::Result<(DumpStats, u32)> {
    let mut attempt = 1;
    loop {
        let src =
            heapspy_reader::source::linux_live::LiveProcess::open_unstopped(pid).map_err(|e| {
                anyhow::Error::from(e).context(DumpSource {
                    kind: heapspy_snapshot::SourceKind::Pid,
                    text: format!("cannot read pid {pid}"),
                })
            })?;
        let stats = heapspy_reader::dump(&src, opts, out).map_err(|e| {
            anyhow::Error::from(e).context(DumpSource {
                kind: heapspy_snapshot::SourceKind::Pid,
                text: format!("snapshot of pid {pid} without stopping it failed"),
            })
        })?;
        if !stats.truncated || attempt >= LIVE_ATTEMPTS {
            return Ok((stats, attempt));
        }
        attempt += 1;
        std::thread::sleep(RECAPTURE_DELAY);
    }
}

/// How many times `dump --pid` captures a target whose walk came back
/// truncated.
///
/// With no memory missing, the walk marks a snapshot truncated only when it
/// cannot follow a GC list to its end. A live target is captured at an
/// arbitrary moment, which can be in the middle of an update to those lists
/// (by the collector, or by an allocation or free), so a busy process
/// occasionally gives a capture whose lists do not close. This was seen on
/// windows-latest in the e2e busy-process test, about once in a dozen
/// `dump --pid` captures in one run and never in the runs before it. The
/// race is in the capture, not the heap, so a capture a moment later gets the
/// whole heap. A frozen image (core, minidump) cannot be captured again; its
/// truncation is final.
const LIVE_ATTEMPTS: u32 = 3;
const RECAPTURE_DELAY: Duration = Duration::from_millis(50);

/// Whether to capture `spec` again after attempt number `attempt`.
fn should_recapture(spec: &SourceSpec, stats: &DumpStats, attempt: u32) -> bool {
    matches!(spec, SourceSpec::Pid(_))
        && stats.truncated
        // Truncated because memory is missing is not a race.
        && stats.image_missing_bytes == 0
        && attempt < LIVE_ATTEMPTS
}

/// Open `spec` and write one snapshot to `out`. The snapshot replaces `out`
/// atomically, so a later attempt simply overwrites an earlier one.
fn dump_once(
    spec: &SourceSpec,
    opts: &DumpOptions,
    out: &Path,
    context: &dyn Fn(String) -> DumpSource,
) -> anyhow::Result<DumpStats> {
    let src = source::open(spec).map_err(|e| {
        anyhow::Error::from(e).context(context(format!(
            "cannot open {} {}",
            spec.kind(),
            spec.reference()
        )))
    })?;
    heapspy_reader::dump(src.as_ref(), opts, out).map_err(|e| {
        let missing_bytes = src.missing_bytes();
        let cut_short = missing_bytes > 0
            && matches!(
                e,
                heapspy_reader::Error::NotPython(_)
                    | heapspy_reader::Error::Unmapped { .. }
                    | heapspy_reader::Error::Format(_)
            );
        let e = anyhow::Error::from(e);
        let e = if cut_short {
            e.context(TruncatedImage { missing_bytes })
        } else {
            e
        };
        e.context(context(format!("dump to {} failed", out.display())))
    })
}

fn report(path: &str, opts: &DumpOptions, stats: &DumpStats, attempts: u32) -> DumpReport {
    let mut notes = Vec::new();
    if attempts > 1 {
        notes.push(note(
            "recaptured",
            format!(
                "The target was captured {attempts} times: the earlier captures caught its GC \
                 lists mid-update."
            ),
        ));
    }
    if stats.truncated {
        notes.push(note(
            "truncated_snapshot",
            "The snapshot is marked truncated: the walk did not finish or the image is \
             incomplete. Numbers from it are lower bounds.",
        ));
    }
    if stats.image_missing_bytes > 0 {
        notes.push(note(
            "image_incomplete",
            format!(
                "The image is missing {} bytes of memory its headers describe (cut short?).",
                stats.image_missing_bytes
            ),
        ));
    }
    if stats.read_errors > 0 {
        notes.push(note(
            "read_errors",
            format!(
                "{} reads of target memory failed; the objects involved are recorded as partial.",
                stats.read_errors
            ),
        ));
    }
    DumpReport {
        schema_version: SchemaVersion,
        kind: DumpKind::Kind,
        path: path.to_string(),
        source: SourceRef {
            kind: opts.source_kind.as_str().to_string(),
            reference: opts.source_ref.clone(),
        },
        python_version: stats.python.to_string(),
        contents_captured: opts.capture_contents,
        objects: stats.objects,
        edges: stats.edges,
        types: stats.types,
        roots: stats.roots,
        bytes_written: stats.bytes_written,
        read_errors: stats.read_errors,
        truncated: stats.truncated,
        image: DumpImage {
            missing_bytes: stats.image_missing_bytes,
        },
        // Milliseconds, to the microsecond.
        pause_ms: stats.pause.map(|d| (d.as_secs_f64() * 1e6).round() / 1e3),
        notes,
    }
}

fn note(code: &str, message: impl Into<String>) -> Note {
    Note {
        code: code.to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use heapspy_snapshot::PythonVersion;

    use super::*;

    fn stats(truncated: bool, image_missing_bytes: u64) -> DumpStats {
        DumpStats {
            python: PythonVersion {
                major: 3,
                minor: 13,
                micro: 0,
                release_level: PythonVersion::LEVEL_FINAL,
                release_serial: 0,
            },
            objects: 1,
            edges: 0,
            types: 1,
            roots: 1,
            bytes_written: 1,
            read_errors: 0,
            truncated,
            image_missing_bytes,
            pause: None,
        }
    }

    #[test]
    fn only_a_truncated_live_capture_is_taken_again() {
        let pid = SourceSpec::Pid(42);
        assert!(should_recapture(&pid, &stats(true, 0), 1));
        assert!(should_recapture(&pid, &stats(true, 0), 2));
        // At most LIVE_ATTEMPTS captures in all.
        assert!(!should_recapture(&pid, &stats(true, 0), LIVE_ATTEMPTS));
        // A whole heap is final.
        assert!(!should_recapture(&pid, &stats(false, 0), 1));
        // Missing memory is not a race with the collector.
        assert!(!should_recapture(&pid, &stats(true, 4096), 1));
        // A frozen image cannot be captured again.
        let core = SourceSpec::Core(PathBuf::from("app.core"));
        let dmp = SourceSpec::Minidump(PathBuf::from("app.dmp"));
        assert!(!should_recapture(&core, &stats(true, 0), 1));
        assert!(!should_recapture(&dmp, &stats(true, 0), 1));
    }

    #[test]
    fn a_recapture_is_noted_in_the_report() {
        let opts = DumpOptions::default();
        let notes = |attempts| -> Vec<String> {
            report("a.hpy", &opts, &stats(false, 0), attempts)
                .notes
                .into_iter()
                .map(|n| n.code)
                .collect()
        };
        assert!(notes(1).is_empty());
        assert_eq!(notes(2), ["recaptured"]);
    }
}
