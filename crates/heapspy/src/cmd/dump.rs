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
    let context = |text: String| DumpSource {
        kind: spec.kind(),
        text,
    };
    let src = source::open(&spec).map_err(|e| {
        anyhow::Error::from(e).context(context(format!(
            "cannot open {} {}",
            spec.kind(),
            spec.reference()
        )))
    })?;
    let stats = heapspy_reader::dump(src.as_ref(), &opts, &args.output).map_err(|e| {
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
        e.context(context(format!("dump to {} failed", args.output.display())))
    })?;
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
        print_json(&report(&args.output.display().to_string(), &opts, &stats))?;
    }
    Ok(())
}

fn report(path: &str, opts: &DumpOptions, stats: &DumpStats) -> DumpReport {
    let mut notes = Vec::new();
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
