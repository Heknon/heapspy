use anyhow::Context;
use heapspy_reader::{source, DumpOptions, SourceSpec};

use crate::cli::DumpArgs;

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
    let src = source::open(&spec)
        .with_context(|| format!("cannot open {} {}", spec.kind(), spec.reference()))?;
    let stats = heapspy_reader::dump(src.as_ref(), &opts, &args.output)
        .with_context(|| format!("dump to {} failed", args.output.display()))?;
    if stats.image_missing_bytes > 0 {
        eprintln!(
            "heapspy: warning: the image is missing {} bytes of memory its headers describe \
             (cut short?); the snapshot is marked truncated",
            stats.image_missing_bytes
        );
    }
    eprintln!(
        "wrote {}: {} objects, {} edges, {} roots, {} bytes{}",
        args.output.display(),
        stats.objects,
        stats.edges,
        stats.roots,
        stats.bytes_written,
        if stats.truncated { " (truncated)" } else { "" }
    );
    Ok(())
}
