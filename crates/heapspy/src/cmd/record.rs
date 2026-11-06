use std::sync::atomic::AtomicBool;

use anyhow::Context;
use heapspy_alloc::SamplingParams;
use heapspy_record::RecordOptions;

use crate::cli::RecordArgs;

pub fn run(args: RecordArgs) -> anyhow::Result<()> {
    let mut opts = RecordOptions::new(args.pid, args.duration, &args.output);
    opts.sampling = SamplingParams {
        events: args.events,
        byte_interval: args.interval,
        max_frames: args.max_frames,
    };
    opts.then_dump = args.then_dump;
    opts.mechanism = args.mechanism;

    let stop = AtomicBool::new(false);
    let stats = heapspy_record::record(&opts, &stop)
        .with_context(|| format!("cannot record pid {}", args.pid))?;

    let mechanisms: Vec<&str> = stats.mechanisms.iter().map(|m| m.as_str()).collect();
    eprintln!(
        "wrote {}: {} samples, {} frames, {} code objects, {} bytes in {:.1}s via {}{}",
        args.output.display(),
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
    Ok(())
}
