//! `heapspy flamegraph`: retention flame graphs rendered with inferno.

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use heapspy_analyzer::flame::DEFAULT_MIN_PCT;
use heapspy_analyzer::render::{format_bytes, format_delta_bytes};
use heapspy_analyzer::{FlameOptions, MinWidth};
use inferno::flamegraph::color::{BasicPalette, Palette};
use inferno::flamegraph::{self, Options};

use super::open_snapshot;
use crate::cli::FlamegraphArgs;

pub const TITLE: &str = "heapspy retention flame graph";

pub fn run(args: FlamegraphArgs) -> anyhow::Result<()> {
    let opts = FlameOptions {
        max_depth: args.max_depth,
        min_width: match (args.min_bytes, args.min_pct) {
            (Some(b), _) => MinWidth::Bytes(b),
            (None, Some(p)) => MinWidth::Pct(p),
            (None, None) => MinWidth::Pct(DEFAULT_MIN_PCT),
        },
    };
    // Rendered in memory first (the output is bounded by the cutoffs), so a
    // failure leaves no half-written file behind.
    let mut buf = Vec::new();
    match &args.diff {
        Some(paths) => diff(&args, &paths[0], &paths[1], &opts, &mut buf)?,
        None => {
            let path = args.snapshot.as_deref().expect("clap requires SNAP");
            single(&args, path, &opts, &mut buf)?
        }
    }
    match &args.output {
        Some(p) => std::fs::write(p, &buf).with_context(|| format!("cannot write {}", p.display())),
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(&buf)?;
            out.flush()?;
            Ok(())
        }
    }
}

fn python(snap: &heapspy_snapshot::Snapshot) -> String {
    format!("CPython {}", snap.info().python)
}

fn cutoff_text(min_bytes: u64) -> String {
    if min_bytes == 0 {
        String::new()
    } else {
        format!("; frames under {} are in [other]", format_bytes(min_bytes))
    }
}

fn svg_options(title: Option<&str>, default_title: String, subtitle: String) -> Options<'static> {
    let mut o = Options::default();
    o.title = title.map(str::to_string).unwrap_or(default_title);
    o.subtitle = Some(subtitle);
    o.count_name = "bytes".to_string();
    o.name_type = "Frame:".to_string();
    // Memory palette, colored by a hash of the frame text: the same input
    // always gives the same colors.
    o.colors = Palette::Basic(BasicPalette::Mem);
    o.hash = true;
    o.notes = "heapspy retention flame graph: frames are dominator-tree hops, \
               width is retained bytes"
        .to_string();
    o
}

fn render(opts: &mut Options, lines: &[String], out: &mut dyn Write) -> anyhow::Result<()> {
    if lines.is_empty() {
        anyhow::bail!("nothing is reachable from the snapshot's roots");
    }
    flamegraph::from_lines(opts, lines.iter().map(String::as_str), out)
        .context("cannot render the flame graph")
}

fn single(
    args: &FlamegraphArgs,
    path: &Path,
    opts: &FlameOptions,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let snap = open_snapshot(path)?;
    let f = heapspy_analyzer::folded_stacks(&snap, opts)?;
    if args.folded {
        f.write_to(out)?;
        return Ok(());
    }
    let subtitle = format!(
        "{}, {} reachable objects, {} retained{}",
        python(&snap),
        f.reachable_objects,
        format_bytes(f.reachable_bytes),
        cutoff_text(f.min_bytes)
    );
    let lines: Vec<String> = f
        .lines
        .iter()
        .map(|l| format!("{} {}", l.stack, l.bytes))
        .collect();
    let mut o = svg_options(args.title.as_deref(), TITLE.to_string(), subtitle);
    render(&mut o, &lines, out)
}

fn diff(
    args: &FlamegraphArgs,
    before_path: &Path,
    after_path: &Path,
    opts: &FlameOptions,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let before = open_snapshot(before_path)?;
    let after = open_snapshot(after_path)?;
    let d = heapspy_analyzer::folded_diff(&before, &after, opts)?;
    if args.folded {
        d.write_to(out)?;
        return Ok(());
    }
    let (b, a) = (d.before_reachable_bytes, d.after_reachable_bytes);
    let subtitle = format!(
        "{} -> {} retained ({}). Red grew, blue shrank. \
         Matched by path, not identity: approximate",
        format_bytes(b),
        format_bytes(a),
        format_delta_bytes(a as i64 - b as i64),
    );
    let lines: Vec<String> = d
        .lines
        .iter()
        .map(|l| format!("{} {} {}", l.stack, l.before, l.after))
        .collect();
    let mut o = svg_options(args.title.as_deref(), format!("{TITLE} (diff)"), subtitle);
    // The subtitle has no room for these; they go in the SVG's notes.
    o.notes = format!(
        "{}. Width is the after snapshot. {} before, {} after{}",
        o.notes,
        python(&before),
        python(&after),
        cutoff_text(d.min_bytes)
    );
    render(&mut o, &lines, out)
}
