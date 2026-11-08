use std::path::PathBuf;

use heapspy_analyzer::render::{self, Paint, Style};
use heapspy_analyzer::AnalyzeOptions;
use heapspy_reader::{DumpOptions, SourceSpec};

use super::{allocations, display_path, open_snapshot};
use crate::cli::AnalyzeArgs;
use crate::live::{self, PyThread};
use crate::output::print_json;

pub fn run(args: AnalyzeArgs, st: Style) -> anyhow::Result<()> {
    // With --pid: take the snapshot first (into --keep or a temporary file).
    let mut live_info = None;
    let mut _temp = None;
    let (path, shown) = match (args.pid, &args.snapshot) {
        (Some(pid), _) => {
            let out = match &args.keep {
                Some(p) => p.clone(),
                None => {
                    let t = tempfile::Builder::new()
                        .prefix(&format!("heapspy-{pid}-"))
                        .suffix(".hpy")
                        .tempfile()?
                        .into_temp_path();
                    let p = t.to_path_buf();
                    _temp = Some(t);
                    p
                }
            };
            let spec = SourceSpec::Pid(pid);
            let opts = DumpOptions {
                capture_contents: args.capture_contents,
                source_kind: spec.kind(),
                source_ref: spec.reference(),
                ..DumpOptions::default()
            };
            let (stats, _) = if args.no_stop {
                if !args.json {
                    eprintln!(
                        "heapspy: --no-stop: the process keeps running during the walk, so this \
                         report is approximate"
                    );
                }
                super::dump::capture_unstopped(pid, &opts, &out)?
            } else {
                super::capture(&spec, &opts, &out, args.json)?
            };
            // Read right after the snapshot: what each thread was doing.
            let threads = live::StackReader::open(pid)
                .map(|mut r| r.read(8))
                .unwrap_or_default();
            let mut shown = format!("pid {pid}");
            if let Some(cmd) = live::command_line(pid) {
                shown.push_str(&format!(" ({})", render::style::shorten(&cmd, 50)));
            }
            if let Some(p) = stats.pause {
                shown.push_str(&format!(" · stopped {} ms", p.as_millis()));
            } else if args.no_stop {
                shown.push_str(" · not stopped, approximate");
            }
            live_info = Some((pid, threads));
            (out, shown)
        }
        (None, Some(p)) => (p.clone(), display_path(p)),
        (None, None) => unreachable!("clap requires a snapshot or --pid"),
    };

    let snap = open_snapshot(&path)?;
    let alloc = allocations::open(args.allocations.as_deref(), &snap)?;
    let opts = AnalyzeOptions { top: args.top };
    let report = match &alloc {
        None => heapspy_analyzer::analyze(&snap, &shown, &opts)?,
        Some(a) => heapspy_analyzer::allocations::analyze_with_allocations(
            &snap, &shown, &opts, &a.profile, &a.path,
        )?,
    };
    if args.json {
        return print_json(&report);
    }
    let mut text = render::analyze_styled(&report, &st)?;
    if let Some((pid, threads)) = &live_info {
        text.push_str(&threads_section(threads, &st));
        text.push_str(&next_steps(&args.keep, *pid, &st));
    }
    print!("{text}");
    Ok(())
}

/// What each thread was running just after the snapshot.
pub(crate) fn threads_section(threads: &[PyThread], st: &Style) -> String {
    if threads.is_empty() {
        return String::new();
    }
    let mut out = format!("\n{}\n", st.paint(Paint::Heading, "Threads"));
    for t in threads {
        let name = live::thread_label(t);
        let state = t.state.unwrap_or("");
        let state = match state {
            "running" => st.paint(Paint::Good, state),
            _ => st.paint(Paint::Dim, state),
        };
        let mut line = format!(
            "  {} {} ",
            render::style::pad_right(&name, 16),
            render::style::pad_right(&state, 9)
        );
        match t.frames.first() {
            None => line.push_str(&st.paint(Paint::Dim, "(no Python code running)")),
            Some(f) => {
                line.push_str(&format!(
                    "{} {} {}",
                    f.location(),
                    st.paint(Paint::Dim, "in"),
                    f.function
                ));
                let callers: Vec<String> = t
                    .frames
                    .iter()
                    .skip(1)
                    .take(2)
                    .map(|c| format!("{} {}", c.function, c.location()))
                    .collect();
                if !callers.is_empty() {
                    line.push_str(&st.paint(Paint::Dim, format!("  ← {}", callers.join(" ← "))));
                }
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn next_steps(keep: &Option<PathBuf>, pid: u32, st: &Style) -> String {
    let mut out = String::from("\n");
    match keep {
        Some(p) => {
            let p = p.display();
            out.push_str(&format!(
                "{}\n  {}\n  {}\n",
                st.paint(
                    Paint::Dim,
                    format!("Snapshot kept at {p}. Dig deeper with:")
                ),
                st.paint(
                    Paint::Command,
                    format!("heapspy query {p} --retaining-path-type <TYPE>")
                ),
                st.paint(
                    Paint::Command,
                    format!("heapspy flamegraph {p} -o heap.svg")
                ),
            ));
        }
        None => {
            out.push_str(&format!(
                "{}\n  {}\n  {}\n",
                st.paint(Paint::Dim, "Next:"),
                st.paint(Paint::Command, format!("heapspy top --pid {pid}")),
                st.paint(
                    Paint::Command,
                    format!("heapspy analyze --pid {pid} --keep app.hpy   # keep the snapshot")
                ),
            ));
        }
    }
    out
}
