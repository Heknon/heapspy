//! `heapspy watch`: snapshot a process every N seconds, print one line per
//! round, and on exit say which holders grew and how steadily.
//!
//! Files in `--dir`: `first.hpy` (the first round) and `last.hpy` (the
//! latest). Each new snapshot is written to `.next.hpy`, compared with
//! `last.hpy`, then renamed over it, so `first.hpy` and `last.hpy` are always
//! complete snapshots that `heapspy diff` can read.
//!
//! With `--no-stop` the snapshots are taken while the process runs
//! ([`super::dump::capture_unstopped`]): approximate, so no holder is
//! called a likely leak. With `--counters` no snapshot is taken at all; see
//! [`super::counters`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::Context;
use heapspy_analyzer::render::style::{pad_left, pad_right, shorten};
use heapspy_analyzer::render::summary::memory_groups;
use heapspy_analyzer::render::{format_bytes, format_delta_bytes, Paint, Style};
use heapspy_analyzer::report::{AnalyzeReport, DiffReport};
use heapspy_analyzer::{AnalyzeOptions, DiffOptions};
use heapspy_reader::{DumpOptions, SourceSpec};
use serde::Serialize;

use super::open_snapshot;
use crate::cli::WatchArgs;
use crate::live;

/// Pseudo-site under which leaked native blocks are tracked.
const LEAKED: &str = "(leaked native blocks: nothing points to them)";

/// One round's numbers.
#[derive(Clone, Debug, Default, Serialize)]
struct Round {
    /// Always `watch_round`.
    kind: &'static str,
    round: u32,
    /// The snapshot was taken without stopping the process (`--no-stop`).
    approximate: bool,
    /// Seconds since the first snapshot.
    elapsed_s: f64,
    rss_bytes: Option<u64>,
    python_bytes: u64,
    native_bytes: u64,
    leaked_bytes: u64,
    pause_ms: Option<f64>,
    /// The site that grew most since the last round, and by how much.
    top_site: Option<String>,
    top_site_type: Option<String>,
    top_site_delta_bytes: i64,
    top_site_delta_objects: i64,
    #[serde(skip)]
    deltas: HashMap<String, i64>,
}

/// A line of the final summary.
#[derive(Clone, Debug, Serialize)]
struct Verdict {
    site: String,
    #[serde(rename = "type")]
    type_name: String,
    delta_retained_bytes: i64,
    delta_retained_objects: i64,
    bytes_per_min: f64,
    /// Rounds in which it grew, of the rounds compared.
    rounds_grown: u32,
    rounds_compared: u32,
    /// `likely_leak`, `growing_in_steps`, `flat`, `shrinking`.
    verdict: &'static str,
}

#[derive(Serialize)]
struct Summary {
    kind: &'static str,
    pid: u32,
    /// The snapshots were taken without stopping the process.
    approximate: bool,
    rounds: u32,
    elapsed_s: f64,
    first: String,
    last: String,
    holders: Vec<Verdict>,
}

pub fn run(args: WatchArgs, st: Style) -> anyhow::Result<()> {
    if args.counters {
        return super::counters::run(&args, &st);
    }
    let pid = args.pid;
    let dir = args
        .dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("watch-{pid}")));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("cannot create directory {}", dir.display()))?;
    let first = dir.join("first.hpy");
    let last = dir.join("last.hpy");
    let next = dir.join(".next.hpy");
    let stop = heapspy_record::stop_on_signals();

    if !args.json {
        let mut head = format!(
            "watching pid {pid} · a snapshot every {} · first and latest kept in {}",
            human_duration(args.interval()),
            dir.display()
        );
        if args.no_stop {
            head.push_str(" · not stopped: approximate");
        }
        if let Some(cmd) = live::command_line(pid) {
            head = format!("{} · {head}", shorten(&cmd, 40));
        }
        println!("{}", st.paint(Paint::Dim, head));
        println!(
            "{}",
            st.paint(Paint::Dim, "Ctrl-C stops and prints what grew.")
        );
        println!();
        println!(
            "{}",
            st.paint(
                Paint::Heading,
                format!(
                    "{}{}{}{}{}{}{}  {}",
                    pad_right("time", 8),
                    pad_left("RSS", 10),
                    pad_left("python", 11),
                    pad_left("native", 11),
                    pad_left("leaked", 11),
                    pad_left("Δ RSS", 11),
                    pad_left("pause", 8),
                    "grew most since the last round"
                )
            )
        );
    }

    let started = Instant::now();
    let mut rounds: Vec<Round> = Vec::new();
    let mut every = args.interval();
    let mut warned_pause = false;
    loop {
        let n = rounds.len() as u32 + 1;
        let target = if n == 1 { &first } else { &next };
        let spec = SourceSpec::Pid(pid);
        let opts = DumpOptions {
            source_kind: spec.kind(),
            source_ref: spec.reference(),
            ..DumpOptions::default()
        };
        let captured = if args.no_stop {
            super::dump::capture_unstopped(pid, &opts, target)
        } else {
            super::capture(&spec, &opts, target, true)
        };
        let stats = match captured {
            Ok((s, _)) => s,
            Err(e) if n > 1 && !process_alive(pid) => {
                if !args.json {
                    println!("{}", st.paint(Paint::Warn, format!("process {pid} exited")));
                }
                let _ = e;
                break;
            }
            Err(e) => return Err(e),
        };
        let elapsed = started.elapsed();
        let snap = open_snapshot(target)?;
        let report =
            heapspy_analyzer::analyze(&snap, &format!("pid {pid}"), &AnalyzeOptions { top: 1 })?;
        let mut round = round_from(&report, n, elapsed, stats.pause);
        round.approximate = args.no_stop;
        if n == 1 {
            std::fs::copy(&first, &last).context("cannot copy the first snapshot")?;
        } else {
            let before = open_snapshot(&last)?;
            let d =
                heapspy_analyzer::diff(&before, "last", &snap, "next", &DiffOptions { top: 200 })?;
            drop(before);
            drop(snap);
            apply_diff(&mut round, &d, rounds.last());
            std::fs::rename(&next, &last).context("cannot replace the latest snapshot")?;
        }
        if args.json {
            println!("{}", serde_json::to_string(&round)?);
        } else {
            println!("{}", round_line(&round, rounds.last(), &st));
        }
        // A pause that grows with the heap is the cost of watching.
        if let (Some(p0), Some(p)) = (rounds.first().and_then(|r| r.pause_ms), round.pause_ms) {
            if !warned_pause && !args.json && p > 200.0 && p > p0 * 1.5 {
                warned_pause = true;
                println!(
                    "{}",
                    st.paint(
                        Paint::Warn,
                        format!(
                            "          ⚠ the pause grows with the heap ({p0:.0} → {p:.0} ms); \
                             use a longer --every or --max-pause"
                        )
                    )
                );
            }
        }
        if let (Some(max), Some(p)) = (args.max_pause, stats.pause) {
            if p > max && every < Duration::from_secs(3600) {
                every *= 2;
                if !args.json {
                    println!(
                        "{}",
                        st.paint(
                            Paint::Warn,
                            format!(
                                "          ⚠ stopped {} ms, over --max-pause: snapshots now every {}",
                                p.as_millis(),
                                human_duration(every)
                            )
                        )
                    );
                }
            }
        }
        rounds.push(round);
        if args.rounds.is_some_and(|r| n >= r) {
            break;
        }
        // Sleep until the next round, waking for Ctrl-C.
        let wake = Instant::now() + every;
        while Instant::now() < wake && !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(100).min(wake - Instant::now()));
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if !process_alive(pid) {
            if !args.json {
                println!("{}", st.paint(Paint::Warn, format!("process {pid} exited")));
            }
            break;
        }
    }
    let _ = std::fs::remove_file(&next);
    summary(&args, &st, &rounds, &first, &last)
}

pub(super) fn process_alive(pid: u32) -> bool {
    live::process_alive(pid)
}

fn round_from(r: &AnalyzeReport, n: u32, elapsed: Duration, pause: Option<Duration>) -> Round {
    let groups = memory_groups(&r.memory);
    let get = |k: &str| groups.iter().filter(|g| g.key == k).map(|g| g.bytes).sum();
    let python = if groups.is_empty() {
        r.memory.graph_bytes
    } else {
        get("python")
    };
    Round {
        kind: "watch_round",
        round: n,
        elapsed_s: elapsed.as_secs_f64(),
        rss_bytes: r.memory.rss_bytes,
        python_bytes: python,
        native_bytes: get("native"),
        leaked_bytes: r.totals.native_lost_bytes,
        pause_ms: pause.map(|p| (p.as_secs_f64() * 1e4).round() / 10.0),
        ..Round::default()
    }
}

/// Fill the round's per-site deltas and its fastest-growing site from the
/// diff against the previous round.
fn apply_diff(round: &mut Round, d: &DiffReport, prev: Option<&Round>) {
    for s in &d.by_site {
        round.deltas.insert(s.site.clone(), s.delta_retained_bytes);
    }
    if let Some(p) = prev {
        round.deltas.insert(
            LEAKED.to_string(),
            round.leaked_bytes as i64 - p.leaked_bytes as i64,
        );
    }
    // The largest grower; among sites within 10% of it, the outermost one
    // (`CACHE` rather than `CACHE[<str len=12>]`).
    let max = d
        .by_site
        .iter()
        .filter(|s| !is_namespace(&s.site))
        .map(|s| s.delta_retained_bytes)
        .max()
        .unwrap_or(0);
    let best = d
        .by_site
        .iter()
        .filter(|s| !is_namespace(&s.site) && s.delta_retained_bytes * 10 >= max * 9)
        .min_by_key(|s| s.site.len());
    let leaked = round.deltas.get(LEAKED).copied().unwrap_or(0);
    match best {
        Some(s) if s.delta_retained_bytes > 0 && s.delta_retained_bytes >= leaked => {
            round.top_site = Some(s.site.clone());
            round.top_site_type = Some(s.type_name.clone());
            round.top_site_delta_bytes = s.delta_retained_bytes;
            round.top_site_delta_objects = s.delta_retained_objects;
        }
        _ if leaked > 0 => {
            round.top_site = Some(LEAKED.to_string());
            round.top_site_delta_bytes = leaked;
        }
        _ => {}
    }
}

pub(super) fn delta_cell(d: i64, st: &Style) -> String {
    let s = format_delta_bytes(d);
    if d > 0 {
        st.paint(Paint::Bad, s)
    } else if d < 0 {
        st.paint(Paint::Good, s)
    } else {
        st.paint(Paint::Dim, s)
    }
}

fn round_line(r: &Round, prev: Option<&Round>, st: &Style) -> String {
    let opt = |b: Option<u64>| b.map_or("-".to_string(), format_bytes);
    let d_rss = match (prev.and_then(|p| p.rss_bytes), r.rss_bytes) {
        (Some(a), Some(b)) => delta_cell(b as i64 - a as i64, st),
        _ => st.paint(Paint::Dim, "baseline"),
    };
    let leaked = if r.leaked_bytes > prev.map_or(r.leaked_bytes, |p| p.leaked_bytes) {
        st.paint(Paint::Leaked, format_bytes(r.leaked_bytes))
    } else {
        format_bytes(r.leaked_bytes)
    };
    let grew = match &r.top_site {
        None if prev.is_some() => st.paint(Paint::Dim, "nothing grew"),
        None => String::new(),
        Some(s) => {
            let mut t = format!(
                "{}  {}",
                shorten(s, 52),
                st.paint(Paint::Bad, format_delta_bytes(r.top_site_delta_bytes))
            );
            if r.top_site_delta_objects != 0 {
                t.push_str(&st.paint(
                    Paint::Dim,
                    format!(" ({:+} objects)", r.top_site_delta_objects),
                ));
            }
            t
        }
    };
    format!(
        "{}{}{}{}{}{}{}  {}",
        pad_right(&clock(r.elapsed_s), 8),
        pad_left(&opt(r.rss_bytes), 10),
        pad_left(&format_bytes(r.python_bytes), 11),
        pad_left(&format_bytes(r.native_bytes), 11),
        pad_left(&leaked, 11),
        pad_left(&d_rss, 11),
        pad_left(&r.pause_ms.map_or("-".into(), |p| format!("{p:.0}ms")), 8),
        grew
    )
}

/// `m:ss` or `h:mm:ss` since the start.
pub(super) fn clock(secs: f64) -> String {
    let s = secs.round() as u64;
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

pub(crate) fn human_duration(d: Duration) -> String {
    let s = d.as_secs();
    if d.subsec_millis() != 0 || s == 0 {
        format!("{}ms", d.as_millis())
    } else if s % 3600 == 0 {
        format!("{}h", s / 3600)
    } else if s % 60 == 0 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

/// A module's or class's `__dict__`: a namespace, not a holder anyone
/// would name (the global inside it is the holder).
fn is_namespace(site: &str) -> bool {
    site.ends_with(".__dict__")
}

/// Whether `child` is a site reached through `parent`.
fn is_under(child: &str, parent: &str) -> bool {
    child.len() > parent.len()
        && child.starts_with(parent)
        && matches!(child.as_bytes()[parent.len()], b'.' | b'[' | b' ')
}

/// Keep the outermost growing holders: drop namespaces and every site under
/// a holder already kept, and give each kept holder the largest site under
/// it as its `inner` (what it is filling up with).
fn outermost(sorted: Vec<Verdict>) -> Vec<(Verdict, Option<Verdict>)> {
    let mut kept: Vec<(Verdict, Option<Verdict>)> = Vec::new();
    for v in sorted {
        if is_namespace(&v.site) {
            continue;
        }
        if let Some(k) = kept.iter_mut().find(|(k, _)| is_under(&v.site, &k.site)) {
            if k.1.is_none() && v.delta_retained_bytes > 0 {
                k.1 = Some(v);
            }
            continue;
        }
        kept.push((v, None));
    }
    kept
}

/// Classify a site's per-round deltas. Snapshots of a process that kept
/// running (`approximate`) can miss or double-count objects, so growth in
/// them is never called a likely leak.
fn verdict(deltas: &[i64], total: i64, approximate: bool) -> &'static str {
    let grown = deltas.iter().filter(|&&d| d > 0).count();
    let n = deltas.len().max(1);
    if total <= 0 {
        if total < 0 {
            "shrinking"
        } else {
            "flat"
        }
    } else if grown * 5 >= n * 4 && n >= 2 && !approximate {
        "likely_leak"
    } else if grown > 0 {
        "growing_in_steps"
    } else {
        "flat"
    }
}

fn summary(
    args: &WatchArgs,
    st: &Style,
    rounds: &[Round],
    first: &Path,
    last: &Path,
) -> anyhow::Result<()> {
    let elapsed = rounds.last().map_or(0.0, |r| r.elapsed_s);
    let mut holders = Vec::new();
    if rounds.len() >= 2 {
        let a = open_snapshot(first)?;
        let b = open_snapshot(last)?;
        let d = heapspy_analyzer::diff(&a, "first", &b, "last", &DiffOptions { top: 200 })?;
        let minutes = (elapsed / 60.0).max(1e-9);
        let per_site = |site: &str| -> Vec<i64> {
            rounds[1..]
                .iter()
                .map(|r| r.deltas.get(site).copied().unwrap_or(0))
                .collect()
        };
        for s in &d.by_site {
            let ds = per_site(&s.site);
            holders.push(Verdict {
                site: s.site.clone(),
                type_name: s.type_name.clone(),
                delta_retained_bytes: s.delta_retained_bytes,
                delta_retained_objects: s.delta_retained_objects,
                bytes_per_min: s.delta_retained_bytes as f64 / minutes,
                rounds_grown: ds.iter().filter(|&&x| x > 0).count() as u32,
                rounds_compared: ds.len() as u32,
                verdict: verdict(&ds, s.delta_retained_bytes, args.no_stop),
            });
        }
        let leaked: i64 =
            rounds.last().unwrap().leaked_bytes as i64 - rounds[0].leaked_bytes as i64;
        if leaked != 0 {
            let ds = per_site(LEAKED);
            holders.push(Verdict {
                site: LEAKED.to_string(),
                type_name: "native".into(),
                delta_retained_bytes: leaked,
                delta_retained_objects: 0,
                bytes_per_min: leaked as f64 / minutes,
                rounds_grown: ds.iter().filter(|&&x| x > 0).count() as u32,
                rounds_compared: ds.len() as u32,
                verdict: verdict(&ds, leaked, args.no_stop),
            });
        }
        holders.sort_by_key(|y| std::cmp::Reverse(y.delta_retained_bytes));
    }
    // Leave out holders whose change is noise next to the largest one.
    let biggest = holders
        .iter()
        .map(|h| h.delta_retained_bytes.unsigned_abs())
        .max()
        .unwrap_or(0);
    holders.retain(|h| {
        let d = h.delta_retained_bytes.unsigned_abs();
        d >= 4096 && d * 100 >= biggest
    });
    let mut holders = outermost(holders);
    holders.truncate(args.top_rows());
    if args.json {
        let s = Summary {
            kind: "watch_summary",
            pid: args.pid,
            approximate: args.no_stop,
            rounds: rounds.len() as u32,
            elapsed_s: elapsed,
            first: first.display().to_string(),
            last: last.display().to_string(),
            holders: holders.into_iter().map(|(v, _)| v).collect(),
        };
        println!("{}", serde_json::to_string(&s)?);
        return Ok(());
    }
    println!();
    if rounds.len() < 2 {
        println!(
            "{}",
            st.paint(
                Paint::Dim,
                "Only one snapshot was taken: nothing to compare."
            )
        );
        return Ok(());
    }
    println!(
        "{}{}{}   {}",
        pad_right(
            &st.paint(
                Paint::Heading,
                format!(
                    "Growth over {} ({} snapshots)",
                    clock(elapsed),
                    rounds.len()
                )
            ),
            64
        ),
        pad_left(&st.paint(Paint::Dim, "Δ retained"), 12),
        pad_left(&st.paint(Paint::Dim, "per minute"), 16),
        st.paint(Paint::Dim, "verdict")
    );
    if args.no_stop {
        println!(
            "  {}",
            st.paint(
                Paint::Dim,
                "approximate: the process was not stopped, so no growth is called a leak"
            )
        );
    }
    if holders.is_empty() {
        println!("  {}", st.paint(Paint::Dim, "no holder changed"));
    }
    for (h, inner) in &holders {
        let (paint, text) = match h.verdict {
            "likely_leak" => (
                Paint::Bad,
                format!(
                    "grew in {}/{} rounds → likely leak",
                    h.rounds_grown, h.rounds_compared
                ),
            ),
            "growing_in_steps" => (
                Paint::Warn,
                format!(
                    "grew in {}/{} rounds → keep watching",
                    h.rounds_grown, h.rounds_compared
                ),
            ),
            "shrinking" => (Paint::Good, "shrank → fine".to_string()),
            _ => (Paint::Good, "flat → fine".to_string()),
        };
        println!(
            "  {}{}{}   {}",
            pad_right(&st.paint(Paint::Strong, shorten(&h.site, 60)), 62),
            pad_left(&delta_cell(h.delta_retained_bytes, st), 12),
            pad_left(
                &format!("{}/min", format_delta_bytes(h.bytes_per_min.round() as i64)),
                16
            ),
            st.paint(paint, text)
        );
        if h.site != LEAKED {
            let mut sub = h.type_name.clone();
            if h.delta_retained_objects != 0 {
                sub.push_str(&format!(" · {:+} objects", h.delta_retained_objects));
            }
            if let Some(i) = inner {
                sub.push_str(&format!(
                    " · mostly {} {} ({:+} objects)",
                    shorten(&i.site[h.site.len()..], 40),
                    i.type_name,
                    i.delta_retained_objects
                ));
            }
            println!("    {}", st.paint(Paint::Dim, sub));
        }
    }
    println!();
    println!(
        "{} {} {}",
        st.paint(Paint::Dim, "Snapshots kept:"),
        first.display(),
        last.display()
    );
    println!(
        "{} {}",
        st.paint(Paint::Dim, "Next:"),
        st.paint(
            Paint::Command,
            format!("heapspy diff {} {}", first.display(), last.display())
        )
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts() {
        assert_eq!(verdict(&[5, 6, 7, 5], 23, false), "likely_leak");
        assert_eq!(verdict(&[5, 6, 7, 5], 23, true), "growing_in_steps");
        assert_eq!(verdict(&[5, 0, 0, 5], 10, false), "growing_in_steps");
        assert_eq!(verdict(&[0, 0], 0, false), "flat");
        assert_eq!(verdict(&[-5, 1], -4, false), "shrinking");
        assert_eq!(verdict(&[5], 5, false), "growing_in_steps");
    }

    fn v(site: &str, d: i64) -> Verdict {
        Verdict {
            site: site.into(),
            type_name: "t".into(),
            delta_retained_bytes: d,
            delta_retained_objects: 1,
            bytes_per_min: 0.0,
            rounds_grown: 1,
            rounds_compared: 1,
            verdict: "flat",
        }
    }

    #[test]
    fn nested_sites_fold_into_their_holder() {
        let m = "sys.modules['m'].__dict__";
        let got = outermost(vec![
            v(m, 100),
            v(&format!("{m}['CACHE']"), 90),
            v(&format!("{m}['CACHE'][<str len=3>]"), 80),
            v(&format!("{m}['CACHE'][<str len=3>].payload"), 70),
            v(&format!("{m}['CACHEX']"), 5),
        ]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0.site, format!("{m}['CACHE']"));
        assert_eq!(
            got[0].1.as_ref().unwrap().site,
            format!("{m}['CACHE'][<str len=3>]")
        );
        assert_eq!(got[1].0.site, format!("{m}['CACHEX']"));
    }

    #[test]
    fn clocks_and_durations() {
        assert_eq!(clock(0.0), "0:00");
        assert_eq!(clock(95.0), "1:35");
        assert_eq!(clock(3725.0), "1:02:05");
        assert_eq!(human_duration(Duration::from_secs(30)), "30s");
        assert_eq!(human_duration(Duration::from_secs(300)), "5m");
        assert_eq!(human_duration(Duration::from_millis(500)), "500ms");
    }
}
