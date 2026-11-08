//! `heapspy watch --counters`: sample a process's counters every interval
//! without stopping it, print one line (or one JSON `sample`) per round,
//! and on exit say how each series moved.
//!
//! The samples come from [`crate::sample::Sampler`]. They say how memory
//! moves (RSS, pymalloc, malloc, GC), not who holds it, so the summary has
//! no leak verdicts: only first, last, change, rate, low and high.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::Context;
use heapspy_analyzer::render::style::{pad_left, pad_right, shorten};
use heapspy_analyzer::render::{format_bytes, format_delta_bytes, Paint, Style};
use serde::Serialize;

use super::watch::{clock, delta_cell, human_duration, process_alive};
use crate::cli::WatchArgs;
use crate::live;
use crate::sample::{sleep_until, Sample, Sampler};

/// How one series moved over the run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub struct Series {
    pub first: u64,
    pub last: u64,
    pub min: u64,
    pub max: u64,
    pub delta: i64,
    pub per_minute: f64,
}

/// GC activity over the run.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct GcActivity {
    /// Collections of generations 0, 1, 2 during the run.
    pub collections: Vec<u64>,
    /// Objects those collections freed, and found uncollectable.
    pub collected: u64,
    pub uncollectable: u64,
}

#[derive(Debug, Serialize)]
struct CountersSummary {
    kind: &'static str,
    pid: u32,
    samples: u64,
    elapsed_s: f64,
    rss_bytes: Option<Series>,
    python_bytes: Option<Series>,
    arena_bytes: Option<Series>,
    malloc_heap_bytes: Option<Series>,
    gc: Option<GcActivity>,
}

pub fn run(args: &WatchArgs, st: &Style) -> anyhow::Result<()> {
    let pid = args.pid;
    let every = args.interval();
    let mut sampler =
        Sampler::open(pid).with_context(|| format!("cannot read pid {pid} without stopping it"))?;
    if let Some(e) = &sampler.counters_error {
        eprintln!(
            "heapspy: no Python counters for pid {pid} ({e}); sampling the OS's numbers only"
        );
    }
    let stop = heapspy_record::stop_on_signals();

    if !args.json {
        let mut head = format!(
            "sampling pid {pid} every {} · the process is not stopped",
            human_duration(every)
        );
        if let Some(cmd) = live::command_line(pid) {
            head = format!("{} · {head}", shorten(&cmd, 40));
        }
        println!("{}", st.paint(Paint::Dim, head));
        println!(
            "{}",
            st.paint(
                Paint::Dim,
                "python: bytes of objects in pymalloc's blocks · pymalloc: its arenas · \
                 malloc: glibc's heaps. Ctrl-C stops."
            )
        );
        println!();
        println!(
            "{}",
            st.paint(
                Paint::Heading,
                format!(
                    "{}{}{}{}{}{}  {}",
                    pad_right("time", 9),
                    pad_left("RSS", 10),
                    pad_left("Δ RSS", 11),
                    pad_left("python", 11),
                    pad_left("pymalloc", 11),
                    pad_left("malloc", 11),
                    "gc"
                )
            )
        );
    }

    let started = Instant::now();
    let mut samples: Vec<Sample> = Vec::new();
    let mut next = started;
    loop {
        let Some(s) = sampler.sample() else {
            if !args.json {
                println!("{}", st.paint(Paint::Warn, format!("process {pid} exited")));
            }
            break;
        };
        let line = if args.json {
            serde_json::to_string(&s)?
        } else {
            sample_line(&s, samples.last(), every, st)
        };
        // A stream read by another program: when it goes away (`| head`),
        // stop quietly, without a summary nobody reads.
        if !emit(&line)? {
            return Ok(());
        }
        // Keep the first, the last and the extremes cheaply: the summary
        // needs only those, so a long run at 100 ms does not grow memory.
        push_bounded(&mut samples, s);
        if args
            .rounds
            .is_some_and(|r| sampler_seq(&samples) >= u64::from(r))
        {
            break;
        }
        // A fixed cadence: a slow read delays the next one, it does not
        // shift every later one.
        next += every;
        let now = Instant::now();
        if next < now {
            next = now;
        }
        sleep_until(next, || stop.load(Ordering::Relaxed));
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
    summary(args, st, &samples)
}

/// Print one line and flush it, so a reader sees each sample as it is
/// taken. `false` when stdout was closed.
fn emit(line: &str) -> anyhow::Result<bool> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match writeln!(out, "{line}").and_then(|()| out.flush()) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The seq of the latest sample.
fn sampler_seq(v: &[Sample]) -> u64 {
    v.last().map_or(0, |s| s.seq)
}

/// Samples kept for the summary. Every sample is folded into running
/// extremes by [`summarise`] from this list, so the list keeps them all up
/// to a bound, then thins the middle (first and last always stay).
const KEEP: usize = 100_000;

fn push_bounded(v: &mut Vec<Sample>, s: Sample) {
    v.push(s);
    if v.len() > KEEP {
        // Drop every other sample of the middle: extremes may move by a
        // sample's worth, which a summary of a run this long can afford.
        let last = v.pop().unwrap();
        let first = v.remove(0);
        let mut thinned: Vec<Sample> = vec![first];
        thinned.extend(v.drain(..).skip(1).step_by(2));
        thinned.push(last);
        *v = thinned;
    }
}

fn opt_bytes(b: Option<u64>) -> String {
    b.map_or("-".to_string(), format_bytes)
}

fn sample_line(s: &Sample, prev: Option<&Sample>, every: Duration, st: &Style) -> String {
    let time = if every < Duration::from_secs(1) {
        format!("{:.1}s", s.elapsed_s)
    } else {
        clock(s.elapsed_s)
    };
    let d_rss = match (prev.and_then(Sample::rss), s.rss()) {
        (Some(a), Some(b)) => delta_cell(b as i64 - a as i64, st),
        _ => st.paint(Paint::Dim, "baseline"),
    };
    let gc = match s.gc() {
        None => st.paint(Paint::Dim, "-"),
        Some(g) => {
            let g0 = &g.generations[0];
            let mut t = format!("gen0 {}/{}", g0.count.max(0), g0.threshold);
            let ran = match (prev.and_then(Sample::collections), s.collections()) {
                (Some(a), Some(b)) => b.saturating_sub(a),
                _ => 0,
            };
            if ran > 0 {
                t.push_str(&st.paint(
                    Paint::Warn,
                    format!(" · {ran} collection{}", if ran == 1 { "" } else { "s" }),
                ));
            }
            if !g.enabled {
                t.push_str(&st.paint(Paint::Dim, " · disabled"));
            }
            t
        }
    };
    format!(
        "{}{}{}{}{}{}  {}",
        pad_right(&time, 9),
        pad_left(&opt_bytes(s.rss()), 10),
        pad_left(&d_rss, 11),
        pad_left(&opt_bytes(s.python_bytes()), 11),
        pad_left(&opt_bytes(s.arena_bytes()), 11),
        pad_left(&opt_bytes(s.malloc_bytes()), 11),
        gc
    )
}

/// How the series `f` moved over `v`.
pub fn series(v: &[Sample], f: impl Fn(&Sample) -> Option<u64>) -> Option<Series> {
    let points: Vec<(f64, u64)> = v
        .iter()
        .filter_map(|s| Some((s.elapsed_s, f(s)?)))
        .collect();
    let (&(t0, first), &(t1, last)) = (points.first()?, points.last()?);
    let minutes = (t1 - t0) / 60.0;
    let delta = last as i64 - first as i64;
    Some(Series {
        first,
        last,
        min: points.iter().map(|p| p.1).min().unwrap_or(0),
        max: points.iter().map(|p| p.1).max().unwrap_or(0),
        delta,
        per_minute: if minutes > 0.0 {
            (delta as f64 / minutes).round()
        } else {
            0.0
        },
    })
}

/// GC activity between the first and the last sample.
pub fn gc_activity(v: &[Sample]) -> Option<GcActivity> {
    let a = v.iter().find_map(Sample::gc)?;
    let b = v.iter().rev().find_map(Sample::gc)?;
    let sum = |g: &crate::sample::GcSample,
               f: fn(&crate::sample::GenerationSample) -> u64|
     -> u64 { g.generations.iter().map(f).sum() };
    Some(GcActivity {
        collections: a
            .generations
            .iter()
            .zip(&b.generations)
            .map(|(x, y)| y.collections.saturating_sub(x.collections))
            .collect(),
        collected: sum(b, |g| g.collected).saturating_sub(sum(a, |g| g.collected)),
        uncollectable: sum(b, |g| g.uncollectable).saturating_sub(sum(a, |g| g.uncollectable)),
    })
}

fn summary(args: &WatchArgs, st: &Style, v: &[Sample]) -> anyhow::Result<()> {
    let elapsed = v.last().map_or(0.0, |s| s.elapsed_s) - v.first().map_or(0.0, |s| s.elapsed_s);
    let s = CountersSummary {
        kind: "watch_counters_summary",
        pid: args.pid,
        samples: sampler_seq(v),
        elapsed_s: (elapsed * 1000.0).round() / 1000.0,
        rss_bytes: series(v, Sample::rss),
        python_bytes: series(v, Sample::python_bytes),
        arena_bytes: series(v, Sample::arena_bytes),
        malloc_heap_bytes: series(v, Sample::malloc_bytes),
        gc: gc_activity(v),
    };
    if args.json {
        println!("{}", serde_json::to_string(&s)?);
        return Ok(());
    }
    println!();
    if v.len() < 2 {
        println!(
            "{}",
            st.paint(Paint::Dim, "Only one sample was taken: nothing to compare.")
        );
        return Ok(());
    }
    println!(
        "{}{}{}{}{}{}",
        pad_right(
            &st.paint(
                Paint::Heading,
                format!("Over {} ({} samples)", clock(elapsed), s.samples)
            ),
            34
        ),
        pad_left(&st.paint(Paint::Dim, "now"), 11),
        pad_left(&st.paint(Paint::Dim, "change"), 12),
        pad_left(&st.paint(Paint::Dim, "per minute"), 15),
        pad_left(&st.paint(Paint::Dim, "low"), 11),
        pad_left(&st.paint(Paint::Dim, "high"), 11),
    );
    for (name, x) in [
        ("RSS", s.rss_bytes),
        ("Python objects (pymalloc blocks)", s.python_bytes),
        ("pymalloc arenas", s.arena_bytes),
        ("malloc heaps", s.malloc_heap_bytes),
    ] {
        let Some(x) = x else { continue };
        println!(
            "  {}{}{}{}{}{}",
            pad_right(name, 32),
            pad_left(&format_bytes(x.last), 11),
            pad_left(&delta_cell(x.delta, st), 12),
            pad_left(
                &format!("{}/min", format_delta_bytes(x.per_minute as i64)),
                15
            ),
            pad_left(&format_bytes(x.min), 11),
            pad_left(&format_bytes(x.max), 11),
        );
    }
    if let Some(g) = &s.gc {
        let total: u64 = g.collections.iter().sum();
        let by_gen: Vec<String> = g.collections.iter().map(u64::to_string).collect();
        let mut line = format!(
            "  GC: {total} collections (by generation {}), {} objects freed",
            by_gen.join("/"),
            g.collected
        );
        if g.uncollectable > 0 {
            line.push_str(&format!(", {} uncollectable", g.uncollectable));
        }
        println!("{line}");
    }
    println!();
    println!(
        "{} {}",
        st.paint(
            Paint::Dim,
            "These counters say how memory moves; to see who holds it:"
        ),
        st.paint(Paint::Command, format!("heapspy watch --pid {}", args.pid))
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::fake as sample;

    #[test]
    fn series_and_gc_over_a_run() {
        let v = vec![
            sample(1, 0.0, 100, 10, 6),
            sample(2, 30.0, 300, 5, 12),
            sample(3, 60.0, 200, 40, 18),
        ];
        let r = series(&v, Sample::rss).unwrap();
        assert_eq!(
            r,
            Series {
                first: 100,
                last: 200,
                min: 100,
                max: 300,
                delta: 100,
                per_minute: 100.0
            }
        );
        let p = series(&v, Sample::python_bytes).unwrap();
        assert_eq!((p.min, p.max, p.delta), (5, 40, 30));
        assert!(series(&v, Sample::malloc_bytes).is_none());
        let g = gc_activity(&v).unwrap();
        assert_eq!(g.collections, vec![12, 6, 4]);
        assert_eq!(g.collected, 3 * 120);
    }

    #[test]
    fn long_runs_keep_the_ends() {
        let mut v = Vec::new();
        for i in 0..(KEEP as u64 + 10) {
            push_bounded(&mut v, sample(i + 1, i as f64, i, 0, 0));
        }
        assert!(v.len() <= KEEP);
        assert_eq!(v.first().unwrap().seq, 1);
        assert_eq!(v.last().unwrap().seq, KEEP as u64 + 10);
        assert_eq!(sampler_seq(&v), KEEP as u64 + 10);
    }

    #[test]
    fn a_line_per_sample() {
        let st = Style::plain();
        let a = sample(1, 0.0, 100 << 20, 10 << 20, 6);
        let b = sample(2, 1.0, 101 << 20, 11 << 20, 8);
        let l = sample_line(&b, Some(&a), Duration::from_secs(1), &st);
        assert!(l.starts_with("0:01"), "{l}");
        assert!(l.contains("101.0 MiB") && l.contains("+1.0 MiB"), "{l}");
        assert!(l.contains("gen0 0/2000 · 3 collections"), "{l}");
        let fast = sample_line(&b, None, Duration::from_millis(250), &st);
        assert!(
            fast.starts_with("1.0s") && fast.contains("baseline"),
            "{fast}"
        );
    }
}
