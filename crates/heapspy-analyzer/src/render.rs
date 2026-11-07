//! Plain-text rendering of reports for the terminal.
//!
//! Text output is for people and may change at any time. Tools must use
//! `--json`.

use std::fmt::Write as _;

pub mod style;
pub mod summary;

pub use style::{Paint, Style};

use crate::report::{
    AllocatedAt, Allocations, AnalyzeReport, DiffReport, LocateReport, Note, PathHop,
    RetainingPathReport, StackFrame, TypeQueryReport,
};
use crate::{root_path_string, Result};

/// A simple left/right aligned table. Columns listed in `right` are
/// right-aligned; the last column is never padded.
fn table(out: &mut String, header: &[&str], rows: &[Vec<String>], right: &[usize]) {
    let cols = header.len();
    let mut width = vec![0usize; cols];
    for (i, h) in header.iter().enumerate() {
        width[i] = h.chars().count();
    }
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            width[i] = width[i].max(c.chars().count());
        }
    }
    let line = |out: &mut String, cells: &mut dyn Iterator<Item = &str>| {
        out.push_str("  ");
        for (i, c) in cells.enumerate() {
            let pad = width[i].saturating_sub(c.chars().count());
            if i + 1 == cols {
                if right.contains(&i) {
                    out.push_str(&" ".repeat(pad));
                }
                out.push_str(c);
            } else if right.contains(&i) {
                let _ = write!(out, "{}{}  ", " ".repeat(pad), c);
            } else {
                let _ = write!(out, "{}{}  ", c, " ".repeat(pad));
            }
        }
        while out.ends_with(' ') {
            out.pop();
        }
        out.push('\n');
    };
    line(out, &mut header.iter().copied());
    for r in rows {
        line(out, &mut r.iter().map(String::as_str));
    }
}

/// [`table`], with `extra[i]` (already indented, newline-terminated) printed
/// under row `i`.
fn table_with_extra(
    out: &mut String,
    header: &[&str],
    rows: &[Vec<String>],
    right: &[usize],
    extra: &[String],
) {
    let mut t = String::new();
    table(&mut t, header, rows, right);
    for (i, line) in t.lines().enumerate() {
        out.push_str(line);
        out.push('\n');
        if let Some(e) = i.checked_sub(1).and_then(|r| extra.get(r)) {
            out.push_str(e);
        }
    }
}

/// Frames shown per stack in the "Allocated by" section.
const SECTION_FRAMES: usize = 12;
/// Frames shown in a one-line stack under a retainer or instance.
const LINE_FRAMES: usize = 3;
/// Stacks shown under each retainer or instance.
const LINE_STACKS: usize = 2;

/// `Cache.load (app/cache.py:12)`, with ` ~` for an approximate frame.
fn frame_text(f: &StackFrame) -> String {
    let mut s = format!("{} ({})", f.function, f.location);
    if f.approximate {
        s.push_str(" ~");
    }
    s
}

/// A stack on one line, innermost first: `a (x:1) <- b (y:2) <- ...`.
fn stack_line(frames: &[StackFrame], max: usize) -> String {
    if frames.is_empty() {
        return "(no Python frames)".to_string();
    }
    let mut parts: Vec<String> = frames.iter().take(max).map(frame_text).collect();
    if frames.len() > max {
        parts.push(format!("... {} more", frames.len() - max));
    }
    parts.join(" <- ")
}

/// How a link was made: `exact` (large-object samples), `approx` (arena
/// and pool samples), or `partly exact`.
fn link_kind(linked: u64, exact: u64) -> &'static str {
    if exact >= linked {
        "exact"
    } else if exact == 0 {
        "approx"
    } else {
        "partly exact"
    }
}

/// The top stacks of one `allocated_at`, one line each.
fn allocated_at_lines(at: &AllocatedAt, indent: &str) -> String {
    let mut out = String::new();
    if at.stacks.is_empty() {
        let _ = writeln!(out, "{indent}allocated at: no sampled allocation in it");
        return out;
    }
    for s in at.stacks.iter().take(LINE_STACKS) {
        let rank = s
            .top_stack_rank
            .map(|r| format!(", stack #{r}"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "{indent}allocated at: {} ({}{rank}) {}",
            format_bytes(s.linked_bytes),
            link_kind(s.linked_bytes, s.exact_linked_bytes),
            stack_line(&s.frames, LINE_FRAMES)
        );
    }
    out
}

/// `60.0 s`, `1.5 s`, `250 ms`.
pub fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.1} s", ms as f64 / 1000.0)
    }
}

/// The "Allocated by" section of `analyze --allocations`.
fn allocations_section(out: &mut String, a: &Allocations) {
    out.push_str("\nAllocated by (sampled while recording)\n\n");
    let mechanisms = if a.mechanisms.is_empty() {
        "no mechanism recorded".to_string()
    } else {
        a.mechanisms.join(", ")
    };
    let _ = writeln!(
        out,
        "  {} samples over {} ({}; events: {}), {} estimated allocated.",
        a.samples,
        format_duration_ms(a.duration_ms),
        mechanisms,
        a.sampling.events.join(", "),
        format_bytes(a.estimated_bytes)
    );
    out.push_str(
        "  This covers only allocations made while recording. Memory allocated before\n  \
         recording started has no stack. Arena and pool links are approximate: they name\n  \
         the most recent growth event that created the memory, not necessarily the call\n  \
         that allocated each object. Large-object links are exact: the object is the\n  \
         sampled allocation itself.\n",
    );
    let c = &a.coverage;
    let _ = writeln!(
        out,
        "  Linked {} reachable objects ({}, {:.1}% of reachable bytes) to samples, {} of it exactly.",
        c.linked_objects,
        format_bytes(c.linked_bytes),
        c.linked_pct,
        format_bytes(c.exact_linked_bytes)
    );
    if c.unlinked_reused_objects > 0 {
        let _ = writeln!(
            out,
            "  Not linked: {} reachable objects ({}) on memory of sampled large allocations they\n  \
             do not match (another start or size): the memory was reused by unsampled allocations.",
            c.unlinked_reused_objects,
            format_bytes(c.unlinked_reused_bytes)
        );
    }
    if a.truncated {
        out.push_str(
            "  The recording stopped early or lost samples; the numbers are lower bounds.\n",
        );
    }
    if a.overhead.samples_dropped > 0 {
        let _ = writeln!(
            out,
            "  {} samples were dropped while recording.",
            a.overhead.samples_dropped
        );
    }
    if a.approximate {
        out.push_str(
            "  Frames marked ~ were matched to the event by time (ETW) and may be off by a call.\n",
        );
    }
    if a.top_stacks.is_empty() {
        out.push_str("\n  (no samples)\n");
    }
    for t in &a.top_stacks {
        let _ = writeln!(
            out,
            "\n  #{}  {} estimated, {} linked ({}), {} samples ({})",
            t.rank,
            format_bytes(t.estimated_bytes),
            format_bytes(t.linked_bytes),
            link_kind(t.linked_bytes, t.exact_linked_bytes),
            t.samples,
            t.events.join(", ")
        );
        if t.frames.is_empty() {
            out.push_str("      (no Python frames)\n");
            continue;
        }
        let shown = &t.frames[..t.frames.len().min(SECTION_FRAMES)];
        let w = shown
            .iter()
            .map(|f| f.function.chars().count())
            .max()
            .unwrap_or(0);
        for f in shown {
            let pad = w - f.function.chars().count();
            let mark = if f.approximate { " ~" } else { "" };
            let _ = writeln!(
                out,
                "      {}{}  {}{mark}",
                f.function,
                " ".repeat(pad),
                f.location
            );
        }
        if t.frames.len() > SECTION_FRAMES {
            let _ = writeln!(
                out,
                "      ... {} more frames",
                t.frames.len() - SECTION_FRAMES
            );
        }
    }
}

fn notes(out: &mut String, notes: &[Note]) {
    if notes.is_empty() {
        return;
    }
    out.push('\n');
    for n in notes {
        let _ = writeln!(out, "note: {}", n.message);
    }
}

/// Signed size: `+1.2 MiB`, `-512 B`, `0 B`.
pub fn format_delta_bytes(d: i64) -> String {
    match d {
        0 => "0 B".to_string(),
        d if d > 0 => format!("+{}", format_bytes(d as u64)),
        d => format!("-{}", format_bytes(d.unsigned_abs())),
    }
}

fn format_delta(d: i64) -> String {
    if d > 0 {
        format!("+{d}")
    } else {
        d.to_string()
    }
}

/// `heapspy analyze` text output, without color.
pub fn analyze(r: &AnalyzeReport) -> Result<String> {
    summary::analyze(r, &Style::plain())
}

/// `heapspy analyze` text output, styled.
pub fn analyze_styled(r: &AnalyzeReport, st: &Style) -> Result<String> {
    summary::analyze(r, st)
}

/// A path root first, one labelled hop per line.
fn path_lines(out: &mut String, p: &[PathHop], indent: &str) {
    let rows: Vec<(String, String)> = p
        .iter()
        .map(|h| {
            let left = match (&h.root_label, &h.edge) {
                (Some(r), _) => r.clone(),
                (None, Some(e)) => format!("  {e}"),
                (None, None) => "  ?".to_string(),
            };
            let mut right = format!("{}  ({})", h.type_name, format_bytes(h.shallow_bytes));
            if let Some(l) = &h.source_loc {
                let _ = write!(right, "  {}", l.display());
            }
            (left, right)
        })
        .collect();
    let w = rows.iter().map(|r| r.0.chars().count()).max().unwrap_or(0);
    for (l, r) in rows {
        let pad = w - l.chars().count();
        let _ = writeln!(out, "{indent}{l}{}  {r}", " ".repeat(pad));
    }
}

/// `heapspy query --type` text output.
pub fn type_query(r: &TypeQueryReport) -> Result<String> {
    let mut out = String::new();
    // `module.Type (file:line)` for each matched type with a location.
    let names: Vec<String> = r
        .matched_types
        .iter()
        .map(|t| {
            let at = r
                .matched_type_locations
                .iter()
                .find(|l| &l.type_name == t)
                .and_then(|l| l.type_location.as_ref());
            match at {
                Some(l) => format!("{t} ({})", l.display()),
                None => t.clone(),
            }
        })
        .collect();
    let _ = writeln!(
        out,
        "{}: {} instances, {} shallow, {} retained",
        names.join(", "),
        r.instances,
        format_bytes(r.shallow_bytes),
        format_bytes(r.retained_bytes)
    );
    kept_by_section(&mut out, r);
    out.push_str("\nLargest instances\n\n");
    // Instances that are functions, classes, modules or code objects get a
    // column with their own location.
    let located = r.top_instances.iter().any(|i| i.source_loc.is_some());
    let rows: Vec<Vec<String>> = r
        .top_instances
        .iter()
        .map(|i| {
            let mut row = vec![
                format_bytes(i.retained_bytes),
                format_bytes(i.shallow_bytes),
                i.length.map_or("-".to_string(), |l| l.to_string()),
                i.address.to_string(),
            ];
            if located {
                row.push(
                    i.source_loc
                        .as_ref()
                        .map_or("-".to_string(), |l| l.display()),
                );
            }
            row.push(
                i.path
                    .as_deref()
                    .map_or("(unreachable)".to_string(), root_path_string),
            );
            row
        })
        .collect();
    let mut header = vec!["retained", "shallow", "len", "address"];
    if located {
        header.push("defined at");
    }
    header.push("root path");
    let extra: Vec<String> = r
        .top_instances
        .iter()
        .map(|i| {
            i.allocated_at
                .as_ref()
                .map(|at| allocated_at_lines(at, "      "))
                .unwrap_or_default()
        })
        .collect();
    table_with_extra(&mut out, &header, &rows, &[0, 1, 2], &extra);
    out.push_str("\nReferenced by\n\n");
    if r.holders.is_empty() {
        out.push_str("  (no references from other objects)\n");
    } else {
        let rows: Vec<Vec<String>> = r
            .holders
            .iter()
            .map(|h| vec![h.count.to_string(), h.type_name.clone(), h.edge.clone()])
            .collect();
        table(&mut out, &["count", "type", "edge"], &rows, &[0]);
    }
    notes(&mut out, &r.notes);
    Ok(out)
}

/// "Kept alive by": the instances grouped by the holder that keeps them,
/// with the path from it and their sizes; then the sizes of all of them.
fn kept_by_section(out: &mut String, r: &TypeQueryReport) {
    if r.kept_by.is_empty() {
        return;
    }
    out.push_str("\nKept alive by\n\n");
    let rows: Vec<Vec<String>> = r
        .kept_by
        .iter()
        .map(|k| {
            let who = match (k.kind.as_str(), &k.holder) {
                ("holder", Some(h)) => summary::holder_name(h),
                ("unreachable", _) if r.matched_types.iter().all(|t| t.starts_with("native.")) => {
                    "nothing: leaked (no pointer to them anywhere)".to_string()
                }
                ("unreachable", _) => "nothing: garbage awaiting collection".to_string(),
                _ => "smaller holders".to_string(),
            };
            vec![
                format!(
                    "{:.0}%",
                    k.bytes as f64 * 100.0 / r.shallow_bytes.max(1) as f64
                ),
                who,
                k.instances.to_string(),
                format_bytes(k.bytes),
                k.sizes
                    .iter()
                    .take(2)
                    .map(|g| format!("{} B ×{}", g.size, g.blocks))
                    .collect::<Vec<_>>()
                    .join(", "),
            ]
        })
        .collect();
    let extra: Vec<String> = r
        .kept_by
        .iter()
        .map(|k| match (&k.through, k.through_pct) {
            (Some(t), Some(p)) if p >= 99 => {
                format!(
                    "        through {}\n",
                    style::shorten(&summary::holder_name(t), 90)
                )
            }
            (Some(t), Some(p)) => format!(
                "        through {}  ({p}% of them)\n",
                style::shorten(&summary::holder_name(t), 90)
            ),
            _ => String::new(),
        })
        .collect();
    table_with_extra(
        out,
        &["share", "kept by", "instances", "bytes", "sizes"],
        &rows,
        &[0, 2, 3],
        &extra,
    );
    if r.by_size.len() > 1 {
        out.push_str("\nSizes\n\n");
        let rows: Vec<Vec<String>> = r
            .by_size
            .iter()
            .take(8)
            .map(|g| {
                vec![
                    format!("{} B", g.size),
                    g.blocks.to_string(),
                    format_bytes(g.bytes),
                ]
            })
            .collect();
        table(out, &["size", "instances", "bytes"], &rows, &[0, 1, 2]);
    }
}

/// `heapspy query --retaining-path` text output.
pub fn retaining_path(r: &RetainingPathReport) -> Result<String> {
    let mut out = String::new();
    for (k, t) in r.targets.iter().enumerate() {
        if k > 0 {
            out.push('\n');
        }
        let at = t
            .type_location
            .as_ref()
            .map_or(String::new(), |l| format!(" ({})", l.display()));
        let _ = writeln!(
            out,
            "{} {}{at}  shallow {}, retained {}",
            t.address,
            t.type_name,
            format_bytes(t.shallow_bytes),
            format_bytes(t.retained_bytes)
        );
        if !t.reachable {
            out.push_str("  not reachable from any root\n");
            continue;
        }
        for (i, p) in t.paths.iter().enumerate() {
            let _ = writeln!(out, "\n  path {} ({} hops)", i + 1, p.len());
            path_lines(&mut out, p, "  ");
        }
    }
    notes(&mut out, &r.notes);
    Ok(out)
}

/// `heapspy query --locate` text output.
pub fn locate(r: &LocateReport) -> Result<String> {
    let mut out = String::new();
    let rows: Vec<Vec<String>> = r
        .matches
        .iter()
        .map(|m| {
            let at = match (&m.source_loc, &m.source_loc_reason) {
                (Some(l), _) => l.display(),
                (None, Some(reason)) => format!("unknown ({reason})"),
                (None, None) => "unknown".to_string(),
            };
            vec![m.kind.clone(), m.address.to_string(), at]
        })
        .collect();
    let _ = writeln!(out, "{}\n", r.query);
    table(&mut out, &["kind", "address", "defined at"], &rows, &[]);
    notes(&mut out, &r.notes);
    Ok(out)
}

/// `heapspy diff` text output.
pub fn diff(r: &DiffReport) -> Result<String> {
    let mut out = String::new();
    let t = &r.totals;
    let _ = writeln!(
        out,
        "{} -> {}: objects {} -> {} ({}), reachable {} -> {} ({})",
        r.before.path,
        r.after.path,
        t.before.objects,
        t.after.objects,
        format_delta(t.delta_objects),
        format_bytes(t.before.reachable_bytes),
        format_bytes(t.after.reachable_bytes),
        format_delta_bytes(t.delta_reachable_bytes)
    );

    out.push_str("\nGrowth by retaining site\n\n");
    if r.by_site.is_empty() {
        out.push_str("  (no change)\n");
    } else {
        let rows: Vec<Vec<String>> = r
            .by_site
            .iter()
            .map(|s| {
                vec![
                    format_delta_bytes(s.delta_retained_bytes),
                    format_bytes(s.before_retained_bytes),
                    format_bytes(s.after_retained_bytes),
                    format_delta(s.delta_retained_objects),
                    s.type_name.clone(),
                    s.site.clone(),
                ]
            })
            .collect();
        table(
            &mut out,
            &["delta", "before", "after", "objects", "type", "site"],
            &rows,
            &[0, 1, 2, 3],
        );
    }

    out.push_str("\nGrowth by type\n\n");
    if r.by_type.is_empty() {
        out.push_str("  (no change)\n");
    } else {
        let rows: Vec<Vec<String>> = r
            .by_type
            .iter()
            .map(|x| {
                vec![
                    format_delta_bytes(x.delta_bytes),
                    format_delta(x.delta_count),
                    x.before_count.to_string(),
                    x.after_count.to_string(),
                    x.type_name.clone(),
                ]
            })
            .collect();
        table(
            &mut out,
            &["delta", "count", "before", "after", "type"],
            &rows,
            &[0, 1, 2, 3],
        );
    }
    notes(&mut out, &r.notes);
    Ok(out)
}

pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1126), "1.1 KiB");
        assert_eq!(format_bytes(432_643_686), "412.6 MiB");
        assert_eq!(format_bytes(u64::MAX), "16.0 EiB");
        assert_eq!(format_delta_bytes(-2048), "-2.0 KiB");
        assert_eq!(format_delta_bytes(5), "+5 B");
    }

    #[test]
    fn table_alignment() {
        let mut s = String::new();
        table(
            &mut s,
            &["n", "name"],
            &[
                vec!["1".into(), "a".into()],
                vec!["100".into(), "bb".into()],
            ],
            &[0],
        );
        assert_eq!(s, "    n  name\n    1  a\n  100  bb\n");
    }
}
