//! Plain-text rendering of reports for the terminal.
//!
//! Text output is for people and may change at any time. Tools must use
//! `--json`.

use std::fmt::Write as _;

use crate::report::{
    AnalyzeReport, DiffReport, LocateReport, Note, PathHop, RetainingPathReport, TypeQueryReport,
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

/// `heapspy analyze` text output.
pub fn analyze(r: &AnalyzeReport) -> Result<String> {
    let mut out = String::new();
    let t = &r.totals;
    let _ = writeln!(
        out,
        "{}: {} objects ({}), {} references, {} roots, CPython {}",
        r.snapshot.path,
        t.objects,
        format_bytes(t.shallow_bytes),
        t.edges,
        t.roots,
        r.snapshot.python_version
    );
    let _ = writeln!(
        out,
        "reachable: {} objects ({}); unreachable: {} objects ({})",
        t.reachable_objects,
        format_bytes(t.reachable_bytes),
        t.unreachable_objects,
        format_bytes(t.unreachable_bytes)
    );

    out.push_str("\nTop retainers by retained size\n\n");
    if r.top_retainers.is_empty() {
        out.push_str("  (none)\n");
    } else {
        let rows: Vec<Vec<String>> = r
            .top_retainers
            .iter()
            .map(|x| {
                vec![
                    format_bytes(x.retained_bytes),
                    format!("{:.1}%", x.retained_pct),
                    format_bytes(x.shallow_bytes),
                    x.type_name.clone(),
                    root_path_string(&x.path),
                ]
            })
            .collect();
        table(
            &mut out,
            &["retained", "%", "shallow", "type", "root path"],
            &rows,
            &[0, 1, 2],
        );
    }

    out.push_str("\nTypes by retained size\n\n");
    if r.type_histogram.is_empty() {
        out.push_str("  (none)\n");
    } else {
        let rows: Vec<Vec<String>> = r
            .type_histogram
            .iter()
            .map(|x| {
                vec![
                    format_bytes(x.retained_bytes),
                    format_bytes(x.shallow_bytes),
                    x.count.to_string(),
                    x.type_name.clone(),
                ]
            })
            .collect();
        table(
            &mut out,
            &["retained", "shallow", "count", "type"],
            &rows,
            &[0, 1, 2],
        );
    }

    let m = &r.memory;
    out.push('\n');
    match m.rss_bytes {
        Some(rss) => {
            let _ = writeln!(
                out,
                "Python graph accounts for {} of {} RSS ({} outside the graph).",
                format_bytes(m.graph_bytes),
                format_bytes(rss),
                format_bytes(m.outside_graph_bytes.unwrap_or(0))
            );
        }
        None => {
            let _ = writeln!(
                out,
                "Python graph holds {}. Process RSS was not recorded.",
                format_bytes(m.graph_bytes)
            );
        }
    }
    let rest: Vec<Note> = r
        .notes
        .iter()
        .filter(|n| n.code != "outside_graph")
        .cloned()
        .collect();
    notes(&mut out, &rest);
    Ok(out)
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
            let right = format!("{}  ({})", h.type_name, format_bytes(h.shallow_bytes));
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
    let _ = writeln!(
        out,
        "{}: {} instances, {} shallow, {} retained",
        r.matched_types.join(", "),
        r.instances,
        format_bytes(r.shallow_bytes),
        format_bytes(r.retained_bytes)
    );
    out.push_str("\nLargest instances\n\n");
    let rows: Vec<Vec<String>> = r
        .top_instances
        .iter()
        .map(|i| {
            vec![
                format_bytes(i.retained_bytes),
                format_bytes(i.shallow_bytes),
                i.length.map_or("-".to_string(), |l| l.to_string()),
                i.address.to_string(),
                i.path
                    .as_deref()
                    .map_or("(unreachable)".to_string(), root_path_string),
            ]
        })
        .collect();
    table(
        &mut out,
        &["retained", "shallow", "len", "address", "root path"],
        &rows,
        &[0, 1, 2],
    );
    out.push_str("\nHeld by\n\n");
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

/// `heapspy query --retaining-path` text output.
pub fn retaining_path(r: &RetainingPathReport) -> Result<String> {
    let mut out = String::new();
    for (k, t) in r.targets.iter().enumerate() {
        if k > 0 {
            out.push('\n');
        }
        let _ = writeln!(
            out,
            "{} {}  shallow {}, retained {}",
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

/// Binary-unit size with one decimal: `412.6 MiB`, `1.1 KiB`, `512 B`.
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
