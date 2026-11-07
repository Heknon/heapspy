//! The `heapspy analyze` text report: where the process's memory is, what
//! holds it, and what to look at next.

use std::fmt::Write as _;

use super::style::{bar, pad_left, pad_right, shorten, Paint, Style};
use super::{allocated_at_lines, allocations_section, format_bytes, notes};
use crate::report::{AnalyzeReport, MemoryTotals, Note};
use crate::{root_path_string, Result};

/// One line of the memory overview: several `memory.breakdown` parts
/// grouped the way a reader thinks about them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryGroup {
    /// Stable key: `python`, `native`, `leaked`, `free`, `other`,
    /// `pymalloc_free`, `mapped`.
    pub key: &'static str,
    pub label: &'static str,
    pub paint: Paint,
    pub bytes: u64,
    /// What it is, in a few words.
    pub what: String,
}

/// The memory overview groups of `m`, in display order, skipping groups the
/// snapshot has no data for. Empty without a memory map.
pub fn memory_groups(m: &MemoryTotals) -> Vec<MemoryGroup> {
    let get = |name: &str| -> Option<u64> {
        m.breakdown.iter().find(|p| p.part == name).map(|p| p.bytes)
    };
    if m.breakdown.is_empty() {
        return Vec::new();
    }
    let mut g = Vec::new();
    let small = get("python_small_objects").unwrap_or(0);
    let large = get("python_large_objects").unwrap_or(0);
    g.push(MemoryGroup {
        key: "python",
        label: "Python objects",
        paint: Paint::Python,
        bytes: small + large,
        what: format!(
            "pymalloc {} · larger objects from malloc {}",
            format_bytes(small),
            format_bytes(large)
        ),
    });
    if let Some(b) = get("native_heap") {
        g.push(MemoryGroup {
            key: "native",
            label: "Native, in use",
            paint: Paint::Native,
            bytes: b,
            what: "malloc'd blocks something still points to".into(),
        });
    }
    if let Some(b) = get("native_lost") {
        g.push(MemoryGroup {
            key: "leaked",
            label: "Native, leaked",
            paint: Paint::Leaked,
            bytes: b,
            what: "malloc'd blocks nothing points to".into(),
        });
    }
    if let Some(b) = get("native_free") {
        let what = match &m.native_allocator {
            Some(a) => format!(
                "freed by C code, kept by malloc in {} arena{}, not returned to the OS",
                a.arenas,
                if a.arenas == 1 { "" } else { "s" }
            ),
            None => "freed by C code, kept by malloc".into(),
        };
        g.push(MemoryGroup {
            key: "free",
            label: "Allocator free",
            paint: Paint::Free,
            bytes: b,
            what,
        });
    }
    if let Some(b) = get("native_other") {
        g.push(MemoryGroup {
            key: "other",
            label: "Other private",
            paint: Paint::Other,
            bytes: b,
            what: if get("native_free").is_some() {
                "allocator overhead, memory C code mapped itself".into()
            } else {
                "allocator overhead and free space, memory C code mapped itself".into()
            },
        });
    }
    if let Some(b) = get("native_unknown") {
        g.push(MemoryGroup {
            key: "other",
            label: "Native (not walked)",
            paint: Paint::Other,
            bytes: b,
            what: "memory C code allocated; the native heap was not walked".into(),
        });
    }
    g.push(MemoryGroup {
        key: "pymalloc_free",
        label: "pymalloc free",
        paint: Paint::PymallocFree,
        bytes: get("pymalloc_free").unwrap_or(0),
        what: "empty space in Python's own arenas".into(),
    });
    let images = get("images").unwrap_or(0);
    let mapped = get("mapped_files").unwrap_or(0);
    let stacks = get("stacks").unwrap_or(0);
    g.push(MemoryGroup {
        key: "mapped",
        label: "Code, files, stacks",
        paint: Paint::Mapped,
        bytes: images + mapped + stacks,
        what: format!(
            "libraries {} · mapped files {} · thread stacks {}",
            format_bytes(images),
            format_bytes(mapped),
            format_bytes(stacks)
        ),
    });
    g
}

/// A share of `total` as ` 12%`.
fn share(part: u64, total: u64) -> String {
    if total == 0 {
        return "-".into();
    }
    let p = part as f64 * 100.0 / total as f64;
    if p > 0.0 && p < 1.0 {
        "<1%".into()
    } else {
        format!("{p:.0}%")
    }
}

/// `heapspy analyze` text output, styled.
pub fn analyze(r: &AnalyzeReport, st: &Style) -> Result<String> {
    let mut out = String::new();
    let t = &r.totals;
    let w = st.width.clamp(60, 200);
    let mut head = format!(
        "{} · CPython {} · {} objects",
        r.snapshot.path, r.snapshot.python_version, t.objects
    );
    if t.native_blocks > 0 {
        let _ = write!(head, " · {} native heap blocks", t.native_blocks);
    }
    let _ = writeln!(out, "{}", st.paint(Paint::Dim, head));

    memory_section(&mut out, r, st, w);
    holders_section(&mut out, r, st, w);
    if let Some(a) = &r.allocations {
        allocations_section(&mut out, a);
    }
    types_section(&mut out, r, st);
    leaked_section(&mut out, r, st);
    free_section(&mut out, r, st);

    let rest: Vec<Note> = r
        .notes
        .iter()
        // Covered by the sections above.
        .filter(|n| {
            !matches!(
                n.code.as_str(),
                "outside_graph" | "allocations_sampled" | "native_lost"
            )
        })
        .cloned()
        .collect();
    if st.color {
        let mut tmp = String::new();
        notes(&mut tmp, &rest);
        out.push_str(&st.paint(Paint::Dim, tmp.trim_end()));
        if !tmp.is_empty() {
            out.push('\n');
        }
    } else {
        notes(&mut out, &rest);
    }
    Ok(out)
}

fn memory_section(out: &mut String, r: &AnalyzeReport, st: &Style, w: usize) {
    let m = &r.memory;
    let groups = memory_groups(m);
    let total: u64 = groups.iter().map(|g| g.bytes).sum();
    out.push('\n');
    if groups.is_empty() || total == 0 {
        let _ = writeln!(out, "{}", st.paint(Paint::Heading, "Memory"));
        let _ = writeln!(
            out,
            "  Python graph {}{}",
            st.paint(Paint::Strong, format_bytes(m.graph_bytes)),
            match m.rss_bytes {
                Some(rss) => format!(" of {} RSS", format_bytes(rss)),
                None => " (process RSS was not recorded)".into(),
            }
        );
        return;
    }
    let basis = m.breakdown_basis.as_deref().unwrap_or("committed");
    let title = if basis == "resident" {
        format!("Where the {} of resident memory is", format_bytes(total))
    } else {
        format!("Where the {} of committed memory is", format_bytes(total))
    };
    let _ = writeln!(out, "{}", st.paint(Paint::Heading, title));
    if st.color {
        // One stacked bar, a color per group.
        let width = (w - 4).min(80);
        let mut line = String::from("  ");
        let mut used = 0usize;
        let mut cum = 0u64;
        for g in &groups {
            cum += g.bytes;
            let end = ((cum as f64 / total as f64) * width as f64).round() as usize;
            let n = end.saturating_sub(used);
            used += n;
            line.push_str(&st.paint(g.paint, "█".repeat(n)));
        }
        let _ = writeln!(out, "{line}");
    }
    for g in &groups {
        if g.bytes == 0 && matches!(g.key, "free" | "other") {
            continue;
        }
        let marker = if st.color {
            st.paint(g.paint, "■")
        } else {
            let (f, e) = bar(g.bytes as f64 / total as f64, 10);
            format!("{f}{e}")
        };
        let _ = writeln!(
            out,
            "  {} {}{}{}   {}",
            marker,
            pad_right(g.label, 20),
            pad_left(&format_bytes(g.bytes), 10),
            pad_left(&share(g.bytes, total), 5),
            st.paint(Paint::Dim, &g.what)
        );
    }
    if let Some(rss) = m.rss_bytes {
        if basis == "resident" && rss.abs_diff(total) > rss / 20 {
            let _ = writeln!(
                out,
                "  {}",
                st.paint(
                    Paint::Dim,
                    format!(
                        "(RSS {}: the map's resident pages and RSS were read at slightly \
                         different moments)",
                        format_bytes(rss)
                    )
                )
            );
        }
    }
}

fn holders_section(out: &mut String, r: &AnalyzeReport, st: &Style, w: usize) {
    out.push('\n');
    let native = r.totals.native_blocks > 0;
    let num_w = 10;
    let cols = if native { 3 } else { 1 };
    // rank + two spaces, the numbers, the share column.
    let path_w = w.saturating_sub(4 + cols * num_w + 8).max(30);
    let mut head = pad_right(
        &st.paint(Paint::Heading, "What is holding memory"),
        path_w + 4,
    );
    head.push_str(&pad_left(&st.paint(Paint::Dim, "retained"), num_w));
    if native {
        head.push_str(&pad_left(&st.paint(Paint::Python, "python"), num_w));
        head.push_str(&pad_left(&st.paint(Paint::Native, "native"), num_w));
    }
    head.push_str(&pad_left(&st.paint(Paint::Dim, "share"), 8));
    let _ = writeln!(out, "{}", head.trim_end());
    if r.top_retainers.is_empty() {
        let _ = writeln!(out, "  (nothing)");
        return;
    }
    for (i, x) in r.top_retainers.iter().enumerate() {
        let path = shorten(&root_path_string(&x.path), path_w);
        let rank = format!("{:>2}", x.rank);
        let rank = if i < 3 {
            st.paint(Paint::Warn, rank)
        } else {
            st.paint(Paint::Dim, rank)
        };
        let mut line = format!(
            "{rank}  {}",
            pad_right(&st.paint(Paint::Strong, &path), path_w)
        );
        let ret = format_bytes(x.retained_bytes);
        line.push_str(&pad_left(
            &if i == 0 {
                st.paint(Paint::Bad, ret)
            } else {
                ret
            },
            num_w,
        ));
        if native {
            let nat = x.native_retained_bytes.unwrap_or(0).min(x.retained_bytes);
            let py = x.retained_bytes - nat;
            let cell = |b: u64, p: Paint| {
                if b == 0 {
                    st.paint(Paint::Dim, "0")
                } else {
                    st.paint(p, format_bytes(b))
                }
            };
            line.push_str(&pad_left(&cell(py, Paint::Python), num_w));
            line.push_str(&pad_left(&cell(nat, Paint::Native), num_w));
        }
        line.push_str(&pad_left(&format!("{:.1}%", x.retained_pct), 8));
        let _ = writeln!(out, "{line}");
        let mut sub = format!("{} · {} objects", x.type_name, x.retained_objects);
        if let Some(l) = &x.type_location {
            let _ = write!(sub, " · {}", l.display());
        }
        let _ = writeln!(out, "      {}", st.paint(Paint::Dim, sub));
        if let Some(at) = &x.allocated_at {
            out.push_str(&allocated_at_lines(at, "      "));
        }
    }
}

fn types_section(out: &mut String, r: &AnalyzeReport, st: &Style) {
    if r.type_histogram.is_empty() {
        return;
    }
    out.push('\n');
    let _ = writeln!(
        out,
        "{}{}{}{}",
        pad_right(&st.paint(Paint::Heading, "Biggest types"), 40),
        pad_left(&st.paint(Paint::Dim, "count"), 12),
        pad_left(&st.paint(Paint::Dim, "shallow"), 12),
        pad_left(&st.paint(Paint::Dim, "retained"), 12)
    );
    for x in r.type_histogram.iter().take(10) {
        let name = shorten(&x.type_name, 36);
        let name = if x.type_name.starts_with("native.") {
            st.paint(Paint::Native, name)
        } else if x.type_name.starts_with("builtins.") {
            name
        } else {
            st.paint(Paint::Type, name)
        };
        let _ = writeln!(
            out,
            "  {}{}{}{}",
            pad_right(&name, 38),
            pad_left(&x.count.to_string(), 12),
            pad_left(&format_bytes(x.shallow_bytes), 12),
            pad_left(&format_bytes(x.retained_bytes), 12)
        );
    }
    if r.type_histogram.len() > 10 {
        let _ = writeln!(
            out,
            "  {}",
            st.paint(
                Paint::Dim,
                format!("… {} more in --json", r.type_histogram.len() - 10)
            )
        );
    }
}

fn leaked_section(out: &mut String, r: &AnalyzeReport, st: &Style) {
    let t = &r.totals;
    if t.native_lost_blocks == 0 {
        return;
    }
    out.push('\n');
    let _ = writeln!(
        out,
        "{}  {} in {} blocks that nothing points to",
        st.paint(Paint::Heading, "Leaked native memory"),
        st.paint(Paint::Leaked, format_bytes(t.native_lost_bytes)),
        t.native_lost_blocks
    );
    let groups = &r.memory.native_lost_by_size;
    if !groups.is_empty() {
        let _ = writeln!(
            out,
            "  {}",
            st.paint(Paint::Dim, "block size      blocks        bytes")
        );
        let shown: u64 = groups.iter().take(5).map(|g| g.bytes).sum();
        for (i, g) in groups.iter().take(5).enumerate() {
            let mut line = format!(
                "  {}{}{}",
                pad_left(&format!("{} B", g.size), 10),
                pad_left(&g.blocks.to_string(), 12),
                pad_left(&format_bytes(g.bytes), 13)
            );
            let frac = g.bytes as f64 / t.native_lost_bytes.max(1) as f64;
            if i == 0 && frac >= 0.5 && g.blocks >= 10 {
                let _ = write!(
                    line,
                    "   {}",
                    st.paint(
                        Paint::Warn,
                        format!("◀ {:.0}% one size: most likely one leak site", frac * 100.0)
                    )
                );
            }
            let _ = writeln!(out, "{line}");
        }
        let rest = t.native_lost_bytes.saturating_sub(shown);
        if groups.len() > 5 && rest > 0 {
            let _ = writeln!(
                out,
                "  {}",
                st.paint(
                    Paint::Dim,
                    format!("     other sizes: {}", format_bytes(rest))
                )
            );
        }
    }
    let _ = writeln!(
        out,
        "  {}",
        st.paint(
            Paint::Dim,
            "No Python object, other block, C global or stack holds their address."
        )
    );
    let _ = writeln!(
        out,
        "  {}",
        st.paint(
            Paint::Dim,
            "Watch them grow with `heapspy top`; a snapshot cannot say who allocated them."
        )
    );
}

fn free_section(out: &mut String, r: &AnalyzeReport, st: &Style) {
    let Some(a) = &r.memory.native_allocator else {
        return;
    };
    let free = r
        .memory
        .breakdown
        .iter()
        .find(|p| p.part == "native_free")
        .map_or(0, |p| p.bytes);
    let total: u64 = r.memory.breakdown.iter().map(|p| p.bytes).sum();
    // Only worth a section when it is a real part of the process.
    if free < (16 << 20) && free * 10 < total {
        return;
    }
    out.push('\n');
    let _ = writeln!(
        out,
        "{}  {} that malloc keeps in {} arena{} ({} free chunks) and has not returned to the OS",
        st.paint(Paint::Heading, "Allocator free"),
        st.paint(Paint::Free, format_bytes(free)),
        a.arenas,
        if a.arenas == 1 { "" } else { "s" },
        a.free_chunks
    );
    if a.arenas > 2 {
        let _ = writeln!(
            out,
            "  {}",
            st.paint(
                Paint::Dim,
                "Many arenas with scattered free chunks is typical of many threads calling malloc."
            )
        );
    }
    let _ = writeln!(
        out,
        "  {} {} {} {}",
        st.paint(Paint::Dim, "Often recovered with"),
        st.paint(Paint::Command, "MALLOC_ARENA_MAX=2"),
        st.paint(Paint::Dim, "in the environment, or a periodic"),
        st.paint(Paint::Command, "malloc_trim(0)")
    );
}
