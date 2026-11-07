//! The `heapspy analyze` text report: where the process's memory is, what
//! holds it, and what to look at next.

use std::fmt::Write as _;

use super::style::{pad_left, pad_right, shorten, Paint, Style};
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

/// A root path as a reader names it: `sys.modules['app.cache'].__dict__['CACHE']`
/// becomes `app.cache.CACHE`, and `.__dict__['x']` becomes `.x` wherever
/// `x` is an identifier. Other paths are kept as they are.
pub fn holder_name(path: &str) -> String {
    let mut s = match path.strip_prefix("sys.modules['") {
        Some(rest) => match rest.find("']") {
            Some(i) => format!("{}{}", &rest[..i], &rest[i + 2..]),
            None => path.to_string(),
        },
        None => path.to_string(),
    };
    while let Some(i) = s.find(".__dict__['") {
        let tail = &s[i + 11..];
        let Some(j) = tail.find("']") else { break };
        let key = &tail[..j];
        if key.is_empty() || !key.chars().all(|c| c.is_alphanumeric() || c == '_') {
            break;
        }
        s = format!("{}.{}{}", &s[..i], key, &tail[j + 2..]);
    }
    collapse_c_hops(&s)
}

/// A run of raw native hops (` <+16>`, ` <contents>`) is one ` → C memory`.
fn collapse_c_hops(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    let mut in_c = false;
    while !rest.is_empty() {
        let hop = if rest.starts_with(" <contents>") {
            Some(" <contents>".len())
        } else {
            rest.strip_prefix(" <+").and_then(|r| {
                let end = r.find('>')?;
                (end > 0 && r[..end].chars().all(|c| c.is_ascii_digit())).then_some(3 + end + 1)
            })
        };
        match hop {
            Some(n) => {
                if !in_c {
                    out.push_str(" → C memory");
                    in_c = true;
                }
                rest = &rest[n..];
            }
            None => {
                let c = rest.chars().next().unwrap_or(' ');
                out.push(c);
                rest = &rest[c.len_utf8()..];
                in_c = false;
            }
        }
    }
    out
}

/// How a type is shown: friendly names for native heap blocks.
pub fn display_type(name: &str) -> (String, Paint) {
    match name {
        "native.heap_block" => ("native malloc blocks".into(), Paint::Native),
        "native.large_allocation" => ("native large allocations (mmap)".into(), Paint::Native),
        "native.small_block_container" => ("native small-block containers".into(), Paint::Native),
        n if n.starts_with("native.") => (n.to_string(), Paint::Native),
        n if n.starts_with("builtins.") => {
            (n.trim_start_matches("builtins.").to_string(), Paint::Strong)
        }
        n => (n.to_string(), Paint::Type),
    }
}

/// One row of "what the memory is": a type, or the leaked part of a native
/// type.
#[derive(Clone, Debug, PartialEq)]
pub struct WhatRow {
    /// Stable key: the type name, or `leaked:<type>`.
    pub key: String,
    /// The type name as in reports (for queries).
    pub type_name: String,
    pub label: String,
    pub paint: Paint,
    pub count: u64,
    /// Shallow bytes: what these objects themselves take.
    pub bytes: u64,
    /// What they keep alive, themselves included.
    pub retained: u64,
    /// Root path of the holder of most of them, and the share it holds.
    pub held_by: Option<String>,
    /// Rank of that holder in `top_retainers`.
    pub held_by_rank: Option<u32>,
    pub held_pct: f64,
    pub leaked: bool,
    pub location: Option<String>,
}

/// What the memory is made of: one row per type, native blocks split into
/// in use and leaked, largest first.
pub fn what_rows(r: &AnalyzeReport) -> Vec<WhatRow> {
    let mut out = Vec::new();
    let src = if r.types_by_size.is_empty() {
        &r.type_histogram
    } else {
        &r.types_by_size
    };
    for t in src {
        let (label, paint) = display_type(&t.type_name);
        let lost_n = t.unreachable_count.unwrap_or(0).min(t.count);
        let lost_b = t.unreachable_bytes.unwrap_or(0).min(t.shallow_bytes);
        let native = t.type_name.starts_with("native.");
        let split = native && lost_n > 0;
        let (count, bytes) = if split {
            (t.count - lost_n, t.shallow_bytes - lost_b)
        } else {
            (t.count, t.shallow_bytes)
        };
        if count > 0 {
            out.push(WhatRow {
                key: t.type_name.clone(),
                type_name: t.type_name.clone(),
                label: if split {
                    format!("{label}, in use")
                } else {
                    label.clone()
                },
                paint,
                count,
                bytes,
                retained: t.retained_bytes,
                held_by: t.held_by.as_deref().map(|h| {
                    if crate::is_interpreter_holder(h) {
                        "the interpreter".to_string()
                    } else {
                        holder_name(h)
                    }
                }),
                held_by_rank: t.held_by_rank,
                held_pct: t
                    .held_by_bytes
                    .map_or(0.0, |b| b as f64 * 100.0 / bytes.max(1) as f64)
                    .min(100.0),
                leaked: false,
                location: t.type_location.as_ref().map(|l| l.display()),
            });
        }
        if split {
            out.push(WhatRow {
                key: format!("leaked:{}", t.type_name),
                type_name: t.type_name.clone(),
                label: format!("{label}, leaked"),
                paint: Paint::Leaked,
                count: lost_n,
                bytes: lost_b,
                retained: lost_b,
                held_by: None,
                held_by_rank: None,
                held_pct: 0.0,
                leaked: true,
                location: None,
            });
        }
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.key.cmp(&b.key)));
    out
}

/// Types that make up the interpreter itself rather than the program's
/// data: code, classes, descriptors, modules. Folded into one row by
/// [`fold_internals`].
pub fn is_internal(type_name: &str) -> bool {
    matches!(
        type_name,
        "builtins.code"
            | "builtins.type"
            | "builtins.module"
            | "builtins.wrapper_descriptor"
            | "builtins.method_descriptor"
            | "builtins.classmethod_descriptor"
            | "builtins.builtin_function_or_method"
            | "builtins.getset_descriptor"
            | "builtins.member_descriptor"
            | "builtins.staticmethod"
            | "builtins.classmethod"
            | "builtins.property"
            | "builtins.mappingproxy"
            | "builtins.method-wrapper"
            | "builtins.weakref"
            | "weakref.ReferenceType"
            | "abc.ABCMeta"
            | "enum.EnumType"
            | "_abc._abc_data"
            | "native.large_allocation"
    ) || (type_name.starts_with("_ctypes.") && type_name.ends_with("Type"))
        || type_name.starts_with("_frozen_importlib")
}

/// Key of the folded row.
pub const INTERNALS: &str = "internals";

/// `rows` with the interpreter's own objects ([`is_internal`]) folded into
/// one row, except those `keep` wants shown (in `top`: the growing ones).
pub fn fold_internals(rows: Vec<WhatRow>, keep: impl Fn(&WhatRow) -> bool) -> Vec<WhatRow> {
    let (mut out, mut folded) = (Vec::new(), Vec::new());
    for r in rows {
        if !r.leaked && is_internal(&r.type_name) && !keep(&r) {
            folded.push(r);
        } else {
            out.push(r);
        }
    }
    if folded.is_empty() {
        return out;
    }
    let names: Vec<String> = folded.iter().take(3).map(|r| r.label.clone()).collect();
    out.push(WhatRow {
        key: INTERNALS.to_string(),
        type_name: INTERNALS.to_string(),
        label: "interpreter internals".to_string(),
        paint: Paint::Dim,
        count: folded.iter().map(|r| r.count).sum(),
        bytes: folded.iter().map(|r| r.bytes).sum(),
        retained: folded.iter().map(|r| r.bytes).sum(),
        held_by: Some(format!("{} types: {}, …", folded.len(), names.join(", "))),
        held_by_rank: None,
        held_pct: 0.0,
        leaked: false,
        location: None,
    });
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.key.cmp(&b.key)));
    out
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
    what_section(&mut out, r, st, w);
    holders_section(&mut out, r, st, w);
    if let Some(a) = &r.allocations {
        allocations_section(&mut out, a);
    }
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
    let all = memory_groups(m);
    let total: u64 = all.iter().map(|g| g.bytes).sum();
    // Leave out slivers, but never the leaked row.
    let groups: Vec<MemoryGroup> = all
        .into_iter()
        .filter(|g| g.bytes > 0 && (g.key == "leaked" || g.bytes * 200 >= total))
        .collect();
    out.push('\n');
    if groups.is_empty() || total == 0 {
        let _ = writeln!(
            out,
            "{} Python graph {}{}",
            st.paint(Paint::Heading, "Memory"),
            st.paint(Paint::Strong, format_bytes(m.graph_bytes)),
            match m.rss_bytes {
                Some(rss) => format!(" of {} RSS", format_bytes(rss)),
                None => String::new(),
            }
        );
        return;
    }
    let what = if m.breakdown_basis.as_deref() == Some("resident") {
        "resident"
    } else {
        "committed"
    };
    // One bar, a color per kind of memory, then the legend.
    let mut line = format!(
        "{} {} {}  ",
        st.paint(Paint::Heading, "Memory"),
        st.paint(Paint::Strong, format_bytes(total)),
        st.paint(Paint::Dim, what)
    );
    let width = 40usize.min(w.saturating_sub(30));
    if st.color {
        let (mut used, mut cum) = (0usize, 0u64);
        for g in &groups {
            cum += g.bytes;
            let end = ((cum as f64 / total as f64) * width as f64).round() as usize;
            line.push_str(&st.paint(g.paint, "█".repeat(end.saturating_sub(used))));
            used = end.max(used);
        }
    }
    let _ = writeln!(out, "{line}");
    let mut legend = String::from(" ");
    let mut col = 1usize;
    for g in &groups {
        let item = format!(
            "{} {} {} {}",
            if st.color {
                "■".to_string()
            } else {
                "·".to_string()
            },
            g.label,
            format_bytes(g.bytes),
            st.paint(Paint::Dim, share(g.bytes, total))
        );
        let item = if st.color {
            item.replacen('■', &st.paint(g.paint, "■"), 1)
        } else {
            item
        };
        let wv = super::style::visible_width(&item) + 3;
        if col + wv > w && col > 1 {
            legend.push_str("\n ");
            col = 1;
        }
        legend.push_str(&format!(" {item}  "));
        col += wv;
    }
    let _ = writeln!(out, "{}", legend.trim_end());
}

fn what_section(out: &mut String, r: &AnalyzeReport, st: &Style, w: usize) {
    let rows = fold_internals(what_rows(r), |_| false);
    if rows.is_empty() {
        return;
    }
    out.push('\n');
    // What, and who keeps it, side by side; the numbers after.
    let name_w = 30usize;
    let held_w = w
        .saturating_sub(2 + name_w + 2 + 9 + 11 + 9 + 13)
        .clamp(20, 48);
    let _ = writeln!(
        out,
        "{}{}{}{}{}{}",
        pad_right(&st.paint(Paint::Heading, "What the memory is"), name_w + 4),
        pad_right(&st.paint(Paint::Dim, "mostly held by"), held_w),
        pad_left(&st.paint(Paint::Dim, "count"), 9),
        pad_left(&st.paint(Paint::Dim, "size"), 11),
        pad_left(&st.paint(Paint::Dim, "each"), 9),
        pad_left(&st.paint(Paint::Dim, "keeps alive"), 13),
    );
    let shown = rows.len().min(15);
    for x in &rows[..shown] {
        let name = st.paint(x.paint, shorten(&x.label, name_w));
        let each = format_bytes(x.bytes / x.count.max(1));
        let held = if x.leaked {
            st.paint(Paint::Leaked, "nothing: leaked")
        } else if x.key == INTERNALS {
            st.paint(Paint::Dim, "the interpreter itself")
        } else {
            match &x.held_by {
                // The share first, so a long name is cut at its end.
                Some(h) => format!(
                    "{} {}",
                    st.paint(Paint::Dim, format!("{:>3.0}%", x.held_pct)),
                    super::style::shorten_left(h, held_w.saturating_sub(6))
                ),
                None => st.paint(Paint::Dim, "various"),
            }
        };
        let _ = writeln!(
            out,
            "  {}  {}{}{}{}{}",
            pad_right(&name, name_w),
            pad_right(&held, held_w),
            pad_left(&x.count.to_string(), 9),
            pad_left(&st.paint(Paint::Strong, format_bytes(x.bytes)), 11),
            pad_left(&st.paint(Paint::Dim, each), 9),
            pad_left(&format_bytes(x.retained), 13),
        );
    }
    if rows.len() > shown {
        let _ = writeln!(
            out,
            "  {}",
            st.paint(
                Paint::Dim,
                format!("… {} more types (--top N, --json)", rows.len() - shown)
            )
        );
    }
}

fn holders_section(out: &mut String, r: &AnalyzeReport, st: &Style, w: usize) {
    out.push('\n');
    let native = r.totals.native_blocks > 0;
    let num_w = 10;
    let cols = if native { 3 } else { 1 };
    // rank + two spaces, the numbers, the share column.
    let path_w = w.saturating_sub(4 + cols * num_w + 8).max(30);
    let mut head = pad_right(&st.paint(Paint::Heading, "Who holds it"), path_w + 4);
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
    let what = what_rows(r);
    // The interpreter's own holders are one line at the end.
    let (interp, program): (Vec<_>, Vec<_>) = r
        .top_retainers
        .iter()
        .partition(|x| crate::is_interpreter_holder(&root_path_string(&x.path)));
    for (i, x) in program.into_iter().take(10).enumerate() {
        let path = shorten(&holder_name(&root_path_string(&x.path)), path_w);
        let rank = format!("{:>2}", i + 1);
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
        // What it holds: the types it is the main holder of.
        let holds: Vec<String> = what
            .iter()
            .filter(|w| w.held_by_rank == Some(x.rank))
            .take(3)
            .map(|w| format!("{} {}", w.label, format_bytes(w.bytes)))
            .collect();
        let mut sub = format!(
            "{} · {} objects",
            display_type(&x.type_name).0,
            x.retained_objects
        );
        if !holds.is_empty() {
            let _ = write!(sub, " · holds {}", holds.join(", "));
        } else if let Some(l) = &x.type_location {
            let _ = write!(sub, " · {}", l.display());
        }
        let _ = writeln!(out, "      {}", st.paint(Paint::Dim, sub));
        if let Some(at) = &x.allocated_at {
            out.push_str(&allocated_at_lines(at, "      "));
        }
    }
    if !interp.is_empty() {
        let bytes: u64 = interp.iter().map(|x| x.retained_bytes).sum();
        let _ = writeln!(
            out,
            "{}",
            st.paint(
                Paint::Dim,
                format!(
                    "    + the interpreter itself: {} holders, {} (libpython's C globals, \
                     interpreter state, code objects)",
                    interp.len(),
                    format_bytes(bytes)
                )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holder_names_read_like_code() {
        assert_eq!(
            holder_name("sys.modules['app.cache'].__dict__['CACHE']"),
            "app.cache.CACHE"
        );
        assert_eq!(
            holder_name("sys.modules['app.events'].__dict__['REGISTRY'].listeners"),
            "app.events.REGISTRY.listeners"
        );
        assert_eq!(
            holder_name("sys.modules['m'].__dict__['D']['user:1']"),
            "m.D['user:1']"
        );
        assert_eq!(holder_name("python3.13 globals"), "python3.13 globals");
        assert_eq!(
            holder_name("python3.13: _PyRuntime <+32> <contents> <+8>"),
            "python3.13: _PyRuntime → C memory"
        );
        assert_eq!(holder_name("m.X <+3x>"), "m.X <+3x>");
        assert_eq!(holder_name("x.__dict__['a b']"), "x.__dict__['a b']");
    }

    fn row(t: &str, bytes: u64) -> WhatRow {
        WhatRow {
            key: t.into(),
            type_name: t.into(),
            label: t.into(),
            paint: Paint::Strong,
            count: 1,
            bytes,
            retained: bytes,
            held_by: None,
            held_by_rank: None,
            held_pct: 0.0,
            leaked: false,
            location: None,
        }
    }

    #[test]
    fn internals_fold_into_one_row_unless_kept() {
        let rows = vec![
            row("builtins.bytes", 100),
            row("builtins.code", 30),
            row("builtins.type", 20),
            row("app.Session", 10),
        ];
        let f = fold_internals(rows.clone(), |_| false);
        assert_eq!(f.len(), 3);
        assert_eq!(f[1].key, INTERNALS);
        assert_eq!(f[1].bytes, 50);
        let k = fold_internals(rows, |r| r.type_name == "builtins.type");
        assert!(k.iter().any(|r| r.key == "builtins.type"));
        assert_eq!(k.iter().find(|r| r.key == INTERNALS).unwrap().bytes, 30);
    }
}
