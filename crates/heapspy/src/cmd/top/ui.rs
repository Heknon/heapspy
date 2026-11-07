//! Drawing `heapspy top`.

use heapspy_analyzer::render::format_bytes;
use heapspy_analyzer::render::style::shorten;
use heapspy_analyzer::report::Retainer;
use heapspy_analyzer::root_path_string;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use super::state::{sparkline, AllocState, App, Sort, Tab};
use crate::live::thread_label;

pub const LEAKED_SITE: &str = "(leaked) native blocks nothing points to";

fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}
fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}
fn bar_style() -> Style {
    Style::default().bg(Color::Rgb(48, 54, 61)).fg(Color::White)
}

pub fn group_color(key: &str) -> Color {
    match key {
        "python" => Color::Cyan,
        "native" => Color::Magenta,
        "leaked" => Color::LightRed,
        "free" => Color::Yellow,
        "pymalloc_free" => Color::Green,
        "mapped" => Color::DarkGray,
        _ => Color::Gray,
    }
}

/// `+3.9 MiB` per minute, colored by sign; dim `0` when flat.
fn rate_span(r: Option<f64>, scale: u64) -> Span<'static> {
    match r {
        None => Span::styled("—", dim()),
        Some(x) if x.abs() < scale as f64 * 0.005 => Span::styled("0", dim()),
        Some(x) if x > 0.0 => Span::styled(
            format!("+{}", format_bytes(x as u64)),
            Style::default().fg(Color::LightRed),
        ),
        Some(x) => Span::styled(
            format!("-{}", format_bytes((-x) as u64)),
            Style::default().fg(Color::Green),
        ),
    }
}

fn count_rate_span(r: Option<f64>) -> Span<'static> {
    match r {
        None => Span::styled("—", dim()),
        Some(x) if x.abs() < 0.5 => Span::styled("0", dim()),
        Some(x) if x > 0.0 => {
            Span::styled(format!("+{:.0}", x), Style::default().fg(Color::LightRed))
        }
        Some(x) => Span::styled(format!("{:.0}", x), Style::default().fg(Color::Green)),
    }
}

fn spark_span(v: &[u64], growing: bool) -> Span<'static> {
    let s = sparkline(v);
    if growing {
        Span::styled(s, Style::default().fg(Color::LightRed))
    } else {
        Span::styled(s, dim())
    }
}

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let groups = app.groups();
    let mem_h = (groups.len().max(1) + 2) as u16;
    let [header, mem, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(mem_h),
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(area);
    draw_header(f, app, header);
    draw_memory(f, app, mem);
    draw_tabs(f, app, tabs);
    match app.tab {
        Tab::Holders => draw_holders(f, app, body),
        Tab::Types => draw_types(f, app, body),
        Tab::Native => draw_native(f, app, body),
        Tab::Threads => draw_threads(f, app, body),
        Tab::Allocated => draw_allocated(f, app, body),
    }
    draw_footer(f, app, footer);
    if app.detail.is_some() {
        draw_detail(f, app, area);
    }
    if app.show_help {
        draw_help(f, area);
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let python = app
        .latest
        .as_ref()
        .map(|s| format!(" · python {}", s.report.snapshot.python_version))
        .unwrap_or_default();
    let left = format!(
        " heapspy top   pid {}{} · {}",
        app.pid,
        python,
        shorten(&app.command, 60)
    );
    let state = if app.gone {
        "✕ exited"
    } else if app.paused {
        "⏸ paused"
    } else {
        "● live"
    };
    let elapsed = app.started.elapsed().as_secs();
    let right = format!("{:02}:{:02}  {state} ", elapsed / 60, elapsed % 60);
    let pad = (area.width as usize).saturating_sub(left.chars().count() + right.chars().count());
    let style = Style::default()
        .bg(Color::Blue)
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    f.render_widget(
        Paragraph::new(Line::from(format!("{left}{}{right}", " ".repeat(pad)))).style(style),
        area,
    );
}

fn draw_memory(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    // Title line: RSS live, snapshot status on the right.
    let rss = app
        .mem
        .map(|m| format_bytes(m.rss))
        .unwrap_or_else(|| "?".into());
    let mut left = vec![
        Span::styled(" MEMORY  ", bold()),
        Span::raw("RSS "),
        Span::styled(rss, bold()),
        Span::raw("  "),
        rate_span(app.rss_rate(), app.mem.map_or(0, |m| m.rss)),
        Span::styled("/min  ", dim()),
        Span::styled(
            sparkline(&app.rss_series(24)),
            Style::default().fg(Color::Blue),
        ),
    ];
    let snap_text = if app.snapshot_running {
        "snapshot in progress…".to_string()
    } else if let Some(e) = &app.snapshot_error {
        format!("snapshot failed: {}", shorten(e, 50))
    } else if let Some(s) = &app.latest {
        let how = match s.pause {
            Some(p) => format!("stopped {} ms", p.as_millis()),
            None if s.approximate || app.no_stop => "not stopped, approximate".to_string(),
            None => format!("took {:.1} s", s.took.as_secs_f64()),
        };
        let age = app.last_snapshot_age().unwrap_or_default().as_secs();
        let next = if app.paused {
            "paused".to_string()
        } else {
            let left = app.every.as_secs().saturating_sub(age);
            format!("next in {left}s")
        };
        format!("split from snapshot {age}s ago, {how} · {next}")
    } else {
        "taking the first snapshot…".to_string()
    };
    let used: usize = left.iter().map(|s| s.content.chars().count()).sum();
    let pad = (area.width as usize).saturating_sub(used + snap_text.chars().count() + 1);
    left.push(Span::raw(" ".repeat(pad)));
    left.push(Span::styled(snap_text, dim()));
    lines.push(Line::from(left).style(bar_style()));
    lines.push(Line::from(vec![Span::styled(
        format!(
            "{:<26}{:>10}{:>7}   {:<18}{:>12}",
            "", "NOW", "SHARE", "HISTORY", "Δ/min"
        ),
        dim(),
    )]));
    let groups = app.groups();
    let total: u64 = groups.iter().map(|g| g.bytes).sum();
    for g in &groups {
        let key = g.key;
        let r = app.rate(|p| p.groups.get(key).copied());
        let series = app.series(18, |p| p.groups.get(key).copied());
        let growing = r.is_some_and(|x| x > (total as f64) * 0.0005);
        let share = if total > 0 {
            g.bytes as f64 * 100.0 / total as f64
        } else {
            0.0
        };
        let mut spans = vec![
            Span::styled(" ■ ", Style::default().fg(group_color(key))),
            Span::raw(format!("{:<22}", g.label)),
            Span::styled(format!("{:>11}", format_bytes(g.bytes)), bold()),
            Span::raw(format!("{:>6.0}%   ", share)),
            spark_span(&series, growing),
            Span::raw(" ".repeat(19usize.saturating_sub(series.len()))),
            Span::raw(format!("{:>12}", "")),
        ];
        // Replace the rate placeholder with the colored rate, right-aligned.
        spans.pop();
        let rs = rate_span(r, total);
        let w = rs.content.chars().count();
        spans.push(Span::raw(" ".repeat(12usize.saturating_sub(w))));
        spans.push(rs);
        if key == "leaked" && growing {
            spans.push(Span::styled(
                "   ◀ growing, nothing points to it",
                Style::default().fg(Color::LightRed),
            ));
        } else if key == "free" && g.bytes > total / 10 {
            spans.push(Span::styled(
                "   fragmentation? see Native tab",
                Style::default().fg(Color::Yellow),
            ));
        }
        lines.push(Line::from(spans));
    }
    if groups.is_empty() {
        lines.push(Line::from(Span::styled(
            "   waiting for the first snapshot (the process may stop briefly while it is taken)",
            dim(),
        )));
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::raw(" ")];
    for (i, t) in Tab::ALL.iter().enumerate() {
        let label = format!(" {} {} ", i + 1, t.title());
        if *t == app.tab {
            spans.push(Span::styled(
                label,
                Style::default()
                    .bg(Color::White)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(label, dim()));
        }
        spans.push(Span::raw(" "));
    }
    let sort = app.sort[app.tab.index()];
    spans.push(Span::styled(format!("   sort: {} ▼", sort.label()), dim()));
    if let AllocState::Running { until, .. } = &app.alloc {
        let left = until
            .saturating_duration_since(std::time::Instant::now())
            .as_secs();
        spans.push(Span::styled(
            format!("   ● sampling allocations, {left}s left"),
            Style::default().fg(Color::LightRed),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// A table with a header, the selected row highlighted.
fn table(
    f: &mut Frame,
    area: Rect,
    header: Vec<&str>,
    widths: Vec<Constraint>,
    rows: Vec<Row>,
    selected: usize,
) {
    let n = rows.len();
    let t = Table::new(rows, widths)
        .header(Row::new(header).style(dim()))
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(31, 59, 99))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶");
    let mut st = TableState::default();
    if n > 0 {
        st.select(Some(selected.min(n - 1)));
    }
    f.render_stateful_widget(t, area, &mut st);
}

/// Holder rows, in display order: `(site, retainer)`; the leaked pseudo-row
/// has no retainer.
pub fn holder_rows(app: &App) -> Vec<(String, Option<&Retainer>)> {
    let Some(s) = &app.latest else {
        return Vec::new();
    };
    let mut v: Vec<(String, Option<&Retainer>, u64)> = s
        .report
        .top_retainers
        .iter()
        .map(|r| (root_path_string(&r.path), Some(r), r.retained_bytes))
        .collect();
    let leaked = s.report.totals.native_lost_bytes;
    if leaked > 0 {
        v.push((LEAKED_SITE.to_string(), None, leaked));
    }
    match app.sort[Tab::Holders.index()] {
        Sort::Growth => {
            let rate = |site: &str| holder_rate(app, site).unwrap_or(f64::MIN);
            v.sort_by(|a, b| rate(&b.0).total_cmp(&rate(&a.0)).then(b.2.cmp(&a.2)));
        }
        _ => v.sort_by_key(|b| std::cmp::Reverse(b.2)),
    }
    v.into_iter().map(|(s, r, _)| (s, r)).collect()
}

fn holder_value(site: &str) -> impl Fn(&super::state::SnapPoint) -> Option<u64> + '_ {
    move |p| {
        if site == LEAKED_SITE {
            Some(p.leaked)
        } else {
            p.holders.get(site).copied()
        }
    }
}

pub fn holder_rate(app: &App, site: &str) -> Option<f64> {
    app.rate(holder_value(site))
}

fn draw_holders(f: &mut Frame, app: &App, area: Rect) {
    let rows_data = holder_rows(app);
    let hot = app.hot_frames(1);
    let [tarea, foot] = Layout::vertical([Constraint::Min(3), Constraint::Length(2)]).areas(area);
    let site_w = (tarea.width as usize)
        .saturating_sub(10 + 10 + 10 + 11 + 14 + 6)
        .max(20);
    let rows: Vec<Row> = rows_data
        .iter()
        .map(|(site, r)| {
            let (ret, nat) = match r {
                Some(r) => (
                    r.retained_bytes,
                    r.native_retained_bytes.unwrap_or(0).min(r.retained_bytes),
                ),
                None => {
                    let l = app
                        .latest
                        .as_ref()
                        .map_or(0, |s| s.report.totals.native_lost_bytes);
                    (l, l)
                }
            };
            let py = ret - nat;
            let rate = holder_rate(app, site);
            let growing = rate.is_some_and(|x| x > 1024.0);
            let series = app.series(12, holder_value(site));
            let name = if r.is_none() {
                Span::styled(shorten(site, site_w), Style::default().fg(Color::LightRed))
            } else {
                Span::raw(shorten(site, site_w))
            };
            let cell_bytes = |b: u64, c: Color| {
                if b == 0 {
                    Span::styled("0", dim())
                } else {
                    Span::styled(format_bytes(b), Style::default().fg(c))
                }
            };
            Row::new(vec![
                Line::from(name),
                Line::from(format_bytes(ret)).right_aligned(),
                Line::from(cell_bytes(py, Color::Cyan)).right_aligned(),
                Line::from(cell_bytes(nat, Color::Magenta)).right_aligned(),
                Line::from(rate_span(rate, ret.max(1))).right_aligned(),
                Line::from(spark_span(&series, growing)),
            ])
        })
        .collect();
    table(
        f,
        tarea,
        vec!["HOLDER", "RETAINED", "PYTHON", "NATIVE", "Δ/min", "  TREND"],
        vec![
            Constraint::Min(20),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(11),
            Constraint::Length(14),
        ],
        rows,
        app.selected[Tab::Holders.index()],
    );
    // What the threads were doing: a lead for whatever is growing.
    let (frames, of) = hot;
    let line = match frames.first() {
        Some((frame, n)) if of > 0 => Line::from(vec![
            Span::styled(" most frequent line on thread stacks (10 min): ", dim()),
            Span::raw(frame.clone()),
            Span::styled(format!("  ({n} of {of} samples)"), dim()),
        ]),
        _ => Line::from(Span::styled(" no Python frames sampled yet", dim())),
    };
    f.render_widget(Paragraph::new(vec![Line::raw(""), line]), foot);
}

/// Type rows in display order: `(name, count, shallow, retained)`.
pub fn type_rows(app: &App) -> Vec<(String, u64, u64, u64)> {
    let Some(s) = &app.latest else {
        return Vec::new();
    };
    let mut v: Vec<(String, u64, u64, u64)> = s
        .report
        .type_histogram
        .iter()
        .map(|t| {
            (
                t.type_name.clone(),
                t.count,
                t.shallow_bytes,
                t.retained_bytes,
            )
        })
        .collect();
    match app.sort[Tab::Types.index()] {
        Sort::Growth => {
            let rate = |n: &str| {
                app.rate(|p| p.types.get(n).map(|x| x.1))
                    .unwrap_or(f64::MIN)
            };
            v.sort_by(|a, b| rate(&b.0).total_cmp(&rate(&a.0)).then(b.2.cmp(&a.2)));
        }
        Sort::Count => v.sort_by_key(|b| std::cmp::Reverse(b.1)),
        Sort::Size => v.sort_by_key(|b| std::cmp::Reverse(b.2)),
    }
    v
}

fn draw_types(f: &mut Frame, app: &App, area: Rect) {
    let rows: Vec<Row> = type_rows(app)
        .into_iter()
        .map(|(name, count, shallow, retained)| {
            let n = name.clone();
            let rc = app.rate(|p| p.types.get(&n).map(|x| x.0));
            let rb = app.rate(|p| p.types.get(&n).map(|x| x.1));
            let series = app.series(12, |p| p.types.get(&n).map(|x| x.1));
            let growing = rb.is_some_and(|x| x > 1024.0);
            let style = if name.starts_with("native.") {
                Style::default().fg(Color::Magenta)
            } else if name.starts_with("builtins.") {
                Style::default()
            } else {
                Style::default().fg(Color::LightMagenta)
            };
            Row::new(vec![
                Line::from(Span::styled(name, style)),
                Line::from(count.to_string()).right_aligned(),
                Line::from(count_rate_span(rc)).right_aligned(),
                Line::from(format_bytes(shallow)).right_aligned(),
                Line::from(rate_span(rb, shallow.max(1))).right_aligned(),
                Line::from(format_bytes(retained)).right_aligned(),
                Line::from(spark_span(&series, growing)),
            ])
        })
        .collect();
    table(
        f,
        area,
        vec![
            "TYPE", "COUNT", "Δ/min", "SHALLOW", "Δ/min", "RETAINED", "  TREND",
        ],
        vec![
            Constraint::Min(24),
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(14),
        ],
        rows,
        app.selected[Tab::Types.index()],
    );
}

/// Holders that retain native memory, most native first.
pub fn native_rows(app: &App) -> Vec<(String, Option<&Retainer>)> {
    let mut v: Vec<(String, Option<&Retainer>)> = holder_rows(app)
        .into_iter()
        .filter(|(_, r)| r.is_none_or(|r| r.native_retained_bytes.unwrap_or(0) > 0))
        .collect();
    let nat = |r: &Option<&Retainer>| match r {
        Some(r) => r.native_retained_bytes.unwrap_or(0),
        None => app
            .latest
            .as_ref()
            .map_or(0, |s| s.report.totals.native_lost_bytes),
    };
    v.sort_by_key(|b| std::cmp::Reverse(nat(&b.1)));
    v
}

fn draw_native(f: &mut Frame, app: &App, area: Rect) {
    let Some(s) = &app.latest else {
        f.render_widget(
            Paragraph::new(Span::styled(" waiting for the first snapshot", dim())),
            area,
        );
        return;
    };
    let r = &s.report;
    let t = &r.totals;
    let mut info: Vec<Line> = Vec::new();
    if t.native_blocks == 0 {
        info.push(Line::from(Span::styled(
            " The native heap was not walked (no glibc heap found, or another allocator such as jemalloc).",
            dim(),
        )));
    } else {
        info.push(Line::from(vec![
            Span::raw(format!(
                " {} heap blocks, {} · ",
                t.native_blocks,
                format_bytes(t.native_bytes)
            )),
            Span::styled(
                format!(
                    "leaked: {} blocks, {}",
                    t.native_lost_blocks,
                    format_bytes(t.native_lost_bytes)
                ),
                Style::default().fg(Color::LightRed),
            ),
        ]));
        if let Some(a) = &r.memory.native_allocator {
            let free = a.free_bytes + a.top_bytes;
            let hint = if free > (64 << 20) || free * 10 > t.native_bytes {
                "   MALLOC_ARENA_MAX=2 or a periodic malloc_trim(0) often returns this to the OS"
            } else {
                ""
            };
            info.push(Line::from(vec![
                Span::raw(format!(
                    " malloc: {} arena{}, {} free chunks ({}), top chunks {}",
                    a.arenas,
                    if a.arenas == 1 { "" } else { "s" },
                    a.free_chunks,
                    format_bytes(a.free_bytes),
                    format_bytes(a.top_bytes)
                )),
                Span::styled(hint, Style::default().fg(Color::Yellow)),
            ]));
        }
        let sizes: Vec<String> = r
            .memory
            .native_lost_by_size
            .iter()
            .take(4)
            .map(|g| format!("{} × {} B", g.blocks, g.size))
            .collect();
        if !sizes.is_empty() {
            info.push(Line::from(vec![
                Span::styled(" leaked by block size: ", dim()),
                Span::raw(sizes.join(", ")),
            ]));
        }
    }
    let ih = info.len() as u16 + 1;
    let [top, rest] = Layout::vertical([Constraint::Length(ih), Constraint::Min(3)]).areas(area);
    f.render_widget(Paragraph::new(info), top);
    let rows: Vec<Row> = native_rows(app)
        .into_iter()
        .map(|(site, r)| {
            let nat = match r {
                Some(r) => r.native_retained_bytes.unwrap_or(0),
                None => t.native_lost_bytes,
            };
            let rate = holder_rate(app, &site);
            let series = app.series(12, holder_value(&site));
            Row::new(vec![
                Line::from(shorten(&site, 70)),
                Line::from(Span::styled(
                    format_bytes(nat),
                    Style::default().fg(Color::Magenta),
                ))
                .right_aligned(),
                Line::from(rate_span(rate, nat.max(1))).right_aligned(),
                Line::from(spark_span(&series, rate.is_some_and(|x| x > 1024.0))),
            ])
        })
        .collect();
    table(
        f,
        rest,
        vec!["HOLDING NATIVE MEMORY", "NATIVE", "Δ/min", "  TREND"],
        vec![
            Constraint::Min(30),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(14),
        ],
        rows,
        app.selected[Tab::Native.index()],
    );
}

fn draw_threads(f: &mut Frame, app: &App, area: Rect) {
    let (hot, of) = app.hot_frames(6);
    let hot_h = if hot.is_empty() {
        0
    } else {
        hot.len() as u16 + 2
    };
    let [tarea, harea] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(hot_h)]).areas(area);
    let rows: Vec<Row> = app
        .threads
        .iter()
        .map(|t| {
            let state = t.state.unwrap_or("");
            let sstyle = if state == "running" {
                Style::default().fg(Color::Green)
            } else {
                dim()
            };
            let (where_, callers) = match t.frames.first() {
                None => (Span::styled("(no Python code)", dim()), String::new()),
                Some(fr) => (
                    Span::raw(format!("{} in {}", fr.location(), fr.function)),
                    t.frames
                        .iter()
                        .skip(1)
                        .take(3)
                        .map(|c| format!("{} {}", c.function, c.location()))
                        .collect::<Vec<_>>()
                        .join(" ← "),
                ),
            };
            Row::new(vec![
                Line::from(thread_label(t)),
                Line::from(Span::styled(state.to_string(), sstyle)),
                Line::from(where_),
                Line::from(Span::styled(
                    if callers.is_empty() {
                        String::new()
                    } else {
                        format!("← {callers}")
                    },
                    dim(),
                )),
            ])
        })
        .collect();
    table(
        f,
        tarea,
        vec!["THREAD", "STATE", "RUNNING", "CALLED FROM"],
        vec![
            Constraint::Length(14),
            Constraint::Length(9),
            Constraint::Percentage(40),
            Constraint::Min(10),
        ],
        rows,
        app.selected[Tab::Threads.index()],
    );
    if !hot.is_empty() {
        let mut lines = vec![Line::from(Span::styled(
            format!(" Most frequent innermost frames over the last 10 min ({of} samples, 1 per thread per second)"),
            dim(),
        ))];
        for (fr, n) in hot {
            let pct = n as f64 * 100.0 / of.max(1) as f64;
            lines.push(Line::from(vec![
                Span::raw(format!(" {:>5.1}%  ", pct)),
                Span::raw(fr),
            ]));
        }
        f.render_widget(Paragraph::new(lines), harea);
    }
}

fn draw_allocated(f: &mut Frame, app: &App, area: Rect) {
    let msg = |f: &mut Frame, lines: Vec<Line>| {
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area)
    };
    let joined = app
        .latest
        .as_ref()
        .and_then(|s| s.report.allocations.as_ref());
    match (&app.alloc, joined) {
        (AllocState::Off, _) => msg(
            f,
            vec![
                Line::raw(""),
                Line::from(vec![
                    Span::raw(" Press "),
                    Span::styled("a", bold()),
                    Span::raw(format!(
                        " to sample allocations for {}s, as `heapspy record` does.",
                        app.alloc_for.as_secs()
                    )),
                ]),
                Line::from(Span::styled(
                    " Then every snapshot is joined with the samples: this tab lists the Python stacks that allocated",
                    dim(),
                )),
                Line::from(Span::styled(
                    " the most, and how much of what they allocated is still alive. Linux: eBPF only (root or",
                    dim(),
                )),
                Line::from(Span::styled(
                    " CAP_BPF+CAP_PERFMON); Windows: ETW. Large-object probes cost ~0.5 µs per malloc above 512 bytes.",
                    dim(),
                )),
            ],
        ),
        (AllocState::Failed(e), _) => msg(
            f,
            vec![
                Line::raw(""),
                Line::from(Span::styled(format!(" Allocation sampling failed: {e}"), Style::default().fg(Color::LightRed))),
            ],
        ),
        (AllocState::Running { since, until }, _) => {
            let left = until.saturating_duration_since(std::time::Instant::now()).as_secs();
            msg(
                f,
                vec![
                    Line::raw(""),
                    Line::from(format!(
                        " Sampling allocations: {}s so far, {left}s left. Press a to stop early.",
                        since.elapsed().as_secs()
                    )),
                    Line::from(Span::styled(
                        " Results appear here after the next snapshot taken once sampling stops.",
                        dim(),
                    )),
                ],
            )
        }
        (AllocState::Done { .. }, None) => msg(
            f,
            vec![Line::raw(""), Line::from(Span::styled(" Joining the samples with the next snapshot…", dim()))],
        ),
        (AllocState::Done { samples, mechanisms, pause_ms, .. }, Some(a)) => {
            let [head, tarea] = Layout::vertical([Constraint::Length(2), Constraint::Min(3)]).areas(area);
            f.render_widget(
                Paragraph::new(vec![Line::from(vec![
                    Span::raw(format!(
                        " {} samples over {:.0}s via {mechanisms} · target stopped {pause_ms:.1} ms in all · ",
                        samples,
                        a.duration_ms as f64 / 1000.0
                    )),
                    Span::styled(
                        "ALLOCATED: estimated bytes allocated while sampling · ALIVE: bytes of the sampled allocations still in the latest snapshot",
                        dim(),
                    ),
                ])]),
                head,
            );
            let rows: Vec<Row> = a
                .top_stacks
                .iter()
                .map(|s| {
                    let top = s.frames.first();
                    let where_ = top.map_or("?".to_string(), |f| {
                        let file = f.file.as_deref().map(crate::live::short_file).unwrap_or_else(|| "?".into());
                        match f.line {
                            Some(l) => format!("{} ({file}:{l})", f.function),
                            None => format!("{} ({file})", f.function),
                        }
                    });
                    let callers = s
                        .frames
                        .iter()
                        .skip(1)
                        .take(3)
                        .map(|f| f.function.clone())
                        .collect::<Vec<_>>()
                        .join(" ← ");
                    let alive_style = if s.linked_bytes > 0 { Style::default().fg(Color::LightRed) } else { dim() };
                    Row::new(vec![
                        Line::from(format_bytes(s.estimated_bytes)).right_aligned(),
                        Line::from(Span::styled(format_bytes(s.linked_bytes), alive_style)).right_aligned(),
                        Line::from(s.samples.to_string()).right_aligned(),
                        Line::from(where_),
                        Line::from(Span::styled(if callers.is_empty() { String::new() } else { format!("← {callers}") }, dim())),
                    ])
                })
                .collect();
            table(
                f,
                tarea,
                vec!["ALLOCATED", "ALIVE", "SAMPLES", "ALLOCATED IN", "CALLED FROM"],
                vec![
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Length(8),
                    Constraint::Percentage(45),
                    Constraint::Min(10),
                ],
                rows,
                app.selected[Tab::Allocated.index()],
            );
        }
    }
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    if let Some((at, s)) = &app.status {
        if at.elapsed().as_secs() < 6 {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!(" {s}"),
                    Style::default().fg(Color::Yellow),
                ))),
                area,
            );
            return;
        }
    }
    let key = |k: &str| {
        Span::styled(
            format!(" {k} "),
            Style::default()
                .bg(Color::White)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
    };
    let mut spans = vec![Span::raw(" ")];
    for (k, what) in [
        ("enter", "details"),
        ("1-5", "tabs"),
        ("s", "sort"),
        ("d", "snapshot now"),
        ("a", "allocations"),
        ("w", "save snapshot"),
        ("space", "pause"),
        ("?", "help"),
        ("q", "quit"),
    ] {
        spans.push(key(k));
        spans.push(Span::raw(format!(" {what}  ")));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn popup(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width.saturating_sub(4));
    let h = h.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(d) = &app.detail else { return };
    let n = match &d.lines {
        Some(Ok(v)) => v.len(),
        _ => 1,
    } as u16;
    let r = popup(area, area.width.saturating_sub(8), (n + 2).max(6));
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(format!(" {} ", d.title), bold()))
        .title_bottom(Span::styled(" esc close · ↑↓ scroll ", dim()));
    let lines: Vec<Line> = match &d.lines {
        None => vec![Line::from(Span::styled("loading…", dim()))],
        Some(Err(e)) => vec![Line::from(Span::styled(
            e.clone(),
            Style::default().fg(Color::LightRed),
        ))],
        Some(Ok(v)) => v.iter().map(|l| styled_detail_line(l)).collect(),
    };
    f.render_widget(Paragraph::new(lines).block(block).scroll((d.scroll, 0)), r);
}

/// Detail lines are plain text; a leading `#` marks a heading.
fn styled_detail_line(l: &str) -> Line<'static> {
    if let Some(h) = l.strip_prefix("# ") {
        Line::from(Span::styled(
            h.to_string(),
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::BOLD),
        ))
    } else if let Some(h) = l.strip_prefix("~ ") {
        Line::from(Span::styled(h.to_string(), dim()))
    } else {
        Line::from(l.to_string())
    }
}

fn draw_help(f: &mut Frame, area: Rect) {
    let r = popup(area, 78, 24);
    f.render_widget(Clear, r);
    let lines = vec![
        Line::from(Span::styled("Memory panel", bold())),
        Line::raw("  RSS refreshes every second. The split refreshes with each snapshot:"),
        Line::raw("  Python objects, native memory in use, leaked native blocks (nothing"),
        Line::raw("  points to them), free memory malloc keeps, other private memory,"),
        Line::raw("  pymalloc's free space, and code/files/stacks."),
        Line::raw(""),
        Line::from(Span::styled("Tabs", bold())),
        Line::raw("  1 Holders    objects (and the leaked pseudo-row) by retained bytes"),
        Line::raw("  2 Types      instances per type; Δ/min over the last 10 minutes"),
        Line::raw("  3 Native     who holds native memory, malloc arenas and free space"),
        Line::raw("  4 Threads    what each thread runs now, and its most frequent lines"),
        Line::raw("  5 Allocated  with allocation sampling: who allocated what is alive"),
        Line::raw(""),
        Line::from(Span::styled("Keys", bold())),
        Line::raw("  ↑↓ jk PgUp PgDn  move     enter  details     esc  close"),
        Line::raw("  s  sort      d  snapshot now     w  save the latest snapshot"),
        Line::raw("  a  start/stop allocation sampling   space  pause   q  quit"),
        Line::raw(""),
        Line::from(Span::styled(
            "  Snapshots stop the process (shown in the header) unless --no-stop.",
            dim(),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" help ")),
        r,
    );
}
