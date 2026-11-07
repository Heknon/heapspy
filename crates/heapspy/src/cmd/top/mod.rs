//! `heapspy top`: a live, full-screen view of a process's memory.
//!
//! Three kinds of data, refreshed at different speeds (see the command's
//! help): the OS's memory numbers and thread stacks every second, without
//! stopping the target ([`workers::vitals`]); a full snapshot every
//! `--every` ([`workers::snapshots`]); and, on request, allocation sampling
//! ([`workers::allocations`]). Workers send [`workers::Msg`]s; this thread
//! owns the [`state::App`] and draws it.

mod state;
mod ui;
mod workers;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use heapspy_analyzer::render::{format_bytes, Style};
use heapspy_analyzer::QueryOptions;

use crate::cli::TopArgs;
use crate::live::{self, StackReader};
use state::{AllocState, App, Detail, Sort, Tab};
use workers::{Msg, SnapConfig, SnapRequest};

pub fn run(args: TopArgs, _st: Style) -> anyhow::Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "top needs a terminal; for plain output use `heapspy watch --pid {}`",
            args.pid
        );
    }
    // Fail before taking over the screen when the process cannot be read.
    let reader = StackReader::open(args.pid).with_context(|| {
        format!("cannot read pid {} (is it a CPython 3.12-3.14 process, and do you have ptrace rights?)", args.pid)
    })?;

    let quit = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Msg>();
    let (snap_tx, snap_rx) = mpsc::channel::<SnapRequest>();
    let profile: Arc<Mutex<Option<std::path::PathBuf>>> = Arc::new(Mutex::new(None));

    let mut handles = Vec::new();
    {
        let (tx, quit) = (tx.clone(), quit.clone());
        let pid = args.pid;
        handles.push(std::thread::spawn(move || {
            workers::vitals(pid, reader, tx, quit)
        }));
    }
    {
        let cfg = SnapConfig {
            pid: args.pid,
            every: args.every,
            no_stop: args.no_stop,
            max_pause: args.max_pause,
            top: args.top,
            profile: profile.clone(),
        };
        let (tx, quit) = (tx.clone(), quit.clone());
        handles.push(std::thread::spawn(move || {
            workers::snapshots(cfg, snap_rx, tx, quit)
        }));
    }

    let mut app = App::new(args.pid, args.every, args.no_stop);
    app.max_pause = args.max_pause;
    app.alloc_for = args.alloc_for;
    let mut alloc_stop: Option<Arc<AtomicBool>> = None;
    if args.alloc {
        alloc_stop = Some(start_alloc(&args, &tx));
    }

    let mut terminal = ratatui::init();
    let result = (|| -> anyhow::Result<()> {
        loop {
            while let Ok(m) = rx.try_recv() {
                on_msg(&mut app, m, &profile, &snap_tx);
            }
            terminal.draw(|f| ui::draw(f, &app))?;
            if !event::poll(Duration::from_millis(250))? {
                continue;
            }
            let Event::Key(k) = event::read()? else {
                continue;
            };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
                return Ok(());
            }
            if app.show_help {
                app.show_help = false;
                continue;
            }
            if let Some(d) = &mut app.detail {
                match k.code {
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.detail = None,
                    KeyCode::Down | KeyCode::Char('j') => d.scroll = d.scroll.saturating_add(1),
                    KeyCode::Up | KeyCode::Char('k') => d.scroll = d.scroll.saturating_sub(1),
                    KeyCode::PageDown => d.scroll = d.scroll.saturating_add(10),
                    KeyCode::PageUp => d.scroll = d.scroll.saturating_sub(10),
                    _ => {}
                }
                continue;
            }
            let ti = app.tab.index();
            match k.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('?') | KeyCode::Char('h') => app.show_help = true,
                KeyCode::Char(c @ '1'..='5') => app.tab = Tab::ALL[(c as u8 - b'1') as usize],
                KeyCode::Tab => app.tab = Tab::ALL[(ti + 1) % Tab::ALL.len()],
                KeyCode::BackTab => app.tab = Tab::ALL[(ti + Tab::ALL.len() - 1) % Tab::ALL.len()],
                KeyCode::Down | KeyCode::Char('j') => {
                    app.selected[ti] = (app.selected[ti] + 1).min(rows(&app).saturating_sub(1))
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.selected[ti] = app.selected[ti].saturating_sub(1)
                }
                KeyCode::PageDown => {
                    app.selected[ti] = (app.selected[ti] + 10).min(rows(&app).saturating_sub(1))
                }
                KeyCode::PageUp => app.selected[ti] = app.selected[ti].saturating_sub(10),
                KeyCode::Home | KeyCode::Char('g') => app.selected[ti] = 0,
                KeyCode::Char('s') => {
                    app.sort[ti] = match (app.tab, app.sort[ti]) {
                        (Tab::Objects, Sort::Size) => Sort::Growth,
                        (Tab::Objects, Sort::Growth) => Sort::Count,
                        (Tab::Objects, _) => Sort::Size,
                        (Tab::Holders, Sort::Size) => Sort::Growth,
                        (Tab::Holders, _) => Sort::Size,
                        (_, s) => s,
                    };
                    app.selected[ti] = 0;
                }
                KeyCode::Char('d') => {
                    let _ = snap_tx.send(SnapRequest::Now);
                    app.set_status("taking a snapshot…");
                }
                KeyCode::Char(' ') => {
                    app.paused = !app.paused;
                    let _ = snap_tx.send(SnapRequest::Paused(app.paused));
                }
                KeyCode::Char('w') => save_snapshot(&mut app),
                KeyCode::Char('i') => {
                    app.show_internals = !app.show_internals;
                    app.set_status(if app.show_internals {
                        "showing interpreter internals type by type"
                    } else {
                        "interpreter internals folded into one row"
                    });
                }
                KeyCode::Char('a') => match &app.alloc {
                    AllocState::Running { .. } => {
                        if let Some(s) = &alloc_stop {
                            s.store(true, Ordering::Relaxed);
                        }
                        app.set_status("stopping allocation sampling…");
                    }
                    _ => {
                        alloc_stop = Some(start_alloc(&args, &tx));
                        app.set_status("starting allocation sampling…");
                    }
                },
                KeyCode::Enter => open_detail(&mut app, &tx),
                _ => {}
            }
        }
    })();
    ratatui::restore();
    quit.store(true, Ordering::Relaxed);
    if let Some(s) = &alloc_stop {
        s.store(true, Ordering::Relaxed);
    }
    drop(snap_tx);
    // The snapshot worker may be in the middle of a walk; it resumes the
    // target before it returns, so wait for it.
    for h in handles {
        let _ = h.join();
    }
    if let AllocState::Done { path, .. } = &app.alloc {
        let _ = std::fs::remove_file(path);
    }
    result
}

fn start_alloc(args: &TopArgs, tx: &Sender<Msg>) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let (pid, dur, events, tx, s) = (
        args.pid,
        args.alloc_for,
        args.alloc_events,
        tx.clone(),
        stop.clone(),
    );
    std::thread::spawn(move || workers::allocations(pid, dur, events, s, tx));
    stop
}

fn on_msg(
    app: &mut App,
    m: Msg,
    profile: &Arc<Mutex<Option<std::path::PathBuf>>>,
    snap_tx: &Sender<SnapRequest>,
) {
    match m {
        Msg::Vitals { at, mem, threads } => app.on_vitals(at, mem, threads),
        Msg::ProcessGone => {
            app.gone = true;
            app.set_status(format!("process {} exited; q quits", app.pid));
        }
        Msg::SnapshotStarted => app.snapshot_running = true,
        Msg::Snapshot(s) => app.on_snapshot(*s),
        Msg::SnapshotFailed(e) => {
            app.snapshot_running = false;
            app.snapshot_error = Some(e);
        }
        Msg::AllocStarted { until } => {
            app.alloc = AllocState::Running {
                since: std::time::Instant::now(),
                until,
            };
        }
        Msg::AllocDone {
            path,
            samples,
            mechanisms,
            pause_ms,
        } => {
            if let AllocState::Done { path: old, .. } = &app.alloc {
                let _ = std::fs::remove_file(old);
            }
            *profile.lock().unwrap_or_else(|e| e.into_inner()) = Some(path.clone());
            app.alloc = AllocState::Done {
                path,
                samples,
                mechanisms,
                pause_ms,
            };
            app.set_status(format!(
                "allocation sampling done: {samples} samples; joining with a new snapshot"
            ));
            let _ = snap_tx.send(SnapRequest::Now);
        }
        Msg::AllocFailed(e) => app.alloc = AllocState::Failed(e),
        Msg::Detail { id, lines } => {
            if let Some(d) = &mut app.detail {
                if d.id == id {
                    d.lines = Some(lines);
                }
            }
        }
    }
}

/// Rows in the current tab, for moving the selection.
fn rows(app: &App) -> usize {
    match app.tab {
        Tab::Holders => ui::holder_rows(app).len(),
        Tab::Objects => ui::object_rows(app).len(),
        Tab::Native => ui::native_rows(app).len(),
        Tab::Threads => app.threads.len(),
        Tab::Allocated => app
            .latest
            .as_ref()
            .and_then(|s| s.report.allocations.as_ref())
            .map_or(0, |a| a.top_stacks.len()),
    }
}

fn save_snapshot(app: &mut App) {
    let Some(s) = &app.latest else {
        app.set_status("no snapshot yet");
        return;
    };
    let secs = s
        .wall
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let out = format!("heapspy-{}-{secs}.hpy", app.pid);
    match std::fs::copy(&**s.path, &out) {
        Ok(_) => app.set_status(format!("saved {out}: heapspy analyze {out}")),
        Err(e) => app.set_status(format!("cannot save {out}: {e}")),
    }
}

fn open_detail(app: &mut App, tx: &Sender<Msg>) {
    let id = app.next_detail_id;
    app.next_detail_id += 1;
    let i = app.selected[app.tab.index()];
    let (title, lines): (String, Option<Result<Vec<String>, String>>) = match app.tab {
        Tab::Holders | Tab::Native => {
            let rows = if app.tab == Tab::Holders {
                ui::holder_rows(app)
            } else {
                ui::native_rows(app)
            };
            let Some((site, r)) = rows.get(i) else { return };
            let title = if r.is_some() {
                heapspy_analyzer::render::summary::holder_name(site)
            } else {
                site.clone()
            };
            (title, Some(Ok(holder_detail(app, site, *r))))
        }
        Tab::Objects => {
            let rows = ui::object_rows(app);
            let Some(w) = rows.get(i) else { return };
            if w.leaked {
                (
                    w.label.clone(),
                    Some(Ok(holder_detail(app, ui::LEAKED_SITE, None))),
                )
            } else {
                let Some(s) = &app.latest else { return };
                // query --type on the latest snapshot, off the UI thread.
                let (path, name2, tx) = (s.path.clone(), w.type_name.clone(), tx.clone());
                std::thread::spawn(move || {
                    let lines = (|| -> anyhow::Result<Vec<String>> {
                        let snap = crate::cmd::open_snapshot(&path)?;
                        let r = heapspy_analyzer::query_type(
                            &snap,
                            "latest snapshot",
                            &name2,
                            &QueryOptions {
                                top: 15,
                                max_paths: 1,
                            },
                        )?;
                        Ok(heapspy_analyzer::render::type_query(&r)?
                            .lines()
                            .map(|l| match l {
                                "Largest instances" | "Held by" => format!("# {l}"),
                                l if l.starts_with("note:") => format!("~ {l}"),
                                l => readable_paths(l),
                            })
                            .collect())
                    })()
                    .map_err(|e| format!("{e:#}"));
                    let _ = tx.send(Msg::Detail { id, lines });
                });
                (w.label.clone(), None)
            }
        }
        Tab::Threads => {
            let Some(t) = app.threads.get(i) else { return };
            let mut v = vec![format!(
                "# Python stack of {} (innermost first)",
                live::thread_label(t)
            )];
            if t.frames.is_empty() {
                v.push("~ not running Python code".into());
            }
            for f in &t.frames {
                v.push(format!("  {}  {}", f.function, f.location()));
                v.push(format!("~     {}", f.file));
            }
            (live::thread_label(t), Some(Ok(v)))
        }
        Tab::Allocated => {
            let Some(a) = app
                .latest
                .as_ref()
                .and_then(|s| s.report.allocations.as_ref())
            else {
                return;
            };
            let Some(s) = a.top_stacks.get(i) else { return };
            let mut v = vec![
                format!(
                    "allocated ~{} in {} samples ({}); {} of it still alive",
                    format_bytes(s.estimated_bytes),
                    s.samples,
                    s.events.join(", "),
                    format_bytes(s.linked_bytes)
                ),
                String::new(),
                "# Stack (innermost first)".into(),
            ];
            for f in &s.frames {
                v.push(format!(
                    "  {}  {}{}",
                    f.function,
                    short_location(f),
                    if f.approximate { "  ~approximate" } else { "" }
                ));
            }
            (format!("allocation stack #{}", s.rank), Some(Ok(v)))
        }
    };
    app.detail = Some(Detail {
        id,
        title,
        lines,
        scroll: 0,
    });
}

fn holder_detail(
    app: &App,
    site: &str,
    r: Option<&heapspy_analyzer::report::Retainer>,
) -> Vec<String> {
    let mut v = Vec::new();
    let rate = ui::holder_rate(app, site);
    let rate_text = rate.map_or("— (needs two snapshots)".to_string(), |x| {
        format!(
            "{}{}/min over the last 10 minutes",
            if x >= 0.0 { "+" } else { "-" },
            format_bytes(x.abs() as u64)
        )
    });
    let Some(r) = r else {
        let Some(s) = &app.latest else { return v };
        let t = &s.report.totals;
        v.push(format!(
            "{} in {} native heap blocks that nothing points to: no Python object, other block,",
            format_bytes(t.native_lost_bytes),
            t.native_lost_blocks
        ));
        v.push("C global or thread stack holds their address. That memory is leaked.".into());
        v.push(format!("growth: {rate_text}"));
        v.push(String::new());
        v.push("# By block size".into());
        for g in &s.report.memory.native_lost_by_size {
            v.push(format!(
                "  {:>10} B  × {:>8}   {}",
                g.size,
                g.blocks,
                format_bytes(g.bytes)
            ));
        }
        v.push(String::new());
        v.push(
            "~ A snapshot cannot say who allocated them. While they grow, the Threads tab shows"
                .into(),
        );
        v.push(
            "~ what the threads run; `heapspy record --events native` records allocation stacks"
                .into(),
        );
        v.push("~ on Windows (Linux planned).".into());
        return v;
    };
    let nat = r.native_retained_bytes.unwrap_or(0).min(r.retained_bytes);
    v.push(format!(
        "retains {} in {} objects ({:.1}% of everything held) · python {} · native {}",
        format_bytes(r.retained_bytes),
        r.retained_objects,
        r.retained_pct,
        format_bytes(r.retained_bytes - nat),
        format_bytes(nat)
    ));
    let mut t = format!(
        "{} at {}, {} itself",
        r.type_name,
        r.address,
        format_bytes(r.shallow_bytes)
    );
    if let Some(l) = &r.type_location {
        t.push_str(&format!(" · type defined at {}", l.display()));
    }
    v.push(t);
    v.push(format!("growth: {rate_text}"));
    v.push(String::new());
    v.push("# Path from a root".into());
    let w = r
        .path
        .iter()
        .map(|h| {
            h.root_label
                .as_deref()
                .or(h.edge.as_deref())
                .unwrap_or("?")
                .chars()
                .count()
                + 2
        })
        .max()
        .unwrap_or(0);
    for h in &r.path {
        let left = match (&h.root_label, &h.edge) {
            (Some(l), _) => l.clone(),
            (None, Some(e)) => format!("  {e}"),
            _ => "  ?".into(),
        };
        let mut right = format!("{}  {}", h.type_name, format_bytes(h.shallow_bytes));
        if let Some(l) = &h.source_loc {
            right.push_str(&format!("  {}", l.display()));
        }
        v.push(format!("  {left:<w$}  {right}"));
    }
    if let Some(at) = &r.allocated_at {
        v.push(String::new());
        v.push(format!(
            "# Allocated by ({} of {} linked to samples)",
            format_bytes(at.linked_bytes),
            format_bytes(r.retained_bytes)
        ));
        for s in &at.stacks {
            v.push(format!(
                "  {} in {} objects",
                format_bytes(s.linked_bytes),
                s.linked_objects
            ));
            for f in s.frames.iter().take(6) {
                v.push(format!("      {}  {}", f.function, short_location(f)));
            }
        }
    }
    v.push(String::new());
    v.push(format!(
        "~ heapspy query <snapshot> --retaining-path {}   (w saves the snapshot)",
        r.address
    ));
    v
}

/// `app/cache.py:10` for a sampled frame.
fn short_location(f: &heapspy_analyzer::report::StackFrame) -> String {
    let file = f
        .file
        .as_deref()
        .map(live::short_file)
        .unwrap_or_else(|| "?".into());
    match f.line {
        Some(l) => format!("{file}:{l}"),
        None => file,
    }
}

/// `l` with each `sys.modules[...]` path in it written the way code names
/// it (see `holder_name`).
fn readable_paths(l: &str) -> String {
    let Some(i) = l.find("sys.modules[") else {
        return l.to_string();
    };
    let end = l[i..].find(' ').map_or(l.len(), |j| i + j);
    format!(
        "{}{}{}",
        &l[..i],
        heapspy_analyzer::render::summary::holder_name(&l[i..end]),
        &l[end..]
    )
}
