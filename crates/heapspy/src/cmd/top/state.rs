//! What `heapspy top` knows: the latest numbers and their history.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use heapspy_analyzer::render::summary::{
    is_internal, memory_groups, what_rows, MemoryGroup, INTERNALS,
};
use heapspy_analyzer::root_path_string;

use super::workers::Snap;
use crate::live::{ProcMemory, PyThread};
use crate::sample::Sample;

/// How far back growth rates and sparklines look.
pub const WINDOW: Duration = Duration::from_secs(10 * 60);
/// Most snapshots kept in the history.
const MAX_SNAPS: usize = 120;
/// Most per-second samples kept (30 minutes).
const MAX_SECONDS: usize = 1800;
/// Windows the Graphs tab cycles through (`s`).
pub const GRAPH_WINDOWS: [Duration; 4] = [
    Duration::from_secs(60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
    Duration::from_secs(30 * 60),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Objects,
    Holders,
    Native,
    Threads,
    Allocated,
    Graphs,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Objects,
        Tab::Holders,
        Tab::Native,
        Tab::Threads,
        Tab::Allocated,
        Tab::Graphs,
    ];
    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|&t| t == self).unwrap_or(0)
    }
    pub fn title(self) -> &'static str {
        match self {
            Tab::Objects => "Objects",
            Tab::Holders => "Holders",
            Tab::Native => "Native",
            Tab::Threads => "Threads",
            Tab::Allocated => "Allocated",
            Tab::Graphs => "Graphs",
        }
    }
}

/// Sort orders. `s` cycles through those of the current tab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Size,
    Growth,
    Count,
}

impl Sort {
    pub fn label(self) -> &'static str {
        match self {
            Sort::Size => "size",
            Sort::Growth => "growth/min",
            Sort::Count => "count",
        }
    }
}

/// Values of one snapshot, by key, for history and rates.
#[derive(Clone, Debug, Default)]
pub struct SnapPoint {
    pub at: Option<Instant>,
    pub groups: HashMap<&'static str, u64>,
    /// Holder site → retained bytes.
    pub holders: HashMap<String, u64>,
    /// Object row key (type, or `leaked:<type>`) → (count, bytes).
    pub types: HashMap<String, (u64, u64)>,
    pub leaked: u64,
}

/// A frame location seen on a thread stack, with when.
struct StackSample {
    at: Instant,
    /// `function (file:line)` of the innermost frame, and of its caller.
    top: String,
    running: bool,
}

pub enum AllocState {
    Off,
    Running {
        since: Instant,
        until: Instant,
    },
    /// Recorded; joined with every later snapshot.
    Done {
        path: PathBuf,
        samples: u64,
        mechanisms: String,
        pause_ms: f64,
    },
    Failed(String),
}

pub struct Detail {
    pub id: u64,
    pub title: String,
    pub lines: Option<Result<Vec<String>, String>>,
    pub scroll: u16,
}

pub struct App {
    pub pid: u32,
    pub command: String,
    pub every: Duration,
    pub no_stop: bool,
    pub started: Instant,
    pub tab: Tab,
    pub selected: [usize; 6],
    pub sort: [Sort; 6],
    pub paused: bool,
    /// Show interpreter internals type by type instead of as one row.
    pub show_internals: bool,
    pub show_help: bool,
    pub detail: Option<Detail>,
    pub next_detail_id: u64,
    pub status: Option<(Instant, String)>,

    pub mem: Option<ProcMemory>,
    /// RSS per second.
    pub rss: VecDeque<(Instant, u64)>,
    pub threads: Vec<PyThread>,
    samples: VecDeque<StackSample>,
    /// Counter samples, one per second ([`crate::sample`]), for the Graphs
    /// tab.
    pub live: VecDeque<(Instant, Sample)>,
    /// Why there are no Python counters, when there are none.
    pub live_note: Option<String>,
    /// How far back the Graphs tab looks.
    pub graph_window: Duration,

    pub latest: Option<Snap>,
    pub history: VecDeque<SnapPoint>,
    pub snapshot_running: bool,
    pub snapshot_error: Option<String>,
    pub max_pause: Option<Duration>,
    pub gone: bool,

    pub alloc: AllocState,
    pub alloc_for: Duration,
}

impl App {
    pub fn new(pid: u32, every: Duration, no_stop: bool) -> App {
        App {
            pid,
            command: crate::live::command_line(pid).unwrap_or_default(),
            every,
            no_stop,
            started: Instant::now(),
            tab: Tab::Objects,
            selected: [0; 6],
            sort: [Sort::Size; 6],
            paused: false,
            show_internals: false,
            show_help: false,
            detail: None,
            next_detail_id: 1,
            status: None,
            mem: None,
            rss: VecDeque::new(),
            threads: Vec::new(),
            samples: VecDeque::new(),
            live: VecDeque::new(),
            live_note: None,
            graph_window: GRAPH_WINDOWS[1],
            latest: None,
            history: VecDeque::new(),
            snapshot_running: false,
            snapshot_error: None,
            max_pause: None,
            gone: false,
            alloc: AllocState::Off,
            alloc_for: Duration::from_secs(60),
        }
    }

    pub fn set_status(&mut self, s: impl Into<String>) {
        self.status = Some((Instant::now(), s.into()));
    }

    pub fn on_vitals(
        &mut self,
        at: Instant,
        mem: Option<ProcMemory>,
        threads: Vec<PyThread>,
        sample: Option<Sample>,
    ) {
        if let Some(s) = sample {
            self.live.push_back((at, s));
            while self.live.len() > MAX_SECONDS {
                self.live.pop_front();
            }
        }
        if let Some(m) = mem {
            self.rss.push_back((at, m.rss));
            while self.rss.len() > MAX_SECONDS {
                self.rss.pop_front();
            }
        }
        self.mem = mem;
        for t in &threads {
            if let Some(f) = t.frames.first() {
                self.samples.push_back(StackSample {
                    at,
                    top: format!("{} ({})", f.function, f.location()),
                    running: t.state == Some("running"),
                });
            }
        }
        while self
            .samples
            .front()
            .is_some_and(|s| at.duration_since(s.at) > WINDOW)
        {
            self.samples.pop_front();
        }
        self.threads = threads;
    }

    pub fn on_snapshot(&mut self, s: Snap) {
        let r = &s.report;
        let mut p = SnapPoint {
            at: Some(s.at),
            leaked: r.totals.native_lost_bytes,
            ..SnapPoint::default()
        };
        for g in memory_groups(&r.memory) {
            *p.groups.entry(g.key).or_default() += g.bytes;
        }
        let interp: u64 = r
            .top_retainers
            .iter()
            .filter(|x| heapspy_analyzer::is_interpreter_holder(&root_path_string(&x.path)))
            .map(|x| x.retained_bytes)
            .sum();
        p.holders.insert(super::ui::INTERP_SITE.to_string(), interp);
        for x in &r.top_retainers {
            p.holders
                .insert(root_path_string(&x.path), x.retained_bytes);
        }
        let rows = what_rows(r);
        let internal = rows
            .iter()
            .filter(|w| !w.leaked && is_internal(&w.type_name));
        let sum = internal.fold((0, 0), |a, w| (a.0 + w.count, a.1 + w.bytes));
        p.types.insert(INTERNALS.to_string(), sum);
        for w in rows {
            p.types.insert(w.key, (w.count, w.bytes));
        }
        self.history.push_back(p);
        while self.history.len() > MAX_SNAPS {
            self.history.pop_front();
        }
        self.snapshot_running = false;
        self.snapshot_error = None;
        if let (Some(max), Some(pause)) = (self.max_pause, s.pause) {
            if pause > max {
                self.set_status(format!(
                    "snapshot stopped the process {} ms, over --max-pause: scheduled snapshots are off; d takes one",
                    pause.as_millis()
                ));
            }
        }
        self.latest = Some(s);
    }

    /// The memory panel's rows: empty "free" and "other" rows are left out.
    pub fn groups(&self) -> Vec<MemoryGroup> {
        self.latest
            .as_ref()
            .map(|s| memory_groups(&s.report.memory))
            .unwrap_or_default()
            .into_iter()
            .filter(|g| g.bytes > 0 || !matches!(g.key, "free" | "other"))
            .collect()
    }

    /// Change per minute of a snapshot series over [`WINDOW`]: from the
    /// oldest point in the window to the newest. `None` with fewer than two
    /// points.
    pub fn rate(&self, value: impl Fn(&SnapPoint) -> Option<u64>) -> Option<f64> {
        let now = self.history.back()?;
        let t1 = now.at?;
        let first = self
            .history
            .iter()
            .find(|p| p.at.is_some_and(|t| t1.duration_since(t) <= WINDOW) && value(p).is_some())?;
        let t0 = first.at?;
        let dt = t1.duration_since(t0).as_secs_f64() / 60.0;
        if dt <= 0.0 {
            return None;
        }
        let v1 = value(now)? as f64;
        let v0 = value(first)? as f64;
        Some((v1 - v0) / dt)
    }

    /// The last `n` values of a snapshot series (missing ones as 0).
    pub fn series(&self, n: usize, value: impl Fn(&SnapPoint) -> Option<u64>) -> Vec<u64> {
        let skip = self.history.len().saturating_sub(n);
        self.history
            .iter()
            .skip(skip)
            .map(|p| value(p).unwrap_or(0))
            .collect()
    }

    /// RSS per minute over the last minutes of per-second samples.
    pub fn rss_rate(&self) -> Option<f64> {
        let (t1, v1) = *self.rss.back()?;
        let (t0, v0) = *self
            .rss
            .iter()
            .find(|(t, _)| t1.duration_since(*t) <= WINDOW)?;
        let dt = t1.duration_since(t0).as_secs_f64() / 60.0;
        (dt >= 10.0 / 60.0).then(|| (v1 as f64 - v0 as f64) / dt)
    }

    /// RSS downsampled to `n` points over the window.
    pub fn rss_series(&self, n: usize) -> Vec<u64> {
        let v: Vec<u64> = self.rss.iter().map(|x| x.1).collect();
        downsample(&v, n)
    }

    /// The innermost frames seen most often on thread stacks over the
    /// window, preferring running threads: `(frame, samples, of)`.
    pub fn hot_frames(&self, n: usize) -> (Vec<(String, u32)>, u32) {
        let running: Vec<&StackSample> = self.samples.iter().filter(|s| s.running).collect();
        let pool: Vec<&StackSample> = if running.len() >= 10 {
            running
        } else {
            self.samples.iter().collect()
        };
        let mut c: HashMap<&str, u32> = HashMap::new();
        for s in &pool {
            *c.entry(s.top.as_str()).or_default() += 1;
        }
        let mut v: Vec<(String, u32)> = c.into_iter().map(|(k, n)| (k.to_string(), n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        (v, pool.len() as u32)
    }

    /// The next Graphs window after the current one.
    pub fn next_graph_window(&mut self) {
        let i = GRAPH_WINDOWS
            .iter()
            .position(|&w| w == self.graph_window)
            .map_or(0, |i| (i + 1) % GRAPH_WINDOWS.len());
        self.graph_window = GRAPH_WINDOWS[i];
    }

    /// A counter series over the Graphs window, as (seconds before the
    /// latest sample, as a negative number; value) points.
    pub fn live_series(&self, value: impl Fn(&Sample) -> Option<u64>) -> Vec<(f64, f64)> {
        let Some(&(t1, _)) = self.live.back() else {
            return Vec::new();
        };
        self.live
            .iter()
            .filter(|(t, _)| t1.duration_since(*t) <= self.graph_window)
            .filter_map(|(t, s)| Some((-t1.duration_since(*t).as_secs_f64(), value(s)? as f64)))
            .collect()
    }

    /// Change per minute of a counter series over the Graphs window.
    pub fn live_rate(&self, value: impl Fn(&Sample) -> Option<u64>) -> Option<f64> {
        let v = self.live_series(value);
        let (&(t0, v0), &(t1, v1)) = (v.first()?, v.last()?);
        let minutes = (t1 - t0) / 60.0;
        (minutes >= 10.0 / 60.0).then(|| (v1 - v0) / minutes)
    }

    /// The first and the latest sample in the Graphs window.
    pub fn live_ends(&self) -> Option<(&Sample, &Sample)> {
        let &(t1, ref last) = self.live.back()?;
        let first = self
            .live
            .iter()
            .find(|(t, _)| t1.duration_since(*t) <= self.graph_window)?;
        Some((&first.1, last))
    }

    pub fn last_snapshot_age(&self) -> Option<Duration> {
        self.latest.as_ref().map(|s| s.at.elapsed())
    }
}

/// `v` reduced to at most `n` points by averaging buckets.
pub fn downsample(v: &[u64], n: usize) -> Vec<u64> {
    if v.len() <= n || n == 0 {
        return v.to_vec();
    }
    (0..n)
        .map(|i| {
            let a = i * v.len() / n;
            let b = ((i + 1) * v.len() / n).max(a + 1);
            v[a..b].iter().sum::<u64>() / (b - a) as u64
        })
        .collect()
}

/// A sparkline of block characters, scaled between the series' min and max.
pub fn sparkline(v: &[u64]) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let (Some(&lo), Some(&hi)) = (v.iter().min(), v.iter().max()) else {
        return String::new();
    };
    v.iter()
        .map(|&x| {
            if hi == lo {
                BARS[0]
            } else {
                BARS[((x - lo) as f64 / (hi - lo) as f64 * 7.0).round() as usize]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_scales() {
        assert_eq!(sparkline(&[1, 2, 3]), "▁▅█");
        assert_eq!(sparkline(&[5, 5]), "▁▁");
        assert_eq!(sparkline(&[]), "");
    }

    #[test]
    fn downsample_averages() {
        assert_eq!(downsample(&[1, 3, 5, 7], 2), vec![2, 6]);
        assert_eq!(downsample(&[1, 2], 5), vec![1, 2]);
    }

    #[test]
    fn rate_over_history() {
        let mut a = App::new(1, Duration::from_secs(10), false);
        let t0 = Instant::now();
        for (i, v) in [100u64, 160, 220].iter().enumerate() {
            a.history.push_back(SnapPoint {
                at: Some(t0 + Duration::from_secs(30 * i as u64)),
                leaked: *v,
                ..SnapPoint::default()
            });
        }
        let r = a.rate(|p| Some(p.leaked)).unwrap();
        assert!((r - 120.0).abs() < 1e-6, "{r}");
    }
}
