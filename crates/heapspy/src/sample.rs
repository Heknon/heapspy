//! Cheap, live numbers about a running CPython process, read without
//! stopping it: the OS's memory figures, CPython's GC and allocator
//! counters, and what glibc malloc holds from the OS.
//!
//! A [`Sample`] takes a millisecond or so, so `watch --counters` and `top`
//! read one every second (or faster) where a full snapshot takes seconds.
//! Nothing here follows object pointers: see
//! `heapspy_reader::cpython::counters` for why the numbers stay sound while
//! the process runs. They are still read at slightly different moments, so
//! every sample says `approximate: true`.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use heapspy_reader::cpython::counters::{AllocatorCounters, CounterReader, GcCounters, PyCounters};
use heapspy_reader::MemorySource;
use serde::Serialize;

use crate::live;

/// One reading of every counter.
#[derive(Clone, Debug, Serialize)]
pub struct Sample {
    /// Always `"sample"`, so a JSON Lines consumer can tell samples from
    /// `watch` rounds and summaries.
    pub kind: &'static str,
    pub pid: u32,
    /// 1, 2, ... in the order taken.
    pub seq: u64,
    /// Seconds since the sampler was opened.
    pub elapsed_s: f64,
    /// When it was taken, in seconds since the Unix epoch.
    pub unix_time: f64,
    /// How long the reads took, in milliseconds.
    pub took_ms: f64,
    /// Always `true`: the process was not stopped.
    pub approximate: bool,
    pub os: Option<OsSample>,
    pub python: Option<PythonSample>,
    pub native: Option<NativeSample>,
}

/// What the OS says about the process.
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct OsSample {
    /// Resident memory (Linux `VmRSS`, Windows working set).
    pub rss_bytes: u64,
    /// Linux: resident anonymous memory (`RssAnon`).
    pub anon_bytes: Option<u64>,
    /// Linux: resident file-backed and shared memory.
    pub file_bytes: Option<u64>,
    /// Windows: private commit (`PrivateUsage`).
    pub private_bytes: Option<u64>,
    pub threads: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PythonSample {
    pub interpreters: u32,
    /// Python thread states.
    pub threads: u32,
    pub gc: Option<GcSample>,
    pub allocator: Option<AllocatorSample>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GcSample {
    pub enabled: bool,
    pub collecting: bool,
    /// Generations 0, 1, 2.
    pub generations: Vec<GenerationSample>,
    pub long_lived_total: i64,
    pub long_lived_pending: i64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct GenerationSample {
    pub count: i64,
    pub threshold: i64,
    pub collections: u64,
    pub collected: u64,
    pub uncollectable: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AllocatorSample {
    pub arenas: u64,
    pub arenas_highwater: u64,
    pub arenas_allocated_total: u64,
    /// Memory pymalloc holds from the OS.
    pub arena_bytes: u64,
    pub pools: u64,
    /// Blocks in use, and their bytes: the small Python objects.
    pub blocks: u64,
    pub block_bytes: u64,
    /// `arena_bytes - block_bytes`: free inside pymalloc's arenas.
    pub free_bytes: u64,
    pub size_classes: Vec<SizeClassSample>,
    pub skipped_pools: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SizeClassSample {
    pub size: u32,
    pub pools: u64,
    pub blocks: u64,
}

/// glibc malloc's heaps, from their headers.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct NativeSample {
    /// brk heap plus thread heaps. mmapped chunks (128 KiB and up) are
    /// not in it.
    pub heap_bytes: u64,
    pub brk_bytes: u64,
    pub thread_arenas: u32,
    pub thread_heap_bytes: u64,
}

impl From<&GcCounters> for GcSample {
    fn from(g: &GcCounters) -> Self {
        GcSample {
            enabled: g.enabled,
            collecting: g.collecting,
            generations: g
                .generations
                .iter()
                .map(|x| GenerationSample {
                    count: x.count,
                    threshold: x.threshold,
                    collections: x.collections,
                    collected: x.collected,
                    uncollectable: x.uncollectable,
                })
                .collect(),
            long_lived_total: g.long_lived_total,
            long_lived_pending: g.long_lived_pending,
        }
    }
}

impl From<&AllocatorCounters> for AllocatorSample {
    fn from(a: &AllocatorCounters) -> Self {
        AllocatorSample {
            arenas: a.arenas,
            arenas_highwater: a.arenas_highwater,
            arenas_allocated_total: a.arenas_allocated_total,
            arena_bytes: a.arena_bytes,
            pools: a.pools,
            blocks: a.blocks,
            block_bytes: a.block_bytes,
            free_bytes: a.arena_bytes.saturating_sub(a.block_bytes),
            size_classes: a
                .size_classes
                .iter()
                .map(|c| SizeClassSample {
                    size: c.size,
                    pools: c.pools,
                    blocks: c.blocks,
                })
                .collect(),
            skipped_pools: a.skipped_pools,
        }
    }
}

impl From<&PyCounters> for PythonSample {
    fn from(c: &PyCounters) -> Self {
        PythonSample {
            interpreters: c.interpreters,
            threads: c.threads,
            gc: c.gc.as_ref().map(GcSample::from),
            allocator: c.allocator.as_ref().map(AllocatorSample::from),
        }
    }
}

impl Sample {
    pub fn rss(&self) -> Option<u64> {
        self.os.map(|o| o.rss_bytes)
    }
    /// Bytes of small Python objects (pymalloc blocks in use).
    pub fn python_bytes(&self) -> Option<u64> {
        Some(self.python.as_ref()?.allocator.as_ref()?.block_bytes)
    }
    pub fn arena_bytes(&self) -> Option<u64> {
        Some(self.python.as_ref()?.allocator.as_ref()?.arena_bytes)
    }
    pub fn malloc_bytes(&self) -> Option<u64> {
        self.native.map(|n| n.heap_bytes)
    }
    pub fn gc(&self) -> Option<&GcSample> {
        self.python.as_ref()?.gc.as_ref()
    }
    /// Collections of every generation so far.
    pub fn collections(&self) -> Option<u64> {
        Some(self.gc()?.generations.iter().map(|g| g.collections).sum())
    }
}

/// The source the sampler reads through: on Linux a [`LiveProcess`] that
/// can also re-read the maps for the malloc heap totals.
///
/// [`LiveProcess`]: heapspy_reader::source::linux_live::LiveProcess
#[cfg(target_os = "linux")]
type Source = heapspy_reader::source::linux_live::LiveProcess;
#[cfg(not(target_os = "linux"))]
type Source = Box<dyn MemorySource>;

/// Takes [`Sample`]s of one process.
pub struct Sampler {
    pid: u32,
    src: Source,
    counters: Option<CounterReader>,
    /// Why there are no Python counters, when there are none.
    pub counters_error: Option<String>,
    started: Instant,
    seq: u64,
}

impl Sampler {
    /// Open `pid` for sampling. Fails when the process cannot be read at
    /// all; a process that is not a supported CPython still gives OS
    /// numbers, with [`Sampler::counters_error`] saying why there are no
    /// others.
    pub fn open(pid: u32) -> anyhow::Result<Sampler> {
        #[cfg(target_os = "linux")]
        let src = heapspy_reader::source::linux_live::LiveProcess::open_running(pid)?;
        #[cfg(not(target_os = "linux"))]
        let src = heapspy_record::live::open(pid)?;
        let (counters, counters_error) = {
            let s: &dyn MemorySource = as_dyn(&src);
            match heapspy_reader::cpython::locate_runtime(s)
                .and_then(|rt| CounterReader::new(s, &rt))
            {
                Ok(c) => (Some(c), None),
                Err(e) => (None, Some(e.to_string())),
            }
        };
        Ok(Sampler {
            pid,
            src,
            counters,
            counters_error,
            started: Instant::now(),
            seq: 0,
        })
    }

    /// Read every counter once. `None` when the process is gone.
    pub fn sample(&mut self) -> Option<Sample> {
        let t0 = Instant::now();
        let os = os_sample(self.pid);
        if os.is_none() && cfg!(target_os = "linux") {
            return None;
        }
        let src: &dyn MemorySource = as_dyn(&self.src);
        let python = self
            .counters
            .as_ref()
            .and_then(|c| c.read(src).ok())
            .map(|c| PythonSample::from(&c));
        #[cfg(target_os = "linux")]
        let native = self.src.heap_totals().map(|t| NativeSample {
            heap_bytes: t.heap_bytes(),
            brk_bytes: t.brk_bytes,
            thread_arenas: t.thread_arenas,
            thread_heap_bytes: t.thread_heap_bytes,
        });
        #[cfg(not(target_os = "linux"))]
        let native = None;
        self.seq += 1;
        Some(Sample {
            kind: "sample",
            pid: self.pid,
            seq: self.seq,
            elapsed_s: round3(t0.duration_since(self.started).as_secs_f64()),
            unix_time: round3(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0.0, |d| d.as_secs_f64()),
            ),
            took_ms: round3(t0.elapsed().as_secs_f64() * 1000.0),
            approximate: true,
            os,
            python,
            native,
        })
    }
}

#[cfg(target_os = "linux")]
fn as_dyn(s: &Source) -> &dyn MemorySource {
    s
}
#[cfg(not(target_os = "linux"))]
fn as_dyn(s: &Source) -> &dyn MemorySource {
    s.as_ref()
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// The OS's numbers for `pid`. `None` when they cannot be read (on Linux,
/// when the process is gone).
pub fn os_sample(pid: u32) -> Option<OsSample> {
    if let Some(m) = live::proc_memory(pid) {
        if cfg!(target_os = "linux") {
            return Some(OsSample {
                rss_bytes: m.rss,
                anon_bytes: Some(m.anon),
                file_bytes: Some(m.file),
                private_bytes: None,
                threads: Some(m.threads),
            });
        }
    }
    heapspy_record::live::windows_memory(pid).map(|(ws, private)| OsSample {
        rss_bytes: ws,
        private_bytes: Some(private),
        ..OsSample::default()
    })
}

/// Sleep until `t`, waking early when `stop` returns true. Checks every
/// 50 ms (or sooner, for short waits).
pub fn sleep_until(t: Instant, stop: impl Fn() -> bool) {
    while !stop() {
        let now = Instant::now();
        if now >= t {
            return;
        }
        std::thread::sleep((t - now).min(Duration::from_millis(50)));
    }
}

/// A sample with these numbers, for tests.
#[cfg(test)]
pub fn fake(seq: u64, t: f64, rss: u64, blocks: u64, collections: u64) -> Sample {
    Sample {
        kind: "sample",
        pid: 1,
        seq,
        elapsed_s: t,
        unix_time: 0.0,
        took_ms: 0.1,
        approximate: true,
        os: Some(OsSample {
            rss_bytes: rss,
            ..OsSample::default()
        }),
        python: Some(PythonSample {
            interpreters: 1,
            threads: 1,
            gc: Some(GcSample {
                enabled: true,
                collecting: false,
                generations: (0..3)
                    .map(|i| GenerationSample {
                        count: 0,
                        threshold: 2000,
                        collections: collections / (i + 1),
                        collected: collections * 10,
                        uncollectable: 0,
                    })
                    .collect(),
                long_lived_total: 0,
                long_lived_pending: 0,
            }),
            allocator: Some(AllocatorSample {
                arenas: 1,
                arenas_highwater: 1,
                arenas_allocated_total: 1,
                arena_bytes: 1 << 20,
                pools: 1,
                blocks: 1,
                block_bytes: blocks,
                free_bytes: 0,
                size_classes: vec![],
                skipped_pools: 0,
            }),
        }),
        native: None,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn samples_itself_without_python_counters() {
        // The test binary is not CPython: OS numbers only.
        let mut s = Sampler::open(std::process::id()).unwrap();
        assert!(s.counters_error.is_some());
        let a = s.sample().unwrap();
        assert_eq!(a.seq, 1);
        assert!(a.rss().unwrap() > 0);
        assert!(a.python.is_none());
        let b = s.sample().unwrap();
        assert_eq!(b.seq, 2);
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["kind"], "sample");
        assert_eq!(v["approximate"], true);
        assert!(v["os"]["rss_bytes"].as_u64().unwrap() > 0);
    }
}
