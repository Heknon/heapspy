//! Joining an allocation profile (`.hpya`, from `heapspy record`) with a
//! snapshot.
//!
//! The report fields are defined in [`crate::report`] and documented in
//! `docs/json-schema.md`: `AnalyzeReport.allocations`,
//! `Retainer.allocated_at` and `Instance.allocated_at`. Design:
//! `docs/allocation-sampling.md`, "Joining with a snapshot".
//!
//! # By address
//!
//! A sample covers `[address, address + size)`: one 16 KiB pool, one 1 MiB
//! arena, or one large allocation. An object is *linked* to the latest
//! sample (highest index; samples are sorted by time) whose range contains
//! the object's address. A later sample over the same memory supersedes an
//! earlier one, because the memory was freed and reused in between.
//!
//! [`latest_covering`] does this in one sweep. Object addresses are sorted
//! (the snapshot stores objects by address); sample ranges are sorted by
//! start once. Walking the objects in address order, every sample whose
//! range starts at or before the current address is pushed onto a max-heap
//! keyed by sample index. The heap top is the answer once samples whose
//! range ended at or before the address have been popped from the top.
//! Ended samples below the top are popped later, when they surface; they
//! never hide a live one, because the top is the largest index of all
//! entries. Each sample is pushed and popped once, so the sweep costs
//! `O(n + m log m)` for `n` objects and `m` samples, with `O(m)` extra
//! memory (the heap, the order, and the ranges) plus one `u32` per object
//! for the result.
//!
//! Links through large-object samples are exact: the range is one
//! allocation. Links through arena and pool samples (and unknown event
//! kinds) are approximate: they name the most recent growth event that
//! created the memory, not necessarily the call that allocated the object.
//! The report keeps the two apart with `exact_linked_*` fields; the
//! `approximate` flags keep their schema meaning (frames matched to events
//! by time).
//!
//! Samples taken after the snapshot (timestamp past the snapshot's capture
//! second) are not used for linking: they describe memory the snapshot has
//! not seen. When [`compatibility`] reports a mismatch (another pid, another
//! CPython, or a snapshot from before the recording), nothing is linked and
//! the report says so with an `allocations_not_linked` note; the sampled
//! stacks are still reported.
//!
//! # By site
//!
//! Samples are grouped by their resolved stack: the sequence of
//! `(function, location)` pairs from `Profile::stack`, innermost first. Raw
//! frames are resolved once per distinct `(code entry, instruction offset)`
//! and interned, so a stack is a short list of frame ids. Each group sums
//! its samples' weights (`estimated_bytes`) and the shallow bytes of the
//! reachable objects linked to its samples (`linked_bytes`). The largest
//! groups by estimated bytes are `top_stacks`.

use std::collections::{BinaryHeap, HashMap};

use heapspy_alloc::{EventKind, Profile, SampleFlags};
use heapspy_snapshot::{Snapshot, SourceKind};

use crate::analysis::Analysis;
use crate::flame::FxMap;
use crate::report::{
    AllocationStack, Allocations, AnalyzeReport, Coverage, Note, OverheadInfo, SamplingInfo,
    StackFrame, TypeQueryReport,
};
use crate::{pct, AnalyzeOptions, Error, QueryOptions, Result};

/// "No sample" in the result of [`latest_covering`].
pub const NO_LINK: u32 = u32::MAX;

const NS_PER_S: u64 = 1_000_000_000;

fn note(code: &str, message: String) -> Note {
    Note {
        code: code.to_string(),
        message,
    }
}

/// Checks that `profile` was recorded from the process and interpreter the
/// snapshot was taken from, and before it. Each mismatch is a note (codes
/// `allocations_pid_mismatch`, `allocations_python_mismatch`,
/// `allocations_after_snapshot`); an empty list means they line up. The
/// pid is only checked for snapshots of a live process.
pub fn compatibility(snap: &Snapshot, profile: &Profile) -> Vec<Note> {
    let s = snap.info();
    let p = profile.info();
    let mut notes = Vec::new();
    if s.source.kind == SourceKind::Pid {
        if let Ok(pid) = s.source.reference.parse::<u32>() {
            if pid != p.pid {
                notes.push(note(
                    "allocations_pid_mismatch",
                    format!(
                        "The allocation profile was recorded from pid {}, but the snapshot is of \
                         pid {pid}. Samples will not match the snapshot's objects.",
                        p.pid
                    ),
                ));
            }
        }
    }
    if s.python != p.python {
        notes.push(note(
            "allocations_python_mismatch",
            format!(
                "The allocation profile was recorded from CPython {}, but the snapshot is of \
                 CPython {}.",
                p.python, s.python
            ),
        ));
    }
    // Snapshot time is in seconds, profile times in nanoseconds.
    let start_s = p.start_ns / NS_PER_S;
    if s.captured_at < start_s {
        notes.push(note(
            "allocations_after_snapshot",
            "The snapshot was taken before the allocation recording started, so no sampled \
             allocation can be in it. Take the snapshot at the end of the recording \
             (heapspy record --then-dump)."
                .to_string(),
        ));
    }
    notes
}

/// The note every joined report carries: what the samples can and cannot
/// say.
pub fn sampled_note() -> Note {
    note(
        "allocations_sampled",
        "Allocation stacks cover only allocations made while recording, and only the sampled \
         events (arena, pool, large object); objects allocated before recording started have no \
         stack. Links through arena and pool samples are approximate: they name the most recent \
         growth event that created the memory, not necessarily the call that allocated the \
         object. Links through large-object samples are exact."
            .to_string(),
    )
}

/// The note added when the profile does not line up with the snapshot and
/// no sample was linked.
pub fn not_linked_note() -> Note {
    note(
        "allocations_not_linked",
        "The allocation profile does not match the snapshot (see the notes above), so no sample \
         was linked to an object. Only the sampled stacks are reported."
            .to_string(),
    )
}

// ---------------------------------------------------------------- by address

/// For each address of `addrs`, the index of the latest range in `ranges`
/// that contains it, or [`NO_LINK`].
///
/// `ranges[i]` is `(start, end)`, half-open, for sample `i`; a range with
/// `start >= end` covers nothing. "Latest" is the highest index. `addrs`
/// must be sorted ascending (snapshot objects are). Fails if there are
/// `u32::MAX` ranges or more.
pub fn latest_covering(
    addrs: impl IntoIterator<Item = u64>,
    ranges: &[(u64, u64)],
) -> Result<Vec<u32>> {
    if ranges.len() >= NO_LINK as usize {
        return Err(Error::InvalidArgument(
            "the allocation profile has more than 2^32 - 2 samples".into(),
        ));
    }
    let mut order: Vec<u32> = (0..ranges.len() as u32)
        .filter(|&i| ranges[i as usize].0 < ranges[i as usize].1)
        .collect();
    order.sort_unstable_by_key(|&i| ranges[i as usize].0);
    let addrs = addrs.into_iter();
    let mut out = Vec::with_capacity(addrs.size_hint().0);
    let mut heap: BinaryHeap<u32> = BinaryHeap::new();
    let mut next = 0;
    let mut prev = 0u64;
    for a in addrs {
        debug_assert!(a >= prev, "addresses must be sorted");
        prev = a;
        while next < order.len() && ranges[order[next] as usize].0 <= a {
            heap.push(order[next]);
            next += 1;
        }
        while let Some(&top) = heap.peek() {
            if ranges[top as usize].1 <= a {
                heap.pop();
            } else {
                break;
            }
        }
        out.push(heap.peek().copied().unwrap_or(NO_LINK));
    }
    Ok(out)
}

// ---------------------------------------------------------------- by site

/// One interned resolved frame.
struct FrameText {
    function: String,
    file: Option<String>,
    line: Option<u32>,
    location: String,
}

const EV_OTHER: u8 = 1 << 0;
const EV_ARENA: u8 = 1 << 1;
const EV_POOL: u8 = 1 << 2;
const EV_LARGE: u8 = 1 << 3;
const EV_UNKNOWN: u8 = 1 << 4;

fn event_bit(k: EventKind) -> u8 {
    match k {
        EventKind::Other => EV_OTHER,
        EventKind::Arena => EV_ARENA,
        EventKind::Pool => EV_POOL,
        EventKind::LargeObject => EV_LARGE,
        EventKind::Unknown(_) => EV_UNKNOWN,
    }
}

/// Event names in a mask, sorted.
fn event_names(mask: u8) -> Vec<String> {
    let mut v: Vec<String> = [
        (EV_ARENA, "arena"),
        (EV_LARGE, "large_object"),
        (EV_OTHER, "other"),
        (EV_POOL, "pool"),
        (EV_UNKNOWN, "unknown"),
    ]
    .iter()
    .filter(|(b, _)| mask & b != 0)
    .map(|(_, n)| n.to_string())
    .collect();
    v.sort();
    v
}

/// Samples with the same resolved stack.
struct Group {
    frames: Box<[u32]>,
    /// Per frame: approximate in any of the group's samples.
    frame_approx: Vec<bool>,
    estimated: u64,
    samples: u64,
    events: u8,
    approximate: bool,
    linked_objects: u64,
    linked_bytes: u64,
    exact_bytes: u64,
}

/// The samples of a profile grouped by resolved stack.
struct Stacks {
    frames: Vec<FrameText>,
    groups: Vec<Group>,
    /// Group of each sample, with [`EXACT_BIT`] set for large-object samples.
    of_sample: Vec<u32>,
    approximate: bool,
    estimated: u64,
}

/// Set in [`Stacks::of_sample`] when the sample's links are exact.
const EXACT_BIT: u32 = 1 << 31;

impl Stacks {
    fn new(profile: &Profile) -> Result<Stacks> {
        let m = profile.sample_count();
        if m >= EXACT_BIT as u64 {
            return Err(Error::InvalidArgument(
                "the allocation profile has more than 2^31 - 1 samples".into(),
            ));
        }
        let mut frames: Vec<FrameText> = Vec::new();
        let mut raw: FxMap<(Option<u32>, Option<u32>), u32> = FxMap::default();
        let mut by_text: HashMap<(String, String), u32> = HashMap::new();
        let mut index: FxMap<Box<[u32]>, u32> = FxMap::default();
        let mut groups: Vec<Group> = Vec::new();
        let mut of_sample = Vec::with_capacity(m as usize);
        let mut ids: Vec<u32> = Vec::new();
        let mut approx: Vec<bool> = Vec::new();
        let (mut any_approx, mut estimated) = (false, 0u64);
        for s in profile.samples() {
            ids.clear();
            approx.clear();
            for f in profile.frames(&s) {
                let key = (f.code.map(|c| c.0), f.instr_offset);
                let id = match raw.get(&key) {
                    Some(&id) => id,
                    None => {
                        let r = profile.resolve(f);
                        let function = r.function().to_string();
                        let location = r.location();
                        let id = *by_text
                            .entry((function.clone(), location.clone()))
                            .or_insert_with(|| {
                                frames.push(FrameText {
                                    function,
                                    file: r.filename.map(str::to_string),
                                    line: r.line,
                                    location,
                                });
                                frames.len() as u32 - 1
                            });
                        raw.insert(key, id);
                        id
                    }
                };
                ids.push(id);
                approx.push(f.approximate);
            }
            let g = match index.get(&ids[..]) {
                Some(&g) => g,
                None => {
                    groups.push(Group {
                        frames: ids.clone().into_boxed_slice(),
                        frame_approx: vec![false; ids.len()],
                        estimated: 0,
                        samples: 0,
                        events: 0,
                        approximate: false,
                        linked_objects: 0,
                        linked_bytes: 0,
                        exact_bytes: 0,
                    });
                    let g = groups.len() as u32 - 1;
                    index.insert(ids.clone().into_boxed_slice(), g);
                    g
                }
            };
            let grp = &mut groups[g as usize];
            grp.estimated = grp.estimated.saturating_add(s.weight);
            grp.samples += 1;
            grp.events |= event_bit(s.kind);
            let sample_approx =
                s.flags.contains(SampleFlags::APPROXIMATE_FRAMES) || approx.iter().any(|&a| a);
            grp.approximate |= sample_approx;
            any_approx |= sample_approx;
            for (slot, &a) in grp.frame_approx.iter_mut().zip(&approx) {
                *slot |= a;
            }
            estimated = estimated.saturating_add(s.weight);
            let exact = if s.kind == EventKind::LargeObject {
                EXACT_BIT
            } else {
                0
            };
            of_sample.push(g | exact);
        }
        Ok(Stacks {
            frames,
            groups,
            of_sample,
            approximate: any_approx,
            estimated,
        })
    }

    fn stack_frames(&self, g: u32) -> Vec<StackFrame> {
        let grp = &self.groups[g as usize];
        grp.frames
            .iter()
            .zip(&grp.frame_approx)
            .map(|(&f, &approximate)| {
                let t = &self.frames[f as usize];
                StackFrame {
                    function: t.function.clone(),
                    file: t.file.clone(),
                    line: t.line,
                    location: t.location.clone(),
                    approximate,
                }
            })
            .collect()
    }

    /// Groups by estimated bytes, then linked bytes, then first appearance.
    fn ranked(&self) -> Vec<u32> {
        let mut v: Vec<u32> = (0..self.groups.len() as u32).collect();
        v.sort_by(|&x, &y| {
            let (a, b) = (&self.groups[x as usize], &self.groups[y as usize]);
            (b.estimated, b.linked_bytes)
                .cmp(&(a.estimated, a.linked_bytes))
                .then(x.cmp(&y))
        });
        v
    }
}

// ---------------------------------------------------------------- the join

/// A profile joined with an analysed snapshot.
struct Join {
    stacks: Stacks,
    /// Linked sample per object, or [`NO_LINK`]. Empty when nothing was
    /// linked.
    link: Vec<u32>,
    coverage: Coverage,
    notes: Vec<Note>,
}

impl Join {
    fn new(a: &Analysis, profile: &Profile) -> Result<Join> {
        let snap = a.snap;
        let mut stacks = Stacks::new(profile)?;
        let mut notes = compatibility(snap, profile);
        let link = if notes.is_empty() {
            // Samples after the snapshot's capture second cannot describe it.
            let cutoff = snap
                .info()
                .captured_at
                .saturating_add(1)
                .saturating_mul(NS_PER_S);
            let ranges: Vec<(u64, u64)> = profile
                .samples()
                .map(|s| {
                    if s.timestamp_ns < cutoff {
                        (s.address, s.address.saturating_add(s.size))
                    } else {
                        (0, 0)
                    }
                })
                .collect();
            let n = snap.object_count() as u32;
            latest_covering((0..n).map(|i| snap.object_addr(i)), &ranges)?
        } else {
            notes.push(not_linked_note());
            Vec::new()
        };
        notes.push(sampled_note());

        let mut coverage = Coverage {
            linked_objects: 0,
            linked_bytes: 0,
            linked_pct: 0.0,
            exact_linked_objects: 0,
            exact_linked_bytes: 0,
        };
        for (v, &l) in link.iter().enumerate() {
            if l == NO_LINK || !a.reachable(v as u32) {
                continue;
            }
            let bytes = snap.object(v as u32).shallow_size;
            let packed = stacks.of_sample[l as usize];
            let grp = &mut stacks.groups[(packed & !EXACT_BIT) as usize];
            grp.linked_objects += 1;
            grp.linked_bytes += bytes;
            coverage.linked_objects += 1;
            coverage.linked_bytes += bytes;
            if packed & EXACT_BIT != 0 {
                grp.exact_bytes += bytes;
                coverage.exact_linked_objects += 1;
                coverage.exact_linked_bytes += bytes;
            }
        }
        coverage.linked_pct = pct(coverage.linked_bytes, a.reachable_bytes());
        Ok(Join {
            stacks,
            link,
            coverage,
            notes,
        })
    }

    /// The first `top` groups, best first.
    fn top(&self, top: usize) -> Vec<u32> {
        let mut r = self.stacks.ranked();
        r.truncate(top);
        r
    }

    fn top_stacks(&self, top: &[u32]) -> Vec<AllocationStack> {
        top.iter()
            .enumerate()
            .map(|(i, &g)| {
                let grp = &self.stacks.groups[g as usize];
                AllocationStack {
                    rank: i as u32 + 1,
                    frames: self.stacks.stack_frames(g),
                    estimated_bytes: grp.estimated,
                    samples: grp.samples,
                    events: event_names(grp.events),
                    linked_bytes: grp.linked_bytes,
                    exact_linked_bytes: grp.exact_bytes,
                    approximate: grp.approximate,
                }
            })
            .collect()
    }

    fn block(&self, profile: &Profile, path: &str, top: &[u32]) -> Allocations {
        let i = profile.info();
        let mut events: Vec<String> = i
            .sampling
            .events
            .iter()
            .map(|k| k.as_str().to_string())
            .collect();
        events.sort();
        Allocations {
            path: path.to_string(),
            pid: i.pid,
            python_version: i.python.to_string(),
            started_at: i.start_ns / NS_PER_S,
            duration_ms: i.duration_ns() / 1_000_000,
            mechanisms: i
                .mechanisms
                .iter()
                .map(|m| m.as_str().to_string())
                .collect(),
            sampling: SamplingInfo {
                events,
                byte_interval: i.sampling.byte_interval,
                max_frames: i.sampling.max_frames,
            },
            overhead: OverheadInfo {
                samples_taken: i.overhead.samples_taken,
                samples_dropped: i.overhead.samples_dropped,
                probe_hits: i.overhead.probe_hits,
                total_pause_ns: i.overhead.total_pause_ns,
            },
            truncated: i.truncated,
            approximate: self.stacks.approximate,
            samples: profile.sample_count(),
            estimated_bytes: self.stacks.estimated,
            coverage: self.coverage.clone(),
            top_stacks: self.top_stacks(top),
        }
    }
}

/// [`crate::analyze`] plus the `allocations` block. `profile_path` is the profile's path as given by the
/// user.
pub fn analyze_with_allocations(
    snap: &Snapshot,
    path: &str,
    opts: &AnalyzeOptions,
    profile: &Profile,
    profile_path: &str,
) -> Result<AnalyzeReport> {
    let a = Analysis::new(snap)?;
    let (mut report, _) = crate::analyze_with(&a, path, opts)?;
    let j = Join::new(&a, profile)?;
    let top = j.top(opts.top);
    report.allocations = Some(j.block(profile, profile_path, &top));
    report.notes.extend(j.notes);
    Ok(report)
}

/// [`crate::query_type`] plus the profile's notes.
pub fn query_type_with_allocations(
    snap: &Snapshot,
    path: &str,
    type_name: &str,
    opts: &QueryOptions,
    profile: &Profile,
) -> Result<TypeQueryReport> {
    let a = Analysis::new(snap)?;
    let (mut report, _) = crate::query::query_type(&a, path, type_name, opts)?;
    let j = Join::new(&a, profile)?;
    report.notes.extend(j.notes);
    Ok(report)
}

/// For tests and tools: the sample linked to each object of `snap` by
/// index, or [`NO_LINK`], with the same rules as the reports (no links
/// when [`compatibility`] reports a mismatch, samples after the snapshot
/// ignored). Unreachable objects are linked too.
pub fn object_links(snap: &Snapshot, profile: &Profile) -> Result<Vec<u32>> {
    let a = Analysis::new(snap)?;
    let j = Join::new(&a, profile)?;
    Ok(if j.link.is_empty() {
        vec![NO_LINK; snap.object_count()]
    } else {
        j.link
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapspy_alloc::{ProfileBuilder, PythonVersion};
    use heapspy_snapshot::SnapshotBuilder;

    fn snap(pid: &str, captured_at: u64) -> Snapshot {
        let mut b = SnapshotBuilder::new();
        b.info_mut().source.reference = pid.into();
        b.info_mut().captured_at = captured_at;
        b.build().unwrap()
    }

    fn profile(pid: u32, minor: u8, start_s: u64) -> Profile {
        let mut b = ProfileBuilder::new();
        b.info_mut().pid = pid;
        b.info_mut().python = PythonVersion::new(3, minor, 0);
        b.info_mut().start_ns = start_s * 1_000_000_000;
        b.build().unwrap()
    }

    fn codes(n: &[Note]) -> Vec<&str> {
        n.iter().map(|n| n.code.as_str()).collect()
    }

    #[test]
    fn compatible_and_not() {
        let s = snap("42", 1000);
        assert!(compatibility(&s, &profile(42, 12, 900)).is_empty());
        assert_eq!(
            codes(&compatibility(&s, &profile(7, 13, 2000))),
            [
                "allocations_pid_mismatch",
                "allocations_python_mismatch",
                "allocations_after_snapshot"
            ]
        );
        // A core file has no pid to compare.
        let mut b = SnapshotBuilder::new();
        b.info_mut().source.kind = SourceKind::Core;
        b.info_mut().source.reference = "core.1234".into();
        b.info_mut().captured_at = 1000;
        let core = b.build().unwrap();
        assert!(compatibility(&core, &profile(7, 12, 0)).is_empty());
    }

    #[test]
    fn latest_covering_basics() {
        // 0: [100, 200), 1: [150, 160), 2: empty, 3: [100, 120)
        let ranges = [(100, 200), (150, 160), (5, 5), (100, 120)];
        let got = latest_covering([0, 5, 100, 119, 120, 150, 159, 160, 199, 200], &ranges).unwrap();
        assert_eq!(
            got,
            [NO_LINK, NO_LINK, 3, 3, 0, 1, 1, 0, 0, NO_LINK],
            "{got:?}"
        );
        assert!(latest_covering([1, 2], &[])
            .unwrap()
            .iter()
            .all(|&l| l == NO_LINK));
        // A range ending at u64::MAX saturates and still covers the top.
        let got = latest_covering([u64::MAX - 1], &[(u64::MAX - 8, u64::MAX)]).unwrap();
        assert_eq!(got, [0]);
    }

    #[test]
    fn event_names_are_sorted() {
        assert_eq!(
            event_names(EV_POOL | EV_ARENA | EV_LARGE),
            ["arena", "large_object", "pool"]
        );
        assert!(event_names(0).is_empty());
    }
}
