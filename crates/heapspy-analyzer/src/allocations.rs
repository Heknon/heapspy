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
//! A large-object sample describes one allocation: its address and its
//! requested size. An object is that allocation only if it starts there
//! and has that size ([`matches_large_object`]). When the latest covering
//! sample is a large-object sample the object does not match, the sampled
//! block was freed and the memory reused by an allocation that was not
//! sampled, so the object is not linked at all: older samples over the
//! same address describe even earlier allocations. Such objects are
//! counted in `coverage.unlinked_reused_*`. Links through large-object
//! samples are exact. Links through arena and pool samples (and unknown
//! event kinds) are approximate: they name the most recent growth event
//! that created the memory, not necessarily the call that allocated the
//! object. The report keeps the two apart with `exact_linked_*` fields; the
//! `approximate` flags keep their schema meaning (frames matched to events
//! by time).
//!
//! # Native samples: by containment
//!
//! A native heap sample is different: its `address` is the pointer the
//! allocator *returned*, which lies **inside** the block, after the
//! allocator's header (and, for a large block, at a randomised offset). The
//! snapshot object for a native block has that block's start as its address
//! and the block's size as its shallow size, so the returned pointer falls
//! in `(object.addr, object.addr + object.shallow_size)`, not at the start.
//! The object-address sweep above, which asks whether the object's *start*
//! is in a sample's range, therefore never links a native block, and native
//! samples are left out of that sweep ([`Join::new`] gives them an empty
//! range). This keeps every arena, pool, large-object and Python link
//! byte-for-byte as it was.
//!
//! [`native_link`] then runs a second pass. For each native sample whose
//! timestamp is in the window, in time order, it finds the snapshot object
//! whose range contains the returned pointer and whose range also contains
//! the whole requested block (`object.addr <= address` and
//! `address + size <= object.addr + object.shallow_size`,
//! [`native_contains`]). That object is linked to the sample, unless it is
//! already linked by the sweep above (an exact large-object match or an
//! arena/pool link is kept). A later native sample over the same object
//! supersedes an earlier native one, as for the sweep. A native link is the
//! object's own allocation, so it is exact.
//!
//! A large-object sample never shadows a legitimate arena link. Blocks from
//! the system allocator (the `brk` heap, or their own `mmap`) and pymalloc
//! arenas (1 MiB `mmap`s) do not overlap while both are mapped. A sample
//! range overlaps an arena range only when one was unmapped and the
//! address range mapped again for the other, and every arena mapping is
//! recorded (arena events are not sampled), so the later arena sample is
//! the one that covers objects carved from the new arena. Only a recording
//! without arena events (`--events large`) leaves pymalloc objects under a
//! stale large-object sample, and those are then not linked rather than
//! linked wrongly.
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
//!
//! # Per retainer and instance
//!
//! The dominator subtree of `v` is exactly the nodes whose dominator-tree
//! preorder number lies in `tin[v] .. tin[v] + retained_count[v]`. The
//! reachable linked objects are sorted by `tin` once; each listed object's
//! subtree is then a contiguous slice found by two binary searches, and
//! only the linked objects in that slice are visited. Top retainers are
//! disjoint, so all of them together visit each linked object at most once.

use std::collections::{BinaryHeap, HashMap};

use heapspy_alloc::{EventKind, Profile, SampleFlags};
use heapspy_snapshot::{Object, ObjectFlags, Snapshot, SourceKind};

use crate::analysis::Analysis;
use crate::flame::{sanitise, FoldedLine, FxMap, MinWidth, TextTree};
use crate::report::{
    AllocatedAt, AllocatedAtStack, AllocationStack, Allocations, AnalyzeReport, Coverage, Note,
    OverheadInfo, SamplingInfo, StackFrame, TypeQueryReport,
};
use crate::{pct, AnalyzeOptions, Error, QueryOptions, Result};

/// "No sample" in the result of [`latest_covering`].
pub const NO_LINK: u32 = u32::MAX;

/// Most stacks listed in one `allocated_at`.
pub const ALLOCATED_AT_STACKS: usize = 5;

/// Frame text for a sample without Python frames in an allocation flame
/// graph.
pub const NO_STACK_FRAME: &str = "[no Python stack]";

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
         events (arena, pool, large object, native heap); objects allocated before recording \
         started have no stack. Links through arena and pool samples are approximate: they name \
         the most recent growth event that created the memory, not necessarily the call that \
         allocated the object. Links through large-object samples are exact: the object starts \
         where the sampled allocation starts and has its size. Links through native heap samples \
         are exact: the object's block contains the pointer the allocator returned."
            .to_string(),
    )
}

/// The note added when some objects sit on memory of a sampled large
/// allocation they do not match, and are therefore not linked.
pub fn reused_note(objects: u64, bytes: u64) -> Note {
    note(
        "allocations_unlinked_reused",
        format!(
            "{objects} reachable objects ({bytes} bytes) are not linked: the latest sample over \
             their address is a large allocation with another start or size, so that block was \
             freed and the memory reused by an allocation that was not sampled (or resized in \
             place by a realloc that was not sampled). Older samples at the address describe \
             even earlier allocations."
        ),
    )
}

/// Bytes a CPython object's allocation can start before the object
/// (`_PyType_PreHeaderSize`, the same on 3.12, 3.13 and 3.14): 0 without
/// `Py_TPFLAGS_HAVE_GC`, 16 for the GC header, 32 for the GC header plus
/// the managed dict and weakref words (`Py_TPFLAGS_MANAGED_DICT` and
/// `Py_TPFLAGS_MANAGED_WEAKREF` require `Py_TPFLAGS_HAVE_GC`). The snapshot
/// does not record type flags, and a GC object the collector untracked
/// (an atomic tuple) has no `GC_TRACKED` flag, so any of the three is
/// accepted, except 0 for a tracked object.
pub const PRE_HEADERS: [u64; 3] = [0, 16, 32];

/// How far a large-object sample's requested size may be from the object's
/// shallow size (which includes the pre-header, as the request does). On
/// 3.12, 3.13 and 3.14 the request is larger than `shallow_size` by up to
/// one item plus rounding to 8 for instances of variable-size subclasses
/// (`PyType_GenericAlloc` allocates one item more; 4 bytes for an `int`
/// subclass, 8 for a `tuple` subclass) and by a few digits for an `int`
/// normalised after allocation. Everything else measured matched exactly,
/// apart from blocks resized in place by a `realloc` that was not sampled.
pub const SIZE_SLACK: u64 = 16;

/// Whether `obj` can be the allocation of a large-object sample at
/// `address` with requested `size`.
///
/// - Start: `obj.addr - address` is one of [`PRE_HEADERS`] (not 0 for a
///   GC-tracked object).
/// - Size: `size` is within [`SIZE_SLACK`] of `obj.shallow_size`. For a type
///   object only the upper bound applies, because its shallow size also
///   counts the shared-keys table, a separate allocation.
///
/// Objects whose shallow size counts other separate allocations (a `str`
/// with a cached UTF-8 copy, a block shrunk or grown in place by a
/// `realloc` that was not sampled) fail the size check and stay unlinked:
/// a missed exact link, never a wrong one.
pub fn matches_large_object(obj: &Object, address: u64, size: u64) -> bool {
    let Some(pre) = obj.addr.checked_sub(address) else {
        return false;
    };
    let tracked = obj.flags.contains(ObjectFlags::GC_TRACKED);
    if !PRE_HEADERS.contains(&pre) || (pre == 0 && tracked) {
        return false;
    }
    let s = obj.shallow_size;
    let below = obj.flags.contains(ObjectFlags::IS_TYPE) || size.saturating_add(SIZE_SLACK) >= s;
    below && size <= s.saturating_add(SIZE_SLACK)
}

/// Whether the block `[address, address + size)` the allocator returned
/// fits entirely inside `obj`'s range `[obj.addr, obj.addr + shallow_size)`.
/// A native sample's `address` is the returned pointer (inside the block,
/// after the header) and `size` the requested bytes, so a native block is
/// the object this is true of. Requiring the whole requested range to fit,
/// not just the pointer, rejects a smaller object whose memory was reused
/// by a later, unsampled allocation.
pub fn native_contains(obj: &Object, address: u64, size: u64) -> bool {
    obj.addr <= address && address.saturating_add(size) <= obj.addr.saturating_add(obj.shallow_size)
}

/// Link reachable-or-not objects to native heap samples by containment (see
/// the module docs). `link` is the per-object link from the address sweep;
/// native samples were excluded from it, so every object they match is
/// either unlinked or linked by an earlier native sample. `obj_addr` gives
/// an object's address; objects are in address order. Only samples before
/// `cutoff` are used.
fn native_link(snap: &Snapshot, profile: &Profile, link: &mut [u32], cutoff: u64) {
    let n = snap.object_count();
    if n == 0 {
        return;
    }
    // Objects are stored in address order, so a binary search finds the
    // last object starting at or before the returned pointer.
    let obj_addrs: Vec<u64> = (0..n as u32).map(|i| snap.object_addr(i)).collect();
    // Which objects this pass already filled, so a later native sample may
    // supersede an earlier native one but never an arena/pool/large link.
    let mut by_native = vec![false; n];
    for (i, s) in profile.samples().enumerate() {
        if s.kind != EventKind::Native || s.timestamp_ns >= cutoff {
            continue;
        }
        // The last object with addr <= returned pointer.
        let pos = obj_addrs.partition_point(|&a| a <= s.address);
        if pos == 0 {
            continue;
        }
        let v = pos - 1;
        let obj = snap.object(v as u32);
        if !native_contains(&obj, s.address, s.size) {
            continue;
        }
        if link[v] == NO_LINK || by_native[v] {
            link[v] = i as u32;
            by_native[v] = true;
        }
    }
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
const EV_NATIVE: u8 = 1 << 4;
const EV_UNKNOWN: u8 = 1 << 5;

fn event_bit(k: EventKind) -> u8 {
    match k {
        EventKind::Other => EV_OTHER,
        EventKind::Arena => EV_ARENA,
        EventKind::Pool => EV_POOL,
        EventKind::LargeObject => EV_LARGE,
        EventKind::Native => EV_NATIVE,
        EventKind::Unknown(_) => EV_UNKNOWN,
    }
}

/// Event names in a mask, sorted.
fn event_names(mask: u8) -> Vec<String> {
    let mut v: Vec<String> = [
        (EV_ARENA, "arena"),
        (EV_LARGE, "large_object"),
        (EV_NATIVE, "native"),
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
            // Large-object and native samples each describe one allocation,
            // so a link through them is the object's own allocation: exact.
            let exact = if s.kind.is_byte_sampled() {
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

    /// Flame graph frames of group `g`, outermost first.
    fn flame_frames(&self, g: u32) -> Vec<String> {
        let grp = &self.groups[g as usize];
        if grp.frames.is_empty() {
            return vec![NO_STACK_FRAME.to_string()];
        }
        grp.frames
            .iter()
            .rev()
            .map(|&f| {
                let t = &self.frames[f as usize];
                let mut s = format!("{} ({})", t.function, t.location);
                sanitise(&mut s);
                s
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
struct Join<'a, 's> {
    a: &'a Analysis<'s>,
    stacks: Stacks,
    /// Linked sample per object, or [`NO_LINK`]. Empty when nothing was
    /// linked.
    link: Vec<u32>,
    coverage: Coverage,
    notes: Vec<Note>,
    /// Reachable linked objects in dominator-tree preorder.
    by_tin: Vec<u32>,
}

impl<'a, 's> Join<'a, 's> {
    fn new(a: &'a Analysis<'s>, profile: &Profile) -> Result<Join<'a, 's>> {
        let snap = a.snap;
        let mut stacks = Stacks::new(profile)?;
        let mut notes = compatibility(snap, profile);
        let mut coverage = Coverage {
            linked_objects: 0,
            linked_bytes: 0,
            linked_pct: 0.0,
            exact_linked_objects: 0,
            exact_linked_bytes: 0,
            unlinked_reused_objects: 0,
            unlinked_reused_bytes: 0,
        };
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
                    // Native samples link by containment of the returned
                    // pointer in an object, not of the object's start in a
                    // range, so they take no part in this sweep.
                    if s.timestamp_ns < cutoff && s.kind != EventKind::Native {
                        (s.address, s.address.saturating_add(s.size))
                    } else {
                        (0, 0)
                    }
                })
                .collect();
            let n = snap.object_count() as u32;
            let mut link = latest_covering((0..n).map(|i| snap.object_addr(i)), &ranges)?;
            // A large-object sample links only the allocation it describes.
            for (v, l) in link.iter_mut().enumerate() {
                if *l == NO_LINK || stacks.of_sample[*l as usize] & EXACT_BIT == 0 {
                    continue;
                }
                let (start, end) = ranges[*l as usize];
                let obj = snap.object(v as u32);
                if !matches_large_object(&obj, start, end - start) {
                    *l = NO_LINK;
                    if a.reachable(v as u32) {
                        coverage.unlinked_reused_objects += 1;
                        coverage.unlinked_reused_bytes += obj.shallow_size;
                    }
                }
            }
            // Native heap samples link by containment, as a second pass.
            native_link(snap, profile, &mut link, cutoff);
            link
        } else {
            notes.push(not_linked_note());
            Vec::new()
        };
        notes.push(sampled_note());
        if coverage.unlinked_reused_objects > 0 {
            notes.push(reused_note(
                coverage.unlinked_reused_objects,
                coverage.unlinked_reused_bytes,
            ));
        }

        // Linked objects scattered to their preorder slot, then compacted:
        // O(n) instead of a sort by tin.
        let mut by_tin = if link.is_empty() {
            Vec::new()
        } else {
            vec![NO_LINK; a.order.len()]
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
            by_tin[a.tin[v] as usize] = v as u32;
        }
        coverage.linked_pct = pct(coverage.linked_bytes, a.reachable_bytes());
        by_tin.retain(|&v| v != NO_LINK);
        by_tin.shrink_to_fit();
        Ok(Join {
            a,
            stacks,
            link,
            coverage,
            notes,
            by_tin,
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

    /// `allocated_at` of node `v`: the linked objects of its dominator
    /// subtree by stack. `rank_of` gives the `top_stacks` rank of a group.
    fn allocated_at(&self, v: u32, rank_of: &HashMap<u32, u32>) -> AllocatedAt {
        let a = self.a;
        let mut out = AllocatedAt {
            linked_objects: 0,
            linked_bytes: 0,
            exact_linked_bytes: 0,
            stacks: Vec::new(),
            approximate: false,
        };
        if !a.reachable(v) {
            return out;
        }
        let lo = a.tin[v as usize];
        let hi = lo + a.retained_count[v as usize];
        let tin = |x: &u32| a.tin[*x as usize];
        let start = self.by_tin.partition_point(|x| tin(x) < lo);
        let end = self.by_tin.partition_point(|x| tin(x) < hi);
        // group -> (objects, bytes, exact bytes)
        let mut per: FxMap<u32, (u64, u64, u64)> = FxMap::default();
        for &x in &self.by_tin[start..end] {
            let bytes = a.snap.object(x).shallow_size;
            let packed = self.stacks.of_sample[self.link[x as usize] as usize];
            let exact = if packed & EXACT_BIT != 0 { bytes } else { 0 };
            let e = per.entry(packed & !EXACT_BIT).or_default();
            e.0 += 1;
            e.1 += bytes;
            e.2 += exact;
            out.linked_objects += 1;
            out.linked_bytes += bytes;
            out.exact_linked_bytes += exact;
        }
        let mut groups: Vec<(u32, (u64, u64, u64))> = per.into_iter().collect();
        groups.sort_by(|x, y| (y.1 .1, y.1 .0).cmp(&(x.1 .1, x.1 .0)).then(x.0.cmp(&y.0)));
        groups.truncate(ALLOCATED_AT_STACKS);
        for (g, (objects, bytes, exact)) in groups {
            out.approximate |= self.stacks.groups[g as usize].approximate;
            out.stacks.push(AllocatedAtStack {
                frames: self.stacks.stack_frames(g),
                linked_objects: objects,
                linked_bytes: bytes,
                exact_linked_bytes: exact,
                top_stack_rank: rank_of.get(&g).copied(),
            });
        }
        out
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

/// [`crate::analyze`] plus the `allocations` block and per-retainer
/// `allocated_at`. `profile_path` is the profile's path as given by the
/// user.
pub fn analyze_with_allocations(
    snap: &Snapshot,
    path: &str,
    opts: &AnalyzeOptions,
    profile: &Profile,
    profile_path: &str,
) -> Result<AnalyzeReport> {
    let a = Analysis::new(snap)?;
    let (mut report, nodes) = crate::analyze_with(&a, path, opts)?;
    let j = Join::new(&a, profile)?;
    let top = j.top(opts.top);
    let rank_of: HashMap<u32, u32> = top
        .iter()
        .enumerate()
        .map(|(i, &g)| (g, i as u32 + 1))
        .collect();
    for (r, &v) in report.top_retainers.iter_mut().zip(&nodes) {
        r.allocated_at = Some(j.allocated_at(v, &rank_of));
    }
    report.allocations = Some(j.block(profile, profile_path, &top));
    report.notes.extend(j.notes);
    Ok(report)
}

/// [`crate::query_type`] plus per-instance `allocated_at`.
/// `top_stack_rank` is always `null` here, since a type query has no
/// `top_stacks`.
pub fn query_type_with_allocations(
    snap: &Snapshot,
    path: &str,
    type_name: &str,
    opts: &QueryOptions,
    profile: &Profile,
) -> Result<TypeQueryReport> {
    let a = Analysis::new(snap)?;
    let (mut report, nodes) = crate::query::query_type(&a, path, type_name, opts)?;
    let j = Join::new(&a, profile)?;
    let none = HashMap::new();
    for (r, &v) in report.top_instances.iter_mut().zip(&nodes) {
        r.allocated_at = Some(j.allocated_at(v, &none));
    }
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

// ---------------------------------------------------------------- flame graph

/// What an allocation flame graph's widths are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlameWeight {
    /// Estimated bytes allocated (sample weights).
    Estimated,
    /// Shallow bytes of reachable snapshot objects linked to the samples:
    /// where the memory still alive was allocated.
    Linked,
}

/// Folded stacks of an allocation profile, sorted by stack. Frames are
/// Python functions, `qualname (file:line)`, outermost first.
#[derive(Clone, Debug, PartialEq)]
pub struct AllocationFolded {
    pub lines: Vec<FoldedLine>,
    pub weight: FlameWeight,
    /// Sum of all widths: estimated bytes, or linked bytes.
    pub total_bytes: u64,
    pub samples: u64,
    /// Some frames were matched to events by time.
    pub approximate: bool,
    /// The cutoff that was applied, in bytes.
    pub min_bytes: u64,
    /// Compatibility notes ([`FlameWeight::Linked`] only).
    pub notes: Vec<Note>,
}

impl AllocationFolded {
    /// Write `stack bytes` lines.
    pub fn write_to(&self, mut w: impl std::io::Write) -> std::io::Result<()> {
        for l in &self.lines {
            writeln!(w, "{} {}", l.stack, l.bytes)?;
        }
        Ok(())
    }
}

fn min_bytes(min_width: MinWidth, total: u64) -> Result<u64> {
    Ok(match min_width {
        MinWidth::Bytes(b) => b,
        MinWidth::Pct(p) if (0.0..=100.0).contains(&p) => (total as f64 * p / 100.0).ceil() as u64,
        MinWidth::Pct(p) => {
            return Err(Error::InvalidArgument(format!(
                "min percentage must be between 0 and 100, got {p}"
            )))
        }
    })
}

fn fold(
    stacks: &Stacks,
    width: impl Fn(&Group) -> u64,
    min_width: MinWidth,
    samples: u64,
    weight: FlameWeight,
    notes: Vec<Note>,
) -> Result<AllocationFolded> {
    let total: u64 = stacks.groups.iter().map(&width).sum();
    let min = min_bytes(min_width, total)?;
    let mut tt = TextTree::default();
    for (g, grp) in stacks.groups.iter().enumerate() {
        let w = width(grp);
        if w > 0 {
            let frames = stacks.flame_frames(g as u32);
            tt.add_path(frames.iter().map(String::as_str), w);
        }
    }
    let tt = if min > 0 { tt.pruned(min) } else { tt };
    let lines = tt
        .lines()
        .into_iter()
        .map(|(stack, b)| FoldedLine { stack, bytes: b[0] })
        .collect();
    Ok(AllocationFolded {
        lines,
        weight,
        total_bytes: total,
        samples,
        approximate: stacks.approximate,
        min_bytes: min,
        notes,
    })
}

/// Folded stacks of a profile, weighted by estimated bytes allocated.
/// Frames narrower than `min_width` (a percentage is of the total
/// estimated bytes) are folded into an `[other]` sibling.
pub fn folded_allocations(profile: &Profile, min_width: MinWidth) -> Result<AllocationFolded> {
    let stacks = Stacks::new(profile)?;
    fold(
        &stacks,
        |g| g.estimated,
        min_width,
        profile.sample_count(),
        FlameWeight::Estimated,
        Vec::new(),
    )
}

/// Folded stacks of a profile, weighted by the shallow bytes of the
/// reachable objects of `snap` linked to each stack's samples.
pub fn folded_allocations_linked(
    snap: &Snapshot,
    profile: &Profile,
    min_width: MinWidth,
) -> Result<AllocationFolded> {
    let a = Analysis::new(snap)?;
    let j = Join::new(&a, profile)?;
    let notes: Vec<Note> = j
        .notes
        .iter()
        .filter(|n| n.code != "allocations_sampled")
        .cloned()
        .collect();
    fold(
        &j.stacks,
        |g| g.linked_bytes,
        min_width,
        profile.sample_count(),
        FlameWeight::Linked,
        notes,
    )
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
            event_names(EV_POOL | EV_ARENA | EV_LARGE | EV_NATIVE),
            ["arena", "large_object", "native", "pool"]
        );
        assert!(event_names(0).is_empty());
    }

    #[test]
    fn native_contains_checks_the_whole_block() {
        let obj = |addr, size| {
            let mut b = SnapshotBuilder::new();
            let t = b.ty("builtins", "bytes");
            b.object(addr, t, size).untracked();
            let s = b.build().unwrap();
            s.object(0)
        };
        // Block [0x10000, 0x11000); the allocator returned 0x10040.
        let block = obj(0x1_0000, 0x1000);
        assert!(native_contains(&block, 0x1_0040, 0xf00));
        // The pointer is inside but the requested range runs past the block:
        // a smaller object whose memory was reused.
        assert!(!native_contains(&block, 0x1_0040, 0x1000));
        // Pointer before the block.
        assert!(!native_contains(&block, 0x0_ffff, 8));
        // Exactly the block (header offset 0, full size).
        assert!(native_contains(&block, 0x1_0000, 0x1000));
    }

    /// A profile of only native samples, each `(timestamp_ns, returned
    /// pointer, requested size)`, with a header that matches [`snap`].
    fn native_profile(samples: &[(u64, u64, u64)]) -> Profile {
        let mut b = ProfileBuilder::new();
        b.info_mut().pid = 42;
        b.info_mut().python = PythonVersion::new(3, 12, 0);
        b.info_mut().start_ns = 100 * NS_PER_S;
        b.info_mut().sampling.events = heapspy_alloc::EventKinds::of(&[EventKind::Native]);
        b.info_mut().sampling.native_min_size = 4096;
        let code = b.code_with_lines(0x7f00_9000, "pin_buffer", "shop/native.py", 7, &[(16, 8)]);
        for &(ts, addr, size) in samples {
            b.sample(EventKind::Native, addr, size)
                .at(ts)
                .native_return(0x7ffa_0000_1000)
                .frame(code, 0);
        }
        b.build().unwrap()
    }

    /// A snapshot (pid 42, captured_at 200) with each object
    /// `(addr, shallow_size)`, untracked bytes blocks in address order.
    fn blocks(objs: &[(u64, u64)]) -> Snapshot {
        let mut b = SnapshotBuilder::new();
        b.info_mut().source.reference = "42".into();
        b.info_mut().captured_at = 200;
        let bytes = b.ty("builtins", "bytes");
        for &(addr, size) in objs {
            b.object(addr, bytes, size).untracked();
        }
        b.build().unwrap()
    }

    #[test]
    fn native_links_block_that_contains_the_returned_pointer() {
        let snap = blocks(&[(0x1_0000, 0x1000), (0x2_0000, 1 << 20)]);
        // One native sample: a 1 MiB request whose pointer is 64 bytes into
        // the big block.
        let p = native_profile(&[(100 * NS_PER_S, 0x2_0040, (1 << 20) - 0x40)]);
        let links = object_links(&snap, &p).unwrap();
        // Object 0 (the small block) is not linked; object 1 (the big block)
        // links to sample 0.
        assert_eq!(links, [NO_LINK, 0]);
    }

    #[test]
    fn native_does_not_link_a_block_the_request_overruns() {
        let snap = blocks(&[(0x1_0000, 0x1000)]);
        // The pointer is inside, but the request runs past the block end:
        // reused memory, not this allocation.
        let p = native_profile(&[(100 * NS_PER_S, 0x1_0040, 0x1000)]);
        assert_eq!(object_links(&snap, &p).unwrap(), [NO_LINK]);
    }

    #[test]
    fn latest_native_sample_over_a_block_wins() {
        let snap = blocks(&[(0x2_0000, 1 << 20)]);
        let p = native_profile(&[
            (100 * NS_PER_S, 0x2_0040, 0x1000),
            (101 * NS_PER_S, 0x2_0080, 0x2000),
        ]);
        // Both contain the block's pointer; the later sample (index 1) wins.
        assert_eq!(object_links(&snap, &p).unwrap(), [1]);
    }

    #[test]
    fn native_samples_after_the_snapshot_do_not_link() {
        let snap = blocks(&[(0x2_0000, 1 << 20)]);
        // captured_at is 200 s; a sample at 250 s is past the window.
        let p = native_profile(&[(250 * NS_PER_S, 0x2_0040, 0x1000)]);
        assert_eq!(object_links(&snap, &p).unwrap(), [NO_LINK]);
    }

    #[test]
    fn native_link_is_counted_exact() {
        let snap = blocks(&[(0x2_0000, 1 << 20)]);
        let p = native_profile(&[(100 * NS_PER_S, 0x2_0040, 0x800)]);
        let a = Analysis::new(&snap).unwrap();
        let j = Join::new(&a, &p).unwrap();
        // The block is unreachable (no roots), so coverage stays zero, but
        // the sample's group is still marked exact.
        assert!(j.stacks.of_sample.iter().any(|&s| s & EXACT_BIT != 0));
        assert_eq!(j.stacks.of_sample.len(), 1);
    }
}
