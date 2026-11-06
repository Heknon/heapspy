//! Joining allocation profiles with snapshots, on synthetic data built with
//! `SnapshotBuilder` and `ProfileBuilder`.

use heapspy_alloc::{CodeId, EventKind, Profile, ProfileBuilder, SampleFlags};
use heapspy_analyzer::allocations::{
    analyze_with_allocations, folded_allocations, folded_allocations_linked, object_links,
    query_type_with_allocations, FlameWeight, NO_LINK, NO_STACK_FRAME, SIZE_SLACK,
};
use heapspy_analyzer::report::{AnalyzeReport, Note, TypeQueryReport};
use heapspy_analyzer::{AnalyzeOptions, MinWidth, QueryOptions};
use heapspy_snapshot::{ObjectFlags, RootKind, Snapshot, SnapshotBuilder, TypeId};

const KIB: u64 = 1024;
const MIB: u64 = 1 << 20;
const ARENA: u64 = 0x7f10_0000_0000;

fn codes(n: &[Note]) -> Vec<&str> {
    n.iter().map(|n| n.code.as_str()).collect()
}

/// How a CACHE entry is recorded in the snapshot.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// `bytes`: no GC header, so its allocation starts at the object.
    Bytes,
    /// A GC-tracked `tuple`: its allocation starts 16 bytes before it.
    Tuple,
    /// A type object (GC-tracked, flag `IS_TYPE`).
    Type,
}

/// A snapshot builder for pid 4242 (matching [`profile`]) with a module
/// `app` whose `CACHE` dict is at 0x3000.
struct Snap {
    b: SnapshotBuilder,
    bytes: TypeId,
    tuple: TypeId,
    ty: TypeId,
    entries: Vec<(u64, u64, Kind)>,
    extra: Vec<(u64, u64, Kind)>,
}

impl Snap {
    fn new() -> Snap {
        let mut b = SnapshotBuilder::new();
        b.info_mut().source.reference = "4242".into();
        b.info_mut().captured_at = 2000;
        let bytes = b.ty("builtins", "bytes");
        let tuple = b.ty("builtins", "tuple");
        let ty = b.ty("builtins", "type");
        Snap {
            b,
            bytes,
            tuple,
            ty,
            entries: Vec::new(),
            extra: Vec::new(),
        }
    }

    /// A `bytes` object of `size` at `addr` held by CACHE.
    fn entry(&mut self, addr: u64, size: u64) -> &mut Self {
        self.entries.push((addr, size, Kind::Bytes));
        self
    }

    /// An object of another kind held by CACHE; `size` includes the GC
    /// header, as the walker's shallow sizes do.
    fn entry_of(&mut self, kind: Kind, addr: u64, size: u64) -> &mut Self {
        self.entries.push((addr, size, kind));
        self
    }

    /// An unreachable `bytes` object.
    fn garbage(&mut self, addr: u64, size: u64) -> &mut Self {
        self.extra.push((addr, size, Kind::Bytes));
        self
    }

    fn build(&self) -> Snapshot {
        let mut b = self.b.clone();
        let m = b.ty("builtins", "module");
        let d = b.ty("builtins", "dict");
        b.object(0x1000, m, 72).attr(0x2000, "__dict__");
        b.object(0x2000, d, 1000).dict_value(0x3000, "'CACHE'");
        let c = b.object(0x3000, d, 200);
        for (i, &(a, _, _)) in self.entries.iter().enumerate() {
            c.dict_value(a, &format!("'k{i}'"));
        }
        for &(a, s, k) in self.entries.iter().chain(&self.extra) {
            match k {
                Kind::Bytes => {
                    b.object(a, self.bytes, s).untracked();
                }
                Kind::Tuple => {
                    b.object(a, self.tuple, s);
                }
                Kind::Type => {
                    b.object(a, self.ty, s)
                        .flags(ObjectFlags::GC_TRACKED | ObjectFlags::IS_TYPE);
                }
            }
        }
        b.root(0x1000, RootKind::ModuleDict, "sys.modules['app']");
        b.build().unwrap()
    }
}

/// A profile builder for pid 4242 on 3.12.0, recorded from second 1000 to
/// 1060, with three code objects: `fill` (app.py), `load` (app.py) and
/// `main` (main.py).
struct Prof {
    b: ProfileBuilder,
    fill: CodeId,
    load: CodeId,
    main: CodeId,
}

fn profile() -> Prof {
    let mut b = ProfileBuilder::new();
    b.info_mut().pid = 4242;
    b.info_mut().start_ns = 1000 * 1_000_000_000;
    b.info_mut().end_ns = 1060 * 1_000_000_000;
    let fill = b.code_with_lines(0x7f00_1000, "fill", "app.py", 3, &[(16, 4), (16, 5)]);
    let load = b.code_with_lines(0x7f00_2000, "load", "app.py", 10, &[(32, 11)]);
    let main = b.code_with_lines(0x7f00_3000, "main", "main.py", 1, &[(64, 2)]);
    Prof {
        b,
        fill,
        load,
        main,
    }
}

impl Prof {
    /// A sample allocated by `fill <- main`.
    fn by_fill(&mut self, kind: EventKind, addr: u64, size: u64) {
        let (f, m) = (self.fill, self.main);
        self.b.sample(kind, addr, size).frame(f, 2).frame(m, 0);
    }
    /// A sample allocated by `load <- main`.
    fn by_load(&mut self, kind: EventKind, addr: u64, size: u64) {
        let (l, m) = (self.load, self.main);
        self.b.sample(kind, addr, size).frame(l, 0).frame(m, 0);
    }
    fn build(&self) -> Profile {
        self.b.build().unwrap()
    }
}

fn analyze(s: &Snapshot, p: &Profile) -> AnalyzeReport {
    analyze_with_allocations(s, "a.hpy", &AnalyzeOptions::default(), p, "a.hpya").unwrap()
}

fn query(s: &Snapshot, p: &Profile) -> TypeQueryReport {
    query_type_with_allocations(s, "a.hpy", "bytes", &QueryOptions::default(), p).unwrap()
}

/// Object index by address.
fn links_by_addr(s: &Snapshot, p: &Profile) -> Vec<(u64, u32)> {
    let l = object_links(s, p).unwrap();
    (0..s.object_count() as u32)
        .map(|i| (s.object_addr(i), l[i as usize]))
        .collect()
}

fn link_of(s: &Snapshot, p: &Profile, addr: u64) -> u32 {
    links_by_addr(s, p)
        .into_iter()
        .find(|&(a, _)| a == addr)
        .unwrap()
        .1
}

#[test]
fn large_object_link_is_exact() {
    // A bytes object has no GC header: its allocation starts at the object.
    let s = Snap::new().entry(0x10_0000, 4096).build();
    let mut p = profile();
    p.by_fill(EventKind::LargeObject, 0x10_0000, 4096);
    let p = p.build();
    assert_eq!(link_of(&s, &p, 0x10_0000), 0);
    assert_eq!(link_of(&s, &p, 0x3000), NO_LINK);

    let r = analyze(&s, &p);
    let a = r.allocations.as_ref().unwrap();
    assert_eq!(a.coverage.linked_objects, 1);
    assert_eq!(a.coverage.linked_bytes, 4096);
    assert_eq!(a.coverage.exact_linked_objects, 1);
    assert_eq!(a.coverage.exact_linked_bytes, 4096);
    let t = &a.top_stacks[0];
    assert_eq!(t.linked_bytes, 4096);
    assert_eq!(t.exact_linked_bytes, 4096);
    assert_eq!(t.events, ["large_object"]);
    assert_eq!(t.frames[0].function, "fill");
    assert_eq!(t.frames[0].location, "app.py:4");
    assert_eq!(t.frames[1].location, "main.py:2");
    assert!(!t.approximate && !a.approximate);
    assert_eq!(a.coverage.unlinked_reused_objects, 0);
    assert_eq!(a.coverage.unlinked_reused_bytes, 0);
    assert_eq!(codes(&r.notes).last(), Some(&"allocations_sampled"));
    assert!(!codes(&r.notes).contains(&"allocations_not_linked"));
    assert!(!codes(&r.notes).contains(&"allocations_unlinked_reused"));
}

#[test]
fn gc_header_is_part_of_the_allocation() {
    // A GC object's allocation starts at its GC header, 16 bytes before the
    // object (32 with the managed dict and weakref words); the shallow size
    // counts the header, as the requested size does.
    let s = Snap::new()
        .entry_of(Kind::Tuple, 0x10_0010, 4112)
        .entry_of(Kind::Tuple, 0x20_0020, 4128)
        .build();
    let mut p = profile();
    p.by_fill(EventKind::LargeObject, 0x10_0000, 4112);
    p.by_fill(EventKind::LargeObject, 0x20_0000, 4128);
    let p = p.build();
    assert_eq!(link_of(&s, &p, 0x10_0010), 0);
    assert_eq!(link_of(&s, &p, 0x20_0020), 1);
    let a = analyze(&s, &p).allocations.unwrap();
    assert_eq!(a.coverage.exact_linked_objects, 2);
    assert_eq!(a.coverage.exact_linked_bytes, 4112 + 4128);
    assert_eq!(a.coverage.unlinked_reused_objects, 0);
}

#[test]
fn size_tolerance() {
    // `PyType_GenericAlloc` asks for one item more than the object holds,
    // rounded to 8: an int subclass 4 to 8 bytes more, a tuple subclass 8.
    let base = 0x100_0000u64;
    let slack = SIZE_SLACK as i64;
    let deltas: [i64; 6] = [0, 8, slack, -slack, slack + 1, -slack - 1];
    let mut s = Snap::new();
    let mut p = profile();
    for (i, d) in deltas.iter().enumerate() {
        let a = base + i as u64 * 0x1_0000;
        s.entry(a, 5000);
        p.by_fill(EventKind::LargeObject, a, (5000 + d) as u64);
    }
    let (s, p) = (s.build(), p.build());
    let got: Vec<bool> = (0..deltas.len() as u64)
        .map(|i| link_of(&s, &p, base + i * 0x1_0000) != NO_LINK)
        .collect();
    assert_eq!(got, [true, true, true, true, false, false]);
    let a = analyze(&s, &p).allocations.unwrap();
    assert_eq!(a.coverage.unlinked_reused_objects, 2);
    assert_eq!(a.coverage.unlinked_reused_bytes, 10_000);
}

#[test]
fn type_objects_may_count_more_than_their_allocation() {
    // A heap type's shallow size also counts its shared-keys table, which
    // is a separate allocation: only the upper bound applies.
    let s = Snap::new()
        .entry_of(Kind::Type, 0x10_0010, 1700)
        .entry_of(Kind::Type, 0x20_0010, 1000)
        .build();
    let mut p = profile();
    p.by_fill(EventKind::LargeObject, 0x10_0000, 1000);
    p.by_fill(EventKind::LargeObject, 0x20_0000, 1700);
    let p = p.build();
    assert_eq!(link_of(&s, &p, 0x10_0010), 0);
    assert_eq!(link_of(&s, &p, 0x20_0010), NO_LINK);
}

/// The reproduction: a large block sampled and freed (`render_page`), and
/// its memory reused by an unsampled allocation of another size (a
/// `Session` blob) that the snapshot then sees.
#[test]
fn reused_address_of_another_size_is_not_linked() {
    let s = Snap::new()
        .entry(0x10_0000, 8225)
        .entry(0x20_0000, 8225)
        .build();
    let mut p = profile();
    p.by_fill(EventKind::LargeObject, 0x10_0000, 20_033);
    // Older samples describe even earlier allocations: an older sample of
    // the right size does not take over.
    p.by_load(EventKind::LargeObject, 0x20_0000, 8225);
    p.by_fill(EventKind::LargeObject, 0x20_0000, 20_033);
    let p = p.build();
    assert_eq!(link_of(&s, &p, 0x10_0000), NO_LINK);
    assert_eq!(link_of(&s, &p, 0x20_0000), NO_LINK);

    let r = analyze(&s, &p);
    let a = r.allocations.as_ref().unwrap();
    assert_eq!(a.coverage.linked_objects, 0);
    assert_eq!(a.coverage.exact_linked_bytes, 0);
    assert_eq!(a.coverage.unlinked_reused_objects, 2);
    assert_eq!(a.coverage.unlinked_reused_bytes, 2 * 8225);
    for t in &a.top_stacks {
        assert_eq!(t.linked_bytes, 0, "{t:?}");
    }
    let at = r.top_retainers[0].allocated_at.as_ref().unwrap();
    assert_eq!(at.linked_objects, 0);
    assert!(at.stacks.is_empty());
    let n = r
        .notes
        .iter()
        .find(|n| n.code == "allocations_unlinked_reused")
        .expect("allocations_unlinked_reused note");
    assert!(
        n.message.starts_with("2 reachable objects (16450 bytes)"),
        "{}",
        n.message
    );
    // Unreachable objects are not counted.
    let s = Snap::new().garbage(0x10_0000, 8225).build();
    let r = analyze(&s, &p);
    assert_eq!(
        r.allocations
            .as_ref()
            .unwrap()
            .coverage
            .unlinked_reused_objects,
        0
    );
    assert!(!codes(&r.notes).contains(&"allocations_unlinked_reused"));
}

#[test]
fn start_offset_mismatch_is_not_linked() {
    let s = Snap::new()
        // Inside the block, not at a pre-header offset.
        .entry(0x10_0008, 4096)
        .entry(0x20_0030, 4096)
        .entry(0x30_0040, 4096)
        // A GC-tracked object has a GC header, so it cannot start at the
        // block's start.
        .entry_of(Kind::Tuple, 0x40_0000, 4096)
        .build();
    let mut p = profile();
    p.by_fill(EventKind::LargeObject, 0x10_0000, 4096);
    p.by_fill(EventKind::LargeObject, 0x20_0000, 4096);
    p.by_fill(EventKind::LargeObject, 0x30_0000, 4096);
    p.by_fill(EventKind::LargeObject, 0x40_0000, 4096);
    let p = p.build();
    for a in [0x10_0008, 0x20_0030, 0x30_0040, 0x40_0000] {
        assert_eq!(link_of(&s, &p, a), NO_LINK, "{a:#x}");
    }
    let a = analyze(&s, &p).allocations.unwrap();
    assert_eq!(a.coverage.unlinked_reused_objects, 4);
}

#[test]
fn reuse_sampled_again_links_to_the_later_sample() {
    // render_page's block, freed; then the blob's own allocation at the
    // same address, sampled.
    let s = Snap::new().entry(0x10_0000, 8225).build();
    let mut p = profile();
    p.by_fill(EventKind::LargeObject, 0x10_0000, 20_033);
    p.by_load(EventKind::LargeObject, 0x10_0000, 8225);
    let p = p.build();
    assert_eq!(link_of(&s, &p, 0x10_0000), 1);
    let a = analyze(&s, &p).allocations.unwrap();
    assert_eq!(a.coverage.exact_linked_bytes, 8225);
    assert_eq!(a.coverage.unlinked_reused_objects, 0);
    let by = |f: &str| {
        a.top_stacks
            .iter()
            .find(|t| t.frames[0].function == f)
            .unwrap()
            .clone()
    };
    assert_eq!(by("fill").linked_bytes, 0);
    assert_eq!(by("load").exact_linked_bytes, 8225);
}

#[test]
fn arena_links_ignore_object_sizes() {
    // Objects carved from an arena link to it whatever their size and
    // offset; no large-object rule applies.
    let s = Snap::new()
        .entry(ARENA + 0x30, 48)
        .entry_of(Kind::Tuple, ARENA + 0x4040, 2440)
        .build();
    let mut p = profile();
    // A large block whose memory was unmapped, then the arena mapped there.
    p.by_load(EventKind::LargeObject, ARENA, 300_000);
    p.by_fill(EventKind::Arena, ARENA, MIB);
    let p = p.build();
    assert_eq!(link_of(&s, &p, ARENA + 0x30), 1);
    assert_eq!(link_of(&s, &p, ARENA + 0x4040), 1);
    let a = analyze(&s, &p).allocations.unwrap();
    assert_eq!(a.coverage.linked_objects, 2);
    assert_eq!(a.coverage.exact_linked_objects, 0);
    assert_eq!(a.coverage.unlinked_reused_objects, 0);
}

#[test]
fn pool_and_arena_links_are_approximate() {
    let s = Snap::new()
        .entry(ARENA + 0x100, 64) // in the arena, outside the pool
        .entry(ARENA + 16 * KIB + 0x40, 64) // in the pool
        .entry(ARENA + MIB, 64) // one past the arena
        .build();
    let mut p = profile();
    p.by_load(EventKind::Arena, ARENA, MIB);
    p.by_fill(EventKind::Pool, ARENA + 16 * KIB, 16 * KIB);
    let p = p.build();
    assert_eq!(link_of(&s, &p, ARENA + 0x100), 0);
    assert_eq!(link_of(&s, &p, ARENA + 16 * KIB + 0x40), 1);
    assert_eq!(link_of(&s, &p, ARENA + MIB), NO_LINK);

    let a = analyze(&s, &p).allocations.unwrap();
    assert_eq!(a.coverage.linked_objects, 2);
    assert_eq!(a.coverage.exact_linked_objects, 0);
    assert_eq!(a.coverage.exact_linked_bytes, 0);
    // The arena stack has the larger estimate.
    assert_eq!(a.top_stacks[0].frames[0].function, "load");
    assert_eq!(a.top_stacks[0].estimated_bytes, MIB);
    assert_eq!(a.top_stacks[0].linked_bytes, 64);
    assert_eq!(a.top_stacks[0].exact_linked_bytes, 0);
    assert_eq!(a.top_stacks[1].events, ["pool"]);
    assert_eq!(a.estimated_bytes, MIB + 16 * KIB);
    // `approximate` keeps its schema meaning: frames matched by time.
    assert!(!a.approximate);
}

#[test]
fn later_sample_supersedes_earlier() {
    let s = Snap::new()
        .entry(0x20_0000, 1000)
        .entry(ARENA + 0x80, 600)
        .entry(ARENA + 2 * MIB + 0x80, 64)
        .build();
    let mut p = profile();
    // The same block allocated twice: the second one is the live one.
    p.by_fill(EventKind::LargeObject, 0x20_0000, 1000);
    p.by_load(EventKind::LargeObject, 0x20_0000, 1000);
    // An arena mapped (then unmapped), a large block there later: the
    // block wins.
    p.by_fill(EventKind::Arena, ARENA, MIB);
    p.by_load(EventKind::LargeObject, ARENA + 0x80, 600);
    // A large block, then an arena mapped over the same memory: the arena
    // wins, whatever the block's size.
    p.by_load(EventKind::LargeObject, ARENA + 2 * MIB + 0x70, 200);
    p.by_fill(EventKind::Arena, ARENA + 2 * MIB, MIB);
    let p = p.build();
    assert_eq!(link_of(&s, &p, 0x20_0000), 1);
    assert_eq!(link_of(&s, &p, ARENA + 0x80), 3);
    assert_eq!(link_of(&s, &p, ARENA + 2 * MIB + 0x80), 5);

    let a = analyze(&s, &p).allocations.unwrap();
    let load = a
        .top_stacks
        .iter()
        .find(|t| t.frames[0].function == "load")
        .unwrap();
    assert_eq!(load.linked_bytes, 1000 + 600);
    assert_eq!(load.exact_linked_bytes, 1000 + 600);
    let fill = a
        .top_stacks
        .iter()
        .find(|t| t.frames[0].function == "fill")
        .unwrap();
    assert_eq!(fill.linked_bytes, 64);
    assert_eq!(fill.exact_linked_bytes, 0);
}

#[test]
fn objects_without_a_covering_sample() {
    let s = Snap::new().entry(0x50_0000, 100).build();
    let mut p = profile();
    // Ends exactly at the object, and starts just past it.
    p.by_fill(EventKind::LargeObject, 0x4f_ff00, 0x100);
    p.by_fill(EventKind::LargeObject, 0x50_0001, 0x100);
    // Zero-size samples cover nothing.
    p.by_fill(EventKind::LargeObject, 0x50_0000, 0);
    let p = p.build();
    assert!(object_links(&s, &p).unwrap().iter().all(|&l| l == NO_LINK));
    let r = analyze(&s, &p);
    let a = r.allocations.as_ref().unwrap();
    assert_eq!(a.coverage.linked_objects, 0);
    assert_eq!(a.coverage.linked_pct, 0.0);
    assert_eq!(a.top_stacks.len(), 1);
    assert_eq!(a.top_stacks[0].samples, 3);
    for t in &r.top_retainers {
        let at = t.allocated_at.as_ref().unwrap();
        assert_eq!(at.linked_objects, 0);
        assert!(at.stacks.is_empty());
    }
}

/// CACHE holds six blocks: four allocated by `fill`, two by `load`.
fn two_stack_cache() -> (Snapshot, Profile) {
    let mut s = Snap::new();
    let mut p = profile();
    for i in 0..6u64 {
        let addr = 0x100_0000 + i * 0x1_0000;
        s.entry(addr, 5000);
        if i < 4 {
            p.by_fill(EventKind::LargeObject, addr, 5000);
        } else {
            p.by_load(EventKind::LargeObject, addr, 5000);
        }
    }
    (s.build(), p.build())
}

#[test]
fn allocated_at_splits_a_cache_by_stack() {
    let (s, p) = two_stack_cache();
    let r = analyze(&s, &p);
    let cache = &r.top_retainers[0];
    assert_eq!(cache.address.0, 0x3000);
    let at = cache.allocated_at.as_ref().unwrap();
    assert_eq!(at.linked_objects, 6);
    assert_eq!(at.linked_bytes, 30_000);
    assert_eq!(at.exact_linked_bytes, 30_000);
    assert_eq!(at.stacks.len(), 2);
    assert_eq!(at.stacks[0].frames[0].function, "fill");
    assert_eq!(at.stacks[0].linked_objects, 4);
    assert_eq!(at.stacks[0].linked_bytes, 20_000);
    assert_eq!(at.stacks[1].frames[0].function, "load");
    assert_eq!(at.stacks[1].linked_objects, 2);
    assert_eq!(at.stacks[1].linked_bytes, 10_000);
    let sum: u64 = at.stacks.iter().map(|s| s.linked_bytes).sum();
    assert_eq!(sum, at.linked_bytes);
    assert!(!at.approximate);

    // The same on a type query, per instance.
    let q = query(&s, &p);
    assert_eq!(q.top_instances.len(), 6);
    let fills = q
        .top_instances
        .iter()
        .filter(|i| {
            let at = i.allocated_at.as_ref().unwrap();
            at.stacks.len() == 1 && at.stacks[0].frames[0].function == "fill"
        })
        .count();
    assert_eq!(fills, 4);
    for i in &q.top_instances {
        let at = i.allocated_at.as_ref().unwrap();
        assert_eq!(at.linked_objects, 1);
        assert_eq!(at.stacks[0].top_stack_rank, None);
    }
    assert!(codes(&q.notes).contains(&"allocations_sampled"));
}

#[test]
fn top_stack_rank_points_into_top_stacks() {
    let (s, p) = two_stack_cache();
    let r = analyze(&s, &p);
    let a = r.allocations.as_ref().unwrap();
    let at = r.top_retainers[0].allocated_at.as_ref().unwrap();
    for st in &at.stacks {
        let rank = st.top_stack_rank.unwrap();
        assert_eq!(a.top_stacks[rank as usize - 1].frames, st.frames);
    }
    assert_eq!(at.stacks[0].top_stack_rank, Some(1));
    assert_eq!(at.stacks[1].top_stack_rank, Some(2));

    // With --top 1 the second stack is not listed, so it has no rank.
    let r =
        analyze_with_allocations(&s, "a.hpy", &AnalyzeOptions { top: 1 }, &p, "a.hpya").unwrap();
    assert_eq!(r.allocations.as_ref().unwrap().top_stacks.len(), 1);
    let at = r.top_retainers[0].allocated_at.as_ref().unwrap();
    assert_eq!(at.stacks[0].top_stack_rank, Some(1));
    assert_eq!(at.stacks[1].top_stack_rank, None);
}

#[test]
fn coverage_counts_reachable_objects_only() {
    let mut p = profile();
    p.by_fill(EventKind::Arena, ARENA, MIB);
    let p = p.build();
    let s = Snap::new()
        .entry(ARENA + 0x10, 1000)
        .entry(ARENA + 0x1000, 3000)
        .garbage(ARENA + 0x2000, 7777)
        .build();
    // The garbage object is linked, but not counted.
    assert_eq!(link_of(&s, &p, ARENA + 0x2000), 0);
    let r = analyze(&s, &p);
    let a = r.allocations.as_ref().unwrap();
    assert_eq!(a.coverage.linked_objects, 2);
    assert_eq!(a.coverage.linked_bytes, 4000);
    let reachable = r.totals.reachable_bytes;
    assert_eq!(reachable, 72 + 1000 + 200 + 4000);
    let want = (4000.0 / reachable as f64 * 10_000.0).round() / 100.0;
    assert_eq!(a.coverage.linked_pct, want);
    assert_eq!(a.top_stacks[0].linked_bytes, 4000);
}

#[test]
fn header_fields_are_reported() {
    let mut p = profile();
    {
        let i = p.b.info_mut();
        i.truncated = true;
        i.overhead.samples_dropped = 3;
        i.overhead.probe_hits = 99;
        i.overhead.total_pause_ns = 1234;
        i.sampling.byte_interval = 4096;
        i.sampling.max_frames = 16;
        i.mechanisms = heapspy_alloc::Mechanisms::of(&[
            heapspy_alloc::Mechanism::Etw,
            heapspy_alloc::Mechanism::Debugger,
        ]);
    }
    let (f, m) = (p.fill, p.main);
    p.b.sample(EventKind::LargeObject, 0x10_0000, 8192)
        .weight(9000)
        .flags(SampleFlags::APPROXIMATE_FRAMES)
        .approximate_frame(f, 2)
        .frame(m, 0);
    p.b.sample(EventKind::Arena, ARENA, MIB).at(5);
    let p = p.build();
    let s = Snap::new().build();
    let a = analyze(&s, &p).allocations.unwrap();
    assert_eq!(a.path, "a.hpya");
    assert_eq!(a.pid, 4242);
    assert_eq!(a.python_version, "3.12.0");
    assert_eq!(a.started_at, 1000);
    assert_eq!(a.duration_ms, 60_000);
    assert_eq!(a.mechanisms, ["etw", "debugger"]);
    assert_eq!(a.sampling.events, ["arena", "large_object"]);
    assert_eq!(a.sampling.byte_interval, 4096);
    assert_eq!(a.sampling.max_frames, 16);
    assert_eq!(a.overhead.samples_taken, 2);
    assert_eq!(a.overhead.samples_dropped, 3);
    assert_eq!(a.overhead.probe_hits, 99);
    assert_eq!(a.overhead.total_pause_ns, 1234);
    assert!(a.truncated);
    assert!(a.approximate);
    assert_eq!(a.samples, 2);
    assert_eq!(a.estimated_bytes, 9000 + MIB);
    // The arena sample has no frames.
    assert_eq!(a.top_stacks[0].frames, []);
    assert!(!a.top_stacks[0].approximate);
    let t = &a.top_stacks[1];
    assert!(t.approximate);
    assert!(t.frames[0].approximate);
    assert!(!t.frames[1].approximate);
}

#[test]
fn mismatched_profiles_are_not_linked() {
    let s = Snap::new().entry(0x10_0000, 8192).build();
    for (what, code) in [
        ("pid", "allocations_pid_mismatch"),
        ("after", "allocations_after_snapshot"),
    ] {
        let mut p = profile();
        match what {
            "pid" => p.b.info_mut().pid = 7,
            _ => p.b.info_mut().start_ns = 3000 * 1_000_000_000,
        }
        p.by_fill(EventKind::LargeObject, 0x10_0000, 8192);
        let p = p.build();
        let r = analyze(&s, &p);
        let c = codes(&r.notes);
        assert!(c.contains(&code), "{c:?}");
        assert!(c.contains(&"allocations_not_linked"), "{c:?}");
        let a = r.allocations.as_ref().unwrap();
        assert_eq!(a.coverage.linked_objects, 0);
        assert_eq!(a.top_stacks.len(), 1);
        assert_eq!(a.top_stacks[0].linked_bytes, 0);
        assert!(object_links(&s, &p).unwrap().iter().all(|&l| l == NO_LINK));
        let q = query(&s, &p);
        assert!(codes(&q.notes).contains(&code));
    }
}

#[test]
fn samples_after_the_snapshot_are_not_linked() {
    let s = Snap::new().entry(0x10_0000, 4096).build();
    let mut p = profile();
    p.by_fill(EventKind::LargeObject, 0x10_0000, 4096);
    // Taken after the snapshot (captured at second 2000): would supersede,
    // and would not match.
    let (l, m) = (p.load, p.main);
    p.b.sample(EventKind::LargeObject, 0x10_0000, 8192)
        .at(2001 * 1_000_000_000)
        .frame(l, 0)
        .frame(m, 0);
    let p = p.build();
    assert_eq!(link_of(&s, &p, 0x10_0000), 0);
}

#[test]
fn reports_round_trip_through_json() {
    let (s, p) = two_stack_cache();
    let r = analyze(&s, &p);
    let text = serde_json::to_string(&r).unwrap();
    let back: AnalyzeReport = serde_json::from_str(&text).unwrap();
    assert_eq!(back, r);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        v["allocations"]["top_stacks"][0]["frames"][0]["location"],
        "app.py:4"
    );
    assert!(v["top_retainers"][0]["allocated_at"]["stacks"][0]["top_stack_rank"].is_u64());

    let q = query(&s, &p);
    let back: TypeQueryReport = serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
    assert_eq!(back, q);
}

// ---------------------------------------------------------------- flame graph

#[test]
fn allocation_folded_stacks() {
    let mut p = profile();
    p.by_fill(EventKind::LargeObject, 0x10_0000, 3000);
    p.by_fill(EventKind::LargeObject, 0x20_0000, 2000);
    p.by_load(EventKind::Arena, ARENA, MIB);
    p.b.sample(EventKind::LargeObject, 0x30_0000, 700);
    let p = p.build();
    let f = folded_allocations(&p, MinWidth::Bytes(0)).unwrap();
    assert_eq!(f.weight, FlameWeight::Estimated);
    assert_eq!(f.total_bytes, 5000 + MIB + 700);
    assert_eq!(f.lines.iter().map(|l| l.bytes).sum::<u64>(), f.total_bytes);
    let lines: Vec<(&str, u64)> = f
        .lines
        .iter()
        .map(|l| (l.stack.as_str(), l.bytes))
        .collect();
    // Outermost frame first; sorted by stack.
    assert_eq!(
        lines,
        [
            (NO_STACK_FRAME, 700),
            ("main (main.py:2);fill (app.py:4)", 5000),
            ("main (main.py:2);load (app.py:11)", MIB),
        ]
    );
    // Deterministic.
    assert_eq!(folded_allocations(&p, MinWidth::Bytes(0)).unwrap(), f);

    // Cutoffs fold narrow frames into [other] and keep the total.
    let c = folded_allocations(&p, MinWidth::Bytes(1000)).unwrap();
    assert_eq!(c.lines.iter().map(|l| l.bytes).sum::<u64>(), c.total_bytes);
    assert!(c
        .lines
        .iter()
        .any(|l| l.stack == "[other]" && l.bytes == 700));
    let c = folded_allocations(&p, MinWidth::Pct(1.0)).unwrap();
    assert_eq!(
        c.min_bytes,
        ((5000 + MIB + 700) as f64 / 100.0).ceil() as u64
    );
    assert!(folded_allocations(&p, MinWidth::Pct(200.0)).is_err());
}

#[test]
fn allocation_folded_stacks_weighted_by_linked_bytes() {
    let (s, p) = two_stack_cache();
    let f = folded_allocations_linked(&s, &p, MinWidth::Bytes(0)).unwrap();
    assert_eq!(f.weight, FlameWeight::Linked);
    assert_eq!(f.total_bytes, 30_000);
    let lines: Vec<(&str, u64)> = f
        .lines
        .iter()
        .map(|l| (l.stack.as_str(), l.bytes))
        .collect();
    assert_eq!(
        lines,
        [
            ("main (main.py:2);fill (app.py:4)", 20_000),
            ("main (main.py:2);load (app.py:11)", 10_000),
        ]
    );
    assert!(f.notes.is_empty());
}
