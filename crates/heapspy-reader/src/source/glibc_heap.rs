//! glibc malloc heap walker: every busy chunk of a Linux process's C heap,
//! read from the image through [`MemorySource::read`]. Nothing is asked of
//! the target and no glibc debug symbols are needed (`main_arena` and `mp_`
//! are not exported). [`super::elf_core`] and [`super::linux_live`] use it
//! for [`MemorySource::native_blocks`].
//!
//! Modelled on glibc 2.15 to 2.43 for 64-bit little-endian targets (x86_64
//! and aarch64, where `SIZE_SZ` is 8 and `MALLOC_ALIGNMENT` is 16). The
//! layouts below are cited from `malloc/malloc.c` and `malloc/arena.c` of
//! those releases (2.15, 2.19, 2.22, 2.23, 2.25 to 2.31, 2.41 to 2.43 were
//! read). Tested on synthetic images laid out like them, and on real
//! CPython processes only with glibc 2.39 and 2.43, by the ignored test
//! `tests/native_heap_live.rs` (run by the e2e workflow).
//!
//! Layouts changed along the way, and the walker reads which one an image
//! has from the image rather than from a version string:
//!
//! - the tcache (2.26+) is recognised by its chunk size: 0x250 with `char
//!   counts[64]` (2.26 to 2.29), 0x290 with `uint16_t counts[64]` (2.30 to
//!   2.41), 0x300 with `uint16_t num_slots[76]` (2.42+);
//! - `malloc_state` has three layouts: 2.15 to 2.26, then
//!   `have_fastchunks` added (2.27 to 2.42), then fastbins removed (2.43+).
//!   `main_arena` is tried in each, and the one found decides where a
//!   thread arena's chunks start; with none found, each thread heap takes
//!   the start that tiles. Builds of the first layout differ in size too
//!   (`next_free` under `PER_THREAD`, `attached_threads` from 2.23), so
//!   each size is tried;
//! - an mmapped chunk's `size` left out its header in 2.43, and goes with
//!   the 2.43 `malloc_state`.
//!
//! Before 2.26 there is no tcache, so a core's brk heap is recognised only
//! through `main_arena` (a live source names `[heap]`).
//!
//! # What is walked
//!
//! - **Chunks** (`struct malloc_chunk`): a `prev_size` word, then a `size`
//!   word whose low bits are `PREV_INUSE` (1), `IS_MMAPPED` (2) and
//!   `NON_MAIN_ARENA` (4). The program's pointer is the chunk plus 16
//!   (`chunk2mem`). Chunks of a heap are contiguous, so the walk steps from
//!   one header to the next by `size`. A chunk is busy when the *next*
//!   chunk's `PREV_INUSE` bit is set; a free chunk also writes its size into
//!   the next chunk's `prev_size` (`set_foot`), which the walk checks.
//! - **The main arena** lives in `[heap]`, the brk area. glibc grows it in
//!   whole pages (`sysmalloc`: `ALIGN_UP (size, pagesize)`), so the top
//!   chunk ends where the mapping ends. A live source names the mapping;
//!   a core does not, so every anonymous mapping is tried, and one counts as
//!   the brk heap only if its chunks tile it exactly from start to end *and*
//!   either its first chunk is a valid tcache (below; glibc's first `malloc`
//!   in a process allocates it, `tcache_init`) or `main_arena` is found with
//!   its `top` pointing at the last chunk.
//! - **Thread arenas** (`arena.c`, `new_heap`): mappings aligned to
//!   `HEAP_MAX_SIZE` (`2 * DEFAULT_MMAP_THRESHOLD_MAX` = 64 MiB on 64-bit)
//!   that start with a `heap_info`: `ar_ptr`, `prev`, `size`,
//!   `mprotect_size`, and since 2.35 `pagesize`, padded to 32 bytes (2.15 to
//!   2.34) or 48 (2.35+). The first heap of an arena holds the arena's
//!   `malloc_state` right after `heap_info` (`_int_new_arena`: `a = h->ar_ptr
//!   = (mstate) (h + 1)`), and its chunks start after it, 16-aligned. Later
//!   heaps of the arena start their chunks right after `heap_info`
//!   (`sysmalloc`: `top (av) = chunk_at_offset (heap, sizeof (*heap))`).
//!   A heap that is no longer the arena's newest ends in fenceposts
//!   (`sysmalloc`: a 16-byte chunk, then a header of size 0) instead of a top
//!   chunk. Arenas are numbered 1, 2, ... in order of their `malloc_state`
//!   address; the main arena is 0.
//! - **mmapped chunks** (`sysmalloc_mmap`): an allocation at or above the
//!   mmap threshold (128 KiB by default, rising up to 32 MiB as such chunks
//!   are freed) gets its own mapping. Its header has `IS_MMAPPED` alone, and
//!   `prev_size` is the distance from the mapping start (0, or the lead
//!   `_int_memalign` skipped for alignment). The mapping is `prev_size +
//!   size` long until 2.42; from 2.43 (`mmap_size`) it is 16 bytes longer,
//!   the header, and `prev_size` bit 0 marks huge pages. As `munmap_chunk`
//!   checks, the mapping start and length are page-aligned and the user
//!   pointer's offset in its page is 0 or a power of two. The kernel merges
//!   neighbouring anonymous mappings, so every 4 KiB page of anonymous
//!   memory outside the arenas is checked at the offsets such a header can
//!   have (0 and `2^k - 16`). Reported as [`NativeBlockKind::Large`] covering
//!   the whole mapping, with heap 0.
//!
//! # Free chunks that look busy
//!
//! tcache and fastbin chunks keep `PREV_INUSE` set in their successor, so
//! the header walk alone counts them busy. They are taken out where the
//! lists can be read reliably:
//!
//! - **tcache** (2.26+): each thread's `tcache_perthread_struct` (`char
//!   counts[64]; tcache_entry *entries[64]`, a 0x250-byte chunk; from 2.30
//!   `uint16_t` counts, 0x290; from 2.42 `uint16_t num_slots[76];
//!   tcache_entry *entries[76]`, 0x300) is a busy chunk somewhere in the
//!   arenas. Such a chunk is taken for one when
//!   every list it describes checks out: each entry is the user pointer of
//!   a busy-looking chunk of size class `i` (`csize2tidx`; from 2.42, bins
//!   64 to 75 hold one power of two each, `large_csize2tidx`), no entry
//!   repeats, and the list ends. With `counts`, `entries[i]` is also null
//!   exactly when `counts[i]` is 0 and the list ends after that many;
//!   `num_slots`, the room left out of a tunable, is not checked. `next`
//!   links are tried raw (before 2.32) and with safe-linking
//!   (`PROTECT_PTR (pos, ptr)` = `(pos >> 12) ^ ptr`, 2.32+). The `key`
//!   field (the tcache's address until 2.33, the random `tcache_key` since
//!   2.34) is not needed. The tcache struct is allocator bookkeeping and is
//!   not listed when it holds entries or is the first chunk of a heap; an
//!   empty one elsewhere (a thread that reused an arena) is listed busy,
//!   since it cannot be told from an all-zero 640-byte allocation.
//! - **fastbins**: `malloc_state.fastbinsY[10]` holds chunk pointers whose
//!   `fd` links are raw or safe-linked like tcache. Thread arenas' states
//!   are at `ar_ptr`; `main_arena` is found by scanning libc's writable
//!   data for the brk heap's top chunk address and checking the state
//!   around it: lock and flag words in range, and every one of the 127
//!   `bins` either empty (both links point at the bin itself, `bin_at`) or
//!   pointing at chunks of the heap, and the arena list from it (`next`)
//!   returns to it (the layouts keep `top`, `bins` and `next` the same
//!   distance apart, so a state read in the wrong layout passes everything
//!   else). Layouts: 2.15 to 2.26 `fastbinsY` at 0x8, `top` at 0x58, `bins`
//!   at 0x68, size 0x880 to 0x890; 2.27 to 2.42 (`have_fastchunks`)
//!   `fastbinsY` at 0x10, `top` at 0x60, `bins` at 0x70, size 0x898; 2.43+
//!   no fastbins, `top` at 0x8, `bins` at 0x18, size 0x840. When the state
//!   is not found or does not check out, fastbin chunks are listed as
//!   busy.
//!
//! # Robustness
//!
//! Every header is checked: size a multiple of 16 and at least 32 (16 only
//! for fenceposts at a heap's end), inside the heap, `IS_MMAPPED` clear,
//! `NON_MAIN_ARENA` clear in the main arena, the first chunk's `PREV_INUSE`
//! set, and the footer of each free chunk. The first bad header stops that
//! heap. A heap found by its own header (a named `[heap]`, a `heap_info`)
//! keeps the chunks before the bad one, minus the last (its size led to
//! the bad header); a guessed heap must tile exactly or it is dropped.
//! Walks are bounded ([`MAX_CHUNKS`] chunks, [`MAX_SCAN_PAGES`] pages for
//! the mmapped-chunk scan), and lists are bounded by the chunks they can
//! point at, so nothing loops.
//!
//! # Not handled
//!
//! - Other allocators: a loaded jemalloc, tcmalloc or mimalloc library, or
//!   no glibc `libc.so.6`, gives `Ok(None)`. So does an image where no arena
//!   heap is found.
//! - The main arena's non-contiguous fallback (brk failed and `sysmalloc`
//!   continued in mmapped memory without a `heap_info`), hugepage arenas
//!   (`glibc.malloc.hugetlb`, which change `HEAP_MAX_SIZE`), 32-bit and
//!   big-endian targets, and glibc before 2.15.
//! - A brk heap merged by the kernel with the anonymous mapping before it
//!   (no ASLR) is found only by a live source, which knows `[heap]`.
//! - Thread stacks are anonymous memory too, and the kernel may merge one
//!   with a neighbouring mmapped chunk, so they are scanned like the rest;
//!   a would-be mmapped chunk that holds a thread's stack pointer is
//!   rejected.

use std::collections::HashSet;

use heapspy_snapshot::{Arch, Os};

use super::{MemorySource, NativeBlock, NativeBlockKind};
use crate::error::Result;

/// The program's data starts this far into a chunk: past `prev_size` and
/// `size` (see `NativeBlock::data_offset`).
const CHUNK_DATA: u64 = 16;

const CHUNK_HDR: u64 = 16;
const MINSIZE: u64 = 32;
const ALIGN: u64 = 16;
const PREV_INUSE: u64 = 1;
const IS_MMAPPED: u64 = 2;
const NON_MAIN_ARENA: u64 = 4;
/// 2.43+: `prev_size` bit 0 of an mmapped chunk, for a huge-page mapping.
const MMAP_HP: u64 = 1;
const FLAGS: u64 = 7;
/// `HEAP_MAX_SIZE` on 64-bit: `2 * DEFAULT_MMAP_THRESHOLD_MAX`, where the
/// latter is `4 * 1024 * 1024 * sizeof (long)`.
const HEAP_MAX_SIZE: u64 = 64 << 20;
/// Granularity of page checks. Linux pages are 4 KiB, or 16/64 KiB on some
/// aarch64 kernels; anything aligned to those is aligned to 4 KiB.
const PAGE: u64 = 4096;
/// `struct malloc_state` on 64-bit: its size and field offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mstate {
    /// `sizeof (struct malloc_state)`: where a thread arena's chunks start.
    /// Builds of one layout can differ (`PER_THREAD`, `attached_threads`),
    /// so a first thread heap tries each; the first is the usual one.
    pub sizes: &'static [u64],
    /// `fastbinsY`, gone in 2.43.
    pub fastbins: Option<u64>,
    /// `int have_fastchunks` after `flags` (2.27 to 2.42).
    pub have_fastchunks: bool,
    pub top: u64,
    pub bins: u64,
    /// `next`, the arena list link.
    pub next: u64,
    /// The mmapped chunks of the same releases: `true` when `size` leaves
    /// out the header and `prev_size` bit 0 marks huge pages (2.43+).
    pub mmap_hdr_apart: bool,
}
impl Mstate {
    #[cfg(test)]
    pub const fn size(&self) -> u64 {
        self.sizes[0]
    }
}
/// 2.15 to 2.26: `mutex`, `flags`, `fastbinsY[10]`, `top`,
/// `last_remainder`, `bins[254]`, `binmap[4]`, `next`, then `next_free`
/// (built with `PER_THREAD`, the default from 2.15, always from 2.20),
/// `attached_threads` (2.23+), `system_mem`, `max_system_mem`.
pub(crate) const MSTATE_2_15: Mstate = Mstate {
    sizes: &[0x888, 0x890, 0x880],
    fastbins: Some(0x08),
    have_fastchunks: false,
    top: 0x58,
    bins: 0x68,
    next: 0x868,
    mmap_hdr_apart: false,
};
/// 2.27 to 2.42: `have_fastchunks` added after `flags`.
pub(crate) const MSTATE_2_27: Mstate = Mstate {
    sizes: &[0x898],
    fastbins: Some(0x10),
    have_fastchunks: true,
    top: 0x60,
    bins: 0x70,
    next: 0x870,
    mmap_hdr_apart: false,
};
/// 2.43+: fastbins removed, so `top` follows `flags`.
pub(crate) const MSTATE_2_43: Mstate = Mstate {
    sizes: &[0x840],
    fastbins: None,
    have_fastchunks: false,
    top: 0x08,
    bins: 0x18,
    next: 0x818,
    mmap_hdr_apart: true,
};
const MSTATES: [Mstate; 3] = [MSTATE_2_27, MSTATE_2_43, MSTATE_2_15];
/// `NFASTBINS`: `fastbin_index (request2size (MAX_FAST_SIZE)) + 1`.
const NFASTBINS: u64 = 10;
/// `NBINS * 2 - 2` pointers, as 127 (fd, bk) pairs.
const NBIN_PAIRS: u64 = 127;

/// A `tcache_perthread_struct` layout: a count per bin, then a pointer per
/// bin, in a chunk of `request2size (sizeof)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tcache {
    pub bins: usize,
    /// Bytes per count: `char` (2.26 to 2.29) or `uint16_t` (2.30+).
    pub count_size: usize,
    pub chunk: u64,
    /// The count is `num_slots`, the room left (2.42+), not `counts`, the
    /// entries held.
    pub slots: bool,
}
impl Tcache {
    pub const fn struct_size(&self) -> usize {
        self.bins * (self.count_size + 8)
    }
    pub const fn entries(&self) -> u64 {
        (self.bins * self.count_size) as u64
    }
}
/// 2.26 to 2.29: `char counts[64]`.
pub(crate) const TCACHE_2_26: Tcache = Tcache {
    bins: 64,
    count_size: 1,
    chunk: 0x250,
    slots: false,
};
/// 2.30 to 2.41: `uint16_t counts[64]`.
pub(crate) const TCACHE_2_30: Tcache = Tcache {
    bins: 64,
    count_size: 2,
    chunk: 0x290,
    slots: false,
};
/// 2.42+: 64 small bins and 12 large ones (`TCACHE_LARGE_BINS`, chunks up
/// to 4 MiB by power of two), of slots left.
pub(crate) const TCACHE_2_42: Tcache = Tcache {
    bins: 76,
    count_size: 2,
    chunk: 0x300,
    slots: true,
};
/// The tcache struct a busy chunk of `size` would hold.
fn tcache_of(size: u64) -> Option<Tcache> {
    [TCACHE_2_26, TCACHE_2_30, TCACHE_2_42]
        .into_iter()
        .find(|t| t.chunk == size)
}
/// `TCACHE_SMALL_BINS`, and the largest chunk they hold
/// (`MAX_TCACHE_SMALL_SIZE`, `tidx2csize (63)`).
const TCACHE_SMALL_BINS: u64 = 64;
const TCACHE_SMALL_MAX: u64 = 63 * ALIGN + MINSIZE;
/// Whether a chunk of `size` belongs in tcache bin `i` (`csize2tidx`, and
/// from 2.42 `large_csize2tidx`: one bin per power of two above the small
/// bins).
fn tcache_bin_holds(i: u64, size: u64) -> bool {
    if i < TCACHE_SMALL_BINS {
        size >= MINSIZE && (size - MINSIZE) / ALIGN == i
    } else {
        // large_csize2tidx: 64 + clz (0x410) - clz (nb), on 32-bit clz.
        let lg = |x: u64| 63 - u64::from(x.leading_zeros());
        size > TCACHE_SMALL_MAX
            && size < 1 << 32
            && TCACHE_SMALL_BINS + lg(size) - lg(TCACHE_SMALL_MAX) == i
    }
}
/// Offsets in a page where an mmapped chunk header can be: the user
/// pointer is page-aligned or at a power of two in its page.
const MMAP_OFFSETS: [u64; 8] = [0, 48, 112, 240, 496, 1008, 2032, 4080];
/// Most chunks walked over all heaps. At 24 bytes each, 768 MiB of
/// bookkeeping for a heap of tens of GiB.
pub const MAX_CHUNKS: usize = 32 << 20;
/// Most pages checked for mmapped chunks (64 GiB of anonymous memory).
pub const MAX_SCAN_PAGES: u64 = 16 << 20;
/// How close to a heap's end a fencepost may sit (`sysmalloc` leaves the
/// size-0 header 16 to 31 bytes before the end, after a 16-byte chunk).
const FENCE_SLACK: u64 = 80;

/// What the source knows about the heap besides its bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeapHints {
    /// The `[heap]` (brk) mapping, `start..end`, when the source names it
    /// (`/proc/<pid>/maps`). A core does not; the walker then looks for it.
    pub brk: Option<(u64, u64)>,
}

/// List the busy chunks of a glibc malloc heap. See the module docs.
pub fn native_blocks<S: MemorySource + ?Sized>(
    src: &S,
    hints: &HeapHints,
) -> Result<Option<Vec<NativeBlock>>> {
    let t = src.target();
    if t.os != Os::Linux
        || t.pointer_size != 8
        || !t.little_endian
        || !matches!(t.arch, Arch::X86_64 | Arch::Aarch64)
    {
        return Ok(None);
    }
    let modules = src.modules()?;
    if modules.iter().any(|m| other_allocator(&m.name)) {
        return Ok(None);
    }
    let Some(libc) = modules.iter().find(|m| is_glibc(&m.name)) else {
        return Ok(None);
    };
    let ranges = src.mapped_ranges()?;
    let stacks: Vec<u64> = src
        .threads()
        .unwrap_or_default()
        .iter()
        .filter_map(|t| t.stack_pointer)
        .collect();
    // Anonymous read-write mappings: where malloc's memory comes from.
    let anon: Vec<Span> = ranges
        .iter()
        .filter(|r| r.file.is_none() && r.perms.read && r.perms.write && r.size > 0)
        .filter_map(|r| Span::new(r.start, r.start.checked_add(r.size)?))
        .collect();
    let merged = coalesce(&anon);
    // libc's writable data, where `main_arena` is.
    let libc_data: Vec<Span> = ranges
        .iter()
        .filter(|r| r.perms.write && r.file.as_deref() == Some(libc.path.as_str()))
        .filter_map(|r| Span::new(r.start, r.start.checked_add(r.size)?))
        .collect();

    let mut w = Walker {
        src,
        budget: MAX_CHUNKS,
    };
    let mut heaps: Vec<Heap> = Vec::new();

    // Thread arenas' headers first: the brk heap is not among them.
    let infos = w.find_thread_heaps(&merged);
    let mut keys: Vec<u64> = infos.iter().map(|h| h.ar_ptr).collect();
    keys.sort_unstable();
    keys.dedup();
    let firsts: HashSet<u64> = infos.iter().filter(|h| h.first).map(|h| h.base).collect();
    let thread_spans: Vec<Span> = infos
        .iter()
        .map(|h| Span {
            start: h.base,
            end: h.base.saturating_add(HEAP_MAX_SIZE),
        })
        .collect();

    // The main arena's brk heap. `main_arena`, when found, says which
    // `malloc_state` layout this glibc has.
    let mut main_state: Option<(u64, Mstate)> = None;
    let mut main_spans: Vec<Span> = Vec::new();
    if let Some((s, e)) = hints.brk {
        if let Some(span) = Span::new(s, e) {
            let walk = w.walk(align_up(s, ALIGN), e, true);
            if !walk.chunks.is_empty() || walk.complete() {
                if let End::Top(top) = walk.end {
                    main_state = w.find_main_arena(&libc_data, top, &walk.chunks);
                }
                main_spans.push(span);
                heaps.push(Heap {
                    arena: 0,
                    first_chunk: Some(align_up(s, ALIGN)),
                    walk,
                });
            }
        }
    } else {
        for r in &anon {
            if thread_spans.iter().any(|t| t.overlaps(r)) {
                continue;
            }
            let start = align_up(r.start, ALIGN);
            // Cheap first look: the first chunk of a fresh brk heap.
            match w.header(start) {
                Some((0, word))
                    if word & FLAGS == PREV_INUSE
                        && (word & !FLAGS) >= MINSIZE
                        && (word & !FLAGS) <= r.end - start => {}
                _ => continue,
            }
            let walk = w.walk(start, r.end, true);
            let End::Top(top) = walk.end else {
                w.refund(&walk);
                continue;
            };
            let state = w.find_main_arena(&libc_data, top, &walk.chunks);
            let tcache_first = walk.chunks.first().is_some_and(|c| {
                c.addr == start
                    && tcache_of(c.size).is_some_and(|t| {
                        w.tcache_entries(t, c.addr + CHUNK_HDR, &walk.chunks)
                            .is_some()
                    })
            });
            if walk.chunks.is_empty() || (state.is_none() && !tcache_first) {
                w.refund(&walk);
                continue;
            }
            main_state = main_state.or(state);
            main_spans.push(*r);
            heaps.push(Heap {
                arena: 0,
                first_chunk: Some(start),
                walk,
            });
        }
    }
    // The layouts still possible.
    let mstates: Vec<Mstate> = match main_state {
        Some((_, l)) => vec![l],
        None => MSTATES.to_vec(),
    };

    // Thread arenas. A first heap's chunks follow its `malloc_state`, whose
    // size depends on the layout: with it unknown, the one that tiles wins.
    let mut thread_mstate: Vec<(u64, Mstate)> = Vec::new();
    for h in &infos {
        let arena_base = h.ar_ptr & !(HEAP_MAX_SIZE - 1);
        let hi = h.ar_ptr - arena_base;
        if hi != 32 && hi != 48 {
            continue;
        }
        // A later heap whose arena's first heap is not in the image has
        // only its own header to vouch for it: it must tile exactly.
        let strict = !h.first && !firsts.contains(&arena_base);
        let starts: Vec<(u64, Option<Mstate>)> = if h.first {
            mstates
                .iter()
                .flat_map(|&l| {
                    l.sizes
                        .iter()
                        .map(move |&size| (align_up(h.ar_ptr + size, ALIGN), Some(l)))
                })
                .collect()
        } else {
            vec![(h.base + hi, None)]
        };
        let mut best: Option<(HeapWalk, u64, Option<Mstate>)> = None;
        for (start, l) in starts {
            let walk = w.walk(start, h.base + h.size, false);
            let better = best.as_ref().is_none_or(|(b, _, _)| {
                (walk.complete(), walk.chunks.len()) > (b.complete(), b.chunks.len())
            });
            if better {
                if let Some((old, _, _)) = best.take() {
                    w.refund(&old);
                }
                best = Some((walk, start, l));
            } else {
                w.refund(&walk);
            }
        }
        let Some((walk, start, l)) = best else {
            continue;
        };
        if strict && !walk.complete() {
            w.refund(&walk);
            continue;
        }
        if let Some(l) = l {
            thread_mstate.push((h.ar_ptr, l));
        }
        let arena = 1 + keys.binary_search(&h.ar_ptr).unwrap_or(0) as u32;
        heaps.push(Heap {
            arena,
            first_chunk: h.first.then_some(start),
            walk,
        });
    }
    // The layout the thread arenas agree on, if the main arena said none.
    let mstates: Vec<Mstate> = if mstates.len() > 1 {
        let mut agreed: Vec<Mstate> = thread_mstate.iter().map(|t| t.1).collect();
        agreed.dedup();
        if agreed.len() == 1 {
            agreed
        } else {
            mstates
        }
    } else {
        mstates
    };

    if heaps.is_empty() {
        return Ok(None);
    }

    // Every chunk the walks could classify, sorted (heaps do not overlap).
    let mut all: Vec<Chunk> = Vec::new();
    let mut arena_of: Vec<(u64, u32)> = Vec::new();
    let mut firsts: HashSet<u64> = HashSet::new();
    let mut tops: Vec<(u32, u64)> = Vec::new();
    for h in &heaps {
        all.extend_from_slice(&h.walk.chunks);
        arena_of.extend(h.walk.chunks.iter().map(|c| (c.addr, h.arena)));
        firsts.extend(h.first_chunk);
        if let End::Top(t) = h.walk.end {
            tops.push((h.arena, t));
        }
    }
    all.sort_unstable_by_key(|c| c.addr);
    arena_of.sort_unstable_by_key(|a| a.0);

    let mut free: HashSet<u64> = HashSet::new();
    let mut bookkeeping: HashSet<u64> = HashSet::new();
    // tcache: every busy chunk of a tcache struct's size that checks out
    // as one.
    for c in all.iter().filter(|c| c.busy) {
        let Some(t) = tcache_of(c.size) else {
            continue;
        };
        if let Some(entries) = w.tcache_entries(t, c.addr + CHUNK_HDR, &all) {
            if !entries.is_empty() || firsts.contains(&c.addr) {
                bookkeeping.insert(c.addr);
            }
            free.extend(entries);
        }
    }
    // fastbins, for each arena whose malloc_state checks out.
    let mut states: Vec<(u32, u64, Mstate)> = keys
        .iter()
        .enumerate()
        .flat_map(|(i, &k)| mstates.iter().map(move |&l| (1 + i as u32, k, l)))
        .collect();
    if let Some((m, l)) = main_state {
        states.push((0, m, l));
    }
    for (arena, ms, l) in states {
        let Some(_) = l.fastbins else {
            continue;
        };
        let chunks: Vec<Chunk> = all
            .iter()
            .zip(&arena_of)
            .filter(|(_, a)| a.1 == arena)
            .map(|(c, _)| *c)
            .collect();
        let arena_tops: Vec<u64> = tops.iter().filter(|t| t.0 == arena).map(|t| t.1).collect();
        if w.check_mstate(ms, l, &arena_tops, &chunks) {
            free.extend(w.fastbin_chunks(ms, l, &chunks));
        }
    }

    let mut out: Vec<NativeBlock> = all
        .iter()
        .zip(&arena_of)
        .filter(|(c, _)| c.busy && !free.contains(&c.addr) && !bookkeeping.contains(&c.addr))
        .map(|(c, a)| NativeBlock {
            start: c.addr,
            size: c.size,
            kind: NativeBlockKind::Allocation,
            heap: a.1,
            data_offset: CHUNK_DATA,
        })
        .collect();

    // mmapped chunks, in the anonymous memory outside the arenas.
    let mut excluded: Vec<Span> = thread_spans;
    excluded.extend(main_spans);
    let mut pages = MAX_SCAN_PAGES;
    for seg in subtract(&merged, &excluded) {
        w.scan_mmapped(seg, &mstates, &stacks, &mut pages, &mut out);
    }

    out.sort_unstable_by_key(|b| b.start);
    let mut end = 0u64;
    out.retain(|b| {
        let keep = b.start >= end && b.size > 0;
        if keep {
            end = b.start.saturating_add(b.size);
        }
        keep
    });
    Ok(Some(out))
}

fn is_glibc(name: &str) -> bool {
    name == "libc.so.6" || (name.starts_with("libc-2.") && name.ends_with(".so"))
}

fn other_allocator(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["jemalloc", "tcmalloc", "mimalloc"]
        .iter()
        .any(|a| n.contains(a))
}

fn align_up(x: u64, a: u64) -> u64 {
    x.checked_add(a - 1).map_or(!(a - 1), |v| v & !(a - 1))
}

/// A half-open address range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    start: u64,
    end: u64,
}

impl Span {
    fn new(start: u64, end: u64) -> Option<Span> {
        (start < end).then_some(Span { start, end })
    }
    fn contains(&self, a: u64) -> bool {
        a >= self.start && a < self.end
    }
    fn overlaps(&self, o: &Span) -> bool {
        self.start < o.end && o.start < self.end
    }
}

/// Join touching spans (the kernel splits and merges anonymous mappings at
/// will; a heap or an mmapped chunk may straddle what a core lists as two).
fn coalesce(spans: &[Span]) -> Vec<Span> {
    let mut v = spans.to_vec();
    v.sort_unstable_by_key(|s| s.start);
    let mut out: Vec<Span> = Vec::with_capacity(v.len());
    for s in v {
        match out.last_mut() {
            Some(l) if s.start <= l.end => l.end = l.end.max(s.end),
            _ => out.push(s),
        }
    }
    out
}

/// `spans` minus everything in `cut`.
fn subtract(spans: &[Span], cut: &[Span]) -> Vec<Span> {
    let mut out = Vec::new();
    for s in spans {
        let mut pieces = vec![*s];
        for c in cut {
            pieces = pieces
                .into_iter()
                .flat_map(|p| {
                    if !p.overlaps(c) {
                        return vec![p];
                    }
                    [Span::new(p.start, c.start), Span::new(c.end, p.end)]
                        .into_iter()
                        .flatten()
                        .collect()
                })
                .collect();
        }
        out.extend(pieces);
    }
    out
}

/// One chunk whose status is known: its successor's header was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Chunk {
    addr: u64,
    size: u64,
    /// The next chunk's `PREV_INUSE` is set. True for tcache and fastbin
    /// chunks too.
    busy: bool,
}

fn find(chunks: &[Chunk], addr: u64) -> Option<&Chunk> {
    chunks
        .binary_search_by_key(&addr, |c| c.addr)
        .ok()
        .map(|i| &chunks[i])
}

/// How a heap walk ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// At the top chunk, which reaches the end of the heap.
    Top(u64),
    /// At `sysmalloc`'s fenceposts: a heap that is no longer the newest.
    Fence,
    /// At a header that does not check out, or out of budget.
    Broken,
}

#[derive(Debug)]
struct HeapWalk {
    /// Every chunk but the last one walked (the top chunk, the fencepost,
    /// or the chunk whose size led to a bad header), and none under 32
    /// bytes. Sorted.
    chunks: Vec<Chunk>,
    end: End,
    /// Headers read, for [`Walker::refund`].
    walked: usize,
}

impl HeapWalk {
    fn complete(&self) -> bool {
        self.end != End::Broken && self.walked >= 2
    }
}

struct Heap {
    arena: u32,
    first_chunk: Option<u64>,
    walk: HeapWalk,
}

/// A `heap_info` that checks out.
#[derive(Clone, Copy, Debug)]
struct HeapInfo {
    base: u64,
    ar_ptr: u64,
    size: u64,
    /// The arena's `malloc_state` follows this header.
    first: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Link {
    Raw,
    /// Safe-linking, 2.32+: stored as `(pos >> 12) ^ ptr`.
    Protected,
}

impl Link {
    fn decode(self, pos: u64, stored: u64) -> u64 {
        match self {
            Link::Raw => stored,
            Link::Protected => (pos >> 12) ^ stored,
        }
    }
}

struct Walker<'a, S: ?Sized> {
    src: &'a S,
    /// Chunks the walks may still record.
    budget: usize,
}

impl<S: MemorySource + ?Sized> Walker<'_, S> {
    fn word(&self, addr: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        self.src.read(addr, &mut b).ok()?;
        Some(u64::from_le_bytes(b))
    }

    /// `(prev_size, size word)` of the chunk at `c`.
    fn header(&self, c: u64) -> Option<(u64, u64)> {
        let mut b = [0u8; 16];
        self.src.read(c, &mut b).ok()?;
        Some((
            u64::from_le_bytes(b[..8].try_into().unwrap()),
            u64::from_le_bytes(b[8..].try_into().unwrap()),
        ))
    }

    fn refund(&mut self, w: &HeapWalk) {
        self.budget += w.walked;
    }

    /// Walk the chunks of one heap, `start..end`. See the module docs for
    /// the checks.
    fn walk(&mut self, start: u64, end: u64, main: bool) -> HeapWalk {
        // (addr, size, PREV_INUSE of its own header)
        let mut seen: Vec<(u64, u64, bool)> = Vec::new();
        let mut c = start;
        let end_kind = loop {
            if seen.len() >= self.budget || c.checked_add(CHUNK_HDR).is_none_or(|e| e > end) {
                break End::Broken;
            }
            let Some((prev_size, word)) = self.header(c) else {
                break End::Broken;
            };
            let size = word & !FLAGS;
            let pinuse = word & PREV_INUSE != 0;
            match seen.last() {
                // A free predecessor leaves its size in our prev_size.
                Some(&(_, psize, _)) if !pinuse && prev_size != psize => break End::Broken,
                None if !pinuse => break End::Broken,
                _ => {}
            }
            if size == 0 {
                if pinuse && !seen.is_empty() && end - c <= FENCE_SLACK {
                    break End::Fence;
                }
                break End::Broken;
            }
            if word & IS_MMAPPED != 0
                || (main && word & NON_MAIN_ARENA != 0)
                || size % ALIGN != 0
                || (size < MINSIZE && end - c > FENCE_SLACK)
            {
                break End::Broken;
            }
            let Some(next) = c.checked_add(size).filter(|&n| n <= end) else {
                break End::Broken;
            };
            seen.push((c, size, pinuse));
            if next == end {
                break End::Top(c);
            }
            c = next;
        };
        self.budget -= seen.len();
        let chunks = seen
            .windows(2)
            .filter(|w| w[0].1 >= MINSIZE)
            .map(|w| Chunk {
                addr: w[0].0,
                size: w[0].1,
                busy: w[1].2,
            })
            .collect();
        HeapWalk {
            chunks,
            end: end_kind,
            walked: seen.len(),
        }
    }

    /// Every `HEAP_MAX_SIZE`-aligned address in `spans` with a plausible
    /// `heap_info`.
    fn find_thread_heaps(&self, spans: &[Span]) -> Vec<HeapInfo> {
        let mut out = Vec::new();
        for s in spans {
            let mut a = align_up(s.start, HEAP_MAX_SIZE);
            while a >= s.start && a.checked_add(48).is_some_and(|e| e <= s.end) {
                if let Some(h) = self.heap_info(a, s) {
                    out.push(h);
                }
                match a.checked_add(HEAP_MAX_SIZE) {
                    Some(n) => a = n,
                    None => break,
                }
            }
        }
        out
    }

    fn heap_info(&self, a: u64, s: &Span) -> Option<HeapInfo> {
        let mut b = [0u8; 40];
        self.src.read(a, &mut b).ok()?;
        let f = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        let (ar_ptr, prev, size, mprotect, pagesize) = (f(0), f(1), f(2), f(3), f(4));
        let sizes_ok = size >= PAGE
            && size % PAGE == 0
            && size <= HEAP_MAX_SIZE
            && mprotect % PAGE == 0
            && (size..=HEAP_MAX_SIZE).contains(&mprotect)
            && a.checked_add(size).is_some_and(|e| e <= s.end);
        if !sizes_ok || ar_ptr == 0 || ar_ptr % 8 != 0 {
            return None;
        }
        let pagesize_ok = pagesize >= PAGE && pagesize.is_power_of_two();
        let first = prev == 0 && (ar_ptr == a + 32 || (ar_ptr == a + 48 && pagesize_ok));
        let later = prev != 0 && prev % HEAP_MAX_SIZE == 0 && prev != a && ar_ptr != a + 32;
        (first || later).then_some(HeapInfo {
            base: a,
            ar_ptr,
            size,
            first,
        })
    }

    /// The tcache entries (as chunk addresses) of the `tcache_perthread_struct`
    /// at user pointer `mem`, if it checks out. `chunks` is what the entries
    /// may point at.
    fn tcache_entries(&self, t: Tcache, mem: u64, chunks: &[Chunk]) -> Option<Vec<u64>> {
        let mut b = vec![0u8; t.struct_size()];
        self.src.read(mem, &mut b).ok()?;
        let count = |i: usize| match t.count_size {
            1 => b[i] as usize,
            _ => u16::from_le_bytes([b[2 * i], b[2 * i + 1]]) as usize,
        };
        let entry = |i: usize| {
            let o = t.entries() as usize + 8 * i;
            u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
        };
        // With counts, a list is null exactly when its count is 0 and ends
        // after that many entries. Slots left say nothing so exact (their
        // start is a tunable), so a list just has to end within the chunks.
        if !t.slots && (0..t.bins).any(|i| (count(i) == 0) != (entry(i) == 0)) {
            return None;
        }
        'mode: for link in [Link::Raw, Link::Protected] {
            let mut out = Vec::new();
            let mut seen = HashSet::new();
            for i in 0..t.bins {
                let mut x = entry(i);
                let mut k = 0usize;
                while x != 0 {
                    let ok = x % ALIGN == 0
                        && x >= CHUNK_HDR
                        && find(chunks, x - CHUNK_HDR)
                            .is_some_and(|c| c.busy && tcache_bin_holds(i as u64, c.size))
                        && seen.insert(x)
                        && (t.slots || k < count(i));
                    if !ok {
                        continue 'mode;
                    }
                    out.push(x - CHUNK_HDR);
                    let Some(stored) = self.word(x) else {
                        continue 'mode;
                    };
                    x = link.decode(x, stored);
                    k += 1;
                }
                if !t.slots && k != count(i) {
                    continue 'mode;
                }
            }
            return Some(out);
        }
        None
    }

    /// Check the `malloc_state` at `ms`: its `top` is one of `tops`, the lock
    /// and flags are in range, and every bin is empty or points at `chunks`.
    fn check_mstate(&self, ms: u64, l: Mstate, tops: &[u64], chunks: &[Chunk]) -> bool {
        // Up to `next`, the last field read.
        let mut b = vec![0u8; (l.next + 8) as usize];
        if self.src.read(ms, &mut b).is_err() {
            return false;
        }
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u64_at = |o: u64| {
            let o = o as usize;
            u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
        };
        if u32_at(0) > 2 || u32_at(4) & !7 != 0 {
            return false;
        }
        // have_fastchunks, a bool, where there are fastbins.
        if l.have_fastchunks && u32_at(8) > 1 {
            return false;
        }
        if !tops.contains(&u64_at(l.top)) {
            return false;
        }
        (0..NBIN_PAIRS).all(|j| {
            let head = ms + l.bins + 16 * j - CHUNK_HDR;
            let (fd, bk) = (u64_at(l.bins + 16 * j), u64_at(l.bins + 16 * j + 8));
            (fd == head && bk == head)
                || (fd != head
                    && bk != head
                    && find(chunks, fd).is_some()
                    && find(chunks, bk).is_some())
        })
    }

    /// `main_arena`: a `malloc_state` in libc's writable data whose `top`
    /// is the brk heap's top chunk.
    fn find_main_arena(&self, data: &[Span], top: u64, chunks: &[Chunk]) -> Option<(u64, Mstate)> {
        const MAX_DATA: u64 = 8 << 20;
        for s in data {
            let len = (s.end - s.start).min(MAX_DATA) as usize;
            let mut b = vec![0u8; len];
            if self.src.read(s.start, &mut b).is_err() {
                continue;
            }
            for (i, w) in b.chunks_exact(8).enumerate() {
                let off = i as u64 * 8;
                if u64::from_le_bytes(w.try_into().unwrap()) != top {
                    continue;
                }
                for l in MSTATES {
                    let Some(ms) = (s.start + off).checked_sub(l.top) else {
                        continue;
                    };
                    if off >= l.top
                        && self.check_mstate(ms, l, &[top], chunks)
                        && self.in_ring(ms, l)
                    {
                        return Some((ms, l));
                    }
                }
            }
        }
        None
    }

    /// Whether the arena list (`next`) from `ms` comes back to `ms`, as
    /// glibc's ring through `main_arena` does. Both layouts keep `top`,
    /// `bins` and `next` the same distance apart, so a 2.43 state read as a
    /// 2.27 one 0x58 bytes early passes the other checks; only the ring
    /// tells them apart.
    fn in_ring(&self, ms: u64, l: Mstate) -> bool {
        const MAX_ARENAS: usize = 1024;
        let mut n = ms;
        for _ in 0..MAX_ARENAS {
            match n.checked_add(l.next).and_then(|a| self.word(a)) {
                Some(next) if next == ms => return true,
                Some(next) if next != 0 && next % 8 == 0 => n = next,
                _ => return false,
            }
        }
        false
    }

    /// The chunks in the fastbins of the `malloc_state` at `ms`, if every
    /// list checks out; otherwise none.
    fn fastbin_chunks(&self, ms: u64, l: Mstate, chunks: &[Chunk]) -> Vec<u64> {
        let Some(fastbins) = l.fastbins else {
            return Vec::new();
        };
        let Some(heads): Option<Vec<u64>> = (0..NFASTBINS)
            .map(|i| self.word(ms + fastbins + 8 * i))
            .collect()
        else {
            return Vec::new();
        };
        'mode: for link in [Link::Raw, Link::Protected] {
            let mut out = Vec::new();
            let mut seen = HashSet::new();
            for (i, &head) in heads.iter().enumerate() {
                let mut p = head;
                while p != 0 {
                    // fastbin_index (sz) = (sz >> 4) - 2 on 64-bit.
                    let ok = find(chunks, p)
                        .is_some_and(|c| c.busy && (c.size >> 4) - 2 == i as u64)
                        && seen.insert(p)
                        && seen.len() <= chunks.len();
                    if !ok {
                        continue 'mode;
                    }
                    out.push(p);
                    let Some(stored) = self.word(p + CHUNK_HDR) else {
                        continue 'mode;
                    };
                    p = link.decode(p + CHUNK_HDR, stored);
                }
            }
            return out;
        }
        Vec::new()
    }

    /// Find mmapped chunks in `seg`, page by page. None holds a stack
    /// pointer in `stacks`.
    fn scan_mmapped(
        &self,
        seg: Span,
        mstates: &[Mstate],
        stacks: &[u64],
        pages: &mut u64,
        out: &mut Vec<NativeBlock>,
    ) {
        let mut p = align_up(seg.start, PAGE);
        let mut min_block = seg.start;
        'pages: while p < seg.end && *pages > 0 {
            *pages -= 1;
            for o in MMAP_OFFSETS {
                let c = p + o;
                if c.checked_add(CHUNK_HDR).is_none_or(|e| e > seg.end) {
                    break;
                }
                let Some((ps, word)) = self.header(c) else {
                    continue;
                };
                let found = mstates
                    .iter()
                    .find_map(|l| mmapped_at(c, ps, word, l.mmap_hdr_apart, seg, min_block))
                    .filter(|&(b, t)| {
                        let m = Span {
                            start: b,
                            end: b + t,
                        };
                        !stacks.iter().any(|&sp| m.contains(sp))
                    });
                if let Some((block, total)) = found {
                    out.push(NativeBlock {
                        start: block,
                        size: total,
                        kind: NativeBlockKind::Large,
                        heap: 0,
                        data_offset: CHUNK_DATA,
                    });
                    p = block + total;
                    min_block = p;
                    continue 'pages;
                }
            }
            p = p.saturating_add(PAGE);
        }
    }
}

/// The mapping (`start`, `length`) of an mmapped chunk whose header at `c`
/// is (`ps`, `word`), if it is one and fits in `seg` at or after `min_block`.
/// `hdr_apart` is the 2.43+ header: `size` leaves out the 16-byte header and
/// `prev_size` bit 0 marks a huge-page mapping (`mmap_set_chunk`).
fn mmapped_at(
    c: u64,
    ps: u64,
    word: u64,
    hdr_apart: bool,
    seg: Span,
    min_block: u64,
) -> Option<(u64, u64)> {
    if word & FLAGS != IS_MMAPPED {
        return None;
    }
    let size = word & !FLAGS;
    if size < MINSIZE || size % ALIGN != 0 {
        return None;
    }
    let (offset, total) = if hdr_apart {
        let offset = ps & !MMAP_HP;
        (offset, offset.checked_add(size)?.checked_add(CHUNK_HDR)?)
    } else {
        (ps, ps.checked_add(size)?)
    };
    let block = c.checked_sub(offset)?;
    if block % PAGE != 0 || total % PAGE != 0 || block < min_block.max(seg.start) {
        return None;
    }
    if block.checked_add(total)? > seg.end {
        return None;
    }
    // munmap_chunk: the user pointer's offset in its page is 0 or a power of two.
    let in_page = (c + CHUNK_HDR) % PAGE;
    (in_page & in_page.wrapping_sub(1) == 0).then_some((block, total))
}

/// Builders for synthetic glibc heaps, shared with the backends' tests.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;

    /// What a chunk in a synthetic heap is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum St {
        Busy,
        /// In a doubly linked bin: the next chunk's `PREV_INUSE` is clear.
        Free,
        /// In a tcache or fastbin: looks busy to the header walk.
        Cached,
    }

    /// How a synthetic heap ends.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Tail {
        Top,
        /// The old top freed (`St::Free`), then `sysmalloc`'s fenceposts.
        Fence,
    }

    /// One glibc version's layout choices.
    #[derive(Clone, Copy, Debug)]
    pub struct Glibc {
        pub safe_linking: bool,
        pub heap_info_size: u64,
        pub mstate: Mstate,
        /// `sizeof (struct malloc_state)` in this build.
        pub mstate_size: u64,
        /// None before 2.26.
        pub tcache: Option<Tcache>,
    }
    pub const V2_15: Glibc = Glibc {
        safe_linking: false,
        heap_info_size: 32,
        mstate: MSTATE_2_15,
        mstate_size: 0x888,
        tcache: None,
    };
    pub const V2_23: Glibc = Glibc {
        mstate_size: 0x890,
        ..V2_15
    };
    pub const V2_26: Glibc = Glibc {
        tcache: Some(TCACHE_2_26),
        ..V2_23
    };
    pub const V2_27: Glibc = Glibc {
        mstate: MSTATE_2_27,
        mstate_size: 0x898,
        ..V2_26
    };
    pub const V2_31: Glibc = Glibc {
        safe_linking: false,
        heap_info_size: 32,
        mstate: MSTATE_2_27,
        mstate_size: 0x898,
        tcache: Some(TCACHE_2_30),
    };
    pub const V2_33: Glibc = Glibc {
        safe_linking: true,
        ..V2_31
    };
    pub const V2_35: Glibc = Glibc {
        heap_info_size: 48,
        ..V2_33
    };
    pub const V2_42: Glibc = Glibc {
        tcache: Some(TCACHE_2_42),
        ..V2_35
    };
    pub const V2_43: Glibc = Glibc {
        mstate: MSTATE_2_43,
        mstate_size: 0x840,
        ..V2_42
    };
    /// Every layout the tests build.
    pub const ALL: [Glibc; 9] = [
        V2_15, V2_23, V2_26, V2_27, V2_31, V2_33, V2_35, V2_42, V2_43,
    ];

    impl Glibc {
        /// The tcache struct's chunk size, or where there is no tcache a
        /// plain chunk of a size no tcache has (a zeroed 0x290 chunk first
        /// in a heap would pass for an empty 2.30 tcache).
        pub fn tcache_chunk(&self) -> u64 {
            self.tcache.map_or(0x2a0, |t| t.chunk)
        }
        pub fn protect(&self, pos: u64, ptr: u64) -> u64 {
            if self.safe_linking {
                (pos >> 12) ^ ptr
            } else {
                ptr
            }
        }
    }

    /// Little-endian byte regions at fixed addresses, written to by address.
    #[derive(Clone, Debug, Default)]
    pub struct Bytes {
        pub regions: Vec<(u64, Vec<u8>)>,
    }

    impl Bytes {
        pub fn region(&mut self, base: u64, len: u64) {
            self.regions.push((base, vec![0; len as usize]));
        }
        pub fn poke(&mut self, addr: u64, v: u64) {
            let (b, r) = self
                .regions
                .iter_mut()
                .find(|(b, r)| addr >= *b && addr + 8 <= *b + r.len() as u64)
                .unwrap_or_else(|| panic!("poke {addr:#x} outside the regions"));
            let o = (addr - *b) as usize;
            r[o..o + 8].copy_from_slice(&v.to_le_bytes());
        }
        pub fn poke_u8(&mut self, addr: u64, v: u8) {
            let (b, r) = self
                .regions
                .iter_mut()
                .find(|(b, r)| addr >= *b && addr < *b + r.len() as u64)
                .unwrap();
            r[(addr - *b) as usize] = v;
        }
        pub fn poke_u16(&mut self, addr: u64, v: u16) {
            let (b, r) = self
                .regions
                .iter_mut()
                .find(|(b, r)| addr >= *b && addr + 2 <= *b + r.len() as u64)
                .unwrap();
            let o = (addr - *b) as usize;
            r[o..o + 2].copy_from_slice(&v.to_le_bytes());
        }

        /// Lay out chunks `start..end` (the region must exist). Returns
        /// `(addr, size, state)` of each chunk, then the top chunk or the
        /// fencepost pair. `non_main` sets `NON_MAIN_ARENA` on busy-looking
        /// chunks, as `_int_malloc` does in thread arenas.
        pub fn heap(
            &mut self,
            start: u64,
            end: u64,
            specs: &[(u64, St)],
            tail: Tail,
            non_main: bool,
        ) -> Vec<(u64, u64, St)> {
            let mut out = Vec::new();
            let mut c = start;
            let mut prev: Option<(u64, St)> = None;
            let put = |me: &mut Self, c: u64, size: u64, st: St, prev: Option<(u64, St)>| {
                let pin = prev.is_none_or(|p| p.1 != St::Free);
                let nm = non_main && st != St::Free;
                me.poke(c, prev.filter(|p| p.1 == St::Free).map_or(0, |p| p.0));
                me.poke(
                    c + 8,
                    size | if pin { PREV_INUSE } else { 0 } | if nm { NON_MAIN_ARENA } else { 0 },
                );
            };
            for &(size, st) in specs {
                put(self, c, size, st, prev);
                out.push((c, size, st));
                prev = Some((size, st));
                c += size;
            }
            match tail {
                Tail::Top => {
                    let size = end - c;
                    put(self, c, size, St::Busy, prev);
                    // The top chunk is never NON_MAIN_ARENA-marked busy;
                    // glibc's set_head (top, size | PREV_INUSE) leaves it bare.
                    let w = size
                        | if prev.is_none_or(|p| p.1 != St::Free) {
                            1
                        } else {
                            0
                        };
                    self.poke(c + 8, w);
                    out.push((c, size, St::Busy));
                }
                Tail::Fence => {
                    let orig = end - c;
                    let old = (orig - MINSIZE) & !(ALIGN - 1);
                    put(self, c, old, St::Free, prev);
                    out.push((c, old, St::Free));
                    let f = c + old;
                    self.poke(f, old);
                    self.poke(f + 8, CHUNK_HDR);
                    self.poke(f + 16, 0);
                    self.poke(f + 24, PREV_INUSE);
                    out.push((f, CHUNK_HDR, St::Busy));
                }
            }
            out
        }

        /// Write a `tcache_perthread_struct` at user pointer `mem` holding
        /// `lists` (size-class index, chunk addresses, head first).
        /// Nothing without a tcache (before 2.26).
        pub fn tcache(&mut self, g: Glibc, mem: u64, lists: &[(usize, Vec<u64>)], key: u64) {
            let Some(t) = g.tcache else {
                return;
            };
            if t.slots {
                // num_slots: room left of `tcache_count` (7 by default).
                for i in 0..t.bins as u64 {
                    self.poke_u16(mem + 2 * i, 7);
                }
            }
            for (idx, list) in lists {
                let n = list.len() as u16;
                let n = if t.slots { 7 - n } else { n };
                if t.count_size == 1 {
                    self.poke_u8(mem + *idx as u64, n as u8);
                } else {
                    self.poke_u16(mem + 2 * *idx as u64, n);
                }
                self.poke(mem + t.entries() + 8 * *idx as u64, list[0] + CHUNK_HDR);
                for (k, &c) in list.iter().enumerate() {
                    let e = c + CHUNK_HDR;
                    let next = list.get(k + 1).map_or(0, |n| n + CHUNK_HDR);
                    self.poke(e, g.protect(e, next));
                    self.poke(e + 8, key);
                }
            }
        }

        /// Write a `malloc_state` at `ms`: `top`, fastbin lists (index,
        /// chunks head first), and `unsorted` chunks linked in bin 1; every
        /// other bin empty. `next` is the arena list link.
        pub fn mstate(
            &mut self,
            g: Glibc,
            ms: u64,
            top: u64,
            fast: &[(usize, Vec<u64>)],
            unsorted: &[u64],
            next: u64,
        ) {
            let l = g.mstate;
            // No fastbins (2.43+): the lists are left out, and their chunks
            // look busy.
            for (idx, list) in fast.iter().filter(|_| l.fastbins.is_some()) {
                self.poke(ms + l.fastbins.unwrap() + 8 * *idx as u64, list[0]);
                for (k, &c) in list.iter().enumerate() {
                    let next = list.get(k + 1).copied().unwrap_or(0);
                    self.poke(c + 16, g.protect(c + 16, next));
                }
            }
            self.poke(ms + l.top, top);
            for j in 0..NBIN_PAIRS {
                let head = ms + l.bins + 16 * j - CHUNK_HDR;
                self.poke(head + 16, head);
                self.poke(head + 24, head);
            }
            if !unsorted.is_empty() {
                let head = ms + l.bins - CHUNK_HDR;
                let ring: Vec<u64> = std::iter::once(head)
                    .chain(unsorted.iter().copied())
                    .collect();
                for (k, &n) in ring.iter().enumerate() {
                    let fd = ring[(k + 1) % ring.len()];
                    let bk = ring[(k + ring.len() - 1) % ring.len()];
                    self.poke(n + 16, fd);
                    self.poke(n + 24, bk);
                }
            }
            self.poke(ms + l.next, next);
            // attached_threads, two words on.
            self.poke(ms + l.next + 0x10, 1);
        }
    }

    /// A small brk heap at `base` (`len` bytes): a tcache struct with two
    /// entries, busy chunks and a top chunk. Returns its bytes and the
    /// blocks it should give.
    pub fn simple_brk_heap(g: Glibc, base: u64, len: u64) -> (Vec<u8>, Vec<NativeBlock>) {
        let mut b = Bytes::default();
        b.region(base, len);
        let ch = b.heap(
            base,
            base + len,
            &[
                (g.tcache_chunk(), St::Busy),
                (0x30, St::Busy),
                (0x30, St::Cached),
                (0x110, St::Busy),
                (0x30, St::Cached),
                (0x1010, St::Busy),
            ],
            Tail::Top,
            false,
        );
        b.tcache(
            g,
            base + CHUNK_HDR,
            &[(1, vec![ch[4].0, ch[2].0])],
            base + 16,
        );
        // Without a tcache (before 2.26) a core has nothing to vouch for
        // a brk heap but main_arena, which this heap has none of.
        let want = [1, 3, 5]
            .iter()
            .filter(|_| g.tcache.is_some())
            .map(|&i| NativeBlock {
                start: ch[i].0,
                size: ch[i].1,
                kind: NativeBlockKind::Allocation,
                heap: 0,
                data_offset: CHUNK_DATA,
            })
            .collect();
        (b.regions.remove(0).1, want)
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::source::mem::MemImage;
    use crate::source::{MappedRange, MemorySummary, Module, TargetInfo, ThreadInfo};

    const LIBC_PATH: &str = "/usr/lib/x86_64-linux-gnu/libc.so.6";
    const LIBC_DATA: u64 = 0x7f12_3456_0000;
    const MAIN_ARENA: u64 = LIBC_DATA + 0xa80;
    const BRK: u64 = 0x5555_5555_9000;
    const BRK_LEN: u64 = 0x21000;

    const AARCH64: TargetInfo = TargetInfo {
        os: Os::Linux,
        arch: Arch::Aarch64,
        pointer_size: 8,
        little_endian: true,
    };

    /// A [`MemImage`] whose ranges can be file-backed, with modules.
    struct Img {
        mem: MemImage,
        files: Vec<(u64, String)>,
    }

    impl MemorySource for Img {
        fn target(&self) -> TargetInfo {
            self.mem.target()
        }
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            self.mem.read(addr, buf)
        }
        fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
            let mut r = self.mem.mapped_ranges()?;
            for m in &mut r {
                m.file = self
                    .files
                    .iter()
                    .find(|f| f.0 == m.start)
                    .map(|f| f.1.clone());
            }
            Ok(r)
        }
        fn modules(&self) -> Result<Vec<Module>> {
            self.mem.modules()
        }
        fn threads(&self) -> Result<Vec<ThreadInfo>> {
            self.mem.threads()
        }
        fn memory_summary(&self) -> Option<MemorySummary> {
            None
        }
    }

    /// The regions of a world, then which of them are libc's data.
    #[derive(Clone)]
    struct World {
        target: TargetInfo,
        bytes: Bytes,
        files: Vec<(u64, String)>,
        modules: Vec<&'static str>,
        threads: Vec<ThreadInfo>,
    }

    impl World {
        fn new(target: TargetInfo) -> World {
            World {
                target,
                bytes: Bytes::default(),
                files: Vec::new(),
                modules: vec!["python3.12", "libc.so.6"],
                threads: Vec::new(),
            }
        }

        fn libc_data(&mut self) {
            self.bytes.region(LIBC_DATA, 0x4000);
            self.files.push((LIBC_DATA, LIBC_PATH.into()));
        }

        fn img(&self) -> Img {
            let mut mem = MemImage::new(self.target);
            for (b, r) in &self.bytes.regions {
                mem.map(*b, r.clone());
            }
            for (i, name) in self.modules.iter().enumerate() {
                mem.add_module(Module {
                    name: name.to_string(),
                    path: if *name == "libc.so.6" {
                        LIBC_PATH.into()
                    } else {
                        format!("/usr/lib/{name}")
                    },
                    base: 0x7f00_1000_0000 + i as u64 * 0x100_0000,
                    size: 0x10_0000,
                    build_id: None,
                });
            }
            for t in &self.threads {
                mem.add_thread(t.clone());
            }
            Img {
                mem,
                files: self.files.clone(),
            }
        }
    }

    fn blocks(src: &dyn MemorySource, hints: &HeapHints) -> Option<Vec<NativeBlock>> {
        native_blocks(src, hints).unwrap()
    }

    fn alloc(c: (u64, u64, St), heap: u32) -> NativeBlock {
        NativeBlock {
            start: c.0,
            size: c.1,
            kind: NativeBlockKind::Allocation,
            heap,
            data_offset: CHUNK_DATA,
        }
    }

    fn large(start: u64, size: u64) -> NativeBlock {
        NativeBlock {
            start,
            size,
            kind: NativeBlockKind::Large,
            heap: 0,
            data_offset: CHUNK_DATA,
        }
    }

    /// A brk heap with every kind of chunk, and `main_arena` describing it:
    /// returns the world and what it should give.
    fn main_heap_world(
        g: Glibc,
        target: TargetInfo,
        with_arena: bool,
    ) -> (World, Vec<NativeBlock>, Vec<NativeBlock>) {
        let mut w = World::new(target);
        w.bytes.region(BRK, BRK_LEN);
        if with_arena {
            w.libc_data();
        }
        let ch = w.bytes.heap(
            BRK,
            BRK + BRK_LEN,
            &[
                (g.tcache_chunk(), St::Busy), // 0: the main thread's tcache
                (0x30, St::Busy),             // 1
                (0x30, St::Cached),           // 2: tcache
                (0x30, St::Cached),           // 3: tcache
                (0x110, St::Busy),            // 4
                (0x20, St::Cached),           // 5: fastbin 0
                (0x420, St::Free),            // 6: unsorted
                (0x50, St::Busy),             // 7
                (0x20, St::Cached),           // 8: fastbin 0
                (0x70, St::Cached),           // 9: fastbin 5
                (0x1010, St::Busy),           // 10
                (g.tcache_chunk(), St::Busy), // 11: a user's zeroed bytes
                (0x40, St::Busy),             // 12
            ],
            Tail::Top,
            false,
        );
        let tcache_mem = BRK + CHUNK_HDR;
        // 2.34+ keys are random; 2.29-2.33 use the tcache's address. Not read.
        w.bytes.tcache(
            g,
            tcache_mem,
            &[(1, vec![ch[3].0, ch[2].0])],
            0x1234_5678_9abc_def0,
        );
        if with_arena {
            w.bytes.mstate(
                g,
                MAIN_ARENA,
                ch[13].0,
                &[(0, vec![ch[8].0, ch[5].0]), (5, vec![ch[9].0])],
                &[ch[6].0],
                MAIN_ARENA,
            );
        }
        // Without fastbins (2.43+) the would-be fastbin chunks look busy.
        // Without fastbins (2.43+) the would-be fastbin chunks look busy;
        // without a tcache (before 2.26), the tcache and its entries.
        let mut with: Vec<usize> = vec![1, 4, 7, 10, 11, 12];
        let mut without: Vec<usize> = vec![1, 4, 5, 7, 8, 9, 10, 11, 12];
        if g.mstate.fastbins.is_none() {
            with.extend([5, 8, 9]);
        }
        if g.tcache.is_none() {
            with.extend([0, 2, 3]);
            without.extend([0, 2, 3]);
        }
        with.sort_unstable();
        without.sort_unstable();
        let with = with.into_iter().map(|i| alloc(ch[i], 0)).collect();
        let without: Vec<NativeBlock> = without.into_iter().map(|i| alloc(ch[i], 0)).collect();
        (w, with, without)
    }

    #[test]
    fn brk_heap_with_main_arena_drops_tcache_fastbin_and_free_chunks() {
        for (g, t) in [
            (V2_15, TargetInfo::LINUX_X86_64),
            (V2_23, AARCH64),
            (V2_26, TargetInfo::LINUX_X86_64),
            (V2_27, TargetInfo::LINUX_X86_64),
            (V2_31, TargetInfo::LINUX_X86_64),
            (V2_33, TargetInfo::LINUX_X86_64),
            (V2_35, AARCH64),
            (V2_42, TargetInfo::LINUX_X86_64),
            (V2_43, AARCH64),
        ] {
            let (w, want, _) = main_heap_world(g, t, true);
            let img = w.img();
            // A core: no hint, the heap is found by its chunks.
            assert_eq!(
                blocks(&img, &HeapHints::default()),
                Some(want.clone()),
                "{g:?}"
            );
            // A live process: [heap] named.
            let hints = HeapHints {
                brk: Some((BRK, BRK + BRK_LEN)),
            };
            assert_eq!(blocks(&img, &hints), Some(want), "{g:?}");
        }
    }

    #[test]
    fn without_main_arena_fastbin_chunks_count_as_busy() {
        for g in ALL {
            let (w, _, want) = main_heap_world(g, TargetInfo::LINUX_X86_64, false);
            // Before 2.26 (no tcache) a core has nothing to tell the brk
            // heap by without main_arena; a live source names it.
            let core = blocks(&w.img(), &HeapHints::default());
            assert_eq!(core, g.tcache.map(|_| want.clone()), "{g:?}");
            let hints = HeapHints {
                brk: Some((BRK, BRK + BRK_LEN)),
            };
            assert_eq!(blocks(&w.img(), &hints), Some(want), "{g:?}");
        }
    }

    #[test]
    fn a_corrupt_main_arena_is_ignored() {
        for g in [V2_15, V2_26, V2_35, V2_43] {
            let (mut w, _, want) = main_heap_world(g, TargetInfo::LINUX_X86_64, true);
            // A bin pointing nowhere: the state does not check out.
            w.bytes
                .poke(MAIN_ARENA + g.mstate.bins + 16 * 40, 0xdead_0000);
            // Without a tcache to vouch for it, a core then has no brk heap.
            let core = blocks(&w.img(), &HeapHints::default());
            assert_eq!(core, g.tcache.map(|_| want.clone()), "{g:?}");
            let hints = HeapHints {
                brk: Some((BRK, BRK + BRK_LEN)),
            };
            assert_eq!(blocks(&w.img(), &hints), Some(want), "{g:?}");
        }
    }

    /// Two thread arenas: A with two heaps (the older ends in fenceposts),
    /// and C with one. Plus a main heap so arena 0 exists.
    fn thread_world(g: Glibc) -> (World, Vec<NativeBlock>) {
        const A: u64 = 0x7f00_0000_0000;
        const B: u64 = 0x7f00_0400_0000;
        const C: u64 = 0x7f00_0800_0000;
        let hi = g.heap_info_size;
        let mut w = World::new(TargetInfo::LINUX_X86_64);
        let (brk, mut want) = simple_brk_heap(g, BRK, 0x4000);
        w.bytes.regions.push((BRK, brk));
        let info = |w: &mut World, base: u64, ar: u64, prev: u64, size: u64, mprot: u64| {
            w.bytes.poke(base, ar);
            w.bytes.poke(base + 8, prev);
            w.bytes.poke(base + 16, size);
            w.bytes.poke(base + 24, mprot);
            if hi == 48 {
                w.bytes.poke(base + 32, 4096);
            }
        };
        // Arena A, first heap: heap_info, malloc_state, chunks, fenceposts.
        let a_ms = A + hi;
        w.bytes.region(A, 0x8000);
        info(&mut w, A, a_ms, 0, 0x8000, 0x8000);
        let a_start = align_up(a_ms + g.mstate_size, 16);
        let a = w.bytes.heap(
            a_start,
            A + 0x8000,
            &[
                (g.tcache_chunk(), St::Busy),
                (0x40, St::Busy),
                (0x40, St::Cached),
                (0x100, St::Busy),
            ],
            Tail::Fence,
            true,
        );
        w.bytes.tcache(g, a_start + 16, &[(2, vec![a[2].0])], 0);
        // Arena A, second heap: the current one, holding top. Only part of
        // its reserved size is in use; the rest is readable.
        w.bytes.region(B, 0x8000);
        info(&mut w, B, a_ms, A, 0x4000, 0x8000);
        let b = w.bytes.heap(
            B + hi,
            B + 0x4000,
            &[(0x60, St::Busy), (0x80, St::Cached), (0x60, St::Busy)],
            Tail::Top,
            true,
        );
        w.bytes
            .mstate(g, a_ms, b[3].0, &[(6, vec![b[1].0])], &[a[4].0], C + hi);
        // Arena C: one heap, an unused tcache first.
        let c_ms = C + hi;
        w.bytes.region(C, 0x4000);
        info(&mut w, C, c_ms, 0, 0x4000, 0x4000);
        let c = w.bytes.heap(
            align_up(c_ms + g.mstate_size, 16),
            C + 0x4000,
            &[(g.tcache_chunk(), St::Busy), (0x30, St::Busy)],
            Tail::Top,
            true,
        );
        w.bytes.mstate(g, c_ms, c[2].0, &[], &[], a_ms);
        want.extend([alloc(a[1], 1), alloc(a[3], 1)]);
        want.extend([alloc(b[0], 1), alloc(b[2], 1)]);
        if g.mstate.fastbins.is_none() {
            want.push(alloc(b[1], 1));
        }
        if g.tcache.is_none() {
            want.extend([alloc(a[0], 1), alloc(a[2], 1), alloc(c[0], 2)]);
        }
        want.push(alloc(c[1], 2));
        want.sort_by_key(|b| b.start);
        (w, want)
    }

    #[test]
    fn thread_arenas_are_found_by_heap_info() {
        for g in ALL {
            let (w, want) = thread_world(g);
            assert_eq!(blocks(&w.img(), &HeapHints::default()), Some(want), "{g:?}");
        }
    }

    #[test]
    fn the_first_thread_heap_chunk_follows_malloc_state() {
        // 2.31: 0x20 + 0x898, rounded up: the familiar ...8c0.
        assert_eq!(
            align_up(0x7f00_0000_0020 + MSTATE_2_27.size(), 16),
            0x7f00_0000_08c0
        );
        assert_eq!(
            align_up(0x7f00_0000_0030 + MSTATE_2_27.size(), 16),
            0x7f00_0000_08d0
        );
        // 2.43, without fastbins: 0x30 + 0x840.
        assert_eq!(
            align_up(0x7f00_0000_0030 + MSTATE_2_43.size(), 16),
            0x7f00_0000_0870
        );
    }

    #[test]
    fn a_later_heap_without_its_first_must_tile() {
        let (mut w, _) = thread_world(V2_35);
        // Drop arena A's first heap from the image.
        w.bytes.regions.retain(|r| r.0 != 0x7f00_0000_0000);
        let got = blocks(&w.img(), &HeapHints::default()).unwrap();
        assert!(
            got.iter().any(|b| b.start == 0x7f00_0400_0000 + 48),
            "{got:?}"
        );
        // Now corrupt its middle: it is dropped, not half-read.
        w.bytes.poke(0x7f00_0400_0000 + 48 + 0x60 + 8, 0x7777);
        let got = blocks(&w.img(), &HeapHints::default()).unwrap();
        assert!(!got.iter().any(|b| b.heap == 1), "{got:?}");
    }

    #[test]
    fn mmapped_chunks_are_large_blocks() {
        const M: u64 = 0x7f20_0000_0000;
        let mut w = World::new(TargetInfo::LINUX_X86_64);
        let (brk, mut want) = simple_brk_heap(V2_35, BRK, 0x4000);
        w.bytes.regions.push((BRK, brk));
        // One merged anonymous mapping: two plain mmapped chunks, a
        // memalign(4096) one (user pointer page-aligned, 4080 bytes of lead)
        // and a memalign(64) one (48 bytes of lead), then unused pages.
        w.bytes.region(M, 0x130000);
        w.bytes.poke(M + 8, 0x21000 | IS_MMAPPED);
        w.bytes.poke(M + 0x21000 + 8, 0x10_0000 | IS_MMAPPED);
        let c3 = M + 0x121000 + 4080;
        w.bytes.poke(c3, 4080);
        w.bytes.poke(c3 + 8, (0x3000 - 4080) | IS_MMAPPED);
        let c4 = M + 0x124000 + 48;
        w.bytes.poke(c4, 48);
        w.bytes.poke(c4 + 8, (0x2000 - 48) | IS_MMAPPED);
        // Noise that is not a chunk: wrong flags, misaligned size, lead
        // that does not reach a page start, a chunk past the mapping.
        w.bytes
            .poke(M + 0x126000 + 8, 0x2000 | IS_MMAPPED | PREV_INUSE);
        w.bytes.poke(M + 0x127000, 0);
        w.bytes.poke(M + 0x127000 + 8, 0x1008 | IS_MMAPPED);
        w.bytes.poke(M + 0x128000 + 48, 40);
        w.bytes.poke(M + 0x128000 + 56, 0x2000 | IS_MMAPPED);
        w.bytes.poke(M + 0x12f000 + 8, 0x2000 | IS_MMAPPED);
        want.extend([
            large(M, 0x21000),
            large(M + 0x21000, 0x10_0000),
            large(M + 0x121000, 0x3000),
            large(M + 0x124000, 0x2000),
        ]);
        assert_eq!(blocks(&w.img(), &HeapHints::default()), Some(want));
        assert_eq!(
            mmapped_at(
                M + 4080,
                4080,
                0x1010 | 2,
                false,
                Span::new(M, M + 0x10000).unwrap(),
                M
            ),
            Some((M, 0x2000))
        );
        // 2.43: size leaves the header out, and bit 0 is the huge-page flag.
        assert_eq!(
            mmapped_at(
                M + 4080,
                4080 | MMAP_HP,
                0x1000 | 2,
                true,
                Span::new(M, M + 0x10000).unwrap(),
                M
            ),
            Some((M, 0x2000))
        );
        assert_eq!(
            mmapped_at(
                M,
                0,
                0xff0 | 2,
                false,
                Span::new(M, M + 0x10000).unwrap(),
                M
            ),
            None
        );
        assert_eq!(
            mmapped_at(
                M + 4080,
                4080,
                0x1010 | 2,
                false,
                Span::new(M, M + 0x10000).unwrap(),
                M + 1
            ),
            None
        );
    }

    #[test]
    fn mmapped_chunks_of_2_43_are_large_blocks() {
        // glibc 2.43, as on a real process: malloc (1 MiB) gives prev_size 0
        // and size 0x100ff0 | IS_MMAPPED in a 0x101000 mapping, with
        // main_arena in the 2.43 layout naming the layout.
        const M: u64 = 0x7f20_0000_0000;
        let (mut w, mut want, _) = main_heap_world(V2_43, TargetInfo::LINUX_X86_64, true);
        w.bytes.region(M, 0x103000);
        w.bytes.poke(M + 8, (0x101000 - CHUNK_HDR) | IS_MMAPPED);
        // A memalign (4096) one after it: 4080 bytes of lead.
        let c = M + 0x101000 + 4080;
        w.bytes.poke(c, 4080);
        w.bytes
            .poke(c + 8, (0x2000 - 4080 - CHUNK_HDR) | IS_MMAPPED);
        want.extend([large(M, 0x101000), large(M + 0x101000, 0x2000)]);
        want.sort_by_key(|b| b.start);
        let hints = HeapHints {
            brk: Some((BRK, BRK + BRK_LEN)),
        };
        assert_eq!(blocks(&w.img(), &hints), Some(want.clone()));
        assert_eq!(blocks(&w.img(), &HeapHints::default()), Some(want));
    }

    #[test]
    fn tcache_bins_by_size() {
        assert!(tcache_bin_holds(0, 0x20) && tcache_bin_holds(63, 0x410));
        assert!(!tcache_bin_holds(1, 0x20) && !tcache_bin_holds(63, 0x420));
        // 2.42 large bins: one per power of two above 0x410.
        assert!(tcache_bin_holds(64, 0x420) && tcache_bin_holds(64, 0x7f0));
        assert!(tcache_bin_holds(65, 0x800) && tcache_bin_holds(75, 0x3f_fff0));
        assert!(!tcache_bin_holds(64, 0x410) && !tcache_bin_holds(65, 0x7f0));
        assert_eq!(tcache_of(0x290), Some(TCACHE_2_30));
        assert_eq!(tcache_of(0x300), Some(TCACHE_2_42));
        assert_eq!(TCACHE_2_42.struct_size(), 0x2f8);
    }

    #[test]
    fn a_2_42_tcache_large_bin_is_read() {
        let mut w = World::new(TargetInfo::LINUX_X86_64);
        w.bytes.region(BRK, 0x4000);
        let ch = w.bytes.heap(
            BRK,
            BRK + 0x4000,
            &[
                (TCACHE_2_42.chunk, St::Busy),
                (0x30, St::Busy),
                (0x500, St::Cached),
                (0x30, St::Busy),
            ],
            Tail::Top,
            false,
        );
        w.bytes
            .tcache(V2_42, BRK + CHUNK_HDR, &[(64, vec![ch[2].0])], 0);
        let hints = HeapHints {
            brk: Some((BRK, BRK + 0x4000)),
        };
        let want: Vec<_> = [1, 3].map(|i| alloc(ch[i], 0)).to_vec();
        assert_eq!(blocks(&w.img(), &hints), Some(want.clone()));
        assert_eq!(blocks(&w.img(), &HeapHints::default()), Some(want));
    }

    #[test]
    fn no_mmapped_chunk_holds_a_stack_pointer() {
        const S: u64 = 0x7ffd_0000_0000;
        let mut w = World::new(TargetInfo::LINUX_X86_64);
        let (brk, mut want) = simple_brk_heap(V2_31, BRK, 0x4000);
        w.bytes.regions.push((BRK, brk));
        // A stack whose bytes look like a chunk header, merged by the
        // kernel with a real mmapped chunk right above it.
        w.bytes.region(S, 0x6000);
        w.bytes.poke(S + 8, 0x4000 | IS_MMAPPED);
        w.bytes.poke(S + 0x4000 + 8, 0x2000 | IS_MMAPPED);
        want.push(large(S + 0x4000, 0x2000));
        w.threads.push(ThreadInfo {
            tid: 1,
            name: None,
            tls_base: None,
            stack_pointer: Some(S + 0x3000),
        });
        assert_eq!(blocks(&w.img(), &HeapHints::default()), Some(want));
    }

    #[test]
    fn a_corrupt_header_stops_a_named_heap_and_drops_a_guessed_one() {
        let (w, _, want) = main_heap_world(V2_31, TargetInfo::LINUX_X86_64, false);
        let hints = HeapHints {
            brk: Some((BRK, BRK + BRK_LEN)),
        };
        // The 0x50 chunk (want[3], after the free 0x420 one) gets a bad
        // header: too big, misaligned, zero, or with the wrong flags.
        let bad = want[3].start;
        for word in [
            BRK_LEN | PREV_INUSE,
            0x58 | PREV_INUSE,
            PREV_INUSE,
            0x50 | PREV_INUSE | IS_MMAPPED,
            0x50 | PREV_INUSE | NON_MAIN_ARENA,
        ] {
            let mut w = w.clone();
            w.bytes.poke(bad + 8, word);
            let img = w.img();
            // Named: the chunks before it, minus the one whose size led there
            // (the free 0x420 chunk, which is not listed anyway).
            let got = blocks(&img, &hints).unwrap();
            assert_eq!(got, want[..3].to_vec(), "{word:#x}");
            // Guessed: nothing tiles, so no heap at all.
            assert_eq!(blocks(&img, &HeapHints::default()), None, "{word:#x}");
        }
        // A free chunk's footer that disagrees.
        let mut w2 = w.clone();
        w2.bytes.poke(bad, 0x410);
        assert_eq!(blocks(&w2.img(), &hints).unwrap(), want[..3].to_vec());
    }

    #[test]
    fn looping_lists_are_rejected_without_hanging() {
        let (w, _, without) = main_heap_world(V2_35, TargetInfo::LINUX_X86_64, true);
        let mut w = w;
        // The second fastbin-0 chunk links back to the first: a loop.
        let f1 = without[4].start; // ch[8], fastbin head
        let f2 = without[2].start; // ch[5]
        w.bytes.poke(f2 + 16, V2_35.protect(f2 + 16, f1));
        // And a tcache entry links to itself.
        let t = BRK + V2_35.tcache_chunk() + 0x30 + 0x30; // ch[3]
        w.bytes.poke(t + 16, V2_35.protect(t + 16, t + 16));
        let got = blocks(&w.img(), &HeapHints::default()).unwrap();
        // The tcache no longer checks out: its entries and itself count busy.
        assert!(got
            .iter()
            .any(|b| b.start == BRK && b.size == V2_35.tcache_chunk()));
        assert!(got.iter().any(|b| b.start == t));
        // Fastbins: neither list mode validates, so they count busy.
        assert!(got.iter().any(|b| b.start == f1) && got.iter().any(|b| b.start == f2));
    }

    #[test]
    fn other_allocators_and_targets_give_none() {
        let (w, _, _) = main_heap_world(V2_35, TargetInfo::LINUX_X86_64, true);
        let mut je = w.clone();
        je.modules.push("libjemalloc.so.2");
        assert_eq!(blocks(&je.img(), &HeapHints::default()), None);
        let mut musl = w.clone();
        musl.modules = vec!["ld-musl-x86_64.so.1"];
        assert_eq!(blocks(&musl.img(), &HeapHints::default()), None);
        let mut win = w.clone();
        win.target = TargetInfo::WINDOWS_X86_64;
        assert_eq!(blocks(&win.img(), &HeapHints::default()), None);
        // glibc, but nothing that looks like a heap.
        let mut empty = World::new(TargetInfo::LINUX_X86_64);
        empty.bytes.region(0x1000_0000, 0x10000);
        for i in 0..0x2000u64 {
            empty
                .bytes
                .poke(0x1000_0000 + i * 8, i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        }
        assert_eq!(blocks(&empty.img(), &HeapHints::default()), None);
        assert!(is_glibc("libc-2.31.so") && !is_glibc("libcrypto.so.3"));
    }

    #[test]
    fn garbage_never_panics_and_blocks_stay_well_formed() {
        let (mut w, _) = thread_world(V2_35);
        let (m, _, _) = main_heap_world(V2_35, TargetInfo::LINUX_X86_64, true);
        w.bytes.regions.retain(|r| r.0 != BRK);
        w.bytes.regions.extend(m.bytes.regions);
        w.files = m.files;
        w.bytes.region(0x7f20_0000_0000, 0x3000);
        w.bytes.poke(0x7f20_0000_0008, 0x2000 | IS_MMAPPED);
        let clean = w.img();
        let ranges = clean.mapped_ranges().unwrap();
        let total: usize = w.bytes.regions.iter().map(|r| r.1.len()).sum();
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        for round in 0..3000 {
            let mut bad = w.clone();
            // Flip a few bytes, mostly in headers (every 16th byte region).
            for _ in 0..1 + round % 4 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let mut at = (x as usize) % total;
                for (_, r) in &mut bad.bytes.regions {
                    if at < r.len() {
                        if round % 2 == 0 {
                            at = (at & !15) + 8 + (at % 8);
                            at = at.min(r.len() - 1);
                        }
                        r[at] ^= (x >> 32) as u8 | 1;
                        break;
                    }
                    at -= r.len();
                }
            }
            let hints = if round % 3 == 0 {
                HeapHints {
                    brk: Some((BRK, BRK + BRK_LEN)),
                }
            } else {
                HeapHints::default()
            };
            let Some(got) = native_blocks(&bad.img(), &hints).unwrap() else {
                continue;
            };
            for pair in got.windows(2) {
                assert!(pair[0].start + pair[0].size <= pair[1].start, "{pair:?}");
            }
            for b in &got {
                assert!(b.size >= MINSIZE);
                assert!(
                    ranges
                        .iter()
                        .any(|r| b.start >= r.start && b.start + b.size <= r.start + r.size),
                    "{b:?}"
                );
            }
        }
    }
}
