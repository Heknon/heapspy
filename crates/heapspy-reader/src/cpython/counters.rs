//! Counters CPython keeps about its own memory, read from a running target
//! without stopping it: the GC's per-generation counts and thresholds, its
//! collection totals, and the small-object allocator's (pymalloc's) arenas,
//! pools and blocks in use.
//!
//! A heap walk follows pointers from object to object, so a walk of a
//! process that keeps running can lose its way. These reads do not: each
//! counter is one word, and each pool header is read on its own, so a read
//! that races with the target spoils one value, which the checks below
//! drop. A [`CounterReader::read`] reads the header of every carved pool
//! (64 per 1 MiB arena) plus a few hundred bytes. A live Linux source
//! batches the headers, 1024 per system call
//! ([`MemorySource::read_many`]).
//!
//! # Layouts
//!
//! Measured with `offsetof` against the internal headers of 3.12.3,
//! 3.13.18 and 3.14.6 (x86_64 Linux, the default GIL build); see
//! `docs/cpython-internals.md#counters`.
//!
//! - `PyInterpreterState.gc` is `struct _gc_runtime_state`: `int enabled`
//!   at 12; `struct gc_generation generations[3]` at 24, 24 bytes each
//!   (`PyGC_Head head; int threshold; int count;`); then the permanent
//!   generation; `struct gc_generation_stats generation_stats[3]` (three
//!   `Py_ssize_t`: `collections`, `collected`, `uncollectable`) at 128
//!   (3.12, 3.13) or 120 (3.14, which dropped `generation0` from before
//!   it); `int collecting` at 200 / 192; `Py_ssize_t long_lived_total`
//!   and `long_lived_pending` at 224 / 240.
//! - pymalloc's `struct _obmalloc_state` is embedded in
//!   `PyInterpreterState` on 3.12 (`obmalloc`, 3848 bytes after `gc`) and
//!   pointed to on 3.13 (3400 after `gc`) and 3.14 (3496 after `gc`).
//!   Taken relative to `gc`, whose offset comes from `_Py_DebugOffsets` on
//!   3.13+, so the reader follows the target's own layout as far as it
//!   can. Its `mgmt` part is at 512: `arenas` (pointer) at 0, `uint
//!   maxarenas` at 8, `narenas_currently_allocated` at 552,
//!   `ntimes_arena_allocated` at 560, `narenas_highwater` at 568.
//! - `struct arena_object` (48 bytes): `address` at 0, `pool_address` at
//!   8 (the next pool not yet carved), `nfreepools` at 16, `ntotalpools`
//!   at 20. An arena's pools are carved in order from its first
//!   `POOL_SIZE`-aligned address up to `pool_address`.
//! - `struct pool_header` (48 bytes): `uint count` (blocks in use) at 0,
//!   `uint arenaindex` at 32, `uint szidx` at 36. Blocks of size class
//!   `szidx` are `(szidx + 1) * 16` bytes. `POOL_SIZE` is 16 KiB and
//!   `ARENA_SIZE` 1 MiB on every supported version (64-bit, radix tree).
//!
//! The values are the same on Windows x64 except where the interpreter
//! state itself differs, which the debug offsets cover on 3.13+. Every
//! value read is checked (an allocator state whose arena count exceeds its
//! array, a pool header whose `arenaindex` is not its arena's), so a wrong
//! layout gives `None`, not wrong numbers.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::Result;
use crate::source::{MemorySource, MemorySourceExt};

use super::frames::{self, FrameOffsets, MAX_INTERPRETERS};
use super::{offsets_for, RuntimeLocation};

/// pymalloc's pool size (`POOL_BITS` 14).
pub const POOL_SIZE: u64 = 16 << 10;
/// pymalloc's arena size (`ARENA_BITS` 20).
pub const ARENA_SIZE: u64 = 1 << 20;
/// `sizeof (struct pool_header)`.
pub const POOL_HEADER: u64 = 48;
/// `ALIGNMENT`: blocks of class `i` are `(i + 1) * ALIGNMENT` bytes.
pub const ALIGNMENT: u64 = 16;
/// `NB_SMALL_SIZE_CLASSES`: 512 / 16.
pub const SIZE_CLASSES: usize = 32;
/// The arena array is read in one piece; larger means a misread.
const MAX_ARENAS: u64 = 1 << 22;

/// Where the counters are, for one CPython minor version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterLayout {
    /// `_PyRuntimeState.interpreters.head`.
    pub rt_interpreters_head: u64,
    /// `PyInterpreterState.next`.
    pub is_next: u64,
    /// `PyInterpreterState.gc`.
    pub is_gc: u64,
    /// `PyInterpreterState.obmalloc`, relative to `gc`.
    pub obmalloc_from_gc: u64,
    /// `obmalloc` is a pointer to the state (3.13+), not the state itself.
    pub obmalloc_is_pointer: bool,
    /// `struct _gc_runtime_state` fields.
    pub gc_enabled: u64,
    pub gc_generations: u64,
    pub gc_stats: u64,
    pub gc_collecting: u64,
    pub gc_long_lived_total: u64,
}

impl CounterLayout {
    /// The layout for `3.<minor>`, with the interpreter offsets
    /// (`rt_interpreters_head`, `is_next`, `is_gc`) taken from `o`.
    pub fn for_offsets(o: &super::Offsets) -> Option<CounterLayout> {
        let (obmalloc_from_gc, pointer, stats, collecting, long_lived) = match o.minor {
            12 => (3848, false, 128, 200, 224),
            13 => (3400, true, 128, 200, 224),
            14 => (3496, true, 120, 192, 240),
            _ => return None,
        };
        Some(CounterLayout {
            rt_interpreters_head: o.rt_interpreters_head,
            is_next: o.is_next,
            is_gc: o.is_gc,
            obmalloc_from_gc,
            obmalloc_is_pointer: pointer,
            gc_enabled: 12,
            gc_generations: 24,
            gc_stats: stats,
            gc_collecting: collecting,
            gc_long_lived_total: long_lived,
        })
    }
}

/// `struct gc_generation` and its `gc_generation_stats`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcGeneration {
    /// Generation 0: allocations of tracked objects minus deallocations
    /// since the last collection. Older generations: collections of the
    /// next younger generation since this one was last collected.
    pub count: i64,
    pub threshold: i64,
    /// Collections of this generation since the interpreter started.
    pub collections: u64,
    /// Objects those collections freed.
    pub collected: u64,
    /// Objects they found unreachable but could not free (`gc.garbage`).
    pub uncollectable: u64,
}

/// The GC state of one interpreter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcCounters {
    /// `gc.isenabled()`.
    pub enabled: bool,
    /// A collection was running when the counters were read.
    pub collecting: bool,
    pub generations: [GcGeneration; 3],
    /// Objects in the oldest generation after the last full collection.
    pub long_lived_total: i64,
    /// Objects that survived a middle collection since then.
    pub long_lived_pending: i64,
}

/// Blocks in use of one pymalloc size class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SizeClass {
    /// Block size in bytes: 16, 32, ... 512.
    pub size: u32,
    /// Pools of this class with at least one block in use.
    pub pools: u64,
    pub blocks: u64,
}

/// pymalloc's arenas, pools and blocks, over every distinct allocator
/// state (subinterpreters that share the main one's are counted once).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AllocatorCounters {
    /// Arenas allocated now (`narenas_currently_allocated`).
    pub arenas: u64,
    /// Most arenas allocated at once.
    pub arenas_highwater: u64,
    /// Arenas allocated since the interpreter started.
    pub arenas_allocated_total: u64,
    /// `arenas * ARENA_SIZE`: the memory pymalloc holds from the OS.
    pub arena_bytes: u64,
    /// Pools with at least one block in use.
    pub pools: u64,
    /// Blocks in use: what `sys.getallocatedblocks()` counts, minus raw
    /// allocations.
    pub blocks: u64,
    /// Bytes of those blocks: the Python objects (and small buffers)
    /// pymalloc holds. The rest of `arena_bytes` is free inside pymalloc.
    pub block_bytes: u64,
    /// By size class, only those with blocks in use.
    pub size_classes: Vec<SizeClass>,
    /// Pool headers that could not be read or did not check out (they
    /// raced with the target, or the arena was freed meanwhile).
    pub skipped_pools: u64,
}

/// What one [`CounterReader::read`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PyCounters {
    pub interpreters: u32,
    /// Python thread states, over every interpreter.
    pub threads: u32,
    /// The main interpreter's GC, `None` when it could not be read.
    pub gc: Option<GcCounters>,
    /// `None` when pymalloc is not in use (`PYTHONMALLOC=malloc`) or its
    /// state could not be read.
    pub allocator: Option<AllocatorCounters>,
}

/// Reads [`PyCounters`] from a target again and again.
#[derive(Debug)]
pub struct CounterReader {
    runtime_addr: u64,
    layout: CounterLayout,
    frames: FrameOffsets,
    /// `obmalloc`'s offset from `gc` as found in this target: unknown
    /// ([`UNKNOWN`]) until the first read, [`NOT_FOUND`] when no offset
    /// gave a state that checks out.
    obmalloc_from_gc: AtomicU64,
}

const UNKNOWN: u64 = u64::MAX;
const NOT_FOUND: u64 = u64::MAX - 1;
/// How far from the measured offset to look for pymalloc's state, in
/// bytes each way. Interpreter fields the debug offsets do not cover can
/// differ between builds (Windows' LLP64 `long`, lock types).
const SEARCH: u64 = 2048;

impl CounterReader {
    /// Prepare to read the counters of the runtime `rt` in `src`.
    pub fn new(src: &dyn MemorySource, rt: &RuntimeLocation) -> Result<CounterReader> {
        let o = offsets_for(src, rt)?;
        let layout = CounterLayout::for_offsets(&o).ok_or_else(|| {
            crate::Error::UnsupportedPython(format!("no counter layout for CPython {}", rt.version))
        })?;
        Ok(CounterReader {
            runtime_addr: rt.runtime_addr,
            layout,
            frames: FrameOffsets::from_offsets(&o, src.target().os),
            obmalloc_from_gc: AtomicU64::new(UNKNOWN),
        })
    }

    /// A reader for a known layout (tests).
    pub fn with_layout(
        runtime_addr: u64,
        layout: CounterLayout,
        frames: FrameOffsets,
    ) -> CounterReader {
        CounterReader {
            runtime_addr,
            layout,
            frames,
            obmalloc_from_gc: AtomicU64::new(UNKNOWN),
        }
    }

    pub fn layout(&self) -> &CounterLayout {
        &self.layout
    }

    /// Read every counter once. Fails only when the interpreter list
    /// itself cannot be read; anything else that fails is left `None`.
    pub fn read(&self, src: &dyn MemorySource) -> Result<PyCounters> {
        let l = &self.layout;
        let mut interps = Vec::new();
        let mut seen = HashSet::new();
        let mut interp = src.read_ptr(self.runtime_addr + l.rt_interpreters_head)?;
        while interp != 0 && interps.len() < MAX_INTERPRETERS && seen.insert(interp) {
            interps.push(interp);
            interp = src.read_ptr(interp + l.is_next).unwrap_or(0);
        }
        let threads = frames::thread_states(src, &self.frames, self.runtime_addr)
            .map(|t| t.len() as u32)
            .unwrap_or(0);
        // New interpreters are pushed at the head: the main one is last.
        let gc = interps.last().and_then(|&i| read_gc(src, i + l.is_gc, l));
        let mut states: Vec<u64> = Vec::new();
        if let Some(off) = self.obmalloc_offset(src, &interps) {
            for &i in &interps {
                if let Some(state) = self.state_at(src, i, off) {
                    if !states.contains(&state) {
                        states.push(state);
                    }
                }
            }
        }
        let mut allocator: Option<AllocatorCounters> = None;
        for s in states {
            let Some(a) = read_allocator(src, s) else {
                continue;
            };
            match &mut allocator {
                None => allocator = Some(a),
                Some(t) => t.add(&a),
            }
        }
        Ok(PyCounters {
            interpreters: interps.len() as u32,
            threads,
            gc,
            allocator: allocator.filter(|a| a.arenas > 0 || a.arenas_allocated_total > 0),
        })
    }
}

impl CounterReader {
    /// Where pymalloc's state is for interpreter `interp`, with `obmalloc`
    /// at `off` from `gc`: the embedded struct (3.12), or the one its
    /// pointer names (3.13+).
    fn state_at(&self, src: &dyn MemorySource, interp: u64, off: u64) -> Option<u64> {
        let at = interp + self.layout.is_gc + off;
        if self.layout.obmalloc_is_pointer {
            src.read_ptr(at).ok().filter(|&p| p != 0)
        } else {
            Some(at)
        }
    }

    /// `obmalloc`'s offset from `gc`. The measured one is tried first; when
    /// the main interpreter's state there does not check out, the offsets
    /// around it are searched once, 8 bytes at a time, for a state whose
    /// arenas hold pools that name their own arena, more of them than not
    /// (a test random memory does not pass), and the one found is kept.
    fn obmalloc_offset(&self, src: &dyn MemorySource, interps: &[u64]) -> Option<u64> {
        match self.obmalloc_from_gc.load(Ordering::Relaxed) {
            NOT_FOUND => return None,
            UNKNOWN => {}
            off => return Some(off),
        }
        let main = *interps.last()?;
        let base = self.layout.obmalloc_from_gc;
        let strict = |off: u64| {
            self.state_at(src, main, off)
                .and_then(|s| read_allocator(src, s))
                .is_some_and(|a| a.arenas > 0 && a.pools > a.skipped_pools)
        };
        let found = std::iter::once(base)
            .chain((1..=SEARCH / 8).flat_map(|k| [base + 8 * k, base.wrapping_sub(8 * k)]))
            .filter(|&o| o < 1 << 20)
            .find(|&o| strict(o));
        let Some(off) = found else {
            // Too early to tell (no arena yet) is not a verdict; a target
            // with arenas but no state that checks out is.
            if self
                .state_at(src, main, base)
                .and_then(|s| read_allocator(src, s))
                .is_none()
            {
                self.obmalloc_from_gc.store(NOT_FOUND, Ordering::Relaxed);
            }
            return None;
        };
        self.obmalloc_from_gc.store(off, Ordering::Relaxed);
        Some(off)
    }
}

impl AllocatorCounters {
    fn add(&mut self, o: &AllocatorCounters) {
        self.arenas += o.arenas;
        self.arenas_highwater += o.arenas_highwater;
        self.arenas_allocated_total += o.arenas_allocated_total;
        self.arena_bytes += o.arena_bytes;
        self.pools += o.pools;
        self.blocks += o.blocks;
        self.block_bytes += o.block_bytes;
        self.skipped_pools += o.skipped_pools;
        for c in &o.size_classes {
            match self.size_classes.iter_mut().find(|x| x.size == c.size) {
                Some(x) => {
                    x.pools += c.pools;
                    x.blocks += c.blocks;
                }
                None => self.size_classes.push(*c),
            }
        }
        self.size_classes.sort_by_key(|c| c.size);
    }
}

/// `struct _gc_runtime_state` at `at`, if it looks like one.
fn read_gc(src: &dyn MemorySource, at: u64, l: &CounterLayout) -> Option<GcCounters> {
    let int = |off: u64| src.read_u32(at + off).ok().map(|v| v as i32);
    let size = |off: u64| src.read_u64(at + off).ok().map(|v| v as i64);
    let enabled = int(l.gc_enabled)?;
    let collecting = int(l.gc_collecting)?;
    if !(0..=1).contains(&enabled) || !(0..=1).contains(&collecting) {
        return None;
    }
    let mut g = GcCounters {
        enabled: enabled == 1,
        collecting: collecting == 1,
        long_lived_total: size(l.gc_long_lived_total)?,
        long_lived_pending: size(l.gc_long_lived_total + 8)?,
        ..GcCounters::default()
    };
    for (i, gen) in g.generations.iter_mut().enumerate() {
        let base = l.gc_generations + 24 * i as u64;
        let stats = l.gc_stats + 24 * i as u64;
        let threshold = i64::from(int(base + 16)?);
        let count = i64::from(int(base + 20)?);
        let collections = size(stats)?;
        let collected = size(stats + 8)?;
        let uncollectable = size(stats + 16)?;
        // `gc.set_threshold` takes C ints, so a negative threshold is a
        // misread; counts go briefly negative only in generation 0 (more
        // frees than allocations since the last collection).
        if threshold < 0 || (i > 0 && count < 0) || collections < 0 || collected < 0 {
            return None;
        }
        *gen = GcGeneration {
            count,
            threshold,
            collections: collections as u64,
            collected: collected as u64,
            uncollectable: uncollectable.max(0) as u64,
        };
    }
    // The GC state starts with `trash_delete_later` and the generation
    // list heads: each head's `_gc_next` is a pointer, never null once the
    // interpreter is initialised.
    for i in 0..3u64 {
        let head = src.read_u64(at + l.gc_generations + 24 * i).ok()?;
        if head == 0 {
            return None;
        }
    }
    Some(g)
}

/// `struct _obmalloc_state` at `at`, if it looks like one.
fn read_allocator(src: &dyn MemorySource, at: u64) -> Option<AllocatorCounters> {
    let mgmt = at + 512;
    let arenas = src.read_ptr(mgmt).ok()?;
    let max = u64::from(src.read_u32(mgmt + 8).ok()?);
    let current = src.read_u64(mgmt + 552).ok()?;
    let total = src.read_u64(mgmt + 560).ok()?;
    let highwater = src.read_u64(mgmt + 568).ok()?;
    if max > MAX_ARENAS || current > max || highwater > max || current > highwater {
        return None;
    }
    if total < highwater || (max > 0 && arenas == 0) {
        return None;
    }
    let mut out = AllocatorCounters {
        arenas: current,
        arenas_highwater: highwater,
        arenas_allocated_total: total,
        arena_bytes: current * ARENA_SIZE,
        ..AllocatorCounters::default()
    };
    if max == 0 {
        return Some(out);
    }
    let table = src.read_vec(arenas, (max * 48) as usize).ok()?;
    let word = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let half = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let mut classes = [SizeClass::default(); SIZE_CLASSES];
    let mut live = 0u64;
    // (arena slot, pool address) of every carved pool.
    let mut pools: Vec<(usize, u64)> = Vec::new();
    for (i, ao) in table.chunks_exact(48).enumerate() {
        let address = word(ao, 0);
        if address == 0 {
            continue;
        }
        live += 1;
        let pool_address = word(ao, 8);
        let ntotal = u64::from(half(ao, 20));
        let first = address.next_multiple_of(POOL_SIZE);
        if pool_address < first
            || pool_address > address + ARENA_SIZE
            || ntotal > ARENA_SIZE / POOL_SIZE
        {
            out.skipped_pools += 1;
            continue;
        }
        let carved = ((pool_address - first) / POOL_SIZE).min(ntotal);
        pools.extend((0..carved).map(|p| (i, first + p * POOL_SIZE)));
    }
    // Every carved pool's header, in as few reads as the source can do.
    let addrs: Vec<u64> = pools.iter().map(|p| p.1).collect();
    let mut headers = vec![0u8; addrs.len() * POOL_HEADER as usize];
    let read = src.read_many(&addrs, POOL_HEADER as usize, &mut headers);
    for ((&(i, _), h), ok) in pools
        .iter()
        .zip(headers.chunks_exact(POOL_HEADER as usize))
        .zip(read)
    {
        if !ok {
            out.skipped_pools += 1;
            continue;
        }
        let count = u64::from(half(h, 0));
        if count == 0 {
            continue;
        }
        let arenaindex = half(h, 32) as usize;
        let szidx = half(h, 36) as usize;
        if arenaindex != i || szidx >= SIZE_CLASSES {
            out.skipped_pools += 1;
            continue;
        }
        let size = (szidx as u64 + 1) * ALIGNMENT;
        if count > (POOL_SIZE - POOL_HEADER) / size {
            out.skipped_pools += 1;
            continue;
        }
        let c = &mut classes[szidx];
        c.size = size as u32;
        c.pools += 1;
        c.blocks += count;
        out.pools += 1;
        out.blocks += count;
        out.block_bytes += count * size;
    }
    // The array changed under us (an arena was allocated or freed between
    // reading the count and the array): trust the array.
    if live != current {
        out.arenas = live;
        out.arena_bytes = live * ARENA_SIZE;
    }
    out.size_classes = classes.into_iter().filter(|c| c.blocks > 0).collect();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpython::Offsets;
    use crate::source::mem::MemImage;
    use crate::TargetInfo;
    use heapspy_snapshot::Os;

    /// A fake target: a runtime, one interpreter with a GC state and an
    /// allocator state holding two arenas.
    struct Fake {
        img: MemImage,
        reader: CounterReader,
    }

    fn put(buf: &mut [u8], at: u64, v: &[u8]) {
        buf[at as usize..at as usize + v.len()].copy_from_slice(v);
    }

    fn fake(minor: u8) -> Fake {
        fake_at(minor, 0)
    }

    /// [`fake`] with pymalloc's state `shift` bytes further from `gc`
    /// than the layout says, as another build's interpreter might put it.
    fn fake_at(minor: u8, shift: u64) -> Fake {
        let o = Offsets::table(minor, Os::Linux).unwrap();
        let l = CounterLayout::for_offsets(&o).unwrap();
        let reader_layout = l;
        let mut l = l;
        l.obmalloc_from_gc += shift;
        let fo = FrameOffsets::from_offsets(&o, Os::Linux);
        let mut img = MemImage::new(TargetInfo::LINUX_X86_64);

        let runtime = 0x10_0000u64;
        let interp = 0x20_0000u64;
        let state_ptr_target = 0x30_0000u64;
        let arenas = 0x40_0000u64;
        let arena0 = 0x100_0000u64; // pool-aligned
        let arena1 = 0x200_0000u64 + 0x1000; // not pool-aligned

        let mut rt = vec![0u8; (l.rt_interpreters_head + 8) as usize];
        put(&mut rt, l.rt_interpreters_head, &interp.to_le_bytes());
        img.map(runtime, rt);

        let state_at = if l.obmalloc_is_pointer {
            state_ptr_target
        } else {
            interp + l.is_gc + l.obmalloc_from_gc
        };
        let mut is = vec![0u8; (l.is_gc + l.obmalloc_from_gc + 2048) as usize];
        let gc = l.is_gc;
        put(&mut is, gc + l.gc_enabled, &1u32.to_le_bytes());
        for i in 0..3u64 {
            let g = gc + l.gc_generations + 24 * i;
            put(&mut is, g, &(interp + g).to_le_bytes());
            put(
                &mut is,
                g + 16,
                &([2000u32, 10, 10][i as usize]).to_le_bytes(),
            );
            put(&mut is, g + 20, &([150u32, 3, 1][i as usize]).to_le_bytes());
            let s = gc + l.gc_stats + 24 * i;
            put(&mut is, s, &(100 - 40 * i).to_le_bytes());
            put(&mut is, s + 8, &(5000u64).to_le_bytes());
        }
        put(&mut is, gc + l.gc_long_lived_total, &4321u64.to_le_bytes());
        if l.obmalloc_is_pointer {
            put(
                &mut is,
                l.is_gc + l.obmalloc_from_gc,
                &state_ptr_target.to_le_bytes(),
            );
        }
        let mut state = vec![0u8; 2048];
        put(&mut state, 512, &arenas.to_le_bytes());
        put(&mut state, 520, &4u32.to_le_bytes());
        put(&mut state, 512 + 552, &2u64.to_le_bytes());
        put(&mut state, 512 + 560, &7u64.to_le_bytes());
        put(&mut state, 512 + 568, &3u64.to_le_bytes());
        if l.obmalloc_is_pointer {
            img.map(interp, is);
            img.map(state_ptr_target, state);
        } else {
            let off = (state_at - interp) as usize;
            is[off..off + 2048].copy_from_slice(&state);
            img.map(interp, is);
        }

        // Arena table: slot 0 and 2 used, 1 and 3 free.
        let mut table = vec![0u8; 4 * 48];
        let first1 = arena1.next_multiple_of(POOL_SIZE);
        for (slot, base, first, carved) in [(0u64, arena0, arena0, 3u64), (2, arena1, first1, 2)] {
            let o = slot * 48;
            put(&mut table, o, &base.to_le_bytes());
            put(
                &mut table,
                o + 8,
                &(first + carved * POOL_SIZE).to_le_bytes(),
            );
            put(&mut table, o + 16, &(64 - carved as u32).to_le_bytes());
            put(&mut table, o + 20, &64u32.to_le_bytes());
        }
        img.map(arenas, table);
        // Pool headers.
        let pool = |count: u32, arena: u32, szidx: u32| {
            let mut h = vec![0u8; POOL_HEADER as usize];
            put(&mut h, 0, &count.to_le_bytes());
            put(&mut h, 32, &arena.to_le_bytes());
            put(&mut h, 36, &szidx.to_le_bytes());
            h
        };
        img.map(arena0, pool(10, 0, 0)); // 10 × 16 B
        img.map(arena0 + POOL_SIZE, pool(0, 0, 3)); // empty
        img.map(arena0 + 2 * POOL_SIZE, pool(5, 0, 3)); // 5 × 64 B
        img.map(first1, pool(2, 2, 31)); // 2 × 512 B
        img.map(first1 + POOL_SIZE, pool(9, 1, 0)); // wrong arena: skipped
        Fake {
            img,
            reader: CounterReader::with_layout(runtime, reader_layout, fo),
        }
    }

    #[test]
    fn reads_gc_and_allocator_on_every_version() {
        for minor in [12, 13, 14] {
            let f = fake(minor);
            let c = f.reader.read(&f.img).unwrap();
            assert_eq!(c.interpreters, 1, "3.{minor}");
            let gc = c.gc.expect("gc");
            assert!(gc.enabled && !gc.collecting);
            assert_eq!(gc.generations[0].threshold, 2000);
            assert_eq!(gc.generations[0].count, 150);
            assert_eq!(gc.generations[2].count, 1);
            assert_eq!(gc.generations[1].collections, 60);
            assert_eq!(gc.generations[0].collected, 5000);
            assert_eq!(gc.long_lived_total, 4321);

            let a = c.allocator.expect("allocator");
            assert_eq!(a.arenas, 2);
            assert_eq!(a.arenas_highwater, 3);
            assert_eq!(a.arenas_allocated_total, 7);
            assert_eq!(a.arena_bytes, 2 * ARENA_SIZE);
            assert_eq!(a.pools, 3);
            assert_eq!(a.blocks, 17);
            assert_eq!(a.block_bytes, 10 * 16 + 5 * 64 + 2 * 512);
            assert_eq!(a.skipped_pools, 1);
            assert_eq!(
                a.size_classes,
                vec![
                    SizeClass {
                        size: 16,
                        pools: 1,
                        blocks: 10
                    },
                    SizeClass {
                        size: 64,
                        pools: 1,
                        blocks: 5
                    },
                    SizeClass {
                        size: 512,
                        pools: 1,
                        blocks: 2
                    },
                ]
            );
        }
    }

    #[test]
    fn a_state_away_from_the_measured_offset_is_found() {
        for minor in [12, 13, 14] {
            for shift in [40u64, 8] {
                let f = fake_at(minor, shift);
                let a = f.reader.read(&f.img).unwrap().allocator;
                let a = a.unwrap_or_else(|| panic!("3.{minor} +{shift}"));
                assert_eq!((a.arenas, a.blocks), (2, 17), "3.{minor} +{shift}");
                // Found once, then kept.
                let again = f.reader.read(&f.img).unwrap().allocator.unwrap();
                assert_eq!(again.blocks, 17);
            }
        }
    }

    #[test]
    fn implausible_states_are_dropped() {
        let f = fake(13);
        let l = *f.reader.layout();
        // A GC state with `enabled` = 7 is not one.
        let interp = 0x20_0000u64;
        let mut bad = MemImage::new(TargetInfo::LINUX_X86_64);
        let mut rt = vec![0u8; (l.rt_interpreters_head + 8) as usize];
        put(&mut rt, l.rt_interpreters_head, &interp.to_le_bytes());
        bad.map(0x10_0000, rt);
        let mut is = vec![0u8; (l.is_gc + l.obmalloc_from_gc + 16) as usize];
        put(&mut is, l.is_gc + l.gc_enabled, &7u32.to_le_bytes());
        // An allocator pointer to a state whose current arenas exceed max.
        put(
            &mut is,
            l.is_gc + l.obmalloc_from_gc,
            &0x30_0000u64.to_le_bytes(),
        );
        bad.map(interp, is);
        let mut state = vec![0u8; 2048];
        put(&mut state, 520, &1u32.to_le_bytes());
        put(&mut state, 512 + 552, &5u64.to_le_bytes());
        bad.map(0x30_0000, state);
        let c = f.reader.read(&bad).unwrap();
        assert_eq!(c.interpreters, 1);
        assert!(c.gc.is_none());
        assert!(c.allocator.is_none());
    }

    #[test]
    fn unreadable_runtime_is_an_error() {
        let f = fake(12);
        let empty = MemImage::new(TargetInfo::LINUX_X86_64);
        assert!(f.reader.read(&empty).is_err());
    }
}
