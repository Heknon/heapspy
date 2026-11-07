//! Walking the Windows NT heap from its own metadata, the way WinDbg's
//! `!heap` does: every busy block of every NT heap in the image, read out of
//! memory with nothing asked of the target.
//!
//! This is what `malloc` (the UCRT, and the older `msvcrt.dll`) and
//! `HeapAlloc` hand out. pymalloc arenas are not here: CPython takes them
//! straight from `VirtualAlloc`.
//!
//! # Finding the heaps
//!
//! `PEB.ProcessHeaps` is not the whole list. On Windows 11 build 26300 it
//! held only the default heap, while `msvcrt.dll`'s private heap (which
//! `ctypes.cdll.msvcrt.malloc` uses) and other `HeapCreate` heaps were
//! missing from it. So the heaps are found by their signatures instead:
//! every private allocation base that starts with an NT heap header
//! (`SegmentSignature` 0xFFEEFFEE at +0x10, `Signature` 0xEEFFEEFF at +0x98,
//! and `Heap` at +0x28 pointing back at itself) is a heap. Heap indexes in
//! [`NativeBlock::heap`] are the `PEB.ProcessHeaps` order first, then the
//! heaps found only by scanning, by address.
//!
//! A segment heap (`Signature` 0xDDEEDDEE at +0x10, opted into by an
//! application manifest; `python.exe` does not) has a different layout and
//! is counted in [`WalkStats::segment_heaps_skipped`] but not walked.
//!
//! # One NT heap
//!
//! The heap is its own first segment; more segments hang off
//! `_HEAP.SegmentList`. Each segment is a run of blocks from `FirstEntry` to
//! `LastValidEntry`, each starting with a 16-byte `_HEAP_ENTRY`. Bytes 8..16
//! of the header are XORed with `_HEAP.Encoding` when `EncodeFlagMask` is
//! set (it always is on Windows 8 and later); decoded, they hold the block
//! size in 16-byte units, the flags (bit 0: busy), a checksum byte (the XOR
//! of the three bytes before it), and the size of the previous block. A run
//! of uncommitted pages inside a segment is listed in the segment's UCR list
//! and skipped. Each block's checksum and previous-size field are checked;
//! the first header that fails, or that cannot be read, ends that segment
//! (counted in [`WalkStats::segments_cut_short`]) and the walk goes on with
//! the next segment.
//!
//! A block's range is `[header + 8, header + 8 + size)`, not
//! `[header, header + size)`: on x64 the first 8 bytes of a header
//! (`PreviousBlockPrivateData`) belong to the block before it, whose data
//! may run into them. A busy block's `UnusedBytes` says so: a 0x20-byte
//! block with 8 unused bytes holds 0x18 bytes from header + 0x10, up to
//! header + 0x28. So the range covers the encoded header half and all of
//! the data, and the pointer the program holds (header + 0x10) is 8 bytes
//! into it. LFH blocks are laid out the same way.
//!
//! Allocations above the heap's `VirtualMemoryThreshold` (about 512 KiB)
//! get their own `VirtualAlloc` and are listed in
//! `_HEAP.VirtualAllocdBlocks`. Their list entry sits at a random page
//! offset inside the allocation (a 1 MiB `malloc` returned `base + 0x5040`),
//! so the whole allocation is reported, as [`NativeBlockKind::Large`].
//!
//! # The low-fragmentation heap
//!
//! The LFH carves same-sized small blocks out of "user blocks": busy backend
//! blocks with flag 0x08 whose data starts with a `_HEAP_USERDATA_HEADER`
//! (signature 0xF0E0D0C0 at +0x14). Its subsegment (pointer at +0) gives the
//! block size and count, and the header carries a bitmap with one bit per
//! block, set when busy. The first block's offset and the stride are stored
//! in `EncodedOffsets`, XORed with a secret key (derived from `RtlpLFHKey`,
//! which is not exported) and the low 32 bits of the user blocks' address.
//!
//! The offset is the header size (`0x30` plus the bitmap in whole u64
//! words, rounded up to 16) or, in about one area in eight on Windows 11
//! build 26300, 0x10 more. So heapspy tries each offset from that minimum
//! up to 0x30 past it, and keeps those where every block's header agrees
//! with the bitmap: the last header byte (`UnusedBytes`) is exactly 0x80
//! for a free block and 0x80 plus the unused byte count for a busy one.
//! Areas where exactly one offset passes vote for the key that offset
//! implies; the key with most votes is the heap's (on the processes tried,
//! every such area gave the same key). An area is decoded only when its
//! `EncodedOffsets`, decoded with that key, give the subsegment's stride and
//! an offset that passed. Then each busy block is reported as an
//! [`NativeBlockKind::Allocation`] of the full stride. Otherwise the area is
//! reported whole as one [`NativeBlockKind::SmallBlockContainer`]. The pages
//! past the last block of a large area may be decommitted, so they are not
//! read.
//!
//! The busy block holding the `_LFH_HEAP` itself (`_HEAP.FrontEndHeap`) is
//! allocator bookkeeping and is left out.
//!
//! # Layouts
//!
//! The offsets below are those of 64-bit Windows 10 and 11. Each one was
//! read back from a live process on Windows 11 build 26300 (x64) and checked
//! against `RtlQueryProcessDebugInformation`'s block list; see
//! `docs/windows.md`. ARM64 uses the same structures but was not tested.
//!
//! # Robustness
//!
//! Every pointer comes from target memory and may be garbage. Lists are
//! walked with a visited set and a length cap; block walks only move
//! forward and stop at the segment's end. Nothing here panics or loops on a
//! corrupt image; the worst case is that blocks are missing.

use std::collections::{HashMap, HashSet};

use crate::source::{MemorySource, MemorySourceExt, NativeBlock, NativeBlockKind};

#[cfg(test)]
pub(crate) mod tests;

/// `_HEAP` / `_HEAP_SEGMENT` field offsets, 64-bit Windows 10 and 11.
pub(crate) mod off {
    /// `_HEAP_SEGMENT.SegmentSignature` (u32), 0xFFEEFFEE.
    pub const SEGMENT_SIGNATURE: u64 = 0x10;
    /// `_HEAP_SEGMENT.SegmentListEntry` (`LIST_ENTRY`): link in `_HEAP.SegmentList`.
    pub const SEGMENT_LIST_ENTRY: u64 = 0x18;
    /// `_HEAP_SEGMENT.Heap`: the heap the segment belongs to.
    pub const SEGMENT_HEAP: u64 = 0x28;
    /// `_HEAP_SEGMENT.FirstEntry`: first block header.
    pub const FIRST_ENTRY: u64 = 0x40;
    /// `_HEAP_SEGMENT.LastValidEntry`: end of the segment.
    pub const LAST_VALID_ENTRY: u64 = 0x48;
    /// `_HEAP_SEGMENT.UCRSegmentList` (`LIST_ENTRY`) of `_HEAP_UCR_DESCRIPTOR`s.
    pub const UCR_SEGMENT_LIST: u64 = 0x60;
    /// `_HEAP.EncodeFlagMask` (u32): non-zero when headers are encoded.
    pub const ENCODE_FLAG_MASK: u64 = 0x7c;
    /// `_HEAP.Encoding` (`_HEAP_ENTRY`): XOR key for bytes 8..16 of headers.
    pub const ENCODING: u64 = 0x80;
    /// `_HEAP.Signature` (u32), 0xEEFFEEFF.
    pub const HEAP_SIGNATURE: u64 = 0x98;
    /// `_HEAP.VirtualAllocdBlocks` (`LIST_ENTRY`) of `_HEAP_VIRTUAL_ALLOC_ENTRY`s.
    pub const VIRTUAL_ALLOCD_BLOCKS: u64 = 0x110;
    /// `_HEAP.SegmentList` (`LIST_ENTRY`) of segments, through `SegmentListEntry`.
    pub const SEGMENT_LIST: u64 = 0x120;
    /// `_HEAP.FrontEndHeap`: the `_LFH_HEAP`, itself a busy block of the heap.
    pub const FRONT_END_HEAP: u64 = 0x1a8;

    /// `_HEAP_UCR_DESCRIPTOR.SegmentEntry`: link in `UCRSegmentList`.
    pub const UCR_SEGMENT_ENTRY: u64 = 0x10;
    /// `_HEAP_UCR_DESCRIPTOR.Address` and `.Size` of the uncommitted run.
    pub const UCR_ADDRESS: u64 = 0x20;
    pub const UCR_SIZE: u64 = 0x28;

    /// `_HEAP_VIRTUAL_ALLOC_ENTRY.CommitSize`, and `.BusyBlock` (a `_HEAP_ENTRY`).
    pub const VA_COMMIT_SIZE: u64 = 0x20;
    pub const VA_BUSY_BLOCK: u64 = 0x30;
    /// User data of a `VirtualAlloc`ed block starts here, after `BusyBlock`.
    pub const VA_HEADER_SIZE: u64 = 0x40;

    /// `_HEAP_USERDATA_HEADER` (at the start of LFH user blocks):
    /// `SubSegment` pointer, `Signature` (u32, 0xF0E0D0C0), `EncodedOffsets`
    /// (u32: first block offset | block stride << 16, XORed), and
    /// `BusyBitmap` (`_RTL_BITMAP_EX`: bit count u64, buffer pointer).
    pub const UD_SUBSEGMENT: u64 = 0x00;
    pub const UD_SIGNATURE: u64 = 0x14;
    pub const UD_ENCODED_OFFSETS: u64 = 0x18;
    pub const UD_BITMAP_BITS: u64 = 0x20;
    pub const UD_BITMAP_BUFFER: u64 = 0x28;
    /// Where the bitmap's words start (`BitmapData`), inline after the header.
    pub const UD_BITMAP_DATA: u64 = 0x30;

    /// `_HEAP_SUBSEGMENT.UserBlocks`, `.BlockSize` (u16, 16-byte units) and
    /// `.BlockCount` (u16).
    pub const SUB_USER_BLOCKS: u64 = 0x08;
    pub const SUB_BLOCK_SIZE: u64 = 0x24;
    pub const SUB_BLOCK_COUNT: u64 = 0x28;
}

pub(crate) const SEGMENT_SIGNATURE: u32 = 0xFFEE_FFEE;
pub(crate) const HEAP_SIGNATURE: u32 = 0xEEFF_EEFF;
pub(crate) const SEGMENT_HEAP_SIGNATURE: u32 = 0xDDEE_DDEE;
pub(crate) const USERDATA_SIGNATURE: u32 = 0xF0E0_D0C0;

/// `_HEAP_ENTRY.Flags`: the block is in use.
pub(crate) const FLAG_BUSY: u8 = 0x01;
/// `_HEAP_ENTRY.Flags` bit set on backend blocks that hold LFH user blocks.
pub(crate) const FLAG_LFH_USER_BLOCKS: u8 = 0x08;
/// Block headers and sizes are in units of this many bytes.
pub(crate) const GRANULARITY: u64 = 16;
/// A block owns its memory from this far past its header: the header's
/// first 8 bytes are the previous block's (see the module docs).
pub(crate) const OWNED_FROM: u64 = 8;

/// Caps for lists read out of target memory, so a corrupt list ends.
const MAX_SEGMENTS: usize = 1 << 16;
const MAX_UCRS: usize = 1 << 20;
const MAX_VIRTUAL_BLOCKS: usize = 1 << 22;
/// A segment longer than this is taken as corrupt.
const MAX_SEGMENT_SPAN: u64 = 1 << 40;

/// What the walk did, for diagnostics and tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalkStats {
    /// NT heaps walked.
    pub nt_heaps: u32,
    /// Segment heaps found and not walked.
    pub segment_heaps_skipped: u32,
    /// Segments walked, over all heaps.
    pub segments: u32,
    /// Segments whose block walk stopped before `LastValidEntry` (bad or
    /// unreadable header); the blocks before that point are kept.
    pub segments_cut_short: u32,
    /// `VirtualAlloc`ed blocks.
    pub large_blocks: u32,
    /// LFH user blocks decoded into single blocks.
    pub lfh_decoded: u32,
    /// LFH user blocks reported whole, as a [`NativeBlockKind::SmallBlockContainer`].
    pub lfh_whole: u32,
    /// Busy blocks left out because they hold the heap's `_LFH_HEAP`.
    pub front_end_skipped: u32,
    /// Blocks dropped because they overlapped one already listed (corrupt lists).
    pub overlaps_dropped: u32,
}

/// The result of [`walk`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeapWalk {
    /// Sorted by start, non-overlapping.
    pub blocks: Vec<NativeBlock>,
    /// Heap base addresses, indexed by [`NativeBlock::heap`]. Entries that
    /// turned out not to be NT heaps are still listed (their index is taken
    /// from `PEB.ProcessHeaps`) but have no blocks.
    pub heaps: Vec<u64>,
    pub stats: WalkStats,
}

/// Walk every NT heap in `src`.
///
/// `listed` is `PEB.ProcessHeaps`, `candidates` the allocation bases to
/// probe for heap headers (every private allocation, in practice).
/// `allocation_span(addr)` returns the `[start, end)` of the whole
/// `VirtualAlloc` reservation containing `addr`, if the source knows it; it
/// sizes [`NativeBlockKind::Large`] blocks.
///
/// Returns `None` when no NT heap was found.
pub fn walk<S: MemorySource + ?Sized>(
    src: &S,
    listed: &[u64],
    candidates: &[u64],
    allocation_span: &dyn Fn(u64) -> Option<(u64, u64)>,
) -> Option<HeapWalk> {
    let mut out = HeapWalk {
        heaps: listed.to_vec(),
        ..HeapWalk::default()
    };
    let mut seen: HashSet<u64> = listed.iter().copied().collect();
    let mut extra: Vec<u64> = candidates
        .iter()
        .copied()
        .filter(|c| !seen.contains(c))
        .collect();
    extra.sort_unstable();
    extra.dedup();
    for c in extra {
        if !matches!(probe(src, c), Probe::Other) && seen.insert(c) {
            out.heaps.push(c);
        }
    }

    let mut blocks = Vec::new();
    for (index, &base) in out.heaps.iter().enumerate() {
        match probe(src, base) {
            Probe::Nt => {}
            Probe::Segment => {
                out.stats.segment_heaps_skipped += 1;
                continue;
            }
            Probe::Other => continue,
        }
        let Some(heap) = Heap::read(src, base, index as u32) else {
            continue;
        };
        out.stats.nt_heaps += 1;
        heap.walk(src, allocation_span, &mut blocks, &mut out.stats);
    }
    if out.stats.nt_heaps == 0 {
        return None;
    }

    blocks.sort_by_key(|b| b.start);
    let mut end = 0u64;
    blocks.retain(|b| {
        if b.start < end {
            out.stats.overlaps_dropped += 1;
            return false;
        }
        end = b.start.saturating_add(b.size);
        true
    });
    out.blocks = blocks;
    Some(out)
}

enum Probe {
    Nt,
    Segment,
    Other,
}

/// What kind of heap, if any, starts at `addr`.
fn probe<S: MemorySource + ?Sized>(src: &S, addr: u64) -> Probe {
    let Some(sig_at) = addr.checked_add(off::SEGMENT_SIGNATURE) else {
        return Probe::Other;
    };
    match src.read_u32(sig_at) {
        Ok(SEGMENT_SIGNATURE) => {}
        Ok(SEGMENT_HEAP_SIGNATURE) => return Probe::Segment,
        _ => return Probe::Other,
    }
    // A segment other than the first also carries 0xFFEEFFEE; only the heap
    // itself has the heap signature and points at itself.
    let own = src.read_ptr(addr.wrapping_add(off::SEGMENT_HEAP)).ok() == Some(addr);
    let sig = src.read_u32(addr.wrapping_add(off::HEAP_SIGNATURE)).ok() == Some(HEAP_SIGNATURE);
    if own && sig {
        Probe::Nt
    } else {
        Probe::Other
    }
}

/// A decoded `_HEAP_ENTRY` (bytes 8..16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Block size in bytes, header included.
    pub size: u64,
    pub flags: u8,
    /// Previous block's size in bytes.
    pub prev_size: u64,
    pub unused: u8,
}

/// Decode a 16-byte block header with the heap's key (`None`: not encoded).
/// Returns `None` when the checksum does not match.
pub(crate) fn decode_entry(raw: &[u8; 16], key: Option<&[u8; 8]>) -> Option<Entry> {
    let mut b = [0u8; 8];
    b.copy_from_slice(&raw[8..16]);
    if let Some(k) = key {
        b.iter_mut().zip(k).for_each(|(x, k)| *x ^= k);
    }
    if b[3] != b[0] ^ b[1] ^ b[2] {
        return None;
    }
    Some(Entry {
        size: u64::from(u16::from_le_bytes([b[0], b[1]])) * GRANULARITY,
        flags: b[2],
        prev_size: u64::from(u16::from_le_bytes([b[4], b[5]])) * GRANULARITY,
        unused: b[7],
    })
}

/// LFH user blocks found by the segment walk, decoded once the heap's key
/// is known.
struct UserBlocks {
    /// The backend block: header address and size.
    start: u64,
    size: u64,
    /// Present when the header and subsegment checked out.
    layout: Option<LfhLayout>,
}

#[derive(Clone, Copy)]
pub(crate) struct LfhLayout {
    /// Address of the `_HEAP_USERDATA_HEADER`.
    pub user: u64,
    /// Bytes from `user` to the end of the backend block.
    pub len: u64,
    pub stride: u64,
    pub count: u64,
    /// `_HEAP_USERDATA_HEADER.EncodedOffsets`.
    pub encoded: u32,
}

impl LfhLayout {
    /// The key that `first` as the first block offset implies.
    fn key_for(&self, first: u64) -> u32 {
        self.encoded ^ (self.user as u32) ^ (first | self.stride << 16) as u32
    }
}

/// How far past the end of the header and bitmap the first LFH block may
/// start. Seen: 0 and 0x10.
const LFH_FIRST_SLACK: u64 = 0x30;

struct Heap {
    base: u64,
    index: u32,
    key: Option<[u8; 8]>,
    front_end: u64,
}

impl Heap {
    fn read<S: MemorySource + ?Sized>(src: &S, base: u64, index: u32) -> Option<Heap> {
        let mask = src
            .read_u32(base.checked_add(off::ENCODE_FLAG_MASK)?)
            .ok()?;
        let enc = src.read_array::<16>(base + off::ENCODING).ok()?;
        let key = (mask != 0).then(|| enc[8..16].try_into().unwrap());
        Some(Heap {
            base,
            index,
            key,
            front_end: src.read_ptr(base + off::FRONT_END_HEAP).unwrap_or(0),
        })
    }

    fn block(&self, start: u64, size: u64, kind: NativeBlockKind) -> NativeBlock {
        NativeBlock {
            start,
            size,
            kind,
            heap: self.index,
        }
    }

    fn walk<S: MemorySource + ?Sized>(
        &self,
        src: &S,
        allocation_span: &dyn Fn(u64) -> Option<(u64, u64)>,
        out: &mut Vec<NativeBlock>,
        stats: &mut WalkStats,
    ) {
        let mut lfh = Vec::new();
        let head = self.base + off::SEGMENT_LIST;
        for link in list(src, head, MAX_SEGMENTS) {
            let seg = link.wrapping_sub(off::SEGMENT_LIST_ENTRY);
            stats.segments += 1;
            if !self.walk_segment(src, seg, out, &mut lfh, stats) {
                stats.segments_cut_short += 1;
            }
        }
        self.decode_lfh(src, lfh, out, stats);

        let head = self.base + off::VIRTUAL_ALLOCD_BLOCKS;
        for entry in list(src, head, MAX_VIRTUAL_BLOCKS) {
            if let Some(b) = self.large_block(src, entry, allocation_span) {
                stats.large_blocks += 1;
                out.push(b);
            }
        }
    }

    /// Walk one segment's blocks. Returns `false` if the walk stopped before
    /// the segment's end.
    fn walk_segment<S: MemorySource + ?Sized>(
        &self,
        src: &S,
        seg: u64,
        out: &mut Vec<NativeBlock>,
        lfh: &mut Vec<UserBlocks>,
        stats: &mut WalkStats,
    ) -> bool {
        let Ok(hdr) = src.read_vec(seg, 0x70) else {
            return false;
        };
        let u32_at =
            |o: u64| u32::from_le_bytes(hdr[o as usize..o as usize + 4].try_into().unwrap());
        let u64_at =
            |o: u64| u64::from_le_bytes(hdr[o as usize..o as usize + 8].try_into().unwrap());
        if u32_at(off::SEGMENT_SIGNATURE) != SEGMENT_SIGNATURE
            || u64_at(off::SEGMENT_HEAP) != self.base
        {
            return false;
        }
        let (first, last) = (u64_at(off::FIRST_ENTRY), u64_at(off::LAST_VALID_ENTRY));
        if first < seg || last <= first || last - first > MAX_SEGMENT_SPAN {
            return false;
        }
        let ucrs = uncommitted_ranges(src, seg, first, last);
        let mut next_ucr = 0;
        let mut cur = first;
        let mut prev_size: Option<u64> = None;
        while cur < last {
            while ucrs.get(next_ucr).is_some_and(|&(a, _)| a < cur) {
                next_ucr += 1;
            }
            let limit = match ucrs.get(next_ucr) {
                // Segments keep an empty descriptor at LastValidEntry; one
                // anywhere else means nothing either.
                Some(&(a, 0)) if a == cur => {
                    next_ucr += 1;
                    continue;
                }
                Some(&(a, size)) if a == cur => {
                    cur = cur.saturating_add(size);
                    prev_size = None;
                    continue;
                }
                Some(&(a, _)) => a,
                None => last,
            };
            let Ok(raw) = src.read_array::<16>(cur) else {
                return false;
            };
            let Some(e) = decode_entry(&raw, self.key.as_ref()) else {
                return false;
            };
            if e.size == 0 || e.size > limit - cur || prev_size.is_some_and(|p| p != e.prev_size) {
                return false;
            }
            if e.flags & FLAG_BUSY != 0 && cur + GRANULARITY == self.front_end {
                stats.front_end_skipped += 1;
            } else if e.flags & FLAG_BUSY != 0 {
                match self.user_blocks(src, cur, &e) {
                    Some(ub) => lfh.push(ub),
                    None => {
                        out.push(self.block(cur + OWNED_FROM, e.size, NativeBlockKind::Allocation))
                    }
                }
            }
            prev_size = Some(e.size);
            cur += e.size;
        }
        true
    }

    /// If the busy block at `start` holds LFH user blocks, describe them.
    fn user_blocks<S: MemorySource + ?Sized>(
        &self,
        src: &S,
        start: u64,
        e: &Entry,
    ) -> Option<UserBlocks> {
        if e.flags & FLAG_LFH_USER_BLOCKS == 0 || e.size < GRANULARITY + off::UD_BITMAP_DATA {
            return None;
        }
        let user = start + GRANULARITY;
        let ud = src.read_array::<0x30>(user).ok()?;
        let u32_at =
            |o: u64| u32::from_le_bytes(ud[o as usize..o as usize + 4].try_into().unwrap());
        let u64_at =
            |o: u64| u64::from_le_bytes(ud[o as usize..o as usize + 8].try_into().unwrap());
        if u32_at(off::UD_SIGNATURE) != USERDATA_SIGNATURE {
            return None;
        }
        let layout = (|| {
            let sub = u64_at(off::UD_SUBSEGMENT);
            if src.read_ptr(sub.checked_add(off::SUB_USER_BLOCKS)?).ok()? != user {
                return None;
            }
            let stride = u64::from(src.read_u16(sub + off::SUB_BLOCK_SIZE).ok()?) * GRANULARITY;
            let count = u64::from(src.read_u16(sub + off::SUB_BLOCK_COUNT).ok()?);
            if stride < GRANULARITY
                || count == 0
                || u64_at(off::UD_BITMAP_BITS) != count
                || u64_at(off::UD_BITMAP_BUFFER) != user + off::UD_BITMAP_DATA
            {
                return None;
            }
            let len = e.size - GRANULARITY;
            if lfh_min_first_offset(count) + count * stride > len || stride > 0xffff {
                return None;
            }
            Some(LfhLayout {
                user,
                len,
                stride,
                count,
                encoded: u32_at(off::UD_ENCODED_OFFSETS),
            })
        })();
        Some(UserBlocks {
            start,
            size: e.size,
            layout,
        })
    }

    /// Decode the heap's LFH user blocks, or report them whole.
    ///
    /// For each user blocks area, every first-block offset from the end of
    /// the header and bitmap up to [`LFH_FIRST_SLACK`] past it is tried
    /// against the per-block check of [`lfh_busy_blocks`]. Areas where
    /// exactly one offset passes vote for the key that offset implies. An
    /// area is decoded only when its stored offsets, decoded with the
    /// winning key, name a passing offset and the subsegment's stride.
    fn decode_lfh<S: MemorySource + ?Sized>(
        &self,
        src: &S,
        all: Vec<UserBlocks>,
        out: &mut Vec<NativeBlock>,
        stats: &mut WalkStats,
    ) {
        // (first offset, busy block starts) for each passing offset.
        let passing: Vec<Vec<(u64, Vec<u64>)>> = all
            .iter()
            .map(|ub| ub.layout.map_or_else(Vec::new, |l| lfh_candidates(src, &l)))
            .collect();
        let mut votes: HashMap<u32, usize> = HashMap::new();
        for (ub, p) in all.iter().zip(&passing) {
            if let (Some(l), [(first, _)]) = (ub.layout, p.as_slice()) {
                *votes.entry(l.key_for(*first)).or_default() += 1;
            }
        }
        // Ties go to the smaller key, so the result does not depend on
        // HashMap order.
        let key = votes
            .into_iter()
            .max_by_key(|&(k, n)| (n, std::cmp::Reverse(k)))
            .map(|(k, _)| k);
        for (ub, p) in all.into_iter().zip(passing) {
            let decoded = match (ub.layout, key) {
                (Some(l), Some(k)) => {
                    let d = l.encoded ^ (l.user as u32) ^ k;
                    let (first, stride) = (u64::from(d & 0xffff), u64::from(d >> 16));
                    (stride == l.stride)
                        .then(|| p.into_iter().find(|(f, _)| *f == first))
                        .flatten()
                        .map(|(_, busy)| (l.stride, busy))
                }
                _ => None,
            };
            match decoded {
                Some((stride, busy)) => {
                    stats.lfh_decoded += 1;
                    out.extend(
                        busy.into_iter().map(|s| {
                            self.block(s + OWNED_FROM, stride, NativeBlockKind::Allocation)
                        }),
                    );
                }
                None => {
                    stats.lfh_whole += 1;
                    out.push(self.block(
                        ub.start + OWNED_FROM,
                        ub.size,
                        NativeBlockKind::SmallBlockContainer,
                    ));
                }
            }
        }
    }

    /// A `VirtualAlloc`ed block from its `_HEAP_VIRTUAL_ALLOC_ENTRY`.
    fn large_block<S: MemorySource + ?Sized>(
        &self,
        src: &S,
        entry: u64,
        allocation_span: &dyn Fn(u64) -> Option<(u64, u64)>,
    ) -> Option<NativeBlock> {
        let commit = src.read_u64(entry.checked_add(off::VA_COMMIT_SIZE)?).ok()?;
        let raw = src.read_array::<16>(entry + off::VA_BUSY_BLOCK).ok()?;
        let e = decode_entry(&raw, self.key.as_ref())?;
        if e.flags & FLAG_BUSY == 0 || commit < off::VA_HEADER_SIZE {
            return None;
        }
        let user_end = entry.checked_add(off::VA_HEADER_SIZE)?;
        let (start, end) = match allocation_span(entry) {
            Some((s, end)) if s <= entry && user_end <= end => (s, end),
            // Without the reservation, report what the entry vouches for:
            // header and committed data.
            _ => (entry, entry.checked_add(commit)?),
        };
        Some(self.block(start, end - start, NativeBlockKind::Large))
    }
}

/// The smallest offset the first LFH block can have from the
/// `_HEAP_USERDATA_HEADER`: the 0x30-byte header and the busy bitmap (whole
/// u64 words), rounded up to 16. Usually it is exactly this; on Windows 11
/// build 26300 some areas put the first block 0x10 further.
pub(crate) fn lfh_min_first_offset(count: u64) -> u64 {
    let bitmap = count.div_ceil(64) * 8;
    (off::UD_BITMAP_DATA + bitmap).next_multiple_of(GRANULARITY)
}

/// Every first-block offset (from the minimum up to [`LFH_FIRST_SLACK`]
/// past it) at which the area's block headers agree with its bitmap, with
/// the busy block starts at that offset.
fn lfh_candidates<S: MemorySource + ?Sized>(src: &S, l: &LfhLayout) -> Vec<(u64, Vec<u64>)> {
    let min = lfh_min_first_offset(l.count);
    let firsts: Vec<u64> = (0..=LFH_FIRST_SLACK / GRANULARITY)
        .map(|j| min + j * GRANULARITY)
        .filter(|first| first + l.count * l.stride <= l.len)
        .collect();
    // One read for the candidates to share, as long as the furthest one
    // needs and the image allows: the pages past the last block may be
    // decommitted and so not captured, which rules out candidates that
    // reach into them.
    let Some(bytes) = firsts.iter().rev().find_map(|first| {
        let n = usize::try_from(first + l.count * l.stride).ok()?;
        src.read_vec(l.user, n).ok()
    }) else {
        return Vec::new();
    };
    firsts
        .into_iter()
        .filter(|first| first + l.count * l.stride <= bytes.len() as u64)
        .filter_map(|first| lfh_busy_blocks(&bytes, l, first).map(|b| (first, b)))
        .collect()
}

/// Start addresses of the busy blocks of one LFH user blocks area (`bytes`,
/// read from `l.user`) with its first block at `first`, or `None` if any
/// block's header disagrees with the bitmap.
pub(crate) fn lfh_busy_blocks(bytes: &[u8], l: &LfhLayout, first: u64) -> Option<Vec<u64>> {
    let bitmap = bytes.get(off::UD_BITMAP_DATA as usize..)?;
    let mut busy = Vec::new();
    for i in 0..l.count as usize {
        let is_busy = *bitmap.get(i / 8)? >> (i % 8) & 1 == 1;
        let block = first as usize + i * l.stride as usize;
        // `_HEAP_ENTRY.UnusedBytes` of an LFH block: 0x80 when free, 0x80
        // plus the unused byte count (at least 8, the header) when busy.
        let unused = *bytes.get(block + 15)?;
        if unused & 0x80 == 0 || (unused == 0x80) == is_busy {
            return None;
        }
        if is_busy {
            busy.push(l.user + block as u64);
        }
    }
    Some(busy)
}

/// The uncommitted runs of a segment, `(address, size)` sorted by address,
/// from its `UCRSegmentList`. Descriptors outside the segment are ignored.
fn uncommitted_ranges<S: MemorySource + ?Sized>(
    src: &S,
    seg: u64,
    first: u64,
    last: u64,
) -> Vec<(u64, u64)> {
    let head = seg + off::UCR_SEGMENT_LIST;
    let mut v: Vec<(u64, u64)> = list(src, head, MAX_UCRS)
        .filter_map(|link| {
            let d = link.wrapping_sub(off::UCR_SEGMENT_ENTRY);
            let addr = src.read_ptr(d.checked_add(off::UCR_ADDRESS)?).ok()?;
            let size = src.read_u64(d.checked_add(off::UCR_SIZE)?).ok()?;
            (addr >= first && addr <= last).then_some((addr, size))
        })
        .collect();
    v.sort_unstable();
    v
}

/// The entries of a circular doubly linked `LIST_ENTRY` list with its head
/// at `head`, following `Flink`. Ends at the head, at an unreadable or
/// repeated link, or after `cap` entries.
fn list<S: MemorySource + ?Sized>(
    src: &S,
    head: u64,
    cap: usize,
) -> impl Iterator<Item = u64> + '_ {
    let mut seen = HashSet::new();
    let mut cur = src.read_ptr(head).ok();
    std::iter::from_fn(move || {
        let link = cur.take()?;
        if link == head || link == 0 || seen.len() >= cap || !seen.insert(link) {
            return None;
        }
        cur = src.read_ptr(link).ok();
        Some(link)
    })
}
