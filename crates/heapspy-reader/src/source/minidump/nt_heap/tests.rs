//! NT heap walker tests on synthetic heaps.
//!
//! [`Img`] lays out heap structures byte by byte at chosen addresses, with
//! the same offsets and header encoding the walker reads, so each test
//! builds exactly the heap it needs and checks what the walk returns.

use super::*;
use crate::source::mem::MemImage;
use crate::source::TargetInfo;

pub(crate) const HEAP: u64 = 0x0000_0100_0000_0000;
/// Where the first block of a heap built by [`Img::heap`] starts.
pub(crate) const FIRST: u64 = 0x200;
/// Its checksum byte is not the XOR of the three before it, so a header
/// read with the wrong key (or none) fails its checksum.
pub(crate) const KEY: [u8; 8] = [0x13, 0x57, 0x9b, 0x00, 0x24, 0x68, 0xac, 0xe0];
/// The LFH key used for `EncodedOffsets`.
const LFH_KEY: u32 = 0x5a5a_1234;

/// Memory regions under construction.
#[derive(Clone, Default)]
pub(crate) struct Img {
    pub regions: Vec<(u64, Vec<u8>)>,
}

impl Img {
    pub fn region(&mut self, base: u64, len: usize) -> &mut Self {
        self.regions.push((base, vec![0; len]));
        self
    }

    pub fn w(&mut self, addr: u64, bytes: &[u8]) {
        let (base, buf) = self
            .regions
            .iter_mut()
            .find(|(b, v)| *b <= addr && addr + bytes.len() as u64 <= b + v.len() as u64)
            .unwrap_or_else(|| panic!("write at {addr:#x} outside every region"));
        let o = (addr - *base) as usize;
        buf[o..o + bytes.len()].copy_from_slice(bytes);
    }

    pub fn u16(&mut self, addr: u64, v: u16) {
        self.w(addr, &v.to_le_bytes());
    }
    pub fn u32(&mut self, addr: u64, v: u32) {
        self.w(addr, &v.to_le_bytes());
    }
    pub fn u64(&mut self, addr: u64, v: u64) {
        self.w(addr, &v.to_le_bytes());
    }

    pub fn mem(&self) -> MemImage {
        let mut m = MemImage::new(TargetInfo::WINDOWS_X86_64);
        for (b, v) in &self.regions {
            m.map(*b, v.clone());
        }
        m
    }

    /// A circular `LIST_ENTRY` list: `head` and each link in `links`.
    pub fn list(&mut self, head: u64, links: &[u64]) {
        let all: Vec<u64> = std::iter::once(head).chain(links.iter().copied()).collect();
        for (i, &l) in all.iter().enumerate() {
            self.u64(l, all[(i + 1) % all.len()]);
            self.u64(l + 8, all[(i + all.len() - 1) % all.len()]);
        }
    }

    /// A 16-byte block header at `at`, encoded with `key`.
    pub fn entry(&mut self, at: u64, size: u64, flags: u8, prev: u64, unused: u8, key: &[u8; 8]) {
        let s = ((size / GRANULARITY) as u16).to_le_bytes();
        let p = ((prev / GRANULARITY) as u16).to_le_bytes();
        let mut b = [
            s[0],
            s[1],
            flags,
            s[0] ^ s[1] ^ flags,
            p[0],
            p[1],
            0,
            unused,
        ];
        b.iter_mut().zip(key).for_each(|(x, k)| *x ^= k);
        self.w(at + 8, &b);
    }

    /// Segment header fields at `seg`, with an empty UCR list.
    pub fn segment(&mut self, seg: u64, heap: u64, first: u64, last: u64) {
        self.u32(seg + off::SEGMENT_SIGNATURE, SEGMENT_SIGNATURE);
        self.u64(seg + off::SEGMENT_HEAP, heap);
        self.u64(seg + off::FIRST_ENTRY, first);
        self.u64(seg + off::LAST_VALID_ENTRY, last);
        self.list(seg + off::UCR_SEGMENT_LIST, &[]);
    }

    /// A heap at `base` whose first segment ends at `base + len`, with
    /// encoded headers, one segment (itself), no large blocks and no LFH.
    /// The region must exist.
    pub fn heap(&mut self, base: u64, len: u64) {
        self.segment(base, base, base + FIRST, base + len);
        self.u32(base + off::ENCODE_FLAG_MASK, 0x10_0000);
        self.w(base + off::ENCODING + 8, &KEY);
        self.u32(base + off::HEAP_SIGNATURE, HEAP_SIGNATURE);
        self.list(base + off::VIRTUAL_ALLOCD_BLOCKS, &[]);
        self.list(base + off::SEGMENT_LIST, &[base + off::SEGMENT_LIST_ENTRY]);
    }

    /// Consecutive blocks from `first`: `(size, flags, unused)`. Returns
    /// their header addresses.
    pub fn blocks(&mut self, first: u64, blocks: &[(u64, u8, u8)]) -> Vec<u64> {
        let mut at = first;
        let mut prev = 0;
        let mut out = Vec::new();
        for &(size, flags, unused) in blocks {
            self.entry(at, size, flags, prev, unused, &KEY);
            out.push(at);
            prev = size;
            at += size;
        }
        out
    }

    /// LFH user blocks in the backend block at `hdr` (its header is not
    /// written here): `busy[i]` per block, the first block `extra` bytes
    /// past the minimum offset, the subsegment at `sub`.
    pub fn user_blocks(&mut self, hdr: u64, sub: u64, stride: u64, busy: &[bool], extra: u64) {
        let user = hdr + GRANULARITY;
        let count = busy.len() as u64;
        let first = lfh_min_first_offset(count) + extra;
        self.u64(user + off::UD_SUBSEGMENT, sub);
        self.u32(user + off::UD_SIGNATURE, USERDATA_SIGNATURE);
        let encoded = (first | stride << 16) as u32 ^ user as u32 ^ LFH_KEY;
        self.u32(user + off::UD_ENCODED_OFFSETS, encoded);
        self.u64(user + off::UD_BITMAP_BITS, count);
        self.u64(user + off::UD_BITMAP_BUFFER, user + off::UD_BITMAP_DATA);
        for (i, &b) in busy.iter().enumerate() {
            if b {
                let at = user + off::UD_BITMAP_DATA + i as u64 / 8;
                let mut byte = [0u8];
                byte[0] = self.byte(at) | 1 << (i % 8);
                self.w(at, &byte);
            }
            let block = user + first + i as u64 * stride;
            self.w(block + 15, &[if b { 0x80 | 0x10 } else { 0x80 }]);
        }
        self.u64(sub + off::SUB_USER_BLOCKS, user);
        self.u16(sub + off::SUB_BLOCK_SIZE, (stride / GRANULARITY) as u16);
        self.u16(sub + off::SUB_BLOCK_COUNT, count as u16);
    }

    fn byte(&self, addr: u64) -> u8 {
        let (b, v) = self
            .regions
            .iter()
            .find(|(b, v)| *b <= addr && addr < b + v.len() as u64)
            .unwrap();
        v[(addr - b) as usize]
    }
}

fn no_span(_: u64) -> Option<(u64, u64)> {
    None
}

fn run(img: &Img, listed: &[u64], candidates: &[u64]) -> Option<HeapWalk> {
    walk(&img.mem(), listed, candidates, &no_span)
}

fn alloc(start: u64, size: u64) -> NativeBlock {
    NativeBlock {
        start,
        size,
        kind: NativeBlockKind::Allocation,
        heap: 0,
    }
}

/// A one-segment heap of 0x1000 bytes: busy 0x40, free 0x100, busy 0x30,
/// busy 0xc90 (filling the rest).
fn simple() -> (Img, Vec<u64>) {
    let mut img = Img::default();
    img.region(HEAP, 0x1000);
    img.heap(HEAP, 0x1000);
    let h = img.blocks(
        HEAP + FIRST,
        &[
            (0x40, 1, 0x10),
            (0x100, 0, 0),
            (0x30, 1, 0x8),
            (0xc90, 1, 0x10),
        ],
    );
    (img, h)
}

#[test]
fn header_decoding() {
    let mut img = Img::default();
    img.region(HEAP, 0x20);
    img.entry(HEAP, 0x1230, 0x09, 0x40, 0x18, &KEY);
    let raw: [u8; 16] = img.regions[0].1[..16].try_into().unwrap();
    let e = decode_entry(&raw, Some(&KEY)).unwrap();
    assert_eq!(
        e,
        Entry {
            size: 0x1230,
            flags: 0x09,
            prev_size: 0x40,
            unused: 0x18
        }
    );
    // Wrong key, or reading it as unencoded: the checksum fails (see
    // [`KEY`]; for a random key it fails 255 times in 256).
    assert_eq!(decode_entry(&raw, None), None);
    assert_eq!(decode_entry(&raw, Some(&[0xff; 8])), None);
    // An unencoded header decodes without a key.
    let mut img = Img::default();
    img.region(HEAP, 0x20);
    img.entry(HEAP, 0x20, 1, 0, 8, &[0; 8]);
    let raw: [u8; 16] = img.regions[0].1[..16].try_into().unwrap();
    assert_eq!(decode_entry(&raw, None).unwrap().size, 0x20);
    // Any single flipped bit of the checksummed bytes is caught.
    for bit in 0..32 {
        let mut r = raw;
        r[8 + bit / 8] ^= 1 << (bit % 8);
        assert_eq!(decode_entry(&r, None), None, "bit {bit}");
    }
}

#[test]
fn walks_one_segment() {
    let (img, h) = simple();
    let w = run(&img, &[HEAP], &[]).unwrap();
    assert_eq!(
        w.blocks,
        vec![
            alloc(h[0] + 8, 0x40),
            alloc(h[2] + 8, 0x30),
            alloc(h[3] + 8, 0xc90)
        ]
    );
    assert_eq!(w.heaps, vec![HEAP]);
    assert_eq!(w.stats.nt_heaps, 1);
    assert_eq!(w.stats.segments, 1);
    assert_eq!(w.stats.segments_cut_short, 0);
}

#[test]
fn unencoded_heap() {
    let mut img = Img::default();
    img.region(HEAP, 0x1000);
    img.heap(HEAP, 0x1000);
    img.u32(HEAP + off::ENCODE_FLAG_MASK, 0);
    img.entry(HEAP + FIRST, 0xe00, 1, 0, 0x10, &[0; 8]);
    let w = run(&img, &[HEAP], &[]).unwrap();
    assert_eq!(w.blocks, vec![alloc(HEAP + FIRST + 8, 0xe00)]);
}

#[test]
fn corrupt_headers_end_the_segment_cleanly() {
    let (img, h) = simple();
    // Each way a header can be wrong: bad checksum, size 0, size past the
    // segment end, previous size that does not match; then unreadable.
    let cases: [fn(&mut Img, u64); 4] = [
        |i, at| i.w(at + 8, &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]),
        |i, at| i.entry(at, 0, 1, 0x100, 8, &KEY),
        |i, at| i.entry(at, 0xfff0, 1, 0x100, 8, &KEY),
        |i, at| i.entry(at, 0x30, 1, 0x200, 8, &KEY),
    ];
    for (n, corrupt) in cases.iter().enumerate() {
        let mut img = img.clone();
        corrupt(&mut img, h[2]);
        let w = run(&img, &[HEAP], &[]).unwrap();
        assert_eq!(w.blocks, vec![alloc(h[0] + 8, 0x40)], "case {n}");
        assert_eq!(w.stats.segments_cut_short, 1, "case {n}");
    }
    // The segment's memory ends early.
    let mut img = img.clone();
    img.regions[0].1.truncate((h[2] - HEAP) as usize + 4);
    let w = run(&img, &[HEAP], &[]).unwrap();
    assert_eq!(w.blocks, vec![alloc(h[0] + 8, 0x40)]);
    assert_eq!(w.stats.segments_cut_short, 1);
}

#[test]
fn every_corrupted_byte_ends_cleanly() {
    let (img, _) = simple();
    let mut base = img.clone();
    // A second segment and a large block, so their lists are corrupted too.
    let seg = HEAP + 0x10_0000;
    base.region(seg, 0x400);
    base.segment(seg, HEAP, seg + 0x70, seg + 0x400);
    base.blocks(seg + 0x70, &[(0x390, 1, 0x10)]);
    base.list(
        HEAP + off::SEGMENT_LIST,
        &[
            HEAP + off::SEGMENT_LIST_ENTRY,
            seg + off::SEGMENT_LIST_ENTRY,
        ],
    );
    let va = HEAP + 0x20_0000;
    base.region(va, 0x100);
    base.u64(va + off::VA_COMMIT_SIZE, 0x100);
    base.entry(va + off::VA_BUSY_BLOCK, 0x100, 3, 0, 0, &KEY);
    base.list(HEAP + off::VIRTUAL_ALLOCD_BLOCKS, &[va]);
    assert_eq!(run(&base, &[HEAP], &[]).unwrap().blocks.len(), 5);
    for r in 0..base.regions.len() {
        for i in 0..base.regions[r].1.len() {
            for x in [0xff, 0x01, 0x80] {
                let mut img = base.clone();
                img.regions[r].1[i] ^= x;
                if let Some(w) = run(&img, &[HEAP], &[seg, va]) {
                    for p in w.blocks.windows(2) {
                        assert!(p[0].start + p[0].size <= p[1].start);
                    }
                }
            }
        }
    }
}

#[test]
fn segments_lists_and_uncommitted_ranges() {
    let (mut img, h) = simple();
    // Segment 2: blocks, then an uncommitted run (not in the image), then
    // more blocks.
    let seg = HEAP + 0x10_0000;
    img.region(seg, 0x1000);
    img.region(seg + 0x3000, 0x1000);
    img.segment(seg, HEAP, seg + 0x70, seg + 0x4000);
    let a = img.blocks(seg + 0x70, &[(0x40, 1, 0x10), (0xf50, 0, 0)]);
    let b = img.blocks(seg + 0x3000, &[(0x1000, 1, 0x10)]);
    let ucr = seg + 0x800;
    img.u64(ucr + off::UCR_ADDRESS, seg + 0x1000);
    img.u64(ucr + off::UCR_SIZE, 0x2000);
    // The empty descriptor at the segment end, as real segments have.
    let end = seg + 0x900;
    img.u64(end + off::UCR_ADDRESS, seg + 0x4000);
    img.u64(end + off::UCR_SIZE, 0);
    img.list(
        seg + off::UCR_SEGMENT_LIST,
        &[end + off::UCR_SEGMENT_ENTRY, ucr + off::UCR_SEGMENT_ENTRY],
    );
    img.list(
        HEAP + off::SEGMENT_LIST,
        &[
            HEAP + off::SEGMENT_LIST_ENTRY,
            seg + off::SEGMENT_LIST_ENTRY,
        ],
    );
    let w = run(&img, &[HEAP], &[]).unwrap();
    assert_eq!(w.stats.segments, 2);
    assert_eq!(w.stats.segments_cut_short, 0);
    let starts: Vec<u64> = w.blocks.iter().map(|b| b.start - 8).collect();
    assert_eq!(starts, vec![h[0], h[2], h[3], a[0], b[0]]);

    // A segment list that loops back on itself (not to the head) ends.
    let mut img2 = img.clone();
    img2.u64(
        seg + off::SEGMENT_LIST_ENTRY,
        HEAP + off::SEGMENT_LIST_ENTRY,
    );
    let w = run(&img2, &[HEAP], &[]).unwrap();
    assert_eq!(w.stats.segments, 2);
    // A segment of another heap, or with a bad signature, is not walked.
    let mut img3 = img.clone();
    img3.u64(seg + off::SEGMENT_HEAP, 0x1234);
    let w = run(&img3, &[HEAP], &[]).unwrap();
    assert_eq!(w.stats.segments_cut_short, 1);
    assert_eq!(w.blocks.len(), 3);
}

#[test]
fn large_blocks() {
    let (mut img, _) = simple();
    let va = HEAP + 0x20_5000;
    img.region(va, 0x100);
    img.u64(va + off::VA_COMMIT_SIZE, 0x10_1000);
    img.entry(va + off::VA_BUSY_BLOCK, 0x1000, 3, 0, 0, &KEY);
    img.list(HEAP + off::VIRTUAL_ALLOCD_BLOCKS, &[va]);
    let mem = img.mem();
    let large = |w: HeapWalk| {
        w.blocks
            .into_iter()
            .find(|b| b.kind == NativeBlockKind::Large)
            .map(|b| (b.start, b.size))
    };
    // With the reservation known, the whole of it.
    let span = |a: u64| (a == va).then_some((HEAP + 0x20_0000, HEAP + 0x30_a000));
    let w = walk(&mem, &[HEAP], &[], &span).unwrap();
    assert_eq!(large(w), Some((HEAP + 0x20_0000, 0x10_a000)));
    // Without it, the entry and its committed bytes.
    let w = walk(&mem, &[HEAP], &[], &no_span).unwrap();
    assert_eq!(large(w), Some((va, 0x10_1000)));
    // A reservation that does not hold the entry is ignored.
    let bad = |_: u64| Some((HEAP, HEAP + 0x10));
    let w = walk(&mem, &[HEAP], &[], &bad).unwrap();
    assert_eq!(large(w), Some((va, 0x10_1000)));
    // A header that does not decode drops the block.
    let mut img2 = img.clone();
    img2.w(va + off::VA_BUSY_BLOCK + 8, &[1; 8]);
    assert_eq!(large(run(&img2, &[HEAP], &[]).unwrap()), None);
}

/// A heap whose second block holds LFH user blocks of 10 blocks of 0x40.
fn lfh_heap(busy: &[bool], extra: u64) -> (Img, u64, u64) {
    let mut img = Img::default();
    img.region(HEAP, 0x2000);
    img.heap(HEAP, 0x2000);
    let ub_size = GRANULARITY + 0x80 + 0x40 * busy.len() as u64;
    let rest = 0x2000 - FIRST - 0x40 - ub_size;
    let h = img.blocks(
        HEAP + FIRST,
        &[(0x40, 1, 0x10), (ub_size, 0x09, 0x10), (rest, 0, 0)],
    );
    let sub = HEAP + 0x1f00;
    img.user_blocks(h[1], sub, 0x40, busy, extra);
    (
        img,
        h[1],
        h[1] + GRANULARITY + lfh_min_first_offset(busy.len() as u64) + extra,
    )
}

#[test]
fn lfh_blocks_are_decoded() {
    let busy = [
        true, false, true, true, false, false, false, false, false, true,
    ];
    for extra in [0, 0x10] {
        let (img, _, first) = lfh_heap(&busy, extra);
        let w = run(&img, &[HEAP], &[]).unwrap();
        assert_eq!(w.stats.lfh_decoded, 1, "extra {extra:#x}");
        let lfh: Vec<NativeBlock> = w.blocks[1..].to_vec();
        let want: Vec<NativeBlock> = busy
            .iter()
            .enumerate()
            .filter(|(_, &b)| b)
            .map(|(i, _)| alloc(first + i as u64 * 0x40 + 8, 0x40))
            .collect();
        assert_eq!(lfh, want, "extra {extra:#x}");
    }
}

#[test]
fn lfh_blocks_that_do_not_check_out_are_reported_whole() {
    let busy = [
        true, false, true, true, false, false, false, false, false, true,
    ];
    let whole = |img: &Img, ub: u64| {
        let w = run(img, &[HEAP], &[]).unwrap();
        assert_eq!(w.stats.lfh_whole, 1);
        assert_eq!(
            w.blocks[1],
            NativeBlock {
                start: ub + 8,
                size: GRANULARITY + 0x80 + 0x40 * 10,
                kind: NativeBlockKind::SmallBlockContainer,
                heap: 0,
            }
        );
    };
    // A block header that disagrees with the bitmap.
    let (mut img, ub, first) = lfh_heap(&busy, 0);
    img.w(first + 0x40 + 15, &[0x90]);
    whole(&img, ub);
    // A subsegment that does not point back.
    let (mut img, ub, _) = lfh_heap(&busy, 0);
    img.u64(HEAP + 0x1f00 + off::SUB_USER_BLOCKS, 0);
    whole(&img, ub);
    // Without the LFH flag or the signature it is an ordinary block.
    let (mut img, ub, _) = lfh_heap(&busy, 0);
    img.u32(ub + GRANULARITY + off::UD_SIGNATURE, 0);
    let w = run(&img, &[HEAP], &[]).unwrap();
    assert_eq!(w.blocks[1].kind, NativeBlockKind::Allocation);
    assert_eq!((w.stats.lfh_decoded, w.stats.lfh_whole), (0, 0));
}

#[test]
fn lfh_key_is_the_majority() {
    // Two areas agree on the key, a third was given another: it is
    // reported whole and the others decoded.
    let mut img = Img::default();
    img.region(HEAP, 0x4000);
    img.heap(HEAP, 0x4000);
    let ub = GRANULARITY + 0x80 + 0x40 * 4;
    let h = img.blocks(
        HEAP + FIRST,
        &[
            (ub, 9, 0x10),
            (ub, 9, 0x10),
            (ub, 9, 0x10),
            (0x4000 - FIRST - 3 * ub, 0, 0),
        ],
    );
    for (i, &at) in h[..3].iter().enumerate() {
        img.user_blocks(at, HEAP + 0x3f00 + i as u64 * 0x40, 0x40, &[true; 4], 0);
    }
    let enc = h[2] + GRANULARITY + off::UD_ENCODED_OFFSETS;
    let e = img.regions[0].1[(enc - HEAP) as usize..][..4].to_vec();
    img.u32(enc, u32::from_le_bytes(e.try_into().unwrap()) ^ 0x10);
    let w = run(&img, &[HEAP], &[]).unwrap();
    assert_eq!((w.stats.lfh_decoded, w.stats.lfh_whole), (2, 1));
}

#[test]
fn front_end_heap_block_is_left_out() {
    let (mut img, h) = simple();
    img.u64(HEAP + off::FRONT_END_HEAP, h[2] + GRANULARITY);
    let w = run(&img, &[HEAP], &[]).unwrap();
    assert_eq!(w.blocks.len(), 2);
    assert_eq!(w.stats.front_end_skipped, 1);
}

#[test]
fn heaps_are_found_by_scanning_and_indexed_after_the_listed_ones() {
    let (mut img, _) = simple();
    let other = HEAP + 0x100_0000;
    img.region(other, 0x1000);
    img.heap(other, 0x1000);
    img.blocks(other + FIRST, &[(0xe00, 1, 0x10)]);
    let seg_heap = HEAP + 0x200_0000;
    img.region(seg_heap, 0x100);
    img.u32(seg_heap + off::SEGMENT_SIGNATURE, SEGMENT_HEAP_SIGNATURE);
    let junk = HEAP + 0x300_0000;
    img.region(junk, 0x100);
    // A later segment of a heap is not a heap of its own.
    let seg = HEAP + 0x400_0000;
    img.region(seg, 0x100);
    img.segment(seg, HEAP, seg + 0x70, seg + 0x100);

    let w = run(&img, &[HEAP], &[junk, seg_heap, other, seg, HEAP]).unwrap();
    assert_eq!(w.heaps, vec![HEAP, other, seg_heap]);
    assert_eq!(w.stats.nt_heaps, 2);
    assert_eq!(w.stats.segment_heaps_skipped, 1);
    let last = w.blocks.last().unwrap();
    assert_eq!((last.start, last.heap), (other + FIRST + 8, 1));

    // Listed heaps keep their index even when they are not NT heaps.
    let w = run(&img, &[junk, other], &[]).unwrap();
    assert_eq!(w.heaps, vec![junk, other]);
    assert!(w.blocks.iter().all(|b| b.heap == 1));

    // No NT heap at all.
    assert!(run(&img, &[junk, seg_heap], &[junk]).is_none());
    assert!(run(&img, &[], &[]).is_none());
}
