//! The user-space mirror of the structs in `bpf/heapspy.bpf.c`. Pure code,
//! compiled and tested on every platform.

use heapspy_reader::cpython::FrameOffsets;

/// Frames the kernel copies per event. `--max-frames` above this is
/// clamped and the sample marked `STACK_TRUNCATED` when frames remain.
pub const KMAX_FRAMES: usize = 128;
/// Exponential quantiles the in-kernel sampler draws from.
pub const N_THRESHOLDS: usize = 256;

pub const KIND_ARENA: u8 = 1;
pub const KIND_LARGE: u8 = 3;

pub const EF_NO_TSTATE: u8 = 1;
pub const EF_TRUNCATED: u8 = 2;
pub const EF_BROKEN: u8 = 4;
pub const EF_HAS_RET: u8 = 8;

/// Per-CPU counter slots.
pub const C_HITS: usize = 0;
pub const C_SAMPLED: usize = 1;
pub const C_DROPPED: usize = 2;
pub const C_ORPHANS: usize = 3;
pub const C_TSTATE_MISS: usize = 4;
pub const C_REFIRES: usize = 5;
pub const N_COUNTERS: usize = 8;

const FRAME_SIZE: usize = 24;
const HEADER_SIZE: usize = 40;
/// `sizeof(struct event)`.
pub const EVENT_SIZE: usize = HEADER_SIZE + KMAX_FRAMES * FRAME_SIZE;

/// `struct config`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub tgid: u64,
    pub arena_size: u64,
    pub large_on: bool,
    pub min_large: u64,
    pub interval: u64,
    pub runtime_addr: u64,
    pub max_frames: u64,
    pub fo: Option<FrameOffsets>,
}

impl Config {
    /// The bytes of `struct config`, 21 native-endian `u64`s in order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u64> = vec![
            self.tgid,
            self.arena_size,
            self.large_on as u64,
            self.min_large,
            self.interval,
            self.runtime_addr,
            self.max_frames.min(KMAX_FRAMES as u64),
        ];
        let f = self.fo.unwrap_or(ZERO_OFFSETS);
        v.extend([
            f.rt_interpreters_head,
            f.is_next,
            f.is_threads_head,
            f.ts_next,
            f.ts_native_thread_id,
            f.ts_native_thread_id_size as u64,
            f.ts_current_frame,
            f.ts_frame_via_cframe as u64,
            f.if_previous,
            f.if_executable,
            f.if_instr_ptr,
            f.if_owner,
            f.owner_first_shim as u64,
            f.executable_is_stackref as u64,
        ]);
        v.iter().flat_map(|x| x.to_ne_bytes()).collect()
    }
}

const ZERO_OFFSETS: FrameOffsets = FrameOffsets {
    minor: 0,
    rt_interpreters_head: 0,
    is_next: 0,
    is_threads_head: 0,
    ts_next: 0,
    ts_native_thread_id: 0,
    ts_native_thread_id_size: 8,
    ts_current_frame: 0,
    ts_frame_via_cframe: false,
    if_previous: 0,
    if_executable: 0,
    if_instr_ptr: 0,
    if_owner: 0,
    owner_first_shim: 0,
    executable_is_stackref: false,
    co_qualname: 0,
    co_filename: 0,
    co_firstlineno: 0,
    co_linetable: 0,
    co_code_adaptive: 0,
    ob_type: 8,
    tp_name: 0,
    str_length: 0,
    str_state: 0,
    str_ascii_data: 0,
    str_compact_data: 0,
    bytes_size: 16,
    bytes_sval: 0,
};

/// `struct frame`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KFrame {
    pub executable: u64,
    pub instr_ptr: u64,
    pub ob_type: u64,
}

/// `struct event`, decoded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    /// `CLOCK_MONOTONIC` ns.
    pub ts: u64,
    pub addr: u64,
    pub size: u64,
    pub ret_addr: u64,
    pub tid: u32,
    pub kind: u8,
    pub flags: u8,
    pub frames: Vec<KFrame>,
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_ne_bytes(b[o..o + 8].try_into().unwrap())
}

/// Decode one ring buffer record. `None` if it is too short.
pub fn parse_event(b: &[u8]) -> Option<Event> {
    if b.len() < HEADER_SIZE {
        return None;
    }
    let n = (u16::from_ne_bytes([b[38], b[39]]) as usize).min(KMAX_FRAMES);
    if b.len() < HEADER_SIZE + n * FRAME_SIZE {
        return None;
    }
    let frames = (0..n)
        .map(|i| {
            let o = HEADER_SIZE + i * FRAME_SIZE;
            KFrame {
                executable: u64_at(b, o),
                instr_ptr: u64_at(b, o + 8),
                ob_type: u64_at(b, o + 16),
            }
        })
        .collect();
    Some(Event {
        ts: u64_at(b, 0),
        addr: u64_at(b, 8),
        size: u64_at(b, 16),
        ret_addr: u64_at(b, 24),
        tid: u32::from_ne_bytes(b[32..36].try_into().unwrap()),
        kind: b[36],
        flags: b[37],
        frames,
    })
}

/// The gaps the kernel sampler draws from: [`N_THRESHOLDS`] quantiles of
/// an exponential distribution with mean `interval`, so the gap between two
/// kept allocations is (approximately) exponential and each allocation of
/// `s` bytes is kept with probability `1 - exp(-s / interval)`, which is what
/// [`heapspy_alloc::sampled_weight`] inverts.
pub fn thresholds(interval: u64) -> Vec<u64> {
    (0..N_THRESHOLDS)
        .map(|k| {
            let u = (k as f64 + 0.5) / N_THRESHOLDS as f64;
            ((-(1.0 - u).ln()) * interval as f64).round().max(1.0) as u64
        })
        .collect()
}

/// One ring buffer record header: `(length, busy, discarded)`.
pub fn record_header(h: u32) -> (usize, bool, bool) {
    (
        (h & 0x3fff_ffff) as usize,
        h & (1 << 31) != 0,
        h & (1 << 30) != 0,
    )
}

/// Bytes a record of `len` occupies in the ring: 8-byte header, rounded
/// up to 8.
pub fn record_span(len: usize) -> usize {
    (len + 8 + 7) & !7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_round_trip() {
        let mut b = vec![0u8; EVENT_SIZE];
        b[0..8].copy_from_slice(&5u64.to_ne_bytes());
        b[8..16].copy_from_slice(&0x1000u64.to_ne_bytes());
        b[16..24].copy_from_slice(&65536u64.to_ne_bytes());
        b[32..36].copy_from_slice(&77u32.to_ne_bytes());
        b[36] = KIND_LARGE;
        b[37] = EF_HAS_RET;
        b[38..40].copy_from_slice(&2u16.to_ne_bytes());
        b[40..48].copy_from_slice(&0xc0deu64.to_ne_bytes());
        b[64..72].copy_from_slice(&0xc1deu64.to_ne_bytes());
        let e = parse_event(&b).unwrap();
        assert_eq!((e.ts, e.addr, e.size, e.tid), (5, 0x1000, 65536, 77));
        assert_eq!(e.frames.len(), 2);
        assert_eq!(e.frames[1].executable, 0xc1de);
        assert!(parse_event(&b[..30]).is_none());
        assert!(parse_event(&b[..60]).is_none());
    }

    #[test]
    fn config_is_21_words_and_clamps_frames() {
        let c = Config {
            max_frames: 1000,
            ..Config::default()
        };
        let b = c.to_bytes();
        assert_eq!(b.len(), 21 * 8);
        assert_eq!(u64_at(&b, 6 * 8), KMAX_FRAMES as u64);
    }

    #[test]
    fn thresholds_have_the_right_mean() {
        let t = thresholds(512 * 1024);
        let mean = t.iter().sum::<u64>() as f64 / t.len() as f64;
        assert!((mean / (512.0 * 1024.0) - 1.0).abs() < 0.05, "{mean}");
        assert!(t.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn ring_records() {
        assert_eq!(record_header(0x8000_0010), (16, true, false));
        assert_eq!(record_header(0x4000_0010), (16, false, true));
        assert_eq!(record_span(EVENT_SIZE), EVENT_SIZE + 8);
        assert_eq!(record_span(1), 16);
    }
}
