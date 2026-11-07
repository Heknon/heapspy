//! Pieces every recorder shares: which event kinds actually ran, code
//! object recognition, instruction offsets.

#[cfg(target_os = "linux")]
use std::collections::HashMap;

use heapspy_alloc::{sampled_weight, EventKind, EventKinds};
#[cfg(target_os = "linux")]
use heapspy_reader::cpython::frames::{self, RawFrame, MAX_INSTR_OFFSET};
#[cfg(target_os = "linux")]
use heapspy_reader::cpython::FrameOffsets;
#[cfg(target_os = "linux")]
use heapspy_reader::{MemorySource, MemorySourceExt};

use crate::error::Result;
use crate::sink::SampleSink;

/// Record in the header which kinds were actually recorded, and name the
/// requested ones that were not in meta `heapspy.skipped_events`
/// (comma-separated, with the reason after a colon).
pub fn note_events(
    sink: &mut SampleSink<'_>,
    recorded: EventKinds,
    skipped: &[(EventKind, String)],
) -> Result<()> {
    let w = sink.writer_mut();
    w.info_mut().sampling.events = recorded;
    if !skipped.is_empty() {
        let v = skipped
            .iter()
            .map(|(k, why)| format!("{k}: {why}"))
            .collect::<Vec<_>>()
            .join(", ");
        w.add_meta("heapspy.skipped_events", &v)?;
    }
    Ok(())
}

/// Decides which native heap allocations to keep. Pure, so it is tested on
/// every platform; the Windows recorder feeds it the size of each
/// `RtlAllocateHeap` / `RtlReAllocateHeap` event of the target.
///
/// Two stages, as the design asks (`docs/allocation-sampling.md`, "Native
/// heap"):
///
/// 1. **Size floor.** A call for fewer than `min_size` bytes is dropped. The
///    smallest allocations are the most frequent, and keeping their stacks
///    would swamp the profile; the floor bounds how many samples the trap
///    rate turns into. `min_size` 0 keeps every size.
/// 2. **Byte-interval sampler.** Of the calls at or above the floor, one of
///    `s` bytes is kept with probability `p = 1 - exp(-s / interval)` and
///    weighed [`sampled_weight`] (`s / p`), the same Poisson-over-bytes
///    sampler the eBPF large-object path uses, so the kept weights are an
///    unbiased estimate of the bytes allocated at or above the floor.
///    `interval` 0 keeps every call that passed the floor, weighed its size.
// Only the Windows recorder samples native allocations so far; a Linux one
// would use the same filter.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Debug)]
pub struct NativeFilter {
    min_size: u64,
    interval: u64,
    rng: u64,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl NativeFilter {
    pub fn new(min_size: u64, interval: u64, seed: u64) -> Self {
        Self {
            min_size,
            interval,
            // Never 0: xorshift is stuck at 0.
            rng: seed | 1,
        }
    }

    /// `Some(weight)` if this allocation of `size` bytes is kept, `None` if
    /// the floor or the sampler dropped it.
    pub fn keep(&mut self, size: u64) -> Option<u64> {
        if size < self.min_size {
            return None;
        }
        if self.interval == 0 {
            return Some(size);
        }
        let ratio = size as f64 / self.interval as f64;
        let p = -(-ratio).exp_m1();
        if self.next_unit() < p {
            Some(sampled_weight(size, self.interval))
        } else {
            None
        }
    }

    /// A uniform number in `[0, 1)` from an xorshift64 generator. No crate,
    /// no cross-sample correlation; the stream only drives sampling.
    fn next_unit(&mut self) -> f64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        // Top 53 bits for an f64 mantissa.
        (x >> 11) as f64 / ((1u64 << 53) as f64)
    }
}

#[cfg(target_os = "linux")]
/// Remembers which type addresses are `code` (`tp_name == "code"`) and
/// which code objects are CPython shim code: the same tests `read_stack`
/// applies to decide which frames to keep.
#[derive(Default)]
pub struct CodeTypes {
    types: HashMap<u64, bool>,
    shims: HashMap<u64, bool>,
}

#[cfg(target_os = "linux")]
impl CodeTypes {
    /// Whether a frame whose executable is `code`, of type `ty`, is a
    /// Python frame `read_stack` would keep: a code object, and not
    /// CPython's shim code ([`frames::is_shim_code`]).
    pub fn keep(&mut self, src: &dyn MemorySource, fo: &FrameOffsets, ty: u64, code: u64) -> bool {
        if code == 0 || !self.is_code(src, fo, ty) {
            return false;
        }
        // Shim code objects are static, so an address is never both.
        !*self
            .shims
            .entry(code)
            .or_insert_with(|| frames::is_shim_code(src, fo, code))
    }

    pub fn is_code(&mut self, src: &dyn MemorySource, fo: &FrameOffsets, ty: u64) -> bool {
        if ty == 0 {
            return false;
        }
        if let Some(&v) = self.types.get(&ty) {
            return v;
        }
        let v = src
            .read_ptr(ty + fo.tp_name)
            .and_then(|n| src.read_cstr(n, 8))
            .is_ok_and(|n| n == b"code");
        // A failed read is not cached: the type may be readable later.
        if v || src.read_ptr(ty + fo.tp_name).is_ok() {
            self.types.insert(ty, v);
        }
        v
    }
}

#[cfg(target_os = "linux")]
/// A frame from a code object address and the frame's instruction pointer,
/// as `read_stack` computes it.
pub fn raw_frame(fo: &FrameOffsets, code: u64, instr_ptr: u64) -> RawFrame {
    let start = code + fo.co_code_adaptive;
    RawFrame {
        code,
        instr_offset: instr_ptr
            .checked_sub(start)
            .filter(|&d| d < MAX_INSTR_OFFSET)
            .map(|d| d as u32),
    }
}

/// `CLOCK_REALTIME - CLOCK_MONOTONIC` in ns, to turn monotonic event
/// times into Unix-epoch times. Measured once, at start.
#[cfg(target_os = "linux")]
pub fn monotonic_to_epoch_offset() -> i128 {
    let read = |clk| {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes one timespec.
        unsafe { libc::clock_gettime(clk, &mut t) };
        t.tv_sec as i128 * 1_000_000_000 + t.tv_nsec as i128
    };
    let m0 = read(libc::CLOCK_MONOTONIC);
    let r = read(libc::CLOCK_REALTIME);
    let m1 = read(libc::CLOCK_MONOTONIC);
    r - (m0 + m1) / 2
}

/// Monotonic ns now.
#[cfg(target_os = "linux")]
pub fn monotonic_ns() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}

#[cfg(target_os = "linux")]
pub fn to_epoch(mono: u64, offset: i128) -> u64 {
    (mono as i128 + offset).clamp(0, u64::MAX as i128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_filter_floor_drops_small_calls() {
        let mut f = NativeFilter::new(4096, 0, 1);
        assert_eq!(f.keep(4095), None);
        // Floor met, interval 0: kept and weighed its size.
        assert_eq!(f.keep(4096), Some(4096));
        assert_eq!(f.keep(1 << 20), Some(1 << 20));
    }

    #[test]
    fn native_filter_keeps_large_relative_to_interval() {
        let mut f = NativeFilter::new(4096, 512 << 10, 0x1234_5678);
        // A 1 MiB request (p = 1 - e^-2 ~ 0.86) is kept almost always and
        // weighs about its own size.
        let mut kept = 0u64;
        let mut sum = 0u64;
        for _ in 0..1000 {
            if let Some(w) = f.keep(1 << 20) {
                kept += 1;
                sum += w;
            }
        }
        assert!((780..=940).contains(&kept), "kept {kept}/1000");
        // The estimate of total bytes (sum of weights) is within 15% of the
        // 1000 MiB actually requested.
        let actual = 1000u64 * (1 << 20);
        let err = (sum as f64 - actual as f64).abs() / actual as f64;
        assert!(
            err < 0.15,
            "estimate off by {err} (sum {sum}, actual {actual})"
        );
    }

    #[test]
    fn native_filter_below_floor_never_sampled() {
        let mut f = NativeFilter::new(1 << 20, 512 << 10, 7);
        for _ in 0..10_000 {
            assert_eq!(f.keep((1 << 20) - 1), None);
        }
    }
}
