//! Pieces every recorder shares: which event kinds actually ran, code
//! object recognition, instruction offsets.

use std::collections::HashMap;

use heapspy_alloc::{EventKind, EventKinds};
use heapspy_reader::cpython::frames::{RawFrame, MAX_INSTR_OFFSET};
use heapspy_reader::cpython::FrameOffsets;
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

/// Remembers which type addresses are `code` (`tp_name == "code"`), the
/// same test `read_stack` applies.
#[derive(Default)]
pub struct CodeTypes {
    types: HashMap<u64, bool>,
}

impl CodeTypes {
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
#[cfg(unix)]
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
#[cfg(unix)]
pub fn monotonic_ns() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}

pub fn to_epoch(mono: u64, offset: i128) -> u64 {
    (mono as i128 + offset).clamp(0, u64::MAX as i128) as u64
}
