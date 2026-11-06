//! On-disk layout constants. `docs/alloc-format.md` is the normative
//! description; every number here must match it.
//!
//! All integers are little-endian. Records are decoded with
//! `from_le_bytes` on byte slices, so nothing depends on alignment or on the
//! host's endianness.

/// The four magic bytes at offset 0.
pub const MAGIC: [u8; 4] = *b"HPYA";
/// The format version this crate writes and the only one it reads.
pub const FORMAT_VERSION: u16 = 1;

/// Size of the fixed file header in bytes.
pub const HEADER_LEN: usize = 128;
/// Size of one section table entry.
pub const SECTION_ENTRY_LEN: usize = 24;
/// Size of the header that starts every record section (count, record_len, reserved).
pub const RECORD_SECTION_HEADER_LEN: usize = 16;
/// Size of the header of the strings and blobs sections (count, data_len).
pub const TABLE_HEADER_LEN: usize = 16;
/// Sections start at offsets that are a multiple of this.
pub const SECTION_ALIGN: u64 = 8;

pub const CODE_RECORD_LEN: u32 = 32;
pub const SAMPLE_RECORD_LEN: u32 = 64;
pub const FRAME_RECORD_LEN: u32 = 12;
pub const META_RECORD_LEN: u32 = 8;

/// Sentinel for "no string" in any u32 string-id field.
pub const NO_STRING: u32 = u32::MAX;
/// Sentinel for "no blob" in the code record's linetable field.
pub const NO_BLOB: u32 = u32::MAX;
/// Sentinel for "code not identified" in the frame record's code_id field.
pub const NO_CODE: u32 = u32::MAX;

// Header field offsets.
pub const H_MAGIC: usize = 0;
pub const H_VERSION: usize = 4;
pub const H_HEADER_LEN: usize = 6;
pub const H_PY_MAJOR: usize = 8;
pub const H_PY_MINOR: usize = 9;
pub const H_PY_MICRO: usize = 10;
pub const H_PY_RELEASE_LEVEL: usize = 11;
pub const H_PY_RELEASE_SERIAL: usize = 12;
pub const H_POINTER_SIZE: usize = 13;
pub const H_OS: usize = 14;
pub const H_ARCH: usize = 15;
pub const H_PID: usize = 16;
pub const H_FLAGS: usize = 20;
pub const H_MECHANISMS: usize = 24;
pub const H_EVENTS: usize = 28;
pub const H_START_NS: usize = 32;
pub const H_END_NS: usize = 40;
pub const H_BYTE_INTERVAL: usize = 48;
pub const H_MAX_FRAMES: usize = 56;
pub const H_SAMPLES_TAKEN: usize = 64;
pub const H_SAMPLES_DROPPED: usize = 72;
pub const H_PROBE_HITS: usize = 80;
pub const H_TOTAL_PAUSE_NS: usize = 88;
pub const H_SECTION_TABLE_OFFSET: usize = 96;
pub const H_SECTION_COUNT: usize = 104;
pub const H_FILE_LEN: usize = 112;

// Header flag bits.
/// Recording stopped before the requested duration, or samples were lost in
/// a way the overhead counters do not describe.
pub const HF_TRUNCATED: u32 = 1 << 0;

// Section table entry flags.
/// A reader that does not know this section kind must refuse the file.
pub const SF_REQUIRED: u32 = 1 << 0;

// Section kinds.
pub const SK_STRINGS: u32 = 1;
pub const SK_BLOBS: u32 = 2;
pub const SK_CODES: u32 = 3;
pub const SK_SAMPLES: u32 = 4;
pub const SK_FRAMES: u32 = 5;
pub const SK_META: u32 = 6;

pub(crate) fn section_name(kind: u32) -> &'static str {
    match kind {
        SK_STRINGS => "strings",
        SK_BLOBS => "blobs",
        SK_CODES => "codes",
        SK_SAMPLES => "samples",
        SK_FRAMES => "frames",
        SK_META => "meta",
        _ => "unknown",
    }
}

// Code record flag bits.
/// Only the address is known; qualname, filename and line table were not read.
pub const CF_UNRESOLVED: u8 = 1 << 0;

// Sample record flag bits.
/// Python frames were matched to the event by time, not read at the event.
pub const SAF_APPROXIMATE_FRAMES: u8 = 1 << 0;
/// The Python stack was deeper than `max_frames`; the outermost frames are missing.
pub const SAF_STACK_TRUNCATED: u8 = 1 << 1;
/// The allocating thread had no Python thread state (a native thread).
pub const SAF_NO_THREAD_STATE: u8 = 1 << 2;

// Frame record flag bits.
/// This frame was attributed by time correlation, not read at the event.
pub const FF_APPROXIMATE: u16 = 1 << 0;
/// `instr_offset` is not meaningful: the frame had not started executing or
/// the instruction pointer could not be read.
pub const FF_NO_OFFSET: u16 = 1 << 1;

#[inline]
pub(crate) fn rd_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

#[inline]
pub(crate) fn rd_u32(b: &[u8], at: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(a)
}

#[inline]
pub(crate) fn rd_u64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

#[inline]
pub(crate) fn wr_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub(crate) fn wr_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub(crate) fn wr_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

pub(crate) fn align_up(v: u64) -> u64 {
    v.div_ceil(SECTION_ALIGN) * SECTION_ALIGN
}
