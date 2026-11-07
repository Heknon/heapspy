//! On-disk layout constants. `docs/snapshot-format.md` is the normative
//! description; every number here must match it.
//!
//! All integers are little-endian. Records are decoded with
//! `from_le_bytes` on byte slices, so nothing depends on alignment or on the
//! host's endianness.

/// The four magic bytes at offset 0.
pub const MAGIC: [u8; 4] = *b"HPSY";
/// The format version this crate writes and the only one it reads.
pub const FORMAT_VERSION: u16 = 1;

/// Size of the fixed file header in bytes.
pub const HEADER_LEN: usize = 64;
/// Size of one section table entry.
pub const SECTION_ENTRY_LEN: usize = 24;
/// Size of the header that starts every record section (count, record_len, reserved).
pub const RECORD_SECTION_HEADER_LEN: usize = 16;
/// Size of the strings section header (count, data_len).
pub const STRINGS_HEADER_LEN: usize = 16;
/// Sections start at offsets that are a multiple of this.
pub const SECTION_ALIGN: u64 = 8;

pub const TYPE_RECORD_LEN: u32 = 24;
pub const OBJECT_RECORD_LEN: u32 = 40;
pub const EDGE_RECORD_LEN: u32 = 16;
pub const ROOT_RECORD_LEN: u32 = 16;
pub const EXTRAS_RECORD_LEN: u32 = 32;
pub const REGION_RECORD_LEN: u32 = 24;
pub const META_RECORD_LEN: u32 = 8;
pub const REFCOUNT_RECORD_LEN: u32 = 8;
/// A refcount record for an object whose header could not be read.
pub const UNKNOWN_REFCOUNT: u64 = u64::MAX;

/// Sentinel for "no string" in any u32 string-id field.
pub const NO_STRING: u32 = u32::MAX;
/// Sentinel for "type unknown" in the object record's type_id field.
pub const UNKNOWN_TYPE: u32 = u32::MAX;
/// Sentinel for "unknown" in the memory region's resident_bytes field.
pub const UNKNOWN_BYTES: u64 = u64::MAX;

// Header field offsets.
pub const H_MAGIC: usize = 0;
pub const H_VERSION: usize = 4;
pub const H_HEADER_LEN: usize = 6;
pub const H_PY_MAJOR: usize = 8;
pub const H_PY_MINOR: usize = 9;
pub const H_PY_MICRO: usize = 10;
pub const H_POINTER_SIZE: usize = 11;
pub const H_ENDIANNESS: usize = 12;
pub const H_OS: usize = 13;
pub const H_ARCH: usize = 14;
pub const H_SOURCE_KIND: usize = 15;
pub const H_FLAGS: usize = 16;
pub const H_SOURCE_REF: usize = 20;
pub const H_CAPTURED_AT: usize = 24;
pub const H_SECTION_TABLE_OFFSET: usize = 32;
pub const H_SECTION_COUNT: usize = 40;
pub const H_PY_RELEASE_LEVEL: usize = 44;
pub const H_PY_RELEASE_SERIAL: usize = 45;
pub const H_FILE_LEN: usize = 48;

// Header flag bits.
pub const HF_CONTENTS_CAPTURED: u32 = 1 << 0;
pub const HF_TRUNCATED: u32 = 1 << 1;
pub const HF_PY_FREE_THREADED: u32 = 1 << 2;
pub const HF_PY_DEBUG_BUILD: u32 = 1 << 3;

// Section table entry flags.
/// A reader that does not know this section kind must refuse the file.
pub const SF_REQUIRED: u32 = 1 << 0;

// Section kinds.
pub const SK_STRINGS: u32 = 1;
pub const SK_TYPES: u32 = 2;
pub const SK_OBJECTS: u32 = 3;
pub const SK_EDGES: u32 = 4;
pub const SK_ROOTS: u32 = 5;
pub const SK_EXTRAS: u32 = 6;
pub const SK_MEMORY_SUMMARY: u32 = 7;
pub const SK_META: u32 = 8;
pub const SK_REFCOUNTS: u32 = 9;

pub(crate) fn section_name(kind: u32) -> &'static str {
    match kind {
        SK_STRINGS => "strings",
        SK_TYPES => "types",
        SK_OBJECTS => "objects",
        SK_EDGES => "edges",
        SK_ROOTS => "roots",
        SK_EXTRAS => "extras",
        SK_MEMORY_SUMMARY => "memory_summary",
        SK_META => "meta",
        SK_REFCOUNTS => "refcounts",
        _ => "unknown",
    }
}

// Extras field bits.
pub const XF_LENGTH: u32 = 1 << 0;
pub const XF_QUALNAME: u32 = 1 << 1;
pub const XF_SOURCE_LOC: u32 = 1 << 2;
pub const XF_CONTENT: u32 = 1 << 3;
pub const XF_CONTENT_TRUNCATED: u32 = 1 << 4;

// Edge flag bits.
/// For DictKey / DictValue labels: the operand string is a placeholder
/// such as `<str len=9>`, not the key's repr.
pub const EF_KEY_REDACTED: u8 = 1 << 0;

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
