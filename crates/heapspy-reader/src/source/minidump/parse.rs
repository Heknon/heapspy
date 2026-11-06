//! Byte-level parsing of the MINIDUMP structures heapspy uses.
//!
//! Everything here works on a `&[u8]` holding the whole file and returns
//! [`Error::Format`] for anything out of bounds or inconsistent. No function
//! in this module panics on any input, and no loop runs more times than the
//! file has bytes to back it.
//!
//! Layouts follow `minidumpapiset.h` (packed to 4 bytes, little-endian).
//! Offsets in the comments are byte offsets within each structure.

use crate::error::{Error, Result};

/// `MINIDUMP_SIGNATURE`, "MDMP" read as a little-endian u32.
pub(super) const SIGNATURE: u32 = 0x504d_444d;
/// Low 16 bits of `MINIDUMP_HEADER.Version`.
pub(super) const VERSION: u32 = 0xa793;

/// `MINIDUMP_STREAM_TYPE` values that heapspy reads.
pub(super) mod stream {
    pub const THREAD_LIST: u32 = 3;
    pub const MODULE_LIST: u32 = 4;
    pub const MEMORY_LIST: u32 = 5;
    pub const SYSTEM_INFO: u32 = 7;
    pub const MEMORY64_LIST: u32 = 9;
    pub const MISC_INFO: u32 = 15;
    pub const MEMORY_INFO_LIST: u32 = 16;
    pub const THREAD_NAMES: u32 = 24;
}

/// `PROCESSOR_ARCHITECTURE_*` values in `MINIDUMP_SYSTEM_INFO`.
pub(super) mod cpu {
    pub const INTEL: u16 = 0;
    pub const ARM: u16 = 5;
    pub const AMD64: u16 = 9;
    pub const ARM64: u16 = 12;
}

/// Size of `MINIDUMP_HEADER`.
pub(super) const HEADER_SIZE: u64 = 32;
const DIRECTORY_ENTRY_SIZE: u64 = 12;
const MEMORY_DESCRIPTOR_SIZE: u64 = 16;
const MEMORY_DESCRIPTOR64_SIZE: u64 = 16;
const MODULE_SIZE: u64 = 108;
const THREAD_SIZE: u64 = 48;
const THREAD_NAME_SIZE: u64 = 12;
const MEMORY_INFO_MIN_SIZE: u64 = 48;
const MEMORY_INFO_LIST_MIN_HEADER: u64 = 16;
const VS_FIXEDFILEINFO_SIGNATURE: u32 = 0xfeef_04bd;
const CV_SIGNATURE_RSDS: u32 = 0x5344_5352; // "RSDS"
const CV_SIGNATURE_NB10: u32 = 0x3031_424e; // "NB10"

pub(super) fn bad(msg: impl std::fmt::Display) -> Error {
    Error::Format(format!("minidump: {msg}"))
}

/// A bounds-checked little-endian view of a byte slice.
#[derive(Clone, Copy)]
pub(super) struct Bytes<'a>(pub &'a [u8]);

impl<'a> Bytes<'a> {
    pub fn len(&self) -> u64 {
        self.0.len() as u64
    }

    /// `[off, off + len)` of this view, or an error naming `what`.
    pub fn sub(&self, off: u64, len: u64, what: &str) -> Result<Bytes<'a>> {
        let end = off
            .checked_add(len)
            .ok_or_else(|| bad(format_args!("{what}: offset {off:#x}+{len:#x} overflows")))?;
        if end > self.len() {
            return Err(bad(format_args!(
                "{what}: bytes {off:#x}..{end:#x} are past the end of the data ({:#x} bytes)",
                self.len()
            )));
        }
        // Both fit in the slice length, which is a usize.
        Ok(Bytes(&self.0[off as usize..end as usize]))
    }

    /// Everything from `off` to the end.
    pub fn tail(&self, off: u64, what: &str) -> Result<Bytes<'a>> {
        let len = self
            .len()
            .checked_sub(off)
            .ok_or_else(|| bad(format_args!("{what}: offset {off:#x} is past the end")))?;
        self.sub(off, len, what)
    }

    fn array<const N: usize>(&self, off: u64, what: &str) -> Result<[u8; N]> {
        let s = self.sub(off, N as u64, what)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s.0);
        Ok(a)
    }

    pub fn u8(&self, off: u64, what: &str) -> Result<u8> {
        Ok(self.array::<1>(off, what)?[0])
    }

    pub fn u16(&self, off: u64, what: &str) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array(off, what)?))
    }

    pub fn u32(&self, off: u64, what: &str) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array(off, what)?))
    }

    pub fn u64(&self, off: u64, what: &str) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array(off, what)?))
    }

    /// `MINIDUMP_LOCATION_DESCRIPTOR` at `off`: `DataSize` u32, then `Rva` u32.
    pub fn loc(&self, off: u64, what: &str) -> Result<Loc> {
        Ok(Loc {
            size: self.u32(off, what)?.into(),
            rva: self.u32(off + 4, what)?.into(),
        })
    }

    /// Check that `count` records of `size` bytes fit after `off`. Callers
    /// use this before looping `count` times, so a huge count in a corrupt
    /// file fails here instead of driving a long loop or a huge allocation.
    fn records(&self, off: u64, count: u64, size: u64, what: &str) -> Result<()> {
        let bytes = count
            .checked_mul(size)
            .ok_or_else(|| bad(format_args!("{what}: {count} entries overflow")))?;
        self.sub(off, bytes, what).map(|_| ())
    }
}

/// A location descriptor: `size` bytes at file offset `rva`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Loc {
    pub size: u64,
    pub rva: u64,
}

impl Loc {
    pub fn data<'a>(&self, file: Bytes<'a>, what: &str) -> Result<Bytes<'a>> {
        file.sub(self.rva, self.size, what)
    }
}

/// `MINIDUMP_HEADER`.
#[derive(Clone, Copy, Debug)]
pub(super) struct Header {
    pub stream_count: u64,
    pub directory_rva: u64,
    pub timestamp: u32,
    pub flags: u64,
}

pub(super) fn header(file: Bytes) -> Result<Header> {
    if file.len() < HEADER_SIZE {
        return Err(bad(format_args!(
            "file is {} bytes, shorter than the 32-byte header",
            file.len()
        )));
    }
    let sig = file.u32(0, "header")?;
    if sig != SIGNATURE {
        return Err(bad(format_args!(
            "bad signature {sig:#010x} (expected \"MDMP\")"
        )));
    }
    let version = file.u32(4, "header")?;
    if version & 0xffff != VERSION {
        return Err(bad(format_args!("unknown version {version:#x}")));
    }
    Ok(Header {
        stream_count: file.u32(8, "header")?.into(),
        directory_rva: file.u32(12, "header")?.into(),
        // 16: CheckSum (always 0 in practice; not verified)
        timestamp: file.u32(20, "header")?,
        flags: file.u64(24, "header")?,
    })
}

/// One `MINIDUMP_DIRECTORY` entry.
#[derive(Clone, Copy, Debug)]
pub(super) struct DirEntry {
    pub stream_type: u32,
    pub loc: Loc,
}

pub(super) fn directory(file: Bytes, h: &Header) -> Result<Vec<DirEntry>> {
    const WHAT: &str = "stream directory";
    let dir_end = h
        .stream_count
        .saturating_mul(DIRECTORY_ENTRY_SIZE)
        .saturating_add(h.directory_rva);
    if dir_end > file.len() {
        return Err(Error::Truncated(format!(
            "minidump: the stream directory ends at {dir_end:#x}, past the end of the file \
             ({:#x} bytes)",
            file.len()
        )));
    }
    file.records(h.directory_rva, h.stream_count, DIRECTORY_ENTRY_SIZE, WHAT)?;
    let mut out = Vec::with_capacity(h.stream_count as usize);
    for i in 0..h.stream_count {
        let off = h.directory_rva + i * DIRECTORY_ENTRY_SIZE;
        let e = DirEntry {
            stream_type: file.u32(off, WHAT)?,
            loc: file.loc(off + 4, WHAT)?,
        };
        // Every stream must lie inside the file, even ones heapspy ignores:
        // a directory that points past the end means the file is truncated.
        if e.loc.rva.saturating_add(e.loc.size) > file.len() {
            return Err(Error::Truncated(format!(
                "minidump: stream {i} at {:#x}+{:#x} is past the end of the file ({:#x} bytes)",
                e.loc.rva,
                e.loc.size,
                file.len()
            )));
        }
        e.loc.data(file, "stream")?;
        out.push(e);
    }
    Ok(out)
}

/// A captured memory range: `size` bytes of target memory starting at
/// `start`, stored at file offset `file_off`. Validated so that neither
/// `start + size` nor `file_off + size` overflows and the data is in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawRange {
    pub start: u64,
    pub size: u64,
    pub file_off: u64,
}

fn checked_range(
    file: Bytes,
    start: u64,
    size: u64,
    file_off: u64,
    what: &str,
) -> Result<RawRange> {
    start
        .checked_add(size)
        .ok_or_else(|| bad(format_args!("{what}: range {start:#x}+{size:#x} overflows")))?;
    // `file` is the whole file: memory past its end was cut off.
    if file_off.saturating_add(size) > file.len() {
        return Err(Error::Truncated(format!(
            "minidump: {what} at {file_off:#x}+{size:#x} is past the end of the file \
             ({:#x} bytes)",
            file.len()
        )));
    }
    file.sub(file_off, size, what)?;
    Ok(RawRange {
        start,
        size,
        file_off,
    })
}

/// `MINIDUMP_MEMORY64_LIST`: `NumberOfMemoryRanges` u64, `BaseRva` u64, then
/// `MINIDUMP_MEMORY_DESCRIPTOR64 { StartOfMemoryRange u64, DataSize u64 }`.
/// The data of all ranges is stored back to back from `BaseRva`.
pub(super) fn memory64_list(file: Bytes, loc: Loc) -> Result<Vec<RawRange>> {
    const WHAT: &str = "Memory64ListStream";
    let s = loc.data(file, WHAT)?;
    let count = s.u64(0, WHAT)?;
    let mut file_off = s.u64(8, WHAT)?;
    s.records(16, count, MEMORY_DESCRIPTOR64_SIZE, WHAT)?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let off = 16 + i * MEMORY_DESCRIPTOR64_SIZE;
        let start = s.u64(off, WHAT)?;
        let size = s.u64(off + 8, WHAT)?;
        out.push(checked_range(
            file,
            start,
            size,
            file_off,
            "Memory64ListStream data",
        )?);
        file_off += size; // cannot overflow: checked_range checked file_off + size
    }
    Ok(out)
}

/// `MINIDUMP_MEMORY_LIST`: `NumberOfMemoryRanges` u32, then
/// `MINIDUMP_MEMORY_DESCRIPTOR { StartOfMemoryRange u64, Memory: location }`.
pub(super) fn memory_list(file: Bytes, loc: Loc) -> Result<Vec<RawRange>> {
    const WHAT: &str = "MemoryListStream";
    let s = loc.data(file, WHAT)?;
    let count: u64 = s.u32(0, WHAT)?.into();
    s.records(4, count, MEMORY_DESCRIPTOR_SIZE, WHAT)?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let off = 4 + i * MEMORY_DESCRIPTOR_SIZE;
        let start = s.u64(off, WHAT)?;
        let mem = s.loc(off + 8, WHAT)?;
        out.push(checked_range(
            file,
            start,
            mem.size,
            mem.rva,
            "MemoryListStream data",
        )?);
    }
    Ok(out)
}

/// `MINIDUMP_STRING` at file offset `rva`: `Length` u32 in bytes (without the
/// terminating NUL), then UTF-16LE code units. Invalid UTF-16 is replaced.
pub(super) fn md_string(file: Bytes, rva: u64, what: &str) -> Result<String> {
    let len: u64 = file.u32(rva, what)?.into();
    let s = file.sub(rva + 4, len, what)?;
    let units: Vec<u16> =
        s.0.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// A CodeView debug record from a module entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CodeView {
    /// RSDS: the 16 GUID bytes as stored, then the age as u32 LE (20 bytes).
    /// NB10: the signature u32 LE, then the age u32 LE (8 bytes).
    pub build_id: Vec<u8>,
    pub pdb_name: Option<String>,
}

fn codeview(rec: Bytes) -> Option<CodeView> {
    let sig = rec.u32(0, "").ok()?;
    let name_at = |off: u64| -> Option<String> {
        let tail = rec.tail(off, "").ok()?;
        let end = tail.0.iter().position(|&b| b == 0).unwrap_or(tail.0.len());
        let name = String::from_utf8_lossy(&tail.0[..end]).into_owned();
        (!name.is_empty()).then_some(name)
    };
    match sig {
        CV_SIGNATURE_RSDS => {
            // CV_INFO_PDB70: sig, GUID[16], Age u32, PdbFileName.
            let guid = rec.sub(4, 16, "").ok()?;
            let age = rec.u32(20, "").ok()?;
            let mut id = guid.0.to_vec();
            id.extend_from_slice(&age.to_le_bytes());
            Some(CodeView {
                build_id: id,
                pdb_name: name_at(24),
            })
        }
        CV_SIGNATURE_NB10 => {
            // CV_INFO_PDB20: sig, Offset u32, Signature u32, Age u32, PdbFileName.
            let signature = rec.u32(8, "").ok()?;
            let age = rec.u32(12, "").ok()?;
            let mut id = signature.to_le_bytes().to_vec();
            id.extend_from_slice(&age.to_le_bytes());
            Some(CodeView {
                build_id: id,
                pdb_name: name_at(16),
            })
        }
        _ => None,
    }
}

/// One `MINIDUMP_MODULE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RawModule {
    pub base: u64,
    pub size: u32,
    pub checksum: u32,
    pub timestamp: u32,
    pub name: String,
    /// `VS_FIXEDFILEINFO` `(dwFileVersionMS, dwFileVersionLS)`, if the
    /// structure carries its signature.
    pub file_version: Option<(u32, u32)>,
    pub codeview: Option<CodeView>,
}

/// `MINIDUMP_MODULE_LIST`: `NumberOfModules` u32, then 108-byte
/// `MINIDUMP_MODULE` entries:
///
/// | off | field |
/// |---:|---|
/// | 0 | BaseOfImage u64 |
/// | 8 | SizeOfImage u32 |
/// | 12 | CheckSum u32 |
/// | 16 | TimeDateStamp u32 |
/// | 20 | ModuleNameRva u32 |
/// | 24 | VersionInfo (`VS_FIXEDFILEINFO`, 52 bytes) |
/// | 76 | CvRecord (location) |
/// | 84 | MiscRecord (location) |
/// | 92 | Reserved0, Reserved1 (u64 each) |
pub(super) fn module_list(file: Bytes, loc: Loc) -> Result<Vec<RawModule>> {
    const WHAT: &str = "ModuleListStream";
    let s = loc.data(file, WHAT)?;
    let count: u64 = s.u32(0, WHAT)?.into();
    s.records(4, count, MODULE_SIZE, WHAT)?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let m = s.sub(4 + i * MODULE_SIZE, MODULE_SIZE, WHAT)?;
        let name_rva: u64 = m.u32(20, WHAT)?.into();
        let name = md_string(file, name_rva, "module name")?;
        let file_version = (m.u32(24, WHAT)? == VS_FIXEDFILEINFO_SIGNATURE)
            .then(|| Ok::<_, Error>((m.u32(32, WHAT)?, m.u32(36, WHAT)?)))
            .transpose()?;
        let cv_loc = m.loc(76, WHAT)?;
        let codeview = if cv_loc.size == 0 {
            None
        } else {
            codeview(cv_loc.data(file, "module CodeView record")?)
        };
        out.push(RawModule {
            base: m.u64(0, WHAT)?,
            size: m.u32(8, WHAT)?,
            checksum: m.u32(12, WHAT)?,
            timestamp: m.u32(16, WHAT)?,
            name,
            file_version,
            codeview,
        });
    }
    Ok(out)
}

/// One `MINIDUMP_THREAD`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RawThread {
    pub tid: u32,
    pub teb: u64,
    pub stack_start: u64,
    pub stack_size: u64,
    /// The raw `CONTEXT` record (layout depends on the architecture).
    pub context: Loc,
}

/// `MINIDUMP_THREAD_LIST`: `NumberOfThreads` u32, then 48-byte entries:
/// ThreadId u32 @0, SuspendCount @4, PriorityClass @8, Priority @12,
/// Teb u64 @16, Stack (`MINIDUMP_MEMORY_DESCRIPTOR`) @24, ThreadContext
/// (location) @40.
pub(super) fn thread_list(file: Bytes, loc: Loc) -> Result<Vec<RawThread>> {
    const WHAT: &str = "ThreadListStream";
    let s = loc.data(file, WHAT)?;
    let count: u64 = s.u32(0, WHAT)?.into();
    s.records(4, count, THREAD_SIZE, WHAT)?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let t = s.sub(4 + i * THREAD_SIZE, THREAD_SIZE, WHAT)?;
        let stack = t.loc(32, WHAT)?;
        let context = t.loc(40, WHAT)?;
        context.data(file, "thread context")?;
        out.push(RawThread {
            tid: t.u32(0, WHAT)?,
            teb: t.u64(16, WHAT)?,
            stack_start: t.u64(24, WHAT)?,
            stack_size: stack.size,
            context,
        });
    }
    Ok(out)
}

/// The stack pointer from a thread `CONTEXT` record, if the record is long
/// enough. AMD64 `CONTEXT.Rsp` is at 0x98; ARM64 `CONTEXT.Sp` is at 0x100.
pub(super) fn context_stack_pointer(ctx: Bytes, cpu_arch: u16) -> Option<u64> {
    let off = match cpu_arch {
        cpu::AMD64 => 0x98,
        cpu::ARM64 => 0x100,
        _ => return None,
    };
    ctx.u64(off, "").ok()
}

/// `MINIDUMP_THREAD_NAME_LIST`: `NumberOfThreadNames` u32, then 12-byte
/// entries `{ ThreadId u32, RvaOfThreadName u64 }` pointing at
/// `MINIDUMP_STRING`s.
pub(super) fn thread_names(file: Bytes, loc: Loc) -> Result<Vec<(u32, String)>> {
    const WHAT: &str = "ThreadNamesStream";
    let s = loc.data(file, WHAT)?;
    let count: u64 = s.u32(0, WHAT)?.into();
    s.records(4, count, THREAD_NAME_SIZE, WHAT)?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let off = 4 + i * THREAD_NAME_SIZE;
        let tid = s.u32(off, WHAT)?;
        let rva = s.u64(off + 4, WHAT)?;
        out.push((tid, md_string(file, rva, "thread name")?));
    }
    Ok(out)
}

/// One `MINIDUMP_MEMORY_INFO` (the `MEMORY_BASIC_INFORMATION` of a region).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawMemoryInfo {
    pub base: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub size: u64,
    pub state: u32,
    pub protect: u32,
    pub kind: u32,
}

/// `MINIDUMP_MEMORY_INFO_LIST`: `SizeOfHeader` u32, `SizeOfEntry` u32,
/// `NumberOfEntries` u64, then entries of `SizeOfEntry` bytes from
/// `SizeOfHeader`. Each entry: BaseAddress u64 @0, AllocationBase u64 @8,
/// AllocationProtect u32 @16, RegionSize u64 @24, State u32 @32,
/// Protect u32 @36, Type u32 @40.
pub(super) fn memory_info_list(file: Bytes, loc: Loc) -> Result<Vec<RawMemoryInfo>> {
    const WHAT: &str = "MemoryInfoListStream";
    let s = loc.data(file, WHAT)?;
    let header: u64 = s.u32(0, WHAT)?.into();
    let entry: u64 = s.u32(4, WHAT)?.into();
    let count = s.u64(8, WHAT)?;
    if header < MEMORY_INFO_LIST_MIN_HEADER || entry < MEMORY_INFO_MIN_SIZE {
        return Err(bad(format_args!(
            "{WHAT}: header size {header} / entry size {entry} too small"
        )));
    }
    s.records(header, count, entry, WHAT)?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let e = s.sub(header + i * entry, entry, WHAT)?;
        out.push(RawMemoryInfo {
            base: e.u64(0, WHAT)?,
            allocation_base: e.u64(8, WHAT)?,
            allocation_protect: e.u32(16, WHAT)?,
            size: e.u64(24, WHAT)?,
            state: e.u32(32, WHAT)?,
            protect: e.u32(36, WHAT)?,
            kind: e.u32(40, WHAT)?,
        });
    }
    Ok(out)
}

/// The fields of `MINIDUMP_SYSTEM_INFO` heapspy uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawSystemInfo {
    pub processor_architecture: u16,
    pub number_of_processors: u8,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
}

/// ProcessorArchitecture u16 @0, ProcessorLevel @2, ProcessorRevision @4,
/// NumberOfProcessors u8 @6, ProductType u8 @7, MajorVersion u32 @8,
/// MinorVersion @12, BuildNumber @16, PlatformId @20, ...
pub(super) fn system_info(file: Bytes, loc: Loc) -> Result<RawSystemInfo> {
    const WHAT: &str = "SystemInfoStream";
    let s = loc.data(file, WHAT)?;
    Ok(RawSystemInfo {
        processor_architecture: s.u16(0, WHAT)?,
        number_of_processors: s.u8(6, WHAT)?,
        major_version: s.u32(8, WHAT)?,
        minor_version: s.u32(12, WHAT)?,
        build_number: s.u32(16, WHAT)?,
        platform_id: s.u32(20, WHAT)?,
    })
}

/// `MINIDUMP_MISC_INFO` (any version; later versions only append fields):
/// SizeOfInfo u32 @0, Flags1 u32 @4, ProcessId u32 @8,
/// ProcessCreateTime u32 @12 (Unix seconds), ProcessUserTime @16,
/// ProcessKernelTime @20.
pub(super) fn misc_info(file: Bytes, loc: Loc) -> Result<(Option<u32>, Option<u32>)> {
    const WHAT: &str = "MiscInfoStream";
    const MISC1_PROCESS_ID: u32 = 1;
    const MISC1_PROCESS_TIMES: u32 = 2;
    let s = loc.data(file, WHAT)?;
    let flags = s.u32(4, WHAT)?;
    let pid = s.u32(8, WHAT)?;
    let created = s.u32(12, WHAT)?;
    s.u32(20, WHAT)?; // the version-1 structure is 24 bytes
    Ok((
        (flags & MISC1_PROCESS_ID != 0).then_some(pid),
        (flags & MISC1_PROCESS_TIMES != 0).then_some(created),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_never_panic_at_the_edges() {
        let b = Bytes(&[1, 2, 3, 4]);
        assert_eq!(b.u32(0, "x").unwrap(), 0x0403_0201);
        assert!(b.u32(1, "x").is_err());
        assert!(b.u8(u64::MAX, "x").is_err());
        assert!(b.sub(u64::MAX, 2, "x").is_err());
        assert!(b.sub(2, u64::MAX, "x").is_err());
        assert!(b.tail(5, "x").is_err());
        assert_eq!(b.tail(4, "x").unwrap().len(), 0);
        assert!(b.records(0, u64::MAX, 16, "x").is_err());
    }

    #[test]
    fn codeview_records() {
        let mut rsds = CV_SIGNATURE_RSDS.to_le_bytes().to_vec();
        rsds.extend(1u8..=16);
        rsds.extend(7u32.to_le_bytes());
        rsds.extend(b"python313.pdb\0");
        let cv = codeview(Bytes(&rsds)).unwrap();
        assert_eq!(cv.build_id.len(), 20);
        assert_eq!(&cv.build_id[16..], &7u32.to_le_bytes());
        assert_eq!(cv.pdb_name.as_deref(), Some("python313.pdb"));
        // Truncated GUID, unknown signature: no record, no panic.
        assert!(codeview(Bytes(&rsds[..10])).is_none());
        assert!(codeview(Bytes(b"XXXXabcdefgh")).is_none());
        assert!(codeview(Bytes(&[])).is_none());
        let mut nb10 = CV_SIGNATURE_NB10.to_le_bytes().to_vec();
        nb10.extend(0u32.to_le_bytes());
        nb10.extend(0x1234u32.to_le_bytes());
        nb10.extend(2u32.to_le_bytes());
        let cv = codeview(Bytes(&nb10)).unwrap();
        assert_eq!(cv.build_id, [0x34, 0x12, 0, 0, 2, 0, 0, 0]);
        assert_eq!(cv.pdb_name, None);
    }
}
