//! Memory-mapped allocation profile reader.
//!
//! [`Profile::open`] maps the file and validates it once:
//!
//! - magic, format version, header length, recorded file length;
//! - every section's offset and length against the file size;
//! - record section headers (count * record_len must equal the section length);
//! - the strings and blobs offset arrays in full;
//! - every code entry: string ids in range and valid UTF-8, blob ids in range;
//! - every sample: timestamps non-decreasing, frame ranges contiguous (CSR)
//!   and covering the frames section exactly;
//! - every frame: code id in range or `NO_CODE`.
//!
//! After that, code, sample and frame accessors (including
//! [`Profile::stack`]) cannot fail and do not allocate, except
//! [`ResolvedFrame::location`]. Meta strings are checked on each lookup.
//!
//! A mapped file must not be truncated or modified while a `Profile` is
//! alive; on most platforms that raises SIGBUS or an access violation.

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

use crate::error::{Error, Result};
use crate::format::*;
use crate::linetable;
use crate::types::*;

enum Backing {
    Map(Mmap),
    Owned(Vec<u8>),
}

impl Backing {
    fn bytes(&self) -> &[u8] {
        match self {
            Backing::Map(m) => m,
            Backing::Owned(v) => v,
        }
    }
}

/// A record section: `count` records of `stride` bytes starting at `start`.
#[derive(Clone, Copy, Debug, Default)]
struct Records {
    start: usize,
    count: usize,
    stride: usize,
}

impl Records {
    #[inline]
    fn at<'a>(&self, b: &'a [u8], i: usize) -> &'a [u8] {
        &b[self.start + i * self.stride..][..self.stride]
    }
}

/// A strings or blobs section: `count` entries, offsets array, data.
#[derive(Clone, Copy, Debug, Default)]
struct Table {
    count: usize,
    offsets: usize,
    data: usize,
}

impl Table {
    /// Bytes of entry `i`. Only valid after `validate_offsets`.
    fn get<'a>(&self, b: &'a [u8], i: u32) -> Option<&'a [u8]> {
        let i = i as usize;
        if i >= self.count {
            return None;
        }
        let start = rd_u64(b, self.offsets + i * 8) as usize;
        let end = rd_u64(b, self.offsets + (i + 1) * 8) as usize;
        Some(&b[self.data + start..self.data + end])
    }
}

/// An open allocation profile. See the module docs.
pub struct Profile {
    backing: Backing,
    info: ProfileInfo,
    strings: Table,
    blobs: Table,
    codes: Records,
    samples: Records,
    frames: Records,
    meta: Records,
    /// (code address, code id), sorted, for [`Profile::codes_at`].
    code_index: Vec<(u64, u32)>,
    unknown_sections: Vec<u32>,
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Profile")
            .field("info", &self.info)
            .field("samples", &self.samples.count)
            .field("frames", &self.frames.count)
            .field("codes", &self.codes.count)
            .finish()
    }
}

fn corrupt(msg: impl Into<String>) -> Error {
    Error::Corrupt(msg.into())
}

impl Profile {
    /// Map and validate a profile file.
    pub fn open(path: impl AsRef<Path>) -> Result<Profile> {
        let mut f = File::open(path)?;
        let len = f.metadata()?.len();
        if len < HEADER_LEN as u64 {
            // Too short to map usefully (and empty files cannot be mapped on
            // every platform). Read it so a wrong file type still reports bad
            // magic rather than truncation.
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut f, &mut bytes)?;
            return Self::from_bytes(bytes);
        }
        // SAFETY: the mapping is read-only. Concurrent modification of the
        // file by another process is documented as unsupported.
        #[allow(unsafe_code)]
        let map = unsafe { Mmap::map(&f)? };
        Self::from_backing(Backing::Map(map))
    }

    /// Validate a profile held in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Profile> {
        Self::from_backing(Backing::Owned(bytes))
    }

    fn from_backing(backing: Backing) -> Result<Profile> {
        let b = backing.bytes();
        if b.len() < 4 || b[0..4] != MAGIC {
            return Err(Error::BadMagic);
        }
        if b.len() < 6 {
            return Err(Error::Truncated("file ends inside the header".into()));
        }
        let version = rd_u16(b, H_VERSION);
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: version,
                supported: FORMAT_VERSION,
            });
        }
        if b.len() < HEADER_LEN {
            return Err(Error::Truncated("file ends inside the header".into()));
        }
        let header_len = rd_u16(b, H_HEADER_LEN) as usize;
        if header_len < HEADER_LEN || header_len > b.len() {
            return Err(corrupt(format!("bad header length {header_len}")));
        }
        let file_len = rd_u64(b, H_FILE_LEN);
        if file_len > b.len() as u64 {
            return Err(Error::Truncated(format!(
                "header says {file_len} bytes, file has {}",
                b.len()
            )));
        }
        if file_len < b.len() as u64 {
            return Err(corrupt(format!(
                "header says {file_len} bytes, file has {} (trailing data)",
                b.len()
            )));
        }

        let table_off = rd_u64(b, H_SECTION_TABLE_OFFSET);
        let table_count = rd_u32(b, H_SECTION_COUNT) as u64;
        let table_end = table_count
            .checked_mul(SECTION_ENTRY_LEN as u64)
            .and_then(|n| n.checked_add(table_off))
            .ok_or_else(|| corrupt("section table size overflows"))?;
        if table_off < header_len as u64 || table_end > file_len {
            return Err(corrupt("section table is outside the file"));
        }

        let mut found: HashMap<u32, (usize, usize)> = HashMap::new();
        let mut unknown_sections = Vec::new();
        for i in 0..table_count as usize {
            let e = &b[table_off as usize + i * SECTION_ENTRY_LEN..][..SECTION_ENTRY_LEN];
            let kind = rd_u32(e, 0);
            let sflags = rd_u32(e, 4);
            let off = rd_u64(e, 8);
            let len = rd_u64(e, 16);
            let end = off
                .checked_add(len)
                .ok_or_else(|| corrupt("section bounds overflow"))?;
            if off < table_end || end > file_len {
                return Err(Error::Truncated(format!(
                    "section {} ({kind}) at {off}+{len} is outside the {file_len}-byte file",
                    section_name(kind)
                )));
            }
            if !(SK_STRINGS..=SK_META).contains(&kind) {
                if sflags & SF_REQUIRED != 0 {
                    return Err(Error::UnknownRequiredSection(kind));
                }
                unknown_sections.push(kind);
                continue;
            }
            if found.insert(kind, (off as usize, len as usize)).is_some() {
                return Err(corrupt(format!("duplicate {} section", section_name(kind))));
            }
        }

        let section = |kind: u32| -> Result<(usize, usize)> {
            found
                .get(&kind)
                .copied()
                .ok_or(Error::MissingSection(section_name(kind)))
        };
        let records = |kind: u32, min_len: u32| -> Result<Records> {
            let (off, len) = section(kind)?;
            if len < RECORD_SECTION_HEADER_LEN {
                return Err(Error::Truncated(format!(
                    "{} section header",
                    section_name(kind)
                )));
            }
            let count = rd_u64(b, off);
            let stride = rd_u32(b, off + 8);
            if stride < min_len {
                return Err(corrupt(format!(
                    "{} records are {stride} bytes, expected at least {min_len}",
                    section_name(kind)
                )));
            }
            let body = count
                .checked_mul(stride as u64)
                .ok_or_else(|| corrupt("record count overflows"))?;
            if body != (len - RECORD_SECTION_HEADER_LEN) as u64 {
                return Err(Error::Truncated(format!(
                    "{} section holds {} bytes, {count} records need {body}",
                    section_name(kind),
                    len - RECORD_SECTION_HEADER_LEN
                )));
            }
            Ok(Records {
                start: off + RECORD_SECTION_HEADER_LEN,
                count: count as usize,
                stride: stride as usize,
            })
        };
        let table = |kind: u32| -> Result<Table> {
            let (off, len) = section(kind)?;
            let name = section_name(kind);
            if len < TABLE_HEADER_LEN {
                return Err(Error::Truncated(format!("{name} section header")));
            }
            let count = rd_u64(b, off);
            let data_len = rd_u64(b, off + 8);
            let need = count
                .checked_add(1)
                .and_then(|n| n.checked_mul(8))
                .and_then(|n| n.checked_add(TABLE_HEADER_LEN as u64))
                .and_then(|n| n.checked_add(data_len))
                .ok_or_else(|| corrupt(format!("{name} section size overflows")))?;
            if need != len as u64 {
                return Err(Error::Truncated(format!(
                    "{name} section is {len} bytes, contents need {need}"
                )));
            }
            if count >= u32::MAX as u64 {
                return Err(corrupt(format!("too many {name}")));
            }
            let t = Table {
                count: count as usize,
                offsets: off + TABLE_HEADER_LEN,
                data: off + TABLE_HEADER_LEN + (count as usize + 1) * 8,
            };
            // Offsets: start at 0, non-decreasing, end at data_len.
            let mut prev = 0u64;
            for i in 0..=t.count {
                let o = rd_u64(b, t.offsets + i * 8);
                if (i == 0 && o != 0) || o < prev || o > data_len {
                    return Err(corrupt(format!("{name} offset {i} is out of order")));
                }
                prev = o;
            }
            if prev != data_len {
                return Err(corrupt(format!(
                    "{name} offsets do not end at the data length"
                )));
            }
            Ok(t)
        };

        let strings = table(SK_STRINGS)?;
        let blobs = table(SK_BLOBS)?;
        let codes = records(SK_CODES, CODE_RECORD_LEN)?;
        let samples = records(SK_SAMPLES, SAMPLE_RECORD_LEN)?;
        let frames = records(SK_FRAMES, FRAME_RECORD_LEN)?;
        let meta = match found.contains_key(&SK_META) {
            true => records(SK_META, META_RECORD_LEN)?,
            false => Records::default(),
        };

        if codes.count >= NO_CODE as usize {
            return Err(corrupt("too many code entries"));
        }

        // Codes: string and blob ids resolve.
        let check_str = |raw: u32, i: usize, what: &str| -> Result<()> {
            if raw == NO_STRING {
                return Ok(());
            }
            let ok = strings
                .get(b, raw)
                .is_some_and(|s| std::str::from_utf8(s).is_ok());
            if ok {
                Ok(())
            } else {
                Err(corrupt(format!(
                    "code {i} has a bad {what} string id {raw}"
                )))
            }
        };
        let mut code_index = Vec::with_capacity(codes.count);
        for i in 0..codes.count {
            let r = codes.at(b, i);
            check_str(rd_u32(r, 8), i, "qualname")?;
            check_str(rd_u32(r, 12), i, "filename")?;
            let blob = rd_u32(r, 20);
            if blob != NO_BLOB && blob as usize >= blobs.count {
                return Err(Error::InvalidBlob(blob));
            }
            code_index.push((rd_u64(r, 0), i as u32));
        }
        code_index.sort_unstable();

        // Samples: sorted by time, CSR-contiguous frame ranges.
        let mut prev_ts = 0u64;
        let mut next_frame = 0u64;
        for i in 0..samples.count {
            let r = samples.at(b, i);
            let ts = rd_u64(r, 0);
            if ts < prev_ts {
                return Err(corrupt(format!("samples not sorted by time at index {i}")));
            }
            prev_ts = ts;
            let start = rd_u64(r, 48);
            let count = rd_u32(r, 56) as u64;
            if start != next_frame {
                return Err(corrupt(format!("sample {i} frame range is not contiguous")));
            }
            next_frame = start + count;
            if next_frame > frames.count as u64 {
                return Err(corrupt(format!(
                    "sample {i} frame range exceeds the frames section"
                )));
            }
        }
        if next_frame != frames.count as u64 {
            return Err(corrupt(
                "frames section has records not owned by any sample",
            ));
        }

        // Frames: code ids resolve.
        for i in 0..frames.count {
            let c = rd_u32(frames.at(b, i), 0);
            if c != NO_CODE && c as usize >= codes.count {
                return Err(Error::InvalidCode(c));
            }
        }

        let flags = rd_u32(b, H_FLAGS);
        let info = ProfileInfo {
            format_version: version,
            pid: rd_u32(b, H_PID),
            python: PythonVersion {
                major: b[H_PY_MAJOR],
                minor: b[H_PY_MINOR],
                micro: b[H_PY_MICRO],
                release_level: b[H_PY_RELEASE_LEVEL],
                release_serial: b[H_PY_RELEASE_SERIAL],
            },
            pointer_size: b[H_POINTER_SIZE],
            os: Os::from_code(b[H_OS]),
            arch: Arch::from_code(b[H_ARCH]),
            start_ns: rd_u64(b, H_START_NS),
            end_ns: rd_u64(b, H_END_NS),
            mechanisms: Mechanisms(rd_u32(b, H_MECHANISMS)),
            sampling: SamplingParams {
                events: EventKinds(rd_u32(b, H_EVENTS)),
                byte_interval: rd_u64(b, H_BYTE_INTERVAL),
                max_frames: rd_u32(b, H_MAX_FRAMES),
                native_min_size: rd_u32(b, H_NATIVE_MIN_SIZE),
            },
            overhead: Overhead {
                samples_taken: rd_u64(b, H_SAMPLES_TAKEN),
                samples_dropped: rd_u64(b, H_SAMPLES_DROPPED),
                probe_hits: rd_u64(b, H_PROBE_HITS),
                total_pause_ns: rd_u64(b, H_TOTAL_PAUSE_NS),
            },
            truncated: flags & HF_TRUNCATED != 0,
        };

        Ok(Profile {
            backing,
            info,
            strings,
            blobs,
            codes,
            samples,
            frames,
            meta,
            code_index,
            unknown_sections,
        })
    }

    #[inline]
    fn b(&self) -> &[u8] {
        self.backing.bytes()
    }

    /// Decoded header.
    pub fn info(&self) -> &ProfileInfo {
        &self.info
    }

    /// Section kinds present in the file that this build does not know (and
    /// that were not marked required). They are skipped.
    pub fn unknown_sections(&self) -> &[u32] {
        &self.unknown_sections
    }

    // ---- strings and blobs ----

    pub fn string_count(&self) -> usize {
        self.strings.count
    }

    /// Look up a string by id.
    pub fn string(&self, id: StrId) -> Result<&str> {
        let bytes = self
            .strings
            .get(self.b(), id.0)
            .ok_or(Error::InvalidString(id.0))?;
        std::str::from_utf8(bytes).map_err(|_| Error::InvalidString(id.0))
    }

    pub fn blob_count(&self) -> usize {
        self.blobs.count
    }

    /// Look up a blob by id.
    pub fn blob(&self, id: BlobId) -> Result<&[u8]> {
        self.blobs
            .get(self.b(), id.0)
            .ok_or(Error::InvalidBlob(id.0))
    }

    // ---- codes ----

    pub fn code_count(&self) -> usize {
        self.codes.count
    }

    /// Code entry by id, or `None` if out of range.
    pub fn code(&self, id: CodeId) -> Option<CodeEntry> {
        ((id.0 as usize) < self.codes.count).then(|| self.decode_code(id.0))
    }

    fn decode_code(&self, i: u32) -> CodeEntry {
        let r = self.codes.at(self.b(), i as usize);
        CodeEntry {
            id: CodeId(i),
            addr: rd_u64(r, 0),
            qualname: dec_str(rd_u32(r, 8)),
            filename: dec_str(rd_u32(r, 12)),
            firstlineno: rd_u32(r, 16) as i32,
            linetable: dec_blob(rd_u32(r, 20)),
            linetable_format: LineTableFormat::from_code(r[24]),
            unresolved: r[25] & CF_UNRESOLVED != 0,
        }
    }

    /// All code entries in id order.
    pub fn codes(&self) -> impl ExactSizeIterator<Item = CodeEntry> + '_ {
        (0..self.codes.count as u32).map(move |i| self.decode_code(i))
    }

    /// Every entry for the code object address `addr`, oldest first. There is
    /// more than one if a code object was freed and another allocated at
    /// the same address during recording.
    pub fn codes_at(&self, addr: u64) -> impl Iterator<Item = CodeEntry> + '_ {
        let lo = self.code_index.partition_point(|e| e.0 < addr);
        self.code_index[lo..]
            .iter()
            .take_while(move |e| e.0 == addr)
            .map(move |e| self.decode_code(e.1))
    }

    /// A code entry's string field. Validated on open, so this only returns
    /// `None` when the field is absent.
    fn code_str(&self, id: Option<StrId>) -> Option<&str> {
        id.and_then(|s| self.string(s).ok())
    }

    /// `co_qualname` of a code entry.
    pub fn code_qualname(&self, code: &CodeEntry) -> Option<&str> {
        self.code_str(code.qualname)
    }

    /// `co_filename` of a code entry.
    pub fn code_filename(&self, code: &CodeEntry) -> Option<&str> {
        self.code_str(code.filename)
    }

    /// Raw `co_linetable` bytes of a code entry.
    pub fn code_linetable(&self, code: &CodeEntry) -> Option<&[u8]> {
        code.linetable.and_then(|b| self.blob(b).ok())
    }

    /// Source line of the instruction at byte `instr_offset` of the code
    /// object's bytecode, for 3.12, 3.13 and 3.14 line tables. With no
    /// offset, `co_firstlineno`. `None` when the instruction has no line,
    /// the table is missing or in an unknown format, or the offset is past
    /// its end.
    pub fn line(&self, code: &CodeEntry, instr_offset: Option<u32>) -> Option<u32> {
        if code.unresolved {
            return None;
        }
        let table = self.code_linetable(code).unwrap_or(&[]);
        linetable::line_for(code.linetable_format, table, code.firstlineno, instr_offset)
    }

    // ---- samples and frames ----

    pub fn sample_count(&self) -> u64 {
        self.samples.count as u64
    }

    /// Sample by index, or `None` if out of range.
    pub fn sample(&self, index: u64) -> Option<Sample> {
        (index < self.samples.count as u64).then(|| self.decode_sample(index))
    }

    fn decode_sample(&self, index: u64) -> Sample {
        let r = self.samples.at(self.b(), index as usize);
        let ret = rd_u64(r, 40);
        Sample {
            index,
            timestamp_ns: rd_u64(r, 0),
            tid: rd_u64(r, 8),
            address: rd_u64(r, 16),
            size: rd_u64(r, 24),
            weight: rd_u64(r, 32),
            native_return_address: (ret != 0).then_some(ret),
            frame_start: rd_u64(r, 48),
            frame_count: rd_u32(r, 56),
            kind: EventKind::from_code(r[60]),
            flags: SampleFlags(r[61]),
        }
    }

    /// All samples, oldest first.
    pub fn samples(&self) -> impl ExactSizeIterator<Item = Sample> + '_ {
        (0..self.samples.count).map(move |i| self.decode_sample(i as u64))
    }

    pub fn frame_count(&self) -> u64 {
        self.frames.count as u64
    }

    /// Frame by global index, or `None` if out of range.
    pub fn frame(&self, index: u64) -> Option<Frame> {
        (index < self.frames.count as u64).then(|| self.decode_frame(index))
    }

    fn decode_frame(&self, index: u64) -> Frame {
        let r = self.frames.at(self.b(), index as usize);
        let flags = rd_u16(r, 8);
        Frame {
            code: dec_code(rd_u32(r, 0)),
            instr_offset: (flags & FF_NO_OFFSET == 0).then(|| rd_u32(r, 4)),
            approximate: flags & FF_APPROXIMATE != 0,
        }
    }

    /// The raw frames of a sample, innermost first.
    pub fn frames(&self, sample: &Sample) -> impl ExactSizeIterator<Item = Frame> + '_ {
        let (start, count) = self.frame_range(sample);
        (start..start + count).map(move |i| self.decode_frame(i as u64))
    }

    /// Clamp a sample's frame range to the frames section, so a `Sample`
    /// value from another profile cannot cause an out-of-range read.
    fn frame_range(&self, s: &Sample) -> (usize, usize) {
        let total = self.frames.count;
        let start = s.frame_start.min(total as u64) as usize;
        (start, (s.frame_count as usize).min(total - start))
    }

    /// Look up a frame's code entry and compute its line.
    pub fn resolve(&self, frame: Frame) -> ResolvedFrame<'_> {
        match frame.code.and_then(|c| self.code(c)) {
            Some(code) => ResolvedFrame {
                code_addr: Some(code.addr),
                qualname: self.code_qualname(&code),
                filename: self.code_filename(&code),
                line: self.line(&code, frame.instr_offset),
                approximate: frame.approximate,
            },
            None => ResolvedFrame {
                code_addr: None,
                qualname: None,
                filename: None,
                line: None,
                approximate: frame.approximate,
            },
        }
    }

    /// The resolved Python stack of a sample, innermost first: `qualname`
    /// and `file:line` per frame.
    pub fn stack(&self, sample: &Sample) -> impl ExactSizeIterator<Item = ResolvedFrame<'_>> + '_ {
        let (start, count) = self.frame_range(sample);
        (start..start + count).map(move |i| self.resolve(self.decode_frame(i as u64)))
    }

    // ---- meta ----

    /// Meta key/value pairs as string ids.
    pub fn meta(&self) -> impl ExactSizeIterator<Item = (StrId, StrId)> + '_ {
        let b = self.b();
        (0..self.meta.count).map(move |i| {
            let r = self.meta.at(b, i);
            (StrId(rd_u32(r, 0)), StrId(rd_u32(r, 4)))
        })
    }

    /// First meta value for `key`.
    pub fn meta_value(&self, key: &str) -> Result<Option<&str>> {
        for (k, v) in self.meta() {
            if self.string(k)? == key {
                return Ok(Some(self.string(v)?));
            }
        }
        Ok(None)
    }
}
