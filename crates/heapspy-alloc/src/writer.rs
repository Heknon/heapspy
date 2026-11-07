//! Streaming allocation profile writer.
//!
//! Samples may arrive in any order, each with its frames. Sample and frame
//! records are appended to spill buffers (in memory, or in anonymous
//! temporary files when a spill directory is given). Only a 16-byte
//! `(timestamp, spill index)` key per sample, the code table and the
//! string and blob tables stay in memory. [`AllocWriter::finish`] sorts the
//! keys by timestamp (stable, so equal timestamps keep arrival order) and
//! writes the file sequentially, so the output only needs [`Write`].
//!
//! Code entries can be added before their samples ([`AllocWriter::add_code`])
//! or created as placeholders from an address while recording
//! ([`AllocWriter::code_for_addr`]) and filled in later
//! ([`AllocWriter::set_code`]), once the recorder has read the code object.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use memmap2::Mmap;

use crate::error::{Error, Result};
use crate::format::*;
use crate::types::*;

/// Summary returned by [`AllocWriter::finish`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteStats {
    pub samples: u64,
    pub frames: u64,
    pub codes: u64,
    pub strings: u64,
    pub blobs: u64,
    pub bytes_written: u64,
}

/// A code object as handed to [`AllocWriter::add_code`] or [`AllocWriter::set_code`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodeInput<'a> {
    /// Address of the code object in the target.
    pub addr: u64,
    pub qualname: Option<&'a str>,
    pub filename: Option<&'a str>,
    pub firstlineno: i32,
    /// Raw `co_linetable` bytes.
    pub linetable: Option<&'a [u8]>,
    /// Encoding of `linetable`. Ignored (written as `None`) without a table.
    pub linetable_format: LineTableFormat,
}

impl<'a> CodeInput<'a> {
    /// A resolved code object with a CPython 3.11+ location table.
    pub fn new(
        addr: u64,
        qualname: &'a str,
        filename: &'a str,
        firstlineno: i32,
        linetable: &'a [u8],
    ) -> Self {
        Self {
            addr,
            qualname: Some(qualname),
            filename: Some(filename),
            firstlineno,
            linetable: Some(linetable),
            linetable_format: LineTableFormat::Locations311,
        }
    }
}

/// A sample as handed to [`AllocWriter::add_sample`]. The frame range is
/// filled in by the writer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SampleInput {
    /// Nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    pub tid: u64,
    pub kind: EventKind,
    pub address: u64,
    pub size: u64,
    /// Bytes this sample stands for; see [`crate::sampled_weight`].
    pub weight: u64,
    pub native_return_address: Option<u64>,
    pub flags: SampleFlags,
}

/// One frame as handed to [`AllocWriter::add_sample`], innermost first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameInput {
    pub code: Option<CodeId>,
    pub instr_offset: Option<u32>,
    pub approximate: bool,
}

enum Spill {
    Mem(Vec<u8>),
    File(BufWriter<File>),
}

impl Spill {
    fn new(dir: Option<&Path>) -> Result<Self> {
        Ok(match dir {
            None => Spill::Mem(Vec::new()),
            Some(d) => Spill::File(BufWriter::with_capacity(1 << 20, tempfile::tempfile_in(d)?)),
        })
    }

    fn write(&mut self, b: &[u8]) -> io::Result<()> {
        match self {
            Spill::Mem(v) => {
                v.extend_from_slice(b);
                Ok(())
            }
            Spill::File(w) => w.write_all(b),
        }
    }

    fn into_data(self) -> Result<SpillData> {
        Ok(match self {
            Spill::Mem(v) => SpillData::Mem(v),
            Spill::File(w) => {
                let f = w.into_inner().map_err(|e| e.into_error())?;
                if f.metadata()?.len() == 0 {
                    SpillData::Mem(Vec::new())
                } else {
                    // SAFETY: the file is an anonymous temporary file owned by
                    // this writer; nothing else can modify or truncate it.
                    #[allow(unsafe_code)]
                    let m = unsafe { Mmap::map(&f)? };
                    SpillData::Map(m)
                }
            }
        })
    }
}

enum SpillData {
    Mem(Vec<u8>),
    Map(Mmap),
}

impl SpillData {
    fn bytes(&self) -> &[u8] {
        match self {
            SpillData::Mem(v) => v,
            SpillData::Map(m) => m,
        }
    }
}

/// A deduplicating table of byte strings (the strings and blobs sections).
#[derive(Default)]
struct Table {
    map: HashMap<Box<[u8]>, u32>,
    data: Vec<u8>,
    offsets: Vec<u64>,
}

impl Table {
    fn intern(&mut self, s: &[u8], what: &'static str) -> Result<u32> {
        if let Some(&id) = self.map.get(s) {
            return Ok(id);
        }
        if self.offsets.is_empty() {
            self.offsets.push(0);
        }
        let id = self.map.len();
        if id >= u32::MAX as usize {
            return Err(Error::LimitExceeded(what));
        }
        self.data.extend_from_slice(s);
        self.offsets.push(self.data.len() as u64);
        self.map.insert(s.into(), id as u32);
        Ok(id as u32)
    }

    fn len(&self) -> u32 {
        self.map.len() as u32
    }

    fn section_len(&self) -> u64 {
        TABLE_HEADER_LEN as u64 + (self.len() as u64 + 1) * 8 + self.data.len() as u64
    }

    fn write<W: Write>(&self, out: &mut Counting<W>) -> io::Result<()> {
        let mut hdr = [0u8; TABLE_HEADER_LEN];
        wr_u64(&mut hdr, 0, self.len() as u64);
        wr_u64(&mut hdr, 8, self.data.len() as u64);
        out.write_all(&hdr)?;
        if self.offsets.is_empty() {
            out.write_all(&0u64.to_le_bytes())?;
        }
        for o in &self.offsets {
            out.write_all(&o.to_le_bytes())?;
        }
        out.write_all(&self.data)
    }
}

/// The in-memory form of a code record.
#[derive(Clone, Copy)]
struct CodeRec {
    addr: u64,
    qualname: u32,
    filename: u32,
    firstlineno: i32,
    linetable: u32,
    format: u8,
    flags: u8,
}

/// Builds an allocation profile file. See the module docs.
pub struct AllocWriter {
    info: ProfileInfo,
    strings: Table,
    blobs: Table,
    codes: Vec<CodeRec>,
    /// Latest code entry per address, for [`AllocWriter::code_for_addr`].
    code_by_addr: HashMap<u64, u32>,
    samples: Spill,
    frames: Spill,
    keys: Vec<(u64, u32)>,
    frame_total: u64,
    meta: Vec<(u32, u32)>,
    frame_buf: Vec<u8>,
}

/// Bytes per sample in the spill buffer: the sample record as written,
/// with `frame_start` pointing into the frames spill.
const SPILL_SAMPLE_LEN: usize = SAMPLE_RECORD_LEN as usize;

impl AllocWriter {
    /// A writer that keeps spill buffers in memory. Fine for tests and short
    /// recordings; use [`AllocWriter::with_spill_dir`] for real ones.
    pub fn new(info: ProfileInfo) -> Result<Self> {
        Self::build(info, None)
    }

    /// A writer that spills sample and frame records to anonymous temporary
    /// files in `dir` (normally the output file's directory). Memory use is
    /// then 16 bytes per sample plus the code, string and blob tables.
    pub fn with_spill_dir(info: ProfileInfo, dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        Self::build(info, Some(&dir))
    }

    fn build(info: ProfileInfo, dir: Option<&Path>) -> Result<Self> {
        Ok(Self {
            info,
            strings: Table::default(),
            blobs: Table::default(),
            codes: Vec::new(),
            code_by_addr: HashMap::new(),
            samples: Spill::new(dir)?,
            frames: Spill::new(dir)?,
            keys: Vec::new(),
            frame_total: 0,
            meta: Vec::new(),
            frame_buf: Vec::new(),
        })
    }

    /// Header fields. Set `end_ns`, `overhead` and `truncated` here when
    /// recording stops.
    pub fn info_mut(&mut self) -> &mut ProfileInfo {
        &mut self.info
    }

    pub fn info(&self) -> &ProfileInfo {
        &self.info
    }

    /// Add `s` to the string table, or return its existing id.
    pub fn intern(&mut self, s: &str) -> Result<StrId> {
        self.strings
            .intern(s.as_bytes(), "more than 2^32-1 strings")
            .map(StrId)
    }

    /// Add `b` to the blob table, or return its existing id.
    pub fn intern_blob(&mut self, b: &[u8]) -> Result<BlobId> {
        self.blobs.intern(b, "more than 2^32-1 blobs").map(BlobId)
    }

    fn code_rec(&mut self, c: &CodeInput<'_>) -> Result<CodeRec> {
        let qualname = enc_str(c.qualname.map(|s| self.intern(s)).transpose()?);
        let filename = enc_str(c.filename.map(|s| self.intern(s)).transpose()?);
        let (linetable, format) = match c.linetable {
            Some(t) => (
                enc_blob(Some(self.intern_blob(t)?)),
                c.linetable_format.code(),
            ),
            None => (NO_BLOB, LineTableFormat::None.code()),
        };
        Ok(CodeRec {
            addr: c.addr,
            qualname,
            filename,
            firstlineno: c.firstlineno,
            linetable,
            format,
            flags: 0,
        })
    }

    fn push_code(&mut self, rec: CodeRec) -> Result<CodeId> {
        let id = self.codes.len();
        if id >= NO_CODE as usize {
            return Err(Error::LimitExceeded("more than 2^32-1 code entries"));
        }
        self.codes.push(rec);
        self.code_by_addr.insert(rec.addr, id as u32);
        Ok(CodeId(id as u32))
    }

    /// Add a code entry. Each call creates a new entry, even for an address
    /// seen before: a code object freed during recording and a new one
    /// allocated at the same address are two entries.
    pub fn add_code(&mut self, code: &CodeInput<'_>) -> Result<CodeId> {
        let rec = self.code_rec(code)?;
        self.push_code(rec)
    }

    /// The latest entry for `addr`, or a new unresolved entry (address only)
    /// if there is none. Use while recording, then fill it in with
    /// [`AllocWriter::set_code`].
    pub fn code_for_addr(&mut self, addr: u64) -> Result<CodeId> {
        if let Some(&id) = self.code_by_addr.get(&addr) {
            return Ok(CodeId(id));
        }
        self.add_unresolved_code(addr)
    }

    /// A new address-only entry (flag `UNRESOLVED`), even if `addr` has
    /// entries already. A recorder calls this when it sees that the code
    /// object at a known address was replaced.
    pub fn add_unresolved_code(&mut self, addr: u64) -> Result<CodeId> {
        self.push_code(CodeRec {
            addr,
            qualname: NO_STRING,
            filename: NO_STRING,
            firstlineno: 0,
            linetable: NO_BLOB,
            format: 0,
            flags: CF_UNRESOLVED,
        })
    }

    /// Replace entry `id` (for example a placeholder from
    /// [`AllocWriter::code_for_addr`]) with resolved data. The address must
    /// match the entry's.
    pub fn set_code(&mut self, id: CodeId, code: &CodeInput<'_>) -> Result<()> {
        let Some(old) = self.codes.get(id.0 as usize).copied() else {
            return Err(Error::InvalidCode(id.0));
        };
        if old.addr != code.addr {
            return Err(Error::InvalidArgument(format!(
                "code {} is at {:#x}, not {:#x}",
                id.0, old.addr, code.addr
            )));
        }
        let rec = self.code_rec(code)?;
        self.codes[id.0 as usize] = rec;
        Ok(())
    }

    /// Number of code entries so far.
    pub fn code_count(&self) -> u32 {
        self.codes.len() as u32
    }

    /// Whether entry `id` is still an address-only placeholder.
    pub fn code_is_unresolved(&self, id: CodeId) -> bool {
        self.codes
            .get(id.0 as usize)
            .is_some_and(|c| c.flags & CF_UNRESOLVED != 0)
    }

    /// Add one sample with its Python frames, innermost first. Every frame's
    /// code id must already exist.
    pub fn add_sample(&mut self, s: &SampleInput, frames: &[FrameInput]) -> Result<()> {
        if self.keys.len() >= u32::MAX as usize {
            return Err(Error::LimitExceeded("more than 2^32-1 samples"));
        }
        let count: u32 = frames
            .len()
            .try_into()
            .map_err(|_| Error::LimitExceeded("more than 2^32-1 frames in one sample"))?;
        self.frame_buf.clear();
        for f in frames {
            if let Some(c) = f.code {
                if c.0 as usize >= self.codes.len() {
                    return Err(Error::InvalidCode(c.0));
                }
            }
            let mut r = [0u8; FRAME_RECORD_LEN as usize];
            wr_u32(&mut r, 0, enc_code(f.code));
            let mut flags = 0u16;
            if f.approximate {
                flags |= FF_APPROXIMATE;
            }
            match f.instr_offset {
                Some(o) => wr_u32(&mut r, 4, o),
                None => flags |= FF_NO_OFFSET,
            }
            wr_u16(&mut r, 8, flags);
            self.frame_buf.extend_from_slice(&r);
        }

        let mut r = [0u8; SPILL_SAMPLE_LEN];
        wr_u64(&mut r, 0, s.timestamp_ns);
        wr_u64(&mut r, 8, s.tid);
        wr_u64(&mut r, 16, s.address);
        wr_u64(&mut r, 24, s.size);
        wr_u64(&mut r, 32, s.weight);
        wr_u64(&mut r, 40, s.native_return_address.unwrap_or(0));
        wr_u64(&mut r, 48, self.frame_total);
        wr_u32(&mut r, 56, count);
        r[60] = s.kind.code();
        r[61] = s.flags.0;

        self.frames.write(&self.frame_buf)?;
        self.samples.write(&r)?;
        self.keys.push((s.timestamp_ns, self.keys.len() as u32));
        self.frame_total += count as u64;
        Ok(())
    }

    /// Add a free-form key/value pair to the meta section (e.g.
    /// `heapspy.version`). Keys are not required to be unique.
    pub fn add_meta(&mut self, key: &str, value: &str) -> Result<()> {
        let k = self.intern(key)?;
        let v = self.intern(value)?;
        self.meta.push((k.0, v.0));
        Ok(())
    }

    pub fn sample_count(&self) -> u64 {
        self.keys.len() as u64
    }

    pub fn frame_count(&self) -> u64 {
        self.frame_total
    }

    /// Write the profile atomically to `path` (via a temporary file in the
    /// same directory that is renamed into place).
    pub fn finish_to_path(self, path: impl AsRef<Path>) -> Result<WriteStats> {
        let path = path.as_ref();
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
        let stats = self.finish(BufWriter::with_capacity(1 << 20, tmp.as_file_mut()))?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| Error::Io(e.error))?;
        Ok(stats)
    }

    /// Write the profile into a byte vector.
    pub fn finish_to_vec(self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        self.finish(&mut v)?;
        Ok(v)
    }

    /// Sort, lay out and write the profile to `out`.
    pub fn finish<W: Write>(mut self, out: W) -> Result<WriteStats> {
        // Stable: equal timestamps keep arrival order.
        self.keys.sort_by_key(|k| k.0);

        let samples = std::mem::replace(&mut self.samples, Spill::Mem(Vec::new())).into_data()?;
        let frames = std::mem::replace(&mut self.frames, Spill::Mem(Vec::new())).into_data()?;
        let sample_bytes = samples.bytes();
        let frame_bytes = frames.bytes();

        let rec = |n: u64, len: u32| RECORD_SECTION_HEADER_LEN as u64 + n * len as u64;
        let sections: [(u32, u32, u64); 6] = [
            (SK_STRINGS, SF_REQUIRED, self.strings.section_len()),
            (SK_BLOBS, SF_REQUIRED, self.blobs.section_len()),
            (
                SK_CODES,
                SF_REQUIRED,
                rec(self.codes.len() as u64, CODE_RECORD_LEN),
            ),
            (
                SK_SAMPLES,
                SF_REQUIRED,
                rec(self.keys.len() as u64, SAMPLE_RECORD_LEN),
            ),
            (
                SK_FRAMES,
                SF_REQUIRED,
                rec(self.frame_total, FRAME_RECORD_LEN),
            ),
            (SK_META, 0, rec(self.meta.len() as u64, META_RECORD_LEN)),
        ];

        let table_offset = HEADER_LEN as u64;
        let mut pos = align_up(table_offset + (sections.len() * SECTION_ENTRY_LEN) as u64);
        let mut offsets = [0u64; 6];
        for (i, &(_, _, len)) in sections.iter().enumerate() {
            offsets[i] = pos;
            pos = align_up(pos + len);
        }
        let file_len = pos;

        let mut out = Counting { inner: out, pos: 0 };
        out.write_all(&encode_header(
            &self.info,
            table_offset,
            sections.len() as u32,
            file_len,
        ))?;

        for (i, &(kind, sflags, len)) in sections.iter().enumerate() {
            let mut e = [0u8; SECTION_ENTRY_LEN];
            wr_u32(&mut e, 0, kind);
            wr_u32(&mut e, 4, sflags);
            wr_u64(&mut e, 8, offsets[i]);
            wr_u64(&mut e, 16, len);
            out.write_all(&e)?;
        }

        for (i, &(kind, _, _)) in sections.iter().enumerate() {
            out.pad_to(offsets[i])?;
            match kind {
                SK_STRINGS => self.strings.write(&mut out)?,
                SK_BLOBS => self.blobs.write(&mut out)?,
                SK_CODES => {
                    out.record_header(self.codes.len() as u64, CODE_RECORD_LEN)?;
                    for c in &self.codes {
                        let mut r = [0u8; CODE_RECORD_LEN as usize];
                        wr_u64(&mut r, 0, c.addr);
                        wr_u32(&mut r, 8, c.qualname);
                        wr_u32(&mut r, 12, c.filename);
                        wr_u32(&mut r, 16, c.firstlineno as u32);
                        wr_u32(&mut r, 20, c.linetable);
                        r[24] = c.format;
                        r[25] = c.flags;
                        out.write_all(&r)?;
                    }
                }
                SK_SAMPLES => {
                    out.record_header(self.keys.len() as u64, SAMPLE_RECORD_LEN)?;
                    let mut frame_start = 0u64;
                    for &(_, si) in &self.keys {
                        let s = &sample_bytes[si as usize * SPILL_SAMPLE_LEN..][..SPILL_SAMPLE_LEN];
                        let mut r = [0u8; SAMPLE_RECORD_LEN as usize];
                        r.copy_from_slice(s);
                        wr_u64(&mut r, 48, frame_start);
                        out.write_all(&r)?;
                        frame_start += rd_u32(s, 56) as u64;
                    }
                }
                SK_FRAMES => {
                    out.record_header(self.frame_total, FRAME_RECORD_LEN)?;
                    for &(_, si) in &self.keys {
                        let s = &sample_bytes[si as usize * SPILL_SAMPLE_LEN..][..SPILL_SAMPLE_LEN];
                        let start = rd_u64(s, 48) as usize * FRAME_RECORD_LEN as usize;
                        let len = rd_u32(s, 56) as usize * FRAME_RECORD_LEN as usize;
                        out.write_all(&frame_bytes[start..start + len])?;
                    }
                }
                SK_META => {
                    out.record_header(self.meta.len() as u64, META_RECORD_LEN)?;
                    for &(k, v) in &self.meta {
                        let mut r = [0u8; META_RECORD_LEN as usize];
                        wr_u32(&mut r, 0, k);
                        wr_u32(&mut r, 4, v);
                        out.write_all(&r)?;
                    }
                }
                _ => unreachable!("writer only emits known sections"),
            }
        }
        out.pad_to(file_len)?;
        out.inner.flush()?;

        Ok(WriteStats {
            samples: self.keys.len() as u64,
            frames: self.frame_total,
            codes: self.codes.len() as u64,
            strings: self.strings.len() as u64,
            blobs: self.blobs.len() as u64,
            bytes_written: out.pos,
        })
    }
}

fn encode_header(
    info: &ProfileInfo,
    table_offset: u64,
    section_count: u32,
    file_len: u64,
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[H_MAGIC..H_MAGIC + 4].copy_from_slice(&MAGIC);
    wr_u16(&mut h, H_VERSION, FORMAT_VERSION);
    wr_u16(&mut h, H_HEADER_LEN, HEADER_LEN as u16);
    h[H_PY_MAJOR] = info.python.major;
    h[H_PY_MINOR] = info.python.minor;
    h[H_PY_MICRO] = info.python.micro;
    h[H_PY_RELEASE_LEVEL] = info.python.release_level;
    h[H_PY_RELEASE_SERIAL] = info.python.release_serial;
    h[H_POINTER_SIZE] = info.pointer_size;
    h[H_OS] = info.os.code();
    h[H_ARCH] = info.arch.code();
    wr_u32(&mut h, H_PID, info.pid);
    wr_u32(
        &mut h,
        H_FLAGS,
        if info.truncated { HF_TRUNCATED } else { 0 },
    );
    wr_u32(&mut h, H_MECHANISMS, info.mechanisms.0);
    wr_u32(&mut h, H_EVENTS, info.sampling.events.0);
    wr_u64(&mut h, H_START_NS, info.start_ns);
    wr_u64(&mut h, H_END_NS, info.end_ns);
    wr_u64(&mut h, H_BYTE_INTERVAL, info.sampling.byte_interval);
    wr_u32(&mut h, H_MAX_FRAMES, info.sampling.max_frames);
    wr_u32(&mut h, H_NATIVE_MIN_SIZE, info.sampling.native_min_size);
    wr_u64(&mut h, H_SAMPLES_TAKEN, info.overhead.samples_taken);
    wr_u64(&mut h, H_SAMPLES_DROPPED, info.overhead.samples_dropped);
    wr_u64(&mut h, H_PROBE_HITS, info.overhead.probe_hits);
    wr_u64(&mut h, H_TOTAL_PAUSE_NS, info.overhead.total_pause_ns);
    wr_u64(&mut h, H_SECTION_TABLE_OFFSET, table_offset);
    wr_u32(&mut h, H_SECTION_COUNT, section_count);
    wr_u64(&mut h, H_FILE_LEN, file_len);
    h
}

struct Counting<W: Write> {
    inner: W,
    pos: u64,
}

impl<W: Write> Counting<W> {
    fn write_all(&mut self, b: &[u8]) -> io::Result<()> {
        self.inner.write_all(b)?;
        self.pos += b.len() as u64;
        Ok(())
    }

    fn pad_to(&mut self, target: u64) -> io::Result<()> {
        debug_assert!(target >= self.pos, "layout error: {target} < {}", self.pos);
        while self.pos < target {
            let n = (target - self.pos).min(8) as usize;
            self.write_all(&[0u8; 8][..n])?;
        }
        Ok(())
    }

    fn record_header(&mut self, count: u64, record_len: u32) -> io::Result<()> {
        let mut h = [0u8; RECORD_SECTION_HEADER_LEN];
        wr_u64(&mut h, 0, count);
        wr_u32(&mut h, 8, record_len);
        self.write_all(&h)
    }
}
