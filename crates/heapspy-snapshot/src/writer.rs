//! Streaming snapshot writer.
//!
//! Objects may be added in any order, each with all of its outgoing edges.
//! Object and edge records are appended to spill buffers (in memory, or in
//! anonymous temporary files when a spill directory is given). Only a
//! 16-byte `(addr, spill index)` key per object and the string table are kept
//! in memory. [`SnapshotWriter::finish`] sorts the keys by address and writes
//! the final file sequentially, so the output only needs [`Write`], not `Seek`.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use memmap2::Mmap;

use crate::error::{Error, Result};
use crate::format::*;
use crate::types::*;

const SPILL_OBJECT_LEN: usize = 64;

/// Summary returned by [`SnapshotWriter::finish`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteStats {
    pub objects: u64,
    pub edges: u64,
    pub types: u64,
    pub strings: u64,
    pub roots: u64,
    pub extras: u64,
    pub bytes_written: u64,
}

/// An object as handed to [`SnapshotWriter::add_object`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectInput {
    pub addr: u64,
    pub type_id: TypeId,
    pub shallow_size: u64,
    pub flags: ObjectFlags,
    pub extras: ObjectExtras,
}

impl ObjectInput {
    pub fn new(addr: u64, type_id: TypeId, shallow_size: u64) -> Self {
        Self {
            addr,
            type_id,
            shallow_size,
            flags: ObjectFlags::GC_TRACKED,
            extras: ObjectExtras::default(),
        }
    }
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

#[derive(Default)]
struct Strings {
    map: HashMap<Box<str>, u32>,
    data: Vec<u8>,
    offsets: Vec<u64>,
}

impl Strings {
    fn intern(&mut self, s: &str) -> Result<StrId> {
        if let Some(&id) = self.map.get(s) {
            return Ok(StrId(id));
        }
        if self.offsets.is_empty() {
            self.offsets.push(0);
        }
        let id = self.map.len();
        if id >= NO_STRING as usize {
            return Err(Error::LimitExceeded("more than 2^32-1 strings"));
        }
        self.data.extend_from_slice(s.as_bytes());
        self.offsets.push(self.data.len() as u64);
        self.map.insert(s.into(), id as u32);
        Ok(StrId(id as u32))
    }

    fn len(&self) -> u32 {
        self.map.len() as u32
    }
}

/// Builds a snapshot file. See the module docs.
pub struct SnapshotWriter {
    info: SnapshotInfo,
    strings: Strings,
    types: Vec<(u64, StrId, StrId)>,
    objects: Spill,
    edges: Spill,
    keys: Vec<(u64, u32)>,
    edge_total: u64,
    extras_count: u64,
    roots: Vec<(u64, RootKind, StrId)>,
    regions: Vec<MemoryRegion>,
    meta: Vec<(StrId, StrId)>,
    edge_buf: Vec<u8>,
}

impl SnapshotWriter {
    /// A writer that keeps spill buffers in memory. Fine for tests and small
    /// heaps; use [`SnapshotWriter::with_spill_dir`] for real dumps.
    pub fn new(info: SnapshotInfo) -> Result<Self> {
        Self::build(info, None)
    }

    /// A writer that spills object and edge records to anonymous temporary
    /// files in `dir` (normally the output file's directory). Memory use is
    /// then about 16 bytes per object plus the string table.
    pub fn with_spill_dir(info: SnapshotInfo, dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        Self::build(info, Some(&dir))
    }

    fn build(info: SnapshotInfo, dir: Option<&Path>) -> Result<Self> {
        let mut w = Self {
            strings: Strings::default(),
            types: Vec::new(),
            objects: Spill::new(dir)?,
            edges: Spill::new(dir)?,
            keys: Vec::new(),
            edge_total: 0,
            extras_count: 0,
            roots: Vec::new(),
            regions: Vec::new(),
            meta: Vec::new(),
            edge_buf: Vec::new(),
            info,
        };
        // Make sure the source reference is in the table so the header can point at it.
        let r = w.info.source.reference.clone();
        w.strings.intern(&r)?;
        Ok(w)
    }

    /// Header fields. Change `truncated` here if the walk stops early.
    pub fn info_mut(&mut self) -> &mut SnapshotInfo {
        &mut self.info
    }

    pub fn info(&self) -> &SnapshotInfo {
        &self.info
    }

    /// Add `s` to the string table, or return its existing id.
    pub fn intern(&mut self, s: &str) -> Result<StrId> {
        self.strings.intern(s)
    }

    /// Add a type. Each call creates a new entry; callers dedupe by type address.
    pub fn add_type(&mut self, addr: u64, module: &str, qualname: &str) -> Result<TypeId> {
        let m = self.intern(module)?;
        let q = self.intern(qualname)?;
        let id = self.types.len();
        if id >= UNKNOWN_TYPE as usize {
            return Err(Error::LimitExceeded("more than 2^32-1 types"));
        }
        self.types.push((addr, q, m));
        Ok(TypeId(id as u32))
    }

    fn check_str(&self, s: Option<StrId>) -> Result<()> {
        match s {
            Some(StrId(id)) if id >= self.strings.len() => Err(Error::InvalidString(id)),
            _ => Ok(()),
        }
    }

    /// Add one object together with all of its outgoing edges, in the order
    /// they should be listed. Each address may be added once.
    pub fn add_object<I>(&mut self, obj: &ObjectInput, edges: I) -> Result<()>
    where
        I: IntoIterator<Item = Edge>,
    {
        if self.keys.len() >= u32::MAX as usize {
            return Err(Error::LimitExceeded("more than 2^32-1 objects"));
        }
        if !obj.type_id.is_unknown() && obj.type_id.0 as usize >= self.types.len() {
            return Err(Error::InvalidType(obj.type_id.0));
        }
        let x = &obj.extras;
        self.check_str(x.qualname)?;
        self.check_str(x.source_loc)?;
        self.check_str(x.content)?;

        self.edge_buf.clear();
        let mut count: u64 = 0;
        for e in edges {
            self.check_str(e.label.string_ref())?;
            let (kind, flags, operand) = e.label.encode();
            let mut r = [0u8; EDGE_RECORD_LEN as usize];
            wr_u64(&mut r, 0, e.target);
            wr_u32(&mut r, 8, operand);
            r[12] = kind;
            r[13] = flags;
            self.edge_buf.extend_from_slice(&r);
            count += 1;
        }
        let count: u32 = count
            .try_into()
            .map_err(|_| Error::LimitExceeded("more than 2^32-1 edges on one object"))?;

        let mut xf = 0u32;
        if x.length.is_some() {
            xf |= XF_LENGTH;
        }
        if x.qualname.is_some() {
            xf |= XF_QUALNAME;
        }
        if x.source_loc.is_some() {
            xf |= XF_SOURCE_LOC;
        }
        if x.content.is_some() {
            xf |= XF_CONTENT;
            if x.content_truncated {
                xf |= XF_CONTENT_TRUNCATED;
            }
        }

        let mut r = [0u8; SPILL_OBJECT_LEN];
        wr_u64(&mut r, 0, obj.addr);
        wr_u64(&mut r, 8, obj.shallow_size);
        wr_u64(&mut r, 16, self.edge_total);
        wr_u32(&mut r, 24, count);
        wr_u32(&mut r, 28, obj.type_id.0);
        wr_u32(&mut r, 32, obj.flags.0);
        wr_u32(&mut r, 36, xf);
        wr_u64(&mut r, 40, x.length.unwrap_or(0));
        wr_u32(&mut r, 48, StrId::encode(x.qualname));
        wr_u32(&mut r, 52, StrId::encode(x.source_loc));
        wr_u32(&mut r, 56, StrId::encode(x.content));

        self.edges.write(&self.edge_buf)?;
        self.objects.write(&r)?;
        self.keys.push((obj.addr, self.keys.len() as u32));
        self.edge_total += count as u64;
        if xf != 0 {
            self.extras_count += 1;
        }
        Ok(())
    }

    /// Add a root. `label` is the rendered root description.
    pub fn add_root(&mut self, addr: u64, kind: RootKind, label: StrId) -> Result<()> {
        self.check_str(Some(label))?;
        self.roots.push((addr, kind, label));
        Ok(())
    }

    /// Add a memory summary entry. Entries of the same kind are kept separately;
    /// readers sum them.
    pub fn add_memory_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Add a free-form key/value pair to the meta section (e.g.
    /// `heapspy.version`). Keys are not required to be unique.
    pub fn add_meta(&mut self, key: &str, value: &str) -> Result<()> {
        let k = self.intern(key)?;
        let v = self.intern(value)?;
        self.meta.push((k, v));
        Ok(())
    }

    pub fn object_count(&self) -> u64 {
        self.keys.len() as u64
    }

    pub fn edge_count(&self) -> u64 {
        self.edge_total
    }

    /// Write the snapshot atomically to `path` (via a temporary file in the
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

    /// Write the snapshot into a byte vector.
    pub fn finish_to_vec(self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        self.finish(&mut v)?;
        Ok(v)
    }

    /// Sort, lay out and write the snapshot to `out`.
    pub fn finish<W: Write>(mut self, out: W) -> Result<WriteStats> {
        self.keys.sort_unstable_by_key(|k| k.0);
        if let Some(w) = self.keys.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(Error::DuplicateAddress(w[0].0));
        }
        let source_ref = self.strings.intern(&self.info.source.reference.clone())?;

        let objects = std::mem::replace(&mut self.objects, Spill::Mem(Vec::new())).into_data()?;
        let edges = std::mem::replace(&mut self.edges, Spill::Mem(Vec::new())).into_data()?;
        let obj_bytes = objects.bytes();
        let edge_bytes = edges.bytes();

        let n_str = self.strings.len() as u64;
        let rec = |n: u64, len: u32| RECORD_SECTION_HEADER_LEN as u64 + n * len as u64;
        let mut sections: Vec<(u32, u32, u64)> = vec![
            (
                SK_STRINGS,
                SF_REQUIRED,
                STRINGS_HEADER_LEN as u64 + (n_str + 1) * 8 + self.strings.data.len() as u64,
            ),
            (
                SK_TYPES,
                SF_REQUIRED,
                rec(self.types.len() as u64, TYPE_RECORD_LEN),
            ),
            (
                SK_OBJECTS,
                SF_REQUIRED,
                rec(self.keys.len() as u64, OBJECT_RECORD_LEN),
            ),
            (SK_EDGES, SF_REQUIRED, rec(self.edge_total, EDGE_RECORD_LEN)),
            (
                SK_ROOTS,
                SF_REQUIRED,
                rec(self.roots.len() as u64, ROOT_RECORD_LEN),
            ),
            (SK_EXTRAS, 0, rec(self.extras_count, EXTRAS_RECORD_LEN)),
        ];
        if !self.regions.is_empty() {
            sections.push((
                SK_MEMORY_SUMMARY,
                0,
                rec(self.regions.len() as u64, REGION_RECORD_LEN),
            ));
        }
        sections.push((SK_META, 0, rec(self.meta.len() as u64, META_RECORD_LEN)));

        let table_offset = HEADER_LEN as u64;
        let mut pos = align_up(table_offset + (sections.len() * SECTION_ENTRY_LEN) as u64);
        let mut offsets = Vec::with_capacity(sections.len());
        for &(_, _, len) in &sections {
            offsets.push(pos);
            pos = align_up(pos + len);
        }
        let file_len = pos;

        let mut out = Counting { inner: out, pos: 0 };

        // Header.
        let info = &self.info;
        let mut h = [0u8; HEADER_LEN];
        h[H_MAGIC..H_MAGIC + 4].copy_from_slice(&MAGIC);
        wr_u16(&mut h, H_VERSION, FORMAT_VERSION);
        wr_u16(&mut h, H_HEADER_LEN, HEADER_LEN as u16);
        h[H_PY_MAJOR] = info.python.major;
        h[H_PY_MINOR] = info.python.minor;
        h[H_PY_MICRO] = info.python.micro;
        h[H_POINTER_SIZE] = info.pointer_size;
        h[H_ENDIANNESS] = if info.target_little_endian { 1 } else { 2 };
        h[H_OS] = info.os.code();
        h[H_ARCH] = info.arch.code();
        h[H_SOURCE_KIND] = info.source.kind.code();
        let mut flags = 0;
        if info.contents_captured {
            flags |= HF_CONTENTS_CAPTURED;
        }
        if info.truncated {
            flags |= HF_TRUNCATED;
        }
        if info.free_threaded {
            flags |= HF_PY_FREE_THREADED;
        }
        if info.debug_build {
            flags |= HF_PY_DEBUG_BUILD;
        }
        wr_u32(&mut h, H_FLAGS, flags);
        wr_u32(&mut h, H_SOURCE_REF, source_ref.0);
        wr_u64(&mut h, H_CAPTURED_AT, info.captured_at);
        wr_u64(&mut h, H_SECTION_TABLE_OFFSET, table_offset);
        wr_u32(&mut h, H_SECTION_COUNT, sections.len() as u32);
        h[H_PY_RELEASE_LEVEL] = info.python.release_level;
        h[H_PY_RELEASE_SERIAL] = info.python.release_serial;
        wr_u64(&mut h, H_FILE_LEN, file_len);
        out.write_all(&h)?;

        // Section table.
        for (i, &(kind, sflags, len)) in sections.iter().enumerate() {
            let mut e = [0u8; SECTION_ENTRY_LEN];
            wr_u32(&mut e, 0, kind);
            wr_u32(&mut e, 4, sflags);
            wr_u64(&mut e, 8, offsets[i]);
            wr_u64(&mut e, 16, len);
            out.write_all(&e)?;
        }

        let mut extras_written = 0u64;
        for (i, &(kind, _, _)) in sections.iter().enumerate() {
            out.pad_to(offsets[i])?;
            match kind {
                SK_STRINGS => {
                    let mut hdr = [0u8; STRINGS_HEADER_LEN];
                    wr_u64(&mut hdr, 0, n_str);
                    wr_u64(&mut hdr, 8, self.strings.data.len() as u64);
                    out.write_all(&hdr)?;
                    if self.strings.offsets.is_empty() {
                        out.write_all(&0u64.to_le_bytes())?;
                    }
                    for o in &self.strings.offsets {
                        out.write_all(&o.to_le_bytes())?;
                    }
                    out.write_all(&self.strings.data)?;
                }
                SK_TYPES => {
                    out.record_header(self.types.len() as u64, TYPE_RECORD_LEN)?;
                    for &(addr, q, m) in &self.types {
                        let mut r = [0u8; TYPE_RECORD_LEN as usize];
                        wr_u64(&mut r, 0, addr);
                        wr_u32(&mut r, 8, q.0);
                        wr_u32(&mut r, 12, m.0);
                        out.write_all(&r)?;
                    }
                }
                SK_OBJECTS => {
                    out.record_header(self.keys.len() as u64, OBJECT_RECORD_LEN)?;
                    let mut edge_start = 0u64;
                    for &(_, si) in &self.keys {
                        let s = &obj_bytes[si as usize * SPILL_OBJECT_LEN..][..SPILL_OBJECT_LEN];
                        let mut r = [0u8; OBJECT_RECORD_LEN as usize];
                        r[0..16].copy_from_slice(&s[0..16]); // addr, shallow_size
                        wr_u64(&mut r, 16, edge_start);
                        r[24..36].copy_from_slice(&s[24..36]); // edge_count, type_id, flags
                        out.write_all(&r)?;
                        edge_start += rd_u32(s, 24) as u64;
                    }
                }
                SK_EDGES => {
                    out.record_header(self.edge_total, EDGE_RECORD_LEN)?;
                    for &(_, si) in &self.keys {
                        let s = &obj_bytes[si as usize * SPILL_OBJECT_LEN..][..SPILL_OBJECT_LEN];
                        let start = rd_u64(s, 16) as usize * EDGE_RECORD_LEN as usize;
                        let len = rd_u32(s, 24) as usize * EDGE_RECORD_LEN as usize;
                        out.write_all(&edge_bytes[start..start + len])?;
                    }
                }
                SK_ROOTS => {
                    out.record_header(self.roots.len() as u64, ROOT_RECORD_LEN)?;
                    for &(addr, kind, label) in &self.roots {
                        let mut r = [0u8; ROOT_RECORD_LEN as usize];
                        wr_u64(&mut r, 0, addr);
                        wr_u32(&mut r, 8, label.0);
                        r[12] = kind.code();
                        out.write_all(&r)?;
                    }
                }
                SK_EXTRAS => {
                    out.record_header(self.extras_count, EXTRAS_RECORD_LEN)?;
                    for (index, &(_, si)) in self.keys.iter().enumerate() {
                        let s = &obj_bytes[si as usize * SPILL_OBJECT_LEN..][..SPILL_OBJECT_LEN];
                        if rd_u32(s, 36) == 0 {
                            continue;
                        }
                        let mut r = [0u8; EXTRAS_RECORD_LEN as usize];
                        wr_u32(&mut r, 0, index as u32);
                        r[4..8].copy_from_slice(&s[36..40]); // fields
                        r[8..28].copy_from_slice(&s[40..60]); // length, qualname, source_loc, content
                        out.write_all(&r)?;
                        extras_written += 1;
                    }
                }
                SK_MEMORY_SUMMARY => {
                    out.record_header(self.regions.len() as u64, REGION_RECORD_LEN)?;
                    for reg in &self.regions {
                        let mut r = [0u8; REGION_RECORD_LEN as usize];
                        wr_u32(&mut r, 0, reg.kind.code());
                        wr_u64(&mut r, 8, reg.mapped_bytes);
                        wr_u64(&mut r, 16, reg.resident_bytes.unwrap_or(UNKNOWN_BYTES));
                        out.write_all(&r)?;
                    }
                }
                SK_META => {
                    out.record_header(self.meta.len() as u64, META_RECORD_LEN)?;
                    for &(k, v) in &self.meta {
                        let mut r = [0u8; META_RECORD_LEN as usize];
                        wr_u32(&mut r, 0, k.0);
                        wr_u32(&mut r, 4, v.0);
                        out.write_all(&r)?;
                    }
                }
                _ => unreachable!("writer only emits known sections"),
            }
        }
        out.pad_to(file_len)?;
        out.inner.flush()?;
        debug_assert_eq!(extras_written, self.extras_count);

        Ok(WriteStats {
            objects: self.keys.len() as u64,
            edges: self.edge_total,
            types: self.types.len() as u64,
            strings: n_str,
            roots: self.roots.len() as u64,
            extras: self.extras_count,
            bytes_written: out.pos,
        })
    }
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
