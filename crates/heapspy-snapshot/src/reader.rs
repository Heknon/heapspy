//! Memory-mapped snapshot reader.
//!
//! [`Snapshot::open`] maps the file and validates it once:
//!
//! - magic, format version, header length, recorded file length;
//! - every section's offset and length against the file size;
//! - record section headers (count * record_len must equal the section length);
//! - the objects section in full: addresses strictly increasing, edge ranges
//!   contiguous (CSR) and inside the edges section, type ids in range;
//! - the extras section: object indices strictly increasing and in range.
//!
//! After that, object and edge accessors are infallible and allocation-free.
//! String lookups are checked on each access and return
//! [`Error::InvalidString`] for a bad id or invalid UTF-8.
//!
//! A mapped file must not be truncated or modified while a `Snapshot` is
//! alive; on most platforms that raises SIGBUS or an access violation.

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

use crate::error::{Error, Result};
use crate::format::*;
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

/// An open snapshot. See the module docs.
pub struct Snapshot {
    backing: Backing,
    info: SnapshotInfo,
    str_count: usize,
    str_offsets: usize,
    str_data: usize,
    str_data_len: usize,
    types: Records,
    objects: Records,
    edges: Records,
    roots: Records,
    extras: Records,
    regions: Option<Records>,
    meta: Records,
    unknown_sections: Vec<u32>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("info", &self.info)
            .field("objects", &self.objects.count)
            .field("edges", &self.edges.count)
            .field("types", &self.types.count)
            .field("roots", &self.roots.count)
            .finish()
    }
}

fn corrupt(msg: impl Into<String>) -> Error {
    Error::Corrupt(msg.into())
}

impl Snapshot {
    /// Map and validate a snapshot file.
    pub fn open(path: impl AsRef<Path>) -> Result<Snapshot> {
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

    /// Validate a snapshot held in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Snapshot> {
        Self::from_backing(Backing::Owned(bytes))
    }

    fn from_backing(backing: Backing) -> Result<Snapshot> {
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

        let flags = rd_u32(b, H_FLAGS);
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

        // Strings.
        let (s_off, s_len) = section(SK_STRINGS)?;
        if s_len < STRINGS_HEADER_LEN {
            return Err(Error::Truncated("strings section header".into()));
        }
        let str_count = rd_u64(b, s_off);
        let str_data_len = rd_u64(b, s_off + 8);
        let need = str_count
            .checked_add(1)
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add(STRINGS_HEADER_LEN as u64))
            .and_then(|n| n.checked_add(str_data_len))
            .ok_or_else(|| corrupt("strings section size overflows"))?;
        if need != s_len as u64 {
            return Err(Error::Truncated(format!(
                "strings section is {s_len} bytes, contents need {need}"
            )));
        }
        if str_count > NO_STRING as u64 {
            return Err(corrupt("too many strings"));
        }
        let str_offsets = s_off + STRINGS_HEADER_LEN;
        let str_data = str_offsets + (str_count as usize + 1) * 8;

        let types = records(SK_TYPES, TYPE_RECORD_LEN)?;
        let objects = records(SK_OBJECTS, OBJECT_RECORD_LEN)?;
        let edges = records(SK_EDGES, EDGE_RECORD_LEN)?;
        let roots = records(SK_ROOTS, ROOT_RECORD_LEN)?;
        let extras = match found.contains_key(&SK_EXTRAS) {
            true => records(SK_EXTRAS, EXTRAS_RECORD_LEN)?,
            false => Records::default(),
        };
        let regions = match found.contains_key(&SK_MEMORY_SUMMARY) {
            true => Some(records(SK_MEMORY_SUMMARY, REGION_RECORD_LEN)?),
            false => None,
        };
        let meta = match found.contains_key(&SK_META) {
            true => records(SK_META, META_RECORD_LEN)?,
            false => Records::default(),
        };

        if objects.count > u32::MAX as usize {
            return Err(corrupt("more than 2^32-1 objects"));
        }

        // Objects: sorted, CSR-contiguous, valid type ids.
        let mut prev_addr: Option<u64> = None;
        let mut next_edge = 0u64;
        for i in 0..objects.count {
            let r = objects.at(b, i);
            let addr = rd_u64(r, 0);
            if prev_addr.is_some_and(|p| p >= addr) {
                return Err(corrupt(format!(
                    "objects not sorted by address at index {i} ({addr:#x})"
                )));
            }
            prev_addr = Some(addr);
            let start = rd_u64(r, 16);
            let count = rd_u32(r, 24) as u64;
            if start != next_edge {
                return Err(corrupt(format!("object {i} edge range is not contiguous")));
            }
            next_edge = start + count;
            if next_edge > edges.count as u64 {
                return Err(corrupt(format!(
                    "object {i} edge range exceeds edges section"
                )));
            }
            let t = rd_u32(r, 28);
            if t != UNKNOWN_TYPE && t as usize >= types.count {
                return Err(Error::InvalidType(t));
            }
        }
        if next_edge != edges.count as u64 {
            return Err(corrupt("edges section has records not owned by any object"));
        }

        // Extras: sorted by object index.
        let mut prev: Option<u32> = None;
        for i in 0..extras.count {
            let idx = rd_u32(extras.at(b, i), 0);
            if prev.is_some_and(|p| p >= idx) || idx as usize >= objects.count {
                return Err(corrupt(format!(
                    "extras record {i} has bad object index {idx}"
                )));
            }
            prev = Some(idx);
        }

        let mut snap = Snapshot {
            info: SnapshotInfo::new_for_test(),
            backing: Backing::Owned(Vec::new()),
            str_count: str_count as usize,
            str_offsets,
            str_data,
            str_data_len: str_data_len as usize,
            types,
            objects,
            edges,
            roots,
            extras,
            regions,
            meta,
            unknown_sections,
        };
        let source_ref = snap_string(&snap, b, StrId(rd_u32(b, H_SOURCE_REF)))?.to_string();
        snap.info = SnapshotInfo {
            format_version: version,
            python: PythonVersion {
                major: b[H_PY_MAJOR],
                minor: b[H_PY_MINOR],
                micro: b[H_PY_MICRO],
                release_level: b[H_PY_RELEASE_LEVEL],
                release_serial: b[H_PY_RELEASE_SERIAL],
            },
            pointer_size: b[H_POINTER_SIZE],
            target_little_endian: b[H_ENDIANNESS] != 2,
            os: Os::from_code(b[H_OS]),
            arch: Arch::from_code(b[H_ARCH]),
            captured_at: rd_u64(b, H_CAPTURED_AT),
            source: SourceInfo {
                kind: SourceKind::from_code(b[H_SOURCE_KIND]),
                reference: source_ref,
            },
            contents_captured: flags & HF_CONTENTS_CAPTURED != 0,
            truncated: flags & HF_TRUNCATED != 0,
            free_threaded: flags & HF_PY_FREE_THREADED != 0,
            debug_build: flags & HF_PY_DEBUG_BUILD != 0,
        };
        snap.backing = backing;
        Ok(snap)
    }

    #[inline]
    fn b(&self) -> &[u8] {
        self.backing.bytes()
    }

    /// Decoded header.
    pub fn info(&self) -> &SnapshotInfo {
        &self.info
    }

    /// Section kinds present in the file that this build does not know (and
    /// that were not marked required). They are skipped.
    pub fn unknown_sections(&self) -> &[u32] {
        &self.unknown_sections
    }

    // ---- strings ----

    pub fn string_count(&self) -> usize {
        self.str_count
    }

    /// Look up a string by id.
    pub fn string(&self, id: StrId) -> Result<&str> {
        snap_string(self, self.b(), id)
    }

    /// Look up an optional string id.
    pub fn opt_string(&self, id: Option<StrId>) -> Result<Option<&str>> {
        id.map(|i| self.string(i)).transpose()
    }

    // ---- types ----

    pub fn type_count(&self) -> usize {
        self.types.count
    }

    /// Type table entry, or `None` for an out-of-range or unknown id.
    pub fn type_entry(&self, id: TypeId) -> Option<TypeEntry> {
        if id.0 as usize >= self.types.count {
            return None;
        }
        let r = self.types.at(self.b(), id.0 as usize);
        Some(TypeEntry {
            addr: rd_u64(r, 0),
            qualname: StrId(rd_u32(r, 8)),
            module: StrId(rd_u32(r, 12)),
        })
    }

    /// Display name of a type: `module.qualname` (`builtins.dict`,
    /// `app.session.Session`). Unknown type ids give `<unknown>`.
    pub fn type_name(&self, id: TypeId) -> Result<String> {
        let Some(t) = self.type_entry(id) else {
            return Ok("<unknown>".to_string());
        };
        let m = self.string(t.module)?;
        let q = self.string(t.qualname)?;
        Ok(if m.is_empty() {
            q.to_string()
        } else {
            format!("{m}.{q}")
        })
    }

    // ---- objects ----

    pub fn object_count(&self) -> usize {
        self.objects.count
    }

    /// Object by dense index. Panics if `index >= object_count()`.
    #[inline]
    pub fn object(&self, index: ObjectIndex) -> Object {
        let r = self.objects.at(self.b(), index as usize);
        Object {
            index,
            addr: rd_u64(r, 0),
            shallow_size: rd_u64(r, 8),
            edge_start: rd_u64(r, 16),
            edge_count: rd_u32(r, 24),
            type_id: TypeId(rd_u32(r, 28)),
            flags: ObjectFlags(rd_u32(r, 32)),
        }
    }

    /// Address of an object without decoding the rest of the record.
    #[inline]
    pub fn object_addr(&self, index: ObjectIndex) -> u64 {
        rd_u64(self.objects.at(self.b(), index as usize), 0)
    }

    /// All objects in address order.
    pub fn objects(&self) -> impl ExactSizeIterator<Item = Object> + '_ {
        (0..self.objects.count as u32).map(move |i| self.object(i))
    }

    /// Binary search for the object at exactly `addr`.
    pub fn find_object(&self, addr: u64) -> Option<ObjectIndex> {
        let (mut lo, mut hi) = (0usize, self.objects.count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let a = self.object_addr(mid as u32);
            match a.cmp(&addr) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(mid as u32),
            }
        }
        None
    }

    // ---- edges ----

    pub fn edge_count(&self) -> usize {
        self.edges.count
    }

    /// Edge by global index (`edge_start .. edge_start + edge_count` of an object).
    #[inline]
    pub fn edge(&self, global_index: u64) -> Edge {
        let r = self.edges.at(self.b(), global_index as usize);
        Edge {
            target: rd_u64(r, 0),
            label: crate::types::EdgeLabel::decode(r[12], r[13], rd_u32(r, 8)),
        }
    }

    /// Outgoing edges of an object, in recorded order.
    pub fn edges(&self, index: ObjectIndex) -> impl ExactSizeIterator<Item = Edge> + '_ {
        let o = self.object(index);
        let start = o.edge_start as usize;
        (start..start + o.edge_count as usize).map(move |g| self.edge(g as u64))
    }

    /// Edge target addresses only (no label decoding), for graph algorithms.
    pub fn edge_targets(&self, index: ObjectIndex) -> impl ExactSizeIterator<Item = u64> + '_ {
        let o = self.object(index);
        let b = self.b();
        let start = o.edge_start as usize;
        (start..start + o.edge_count as usize).map(move |g| rd_u64(self.edges.at(b, g), 0))
    }

    /// Render a label using this snapshot's string table.
    pub fn render_label(&self, label: EdgeLabel) -> Result<String> {
        label.render(|s| self.string(s))
    }

    // ---- extras ----

    pub fn extras_count(&self) -> usize {
        self.extras.count
    }

    /// Extras of an object, if any were recorded. Binary search.
    pub fn extras(&self, index: ObjectIndex) -> Option<ObjectExtras> {
        let b = self.b();
        let (mut lo, mut hi) = (0usize, self.extras.count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let r = self.extras.at(b, mid);
            match rd_u32(r, 0).cmp(&index) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(decode_extras(r)),
            }
        }
        None
    }

    /// All extras records as `(object index, extras)`, in index order.
    pub fn all_extras(&self) -> impl ExactSizeIterator<Item = (ObjectIndex, ObjectExtras)> + '_ {
        let b = self.b();
        (0..self.extras.count).map(move |i| {
            let r = self.extras.at(b, i);
            (rd_u32(r, 0), decode_extras(r))
        })
    }

    // ---- roots ----

    pub fn root_count(&self) -> usize {
        self.roots.count
    }

    pub fn roots(&self) -> impl ExactSizeIterator<Item = Root> + '_ {
        let b = self.b();
        (0..self.roots.count).map(move |i| {
            let r = self.roots.at(b, i);
            Root {
                addr: rd_u64(r, 0),
                label: StrId(rd_u32(r, 8)),
                kind: RootKind::from_code(r[12]),
            }
        })
    }

    // ---- memory summary / meta ----

    /// Memory summary entries, or `None` if the source had no memory map data.
    pub fn memory_summary(&self) -> Option<Vec<MemoryRegion>> {
        let recs = self.regions?;
        let b = self.b();
        Some(
            (0..recs.count)
                .map(|i| {
                    let r = recs.at(b, i);
                    let res = rd_u64(r, 16);
                    MemoryRegion {
                        kind: RegionKind::from_code(rd_u32(r, 0)),
                        mapped_bytes: rd_u64(r, 8),
                        resident_bytes: (res != UNKNOWN_BYTES).then_some(res),
                    }
                })
                .collect(),
        )
    }

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

fn decode_extras(r: &[u8]) -> ObjectExtras {
    let f = rd_u32(r, 4);
    let opt = |bit: u32, at: usize| (f & bit != 0).then(|| StrId(rd_u32(r, at)));
    ObjectExtras {
        length: (f & XF_LENGTH != 0).then(|| rd_u64(r, 8)),
        qualname: opt(XF_QUALNAME, 16),
        source_loc: opt(XF_SOURCE_LOC, 20),
        content: opt(XF_CONTENT, 24),
        content_truncated: f & XF_CONTENT_TRUNCATED != 0,
    }
}

fn snap_string<'a>(s: &Snapshot, b: &'a [u8], id: StrId) -> Result<&'a str> {
    let i = id.0 as usize;
    if i >= s.str_count {
        return Err(Error::InvalidString(id.0));
    }
    let start = rd_u64(b, s.str_offsets + i * 8) as usize;
    let end = rd_u64(b, s.str_offsets + (i + 1) * 8) as usize;
    if start > end || end > s.str_data_len {
        return Err(Error::InvalidString(id.0));
    }
    std::str::from_utf8(&b[s.str_data + start..s.str_data + end])
        .map_err(|_| Error::InvalidString(id.0))
}
