//! Build small synthetic snapshots for tests and examples.
//!
//! ```
//! use heapspy_snapshot::{RootKind, SnapshotBuilder};
//!
//! let mut b = SnapshotBuilder::new();
//! let module = b.ty("builtins", "module");
//! let dict = b.ty("builtins", "dict");
//! let bytes = b.ty("builtins", "bytes");
//!
//! b.object(0x1000, module, 72).attr(0x2000, "__dict__");
//! b.object(0x2000, dict, 232).dict_value(0x3000, "'CACHE'");
//! b.object(0x3000, dict, 1024)
//!     .redacted_dict_value(0x4000, "str", 9)
//!     .length(1);
//! b.object(0x4000, bytes, 1 << 20).untracked().length((1 << 20) - 33);
//! b.root(0x1000, RootKind::ModuleDict, "sys.modules['app.cache']");
//!
//! let snap = b.build().unwrap();
//! assert_eq!(snap.object_count(), 4);
//! let i = snap.find_object(0x3000).unwrap();
//! let e = snap.edges(i).next().unwrap();
//! assert_eq!(snap.render_label(e.label).unwrap(), "[<str len=9>]");
//! ```

use std::collections::HashMap;
use std::path::Path;

use crate::error::Result;
use crate::label::redacted_key_placeholder;
use crate::reader::Snapshot;
use crate::types::*;
use crate::writer::{ObjectInput, SnapshotWriter, WriteStats};

#[derive(Clone, Debug)]
enum L {
    Other(Option<String>),
    DictValue(Option<String>, bool),
    DictKey(Option<String>, bool),
    ListItem(u32),
    TupleItem(u32),
    SetItem,
    Attr(String),
    Type,
    CellContents,
    ClosureCell(u32),
    FrameLocal(String),
}

/// One object being built. Returned by [`SnapshotBuilder::object`]; methods chain.
#[derive(Clone, Debug)]
pub struct ObjectSpec {
    addr: u64,
    ty: TypeId,
    size: u64,
    flags: ObjectFlags,
    edges: Vec<(u64, L)>,
    length: Option<u64>,
    qualname: Option<String>,
    source_loc: Option<String>,
    content: Option<(String, bool)>,
}

impl ObjectSpec {
    fn push(&mut self, target: u64, l: L) -> &mut Self {
        self.edges.push((target, l));
        self
    }
    /// `[key]` where `key_repr` is the key's repr text, e.g. `"'cache'"` or `"3"`.
    pub fn dict_value(&mut self, target: u64, key_repr: &str) -> &mut Self {
        self.push(target, L::DictValue(Some(key_repr.into()), false))
    }
    /// A dict value whose key is redacted to `<type_name len=len>`.
    pub fn redacted_dict_value(&mut self, target: u64, type_name: &str, len: u64) -> &mut Self {
        let p = redacted_key_placeholder(type_name, Some(len));
        self.push(target, L::DictValue(Some(p), true))
    }
    /// A dict value whose key could not be read.
    pub fn unknown_dict_value(&mut self, target: u64) -> &mut Self {
        self.push(target, L::DictValue(None, false))
    }
    /// The dict references `target` as a key.
    pub fn dict_key(&mut self, target: u64, key_repr: &str) -> &mut Self {
        self.push(target, L::DictKey(Some(key_repr.into()), false))
    }
    /// A key reference with a redacted key text.
    pub fn redacted_dict_key(&mut self, target: u64, type_name: &str, len: u64) -> &mut Self {
        let p = redacted_key_placeholder(type_name, Some(len));
        self.push(target, L::DictKey(Some(p), true))
    }
    pub fn list_item(&mut self, target: u64, index: u32) -> &mut Self {
        self.push(target, L::ListItem(index))
    }
    pub fn tuple_item(&mut self, target: u64, index: u32) -> &mut Self {
        self.push(target, L::TupleItem(index))
    }
    pub fn set_item(&mut self, target: u64) -> &mut Self {
        self.push(target, L::SetItem)
    }
    pub fn attr(&mut self, target: u64, name: &str) -> &mut Self {
        self.push(target, L::Attr(name.into()))
    }
    /// The `ob_type` edge.
    pub fn type_edge(&mut self, target: u64) -> &mut Self {
        self.push(target, L::Type)
    }
    pub fn cell_contents(&mut self, target: u64) -> &mut Self {
        self.push(target, L::CellContents)
    }
    pub fn closure_cell(&mut self, target: u64, index: u32) -> &mut Self {
        self.push(target, L::ClosureCell(index))
    }
    pub fn frame_local(&mut self, target: u64, name: &str) -> &mut Self {
        self.push(target, L::FrameLocal(name.into()))
    }
    pub fn other(&mut self, target: u64, desc: Option<&str>) -> &mut Self {
        self.push(target, L::Other(desc.map(Into::into)))
    }
    /// Replace the flags (default: `GC_TRACKED`).
    pub fn flags(&mut self, flags: ObjectFlags) -> &mut Self {
        self.flags = flags;
        self
    }
    /// Clear `GC_TRACKED`.
    pub fn untracked(&mut self) -> &mut Self {
        self.flags.0 &= !ObjectFlags::GC_TRACKED.0;
        self
    }
    pub fn length(&mut self, len: u64) -> &mut Self {
        self.length = Some(len);
        self
    }
    pub fn qualname(&mut self, q: &str) -> &mut Self {
        self.qualname = Some(q.into());
        self
    }
    pub fn source_loc(&mut self, loc: &str) -> &mut Self {
        self.source_loc = Some(loc.into());
        self
    }
    /// Captured content; `truncated` marks it as cut at `max_str`.
    pub fn content(&mut self, text: &str, truncated: bool) -> &mut Self {
        self.content = Some((text.into(), truncated));
        self
    }
}

/// Builder for synthetic snapshots. See the module docs for an example.
#[derive(Clone, Debug)]
pub struct SnapshotBuilder {
    info: SnapshotInfo,
    types: Vec<(u64, String, String)>,
    type_ids: HashMap<(String, String), TypeId>,
    objects: Vec<ObjectSpec>,
    roots: Vec<(u64, RootKind, String)>,
    regions: Vec<MemoryRegion>,
    meta: Vec<(String, String)>,
}

impl Default for SnapshotBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotBuilder {
    /// Defaults: CPython 3.12.0, x86_64 Linux, source `pid 0`, no contents.
    pub fn new() -> Self {
        Self {
            info: SnapshotInfo::new_for_test(),
            types: Vec::new(),
            type_ids: HashMap::new(),
            objects: Vec::new(),
            roots: Vec::new(),
            regions: Vec::new(),
            meta: Vec::new(),
        }
    }

    /// Header fields, for anything the shortcut setters do not cover.
    pub fn info_mut(&mut self) -> &mut SnapshotInfo {
        &mut self.info
    }

    pub fn python(&mut self, major: u8, minor: u8, micro: u8) -> &mut Self {
        self.info.python = PythonVersion::new(major, minor, micro);
        self
    }

    pub fn os(&mut self, os: Os) -> &mut Self {
        self.info.os = os;
        self
    }

    pub fn source(&mut self, kind: SourceKind, reference: &str) -> &mut Self {
        self.info.source = SourceInfo {
            kind,
            reference: reference.into(),
        };
        self
    }

    pub fn captured_at(&mut self, unix_secs: u64) -> &mut Self {
        self.info.captured_at = unix_secs;
        self
    }

    pub fn contents_captured(&mut self, yes: bool) -> &mut Self {
        self.info.contents_captured = yes;
        self
    }

    pub fn truncated(&mut self, yes: bool) -> &mut Self {
        self.info.truncated = yes;
        self
    }

    /// Get or create the type `module.qualname`. Repeated calls with the same
    /// names return the same id. The type's address is 0.
    pub fn ty(&mut self, module: &str, qualname: &str) -> TypeId {
        self.ty_at(0, module, qualname)
    }

    /// Like [`SnapshotBuilder::ty`] but records the type object's address.
    pub fn ty_at(&mut self, addr: u64, module: &str, qualname: &str) -> TypeId {
        let key = (module.to_string(), qualname.to_string());
        if let Some(&id) = self.type_ids.get(&key) {
            return id;
        }
        let id = TypeId(self.types.len() as u32);
        self.types.push((addr, module.into(), qualname.into()));
        self.type_ids.insert(key, id);
        id
    }

    /// Add an object (GC-tracked by default). Chain edge and extras methods on
    /// the result. Objects can be added in any order and edges may point to
    /// addresses that are never added (they become dangling edges).
    pub fn object(&mut self, addr: u64, ty: TypeId, shallow_size: u64) -> &mut ObjectSpec {
        self.objects.push(ObjectSpec {
            addr,
            ty,
            size: shallow_size,
            flags: ObjectFlags::GC_TRACKED,
            edges: Vec::new(),
            length: None,
            qualname: None,
            source_loc: None,
            content: None,
        });
        self.objects.last_mut().expect("just pushed")
    }

    pub fn root(&mut self, addr: u64, kind: RootKind, label: &str) -> &mut Self {
        self.roots.push((addr, kind, label.into()));
        self
    }

    pub fn memory_region(
        &mut self,
        kind: RegionKind,
        mapped: u64,
        resident: Option<u64>,
    ) -> &mut Self {
        self.regions.push(MemoryRegion {
            kind,
            mapped_bytes: mapped,
            resident_bytes: resident,
        });
        self
    }

    pub fn meta(&mut self, key: &str, value: &str) -> &mut Self {
        self.meta.push((key.into(), value.into()));
        self
    }

    fn writer(&self) -> Result<SnapshotWriter> {
        let mut w = SnapshotWriter::new(self.info.clone())?;
        for (addr, m, q) in &self.types {
            w.add_type(*addr, m, q)?;
        }
        for o in &self.objects {
            let mut edges = Vec::with_capacity(o.edges.len());
            for (target, l) in &o.edges {
                let key =
                    |w: &mut SnapshotWriter, t: &Option<String>, red: bool| -> Result<KeyLabel> {
                        Ok(match t {
                            None => KeyLabel::Unknown,
                            Some(s) if red => KeyLabel::Redacted(w.intern(s)?),
                            Some(s) => KeyLabel::Repr(w.intern(s)?),
                        })
                    };
                let label = match l {
                    L::Other(d) => EdgeLabel::Other(d.as_deref().map(|s| w.intern(s)).transpose()?),
                    L::DictValue(t, red) => EdgeLabel::DictValue(key(&mut w, t, *red)?),
                    L::DictKey(t, red) => EdgeLabel::DictKey(key(&mut w, t, *red)?),
                    L::ListItem(i) => EdgeLabel::ListItem(*i),
                    L::TupleItem(i) => EdgeLabel::TupleItem(*i),
                    L::SetItem => EdgeLabel::SetItem,
                    L::Attr(n) => EdgeLabel::Attr(w.intern(n)?),
                    L::Type => EdgeLabel::Type,
                    L::CellContents => EdgeLabel::CellContents,
                    L::ClosureCell(i) => EdgeLabel::ClosureCell(*i),
                    L::FrameLocal(n) => EdgeLabel::FrameLocal(w.intern(n)?),
                };
                edges.push(Edge {
                    target: *target,
                    label,
                });
            }
            let extras = ObjectExtras {
                length: o.length,
                qualname: o.qualname.as_deref().map(|s| w.intern(s)).transpose()?,
                source_loc: o.source_loc.as_deref().map(|s| w.intern(s)).transpose()?,
                content: o.content.as_ref().map(|(s, _)| w.intern(s)).transpose()?,
                content_truncated: o.content.as_ref().is_some_and(|c| c.1),
            };
            let input = ObjectInput {
                addr: o.addr,
                type_id: o.ty,
                shallow_size: o.size,
                flags: o.flags,
                extras,
            };
            w.add_object(&input, edges)?;
        }
        for (addr, kind, label) in &self.roots {
            let l = w.intern(label)?;
            w.add_root(*addr, *kind, l)?;
        }
        for r in &self.regions {
            w.add_memory_region(*r);
        }
        for (k, v) in &self.meta {
            w.add_meta(k, v)?;
        }
        Ok(w)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.writer()?.finish_to_vec()
    }

    /// Write to a file.
    pub fn write_to(&self, path: impl AsRef<Path>) -> Result<WriteStats> {
        self.writer()?.finish_to_path(path)
    }

    /// Serialize and open in memory.
    pub fn build(&self) -> Result<Snapshot> {
        Snapshot::from_bytes(self.to_bytes()?)
    }
}
