//! The object-graph walk itself. See the module docs of [`super`].

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use heapspy_snapshot::{
    redacted_key_placeholder, truncate_capture, Edge, EdgeLabel, KeyLabel, ObjectExtras,
    ObjectFlags, ObjectInput, RootKind, SnapshotWriter, StrId, TypeId,
};

use super::offsets::*;
use super::text;
use super::WalkStats;
use crate::dump::DumpOptions;
use crate::error::Result;
use crate::source::{MemorySource, MemorySourceExt};

/// Hard caps that keep garbage from causing huge allocations or long loops.
const MAX_ITEMS: u64 = 1 << 28;
const MAX_LOG2_DICT: u8 = 32;
const MAX_TYPE_CHAIN: usize = 64;
const MAX_SLOTS: u64 = 4096;
const MAX_FRAMES: usize = 100_000;
const MAX_INTERPRETERS: usize = 1024;
const MAX_THREADS: usize = 100_000;
/// Identifier text (attribute names, identifier dict keys, root labels).
const MAX_NAME: usize = 1024;
/// Entries kept in the label caches before they are cleared.
const MAX_CACHE: usize = 1 << 20;

/// What an object is, as far as the walker cares. Heap subclasses of builtins
/// get the kind of their nearest static base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Dict,
    List,
    Tuple,
    Str,
    Bytes,
    ByteArray,
    Int,
    Float,
    Set,
    FrozenSet,
    Module,
    Function,
    Cell,
    Method,
    CFunction,
    ClassOrStaticMethod,
    Property,
    Code,
    Type,
    Gen,
    Frame,
    Other,
}

fn kind_from_static_name(name: &str) -> Kind {
    match name {
        "float" => Kind::Float,
        "set" => Kind::Set,
        "frozenset" => Kind::FrozenSet,
        "module" => Kind::Module,
        "function" => Kind::Function,
        "cell" => Kind::Cell,
        "method" => Kind::Method,
        "builtin_function_or_method" => Kind::CFunction,
        "classmethod" | "staticmethod" => Kind::ClassOrStaticMethod,
        "property" => Kind::Property,
        "code" => Kind::Code,
        "generator" | "coroutine" | "async_generator" => Kind::Gen,
        "frame" => Kind::Frame,
        "bytearray" => Kind::ByteArray,
        _ => Kind::Other,
    }
}

pub(super) struct TypeInfo {
    pub id: TypeId,
    pub kind: Kind,
    pub flags: u64,
    pub basicsize: u64,
    pub itemsize: u64,
    pub heap: bool,
    pub dictoffset: i64,
    /// `__slots__` members of this type and its heap bases: (name, offset).
    pub slots: Vec<(StrId, u64)>,
    /// `ht_cached_keys` (shared keys of instance dicts / inline values).
    pub cached_keys: u64,
    /// Name used in redaction placeholders: the qualname for builtins,
    /// `module.qualname` otherwise.
    pub display: String,
    pub qualname: String,
}

impl TypeInfo {
    fn unknown() -> Self {
        TypeInfo {
            id: TypeId::UNKNOWN,
            kind: Kind::Other,
            flags: 0,
            basicsize: 16,
            itemsize: 0,
            heap: false,
            dictoffset: 0,
            slots: Vec::new(),
            cached_keys: 0,
            display: "object".into(),
            qualname: "?".into(),
        }
    }

    fn has_gc(&self) -> bool {
        self.flags & TPFLAGS_HAVE_GC != 0
    }

    /// `_PyType_PreHeaderSize`: GC header plus the managed dict / weakref words.
    fn preheader(&self) -> u64 {
        let mut n = 0;
        if self.has_gc() {
            n += GC_HEAD;
        }
        if self.flags & (TPFLAGS_MANAGED_DICT | TPFLAGS_MANAGED_WEAKREF) != 0 {
            n += 16;
        }
        n
    }
}

/// Edges of one object plus whether any read for them failed.
#[derive(Default)]
struct Out {
    edges: Vec<Edge>,
    partial: bool,
    /// Extra bytes owned out of line (item arrays, tables, buffers).
    extra_size: u64,
    extras: ObjectExtras,
}

/// The layout of a dict keys object.
struct Keys {
    refcnt: i64,
    log2_size: u8,
    log2_index_bytes: u8,
    general: bool,
    usable: i64,
    nentries: u64,
    entries: u64,
}

impl Keys {
    fn entry_size(&self) -> u64 {
        if self.general {
            24
        } else {
            16
        }
    }

    /// `_PyDict_KeysSize`.
    fn alloc_size(&self, o: &Offsets) -> u64 {
        let size = 1u64 << self.log2_size;
        let usable = (size << 1) / 3;
        o.dict_keys_size + (1u64 << self.log2_index_bytes) + usable * self.entry_size()
    }

    /// `shared_keys_usable_size`.
    fn shared_usable(&self) -> u64 {
        (self.usable.max(0) as u64).saturating_add(self.nentries)
    }
}

/// What kind of dict a dict is, for key redaction.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DictRole {
    /// Module, type, instance or function `__dict__`: str keys are identifiers.
    Namespace,
    Ordinary,
}

pub(super) struct Walker<'a> {
    src: &'a dyn MemorySource,
    o: Offsets,
    opts: &'a DumpOptions,
    out: &'a mut SnapshotWriter,
    types: HashMap<u64, Rc<TypeInfo>>,
    /// Sorted, deduplicated addresses of GC-tracked objects.
    tracked: Vec<u64>,
    /// Untracked objects already emitted (or queued).
    untracked: HashSet<u64>,
    queue: Vec<u64>,
    namespaces: HashSet<u64>,
    /// Interned label text by str object address, for identifier keys and
    /// attribute names.
    names: HashMap<u64, Option<StrId>>,
    stats: WalkStats,
}

fn mask_stackref(o: &Offsets, v: u64) -> Option<u64> {
    if o.stackrefs {
        // Tagged ints (low bits 0b11) are not objects.
        if v & 3 == 3 {
            return None;
        }
        Some(v & !3)
    } else {
        Some(v)
    }
}

impl<'a> Walker<'a> {
    pub fn new(
        src: &'a dyn MemorySource,
        o: Offsets,
        opts: &'a DumpOptions,
        out: &'a mut SnapshotWriter,
    ) -> Self {
        Walker {
            src,
            o,
            opts,
            out,
            types: HashMap::new(),
            tracked: Vec::new(),
            untracked: HashSet::new(),
            queue: Vec::new(),
            namespaces: HashSet::new(),
            names: HashMap::new(),
            stats: WalkStats::default(),
        }
    }

    // ---- small read helpers -------------------------------------------------

    fn ptr(&self, addr: u64) -> Result<u64> {
        self.src.read_ptr(addr)
    }

    fn i64(&self, addr: u64) -> Result<i64> {
        self.src.read_i64(addr)
    }

    fn err(&mut self, out: &mut Out) {
        out.partial = true;
        self.stats.read_errors += 1;
    }

    /// Push an edge to the pointer stored at `field`, if non-null.
    fn field(&mut self, out: &mut Out, field: u64, label: EdgeLabel) {
        match self.ptr(field) {
            Ok(0) => {}
            Ok(t) => out.edges.push(Edge { target: t, label }),
            Err(_) => self.err(out),
        }
    }

    fn attr(&mut self, name: &str) -> Result<EdgeLabel> {
        Ok(EdgeLabel::Attr(self.out.intern(name)?))
    }

    fn attr_field(&mut self, out: &mut Out, field: u64, name: &str) -> Result<()> {
        let l = self.attr(name)?;
        self.field(out, field, l);
        Ok(())
    }

    fn is_tracked(&self, addr: u64) -> bool {
        self.tracked.binary_search(&addr).is_ok()
    }

    // ---- strings -------------------------------------------------------------

    /// Flags of the type at `ob_type` of `addr`, without building a TypeInfo.
    fn raw_type_flags(&self, addr: u64) -> Option<u64> {
        let t = self.ptr(addr + 8).ok()?;
        self.src.read_u32(t + self.o.tp_flags).ok().map(u64::from)
    }

    /// Text of the str object at `addr` (at most `max` characters) and its
    /// length in characters. `None` if it is not a readable str.
    fn read_str(&self, addr: u64, max: usize) -> Option<(String, u64)> {
        if addr == 0 {
            return None;
        }
        let flags = self.raw_type_flags(addr)?;
        if flags & TPFLAGS_UNICODE_SUBCLASS == 0 {
            return None;
        }
        self.read_str_data(addr, max)
    }

    fn read_str_data(&self, addr: u64, max: usize) -> Option<(String, u64)> {
        let o = &self.o;
        let len = self.i64(addr + o.str_length).ok()?;
        if !(0..=1 << 40).contains(&len) {
            return None;
        }
        let len = len as u64;
        let state = self.src.read_u32(addr + o.str_state).ok()?;
        let kind = (state >> 2) & 7;
        let compact = state & 32 != 0;
        let ascii = state & 64 != 0;
        if !matches!(kind, 1 | 2 | 4) {
            return None;
        }
        let data = if compact {
            addr + if ascii { o.ascii_size } else { o.compact_size }
        } else {
            // Legacy (non-compact) strings keep a data pointer after the
            // compact header.
            self.ptr(addr + o.compact_size).ok()?
        };
        let n = len.min(max as u64) as usize;
        let raw = self.src.read_vec(data, n * kind as usize).ok()?;
        let s: String = match kind {
            1 => raw.iter().map(|&b| b as char).collect(),
            2 => raw
                .chunks_exact(2)
                .map(|c| {
                    char::from_u32(u16::from_le_bytes([c[0], c[1]]) as u32)
                        .unwrap_or(char::REPLACEMENT_CHARACTER)
                })
                .collect(),
            _ => raw
                .chunks_exact(4)
                .map(|c| {
                    char::from_u32(u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                        .unwrap_or(char::REPLACEMENT_CHARACTER)
                })
                .collect(),
        };
        Some((s, len))
    }

    /// Interned text of the str at `addr`, for attribute names and identifier
    /// keys. Cached by address.
    fn name_of(&mut self, addr: u64, quoted: bool) -> Result<Option<StrId>> {
        // Quoted and bare forms are cached separately (low bit of the key;
        // object addresses are 8-aligned).
        let key = addr | quoted as u64;
        if let Some(v) = self.names.get(&key) {
            return Ok(*v);
        }
        let v = match self.read_str(addr, MAX_NAME) {
            Some((s, _)) => {
                let s = if quoted { text::str_repr(&s) } else { s };
                Some(self.out.intern(&s)?)
            }
            None => None,
        };
        if self.names.len() >= MAX_CACHE {
            self.names.clear();
        }
        self.names.insert(key, v);
        Ok(v)
    }

    // ---- types ---------------------------------------------------------------

    fn type_info(&mut self, t: u64) -> Result<Rc<TypeInfo>> {
        if let Some(ti) = self.types.get(&t) {
            return Ok(ti.clone());
        }
        let ti = match self.build_type(t)? {
            Some(ti) => Rc::new(ti),
            None => Rc::new(TypeInfo::unknown()),
        };
        self.types.insert(t, ti.clone());
        Ok(ti)
    }

    /// Look up `name` among the str keys of the dict at `d`.
    fn dict_get_str(&mut self, d: u64, name: &str) -> Option<u64> {
        let entries = self.dict_entries(d).ok()?;
        for (k, v) in entries {
            if let Some((s, _)) = self.read_str(k, name.len() + 1) {
                if s == name {
                    return Some(v);
                }
            }
        }
        None
    }

    fn build_type(&mut self, t: u64) -> Result<Option<TypeInfo>> {
        let o = self.o.clone();
        let Ok(flags) = self.src.read_u32(t + o.tp_flags).map(u64::from) else {
            return Ok(None);
        };
        let (Ok(basicsize), Ok(itemsize)) =
            (self.i64(t + o.tp_basicsize), self.i64(t + o.tp_itemsize))
        else {
            return Ok(None);
        };
        if !(0..1 << 32).contains(&basicsize) || !(0..1 << 32).contains(&itemsize) {
            return Ok(None);
        }
        let heap = flags & TPFLAGS_HEAPTYPE != 0;
        let tp_name = match self.ptr(t + o.tp_name) {
            Ok(p) if p != 0 => self
                .src
                .read_cstr(p, MAX_NAME)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_else(|_| "?".into()),
            _ => "?".into(),
        };

        let (module, qualname) = if heap {
            let q = self
                .ptr(t + o.ht_qualname)
                .ok()
                .and_then(|p| self.read_str(p, MAX_NAME))
                .map(|(s, _)| s)
                .unwrap_or_else(|| tp_name.clone());
            let m = self
                .ptr(t + o.tp_dict)
                .ok()
                .filter(|&d| d != 0)
                .and_then(|d| self.dict_get_str(d, "__module__"))
                .and_then(|p| self.read_str(p, MAX_NAME))
                .map(|(s, _)| s)
                .unwrap_or_else(|| "builtins".into());
            (m, q)
        } else {
            match tp_name.rsplit_once('.') {
                Some((m, q)) => (m.to_string(), q.to_string()),
                None => ("builtins".to_string(), tp_name.clone()),
            }
        };

        // Kind: subclass flag bits first, then the nearest static base's name.
        let kind = if flags & TPFLAGS_DICT_SUBCLASS != 0 {
            Kind::Dict
        } else if flags & TPFLAGS_LIST_SUBCLASS != 0 {
            Kind::List
        } else if flags & TPFLAGS_TUPLE_SUBCLASS != 0 {
            Kind::Tuple
        } else if flags & TPFLAGS_UNICODE_SUBCLASS != 0 {
            Kind::Str
        } else if flags & TPFLAGS_BYTES_SUBCLASS != 0 {
            Kind::Bytes
        } else if flags & TPFLAGS_LONG_SUBCLASS != 0 {
            Kind::Int
        } else if flags & TPFLAGS_TYPE_SUBCLASS != 0 {
            Kind::Type
        } else {
            let mut cur = t;
            let mut name = tp_name.clone();
            let mut is_heap = heap;
            let mut depth = 0;
            while is_heap && depth < MAX_TYPE_CHAIN {
                depth += 1;
                let Ok(b) = self.ptr(cur + o.tp_base) else {
                    break;
                };
                if b == 0 {
                    break;
                }
                cur = b;
                is_heap = self
                    .src
                    .read_u32(cur + o.tp_flags)
                    .map(|f| f as u64 & TPFLAGS_HEAPTYPE != 0)
                    .unwrap_or(false);
                name = self
                    .ptr(cur + o.tp_name)
                    .and_then(|p| self.src.read_cstr(p, MAX_NAME))
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
            }
            if is_heap {
                Kind::Other
            } else {
                kind_from_static_name(&name)
            }
        };

        // __slots__ members of this type and its heap bases.
        let mut slots = Vec::new();
        if heap {
            let mut cur = t;
            let mut seen_offsets = HashSet::new();
            for _ in 0..MAX_TYPE_CHAIN {
                let Ok(f) = self.src.read_u32(cur + o.tp_flags) else {
                    break;
                };
                if f as u64 & TPFLAGS_HEAPTYPE == 0 {
                    break;
                }
                let nslots = self.i64(cur + 16).unwrap_or(0);
                let meta_basic = self
                    .ptr(cur + 8)
                    .and_then(|m| self.i64(m + o.tp_basicsize))
                    .unwrap_or(0);
                if (1..=MAX_SLOTS as i64).contains(&nslots) && meta_basic > 0 {
                    let members = cur + meta_basic as u64;
                    for i in 0..nslots as u64 {
                        let m = members + i * MEMBERDEF_SIZE;
                        let Ok(np) = self.ptr(m) else { break };
                        if np == 0 {
                            break;
                        }
                        let ty = self.src.read_u32(m + MEMBERDEF_TYPE).unwrap_or(0);
                        let off = self.i64(m + MEMBERDEF_OFFSET).unwrap_or(-1);
                        if !(ty == T_OBJECT_EX || ty == T_OBJECT) || off <= 0 {
                            continue;
                        }
                        let Ok(nb) = self.src.read_cstr(np, MAX_NAME) else {
                            continue;
                        };
                        if seen_offsets.insert(off) {
                            let id = self.out.intern(&String::from_utf8_lossy(&nb))?;
                            slots.push((id, off as u64));
                        }
                    }
                }
                match self.ptr(cur + o.tp_base) {
                    Ok(b) if b != 0 => cur = b,
                    _ => break,
                }
            }
        }

        let dictoffset = self.i64(t + o.tp_dictoffset).unwrap_or(0);
        let cached_keys = if heap {
            self.ptr(t + o.ht_cached_keys).unwrap_or(0)
        } else {
            0
        };
        let display = if module == "builtins" {
            qualname.clone()
        } else {
            format!("{module}.{qualname}")
        };
        let id = self.out.add_type(t, &module, &qualname)?;
        Ok(Some(TypeInfo {
            id,
            kind,
            flags,
            basicsize: basicsize as u64,
            itemsize: itemsize as u64,
            heap,
            dictoffset,
            slots,
            cached_keys,
            display,
            qualname,
        }))
    }

    // ---- dicts ---------------------------------------------------------------

    fn read_keys(&self, k: u64) -> Result<Keys> {
        let o = &self.o;
        let hdr = self.src.read_vec(k, o.dk_indices as usize)?;
        let g =
            |off: u64| i64::from_le_bytes(hdr[off as usize..off as usize + 8].try_into().unwrap());
        let log2_size = hdr[o.dk_log2_size as usize];
        let log2_index_bytes = hdr[o.dk_log2_index_bytes as usize];
        let kind = hdr[o.dk_kind as usize];
        let nentries = g(o.dk_nentries);
        let bad = crate::error::Error::Format(format!("bad dict keys at {k:#x}"));
        if log2_size > MAX_LOG2_DICT || log2_index_bytes > MAX_LOG2_DICT + 3 || kind > 2 {
            return Err(bad);
        }
        let size = 1u64 << log2_size;
        if nentries < 0 || nentries as u64 > size {
            return Err(bad);
        }
        Ok(Keys {
            refcnt: g(o.dk_refcnt),
            log2_size,
            log2_index_bytes,
            general: kind == 0,
            usable: g(o.dk_usable),
            nentries: nentries as u64,
            entries: k + o.dk_indices + (1u64 << log2_index_bytes),
        })
    }

    /// (key, value) pairs of the keys object `keys`, with values from
    /// `values` (a split table's value array) when non-zero. Skips empty slots.
    fn keys_entries(&self, keys: &Keys, values: Option<(u64, u64)>) -> Result<Vec<(u64, u64)>> {
        let n = keys.nentries.min(MAX_ITEMS);
        let esz = keys.entry_size();
        let raw = self.src.read_vec(keys.entries, (n * esz) as usize)?;
        let word = |i: usize| u64::from_le_bytes(raw[i..i + 8].try_into().unwrap());
        let vals = match values {
            Some((arr, count)) => Some(self.src.read_ptrs(arr, n.min(count) as usize)?),
            None => None,
        };
        let mut out = Vec::new();
        for i in 0..n as usize {
            let base = i * esz as usize;
            let (k, v) = if keys.general {
                (word(base + 8), word(base + 16))
            } else {
                (word(base), word(base + 8))
            };
            let v = match &vals {
                Some(vs) => vs.get(i).copied().unwrap_or(0),
                None => v,
            };
            if k != 0 && v != 0 {
                out.push((k, v));
            }
        }
        Ok(out)
    }

    /// Split-table value array of a dict: (address of values[0], count).
    fn split_values(&self, values: u64, keys: &Keys) -> Result<(u64, u64)> {
        if self.o.dv_has_header {
            let cap = self.src.read_u8(values)? as u64;
            Ok((values + self.o.dv_values, cap.min(keys.nentries)))
        } else {
            Ok((values, keys.nentries))
        }
    }

    fn dict_entries(&self, d: u64) -> Result<Vec<(u64, u64)>> {
        let k = self.ptr(d + self.o.ma_keys)?;
        let values = self.ptr(d + self.o.ma_values)?;
        let keys = self.read_keys(k)?;
        let vals = if values != 0 {
            Some(self.split_values(values, &keys)?)
        } else {
            None
        };
        self.keys_entries(&keys, vals)
    }

    /// The label text for a dict key.
    fn key_label(&mut self, key: u64, role: DictRole) -> Result<KeyLabel> {
        let Ok(t) = self.ptr(key + 8) else {
            return Ok(KeyLabel::Unknown);
        };
        let ti = self.type_info(t)?;
        if ti.id.is_unknown() {
            return Ok(KeyLabel::Unknown);
        }
        if ti.kind == Kind::Str && role == DictRole::Namespace {
            return Ok(match self.name_of(key, true)? {
                Some(s) => KeyLabel::Repr(s),
                None => KeyLabel::Unknown,
            });
        }
        if self.opts.capture_contents {
            if let Some(r) = self.scalar_repr(key, &ti) {
                let (s, _) = truncate_capture(&r, self.opts.max_str);
                return Ok(KeyLabel::Repr(self.out.intern(&s)?));
            }
        }
        let len = self.len_of(key, &ti);
        let p = redacted_key_placeholder(&ti.display, len);
        Ok(KeyLabel::Redacted(self.out.intern(&p)?))
    }

    /// `len()` for the types whose placeholders and extras carry one.
    fn len_of(&self, addr: u64, ti: &TypeInfo) -> Option<u64> {
        let o = &self.o;
        let v = match ti.kind {
            Kind::Str => self.i64(addr + o.str_length).ok()?,
            Kind::Bytes | Kind::ByteArray | Kind::List | Kind::Tuple => self.i64(addr + 16).ok()?,
            Kind::Dict => self.i64(addr + o.ma_used).ok()?,
            Kind::Set | Kind::FrozenSet => self.i64(addr + o.set_used).ok()?,
            _ => return None,
        };
        (v >= 0).then_some(v as u64)
    }

    /// `repr()` of str, bytes, int and float objects (cut to a sane length).
    fn scalar_repr(&self, addr: u64, ti: &TypeInfo) -> Option<String> {
        let max = self.opts.max_str + 1;
        match ti.kind {
            Kind::Str => self
                .read_str_data(addr, max)
                .map(|(s, _)| text::str_repr(&s)),
            Kind::Bytes => {
                let n = self.i64(addr + 16).ok()?;
                if n < 0 {
                    return None;
                }
                let b = self
                    .src
                    .read_vec(addr + self.o.bytes_sval, (n as usize).min(max))
                    .ok()?;
                Some(text::bytes_repr(&b))
            }
            Kind::Int => {
                let tag = self.src.read_u64(addr + self.o.long_tag).ok()?;
                let nd = (tag >> 3) as usize;
                let digits = self
                    .src
                    .read_vec(addr + self.o.long_digits, nd.min(64) * 4)
                    .ok()?;
                let d: Vec<u32> = digits
                    .chunks_exact(4)
                    .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
                if ti.display == "bool" {
                    return Some(
                        if d.iter().any(|&x| x != 0) {
                            "True"
                        } else {
                            "False"
                        }
                        .into(),
                    );
                }
                text::long_repr(&d, tag & 3 == 2, 64)
            }
            Kind::Float => {
                let v = self.src.read_u64(addr + self.o.float_val).ok()?;
                Some(text::float_repr(f64::from_bits(v)))
            }
            _ => None,
        }
    }

    // ---- per-object description --------------------------------------------

    /// Emit the dict's entries as `DictKey` + `DictValue` edges.
    fn dict_edges(&mut self, d: u64, out: &mut Out) -> Result<()> {
        let o = self.o.clone();
        let (Ok(k), Ok(values)) = (self.ptr(d + o.ma_keys), self.ptr(d + o.ma_values)) else {
            self.err(out);
            return Ok(());
        };
        let keys = match self.read_keys(k) {
            Ok(k) => k,
            Err(_) => {
                self.err(out);
                return Ok(());
            }
        };
        let mut vals = None;
        if values != 0 {
            match self.split_values(values, &keys) {
                Ok(v) => vals = Some(v),
                Err(_) => {
                    self.err(out);
                    return Ok(());
                }
            }
        }
        // getsizeof: the values array of a split table (on 3.13+ also when it
        // is embedded in the owning instance; the instance then does not
        // count it), and the keys object when this dict owns it alone.
        if values != 0 {
            out.extra_size += keys.shared_usable() * 8;
        }
        if keys.refcnt == 1 {
            out.extra_size += keys.alloc_size(&o);
        }
        let entries = match self.keys_entries(&keys, vals) {
            Ok(e) => e,
            Err(_) => {
                self.err(out);
                return Ok(());
            }
        };
        let role = if self.namespaces.contains(&d) {
            DictRole::Namespace
        } else {
            DictRole::Ordinary
        };
        for (kp, vp) in entries {
            let label = self.key_label(kp, role)?;
            out.edges.push(Edge {
                target: kp,
                label: EdgeLabel::DictKey(label),
            });
            out.edges.push(Edge {
                target: vp,
                label: EdgeLabel::DictValue(label),
            });
        }
        Ok(())
    }

    /// Attribute edges for values stored against the type's shared keys
    /// (3.12 managed values, 3.13+ inline values).
    fn values_edges(&mut self, values: u64, ti: &TypeInfo, out: &mut Out) -> Result<()> {
        if ti.cached_keys == 0 {
            self.err(out);
            return Ok(());
        }
        let Ok(keys) = self.read_keys(ti.cached_keys) else {
            self.err(out);
            return Ok(());
        };
        let Ok(vals) = self.split_values(values, &keys) else {
            self.err(out);
            return Ok(());
        };
        let Ok(entries) = self.keys_entries(&keys, Some(vals)) else {
            self.err(out);
            return Ok(());
        };
        for (k, v) in entries {
            let label = match self.name_of(k, false)? {
                Some(s) => EdgeLabel::Attr(s),
                None => EdgeLabel::Other(None),
            };
            out.edges.push(Edge { target: v, label });
        }
        Ok(())
    }

    /// The materialized `__dict__` of an instance, if any, and whether the
    /// attributes live in values instead (3.12 managed values / 3.13 inline).
    fn instance_dict(&self, addr: u64, ti: &TypeInfo) -> Result<(u64, Option<u64>)> {
        let o = &self.o;
        if ti.flags & TPFLAGS_MANAGED_DICT != 0 {
            let w = self.ptr(addr.wrapping_sub(24))?;
            if o.minor == 12 {
                // `PyDictOrValues`: a values pointer is stored as `values - 1`.
                if w & 1 != 0 {
                    return Ok((0, Some(w + 1)));
                }
                return Ok((w, None));
            }
            if w != 0 {
                return Ok((w, None));
            }
            if ti.flags & TPFLAGS_INLINE_VALUES != 0 {
                let values = addr + ti.basicsize;
                let valid = self.src.read_u8(values + 3)?;
                if valid != 0 {
                    return Ok((0, Some(values)));
                }
            }
            return Ok((0, None));
        }
        if ti.dictoffset > 0 {
            return Ok((self.ptr(addr + ti.dictoffset as u64)?, None));
        }
        Ok((0, None))
    }

    /// Instance-level edges every heap-type instance gets: `__dict__` or
    /// inline values, `__slots__`, and `ob_type`.
    fn instance_edges(&mut self, addr: u64, ti: &TypeInfo, t: u64, out: &mut Out) -> Result<()> {
        match self.instance_dict(addr, ti) {
            Ok((d, values)) => {
                // Modules, functions and types already emitted their dict.
                if d != 0 && !out.edges.iter().any(|e| e.target == d) {
                    let l = self.attr("__dict__")?;
                    out.edges.push(Edge {
                        target: d,
                        label: l,
                    });
                }
                if let Some(v) = values {
                    self.values_edges(v, ti, out)?;
                    if self.o.minor == 12 && ti.cached_keys != 0 {
                        // The values array is a separate allocation on 3.12.
                        if let Ok(k) = self.read_keys(ti.cached_keys) {
                            let n = k.shared_usable();
                            out.extra_size += n * 8 + ((n + 1 + 7) & !7);
                        }
                    }
                }
            }
            Err(_) => self.err(out),
        }
        for (name, off) in ti.slots.clone() {
            self.field(out, addr + off, EdgeLabel::Attr(name));
        }
        if ti.heap {
            out.edges.push(Edge {
                target: t,
                label: EdgeLabel::Type,
            });
        }
        Ok(())
    }

    /// Edges of an interpreter frame (`_PyInterpreterFrame`) embedded in a
    /// generator or frame object, plus local names.
    fn iframe_edges(&mut self, f: u64, out: &mut Out) -> Result<()> {
        let o = self.o.clone();
        let code = match self.ptr(f + o.if_executable) {
            Ok(c) => mask_stackref(&o, c).unwrap_or(0),
            Err(_) => {
                self.err(out);
                return Ok(());
            }
        };
        if code != 0 {
            let l = self.attr("f_code")?;
            out.edges.push(Edge {
                target: code,
                label: l,
            });
        }
        let l = self.attr("f_func")?;
        self.field(out, f + o.if_funcobj, l);
        self.attr_field(out, f + o.if_globals, "f_globals")?;
        self.attr_field(out, f + o.if_builtins, "f_builtins")?;
        self.attr_field(out, f + o.if_locals, "f_locals")?;
        match self.frame_slots(f, code) {
            Ok(slots) => {
                for (name, v) in slots {
                    let label = match name {
                        Some(n) => EdgeLabel::FrameLocal(self.out.intern(&n)?),
                        None => EdgeLabel::Other(Some(self.out.intern("stack")?)),
                    };
                    out.edges.push(Edge { target: v, label });
                }
            }
            Err(_) => self.err(out),
        }
        Ok(())
    }

    /// Non-null local and stack slots of a frame: (local name or `None` for
    /// a value-stack entry, object).
    fn frame_slots(&mut self, f: u64, code: u64) -> Result<Vec<(Option<String>, u64)>> {
        let o = self.o.clone();
        if code == 0 {
            return Ok(Vec::new());
        }
        let nlocals = self.src.read_u32(code + o.co_nlocalsplus)? as i32;
        if !(0..1 << 20).contains(&nlocals) {
            return Ok(Vec::new());
        }
        let base = f + o.if_localsplus;
        let top = if o.if_stack_is_pointer {
            let sp = self.ptr(f + o.if_stack)?;
            if sp < base {
                nlocals as u64
            } else {
                (sp - base) / 8
            }
        } else {
            let t = self.src.read_u32(f + o.if_stack)? as i32;
            t.max(0) as u64
        };
        let top = top.clamp(nlocals as u64, nlocals as u64 + 4096);
        let names = self.ptr(code + o.co_localsplusnames).unwrap_or(0);
        let raw = self.src.read_ptrs(base, top as usize)?;
        let mut out = Vec::new();
        for (i, v) in raw.into_iter().enumerate() {
            let Some(v) = mask_stackref(&o, v) else {
                continue;
            };
            if v == 0 {
                continue;
            }
            let name = if (i as u64) < nlocals as u64 && names != 0 {
                let np = self
                    .ptr(names + o.tuple_ob_item + 8 * i as u64)
                    .unwrap_or(0);
                Some(
                    self.read_str(np, MAX_NAME)
                        .map(|(s, _)| s)
                        .unwrap_or_else(|| format!("<local {i}>")),
                )
            } else {
                None
            };
            out.push((name, v));
        }
        Ok(out)
    }

    fn code_source_loc(&mut self, code: u64) -> Result<Option<StrId>> {
        let o = self.o.clone();
        let Some((file, _)) = self
            .ptr(code + o.co_filename)
            .ok()
            .and_then(|p| self.read_str(p, MAX_NAME))
        else {
            return Ok(None);
        };
        let line = self.src.read_u32(code + o.co_firstlineno).unwrap_or(0) as i32;
        Ok(Some(self.out.intern(&format!("{file}:{line}"))?))
    }

    fn qualname_extra(&mut self, field: u64) -> Result<Option<StrId>> {
        let Ok(p) = self.ptr(field) else {
            return Ok(None);
        };
        self.name_of(p, false)
    }

    /// Edges, out-of-line size and extras of the object at `addr`.
    fn describe(&mut self, addr: u64, t: u64, ti: &TypeInfo) -> Result<Out> {
        let o = self.o.clone();
        let mut out = Out::default();
        match ti.kind {
            Kind::Dict => self.dict_edges(addr, &mut out)?,
            Kind::List => match (self.i64(addr + 16), self.ptr(addr + o.list_ob_item)) {
                (Ok(n), Ok(items)) => {
                    let alloc = self.i64(addr + o.list_allocated).unwrap_or(n).max(0) as u64;
                    out.extra_size += alloc.min(MAX_ITEMS) * 8;
                    let n = (n.max(0) as u64).min(MAX_ITEMS);
                    if n > 0 && items != 0 {
                        match self.src.read_ptrs(items, n as usize) {
                            Ok(v) => {
                                for (i, x) in v.into_iter().enumerate() {
                                    if x != 0 {
                                        out.edges.push(Edge {
                                            target: x,
                                            label: EdgeLabel::ListItem(i as u32),
                                        });
                                    }
                                }
                            }
                            Err(_) => self.err(&mut out),
                        }
                    }
                }
                _ => self.err(&mut out),
            },
            Kind::Tuple => match self.i64(addr + 16) {
                Ok(n) => {
                    let n = (n.max(0) as u64).min(MAX_ITEMS);
                    match self.src.read_ptrs(addr + o.tuple_ob_item, n as usize) {
                        Ok(v) => {
                            for (i, x) in v.into_iter().enumerate() {
                                if x != 0 {
                                    out.edges.push(Edge {
                                        target: x,
                                        label: EdgeLabel::TupleItem(i as u32),
                                    });
                                }
                            }
                        }
                        Err(_) => self.err(&mut out),
                    }
                }
                Err(_) => self.err(&mut out),
            },
            Kind::Set | Kind::FrozenSet => {
                match (self.i64(addr + o.set_mask), self.ptr(addr + o.set_table)) {
                    (Ok(mask), Ok(table)) if (0..MAX_ITEMS as i64).contains(&mask) => {
                        let n = mask as u64 + 1;
                        if table != addr + o.set_smalltable {
                            out.extra_size += n * 16;
                        }
                        match self.src.read_vec(table, (n * 16) as usize) {
                            Ok(raw) => {
                                for e in raw.chunks_exact(16) {
                                    let key = u64::from_le_bytes(e[0..8].try_into().unwrap());
                                    let hash = i64::from_le_bytes(e[8..16].try_into().unwrap());
                                    // Dummy (deleted) entries have hash -1.
                                    if key != 0 && hash != -1 {
                                        out.edges.push(Edge {
                                            target: key,
                                            label: EdgeLabel::SetItem,
                                        });
                                    }
                                }
                            }
                            Err(_) => self.err(&mut out),
                        }
                    }
                    _ => self.err(&mut out),
                }
            }
            Kind::ByteArray => match self.i64(addr + o.bytearray_alloc) {
                Ok(n) if n >= 0 => out.extra_size += n as u64,
                _ => self.err(&mut out),
            },
            Kind::Module => {
                self.attr_field(&mut out, addr + o.md_dict, "__dict__")?;
                out.extras.qualname = self.qualname_extra(addr + o.md_name)?;
            }
            Kind::Function => {
                for (off, name) in [
                    (o.func_globals, "__globals__"),
                    (o.func_builtins, "__builtins__"),
                    (o.func_name, "__name__"),
                    (o.func_qualname, "__qualname__"),
                    (o.func_code, "__code__"),
                    (o.func_defaults, "__defaults__"),
                    (o.func_kwdefaults, "__kwdefaults__"),
                    (o.func_closure, "__closure__"),
                    (o.func_doc, "__doc__"),
                    (o.func_dict, "__dict__"),
                    (o.func_module, "__module__"),
                    (o.func_annotations, "__annotations__"),
                    (o.func_typeparams, "__type_params__"),
                ] {
                    self.attr_field(&mut out, addr + off, name)?;
                }
                if let Some(a) = o.func_annotate {
                    self.attr_field(&mut out, addr + a, "__annotate__")?;
                }
                // Closure cells, directly.
                if let Ok(c) = self.ptr(addr + o.func_closure) {
                    if c != 0 {
                        let n = self.i64(c + 16).unwrap_or(0).clamp(0, 1 << 16) as usize;
                        match self.src.read_ptrs(c + o.tuple_ob_item, n) {
                            Ok(cells) => {
                                for (i, cell) in cells.into_iter().enumerate() {
                                    if cell != 0 {
                                        out.edges.push(Edge {
                                            target: cell,
                                            label: EdgeLabel::ClosureCell(i as u32),
                                        });
                                    }
                                }
                            }
                            Err(_) => self.err(&mut out),
                        }
                    }
                }
                out.extras.qualname = self.qualname_extra(addr + o.func_qualname)?;
                if let Ok(code) = self.ptr(addr + o.func_code) {
                    if code != 0 {
                        out.extras.source_loc = self.code_source_loc(code)?;
                    }
                }
            }
            Kind::Cell => self.field(&mut out, addr + o.cell_ref, EdgeLabel::CellContents),
            Kind::Method => {
                self.attr_field(&mut out, addr + o.im_func, "__func__")?;
                self.attr_field(&mut out, addr + o.im_self, "__self__")?;
            }
            Kind::CFunction => {
                self.attr_field(&mut out, addr + o.cfunc_self, "__self__")?;
                self.attr_field(&mut out, addr + o.cfunc_module, "__module__")?;
            }
            Kind::ClassOrStaticMethod => {
                self.attr_field(&mut out, addr + 16, "__func__")?;
                self.attr_field(&mut out, addr + 24, "__dict__")?;
            }
            Kind::Property => {
                for (off, name) in [(16, "fget"), (24, "fset"), (32, "fdel"), (40, "__doc__")] {
                    self.attr_field(&mut out, addr + off, name)?;
                }
            }
            Kind::Code => {
                for (off, name) in [
                    (o.co_consts, "co_consts"),
                    (o.co_names, "co_names"),
                    (o.co_exceptiontable, "co_exceptiontable"),
                    (o.co_localsplusnames, "co_localsplusnames"),
                    (o.co_localspluskinds, "co_localspluskinds"),
                    (o.co_filename, "co_filename"),
                    (o.co_name, "co_name"),
                    (o.co_qualname, "co_qualname"),
                    (o.co_linetable, "co_linetable"),
                ] {
                    self.attr_field(&mut out, addr + off, name)?;
                }
                out.extras.qualname = self.qualname_extra(addr + o.co_qualname)?;
                out.extras.source_loc = self.code_source_loc(addr)?;
            }
            Kind::Type => {
                self.attr_field(&mut out, addr + o.tp_dict, "__dict__")?;
                self.attr_field(&mut out, addr + o.tp_bases, "__bases__")?;
                self.attr_field(&mut out, addr + o.tp_mro, "__mro__")?;
                self.attr_field(&mut out, addr + o.tp_base, "__base__")?;
                let own = self.type_info(addr)?;
                if own.heap {
                    self.attr_field(&mut out, addr + o.ht_name, "__name__")?;
                    self.attr_field(&mut out, addr + o.ht_qualname, "__qualname__")?;
                    self.attr_field(&mut out, addr + o.ht_slots, "__slots__")?;
                    self.attr_field(&mut out, addr + o.ht_module, "__module_object__")?;
                    if own.cached_keys != 0 {
                        if let Ok(k) = self.read_keys(own.cached_keys) {
                            out.extra_size += k.alloc_size(&o);
                        }
                    }
                }
                if !own.id.is_unknown() {
                    out.extras.qualname = Some(self.out.intern(&own.qualname)?);
                }
            }
            Kind::Gen => {
                self.attr_field(&mut out, addr + o.gi_name, "__name__")?;
                self.attr_field(&mut out, addr + o.gi_qualname, "__qualname__")?;
                match self.src.read_u8(addr + o.gi_frame_state) {
                    Ok(s) if (s as i8) < 1 => self.iframe_edges(addr + o.gi_iframe, &mut out)?,
                    Ok(_) => {}
                    Err(_) => self.err(&mut out),
                }
                out.extras.qualname = self.qualname_extra(addr + o.gi_qualname)?;
            }
            Kind::Frame => {
                self.attr_field(&mut out, addr + o.frameobj_back, "f_back")?;
                match self.ptr(addr + o.frameobj_frame) {
                    Ok(f) if f != 0 => self.iframe_edges(f, &mut out)?,
                    Ok(_) => {}
                    Err(_) => self.err(&mut out),
                }
            }
            Kind::Str | Kind::Bytes | Kind::Int | Kind::Float | Kind::Other => {}
        }
        if ti.heap || ti.flags & TPFLAGS_MANAGED_DICT != 0 || ti.dictoffset > 0 {
            self.instance_edges(addr, ti, t, &mut out)?;
        }
        out.extras.length = self.len_of(addr, ti);
        if self.opts.capture_contents && matches!(ti.kind, Kind::Str | Kind::Bytes) {
            let text = match ti.kind {
                Kind::Str => self
                    .read_str_data(addr, self.opts.max_str + 1)
                    .map(|(s, n)| {
                        let (c, cut) = truncate_capture(&s, self.opts.max_str);
                        (c, cut || n > s.chars().count() as u64)
                    }),
                _ => self.scalar_repr(addr, ti).map(|s| {
                    let n = self.i64(addr + 16).unwrap_or(0).max(0) as usize;
                    let (c, cut) = truncate_capture(&s, self.opts.max_str);
                    (c, cut || n > self.opts.max_str + 1)
                }),
            };
            if let Some((c, cut)) = text {
                out.extras.content = Some(self.out.intern(&c)?);
                out.extras.content_truncated = cut;
            }
        }
        Ok(out)
    }

    /// `sys.getsizeof` without the out-of-line parts.
    fn base_size(&self, addr: u64, ti: &TypeInfo) -> u64 {
        let o = &self.o;
        let var = || -> u64 {
            let n = self
                .i64(addr + 16)
                .unwrap_or(0)
                .unsigned_abs()
                .min(MAX_ITEMS);
            ti.basicsize + ti.itemsize * n
        };
        let core = match ti.kind {
            Kind::Int => {
                let tag = self.src.read_u64(addr + o.long_tag).unwrap_or(0);
                o.long_digits + 4 * (tag >> 3).clamp(1, MAX_ITEMS)
            }
            Kind::Str => self.str_size(addr).unwrap_or(ti.basicsize),
            // `_PyObject_VAR_SIZE` rounds up to a pointer.
            Kind::Code => (var() + 7) & !7,
            Kind::Gen => self.frame_size(addr + o.gi_iframe, o.gi_iframe),
            Kind::Frame => match self.ptr(addr + o.frameobj_frame) {
                Ok(f) if f != 0 => self.frame_size(f, o.frameobj_data),
                _ => ti.basicsize,
            },
            Kind::List | Kind::Dict | Kind::Set | Kind::FrozenSet | Kind::ByteArray => ti.basicsize,
            _ => {
                let mut s = if ti.itemsize > 0 { var() } else { ti.basicsize };
                // Inline values, unless a materialized dict counts them.
                let has_dict = self.ptr(addr.wrapping_sub(24)).map_or(true, |d| d != 0);
                if o.minor >= 13
                    && ti.flags & TPFLAGS_INLINE_VALUES != 0
                    && ti.cached_keys != 0
                    && !has_dict
                {
                    if let Ok(k) = self.read_keys(ti.cached_keys) {
                        let n = k.shared_usable();
                        s += ((n + 7) & !7) + (n + 1) * 8;
                    }
                }
                s
            }
        };
        core + ti.preheader()
    }

    /// `gen.__sizeof__` / `frame.__sizeof__`: the fixed part up to the frame,
    /// the frame header, and `co_framesize` minus the header words.
    fn frame_size(&self, iframe: u64, fixed: u64) -> u64 {
        let o = &self.o;
        let slots = self
            .ptr(iframe + o.if_executable)
            .ok()
            .and_then(|c| mask_stackref(o, c))
            .and_then(|c| self.src.read_u32(c + o.co_framesize).ok())
            .map(|n| (n as u64).saturating_sub(o.if_localsplus / 8))
            .unwrap_or(0)
            .min(1 << 20);
        fixed + o.if_localsplus + slots * 8
    }

    fn str_size(&self, addr: u64) -> Option<u64> {
        let o = &self.o;
        let len = self.i64(addr + o.str_length).ok()?.clamp(0, 1 << 40) as u64;
        let state = self.src.read_u32(addr + o.str_state).ok()?;
        let kind = ((state >> 2) & 7) as u64;
        let compact = state & 32 != 0;
        let ascii = state & 64 != 0;
        let mut size = if compact && ascii {
            o.ascii_size + len + 1
        } else if compact {
            o.compact_size + (len + 1) * kind
        } else {
            o.compact_size + 8 + (len + 1) * kind
        };
        if !(compact && ascii) {
            let utf8 = self.ptr(addr + o.str_utf8).unwrap_or(0);
            let data = addr + if compact { o.compact_size } else { 0 };
            if utf8 != 0 && utf8 != data {
                size += self.i64(addr + o.str_utf8_length).unwrap_or(0).max(0) as u64 + 1;
            }
        }
        Some(size)
    }

    /// Emit the object at `addr` with all of its edges.
    fn emit(&mut self, addr: u64, tracked: bool) -> Result<()> {
        let mut flags = if tracked {
            ObjectFlags::GC_TRACKED
        } else {
            ObjectFlags::NONE
        };
        let hdr = match self.src.read_vec(addr, 16) {
            Ok(h) => h,
            Err(_) => {
                self.stats.read_errors += 1;
                let obj = ObjectInput {
                    addr,
                    type_id: TypeId::UNKNOWN,
                    shallow_size: 16,
                    flags: flags | ObjectFlags::PARTIAL,
                    extras: ObjectExtras::default(),
                };
                self.out.add_object(&obj, [])?;
                self.stats.objects += 1;
                return Ok(());
            }
        };
        let refcnt = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
        let t = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        if (refcnt as u32 as i32) < 0 {
            flags |= ObjectFlags::IMMORTAL;
        }
        let ti = self.type_info(t)?;
        let mut d = if ti.id.is_unknown() {
            self.stats.read_errors += 1;
            Out {
                partial: true,
                ..Out::default()
            }
        } else {
            self.describe(addr, t, &ti)?
        };
        if d.partial {
            flags |= ObjectFlags::PARTIAL;
        }
        if ti.kind == Kind::Type {
            flags |= ObjectFlags::IS_TYPE;
            // Make sure the type itself is in the type table.
            self.type_info(addr)?;
        }
        let size = self.base_size(addr, &ti) + d.extra_size;
        for e in &d.edges {
            if !self.is_tracked(e.target) && self.untracked.insert(e.target) {
                self.queue.push(e.target);
            }
        }
        let obj = ObjectInput {
            addr,
            type_id: ti.id,
            shallow_size: size,
            flags,
            extras: d.extras,
        };
        self.stats.edges += d.edges.len() as u64;
        self.out.add_object(&obj, d.edges.drain(..))?;
        self.stats.objects += 1;
        Ok(())
    }

    /// Emit queued untracked objects (and whatever they reach).
    fn drain(&mut self) -> Result<()> {
        while let Some(a) = self.queue.pop() {
            // Only objects whose header and type are readable, and not static
            // type objects (they live in the interpreter image, not the heap).
            let Ok(t) = self.ptr(a + 8) else {
                continue;
            };
            if a % 8 != 0 {
                continue;
            }
            let ti = self.type_info(t)?;
            if ti.id.is_unknown() {
                continue;
            }
            if ti.kind == Kind::Type {
                let own = self.type_info(a)?;
                if !own.heap {
                    continue;
                }
            }
            self.emit(a, false)?;
        }
        Ok(())
    }

    // ---- enumeration ---------------------------------------------------------

    /// Walk one GC list starting at the sentinel `head`, appending object
    /// addresses. Returns `false` if the list was corrupt.
    fn walk_gc_list(&mut self, head: u64, limit: u64) -> bool {
        let mut cur = match self.ptr(head) {
            Ok(n) => n & !7,
            Err(_) => return false,
        };
        // Brent's cycle detection: a loop that never returns to the head.
        let (mut power, mut lam, mut saved) = (1u64, 0u64, cur);
        let mut steps = 0u64;
        while cur != head {
            if cur == 0 || steps >= limit {
                return false;
            }
            let Ok(next) = self.ptr(cur) else {
                return false;
            };
            self.tracked.push(cur + GC_HEAD);
            steps += 1;
            cur = next & !7;
            lam += 1;
            if cur == saved {
                return false;
            }
            if lam == power {
                saved = cur;
                power *= 2;
                lam = 0;
            }
        }
        true
    }

    /// Record which dicts are namespaces (module, type, instance, function
    /// `__dict__`s), before any dict is emitted.
    fn find_namespaces(&mut self) -> Result<()> {
        let o = self.o.clone();
        for i in 0..self.tracked.len() {
            let a = self.tracked[i];
            let Ok(t) = self.ptr(a + 8) else { continue };
            let ti = self.type_info(t)?;
            let d = match ti.kind {
                Kind::Module => self.ptr(a + o.md_dict).unwrap_or(0),
                Kind::Type => self.ptr(a + o.tp_dict).unwrap_or(0),
                Kind::Function => self.ptr(a + o.func_dict).unwrap_or(0),
                _ => 0,
            };
            if d != 0 {
                self.namespaces.insert(d);
            }
            if ti.heap || ti.flags & TPFLAGS_MANAGED_DICT != 0 || ti.dictoffset > 0 {
                if let Ok((d, _)) = self.instance_dict(a, &ti) {
                    if d != 0 {
                        self.namespaces.insert(d);
                    }
                }
            }
        }
        Ok(())
    }

    fn interpreters(&self, runtime: u64) -> Vec<u64> {
        let mut v = Vec::new();
        let mut cur = self.ptr(runtime + self.o.rt_interpreters_head).unwrap_or(0);
        while cur != 0 && v.len() < MAX_INTERPRETERS && !v.contains(&cur) {
            v.push(cur);
            cur = self.ptr(cur + self.o.is_next).unwrap_or(0);
        }
        v
    }

    pub fn run(mut self, runtime: u64) -> Result<WalkStats> {
        let o = self.o.clone();
        let interps = self.interpreters(runtime);
        if interps.is_empty() {
            return Err(crate::error::Error::NotPython(format!(
                "_PyRuntime at {runtime:#x} has no interpreters"
            )));
        }
        let limit = self
            .src
            .mapped_ranges()
            .map(|r| r.iter().map(|m| m.size).sum::<u64>() / 32)
            .unwrap_or(1 << 32)
            .max(1 << 16);

        for &is in &interps {
            let gc = is + o.is_gc;
            for off in o.gc_lists {
                if !self.walk_gc_list(gc + off, limit) {
                    self.stats.truncated = true;
                }
            }
        }
        self.tracked.sort_unstable();
        self.tracked.dedup();
        self.find_namespaces()?;

        for i in 0..self.tracked.len() {
            let a = self.tracked[i];
            self.emit(a, true)?;
            self.drain()?;
        }

        for &is in &interps {
            self.interp_roots(is)?;
        }
        self.drain()?;
        Ok(self.stats)
    }

    // ---- roots ---------------------------------------------------------------

    fn root(&mut self, addr: u64, kind: RootKind, label: &str) -> Result<()> {
        if addr == 0 {
            return Ok(());
        }
        let l = self.out.intern(label)?;
        self.out.add_root(addr, kind, l)?;
        self.stats.roots += 1;
        if !self.is_tracked(addr) && self.untracked.insert(addr) {
            self.queue.push(addr);
        }
        Ok(())
    }

    fn interp_roots(&mut self, is: u64) -> Result<()> {
        let o = self.o.clone();
        let modules = self.ptr(is + o.is_modules).unwrap_or(0);
        if modules != 0 {
            match self.dict_entries(modules) {
                Ok(entries) => {
                    for (k, v) in entries {
                        if let Some((name, _)) = self.read_str(k, MAX_NAME) {
                            self.root(v, RootKind::ModuleDict, &format!("sys.modules['{name}']"))?;
                        } else {
                            self.root(v, RootKind::ModuleDict, "sys.modules[?]")?;
                        }
                    }
                }
                Err(_) => self.stats.read_errors += 1,
            }
            self.root(modules, RootKind::Interp, "interp sys.modules")?;
        }
        let builtins = self.ptr(is + o.is_builtins).unwrap_or(0);
        self.root(builtins, RootKind::Interp, "interp builtins")?;
        let sysdict = self.ptr(is + o.is_sysdict).unwrap_or(0);
        self.root(sysdict, RootKind::Interp, "interp sys")?;

        let mut ts = self.ptr(is + o.is_threads_head).unwrap_or(0);
        let mut seen = HashSet::new();
        while ts != 0 && seen.len() < MAX_THREADS && seen.insert(ts) {
            self.thread_roots(ts)?;
            ts = self.ptr(ts + o.ts_next).unwrap_or(0);
        }
        Ok(())
    }

    fn thread_roots(&mut self, ts: u64) -> Result<()> {
        let o = self.o.clone();
        let tid = if self.src.target().os == heapspy_snapshot::Os::Windows && o.minor == 12 {
            self.src.read_u32(ts + o.ts_native_thread_id).map(u64::from)
        } else {
            self.src.read_u64(ts + o.ts_native_thread_id)
        }
        .unwrap_or(0);
        let tdict = self.ptr(ts + o.ts_dict).unwrap_or(0);
        self.root(tdict, RootKind::ThreadLocals, &format!("thread {tid} dict"))?;
        let exc = self.ptr(ts + o.ts_current_exception).unwrap_or(0);
        self.root(
            exc,
            RootKind::ThreadLocals,
            &format!("thread {tid} exception"),
        )?;

        let mut f = if o.ts_frame_via_cframe {
            self.ptr(ts + o.ts_current_frame)
                .and_then(|c| if c == 0 { Ok(0) } else { self.ptr(c) })
                .unwrap_or(0)
        } else {
            self.ptr(ts + o.ts_current_frame).unwrap_or(0)
        };
        let mut seen = HashSet::new();
        while f != 0 && seen.len() < MAX_FRAMES && seen.insert(f) {
            self.frame_roots(f)?;
            f = self.ptr(f + o.if_previous).unwrap_or(0);
        }
        Ok(())
    }

    fn frame_roots(&mut self, f: u64) -> Result<()> {
        let o = self.o.clone();
        let owner = self.src.read_u8(f + o.if_owner).unwrap_or(u8::MAX);
        if owner >= o.owner_first_shim {
            return Ok(());
        }
        let Some(code) = self
            .ptr(f + o.if_executable)
            .ok()
            .and_then(|c| mask_stackref(&o, c))
        else {
            return Ok(());
        };
        if code == 0 {
            return Ok(());
        }
        // Only real code objects (3.13+ shim frames may hold other things).
        let Ok(ct) = self.ptr(code + 8) else {
            return Ok(());
        };
        if self.type_info(ct)?.kind != Kind::Code {
            return Ok(());
        }
        let code_name = self
            .ptr(code + o.co_qualname)
            .ok()
            .and_then(|p| self.read_str(p, MAX_NAME))
            .map(|(s, _)| s)
            .unwrap_or_else(|| "?".into());
        let func = self
            .ptr(f + o.if_funcobj)
            .ok()
            .and_then(|p| mask_stackref(&o, p))
            .unwrap_or(0);
        let module = if func != 0 {
            self.ptr(func + o.func_module)
                .ok()
                .and_then(|p| self.read_str(p, MAX_NAME))
                .map(|(s, _)| s)
        } else {
            None
        };
        let module = module.unwrap_or_else(|| {
            self.ptr(code + o.co_filename)
                .ok()
                .and_then(|p| self.read_str(p, MAX_NAME))
                .map(|(s, _)| {
                    let file = s.rsplit(['/', '\\']).next().unwrap_or(&s).to_string();
                    file.strip_suffix(".py").map(str::to_string).unwrap_or(file)
                })
                .unwrap_or_else(|| "?".into())
        });
        let frame = format!("frame {module}:{code_name}");
        let slots = match self.frame_slots(f, code) {
            Ok(s) => s,
            Err(_) => {
                self.stats.read_errors += 1;
                Vec::new()
            }
        };
        for (name, v) in slots {
            let label = match name {
                Some(n) => format!("{frame} local '{n}'"),
                None => format!("{frame} stack"),
            };
            self.root(v, RootKind::FrameLocal, &label)?;
        }
        let globals = self.ptr(f + o.if_globals).unwrap_or(0);
        let locals = self.ptr(f + o.if_locals).unwrap_or(0);
        if locals != globals {
            self.root(locals, RootKind::FrameLocal, &format!("{frame} f_locals"))?;
        }
        Ok(())
    }
}
