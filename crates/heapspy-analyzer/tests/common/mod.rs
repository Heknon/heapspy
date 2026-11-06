//! A tiny heap model for building realistic snapshots in tests. Objects get
//! edges after creation (the builder needs them up front), and helpers lay
//! out modules the way the walker records them: a `module_dict` root on the
//! module object, `.__dict__` to the module's dict, `['NAME']` to globals.

#![allow(dead_code)]

use std::collections::HashMap;

use heapspy_snapshot::{ObjectFlags, RootKind, Snapshot, SnapshotBuilder, TypeId};

#[derive(Clone, Debug)]
pub enum L {
    Key(String),
    Redacted(u64),
    Item(u32),
    Attr(String),
    Cell,
    Closure(u32),
    Type,
}

struct Obj {
    addr: u64,
    ty: TypeId,
    size: u64,
    flags: ObjectFlags,
    length: Option<u64>,
    edges: Vec<(u64, L)>,
}

pub struct Heap {
    pub b: SnapshotBuilder,
    objs: Vec<Obj>,
    index: HashMap<u64, usize>,
    roots: Vec<(u64, RootKind, String)>,
    next: u64,
}

impl Default for Heap {
    fn default() -> Self {
        Self::new()
    }
}

impl Heap {
    pub fn new() -> Heap {
        Heap {
            b: SnapshotBuilder::new(),
            objs: Vec::new(),
            index: HashMap::new(),
            roots: Vec::new(),
            next: 0x7f00_0000_0000,
        }
    }

    pub fn ty(&mut self, full: &str) -> TypeId {
        let (m, q) = full.rsplit_once('.').unwrap_or(("", full));
        self.b.ty(m, q)
    }

    /// New object of type `full` (e.g. `"builtins.dict"`); returns its address.
    pub fn obj(&mut self, full: &str, size: u64) -> u64 {
        let ty = self.ty(full);
        self.next += 0x100;
        self.index.insert(self.next, self.objs.len());
        self.objs.push(Obj {
            addr: self.next,
            ty,
            size,
            flags: ObjectFlags::GC_TRACKED,
            length: None,
            edges: Vec::new(),
        });
        self.next
    }

    fn find(&mut self, addr: u64) -> &mut Obj {
        let i = self.index[&addr];
        &mut self.objs[i]
    }

    pub fn edge(&mut self, from: u64, to: u64, l: L) {
        self.find(from).edges.push((to, l));
    }

    pub fn key(&mut self, from: u64, to: u64, k: &str) {
        self.edge(from, to, L::Key(format!("'{k}'")));
    }

    pub fn attr(&mut self, from: u64, to: u64, name: &str) {
        self.edge(from, to, L::Attr(name.into()));
    }

    pub fn item(&mut self, from: u64, to: u64, i: u32) {
        self.edge(from, to, L::Item(i));
    }

    pub fn untracked(&mut self, addr: u64) {
        self.find(addr).flags = ObjectFlags::NONE;
    }

    pub fn is_type(&mut self, addr: u64) {
        self.find(addr).flags = ObjectFlags::GC_TRACKED | ObjectFlags::IS_TYPE;
    }

    pub fn length(&mut self, addr: u64, n: u64) {
        self.find(addr).length = Some(n);
    }

    pub fn root(&mut self, addr: u64, kind: RootKind, label: &str) {
        self.roots.push((addr, kind, label.into()));
    }

    /// A module object rooted as `sys.modules['name']` with its `__dict__`.
    /// Returns `(module, dict)`.
    pub fn module(&mut self, name: &str) -> (u64, u64) {
        let m = self.obj("builtins.module", 72);
        let d = self.obj("builtins.dict", 2272);
        self.attr(m, d, "__dict__");
        self.root(m, RootKind::ModuleDict, &format!("sys.modules['{name}']"));
        (m, d)
    }

    /// A class object stored as a module global, with its own `__dict__`.
    pub fn class(&mut self, module_dict: u64, full: &str) -> u64 {
        let t = self.obj("builtins.type", 1704);
        self.is_type(t);
        let d = self.obj("builtins.dict", 648);
        self.attr(t, d, "__dict__");
        let q = full.rsplit('.').next().unwrap().to_string();
        self.key(module_dict, t, &q);
        t
    }

    pub fn build(&self) -> Snapshot {
        let mut b = self.b.clone();
        for o in &self.objs {
            let s = b.object(o.addr, o.ty, o.size).flags(o.flags);
            if let Some(n) = o.length {
                s.length(n);
            }
            for (t, l) in &o.edges {
                match l {
                    L::Key(k) => s.dict_value(*t, k),
                    L::Redacted(n) => s.redacted_dict_value(*t, "str", *n),
                    L::Item(i) => s.list_item(*t, *i),
                    L::Attr(a) => s.attr(*t, a),
                    L::Cell => s.cell_contents(*t),
                    L::Closure(i) => s.closure_cell(*t, *i),
                    L::Type => s.type_edge(*t),
                };
            }
        }
        for (a, k, l) in &self.roots {
            b.root(*a, *k, l);
        }
        b.build().unwrap()
    }
}

pub const MIB: u64 = 1 << 20;

/// `app.cache` with `CACHE = {key: Session(payload=bytes)}` holding `n`
/// sessions of `payload` bytes each, plus some unrelated globals in
/// `__main__`. Returns the heap and the CACHE dict's address.
pub fn unbounded_cache(n: u32, payload: u64) -> (Heap, u64) {
    let mut h = Heap::new();
    let (_, main) = h.module("__main__");
    let small = h.obj("builtins.list", 120);
    h.key(main, small, "config");
    let (_, md) = h.module("app.cache");
    let cls = h.class(md, "app.session.Session");
    let cache = h.obj("builtins.dict", 36 * n as u64 + 232);
    h.key(md, cache, "CACHE");
    h.length(cache, n as u64);
    for i in 0..n {
        let s = h.obj("app.session.Session", 56);
        h.edge(s, cls, L::Type);
        h.edge(cache, s, L::Redacted(9 + (i as u64 % 3)));
        let p = h.obj("builtins.bytes", payload);
        h.untracked(p);
        h.attr(s, p, "payload");
    }
    (h, cache)
}
