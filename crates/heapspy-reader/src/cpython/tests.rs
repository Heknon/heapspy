//! Walker tests over fake heaps laid out in a [`MemImage`].
//!
//! [`Heap`] writes CPython structures at the offsets of a given [`Offsets`]
//! table, so the same scenarios run against the 3.12, 3.13 and 3.14 layouts.

use heapspy_snapshot::{
    EdgeOrigin, KeyLabel, ObjectFlags, PythonVersion, RootKind, Snapshot, SnapshotInfo,
    SnapshotWriter,
};

use super::offsets::*;
use super::*;
use crate::dump::DumpOptions;
use crate::source::mem::MemImage;
use crate::source::{Module, TargetInfo};

const BASE: u64 = 0x10_0000;
const SIZE: usize = 1 << 20;

/// A bump-allocated fake heap.
struct Heap {
    o: Offsets,
    mem: Vec<u8>,
    top: u64,
    /// Static types.
    type_type: u64,
    str_t: u64,
    bytes_t: u64,
    int_t: u64,
    dict_t: u64,
    list_t: u64,
    tuple_t: u64,
    module_t: u64,
    code_t: u64,
    func_t: u64,
    cell_t: u64,
    /// Generation list heads (sentinels), the permanent generation last.
    gens: [u64; 4],
    runtime: u64,
    interp: u64,
}

impl Heap {
    fn new(minor: u8) -> Heap {
        let o = Offsets::table(minor, heapspy_snapshot::Os::Linux).unwrap();
        let mut h = Heap {
            o,
            mem: vec![0; SIZE],
            top: BASE + 0x100,
            type_type: 0,
            str_t: 0,
            bytes_t: 0,
            int_t: 0,
            dict_t: 0,
            list_t: 0,
            tuple_t: 0,
            module_t: 0,
            code_t: 0,
            func_t: 0,
            cell_t: 0,
            gens: [0; 4],
            runtime: 0,
            interp: 0,
        };
        let o = h.o.clone();
        // `type` first so the other static types can point at it.
        h.type_type = h.static_type("type", TPFLAGS_HAVE_GC | TPFLAGS_TYPE_SUBCLASS, 936, 40);
        h.str_t = h.static_type("str", TPFLAGS_UNICODE_SUBCLASS, o.ascii_size, 0);
        h.bytes_t = h.static_type("bytes", TPFLAGS_BYTES_SUBCLASS, o.bytes_sval + 1, 1);
        h.int_t = h.static_type("int", TPFLAGS_LONG_SUBCLASS, o.long_digits, 4);
        h.dict_t = h.static_type("dict", TPFLAGS_HAVE_GC | TPFLAGS_DICT_SUBCLASS, 48, 0);
        h.list_t = h.static_type("list", TPFLAGS_HAVE_GC | TPFLAGS_LIST_SUBCLASS, 40, 0);
        h.tuple_t = h.static_type(
            "tuple",
            TPFLAGS_HAVE_GC | TPFLAGS_TUPLE_SUBCLASS,
            o.tuple_ob_item,
            8,
        );
        h.module_t = h.static_type("module", TPFLAGS_HAVE_GC, 72, 0);
        h.code_t = h.static_type("code", 0, 200, 2);
        h.func_t = h.static_type("function", TPFLAGS_HAVE_GC, 160, 0);
        h.cell_t = h.static_type("cell", TPFLAGS_HAVE_GC, 24, 0);

        // Runtime -> interpreter -> GC state.
        h.runtime = h.alloc(1024);
        h.interp = h.alloc(o.is_modules + 64);
        h.w64(h.runtime + o.rt_interpreters_head, h.interp);
        for (i, off) in o.gc_lists.iter().enumerate() {
            let head = h.interp + o.is_gc + off;
            h.w64(head, head);
            h.w64(head + 8, head);
            h.gens[i] = head;
        }
        h
    }

    fn alloc(&mut self, n: u64) -> u64 {
        let a = self.top;
        self.top = (self.top + n + 15) & !15;
        assert!(self.top < BASE + SIZE as u64, "fake heap full");
        a
    }

    fn w64(&mut self, a: u64, v: u64) {
        let i = (a - BASE) as usize;
        self.mem[i..i + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(&mut self, a: u64, v: u32) {
        let i = (a - BASE) as usize;
        self.mem[i..i + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn w8(&mut self, a: u64, v: u8) {
        self.mem[(a - BASE) as usize] = v;
    }
    fn bytes(&mut self, a: u64, b: &[u8]) {
        let i = (a - BASE) as usize;
        self.mem[i..i + b.len()].copy_from_slice(b);
    }

    fn cstr(&mut self, s: &str) -> u64 {
        let a = self.alloc(s.len() as u64 + 1);
        self.bytes(a, s.as_bytes());
        a
    }

    fn static_type(&mut self, name: &str, flags: u64, basic: u64, item: u64) -> u64 {
        let o = self.o.clone();
        let t = self.alloc(936);
        self.w64(t, 0xFFFF_FFFF);
        self.w64(t + 8, self.type_type);
        let n = self.cstr(name);
        self.w64(t + o.tp_name, n);
        self.w64(t + o.tp_basicsize, basic);
        self.w64(t + o.tp_itemsize, item);
        self.w64(t + o.tp_flags, flags);
        t
    }

    /// Allocate an object with `pre` bytes of pre-header; returns the object
    /// address. GC objects are linked into generation `gen`.
    fn object(&mut self, ty: u64, size: u64, gc: Option<usize>, managed: bool) -> u64 {
        let pre = if gc.is_some() { 16 } else { 0 } + if managed { 16 } else { 0 };
        let a = self.alloc(pre + size) + pre;
        self.w64(a, 1);
        self.w64(a + 8, ty);
        if let Some(g) = gc {
            self.link(a, self.gens[g]);
        }
        a
    }

    /// Append the object at `a` to the GC list with sentinel `head`.
    fn link(&mut self, a: u64, head: u64) {
        let gch = a - 16;
        let last = self.r64(head + 8);
        self.w64(last, gch); // last.next = gch
        self.w64(gch, head); // gch.next = head
        self.w64(gch + 8, last); // gch.prev = last
        self.w64(head + 8, gch); // head.prev = gch
    }

    fn r64(&self, a: u64) -> u64 {
        let i = (a - BASE) as usize;
        u64::from_le_bytes(self.mem[i..i + 8].try_into().unwrap())
    }

    fn str(&mut self, s: &str) -> u64 {
        assert!(s.is_ascii());
        let o = self.o.clone();
        let a = self.object(self.str_t, o.ascii_size + s.len() as u64 + 1, None, false);
        self.w64(a + o.str_length, s.len() as u64);
        self.w64(a + 24, u64::MAX); // hash
        self.w32(a + o.str_state, (1 << 2) | 32 | 64);
        self.bytes(a + o.ascii_size, s.as_bytes());
        a
    }

    fn bytes_obj(&mut self, b: &[u8]) -> u64 {
        let o = self.o.clone();
        let a = self.object(self.bytes_t, o.bytes_sval + b.len() as u64 + 1, None, false);
        self.w64(a + 16, b.len() as u64);
        self.bytes(a + o.bytes_sval, b);
        a
    }

    fn int(&mut self, v: u32) -> u64 {
        assert!(v < 1 << 30);
        let o = self.o.clone();
        let a = self.object(self.int_t, o.long_digits + 4, None, false);
        self.w64(a + o.long_tag, if v == 0 { 1 } else { 1 << 3 });
        self.w32(a + o.long_digits, v);
        a
    }

    /// A combined-table keys object holding `items`.
    fn keys(&mut self, items: &[(u64, u64)], unicode: bool) -> u64 {
        let o = self.o.clone();
        let esz = if unicode { 16 } else { 24 };
        let log2 = 3u8;
        let k = self.alloc(o.dk_indices + 8 + 8 * esz);
        self.w64(k + o.dk_refcnt, 1);
        self.w8(k + o.dk_log2_size, log2);
        self.w8(k + o.dk_log2_index_bytes, 3);
        self.w8(k + o.dk_kind, if unicode { 1 } else { 0 });
        self.w64(k + o.dk_usable, 5 - items.len() as u64);
        self.w64(k + o.dk_nentries, items.len() as u64);
        let entries = k + o.dk_indices + 8;
        for (i, &(key, val)) in items.iter().enumerate() {
            let e = entries + i as u64 * esz;
            self.w8(k + o.dk_indices + i as u64, i as u8);
            if unicode {
                self.w64(e, key);
                self.w64(e + 8, val);
            } else {
                self.w64(e, 42);
                self.w64(e + 8, key);
                self.w64(e + 16, val);
            }
        }
        k
    }

    fn dict(&mut self, items: &[(u64, u64)], unicode: bool, gc: bool) -> u64 {
        let o = self.o.clone();
        let d = self.object(self.dict_t, 48, gc.then_some(0), false);
        let k = self.keys(items, unicode);
        self.w64(d + o.ma_used, items.len() as u64);
        self.w64(d + o.ma_keys, k);
        d
    }

    fn str_dict(&mut self, items: &[(&str, u64)]) -> u64 {
        let it: Vec<(u64, u64)> = items.iter().map(|&(k, v)| (self.str(k), v)).collect();
        self.dict(&it, true, true)
    }

    fn tuple(&mut self, items: &[u64]) -> u64 {
        let o = self.o.clone();
        let t = self.object(
            self.tuple_t,
            o.tuple_ob_item + 8 * items.len() as u64,
            Some(0),
            false,
        );
        self.w64(t + 16, items.len() as u64);
        for (i, &x) in items.iter().enumerate() {
            self.w64(t + o.tuple_ob_item + 8 * i as u64, x);
        }
        t
    }

    fn list(&mut self, items: &[u64]) -> u64 {
        let o = self.o.clone();
        let l = self.object(self.list_t, 40, Some(1), false);
        let arr = self.alloc(8 * items.len() as u64 + 8);
        for (i, &x) in items.iter().enumerate() {
            self.w64(arr + 8 * i as u64, x);
        }
        self.w64(l + 16, items.len() as u64);
        self.w64(l + o.list_ob_item, arr);
        self.w64(l + o.list_allocated, items.len() as u64);
        l
    }

    fn module(&mut self, name: &str, dict: u64) -> u64 {
        let o = self.o.clone();
        let m = self.object(self.module_t, 72, Some(2), false);
        self.w64(m + o.md_dict, dict);
        let n = self.str(name);
        self.w64(m + o.md_name, n);
        m
    }

    /// A heap type `module.name` whose instances keep `attrs` in managed /
    /// inline values. Returns the type address.
    fn heap_type(&mut self, module: &str, name: &str, attrs: &[&str]) -> u64 {
        let o = self.o.clone();
        let mut flags = TPFLAGS_HEAPTYPE | TPFLAGS_HAVE_GC | TPFLAGS_MANAGED_DICT;
        if o.minor >= 13 {
            flags |= TPFLAGS_INLINE_VALUES;
        }
        let t = self.object(self.type_type, 936, Some(2), false);
        let n = self.cstr(name);
        self.w64(t + o.tp_name, n);
        self.w64(t + o.tp_basicsize, 16);
        self.w64(t + o.tp_flags, flags);
        let q = self.str(name);
        self.w64(t + o.ht_qualname, q);
        self.w64(t + o.ht_name, q);
        let m = self.str(module);
        let tdict = self.str_dict(&[("__module__", m)]);
        self.w64(t + o.tp_dict, tdict);
        let names: Vec<(u64, u64)> = attrs.iter().map(|a| (self.str(a), 0)).collect();
        let k = self.keys(&names, true);
        self.w64(k + o.dk_refcnt, 2); // shared
        self.w64(t + o.ht_cached_keys, k);
        t
    }

    /// An instance of heap type `t` with attribute values `vals` (in the
    /// order of the type's shared keys).
    fn instance(&mut self, t: u64, vals: &[u64]) -> u64 {
        let o = self.o.clone();
        let inline = 8 + 8 * vals.len() as u64;
        let a = self.object(
            t,
            16 + if o.minor >= 13 { inline } else { 0 },
            Some(0),
            true,
        );
        if o.minor == 12 {
            let values = self.alloc(8 * vals.len() as u64 + 8);
            for (i, &v) in vals.iter().enumerate() {
                self.w64(values + 8 * i as u64, v);
            }
            self.w64(a - 24, values - 1);
        } else {
            let values = a + 16;
            self.w8(values, vals.len() as u8); // capacity
            self.w8(values + 1, vals.len() as u8); // size
            self.w8(values + 2, 1); // embedded
            self.w8(values + 3, 1); // valid
            for (i, &v) in vals.iter().enumerate() {
                self.w64(values + o.dv_values + 8 * i as u64, v);
            }
        }
        a
    }

    fn code(&mut self, file: &str, qualname: &str, line: u32, locals: &[&str]) -> u64 {
        let o = self.o.clone();
        let c = self.object(self.code_t, 200, None, false);
        let names: Vec<u64> = locals.iter().map(|n| self.str(n)).collect();
        let t = self.tuple(&names);
        self.w64(c + o.co_localsplusnames, t);
        self.w32(c + o.co_nlocalsplus, locals.len() as u32);
        self.w32(
            c + o.co_framesize,
            (o.if_localsplus / 8) as u32 + locals.len() as u32,
        );
        let f = self.str(file);
        self.w64(c + o.co_filename, f);
        let q = self.str(qualname);
        self.w64(c + o.co_qualname, q);
        self.w64(c + o.co_name, q);
        self.w32(c + o.co_firstlineno, line);
        c
    }

    fn function(&mut self, code: u64, globals: u64, module: &str, closure: u64) -> u64 {
        let o = self.o.clone();
        let f = self.object(self.func_t, 160, Some(1), false);
        self.w64(f + o.func_code, code);
        self.w64(f + o.func_globals, globals);
        let m = self.str(module);
        self.w64(f + o.func_module, m);
        let q = self.r64(code + o.co_qualname);
        self.w64(f + o.func_qualname, q);
        self.w64(f + o.func_closure, closure);
        f
    }

    fn cell(&mut self, contents: u64) -> u64 {
        let o = self.o.clone();
        let c = self.object(self.cell_t, 24, Some(1), false);
        self.w64(c + o.cell_ref, contents);
        c
    }

    /// A thread with one Python frame running `func` with local values.
    fn thread(&mut self, tid: u64, func: u64, code: u64, globals: u64, locals: &[u64]) {
        let o = self.o.clone();
        let ts = self.alloc(512);
        self.w64(self.interp + o.is_threads_head, ts);
        self.w64(ts + o.ts_native_thread_id, tid);
        let fr = self.alloc(o.if_localsplus + 8 * locals.len() as u64 + 64);
        if o.ts_frame_via_cframe {
            let cf = self.alloc(32);
            self.w64(ts + o.ts_current_frame, cf);
            self.w64(cf, fr);
        } else {
            self.w64(ts + o.ts_current_frame, fr);
        }
        self.w64(fr + o.if_executable, code);
        self.w64(fr + o.if_funcobj, func);
        self.w64(fr + o.if_globals, globals);
        self.w64(fr + o.if_locals, 0);
        self.w8(fr + o.if_owner, 0);
        for (i, &v) in locals.iter().enumerate() {
            self.w64(fr + o.if_localsplus + 8 * i as u64, v);
        }
        if o.if_stack_is_pointer {
            self.w64(
                fr + o.if_stack,
                fr + o.if_localsplus + 8 * locals.len() as u64,
            );
        } else {
            self.w32(fr + o.if_stack, locals.len() as u32);
        }
    }

    fn image(&self) -> MemImage {
        let mut m = MemImage::new(TargetInfo::LINUX_X86_64);
        m.map(BASE, self.mem.clone());
        m
    }

    fn runtime_location(&self) -> RuntimeLocation {
        RuntimeLocation {
            module: Module {
                name: "libpython3.so".into(),
                path: "/x/libpython3.so".into(),
                base: 0,
                size: 0,
                build_id: None,
            },
            runtime_addr: self.runtime,
            version: PythonVersion::new(3, self.o.minor, 0),
            free_threaded: false,
            debug_build: false,
        }
    }
}

/// Run the walker over `h` and read the snapshot back.
fn walk_heap(h: &Heap, opts: &DumpOptions) -> (Snapshot, WalkStats) {
    let img = h.image();
    let mut w = SnapshotWriter::new(SnapshotInfo::new_for_test()).unwrap();
    let stats = walk(&img, &h.runtime_location(), opts, &mut w).unwrap();
    w.info_mut().truncated = stats.truncated;
    let snap = Snapshot::from_bytes(w.finish_to_vec().unwrap()).unwrap();
    (snap, stats)
}

/// Rendered `(label, target)` pairs of the object at `addr`.
fn edges(s: &Snapshot, addr: u64) -> Vec<(String, u64)> {
    let i = s
        .find_object(addr)
        .unwrap_or_else(|| panic!("no object at {addr:#x}"));
    s.edges(i)
        .map(|e| (s.render_label(e.label).unwrap(), e.target))
        .collect()
}

/// Like [`edges`], leaving out speculative (out-of-line) edges.
fn known_edges(s: &Snapshot, addr: u64) -> Vec<(String, u64)> {
    let i = s.find_object(addr).unwrap();
    s.edges(i)
        .filter(|e| e.origin != EdgeOrigin::Speculative)
        .map(|e| (s.render_label(e.label).unwrap(), e.target))
        .collect()
}

/// Speculative edges of the object at `addr`: `(label, target)`.
fn speculative_edges(s: &Snapshot, addr: u64) -> Vec<(String, u64)> {
    let i = s.find_object(addr).unwrap();
    s.edges(i)
        .filter(|e| e.origin == EdgeOrigin::Speculative)
        .map(|e| (s.render_label(e.label).unwrap(), e.target))
        .collect()
}

fn type_of(s: &Snapshot, addr: u64) -> String {
    let o = s.object(s.find_object(addr).unwrap());
    s.type_name(o.type_id).unwrap()
}

fn roots(s: &Snapshot) -> Vec<(RootKind, u64, String)> {
    s.roots()
        .map(|r| (r.kind, r.addr, s.string(r.label).unwrap().to_string()))
        .collect()
}

/// The scenario from the integration test, in miniature: `app.CACHE` holds
/// two `Session`s, each with a bytes payload, plus a function with a closure
/// and a running frame.
struct App {
    module: u64,
    mdict: u64,
    cache: u64,
    session_t: u64,
    sessions: Vec<u64>,
    payloads: Vec<u64>,
    keys: Vec<u64>,
    func: u64,
    cell: u64,
    code: u64,
    local_list: u64,
    modules: u64,
}

fn build_app(h: &mut Heap) -> App {
    let session_t = h.heap_type("app", "Session", &["payload"]);
    let mut sessions = Vec::new();
    let mut payloads = Vec::new();
    for i in 0..2u8 {
        let p = h.bytes_obj(&[i; 64]);
        sessions.push(h.instance(session_t, &[p]));
        payloads.push(p);
    }
    let keys: Vec<u64> = ["sess-a", "sess-b"].iter().map(|k| h.str(k)).collect();
    let cache = h.dict(
        &[(keys[0], sessions[0]), (keys[1], sessions[1])],
        true,
        true,
    );
    let cache_key = h.str("CACHE");
    let mdict = h.dict(&[(cache_key, cache)], true, true);
    let module = h.module("app", mdict);
    let code = h.code("app/main.py", "run", 7, &["pending", "unset"]);
    let cell_val = h.int(5);
    let cell = h.cell(cell_val);
    let closure = h.tuple(&[cell]);
    let func = h.function(code, mdict, "app", closure);
    let s1 = h.str("x");
    let local_list = h.list(&[s1]);
    h.thread(4021, func, code, mdict, &[local_list, 0]);
    let mod_key = h.str("app");
    let modules = h.dict(&[(mod_key, module)], true, true);
    let o = h.o.clone();
    h.w64(h.interp + o.is_modules, modules);
    App {
        module,
        mdict,
        cache,
        session_t,
        sessions,
        payloads,
        keys,
        func,
        cell,
        code,
        local_list,
        modules,
    }
}

fn check_app(minor: u8) {
    let mut h = Heap::new(minor);
    let app = build_app(&mut h);
    let (s, stats) = walk_heap(&h, &DumpOptions::default());
    assert!(!stats.truncated);
    assert_eq!(stats.read_errors, 0, "{minor}");

    // Module -> __dict__ -> ['CACHE'] -> dict.
    assert_eq!(
        edges(&s, app.module),
        vec![(".__dict__".to_string(), app.mdict)]
    );
    let md = edges(&s, app.mdict);
    assert_eq!(md[1], ("['CACHE']".to_string(), app.cache));
    assert_eq!(md[0].0, "<key ['CACHE']>");

    // Ordinary dict keys are redacted; values keep the edge.
    let c = edges(&s, app.cache);
    assert_eq!(
        c,
        vec![
            ("<key [<str len=6>]>".to_string(), app.keys[0]),
            ("[<str len=6>]".to_string(), app.sessions[0]),
            ("<key [<str len=6>]>".to_string(), app.keys[1]),
            ("[<str len=6>]".to_string(), app.sessions[1]),
        ]
    );
    let i = s.find_object(app.cache).unwrap();
    let e = s.edges(i).next().unwrap();
    assert!(matches!(
        e.label,
        heapspy_snapshot::EdgeLabel::DictKey(KeyLabel::Redacted(_))
    ));
    assert_eq!(s.extras(i).unwrap().length, Some(2));

    // Instances: inline / managed values become attributes, plus ob_type.
    for (sess, p) in app.sessions.iter().zip(&app.payloads) {
        assert_eq!(type_of(&s, *sess), "app.Session");
        assert_eq!(
            edges(&s, *sess),
            vec![
                (".payload".to_string(), *p),
                (".__class__".to_string(), app.session_t)
            ]
        );
        let o = s.object(s.find_object(*sess).unwrap());
        assert!(o.flags.contains(ObjectFlags::GC_TRACKED));
        // Untracked leaf: sized like sys.getsizeof (33 + 64), no GC flag.
        let po = s.object(s.find_object(*p).unwrap());
        assert_eq!(po.shallow_size, 33 + 64);
        assert!(!po.flags.contains(ObjectFlags::GC_TRACKED));
        assert_eq!(po.edge_count, 0);
        assert_eq!(s.extras(po.index).unwrap().length, Some(64));
        assert_eq!(s.extras(po.index).unwrap().content, None);
    }
    // The heap type is a type object with its dict and qualname.
    let ti = s.find_object(app.session_t).unwrap();
    assert!(s.object(ti).flags.contains(ObjectFlags::IS_TYPE));
    let te = edges(&s, app.session_t);
    assert_eq!(te[0].0, ".__dict__");
    let tdict = te[0].1;
    assert_eq!(edges(&s, tdict)[1].0, "['__module__']");

    // Functions: closure cells, globals, code; cell contents.
    let fe = edges(&s, app.func);
    assert!(fe.contains(&(".__globals__".to_string(), app.mdict)));
    assert!(fe.contains(&(".__code__".to_string(), app.code)));
    assert!(fe.contains(&(".__closure__[0]".to_string(), app.cell)));
    let fx = s.extras(s.find_object(app.func).unwrap()).unwrap();
    assert_eq!(s.string(fx.qualname.unwrap()).unwrap(), "run");
    assert_eq!(s.string(fx.source_loc.unwrap()).unwrap(), "app/main.py:7");
    assert_eq!(edges(&s, app.cell)[0].0, ".cell_contents");
    let cx = s.extras(s.find_object(app.code).unwrap()).unwrap();
    assert_eq!(s.string(cx.source_loc.unwrap()).unwrap(), "app/main.py:7");

    // Lists and tuples.
    assert_eq!(edges(&s, app.local_list)[0].0, "[0]");

    // Roots.
    let r = roots(&s);
    assert!(r.contains(&(
        RootKind::ModuleDict,
        app.module,
        "sys.modules['app']".into()
    )));
    assert!(r.contains(&(
        RootKind::FrameLocal,
        app.local_list,
        "frame app:run local 'pending'".into()
    )));
    assert!(r.contains(&(RootKind::Interp, app.modules, "interp sys.modules".into())));
    // A null local slot is not a root.
    assert!(!r.iter().any(|x| x.2.contains("'unset'")));
}

#[test]
fn app_graph_312() {
    check_app(12);
}

#[test]
fn app_graph_313() {
    check_app(13);
}

#[test]
fn app_graph_314() {
    check_app(14);
}

#[test]
fn capture_contents_stores_key_reprs_and_text() {
    let mut h = Heap::new(12);
    let app = build_app(&mut h);
    let opts = DumpOptions {
        capture_contents: true,
        max_str: 8,
        ..DumpOptions::default()
    };
    let (s, _) = walk_heap(&h, &opts);
    let c = edges(&s, app.cache);
    assert_eq!(c[1].0, "['sess-a']");
    let k = s.extras(s.find_object(app.keys[0]).unwrap()).unwrap();
    assert_eq!(s.string(k.content.unwrap()).unwrap(), "sess-a");
    assert!(!k.content_truncated);
    let p = s.extras(s.find_object(app.payloads[0]).unwrap()).unwrap();
    assert_eq!(s.string(p.content.unwrap()).unwrap(), "b'\\x00\\x...");
    assert!(p.content_truncated);
}

#[test]
fn ordinary_dict_with_int_keys_is_redacted_without_length() {
    let mut h = Heap::new(13);
    let k = h.int(3);
    let v = h.str("v");
    let d = h.dict(&[(k, v)], false, true);
    let (s, _) = walk_heap(&h, &DumpOptions::default());
    assert_eq!(edges(&s, d)[1], ("[<int>]".to_string(), v));
    let opts = DumpOptions {
        capture_contents: true,
        ..DumpOptions::default()
    };
    let (s, _) = walk_heap(&h, &opts);
    assert_eq!(edges(&s, d)[1], ("[3]".to_string(), v));
}

#[test]
fn bad_pointer_marks_partial_and_counts() {
    let mut h = Heap::new(12);
    let l = h.list(&[]);
    let o = h.o.clone();
    // ob_item points nowhere.
    h.w64(l + 16, 3);
    h.w64(l + o.list_ob_item, 0xdead_0000);
    let (s, stats) = walk_heap(&h, &DumpOptions::default());
    let ob = s.object(s.find_object(l).unwrap());
    assert!(ob.flags.contains(ObjectFlags::PARTIAL));
    assert_eq!(ob.edge_count, 0);
    assert!(stats.read_errors >= 1);
    assert!(!stats.truncated);
}

#[test]
fn dangling_edge_target_is_not_emitted() {
    let mut h = Heap::new(14);
    let t = h.tuple(&[0x7777_0000]);
    let (s, stats) = walk_heap(&h, &DumpOptions::default());
    assert_eq!(edges(&s, t), vec![("[0]".to_string(), 0x7777_0000)]);
    assert!(s.find_object(0x7777_0000).is_none());
    assert!(!stats.truncated);
}

#[test]
fn corrupt_gc_list_truncates_instead_of_hanging() {
    // A list whose tail points back into itself, not at the head.
    let mut h = Heap::new(12);
    let a = h.tuple(&[]);
    let b = h.tuple(&[]);
    h.w64(b - 16, a - 16);
    let (s, stats) = walk_heap(&h, &DumpOptions::default());
    assert!(stats.truncated);
    assert!(s.find_object(a).is_some() && s.find_object(b).is_some());

    // A next pointer into unmapped memory.
    let mut h = Heap::new(13);
    let a = h.tuple(&[]);
    h.w64(a - 16, 0x50);
    let (_, stats) = walk_heap(&h, &DumpOptions::default());
    assert!(stats.truncated);
}

#[test]
fn permanent_generation_is_walked() {
    for minor in [12, 13, 14] {
        let mut h = Heap::new(minor);
        let l = h.list(&[]);
        // Move it from generation 1 to the permanent generation.
        let gens = h.gens;
        for head in gens {
            h.w64(head, head);
            h.w64(head + 8, head);
        }
        h.link(l, gens[3]);
        let (s, _) = walk_heap(&h, &DumpOptions::default());
        let o = s.object(s.find_object(l).unwrap());
        assert!(o.flags.contains(ObjectFlags::GC_TRACKED), "{minor}");
    }
}

#[test]
fn untracked_dict_reached_from_tracked_object_is_walked() {
    let mut h = Heap::new(12);
    let v = h.str("leaf");
    let k = h.str("k");
    let d = h.dict(&[(k, v)], true, false);
    let l = h.list(&[d]);
    let (s, _) = walk_heap(&h, &DumpOptions::default());
    let di = s.find_object(d).unwrap();
    assert!(!s.object(di).flags.contains(ObjectFlags::GC_TRACKED));
    assert_eq!(edges(&s, d)[1], ("[<str len=1>]".to_string(), v));
    assert!(s.find_object(v).is_some());
    assert_eq!(edges(&s, l)[0].1, d);
}

/// An extension type the walker has no layout for: GC-tracked, 56 bytes,
/// with `tp_members` naming the field at offset 16.
fn holder_type(h: &mut Heap, name: &str) -> u64 {
    let t = h.static_type(name, TPFLAGS_HAVE_GC, 56, 0);
    let defs = h.alloc(2 * MEMBERDEF_SIZE);
    let n = h.cstr("payload");
    h.w64(defs, n);
    h.w32(defs + MEMBERDEF_TYPE, T_OBJECT_EX);
    h.w64(defs + MEMBERDEF_OFFSET, 16);
    let tp_members = h.o.tp_base - 16;
    h.w64(t + tp_members, defs);
    t
}

#[test]
fn unknown_c_type_fields_are_scanned_for_references() {
    for minor in [12, 13, 14] {
        let mut h = Heap::new(minor);
        let t = holder_type(&mut h, "_ext.Holder");
        let owned = h.list(&[]);
        let leaf = h.str("leaf");
        let x = h.object(t, 56, Some(0), false);
        h.w64(x + 16, owned); // named by tp_members
        h.w64(x + 24, 0x1234_5679); // not a pointer
        h.w64(x + 32, leaf); // untracked object, unnamed field
        h.w64(x + 40, owned + 8); // points inside an object
        h.w64(x + 48, BASE + 0x40); // aligned, but no object there
        let (s, _) = walk_heap(&h, &DumpOptions::default());
        // The last two are heap pointers that are not objects, so they are
        // searched out of line; whatever that finds is speculative and is
        // the analyzer's to keep or drop.
        assert_eq!(
            known_edges(&s, x),
            vec![(".payload".to_string(), owned), ("<+32>".to_string(), leaf)],
            "3.{minor}"
        );
        let i = s.find_object(x).unwrap();
        assert!(
            s.edges(i)
                .any(|e| e.target == leaf && e.origin == EdgeOrigin::Scanned),
            "3.{minor}"
        );
        assert!(s.find_object(leaf).is_some(), "3.{minor}");
    }
}

#[test]
fn out_of_line_block_items_are_speculative_edges() {
    // A deque-like container: its body points at a separately allocated
    // block (not an object) holding a link and two items.
    let mut h = Heap::new(12);
    let t = holder_type(&mut h, "_ext.Chain");
    let a = h.list(&[]);
    let b = h.str("item");
    let block = h.alloc(8 * 4);
    h.w64(block, 0); // link to the next block: none
    h.w64(block + 8, a);
    h.w64(block + 16, b);
    h.w64(block + 24, a); // the same item twice: one edge
    let x = h.object(t, 56, Some(0), false);
    h.w64(x + 24, block);
    let (s, _) = walk_heap(&h, &DumpOptions::default());
    let spec = speculative_edges(&s, x);
    assert!(spec.contains(&("<+24[1]>".to_string(), a)), "{spec:?}");
    assert!(spec.contains(&("<+24[2]>".to_string(), b)), "{spec:?}");
    assert_eq!(spec.iter().filter(|e| e.1 == a).count(), 1, "{spec:?}");
    // The untracked item was reached only out of line and is recorded.
    assert!(s.find_object(b).is_some());
}

#[test]
fn chained_blocks_are_followed_and_foreign_memory_is_not() {
    // A deque-like chain: block1 <-> block2, both linked both ways, and a
    // pointer from block2 into an unrelated block that does not link back.
    let mut h = Heap::new(12);
    let t = holder_type(&mut h, "_ext.Chain");
    let near = h.str("near");
    let far = h.str("far");
    let foreign_item = h.str("not mine");
    let foreign = h.alloc(8 * 4);
    h.w64(foreign + 8, foreign_item);
    let block1 = h.alloc(8 * 4);
    let block2 = h.alloc(8 * 4);
    h.w64(block1, block2); // link to the next block
    h.w64(block1 + 8, near);
    h.w64(block2, block1); // link back
    h.w64(block2 + 8, far);
    h.w64(block2 + 16, foreign); // a heap pointer, but not a chain link
    let x = h.object(t, 56, Some(0), false);
    h.w64(x + 24, block1);
    let (s, _) = walk_heap(&h, &DumpOptions::default());
    let spec: Vec<u64> = speculative_edges(&s, x).into_iter().map(|e| e.1).collect();
    assert!(spec.contains(&near), "{spec:?}");
    assert!(spec.contains(&far), "{spec:?}");
    assert!(!spec.contains(&foreign_item), "{spec:?}");
}

#[test]
fn a_block_first_reached_from_the_wrong_neighbour_is_still_followed() {
    // block1 -> block2 -> block3. block1's window runs on past its end into
    // block2's memory, so it sees block2's link to block3 before block2 is
    // read. block3 rejects that (it links back to block2, not block1) and
    // must still be accepted when block2 itself gets to it.
    let mut h = Heap::new(12);
    let t = holder_type(&mut h, "_ext.Chain");
    let last = h.str("last");
    let block1 = h.alloc(8 * 2);
    let block2 = h.alloc(8 * 2);
    let block3 = h.alloc(8 * 2);
    h.w64(block1, 0);
    h.w64(block1 + 8, block2);
    h.w64(block2, block1);
    h.w64(block2 + 8, block3);
    h.w64(block3, block2);
    h.w64(block3 + 8, last);
    let x = h.object(t, 56, Some(0), false);
    h.w64(x + 24, block1);
    let (s, _) = walk_heap(&h, &DumpOptions::default());
    let spec: Vec<u64> = speculative_edges(&s, x).into_iter().map(|e| e.1).collect();
    assert!(spec.contains(&last), "{spec:?}");
}

#[test]
fn freed_object_is_not_taken_for_a_live_one() {
    // pymalloc reuses the refcount word of a freed block for its free list
    // and leaves the type pointer alone. Such a block must not become an
    // object, or a stale pointer to it an edge.
    let mut h = Heap::new(12);
    let t = holder_type(&mut h, "_ext.Holder");
    let freed = h.str("gone");
    h.w64(freed, 0); // end of the free list
    let reused = h.str("gone too");
    h.w64(reused, freed); // a free-list link
    let x = h.object(t, 56, Some(0), false);
    h.w64(x + 16, freed);
    h.w64(x + 24, reused);
    let (s, _) = walk_heap(&h, &DumpOptions::default());
    assert!(known_edges(&s, x).is_empty(), "{:?}", known_edges(&s, x));
    assert!(s.find_object(freed).is_none());
    assert!(s.find_object(reused).is_none());
}

#[test]
fn weak_references_are_not_scanned() {
    let mut h = Heap::new(12);
    let t = h.static_type("weakref.ReferenceType", TPFLAGS_HAVE_GC, 48, 0);
    let target = h.list(&[]);
    let wr = h.object(t, 48, Some(0), false);
    h.w64(wr + 16, target); // wr_object: borrowed, must not retain
    let (s, _) = walk_heap(&h, &DumpOptions::default());
    assert!(edges(&s, wr).is_empty());
}

#[test]
fn scanned_fields_do_not_repeat_known_edges() {
    // Two fields pointing at the same object: one edge, under the name the
    // first field has.
    let mut h = Heap::new(12);
    let t = holder_type(&mut h, "_ext.Holder");
    let owned = h.list(&[]);
    let x = h.object(t, 56, Some(0), false);
    h.w64(x + 16, owned);
    h.w64(x + 24, owned);
    let (s, _) = walk_heap(&h, &DumpOptions::default());
    assert_eq!(edges(&s, x), vec![(".payload".to_string(), owned)]);
}

#[test]
fn materialized_instance_dict_keeps_identifier_keys() {
    let mut h = Heap::new(12);
    let t = h.heap_type("app", "Session", &[]);
    let inst = h.instance(t, &[]);
    let v = h.int(1);
    let k = h.str("user_id");
    let d = h.dict(&[(k, v)], true, true);
    h.w64(inst - 24, d); // 3.12: a dict pointer (untagged)
    let (s, _) = walk_heap(&h, &DumpOptions::default());
    assert_eq!(edges(&s, inst)[0], (".__dict__".to_string(), d));
    assert_eq!(edges(&s, d)[1], ("['user_id']".to_string(), v));
}

#[test]
fn debug_offsets_override_the_table() {
    // Move `interpreters.head` in the fake runtime, and say so in the debug
    // offsets. The walk only finds the heap if the override is applied.
    let mut h = Heap::new(13);
    let app = build_app(&mut h);
    let o = h.o.clone();
    let rt = h.runtime;
    h.w64(rt + o.rt_interpreters_head, 0);
    let mut moved = o.clone();
    moved.rt_interpreters_head = 600;
    for (slot, v) in moved.debug_image(0x030d_00f0) {
        h.w64(rt + slot, v);
    }
    h.w64(rt + 600, h.interp);
    let img = h.image();
    let mut ofs = Offsets::table(13, heapspy_snapshot::Os::Linux).unwrap();
    assert!(!ofs.apply_debug_offsets(&img, rt).unwrap());
    assert_eq!(ofs.rt_interpreters_head, 600);
    let (s, _) = walk_heap(&h, &DumpOptions::default());
    assert!(s.find_object(app.module).is_some());

    // Free-threaded per the debug offsets: refused.
    h.w64(rt + 16, 1);
    let img = h.image();
    let mut w = SnapshotWriter::new(SnapshotInfo::new_for_test()).unwrap();
    let err = walk(&img, &h.runtime_location(), &DumpOptions::default(), &mut w).unwrap_err();
    assert!(matches!(err, Error::UnsupportedPython(_)), "{err}");
}

#[test]
fn unsupported_runtimes_are_refused() {
    let h = Heap::new(12);
    let img = h.image();
    let mut rt = h.runtime_location();
    for (v, ft, dbg) in [
        (11, false, false),
        (15, false, false),
        (12, true, false),
        (12, false, true),
    ] {
        rt.version = PythonVersion::new(3, v, 0);
        rt.free_threaded = ft;
        rt.debug_build = dbg;
        let mut w = SnapshotWriter::new(SnapshotInfo::new_for_test()).unwrap();
        let err = walk(&img, &rt, &DumpOptions::default(), &mut w).unwrap_err();
        assert!(matches!(err, Error::UnsupportedPython(_)), "{err}");
    }
}

#[test]
fn locate_runtime_needs_a_python_module() {
    let img = MemImage::new(TargetInfo::LINUX_X86_64);
    assert!(matches!(locate_runtime(&img), Err(Error::NotPython(_))));
}

#[test]
fn name_flags_and_version_hex() {
    assert_eq!(name_flags("libpython3.13t.so.1.0"), (true, false));
    assert_eq!(name_flags("libpython3.12d.so"), (false, true));
    assert_eq!(name_flags("libpython3.12.so.1.0"), (false, false));
    assert_eq!(name_flags("python313t_d.dll"), (true, true));
    assert_eq!(name_flags("python3.14"), (false, false));
    let v = version_from_hex(0x030d_02f0);
    assert_eq!((v.major, v.minor, v.micro), (3, 13, 2));
    assert_eq!(v.release_level, PythonVersion::LEVEL_FINAL);
    let v = version_from_hex(0x030e_00a3);
    assert_eq!(v.to_string(), "3.14.0a3");
}
