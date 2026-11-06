//! Per-version struct layouts for the CPython default (GIL) build on 64-bit
//! targets.
//!
//! The tables were generated with `offsetof` / `sizeof` against the internal
//! headers of each interpreter (3.12.3, 3.13.18, 3.14.6, x86_64 Linux) and are
//! stable across micro releases of a minor version. `docs/cpython-internals.md`
//! lists them with the C declarations they come from.
//!
//! Windows x64 (LLP64) differs from Linux (LP64) only where C `long` is used.
//! In the fields used here that is `PyThreadState.thread_id` /
//! `native_thread_id` (`unsigned long`). `tp_flags` is also `unsigned long`,
//! but the next field is a pointer, so its offset does not move. On 3.13+ the
//! target's own `_Py_DebugOffsets` (written by the target's compiler) overrides
//! the runtime, interpreter, thread, frame and code offsets, so the table only
//! matters for 3.12 there.

use heapspy_snapshot::Os;

use crate::error::{Error, Result};
use crate::source::{MemorySource, MemorySourceExt};

/// `_Py_DebugOffsets.cookie`.
pub const DEBUG_COOKIE: &[u8; 8] = b"xdebugpy";

/// Field offsets the walker reads. All values are byte offsets from the start
/// of the named struct unless the name says `size`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offsets {
    pub minor: u8,

    // PyTypeObject / PyHeapTypeObject
    pub tp_name: u64,
    pub tp_basicsize: u64,
    pub tp_itemsize: u64,
    pub tp_flags: u64,
    pub tp_base: u64,
    pub tp_dict: u64,
    pub tp_bases: u64,
    pub tp_mro: u64,
    pub tp_dictoffset: u64,
    pub ht_name: u64,
    pub ht_slots: u64,
    pub ht_qualname: u64,
    pub ht_cached_keys: u64,
    pub ht_module: u64,

    // dict
    pub ma_used: u64,
    pub ma_keys: u64,
    pub ma_values: u64,
    pub dk_refcnt: u64,
    pub dk_log2_size: u64,
    pub dk_log2_index_bytes: u64,
    pub dk_kind: u64,
    pub dk_usable: u64,
    pub dk_nentries: u64,
    pub dk_indices: u64,
    pub dict_keys_size: u64,
    /// `offsetof(PyDictValues, values)`: 0 on 3.12, 8 on 3.13+ (where the
    /// struct starts with `capacity`, `size`, `embedded`, `valid`).
    pub dv_values: u64,
    pub dv_has_header: bool,

    // sequences and scalars
    pub list_ob_item: u64,
    pub list_allocated: u64,
    pub tuple_ob_item: u64,
    pub ascii_size: u64,
    pub compact_size: u64,
    pub str_length: u64,
    pub str_state: u64,
    pub str_utf8_length: u64,
    pub str_utf8: u64,
    pub bytes_sval: u64,
    pub bytearray_alloc: u64,
    pub bytearray_bytes: u64,
    pub bytearray_start: u64,
    pub long_tag: u64,
    pub long_digits: u64,
    pub float_val: u64,
    pub set_used: u64,
    pub set_mask: u64,
    pub set_table: u64,
    pub set_smalltable: u64,

    // module, function, cell, method, code
    pub md_dict: u64,
    pub md_name: u64,
    pub func_globals: u64,
    pub func_builtins: u64,
    pub func_name: u64,
    pub func_qualname: u64,
    pub func_code: u64,
    pub func_defaults: u64,
    pub func_kwdefaults: u64,
    pub func_closure: u64,
    pub func_doc: u64,
    pub func_dict: u64,
    pub func_module: u64,
    pub func_annotations: u64,
    pub func_annotate: Option<u64>,
    pub func_typeparams: u64,
    pub cell_ref: u64,
    pub im_func: u64,
    pub im_self: u64,
    pub cfunc_self: u64,
    pub cfunc_module: u64,
    pub co_consts: u64,
    pub co_names: u64,
    pub co_exceptiontable: u64,
    pub co_firstlineno: u64,
    pub co_nlocalsplus: u64,
    pub co_localsplusnames: u64,
    pub co_localspluskinds: u64,
    pub co_filename: u64,
    pub co_name: u64,
    pub co_qualname: u64,
    pub co_linetable: u64,
    /// `offsetof(PyCodeObject, co_code_adaptive)`: where the bytecode starts
    /// (`_PyCode_CODE(co)`). Also `type(code).__basicsize__`.
    pub co_code_adaptive: u64,
    /// `int co_framesize`: frame slots (specials + locals + stack), in words.
    pub co_framesize: u64,

    // generators and frames
    pub gi_name: u64,
    pub gi_qualname: u64,
    pub gi_frame_state: u64,
    pub gi_iframe: u64,
    pub frameobj_back: u64,
    pub frameobj_frame: u64,
    /// `offsetof(PyFrameObject, _f_frame_data)`.
    pub frameobj_data: u64,
    pub if_executable: u64,
    pub if_previous: u64,
    pub if_funcobj: u64,
    pub if_globals: u64,
    pub if_builtins: u64,
    pub if_locals: u64,
    /// The executing instruction: `_Py_CODEUNIT *prev_instr` on 3.12,
    /// `instr_ptr` on 3.13+. Its distance from `_PyCode_CODE(code)` is the
    /// frame's `f_lasti` in bytes on every version.
    pub if_instr_ptr: u64,
    /// 3.12 / 3.13: `int stacktop` (an index into `localsplus`).
    /// 3.14: `_PyStackRef *stackpointer`.
    pub if_stack: u64,
    pub if_stack_is_pointer: bool,
    pub if_owner: u64,
    pub if_localsplus: u64,
    /// Frame `owner` values at or above this are shim / interpreter-owned
    /// frames with no Python code.
    pub owner_first_shim: u8,
    /// Frame slots are `_PyStackRef` (3.14): tagged, mask the low bits.
    pub stackrefs: bool,

    // runtime / interpreter / thread
    pub rt_interpreters_head: u64,
    pub is_next: u64,
    pub is_threads_head: u64,
    pub is_gc: u64,
    pub is_modules: u64,
    pub is_sysdict: u64,
    pub is_builtins: u64,
    /// Offsets of the generation list heads inside `struct _gc_runtime_state`,
    /// the permanent generation last.
    pub gc_lists: [u64; 4],
    pub ts_next: u64,
    pub ts_dict: u64,
    pub ts_current_exception: u64,
    pub ts_native_thread_id: u64,
    /// 3.12: offset of `cframe` (then `_PyCFrame.current_frame` at 0).
    /// 3.13+: offset of `current_frame`.
    pub ts_current_frame: u64,
    pub ts_frame_via_cframe: bool,
}

/// Layout of `_Py_DebugOffsets` fields we read, by minor version. Offsets are
/// into the debug-offsets struct, which is all `uint64_t`, so they are the same
/// on every OS.
struct DebugLayout {
    free_threaded: u64,
    interpreters_head: u64,
    is_next: u64,
    is_threads_head: u64,
    is_gc: u64,
    is_modules: u64,
    is_sysdict: u64,
    is_builtins: u64,
    ts_next: u64,
    ts_current_frame: u64,
    ts_native_thread_id: u64,
    if_previous: u64,
    if_executable: u64,
    if_instr_ptr: u64,
    if_localsplus: u64,
    if_owner: u64,
    co_filename: u64,
    co_name: u64,
    co_qualname: u64,
    co_linetable: u64,
    co_firstlineno: u64,
    co_localsplusnames: u64,
    co_code_adaptive: u64,
    tp_name: u64,
    tp_flags: u64,
    ma_keys: u64,
    ma_values: u64,
    str_state: u64,
    str_length: u64,
}

const DEBUG_313: DebugLayout = DebugLayout {
    free_threaded: 16,
    interpreters_head: 40,
    is_next: 64,
    is_threads_head: 72,
    is_gc: 80,
    is_modules: 88,
    is_sysdict: 96,
    is_builtins: 104,
    ts_next: 168,
    ts_current_frame: 184,
    ts_native_thread_id: 200,
    if_previous: 232,
    if_executable: 240,
    if_instr_ptr: 248,
    if_localsplus: 256,
    if_owner: 264,
    co_filename: 280,
    co_name: 288,
    co_qualname: 296,
    co_linetable: 304,
    co_firstlineno: 312,
    co_localsplusnames: 328,
    co_code_adaptive: 344,
    tp_name: 376,
    tp_flags: 392,
    ma_keys: 456,
    ma_values: 464,
    str_state: 544,
    str_length: 552,
};

const DEBUG_314: DebugLayout = DebugLayout {
    free_threaded: 16,
    interpreters_head: 40,
    is_next: 64,
    is_threads_head: 72,
    is_gc: 88,
    is_modules: 96,
    is_sysdict: 104,
    is_builtins: 112,
    ts_next: 192,
    ts_current_frame: 208,
    ts_native_thread_id: 224,
    if_previous: 256,
    if_executable: 264,
    if_instr_ptr: 272,
    if_localsplus: 280,
    if_owner: 288,
    co_filename: 320,
    co_name: 328,
    co_qualname: 336,
    co_linetable: 344,
    co_firstlineno: 352,
    co_localsplusnames: 368,
    co_code_adaptive: 384,
    tp_name: 424,
    tp_flags: 440,
    ma_keys: 536,
    ma_values: 544,
    str_state: 624,
    str_length: 632,
};

impl Offsets {
    /// The shipped table for `3.<minor>` on `os`, or `None` if unsupported.
    pub fn table(minor: u8, os: Os) -> Option<Offsets> {
        let mut o = match minor {
            12 => Self::v312(),
            13 => Self::v313(),
            14 => Self::v314(),
            _ => return None,
        };
        if os == Os::Windows && minor == 12 {
            // `unsigned long thread_id; unsigned long native_thread_id;` are
            // 4 bytes each under LLP64.
            o.ts_native_thread_id -= 4;
        }
        Some(o)
    }

    fn v312() -> Offsets {
        Offsets {
            minor: 12,
            tp_name: 24,
            tp_basicsize: 32,
            tp_itemsize: 40,
            tp_flags: 168,
            tp_base: 256,
            tp_dict: 264,
            tp_bases: 336,
            tp_mro: 344,
            tp_dictoffset: 288,
            ht_name: 856,
            ht_slots: 864,
            ht_qualname: 872,
            ht_cached_keys: 880,
            ht_module: 888,
            ma_used: 16,
            ma_keys: 32,
            ma_values: 40,
            dk_refcnt: 0,
            dk_log2_size: 8,
            dk_log2_index_bytes: 9,
            dk_kind: 10,
            dk_usable: 16,
            dk_nentries: 24,
            dk_indices: 32,
            dict_keys_size: 32,
            dv_values: 0,
            dv_has_header: false,
            list_ob_item: 24,
            list_allocated: 32,
            tuple_ob_item: 24,
            ascii_size: 40,
            compact_size: 56,
            str_length: 16,
            str_state: 32,
            str_utf8_length: 40,
            str_utf8: 48,
            bytes_sval: 32,
            bytearray_alloc: 24,
            bytearray_bytes: 32,
            bytearray_start: 40,
            long_tag: 16,
            long_digits: 24,
            float_val: 16,
            set_used: 24,
            set_mask: 32,
            set_table: 40,
            set_smalltable: 64,
            md_dict: 16,
            md_name: 48,
            func_globals: 16,
            func_builtins: 24,
            func_name: 32,
            func_qualname: 40,
            func_code: 48,
            func_defaults: 56,
            func_kwdefaults: 64,
            func_closure: 72,
            func_doc: 80,
            func_dict: 88,
            func_module: 104,
            func_annotations: 112,
            func_annotate: None,
            func_typeparams: 120,
            cell_ref: 16,
            im_func: 16,
            im_self: 24,
            cfunc_self: 24,
            cfunc_module: 32,
            co_consts: 24,
            co_names: 32,
            co_exceptiontable: 40,
            co_firstlineno: 68,
            co_nlocalsplus: 72,
            co_localsplusnames: 96,
            co_localspluskinds: 104,
            co_filename: 112,
            co_name: 120,
            co_qualname: 128,
            co_linetable: 136,
            co_code_adaptive: 192,
            co_framesize: 76,
            gi_name: 24,
            gi_qualname: 32,
            gi_frame_state: 67,
            gi_iframe: 72,
            frameobj_back: 16,
            frameobj_frame: 24,
            frameobj_data: 48,
            if_executable: 0,
            if_previous: 8,
            if_funcobj: 16,
            if_globals: 24,
            if_builtins: 32,
            if_locals: 40,
            if_instr_ptr: 56,
            if_stack: 64,
            if_stack_is_pointer: false,
            if_owner: 70,
            if_localsplus: 72,
            owner_first_shim: 3,
            stackrefs: false,
            rt_interpreters_head: 40,
            is_next: 0,
            is_threads_head: 72,
            is_gc: 112,
            is_modules: 944,
            is_sysdict: 352,
            is_builtins: 360,
            gc_lists: [24, 48, 72, 104],
            ts_next: 8,
            ts_dict: 112,
            ts_current_exception: 96,
            ts_native_thread_id: 144,
            ts_current_frame: 56,
            ts_frame_via_cframe: true,
        }
    }

    fn v313() -> Offsets {
        Offsets {
            minor: 13,
            co_code_adaptive: 200,
            dv_values: 8,
            frameobj_data: 64,
            dv_has_header: true,
            rt_interpreters_head: 632,
            is_next: 7264,
            is_threads_head: 7344,
            is_gc: 7400,
            is_modules: 7656,
            is_sysdict: 7640,
            is_builtins: 7648,
            ts_dict: 128,
            ts_current_exception: 112,
            ts_native_thread_id: 160,
            ts_current_frame: 72,
            ts_frame_via_cframe: false,
            ..Self::v312()
        }
    }

    fn v314() -> Offsets {
        Offsets {
            minor: 14,
            co_code_adaptive: 208,
            tuple_ob_item: 32,
            frameobj_data: 72,
            func_annotate: Some(120),
            func_typeparams: 128,
            if_stack: 64,
            if_stack_is_pointer: true,
            if_owner: 74,
            if_localsplus: 80,
            stackrefs: true,
            rt_interpreters_head: 808,
            is_next: 7272,
            is_threads_head: 7344,
            is_gc: 7408,
            is_modules: 7688,
            is_sysdict: 7672,
            is_builtins: 7680,
            gc_lists: [24, 48, 72, 96],
            ..Self::v313()
        }
    }

    /// (slot in `_Py_DebugOffsets`, field it overrides).
    fn debug_fields(&mut self, l: &DebugLayout) -> Vec<(u64, &mut u64)> {
        vec![
            (l.interpreters_head, &mut self.rt_interpreters_head),
            (l.is_next, &mut self.is_next),
            (l.is_threads_head, &mut self.is_threads_head),
            (l.is_gc, &mut self.is_gc),
            (l.is_modules, &mut self.is_modules),
            (l.is_sysdict, &mut self.is_sysdict),
            (l.is_builtins, &mut self.is_builtins),
            (l.ts_next, &mut self.ts_next),
            (l.ts_current_frame, &mut self.ts_current_frame),
            (l.ts_native_thread_id, &mut self.ts_native_thread_id),
            (l.if_previous, &mut self.if_previous),
            (l.if_executable, &mut self.if_executable),
            (l.if_instr_ptr, &mut self.if_instr_ptr),
            (l.if_localsplus, &mut self.if_localsplus),
            (l.if_owner, &mut self.if_owner),
            (l.co_filename, &mut self.co_filename),
            (l.co_name, &mut self.co_name),
            (l.co_qualname, &mut self.co_qualname),
            (l.co_linetable, &mut self.co_linetable),
            (l.co_firstlineno, &mut self.co_firstlineno),
            (l.co_localsplusnames, &mut self.co_localsplusnames),
            (l.co_code_adaptive, &mut self.co_code_adaptive),
            (l.tp_name, &mut self.tp_name),
            (l.tp_flags, &mut self.tp_flags),
            (l.ma_keys, &mut self.ma_keys),
            (l.ma_values, &mut self.ma_values),
            (l.str_state, &mut self.str_state),
            (l.str_length, &mut self.str_length),
        ]
    }

    /// The `_Py_DebugOffsets` image (slot, value) a target with this layout
    /// would carry, including the cookie, version and free-threaded words.
    #[cfg(test)]
    pub fn debug_image(&self, version_hex: u64) -> Vec<(u64, u64)> {
        let layout = match self.minor {
            13 => &DEBUG_313,
            _ => &DEBUG_314,
        };
        let mut me = self.clone();
        let mut v: Vec<(u64, u64)> = me
            .debug_fields(layout)
            .into_iter()
            .map(|(s, f)| (s, *f))
            .collect();
        v.push((0, u64::from_le_bytes(*DEBUG_COOKIE)));
        v.push((8, version_hex));
        v.push((layout.free_threaded, 0));
        v
    }

    /// Override fields from the target's `_Py_DebugOffsets` (3.13+), which
    /// starts at `_PyRuntime`. Returns whether the struct declares a
    /// free-threaded build. Missing or unreadable debug offsets leave the
    /// table as is.
    pub fn apply_debug_offsets(&mut self, src: &dyn MemorySource, runtime: u64) -> Result<bool> {
        let layout = match self.minor {
            13 => &DEBUG_313,
            14 => &DEBUG_314,
            _ => return Ok(false),
        };
        let cookie = src.read_array::<8>(runtime)?;
        if &cookie != DEBUG_COOKIE {
            return Err(Error::NotPython(format!(
                "_PyRuntime at {runtime:#x} does not start with the debug offsets cookie"
            )));
        }
        let rd = |off: u64| src.read_u64(runtime + off);
        let free_threaded = rd(layout.free_threaded)? != 0;
        for (slot, field) in self.debug_fields(layout) {
            let v = rd(slot)?;
            // A plausible struct offset; anything larger is a misread.
            if v < 1 << 20 {
                *field = v;
            }
        }
        Ok(free_threaded)
    }
}

/// Size of `PyGC_Head`.
pub const GC_HEAD: u64 = 16;

pub const TPFLAGS_MANAGED_WEAKREF: u64 = 1 << 3;
pub const TPFLAGS_MANAGED_DICT: u64 = 1 << 4;
pub const TPFLAGS_INLINE_VALUES: u64 = 1 << 2;
pub const TPFLAGS_HEAPTYPE: u64 = 1 << 9;
pub const TPFLAGS_HAVE_GC: u64 = 1 << 14;
pub const TPFLAGS_LONG_SUBCLASS: u64 = 1 << 24;
pub const TPFLAGS_LIST_SUBCLASS: u64 = 1 << 25;
pub const TPFLAGS_TUPLE_SUBCLASS: u64 = 1 << 26;
pub const TPFLAGS_BYTES_SUBCLASS: u64 = 1 << 27;
pub const TPFLAGS_UNICODE_SUBCLASS: u64 = 1 << 28;
pub const TPFLAGS_DICT_SUBCLASS: u64 = 1 << 29;
pub const TPFLAGS_TYPE_SUBCLASS: u64 = 1 << 31;

/// `PyMemberDef`: `{ const char *name; int type; Py_ssize_t offset; int flags; const char *doc; }`.
pub const MEMBERDEF_SIZE: u64 = 40;
pub const MEMBERDEF_TYPE: u64 = 8;
pub const MEMBERDEF_OFFSET: u64 = 16;
pub const T_OBJECT: u32 = 6;
pub const T_OBJECT_EX: u32 = 16;

/// `co_localspluskinds` bits.
pub const CO_FAST_HIDDEN: u8 = 0x10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_exist_for_supported_versions() {
        for m in [12, 13, 14] {
            let o = Offsets::table(m, Os::Linux).unwrap();
            assert_eq!(o.minor, m);
        }
        assert!(Offsets::table(11, Os::Linux).is_none());
        assert_eq!(Offsets::table(14, Os::Linux).unwrap().gc_lists[3], 96);
        assert_eq!(Offsets::table(13, Os::Linux).unwrap().gc_lists[3], 104);
        let w = Offsets::table(12, Os::Windows).unwrap();
        assert_eq!(w.ts_native_thread_id, 140);
        // Measured with `type(code).__basicsize__` on 3.12.3, 3.13.18, 3.14.6.
        let adaptive: Vec<u64> = [12, 13, 14]
            .iter()
            .map(|&m| Offsets::table(m, Os::Linux).unwrap().co_code_adaptive)
            .collect();
        assert_eq!(adaptive, [192, 200, 208]);
        for m in [12, 13, 14] {
            assert_eq!(Offsets::table(m, Os::Linux).unwrap().if_instr_ptr, 56);
        }
    }
}
