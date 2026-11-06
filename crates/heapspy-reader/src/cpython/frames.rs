//! Python stacks of a target, for allocation recorders (M7).
//!
//! A recorder captures, at each allocation event, the allocating thread's
//! Python frames as `(code object address, instruction offset)` pairs, and
//! later turns code objects into names and line tables. Both need a few
//! CPython layouts. [`FrameOffsets`] is that subset of [`Offsets`], as a
//! plain `Copy` struct of byte offsets that a recorder can hand to an eBPF
//! program as a map value or use from user space. Get it with
//! [`frame_offsets`], which picks the shipped table for the target's version
//! and applies `_Py_DebugOffsets` on 3.13+, exactly as the heap walker does.
//!
//! The functions here are the user-space reference for reading those
//! structures through any [`MemorySource`]: the ptrace and debugger
//! recorders call them on a stopped thread, the ETW recorder's side
//! sampler calls them on a running one, and an eBPF program must follow
//! the same steps. None of them needs the target to be stopped as a whole;
//! on a running target a read may see a torn chain, which shows up as a
//! short or failed stack, never a hang (every loop is bounded).
//!
//! # The walk
//!
//! ```text
//! _PyRuntime + rt_interpreters_head  -> PyInterpreterState *
//!   interp + is_threads_head         -> PyThreadState *       (then ts + ts_next)
//!     ts + ts_native_thread_id       == OS thread id (4 bytes on 3.12 Windows)
//!     3.12:  ts + ts_current_frame   -> _PyCFrame *; +0 -> _PyInterpreterFrame *
//!     3.13+: ts + ts_current_frame   -> _PyInterpreterFrame *
//!       frame + if_owner (u8)        >= owner_first_shim: C-stack shim, skip
//!       frame + if_executable        -> code object (3.14: _PyStackRef, clear low 2 bits;
//!                                       low bits 0b11 is a tagged int, skip)
//!       code + co_flags (u32)        & shim_code_flag: CPython's shim code, skip
//!       frame + if_instr_ptr         -> _Py_CODEUNIT * (3.12: prev_instr)
//!       instr_offset = instr_ptr - (code + co_code_adaptive), in bytes
//!       frame + if_previous          -> next outer frame, or 0
//! ```
//!
//! The instruction offset is the frame's `f_lasti` in bytes on every
//! version, so `heapspy_alloc::linetable` maps it to a line with the code
//! object's `co_linetable`. On 3.12 a frame that has not started has
//! `prev_instr` one code unit before the code; that is recorded as "no
//! offset" and resolves to `co_firstlineno`, as CPython does.
//!
//! # Shim frames
//!
//! Two kinds of frames on the chain run no Python code of the program, and
//! CPython's tracebacks do not show them:
//!
//! - The entry frame `_PyEval_EvalFrameDefault` pushes for each C-level
//!   call into the interpreter: owner `FRAME_OWNED_BY_CSTACK` (3.12, 3.13)
//!   or `FRAME_OWNED_BY_INTERPRETER` (3.14), so `owner >= owner_first_shim`.
//!   Its executable is the interpreter's trampoline code object on 3.12 and
//!   `None` on 3.13 and 3.14.
//! - On 3.13 and 3.14, the frame of `_Py_InitCleanup`, which the
//!   `CALL_ALLOC_AND_ENTER_INIT` instruction (a call to a Python class
//!   with a Python `__init__`) pushes under `__init__`'s frame to check
//!   that `__init__` returned `None`. It is an ordinary frame
//!   (`FRAME_OWNED_BY_THREAD`) whose code object is a static one named
//!   `__init__` in file `__init__`. CPython hides it because its
//!   instruction pointer is before the code's `_co_firsttraceable`
//!   (`_PyFrame_IsIncomplete`). This module recognises the code object
//!   instead, by `CO_NO_MONITORING_EVENTS` (0x2000000) in `co_flags`: the
//!   compiler never sets it, and CPython sets it on its internal shim code
//!   so that monitoring does not see it either. 3.12 has no such frame (and
//!   no such flag).
//!
//! [`read_stack`] skips both, and the eBPF recorder applies the same two
//! tests to the frames its kernel program copies ([`is_shim_code`]).

use std::collections::{HashMap, HashSet};

use heapspy_snapshot::Os;

use super::offsets::Offsets;
use super::{offsets_for, RuntimeLocation};
use crate::error::{Error, Result};
use crate::source::{MemorySource, MemorySourceExt};

/// Most interpreters followed from `_PyRuntime`.
pub const MAX_INTERPRETERS: usize = 64;
/// Most threads followed per interpreter.
pub const MAX_THREADS: usize = 4096;
/// Longest name read from a code object.
pub const MAX_NAME_LEN: usize = 4096;
/// Largest `co_linetable` read.
pub const MAX_LINETABLE_LEN: usize = 1 << 20;
/// Instruction offsets at or above this are treated as misreads.
pub const MAX_INSTR_OFFSET: u64 = 1 << 26;
/// `offsetof(PyCodeObject, co_flags)` on 3.12, 3.13 and 3.14: after
/// `PyObject_VAR_HEAD` and `co_consts`, `co_names`, `co_exceptiontable`.
pub const CO_FLAGS: u64 = 48;
/// `CO_NO_MONITORING_EVENTS` (3.13+): set on CPython's shim code
/// (`_Py_InitCleanup`), never by the compiler.
pub const CO_NO_MONITORING_EVENTS: u32 = 0x0200_0000;

/// Byte offsets a recorder needs to read Python stacks and code objects.
/// See the module docs for how they chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameOffsets {
    /// CPython minor version (12, 13, 14).
    pub minor: u8,

    /// `_PyRuntimeState.interpreters.head`.
    pub rt_interpreters_head: u64,
    /// `PyInterpreterState.next`.
    pub is_next: u64,
    /// `PyInterpreterState.threads.head`.
    pub is_threads_head: u64,

    /// `PyThreadState.next`.
    pub ts_next: u64,
    /// `PyThreadState.native_thread_id`.
    pub ts_native_thread_id: u64,
    /// Size of `native_thread_id` in bytes: 4 on 3.12 Windows (`unsigned
    /// long` under LLP64), else 8.
    pub ts_native_thread_id_size: u8,
    /// 3.12: offset of `cframe` (then `_PyCFrame.current_frame` at 0).
    /// 3.13+: offset of `current_frame`.
    pub ts_current_frame: u64,
    /// `ts_current_frame` points at a `_PyCFrame` (3.12), not at the frame.
    pub ts_frame_via_cframe: bool,

    /// `_PyInterpreterFrame.previous`.
    pub if_previous: u64,
    /// `_PyInterpreterFrame.f_code` (3.12) / `f_executable` (3.13+).
    pub if_executable: u64,
    /// `_PyInterpreterFrame.prev_instr` (3.12) / `instr_ptr` (3.13+).
    pub if_instr_ptr: u64,
    /// `_PyInterpreterFrame.owner` (one byte).
    pub if_owner: u64,
    /// Frames with `owner >= owner_first_shim` hold no Python code.
    pub owner_first_shim: u8,
    /// `f_executable` is a `_PyStackRef` (3.14): clear the low 2 bits.
    pub executable_is_stackref: bool,

    /// `PyCodeObject.co_qualname`, `co_filename` (pointers to `str`).
    pub co_qualname: u64,
    pub co_filename: u64,
    /// `PyCodeObject.co_firstlineno` (`int`).
    pub co_firstlineno: u64,
    /// `PyCodeObject.co_flags` (`int`).
    pub co_flags: u64,
    /// The `co_flags` bit that marks CPython's shim code objects
    /// (`CO_NO_MONITORING_EVENTS` on 3.13+), or 0 if the version has none.
    pub shim_code_flag: u32,
    /// `PyCodeObject.co_linetable` (pointer to `bytes`).
    pub co_linetable: u64,
    /// Start of the bytecode inside the code object (`_PyCode_CODE`).
    pub co_code_adaptive: u64,

    /// `PyObject.ob_type`.
    pub ob_type: u64,
    /// `PyTypeObject.tp_name` (`const char *`).
    pub tp_name: u64,
    /// `PyASCIIObject.length`, `.state`; data of compact ASCII and compact
    /// non-ASCII strings.
    pub str_length: u64,
    pub str_state: u64,
    pub str_ascii_data: u64,
    pub str_compact_data: u64,
    /// `PyVarObject.ob_size` of a `bytes`, and `PyBytesObject.ob_sval`.
    pub bytes_size: u64,
    pub bytes_sval: u64,
}

impl FrameOffsets {
    /// The subset of a full offset table, for a target on `os`.
    pub fn from_offsets(o: &Offsets, os: Os) -> Self {
        Self {
            minor: o.minor,
            rt_interpreters_head: o.rt_interpreters_head,
            is_next: o.is_next,
            is_threads_head: o.is_threads_head,
            ts_next: o.ts_next,
            ts_native_thread_id: o.ts_native_thread_id,
            ts_native_thread_id_size: if os == Os::Windows && o.minor == 12 {
                4
            } else {
                8
            },
            ts_current_frame: o.ts_current_frame,
            ts_frame_via_cframe: o.ts_frame_via_cframe,
            if_previous: o.if_previous,
            if_executable: o.if_executable,
            if_instr_ptr: o.if_instr_ptr,
            if_owner: o.if_owner,
            owner_first_shim: o.owner_first_shim,
            executable_is_stackref: o.stackrefs,
            co_qualname: o.co_qualname,
            co_filename: o.co_filename,
            co_firstlineno: o.co_firstlineno,
            co_flags: CO_FLAGS,
            shim_code_flag: if o.minor >= 13 {
                CO_NO_MONITORING_EVENTS
            } else {
                0
            },
            co_linetable: o.co_linetable,
            co_code_adaptive: o.co_code_adaptive,
            ob_type: 8,
            tp_name: o.tp_name,
            str_length: o.str_length,
            str_state: o.str_state,
            str_ascii_data: o.ascii_size,
            str_compact_data: o.compact_size,
            bytes_size: 16,
            bytes_sval: o.bytes_sval,
        }
    }
}

/// Frame offsets for the runtime `rt` in `src`: the shipped table for the
/// version, overridden by the target's `_Py_DebugOffsets` on 3.13+.
pub fn frame_offsets(src: &dyn MemorySource, rt: &RuntimeLocation) -> Result<FrameOffsets> {
    let o = offsets_for(src, rt)?;
    Ok(FrameOffsets::from_offsets(&o, src.target().os))
}

/// One Python thread state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadState {
    /// Address of the `PyThreadState`.
    pub addr: u64,
    /// `native_thread_id`: the OS thread id (Linux TID, Windows thread id).
    pub native_thread_id: u64,
}

/// One frame of a Python stack, as captured: the code object's address and
/// the executing instruction's byte offset into its bytecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RawFrame {
    pub code: u64,
    /// `None` before the first instruction, or if the pointer was unreadable.
    pub instr_offset: Option<u32>,
}

/// What [`read_stack`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawStack {
    /// Innermost first.
    pub frames: Vec<RawFrame>,
    /// More frames remained past `max_frames`.
    pub truncated: bool,
    /// The chain ended at an unreadable pointer or a loop.
    pub broken: bool,
}

fn ptr(src: &dyn MemorySource, addr: u64) -> Result<u64> {
    src.read_ptr(addr)
}

/// The thread states of every interpreter, in list order.
pub fn thread_states(
    src: &dyn MemorySource,
    fo: &FrameOffsets,
    runtime_addr: u64,
) -> Result<Vec<ThreadState>> {
    let mut out = Vec::new();
    let mut interp = ptr(src, runtime_addr + fo.rt_interpreters_head)?;
    let mut seen_interp = HashSet::new();
    while interp != 0 && seen_interp.len() < MAX_INTERPRETERS && seen_interp.insert(interp) {
        let mut ts = ptr(src, interp + fo.is_threads_head).unwrap_or(0);
        let mut seen = HashSet::new();
        while ts != 0 && seen.len() < MAX_THREADS && seen.insert(ts) {
            let tid = if fo.ts_native_thread_id_size == 4 {
                src.read_u32(ts + fo.ts_native_thread_id).map(u64::from)
            } else {
                src.read_u64(ts + fo.ts_native_thread_id)
            }
            .unwrap_or(0);
            out.push(ThreadState {
                addr: ts,
                native_thread_id: tid,
            });
            ts = ptr(src, ts + fo.ts_next).unwrap_or(0);
        }
        interp = ptr(src, interp + fo.is_next).unwrap_or(0);
    }
    Ok(out)
}

/// The thread state whose `native_thread_id` is `tid`, if any.
pub fn thread_state_for(
    src: &dyn MemorySource,
    fo: &FrameOffsets,
    runtime_addr: u64,
    tid: u64,
) -> Result<Option<ThreadState>> {
    Ok(thread_states(src, fo, runtime_addr)?
        .into_iter()
        .find(|t| t.native_thread_id == tid))
}

/// The innermost frame of a thread, or 0 if it is not running Python code.
pub fn current_frame(src: &dyn MemorySource, fo: &FrameOffsets, tstate: u64) -> Result<u64> {
    let p = ptr(src, tstate + fo.ts_current_frame)?;
    if fo.ts_frame_via_cframe && p != 0 {
        ptr(src, p)
    } else {
        Ok(p)
    }
}

/// Whether the object at `addr` is a code object: its type's `tp_name` is
/// `"code"`. `cache` maps type addresses to the answer.
fn is_code(
    src: &dyn MemorySource,
    fo: &FrameOffsets,
    addr: u64,
    cache: &mut HashMap<u64, bool>,
) -> bool {
    let Ok(t) = ptr(src, addr + fo.ob_type) else {
        return false;
    };
    if let Some(&v) = cache.get(&t) {
        return v;
    }
    let v = ptr(src, t + fo.tp_name)
        .and_then(|n| src.read_cstr(n, 8))
        .is_ok_and(|n| n == b"code");
    cache.insert(t, v);
    v
}

/// Whether the code object at `code` is one of CPython's shim code objects
/// (see "Shim frames" in the module docs). A failed read says no: the frame
/// is kept.
pub fn is_shim_code(src: &dyn MemorySource, fo: &FrameOffsets, code: u64) -> bool {
    fo.shim_code_flag != 0
        && src
            .read_u32(code + fo.co_flags)
            .is_ok_and(|f| f & fo.shim_code_flag != 0)
}

/// Read a thread's Python stack, innermost first, at most `max_frames`
/// frames. Shim frames (see the module docs) and frames whose executable is
/// not a code object are skipped.
pub fn read_stack(
    src: &dyn MemorySource,
    fo: &FrameOffsets,
    tstate: u64,
    max_frames: usize,
) -> Result<RawStack> {
    let mut out = RawStack::default();
    let mut f = current_frame(src, fo, tstate)?;
    let mut seen = HashSet::new();
    let mut types = HashMap::new();
    let mut shims: HashMap<u64, bool> = HashMap::new();
    // Bound the walk even when every frame is a shim.
    let limit = max_frames.saturating_mul(4).max(64);
    while f != 0 {
        if !seen.insert(f) || seen.len() > limit {
            out.broken = seen.len() <= limit;
            out.truncated |= seen.len() > limit;
            break;
        }
        let owner = match src.read_u8(f + fo.if_owner) {
            Ok(o) => o,
            Err(_) => {
                out.broken = true;
                break;
            }
        };
        if owner < fo.owner_first_shim {
            let raw = ptr(src, f + fo.if_executable).unwrap_or(0);
            let code = if fo.executable_is_stackref {
                if raw & 3 == 3 {
                    0
                } else {
                    raw & !3
                }
            } else {
                raw
            };
            if code != 0
                && is_code(src, fo, code, &mut types)
                && !*shims
                    .entry(code)
                    .or_insert_with(|| is_shim_code(src, fo, code))
            {
                if out.frames.len() == max_frames {
                    out.truncated = true;
                    break;
                }
                let start = code + fo.co_code_adaptive;
                let instr_offset = ptr(src, f + fo.if_instr_ptr)
                    .ok()
                    .and_then(|ip| ip.checked_sub(start))
                    .filter(|&d| d < MAX_INSTR_OFFSET)
                    .map(|d| d as u32);
                out.frames.push(RawFrame { code, instr_offset });
            }
        }
        f = match ptr(src, f + fo.if_previous) {
            Ok(p) => p,
            Err(_) => {
                out.broken = true;
                break;
            }
        };
    }
    Ok(out)
}

/// What a code object says about itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodeInfo {
    pub qualname: Option<String>,
    pub filename: Option<String>,
    pub firstlineno: i32,
    /// Raw `co_linetable` bytes.
    pub linetable: Option<Vec<u8>>,
}

/// Read a `str` (compact ASCII or compact UCS1/2/4) of at most `max` characters.
pub fn read_str(
    src: &dyn MemorySource,
    fo: &FrameOffsets,
    addr: u64,
    max: usize,
) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let len = src.read_i64(addr + fo.str_length).ok()?;
    if !(0..=1 << 32).contains(&len) {
        return None;
    }
    let state = src.read_u32(addr + fo.str_state).ok()?;
    let kind = (state >> 2) & 7;
    let compact = state & 32 != 0;
    let ascii = state & 64 != 0;
    if !compact || !matches!(kind, 1 | 2 | 4) {
        return None;
    }
    let data = addr
        + if ascii {
            fo.str_ascii_data
        } else {
            fo.str_compact_data
        };
    let n = (len as usize).min(max);
    let raw = src.read_vec(data, n * kind as usize).ok()?;
    let le = src.target().little_endian;
    Some(match kind {
        1 => raw.iter().map(|&b| b as char).collect(),
        2 => raw
            .chunks_exact(2)
            .map(|c| {
                let v = if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                };
                char::from_u32(v as u32).unwrap_or(char::REPLACEMENT_CHARACTER)
            })
            .collect(),
        _ => raw
            .chunks_exact(4)
            .map(|c| {
                let a = [c[0], c[1], c[2], c[3]];
                let v = if le {
                    u32::from_le_bytes(a)
                } else {
                    u32::from_be_bytes(a)
                };
                char::from_u32(v).unwrap_or(char::REPLACEMENT_CHARACTER)
            })
            .collect(),
    })
}

/// Read the contents of a `bytes` object of at most `max` bytes.
pub fn read_bytes(
    src: &dyn MemorySource,
    fo: &FrameOffsets,
    addr: u64,
    max: usize,
) -> Option<Vec<u8>> {
    if addr == 0 {
        return None;
    }
    let n = src.read_i64(addr + fo.bytes_size).ok()?;
    if n < 0 || n as u64 > max as u64 {
        return None;
    }
    src.read_vec(addr + fo.bytes_sval, n as usize).ok()
}

/// Read a code object's qualname, filename, first line and line table.
/// Fields that cannot be read are `None`; the call fails only if the code
/// object itself is unreadable.
pub fn read_code(src: &dyn MemorySource, fo: &FrameOffsets, code: u64) -> Result<CodeInfo> {
    if code == 0 {
        return Err(Error::Unmapped { addr: 0, len: 8 });
    }
    let firstlineno = src.read_u32(code + fo.co_firstlineno)? as i32;
    let field = |off: u64| ptr(src, code + off).ok();
    Ok(CodeInfo {
        qualname: field(fo.co_qualname).and_then(|p| read_str(src, fo, p, MAX_NAME_LEN)),
        filename: field(fo.co_filename).and_then(|p| read_str(src, fo, p, MAX_NAME_LEN)),
        firstlineno,
        linetable: field(fo.co_linetable).and_then(|p| read_bytes(src, fo, p, MAX_LINETABLE_LEN)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::mem::MemImage;
    use crate::source::TargetInfo;

    const BASE: u64 = 0x10_0000;

    /// A bump allocator over one mapped segment.
    struct Img {
        mem: Vec<u8>,
        top: u64,
    }

    impl Img {
        fn new() -> Self {
            Self {
                mem: vec![0; 1 << 16],
                top: BASE + 16,
            }
        }
        fn alloc(&mut self, n: u64) -> u64 {
            let a = self.top;
            self.top += n.div_ceil(16) * 16;
            a
        }
        fn put(&mut self, at: u64, b: &[u8]) {
            let o = (at - BASE) as usize;
            self.mem[o..o + b.len()].copy_from_slice(b);
        }
        fn u64(&mut self, at: u64, v: u64) {
            self.put(at, &v.to_le_bytes());
        }
        fn u32(&mut self, at: u64, v: u32) {
            self.put(at, &v.to_le_bytes());
        }
        fn ascii(&mut self, fo: &FrameOffsets, s: &str) -> u64 {
            let a = self.alloc(fo.str_ascii_data + s.len() as u64 + 1);
            self.u64(a + fo.str_length, s.len() as u64);
            // kind 1, compact, ascii
            self.u32(a + fo.str_state, (1 << 2) | 32 | 64);
            self.put(a + fo.str_ascii_data, s.as_bytes());
            a
        }
        fn bytes(&mut self, fo: &FrameOffsets, b: &[u8]) -> u64 {
            let a = self.alloc(fo.bytes_sval + b.len() as u64 + 1);
            self.u64(a + fo.bytes_size, b.len() as u64);
            self.put(a + fo.bytes_sval, b);
            a
        }
        fn source(self) -> MemImage {
            let mut m = MemImage::new(TargetInfo::LINUX_X86_64);
            m.map(BASE, self.mem);
            m
        }
    }

    struct Fake {
        src: MemImage,
        runtime: u64,
        tstates: Vec<u64>,
        codes: Vec<u64>,
    }

    /// Runtime -> one interpreter -> two threads. Thread 101 runs
    /// `inner` (offset 6) called from `outer` (offset 40) through a shim
    /// frame; thread 102 has no frame.
    fn fake(fo: &FrameOffsets) -> Fake {
        let mut m = Img::new();
        let code_type = m.alloc(64);
        let tp_name = m.alloc(8);
        m.put(tp_name, b"code\0");
        m.u64(code_type + fo.tp_name, tp_name);
        let other_type = m.alloc(64);
        let other_name = m.alloc(8);
        m.put(other_name, b"dict\0");
        m.u64(other_type + fo.tp_name, other_name);

        let mut codes = Vec::new();
        for (q, line) in [("inner", 10), ("Outer.outer", 3)] {
            let c = m.alloc(fo.co_code_adaptive + 64);
            m.u64(c + fo.ob_type, code_type);
            let qs = m.ascii(fo, q);
            let fs = m.ascii(fo, "app/mod.py");
            let lt = m.bytes(fo, &[0xe8, 0x00]);
            m.u64(c + fo.co_qualname, qs);
            m.u64(c + fo.co_filename, fs);
            m.u64(c + fo.co_linetable, lt);
            m.u32(c + fo.co_firstlineno, line);
            codes.push(c);
        }
        let not_code = m.alloc(32);
        m.u64(not_code + fo.ob_type, other_type);

        let frame = |m: &mut Img, code: u64, owner: u8, off: Option<u64>, prev: u64| -> u64 {
            let f = m.alloc(96);
            let exec = if fo.executable_is_stackref {
                code | 1
            } else {
                code
            };
            m.u64(f + fo.if_executable, exec);
            m.put(f + fo.if_owner, &[owner]);
            let ip = match off {
                Some(o) => code + fo.co_code_adaptive + o,
                None => code + fo.co_code_adaptive - 2,
            };
            m.u64(f + fo.if_instr_ptr, ip);
            m.u64(f + fo.if_previous, prev);
            f
        };
        let outer = frame(&mut m, codes[1], 0, Some(40), 0);
        let shim = frame(&mut m, codes[1], fo.owner_first_shim, Some(0), outer);
        let odd = frame(&mut m, not_code, 0, Some(0), shim);
        let inner = frame(&mut m, codes[0], 0, Some(6), odd);

        let runtime = m.alloc(fo.rt_interpreters_head + 8);
        let interp = m.alloc(fo.is_threads_head.max(fo.is_next) + 8);
        m.u64(runtime + fo.rt_interpreters_head, interp);
        let ts_len = fo.ts_current_frame.max(fo.ts_native_thread_id) + 16;
        let t1 = m.alloc(ts_len);
        let t2 = m.alloc(ts_len);
        m.u64(interp + fo.is_threads_head, t1);
        m.u64(t1 + fo.ts_next, t2);
        m.u64(t1 + fo.ts_native_thread_id, 101);
        m.u64(t2 + fo.ts_native_thread_id, 102);
        if fo.ts_frame_via_cframe {
            let cframe = m.alloc(16);
            m.u64(cframe, inner);
            m.u64(t1 + fo.ts_current_frame, cframe);
        } else {
            m.u64(t1 + fo.ts_current_frame, inner);
        }
        Fake {
            src: m.source(),
            runtime,
            tstates: vec![t1, t2],
            codes,
        }
    }

    #[test]
    fn walks_threads_stacks_and_codes() {
        for minor in [12u8, 13, 14] {
            let fo =
                FrameOffsets::from_offsets(&Offsets::table(minor, Os::Linux).unwrap(), Os::Linux);
            let f = fake(&fo);
            let ts = thread_states(&f.src, &fo, f.runtime).unwrap();
            assert_eq!(
                ts,
                [
                    ThreadState {
                        addr: f.tstates[0],
                        native_thread_id: 101
                    },
                    ThreadState {
                        addr: f.tstates[1],
                        native_thread_id: 102
                    },
                ],
                "3.{minor}"
            );
            let t = thread_state_for(&f.src, &fo, f.runtime, 101)
                .unwrap()
                .unwrap();
            let st = read_stack(&f.src, &fo, t.addr, 64).unwrap();
            assert_eq!(
                st.frames,
                [
                    RawFrame {
                        code: f.codes[0],
                        instr_offset: Some(6)
                    },
                    RawFrame {
                        code: f.codes[1],
                        instr_offset: Some(40)
                    },
                ],
                "3.{minor}"
            );
            assert!(!st.truncated && !st.broken);
            let st = read_stack(&f.src, &fo, t.addr, 1).unwrap();
            assert_eq!(st.frames.len(), 1);
            assert!(st.truncated);
            let empty = read_stack(&f.src, &fo, f.tstates[1], 64).unwrap();
            assert!(empty.frames.is_empty());
            assert!(thread_state_for(&f.src, &fo, f.runtime, 7)
                .unwrap()
                .is_none());

            let c = read_code(&f.src, &fo, f.codes[1]).unwrap();
            assert_eq!(c.qualname.as_deref(), Some("Outer.outer"));
            assert_eq!(c.filename.as_deref(), Some("app/mod.py"));
            assert_eq!(c.firstlineno, 3);
            assert_eq!(c.linetable.as_deref(), Some(&[0xe8, 0x00][..]));
            assert!(read_code(&f.src, &fo, 0).is_err());
            assert!(read_code(&f.src, &fo, 0xdead_0000).is_err());
        }
    }

    #[test]
    fn windows_312_thread_id_is_32_bits() {
        let o = Offsets::table(12, Os::Windows).unwrap();
        let fo = FrameOffsets::from_offsets(&o, Os::Windows);
        assert_eq!(fo.ts_native_thread_id_size, 4);
        assert_eq!(fo.ts_native_thread_id, 140);
        let fo = FrameOffsets::from_offsets(&Offsets::table(13, Os::Windows).unwrap(), Os::Windows);
        assert_eq!(fo.ts_native_thread_id_size, 8);
    }

    #[test]
    fn garbage_pointers_end_the_walk() {
        let fo = FrameOffsets::from_offsets(&Offsets::table(13, Os::Linux).unwrap(), Os::Linux);
        let mut m = Img::new();
        // A frame whose previous points at itself, and a thread pointing at it.
        let f = m.alloc(96);
        m.u64(f + fo.if_previous, f);
        let t = m.alloc(256);
        m.u64(t + fo.ts_current_frame, f);
        let src = m.source();
        let st = read_stack(&src, &fo, t, 64).unwrap();
        assert!(st.broken);
        assert!(read_stack(&src, &fo, 0xdead_0000, 64).is_err());
        assert!(thread_states(&src, &fo, 0xdead_0000).is_err());
    }
}
