//! PE (Windows image) export lookup and Windows naming helpers.
//!
//! Everything reads the image as it is mapped in the target, through
//! [`MemorySource::read`], so it works the same on a minidump and on a live
//! process. Image headers are always in a full-memory dump: they are part of
//! the `MEM_IMAGE` region at the module base.
//!
//! In memory, PE structures are addressed by RVA (offset from the module
//! base), not by file offset, so no section table is needed.
//!
//! - [`find_export`]: name -> absolute address via the export directory.
//! - [`exports`]: every named export, for diagnostics.
//! - [`python_dll`]: `python312.dll` -> 3.12, `python313t.dll` -> 3.13
//!   free-threaded, `python312_d.dll` -> debug build.
//! - [`python_version_from_file_version`]: the micro version and release
//!   level from the DLL's `VS_FIXEDFILEINFO` (see
//!   [`crate::source::minidump::MinidumpModule::file_version`]).
//! - [`static_tls_block`], [`tls_slot`]: find a thread's thread-local data
//!   from its TEB.

use heapspy_snapshot::PythonVersion;

use crate::error::{Error, Result};
use crate::source::{MemorySource, MemorySourceExt, Module};

/// Upper bound on `NumberOfNames` / `NumberOfFunctions`. `python3XY.dll`
/// exports about 1,700 names; this only rejects garbage before allocating.
const MAX_EXPORTS: u32 = 1 << 20;
/// Upper bound on `e_lfanew`. Real images put the NT headers in the first
/// page; anything far beyond it is a corrupt header.
const MAX_LFANEW: u32 = 1 << 20;
/// Longest export name read.
const MAX_NAME: usize = 1024;

const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;

fn bad(module: &Module, msg: impl std::fmt::Display) -> Error {
    Error::Format(format!(
        "PE image {} at {:#x}: {msg}",
        module.name, module.base
    ))
}

/// One `IMAGE_DATA_DIRECTORY`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

impl DataDirectory {
    fn is_empty(&self) -> bool {
        self.rva == 0 || self.size == 0
    }

    fn contains(&self, rva: u32) -> bool {
        rva >= self.rva && rva - self.rva < self.size
    }
}

/// The parts of the DOS / NT headers heapspy uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeHeaders {
    /// `IMAGE_FILE_HEADER.Machine`: 0x8664 AMD64, 0xaa64 ARM64.
    pub machine: u16,
    /// PE32+ (64-bit) rather than PE32.
    pub pe32_plus: bool,
    /// `SizeOfImage` from the optional header.
    pub size_of_image: u32,
    pub export: DataDirectory,
    pub tls: DataDirectory,
}

/// Read and check the DOS and NT headers of the image at `module.base`.
pub fn headers<S: MemorySource + ?Sized>(src: &S, module: &Module) -> Result<PeHeaders> {
    let base = module.base;
    let dos = src.read_array::<64>(base)?;
    if &dos[..2] != b"MZ" {
        return Err(bad(module, "no MZ signature"));
    }
    let lfanew = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap());
    if lfanew > MAX_LFANEW {
        return Err(bad(
            module,
            format_args!("e_lfanew {lfanew:#x} is implausible"),
        ));
    }
    let nt = base
        .checked_add(lfanew.into())
        .ok_or_else(|| bad(module, "NT headers overflow"))?;
    let file_header = src.read_array::<24>(nt)?;
    if &file_header[..4] != b"PE\0\0" {
        return Err(bad(module, "no PE signature"));
    }
    let u16_at = |b: &[u8], o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let u32_at = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let machine = u16_at(&file_header, 4);
    let opt_size = usize::from(u16_at(&file_header, 20));

    // The optional header is at most 240 bytes (PE32+ with 16 directories).
    let opt = src.read_vec(nt + 24, opt_size.min(240))?;
    if opt.len() < 2 {
        return Err(bad(module, "optional header missing"));
    }
    let (pe32_plus, count_off, dirs_off) = match u16_at(&opt, 0) {
        PE32_PLUS_MAGIC => (true, 108, 112),
        PE32_MAGIC => (false, 92, 96),
        m => return Err(bad(module, format_args!("optional header magic {m:#x}"))),
    };
    if opt.len() < dirs_off {
        return Err(bad(module, "optional header too short"));
    }
    let size_of_image = u32_at(&opt, 56);
    let count = u32_at(&opt, count_off) as usize;
    let dir = |i: usize| -> DataDirectory {
        let off = dirs_off + i * 8;
        if i >= count || off + 8 > opt.len() {
            return DataDirectory::default();
        }
        DataDirectory {
            rva: u32_at(&opt, off),
            size: u32_at(&opt, off + 4),
        }
    };
    Ok(PeHeaders {
        machine,
        pe32_plus,
        size_of_image,
        export: dir(IMAGE_DIRECTORY_ENTRY_EXPORT),
        tls: dir(IMAGE_DIRECTORY_ENTRY_TLS),
    })
}

/// What an export resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportTarget {
    /// Absolute address in the target.
    Address(u64),
    /// Forwarded to another DLL, e.g. `"NTDLL.RtlAllocateHeap"`.
    Forwarder(String),
}

/// One named export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    /// Biased ordinal (`Base` + index), as `dumpbin /exports` shows it.
    pub ordinal: u32,
    pub target: ExportTarget,
}

/// The export directory, read and checked.
struct ExportTable<'a, S: ?Sized> {
    src: &'a S,
    module: &'a Module,
    dir: DataDirectory,
    size_of_image: u32,
    ordinal_base: u32,
    function_count: u32,
    functions: u32,
    ordinals: u32,
    /// Name RVAs, sorted by name (the Windows loader binary-searches them too).
    names: Vec<u32>,
}

impl<'a, S: MemorySource + ?Sized> ExportTable<'a, S> {
    fn read(src: &'a S, module: &'a Module) -> Result<Option<Self>> {
        let h = headers(src, module)?;
        let dir = h.export;
        if dir.is_empty() {
            return Ok(None);
        }
        let size_of_image = h.size_of_image;
        let t = ExportTable {
            src,
            module,
            dir,
            size_of_image,
            ordinal_base: 0,
            function_count: 0,
            functions: 0,
            ordinals: 0,
            names: Vec::new(),
        };
        let ed = src.read_array::<40>(t.va(dir.rva.into(), 40)?)?;
        let f = |o: usize| u32::from_le_bytes(ed[o..o + 4].try_into().unwrap());
        let (function_count, name_count) = (f(20), f(24));
        if function_count > MAX_EXPORTS || name_count > MAX_EXPORTS {
            return Err(bad(
                module,
                format_args!(
                    "export directory claims {function_count} functions, {name_count} names"
                ),
            ));
        }
        let (functions, names_rva, ordinals) = (f(28), f(32), f(36));
        t.va(functions.into(), u64::from(function_count) * 4)?;
        t.va(ordinals.into(), u64::from(name_count) * 2)?;
        let raw = src.read_vec(
            t.va(names_rva.into(), u64::from(name_count) * 4)?,
            name_count as usize * 4,
        )?;
        let names = raw
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        Ok(Some(ExportTable {
            ordinal_base: f(16),
            function_count,
            functions,
            ordinals,
            names,
            ..t
        }))
    }

    /// Absolute address of `[rva, rva + len)`, checked against `SizeOfImage`.
    fn va(&self, rva: u64, len: u64) -> Result<u64> {
        let end = rva.saturating_add(len);
        if end > u64::from(self.size_of_image) {
            return Err(bad(
                self.module,
                format_args!(
                    "RVA range {rva:#x}+{len:#x} is outside SizeOfImage {:#x}",
                    self.size_of_image
                ),
            ));
        }
        self.module
            .base
            .checked_add(rva)
            .ok_or_else(|| bad(self.module, "address overflows"))
    }

    fn name(&self, i: usize) -> Result<Vec<u8>> {
        let rva = self.names[i];
        self.src.read_cstr(self.va(rva.into(), 1)?, MAX_NAME)
    }

    /// Resolve the `i`-th name to its ordinal and target.
    fn resolve(&self, i: usize) -> Result<(u32, ExportTarget)> {
        let index = self
            .src
            .read_u16(self.va(u64::from(self.ordinals) + 2 * i as u64, 2)?)?;
        if u32::from(index) >= self.function_count {
            return Err(bad(
                self.module,
                format_args!(
                    "export ordinal index {index} is beyond {} functions",
                    self.function_count
                ),
            ));
        }
        let rva = self
            .src
            .read_u32(self.va(u64::from(self.functions) + 4 * u64::from(index), 4)?)?;
        let ordinal = self.ordinal_base.wrapping_add(index.into());
        if self.dir.contains(rva) {
            let s = self.src.read_cstr(self.va(rva.into(), 1)?, MAX_NAME)?;
            return Ok((
                ordinal,
                ExportTarget::Forwarder(String::from_utf8_lossy(&s).into_owned()),
            ));
        }
        Ok((ordinal, ExportTarget::Address(self.va(rva.into(), 1)?)))
    }

    fn find(&self, name: &[u8]) -> Result<Option<usize>> {
        let (mut lo, mut hi) = (0, self.names.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.name(mid)?.as_slice().cmp(name) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Ok(Some(mid)),
            }
        }
        Ok(None)
    }
}

/// Resolve the exported `name` of the PE image `module` to an absolute
/// address. Returns `Ok(None)` if there is no such export, if the image has
/// no export directory, or if the export is forwarded to another DLL
/// (forwarders have no address in this image; `_PyRuntime` is never one).
pub fn find_export<S: MemorySource + ?Sized>(
    src: &S,
    module: &Module,
    name: &str,
) -> Result<Option<u64>> {
    let Some(t) = ExportTable::read(src, module)? else {
        return Ok(None);
    };
    let Some(i) = t.find(name.as_bytes())? else {
        return Ok(None);
    };
    Ok(match t.resolve(i)?.1 {
        ExportTarget::Address(a) if a != module.base => Some(a),
        // A zero RVA marks an unused slot.
        _ => None,
    })
}

/// Every named export of `module`, in name order.
pub fn exports<S: MemorySource + ?Sized>(src: &S, module: &Module) -> Result<Vec<Export>> {
    let Some(t) = ExportTable::read(src, module)? else {
        return Ok(Vec::new());
    };
    (0..t.names.len())
        .map(|i| {
            let name = String::from_utf8_lossy(&t.name(i)?).into_owned();
            let (ordinal, target) = t.resolve(i)?;
            Ok(Export {
                name,
                ordinal,
                target,
            })
        })
        .collect()
}

/// What a CPython DLL's file name says about the build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PythonDll {
    pub major: u8,
    pub minor: u8,
    /// `t` suffix: a free-threaded (no-GIL) build, e.g. `python313t.dll`.
    pub free_threaded: bool,
    /// `_d` suffix: a debug build, e.g. `python312_d.dll`.
    pub debug: bool,
}

/// Parse a CPython DLL name: `python312.dll`, `python313t.dll`,
/// `python314_d.dll`, `python313t_d.dll` (case-insensitive). Returns `None`
/// for anything else, including `python3.dll` (the stable-ABI forwarder,
/// which does not contain the runtime).
pub fn python_dll(name: &str) -> Option<PythonDll> {
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_prefix("python")?.strip_suffix(".dll")?;
    let (stem, debug) = match stem.strip_suffix("_d") {
        Some(s) => (s, true),
        None => (stem, false),
    };
    let (digits, free_threaded) = match stem.strip_suffix('t') {
        Some(s) => (s, true),
        None => (stem, false),
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) || !(2..=3).contains(&digits.len()) {
        return None;
    }
    let major = digits[..1].parse().ok()?;
    let minor = digits[1..].parse().ok()?;
    (major == 3).then_some(PythonDll {
        major,
        minor,
        free_threaded,
        debug,
    })
}

/// Decode CPython's `VS_FIXEDFILEINFO` file version (`PC/python_ver_rc.h`):
/// `major.minor.FIELD3.api` where `FIELD3 = micro * 1000 + level * 10 +
/// serial` and `level` is `PY_RELEASE_LEVEL` (0xA alpha .. 0xF final). For
/// example `[3, 12, 4150, 1013]` is 3.12.4 final.
pub fn python_version_from_file_version(v: [u16; 4]) -> Option<PythonVersion> {
    let [major, minor, field3, _] = v;
    let level = (field3 % 1000) / 10;
    if major != 3 || !(0xA..=0xF).contains(&level) {
        return None;
    }
    Some(PythonVersion {
        major: 3,
        minor: u8::try_from(minor).ok()?,
        micro: u8::try_from(field3 / 1000).ok()?,
        release_level: level as u8,
        release_serial: (field3 % 10) as u8,
    })
}

/// 64-bit TEB offsets (the same on AMD64 and ARM64).
pub mod teb {
    /// `NT_TIB.StackBase`.
    pub const STACK_BASE: u64 = 0x08;
    /// `NT_TIB.StackLimit`.
    pub const STACK_LIMIT: u64 = 0x10;
    /// `ClientId.UniqueThread`.
    pub const THREAD_ID: u64 = 0x48;
    /// `ThreadLocalStoragePointer`: array of per-module static TLS blocks,
    /// indexed by each module's TLS index.
    pub const THREAD_LOCAL_STORAGE_POINTER: u64 = 0x58;
    /// `ProcessEnvironmentBlock`.
    pub const PEB: u64 = 0x60;
    /// `TlsSlots[64]`: values set with `TlsSetValue` for indices below 64.
    pub const TLS_SLOTS: u64 = 0x1480;
    /// `TlsExpansionSlots`: pointer to 1024 more slots for indices 64..1088.
    pub const TLS_EXPANSION_SLOTS: u64 = 0x1780;
}

/// A module's static TLS (`__declspec(thread)` / `thread_local`) data for
/// one thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsBlock {
    /// Where this thread's copy of the module's `.tls` data starts.
    pub block: u64,
    /// `IMAGE_TLS_DIRECTORY.StartAddressOfRawData`: the template address the
    /// block is a copy of. A thread-local variable at address `v` in the
    /// template (from a PDB) lives at `block + (v - template_start)`.
    pub template_start: u64,
}

/// Find `module`'s static TLS block for the thread whose TEB is at `teb`
/// (`ThreadInfo::tls_base` on Windows). Returns `Ok(None)` if the module
/// has no TLS directory or the thread has no block for it.
///
/// Only PE32+ images are handled.
pub fn static_tls_block<S: MemorySource + ?Sized>(
    src: &S,
    module: &Module,
    teb: u64,
) -> Result<Option<TlsBlock>> {
    let h = headers(src, module)?;
    if h.tls.is_empty() {
        return Ok(None);
    }
    if !h.pe32_plus {
        return Err(Error::Unsupported("TLS lookup in 32-bit images".into()));
    }
    if u64::from(h.tls.rva) + 24 > u64::from(h.size_of_image) {
        return Err(bad(module, "TLS directory outside the image"));
    }
    // IMAGE_TLS_DIRECTORY64: StartAddressOfRawData, EndAddressOfRawData,
    // AddressOfIndex, AddressOfCallBacks (all absolute VAs), ...
    let dir = src.read_ptrs(module.base + u64::from(h.tls.rva), 3)?;
    let (template_start, index_addr) = (dir[0], dir[2]);
    let index = src.read_u32(index_addr)?;
    let array = src.read_ptr(teb.wrapping_add(teb::THREAD_LOCAL_STORAGE_POINTER))?;
    if array == 0 {
        return Ok(None);
    }
    let block = src.read_ptr(array.wrapping_add(8 * u64::from(index)))?;
    Ok((block != 0).then_some(TlsBlock {
        block,
        template_start,
    }))
}

/// The value a thread stored with `TlsSetValue(key, value)` (dynamic TLS,
/// used by `PyThread_tss_set`), read from its TEB. Keys 64..1088 live in
/// the expansion slots; an unallocated expansion array reads as 0.
pub fn tls_slot<S: MemorySource + ?Sized>(src: &S, teb: u64, key: u32) -> Result<u64> {
    const SLOTS: u32 = 64;
    const EXPANSION_SLOTS: u32 = 1024;
    if key < SLOTS {
        return src.read_ptr(teb.wrapping_add(teb::TLS_SLOTS + 8 * u64::from(key)));
    }
    if key - SLOTS >= EXPANSION_SLOTS {
        return Err(Error::Format(format!("TLS key {key} out of range")));
    }
    let exp = src.read_ptr(teb.wrapping_add(teb::TLS_EXPANSION_SLOTS))?;
    if exp == 0 {
        return Ok(0);
    }
    src.read_ptr(exp.wrapping_add(8 * u64::from(key - SLOTS)))
}

#[cfg(test)]
pub(crate) mod test_image {
    //! Build a minimal PE32+ image as it looks when mapped: DOS header, NT
    //! headers, an export directory and a TLS directory. No sections.

    /// How a test export resolves.
    #[derive(Clone, Debug)]
    pub enum Target {
        Rva(u32),
        Forward(&'static str),
    }

    pub const SIZE: usize = 0x3000;
    pub const EXPORT_RVA: usize = 0x1000;
    pub const TLS_RVA: usize = 0x2000;
    pub const TLS_TEMPLATE_RVA: usize = 0x2100;
    pub const TLS_INDEX_RVA: usize = 0x2200;
    pub const TLS_INDEX: u32 = 3;

    fn put32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// The image for `base`, with `exports` (any order; sorted here).
    pub fn build(base: u64, dll_name: &str, exports: &[(&str, Target)]) -> Vec<u8> {
        let mut b = vec![0u8; SIZE];
        b[..2].copy_from_slice(b"MZ");
        put32(&mut b, 0x3c, 0x80);
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
        let opt = 0x98;
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        put32(&mut b, opt + 56, SIZE as u32);
        put32(&mut b, opt + 108, 16);

        let mut sorted: Vec<_> = exports.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let n = sorted.len();
        let ed = EXPORT_RVA;
        let functions = ed + 40;
        let ordinals = functions + 4 * n;
        let names = ordinals + 2 * n;
        let mut strings = names + 4 * n;
        let mut add_str = |b: &mut Vec<u8>, s: &str| {
            let at = strings;
            b[at..at + s.len()].copy_from_slice(s.as_bytes());
            strings += s.len() + 1;
            at as u32
        };
        let name_rva = add_str(&mut b, dll_name);
        put32(&mut b, ed + 12, name_rva);
        put32(&mut b, ed + 16, 1); // ordinal base
        put32(&mut b, ed + 20, n as u32);
        put32(&mut b, ed + 24, n as u32);
        put32(&mut b, ed + 28, functions as u32);
        put32(&mut b, ed + 32, names as u32);
        put32(&mut b, ed + 36, ordinals as u32);
        // Function slots in reverse name order, so that name index and
        // ordinal index differ and the ordinal table is really used.
        for (i, (name, target)) in sorted.iter().enumerate() {
            let slot = n - 1 - i;
            let rva = match target {
                Target::Rva(r) => *r,
                Target::Forward(f) => add_str(&mut b, f),
            };
            put32(&mut b, functions + 4 * slot, rva);
            b[ordinals + 2 * i..ordinals + 2 * i + 2].copy_from_slice(&(slot as u16).to_le_bytes());
            let nr = add_str(&mut b, name);
            put32(&mut b, names + 4 * i, nr);
        }
        let export_size = strings - ed;
        put32(&mut b, opt + 112, ed as u32);
        put32(&mut b, opt + 116, export_size as u32);

        put32(&mut b, opt + 112 + 9 * 8, TLS_RVA as u32);
        put32(&mut b, opt + 116 + 9 * 8, 40);
        put64(&mut b, TLS_RVA, base + TLS_TEMPLATE_RVA as u64);
        put64(&mut b, TLS_RVA + 8, base + TLS_TEMPLATE_RVA as u64 + 0x40);
        put64(&mut b, TLS_RVA + 16, base + TLS_INDEX_RVA as u64);
        put32(&mut b, TLS_INDEX_RVA, TLS_INDEX);
        b
    }

    /// Offset of the optional header, for tests that corrupt it.
    pub const OPT: usize = 0x98;
}

#[cfg(test)]
mod tests {
    use super::test_image::{build, Target, EXPORT_RVA, OPT, SIZE, TLS_INDEX, TLS_TEMPLATE_RVA};
    use super::*;
    use crate::source::mem::MemImage;
    use crate::source::TargetInfo;

    const BASE: u64 = 0x7ff8_4000_0000;

    fn exports_list() -> Vec<(&'static str, Target)> {
        vec![
            ("_PyRuntime", Target::Rva(0x2a00)),
            ("PyObject_GetAttr", Target::Rva(0x2810)),
            ("Py_Initialize", Target::Rva(0x2820)),
            ("PyFwd", Target::Forward("KERNEL32.HeapAlloc")),
            ("Unused", Target::Rva(0)),
        ]
    }

    fn module() -> Module {
        Module {
            name: "python313.dll".into(),
            path: r"C:\Python313\python313.dll".into(),
            base: BASE,
            size: SIZE as u64,
            build_id: None,
        }
    }

    fn image(bytes: Vec<u8>) -> MemImage {
        let mut m = MemImage::new(TargetInfo::WINDOWS_X86_64);
        m.map(BASE, bytes).add_module(module());
        m
    }

    fn good() -> Vec<u8> {
        build(BASE, "python313.dll", &exports_list())
    }

    #[test]
    fn resolves_exports() {
        let src = image(good());
        let m = module();
        assert_eq!(
            find_export(&src, &m, "_PyRuntime").unwrap(),
            Some(BASE + 0x2a00)
        );
        assert_eq!(
            find_export(&src, &m, "PyObject_GetAttr").unwrap(),
            Some(BASE + 0x2810)
        );
        assert_eq!(
            find_export(&src, &m, "Py_Initialize").unwrap(),
            Some(BASE + 0x2820)
        );
        assert_eq!(find_export(&src, &m, "PyFwd").unwrap(), None);
        assert_eq!(find_export(&src, &m, "Unused").unwrap(), None);
        assert_eq!(find_export(&src, &m, "_PyRuntim").unwrap(), None);
        assert_eq!(find_export(&src, &m, "").unwrap(), None);
        assert_eq!(find_export(&src, &m, "zzz").unwrap(), None);
        // Through the trait default, which dispatches on the MZ magic.
        assert_eq!(
            src.find_symbol(&m, "_PyRuntime").unwrap(),
            Some(BASE + 0x2a00)
        );

        let all = exports(&src, &m).unwrap();
        let names: Vec<_> = all.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "PyFwd",
                "PyObject_GetAttr",
                "Py_Initialize",
                "Unused",
                "_PyRuntime"
            ]
        );
        assert_eq!(
            all[0].target,
            ExportTarget::Forwarder("KERNEL32.HeapAlloc".into())
        );
        assert_eq!(all[4].target, ExportTarget::Address(BASE + 0x2a00));
        assert_eq!(all[4].ordinal, 1); // slot 0, ordinal base 1

        let h = headers(&src, &m).unwrap();
        assert!(h.pe32_plus);
        assert_eq!(h.machine, 0x8664);
        assert_eq!(h.size_of_image, SIZE as u32);
    }

    #[test]
    fn no_export_directory() {
        let mut b = good();
        b[OPT + 112..OPT + 120].fill(0);
        let src = image(b);
        assert_eq!(find_export(&src, &module(), "_PyRuntime").unwrap(), None);
        assert!(exports(&src, &module()).unwrap().is_empty());
        // Fewer data directories than the export entry needs.
        let mut b = good();
        b[OPT + 108..OPT + 112].fill(0);
        assert_eq!(
            find_export(&image(b), &module(), "_PyRuntime").unwrap(),
            None
        );
    }

    fn put32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn assert_format(b: Vec<u8>, what: &str) {
        let src = image(b);
        let r = find_export(&src, &module(), "_PyRuntime");
        assert!(matches!(r, Err(Error::Format(_))), "{what}: {r:?}");
        let _ = exports(&src, &module());
    }

    #[test]
    fn malformed_images() {
        let mut b = good();
        b[0] = b'X';
        assert_format(b, "MZ");
        let mut b = good();
        put32(&mut b, 0x3c, 0xffff_fff0);
        assert_format(b, "e_lfanew");
        let mut b = good();
        b[0x80] = b'X';
        assert_format(b, "PE signature");
        let mut b = good();
        b[OPT] = 0;
        assert_format(b, "optional magic");
        let mut b = good();
        b[0x94..0x96].copy_from_slice(&50u16.to_le_bytes());
        assert_format(b, "short optional header");
        let mut b = good();
        put32(&mut b, EXPORT_RVA + 24, u32::MAX);
        assert_format(b, "NumberOfNames");
        let mut b = good();
        put32(&mut b, EXPORT_RVA + 20, u32::MAX);
        assert_format(b, "NumberOfFunctions");
        let mut b = good();
        put32(&mut b, EXPORT_RVA + 32, 0x2ff0);
        assert_format(b, "names array past SizeOfImage");
        let mut b = good();
        put32(&mut b, OPT + 112, 0x10_0000);
        assert_format(b, "export directory past SizeOfImage");
        // Every ordinal index out of range.
        let mut b = good();
        put32(&mut b, EXPORT_RVA + 20, 0);
        assert_format(b, "ordinal index");
        // A name RVA outside the image.
        let mut b = good();
        let names = EXPORT_RVA + 40 + 4 * 5 + 2 * 5;
        for i in 0..5 {
            put32(&mut b, names + 4 * i, 0xffff_0000);
        }
        assert_format(b, "name RVA");
        // A function RVA outside the image.
        let mut b = good();
        for i in 0..5 {
            put32(&mut b, EXPORT_RVA + 40 + 4 * i, 0x7fff_0000);
        }
        assert_format(b, "function RVA");
    }

    #[test]
    fn unmapped_or_truncated_images_error() {
        // Header not in memory at all.
        let src = MemImage::new(TargetInfo::WINDOWS_X86_64);
        assert!(matches!(
            find_export(&src, &module(), "_PyRuntime"),
            Err(Error::Unmapped { .. })
        ));
        // Every truncation of the mapped image fails or resolves to None;
        // none panics, and none returns a wrong address.
        let full = good();
        for len in (0..full.len()).step_by(7) {
            let src = image(full[..len].to_vec());
            if let Ok(Some(a)) = find_export(&src, &module(), "_PyRuntime") {
                assert_eq!(a, BASE + 0x2a00);
            }
            let _ = exports(&src, &module());
            let _ = static_tls_block(&src, &module(), 0x1000);
        }
        // Module at the top of the address space.
        let mut m = module();
        m.base = u64::MAX - 10;
        assert!(find_export(&image(good()), &m, "_PyRuntime").is_err());
    }

    #[test]
    fn corrupted_images_never_panic() {
        let full = good();
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..3000 {
            let mut b = full.clone();
            for _ in 0..1 + next() % 3 {
                // Headers and the export directory are in the first 0x1200 bytes.
                let pos = (next() % 0x1200) as usize;
                b[pos] = next() as u8;
            }
            let src = image(b);
            let _ = find_export(&src, &module(), "_PyRuntime");
            let _ = exports(&src, &module());
        }
    }

    #[test]
    fn thread_local_storage() {
        const TEB: u64 = 0x0000_00c0_0000_0000;
        const TLS_ARRAY: u64 = 0x0000_00c0_0001_0000;
        const BLOCK: u64 = 0x0000_00c0_0002_0000;
        const EXP: u64 = 0x0000_00c0_0003_0000;
        let mut teb_page = vec![0u8; 0x1800];
        teb_page[0x58..0x60].copy_from_slice(&TLS_ARRAY.to_le_bytes());
        teb_page[0x1480 + 5 * 8..0x1480 + 6 * 8].copy_from_slice(&0x1234u64.to_le_bytes());
        teb_page[0x1780..0x1788].copy_from_slice(&EXP.to_le_bytes());
        let mut array = vec![0u8; 0x40];
        let i = TLS_INDEX as usize * 8;
        array[i..i + 8].copy_from_slice(&BLOCK.to_le_bytes());
        let mut exp = vec![0u8; 1024 * 8];
        exp[2 * 8..3 * 8].copy_from_slice(&0x5678u64.to_le_bytes());

        let mut src = image(good());
        src.map(TEB, teb_page).map(TLS_ARRAY, array).map(EXP, exp);
        assert_eq!(
            static_tls_block(&src, &module(), TEB).unwrap(),
            Some(TlsBlock {
                block: BLOCK,
                template_start: BASE + TLS_TEMPLATE_RVA as u64,
            })
        );
        assert_eq!(tls_slot(&src, TEB, 5).unwrap(), 0x1234);
        assert_eq!(tls_slot(&src, TEB, 6).unwrap(), 0);
        assert_eq!(tls_slot(&src, TEB, 66).unwrap(), 0x5678);
        assert!(tls_slot(&src, TEB, 64 + 1024).is_err());
        assert!(tls_slot(&src, u64::MAX - 8, 1).is_err());

        // No TLS directory.
        let mut b = good();
        b[OPT + 112 + 72..OPT + 120 + 72].fill(0);
        assert_eq!(static_tls_block(&image(b), &module(), TEB).unwrap(), None);
    }

    #[test]
    fn python_dll_names() {
        let v = |major, minor, ft, dbg| {
            Some(PythonDll {
                major,
                minor,
                free_threaded: ft,
                debug: dbg,
            })
        };
        assert_eq!(python_dll("python312.dll"), v(3, 12, false, false));
        assert_eq!(python_dll("PYTHON313.DLL"), v(3, 13, false, false));
        assert_eq!(python_dll("python314t.dll"), v(3, 14, true, false));
        assert_eq!(python_dll("python313_d.dll"), v(3, 13, false, true));
        assert_eq!(python_dll("python313t_d.dll"), v(3, 13, true, true));
        assert_eq!(python_dll("python39.dll"), v(3, 9, false, false));
        for n in [
            "python3.dll",
            "python3_d.dll",
            "python.dll",
            "python312.exe",
            "python3x2.dll",
            "python2712.dll",
            "python27.dll",
            "python3123.dll",
            "libpython3.12.so",
            "pythoncom312.dll",
            "",
        ] {
            assert_eq!(python_dll(n), None, "{n}");
        }
    }

    #[test]
    fn file_versions() {
        let v = python_version_from_file_version([3, 12, 4150, 1013]).unwrap();
        assert_eq!(v, PythonVersion::new(3, 12, 4));
        let v = python_version_from_file_version([3, 14, 101, 1013]).unwrap();
        assert_eq!(
            (v.micro, v.release_level, v.release_serial),
            (0, PythonVersion::LEVEL_ALPHA, 1)
        );
        let v = python_version_from_file_version([3, 13, 122, 1013]).unwrap();
        assert_eq!(v.to_string(), "3.13.0rc2");
        assert!(python_version_from_file_version([2, 7, 18150, 0]).is_none());
        assert!(python_version_from_file_version([3, 12, 4050, 0]).is_none());
    }
}
