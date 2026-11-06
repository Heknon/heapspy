//! ELF symbol lookup.
//!
//! Two paths:
//!
//! - [`find_exported`] reads the dynamic symbol table out of target memory:
//!   ELF header at `module.base`, program headers, `PT_DYNAMIC`, then
//!   `DT_SYMTAB` / `DT_STRTAB` and `DT_GNU_HASH` or `DT_HASH` for the lookup.
//!   This needs only what the loader mapped.
//! - [`find_in_file`] parses the module's file on disk with the `object`
//!   crate: `.dynsym`, then the static `.symtab`, then (for `_PyRuntime`
//!   only) the start of the `.PyRuntime` section. Stripped builds keep the
//!   section even when the symbol is gone.
//!
//! Addresses from either path are link-time virtual addresses plus the load
//! bias: `module.base - first PT_LOAD p_vaddr (page aligned)`. For a non-PIE
//! executable the bias is 0.

use std::path::Path;

use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};

use crate::error::{Error, Result};
use crate::source::{MemorySource, MemorySourceExt, Module};

pub const ELF_MAGIC: [u8; 4] = *b"\x7fELF";

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_NOTE: u32 = 4;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const NT_GNU_BUILD_ID: u32 = 3;
const SYM_LEN: u64 = 24;
const PAGE: u64 = 4096;

/// Upper bounds that keep a corrupt image from sending us into huge reads.
const MAX_PHNUM: u16 = 256;
const MAX_DYN: usize = 4096;
const MAX_CHAIN: u32 = 1 << 20;
const MAX_NAME: usize = 1024;

/// The parts of an in-memory ELF image needed for lookups.
#[derive(Debug, Clone)]
struct Image {
    bias: u64,
    /// `(p_type, p_vaddr, p_memsz)` of each program header.
    phdrs: Vec<(u32, u64, u64)>,
}

fn read_image<S: MemorySource + ?Sized>(src: &S, base: u64) -> Result<Image> {
    let ident = src.read_array::<16>(base)?;
    if ident[..4] != ELF_MAGIC {
        return Err(Error::Format(format!("no ELF header at {base:#x}")));
    }
    if ident[4] != 2 {
        return Err(Error::Unsupported("32-bit ELF images".into()));
    }
    let phoff = src.read_u64(base + 0x20)?;
    let phentsize = src.read_u16(base + 0x36)?;
    let phnum = src.read_u16(base + 0x38)?;
    if phentsize < 56 || phnum == 0 || phnum > MAX_PHNUM {
        return Err(Error::Format(format!(
            "bad program header table at {base:#x} (entsize {phentsize}, count {phnum})"
        )));
    }
    let mut phdrs = Vec::with_capacity(phnum as usize);
    let mut min_load = u64::MAX;
    for i in 0..phnum as u64 {
        let ph = base
            .checked_add(phoff)
            .and_then(|a| a.checked_add(i * phentsize as u64))
            .ok_or(Error::Format("program header address overflows".into()))?;
        let p_type = src.read_u32(ph)?;
        let p_vaddr = src.read_u64(ph + 0x10)?;
        let p_memsz = src.read_u64(ph + 0x28)?;
        if p_type == PT_LOAD {
            min_load = min_load.min(p_vaddr);
        }
        phdrs.push((p_type, p_vaddr, p_memsz));
    }
    if min_load == u64::MAX {
        return Err(Error::Format(format!("no PT_LOAD in image at {base:#x}")));
    }
    Ok(Image {
        bias: base.wrapping_sub(min_load & !(PAGE - 1)),
        phdrs,
    })
}

/// Resolve `name` in the dynamic symbol table of the ELF image mapped at
/// `module.base`, reading only target memory.
pub fn find_exported<S: MemorySource + ?Sized>(
    src: &S,
    module: &Module,
    name: &str,
) -> Result<Option<u64>> {
    let img = read_image(src, module.base)?;
    let Some(&(_, dyn_vaddr, dyn_size)) = img.phdrs.iter().find(|p| p.0 == PT_DYNAMIC) else {
        return Ok(None);
    };
    let dyn_addr = img.bias.wrapping_add(dyn_vaddr);
    let (mut strtab, mut symtab, mut strsz, mut hash, mut gnu_hash) = (0, 0, 0, 0, 0);
    let count = ((dyn_size / 16) as usize).min(MAX_DYN);
    for i in 0..count as u64 {
        let tag = src.read_i64(dyn_addr + i * 16)?;
        let val = src.read_u64(dyn_addr + i * 16 + 8)?;
        match tag {
            DT_NULL => break,
            DT_STRTAB => strtab = val,
            DT_SYMTAB => symtab = val,
            DT_STRSZ => strsz = val,
            DT_HASH => hash = val,
            DT_GNU_HASH => gnu_hash = val,
            _ => {}
        }
    }
    if strtab == 0 || symtab == 0 {
        return Ok(None);
    }
    // glibc rewrites these to absolute addresses in place; other loaders
    // (and file images) leave them relative to the link address.
    let fix = |v: u64| {
        if module.size != 0 && module.contains(v) {
            v
        } else {
            img.bias.wrapping_add(v)
        }
    };
    let (strtab, symtab) = (fix(strtab), fix(symtab));
    let check = |idx: u32| -> Result<Option<u64>> {
        let sym = symtab + idx as u64 * SYM_LEN;
        let st_name = src.read_u32(sym)? as u64;
        if strsz != 0 && st_name >= strsz {
            return Ok(None);
        }
        let n = src.read_cstr(strtab + st_name, MAX_NAME)?;
        if n != name.as_bytes() {
            return Ok(None);
        }
        let shndx = src.read_u16(sym + 6)?;
        let value = src.read_u64(sym + 8)?;
        if shndx == 0 || value == 0 {
            return Ok(None);
        }
        Ok(Some(img.bias.wrapping_add(value)))
    };

    if gnu_hash != 0 {
        let h = fix(gnu_hash);
        let nbuckets = src.read_u32(h)?;
        let symoffset = src.read_u32(h + 4)?;
        let bloom_size = src.read_u32(h + 8)?;
        if nbuckets == 0 {
            return Ok(None);
        }
        let buckets = h + 16 + bloom_size as u64 * 8;
        let chains = buckets + nbuckets as u64 * 4;
        let hv = gnu_hash_of(name.as_bytes());
        let mut idx = src.read_u32(buckets + (hv % nbuckets) as u64 * 4)?;
        if idx < symoffset {
            return Ok(None);
        }
        for _ in 0..MAX_CHAIN {
            let h2 = src.read_u32(chains + (idx - symoffset) as u64 * 4)?;
            if (h2 | 1) == (hv | 1) {
                if let Some(a) = check(idx)? {
                    return Ok(Some(a));
                }
            }
            if h2 & 1 != 0 {
                break;
            }
            idx = idx
                .checked_add(1)
                .ok_or(Error::Format("hash chain".into()))?;
        }
        return Ok(None);
    }
    if hash != 0 {
        let h = fix(hash);
        let nbucket = src.read_u32(h)?;
        let nchain = src.read_u32(h + 4)?;
        if nbucket == 0 {
            return Ok(None);
        }
        let hv = sysv_hash_of(name.as_bytes());
        let mut idx = src.read_u32(h + 8 + (hv % nbucket) as u64 * 4)?;
        let chain = h + 8 + nbucket as u64 * 4;
        for _ in 0..MAX_CHAIN.min(nchain.saturating_add(1)) {
            if idx == 0 || idx >= nchain {
                break;
            }
            if let Some(a) = check(idx)? {
                return Ok(Some(a));
            }
            idx = src.read_u32(chain + idx as u64 * 4)?;
        }
    }
    Ok(None)
}

fn gnu_hash_of(name: &[u8]) -> u32 {
    name.iter()
        .fold(5381u32, |h, &c| h.wrapping_mul(33).wrapping_add(c as u32))
}

fn sysv_hash_of(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in name {
        h = (h << 4).wrapping_add(c as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// The GNU build id of the image at `base`, from its `PT_NOTE` segments.
pub fn read_build_id<S: MemorySource + ?Sized>(src: &S, base: u64) -> Option<Vec<u8>> {
    let img = read_image(src, base).ok()?;
    for &(p_type, vaddr, memsz) in &img.phdrs {
        if p_type != PT_NOTE || memsz > 1 << 16 {
            continue;
        }
        let data = src
            .read_vec(img.bias.wrapping_add(vaddr), memsz as usize)
            .ok()?;
        let mut pos = 0usize;
        while pos + 12 <= data.len() {
            let u = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
            let (namesz, descsz, ntype) = (u(pos), u(pos + 4), u(pos + 8) as u32);
            let name_start = pos + 12;
            let desc_start = name_start + namesz.div_ceil(4) * 4;
            let next = desc_start.checked_add(descsz.div_ceil(4) * 4)?;
            if next > data.len() || desc_start + descsz > data.len() {
                break;
            }
            if ntype == NT_GNU_BUILD_ID && data.get(name_start..name_start + namesz)? == b"GNU\0" {
                return Some(data[desc_start..desc_start + descsz].to_vec());
            }
            pos = next;
        }
    }
    None
}

/// A symbol found in a module's file on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileSymbol {
    /// Link-time virtual address of the symbol.
    pub vaddr: u64,
    /// Lowest `PT_LOAD` virtual address, rounded down to a page. The load
    /// bias is `module.base - load_base`.
    pub load_base: u64,
    /// Where it came from: `.dynsym`, `.symtab` or `.PyRuntime`.
    pub from: &'static str,
}

impl FileSymbol {
    /// The symbol's address in the target, given where the module is mapped.
    pub fn address(&self, module_base: u64) -> u64 {
        module_base
            .wrapping_sub(self.load_base)
            .wrapping_add(self.vaddr)
    }
}

/// Look `name` up in the ELF file at `path`: `.dynsym`, then `.symtab`, then
/// for `_PyRuntime` the start of the `.PyRuntime` section.
pub fn find_in_file(path: &Path, name: &str) -> Result<Option<FileSymbol>> {
    let file = std::fs::File::open(path)?;
    // SAFETY: read-only private mapping of a regular file. If another process
    // truncates the file while it is mapped, reads can fault; module files on
    // disk are not expected to change during a dump.
    let map = unsafe { memmap2::Mmap::map(&file)? };
    find_in_bytes(&map, name)
}

/// [`find_in_file`] on an in-memory copy of the file.
pub fn find_in_bytes(data: &[u8], name: &str) -> Result<Option<FileSymbol>> {
    let obj = object::File::parse(data).map_err(|e| Error::Format(e.to_string()))?;
    let load_base = obj
        .segments()
        .map(|s| s.address())
        .min()
        .map(|a| a & !(PAGE - 1))
        .ok_or_else(|| Error::Format("ELF file has no loadable segments".into()))?;
    let hit = |sym: object::Symbol<'_, '_>| -> Option<u64> {
        (sym.name_bytes().ok()? == name.as_bytes() && !sym.is_undefined() && sym.address() != 0)
            .then(|| sym.address())
    };
    for (syms, from) in [
        (obj.dynamic_symbols(), ".dynsym"),
        (obj.symbols(), ".symtab"),
    ] {
        let mut syms = syms;
        if let Some(vaddr) = syms.find_map(hit) {
            return Ok(Some(FileSymbol {
                vaddr,
                load_base,
                from,
            }));
        }
    }
    if name == "_PyRuntime" {
        if let Some(sec) = obj.section_by_name(".PyRuntime") {
            return Ok(Some(FileSymbol {
                vaddr: sec.address(),
                load_base,
                from: ".PyRuntime",
            }));
        }
    }
    Ok(None)
}

/// Memory first ([`find_exported`]), then each existing file in `paths`
/// ([`find_in_file`]). Memory errors (for example header pages missing from
/// a core) fall through to the files.
pub fn find_with_files<S: MemorySource + ?Sized>(
    src: &S,
    module: &Module,
    name: &str,
    paths: &[std::path::PathBuf],
) -> Result<Option<u64>> {
    let mem = find_exported(src, module, name);
    if let Ok(Some(a)) = mem {
        return Ok(Some(a));
    }
    let mut last_err = mem.err();
    for p in paths {
        if !p.is_file() {
            continue;
        }
        match find_in_file(p, name) {
            Ok(Some(s)) => return Ok(Some(s.address(module.base))),
            Ok(None) => return Ok(None),
            Err(e) => last_err = Some(e),
        }
    }
    match last_err {
        Some(e) if paths.iter().all(|p| !p.is_file()) => Err(e),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_match_reference_values() {
        // Reference values from the ELF and GNU hash definitions.
        assert_eq!(gnu_hash_of(b""), 5381);
        assert_eq!(gnu_hash_of(b"printf"), 0x156b_2bb8);
        assert_eq!(sysv_hash_of(b"printf"), 0x077_905a6);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finds_symbols_in_own_test_binary_file() {
        // The test executable is an ELF file with a .symtab; `main` exists in
        // every Rust binary.
        let exe = std::env::current_exe().unwrap();
        let s = find_in_file(&exe, "main").unwrap();
        assert!(s.is_some(), "main not found in {}", exe.display());
        assert!(find_in_file(&exe, "no_such_symbol_heapspy")
            .unwrap()
            .is_none());
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert!(find_in_bytes(b"\x7fELFgarbage", "x").is_err());
        assert!(find_in_bytes(&[], "x").is_err());
    }
}
