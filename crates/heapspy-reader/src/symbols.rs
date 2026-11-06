//! Exported-symbol lookup from module images in target memory.
//!
//! The CPython walker starts from the exported `_PyRuntime` symbol. That
//! symbol lives in libpython (`libpython3.12.so.1.0`), in `python3XX.dll`, or
//! in the main executable when CPython is statically linked (Debian and
//! Ubuntu's `/usr/bin/python3.X` are). [`find_python_module`] picks the
//! candidate; [`find_exported`] resolves a name in it.
//!
//! [`find_exported`] is the default for [`MemorySource::find_symbol`]. It
//! reads only from target memory and dispatches on the image magic at the
//! module base: `MZ` goes to [`pe`]; ELF is a **stub** for now.
//!
//! - ELF: read the ELF header at `module.base`, the program headers, then the
//!   `PT_DYNAMIC` segment for `DT_SYMTAB`, `DT_STRTAB`, `DT_GNU_HASH` /
//!   `DT_HASH`. Use the hash table to find the symbol (the symbol count is
//!   not stored directly). Addresses in the dynamic section may be absolute
//!   or base-relative depending on the loader; check against the module range.
//! - PE: see [`pe::find_export`]. Forwarded exports resolve to `None`.

use crate::error::{Error, Result};
use crate::source::{MemorySource, Module};

pub mod pe;

/// Resolve `name` in the dynamic symbol table / export directory of `module`
/// by reading the image out of `src`. PE images are handled by [`pe`]; ELF
/// lookup is a **stub** that returns `Error::Unimplemented`.
pub fn find_exported<S: MemorySource + ?Sized>(
    src: &S,
    module: &Module,
    name: &str,
) -> Result<Option<u64>> {
    let mut magic = [0u8; 2];
    src.read(module.base, &mut magic)?;
    match &magic {
        b"MZ" => pe::find_export(src, module, name),
        _ => Err(Error::Unimplemented("exported symbol lookup (ELF .dynsym)")),
    }
}

/// Pick the module most likely to contain `_PyRuntime`, in this order:
/// a libpython shared library (`libpython3.*.so*`), a `python3XY.dll`
/// (see [`pe::python_dll`]; not `python3.dll`, the stable-ABI forwarder),
/// then the main executable if its name starts with `python`.
///
/// This only looks at names. The caller confirms by resolving the symbol.
pub fn find_python_module(modules: &[Module]) -> Option<&Module> {
    let lower = |m: &Module| m.name.to_ascii_lowercase();
    modules
        .iter()
        .find(|m| {
            let n = lower(m);
            n.starts_with("libpython3") && n.contains(".so")
        })
        .or_else(|| modules.iter().find(|m| pe::python_dll(&m.name).is_some()))
        .or_else(|| modules.first().filter(|m| lower(m).starts_with("python")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str) -> Module {
        Module {
            name: name.into(),
            path: format!("/x/{name}"),
            base: 0,
            size: 0,
            build_id: None,
        }
    }

    #[test]
    fn picks_python_module() {
        let mods = [m("python3.12"), m("libc.so.6"), m("libpython3.12.so.1.0")];
        assert_eq!(
            find_python_module(&mods).unwrap().name,
            "libpython3.12.so.1.0"
        );
        let mods = [m("app.exe"), m("python3.dll"), m("python313.dll")];
        assert_eq!(find_python_module(&mods).unwrap().name, "python313.dll");
        let mods = [m("python.exe"), m("python3_d.dll"), m("python314t_d.dll")];
        assert_eq!(find_python_module(&mods).unwrap().name, "python314t_d.dll");
        let mods = [m("app.exe"), m("PYTHON312.DLL")];
        assert_eq!(find_python_module(&mods).unwrap().name, "PYTHON312.DLL");
        let mods = [m("python3.12"), m("libc.so.6")];
        assert_eq!(find_python_module(&mods).unwrap().name, "python3.12");
        assert!(find_python_module(&[m("bash"), m("libc.so.6")]).is_none());
    }
}
