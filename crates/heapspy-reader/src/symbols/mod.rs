//! Exported-symbol lookup from module images in target memory.
//!
//! The CPython walker starts from the exported `_PyRuntime` symbol. That
//! symbol lives in libpython (`libpython3.12.so.1.0`), in `python3XX.dll`, or
//! in the main executable when CPython is statically linked (Debian and
//! Ubuntu's `/usr/bin/python3.X` are). [`find_python_module`] picks the
//! candidate; [`find_exported`] resolves a name in it.
//!
//! [`find_exported`] is the default for [`MemorySource::find_symbol`]. It
//! reads the module's first bytes and dispatches on the image magic:
//!
//! - ELF (`\x7fELF`): [`elf::find_exported`], which reads the ELF header at
//!   `module.base`, the program headers, then the `PT_DYNAMIC` segment for
//!   `DT_SYMTAB`, `DT_STRTAB`, `DT_GNU_HASH` / `DT_HASH`, and looks the name
//!   up through the hash table. [`elf::find_in_file`] does the same from the
//!   file on disk and also searches `.symtab` and the `.PyRuntime` section;
//!   the ELF core and live Linux backends use it as a fallback.
//! - PE (`MZ`): not implemented yet. The planned implementation reads the
//!   `MZ` header at `module.base`, `e_lfanew`, optional header data
//!   directory 0 (export table), then the name pointer / ordinal / function
//!   RVA arrays. Result is `base + rva`. Forwarded exports are not needed.

use crate::error::{Error, Result};
use crate::source::{MemorySource, MemorySourceExt, Module};

pub mod elf;

/// Resolve `name` in the dynamic symbol table / export directory of `module`
/// by reading the image out of `src`, dispatching on the image magic.
pub fn find_exported<S: MemorySource + ?Sized>(
    src: &S,
    module: &Module,
    name: &str,
) -> Result<Option<u64>> {
    let magic = src.read_array::<4>(module.base)?;
    if magic == elf::ELF_MAGIC {
        elf::find_exported(src, module, name)
    } else if magic[..2] == *b"MZ" {
        Err(Error::Unimplemented("PE export lookup"))
    } else {
        Err(Error::Format(format!(
            "unknown image format at {:#x} ({})",
            module.base, module.name
        )))
    }
}

/// Pick the module most likely to contain `_PyRuntime`, in this order:
/// a libpython shared library (`libpython3.*.so*`), a `python3*.dll`
/// (not `python3.dll`, the stable-ABI forwarder), then the main executable
/// if its name starts with `python`.
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
        .or_else(|| {
            modules.iter().find(|m| {
                let n = lower(m);
                n.starts_with("python3") && n.ends_with(".dll") && n != "python3.dll"
            })
        })
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
        let mods = [m("python3.12"), m("libc.so.6")];
        assert_eq!(find_python_module(&mods).unwrap().name, "python3.12");
        assert!(find_python_module(&[m("bash"), m("libc.so.6")]).is_none());
    }
}
