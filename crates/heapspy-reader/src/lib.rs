//! Read a CPython process's heap from a memory image and write a snapshot.
//!
//! - [`source`]: the [`MemorySource`] trait and its backends (ELF core,
//!   live Linux process, Windows minidump, in-memory test image).
//! - [`symbols`]: exported-symbol lookup in module images.
//! - [`cpython`]: the heap walker.
//! - [`dump()`]: source -> snapshot file, the `heapspy dump` entry point.

pub mod cpython;
mod dump;
mod error;
pub mod source;
pub mod symbols;

pub use dump::{dump, DumpOptions, DumpStats, DEFAULT_MAX_STR};
pub use error::{Error, Result};
pub use source::{
    MappedRange, MemorySource, MemorySourceExt, MemorySummary, Module, Perms, SourceSpec,
    TargetInfo, ThreadInfo,
};

#[cfg(test)]
mod tests {
    use super::*;
    use source::mem::MemImage;

    #[test]
    fn dump_of_non_python_image_fails_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("x.hpy");
        let src = MemImage::new(TargetInfo::LINUX_X86_64);
        let err = dump(&src, &DumpOptions::default(), &out).unwrap_err();
        assert!(matches!(err, Error::NotPython(_)), "{err}");
        assert!(!out.exists());
    }

    #[test]
    fn stub_backends_return_errors() {
        let p = std::path::Path::new("does-not-matter");
        assert!(source::open(&SourceSpec::Core(p.into())).is_err());
        assert!(source::open(&SourceSpec::Minidump(p.into())).is_err());
        assert!(source::open(&SourceSpec::Pid(1)).is_err());
    }
}
