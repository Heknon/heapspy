/// Errors from memory sources, symbol lookup, and the CPython walker.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The feature exists in the interface but has not been written yet.
    #[error("not implemented yet: {0}")]
    Unimplemented(&'static str),

    /// The operation is not available on this platform or for this source.
    #[error("not supported: {0}")]
    Unsupported(String),

    /// `[addr, addr + len)` is not (fully) present in the memory image.
    #[error("address range {addr:#x}+{len} is not mapped in the image")]
    Unmapped { addr: u64, len: usize },

    /// Permission to read the target was denied (ptrace scope, SeDebugPrivilege, ...).
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The image or a module inside it is malformed (bad ELF/PE/minidump structure).
    #[error("malformed image: {0}")]
    Format(String),

    /// No CPython runtime was found in the target.
    #[error("not a CPython process: {0}")]
    NotPython(String),

    /// CPython was found but its version or build is not supported.
    #[error("unsupported CPython: {0}")]
    UnsupportedPython(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Snapshot(#[from] heapspy_snapshot::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
