use std::io;

/// Errors from reading or writing a snapshot file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("not a heapspy snapshot (bad magic bytes)")]
    BadMagic,

    #[error(
        "unsupported snapshot format version {found}; this build of heapspy reads version {supported}"
    )]
    UnsupportedVersion { found: u16, supported: u16 },

    #[error("snapshot is truncated or cut short: {0}")]
    Truncated(String),

    #[error("snapshot is corrupt: {0}")]
    Corrupt(String),

    #[error("snapshot is missing required section {0}")]
    MissingSection(&'static str),

    #[error(
        "snapshot contains section kind {0} marked required, which this build does not understand"
    )]
    UnknownRequiredSection(u32),

    #[error("string id {0} is out of range or not valid UTF-8")]
    InvalidString(u32),

    #[error("type id {0} is out of range")]
    InvalidType(u32),

    #[error("object at address {0:#x} was added twice")]
    DuplicateAddress(u64),

    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
