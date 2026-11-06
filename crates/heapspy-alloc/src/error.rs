use std::io;

/// Errors from reading or writing an allocation profile (`.hpya`).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("not a heapspy allocation profile (bad magic bytes)")]
    BadMagic,

    #[error(
        "unsupported allocation profile format version {found}; this build of heapspy reads version {supported}"
    )]
    UnsupportedVersion { found: u16, supported: u16 },

    #[error("allocation profile is truncated or cut short: {0}")]
    Truncated(String),

    #[error("allocation profile is corrupt: {0}")]
    Corrupt(String),

    #[error("allocation profile is missing required section {0}")]
    MissingSection(&'static str),

    #[error(
        "allocation profile contains section kind {0} marked required, which this build does not understand"
    )]
    UnknownRequiredSection(u32),

    #[error("string id {0} is out of range or not valid UTF-8")]
    InvalidString(u32),

    #[error("blob id {0} is out of range")]
    InvalidBlob(u32),

    #[error("code id {0} is out of range")]
    InvalidCode(u32),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
