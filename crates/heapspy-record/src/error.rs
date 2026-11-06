/// Errors from `heapspy record`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The recorder exists in the interface but has not been written yet.
    #[error("not implemented yet: {0}")]
    Unimplemented(&'static str),

    /// The mechanism cannot run here: wrong OS, kernel too old, feature
    /// missing. `auto` moves on to the next mechanism after this error.
    #[error("not supported: {0}")]
    Unsupported(String),

    /// The mechanism needs privileges the process does not have
    /// (`CAP_BPF`/`CAP_PERFMON`, ptrace scope, `SeDebugPrivilege`).
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// A recording option is out of range.
    #[error("invalid option: {0}")]
    InvalidOption(String),

    /// Reading the target failed (runtime not found, unsupported CPython,
    /// unreadable memory).
    #[error(transparent)]
    Reader(#[from] heapspy_reader::Error),

    /// Writing the profile failed.
    #[error(transparent)]
    Alloc(#[from] heapspy_alloc::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Whether `MechanismChoice::Auto` should try the next mechanism after
    /// this error from [`crate::Recorder::probe`].
    pub fn try_next(&self) -> bool {
        matches!(
            self,
            Error::Unsupported(_) | Error::PermissionDenied(_) | Error::Unimplemented(_)
        )
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
