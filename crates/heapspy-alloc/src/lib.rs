//! The heapspy allocation profile format (`.hpya`).
//!
//! `heapspy record` samples allocations of a running CPython process from
//! outside it, each with its Python stack, and writes them to an allocation
//! profile: a little-endian binary sidecar file that the analyzer joins with
//! a snapshot (`.hpy`) taken at the end of the window. It holds a header
//! (target, window, mechanisms, sampling parameters, measured overhead), a
//! code table keyed by code object address with each code object's raw
//! `co_linetable`, fixed-size sample records sorted by time, and their
//! frames in CSR layout. The byte layout is specified in
//! `docs/alloc-format.md`; it follows the container conventions of
//! `docs/snapshot-format.md`.
//!
//! - [`AllocWriter`] streams samples in any order and assembles the file on
//!   [`AllocWriter::finish`].
//! - [`Profile`] memory-maps a file, validates it once, and then gives
//!   allocation-free access to samples, frames and codes, plus
//!   [`Profile::stack`] for resolved frames (`qualname`, `file:line`).
//! - [`linetable`] maps an instruction offset to a source line for the
//!   CPython 3.12, 3.13 and 3.14 location table.
//! - [`ProfileBuilder`] builds small synthetic profiles for tests.

#![deny(unsafe_code)]

pub mod builder;
mod error;
pub mod format;
pub mod linetable;
mod reader;
mod types;
mod writer;

pub use builder::{ProfileBuilder, SampleSpec};
pub use error::{Error, Result};
pub use format::FORMAT_VERSION;
pub use reader::Profile;
pub use types::*;
pub use writer::{AllocWriter, CodeInput, FrameInput, SampleInput, WriteStats};

/// Conventional file extension for allocation profiles.
pub const FILE_EXTENSION: &str = "hpya";
