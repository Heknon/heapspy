//! The heapspy snapshot file format.
//!
//! A snapshot is a compact, little-endian binary file holding a CPython
//! object graph: objects (fixed-size records sorted by address), their
//! outgoing edges (CSR layout, labelled), types, roots, a deduplicated string
//! table, and optional per-object extras and memory totals. The byte layout is
//! specified in `docs/snapshot-format.md`.
//!
//! - [`SnapshotWriter`] streams objects in any order and assembles the file on
//!   [`SnapshotWriter::finish`].
//! - [`Snapshot`] memory-maps a file, validates it once, and then gives
//!   allocation-free access to objects and edges by dense index.
//! - [`SnapshotBuilder`] builds small synthetic snapshots for tests.
//!
//! Object *index* (position in the address-sorted objects section) is the
//! dense id used by the analyzer. Edges store target *addresses*, not
//! indices, because a target may be missing from the dump; resolve them with
//! [`Snapshot::find_object`].

#![deny(unsafe_code)]

pub mod builder;
mod error;
pub mod format;
pub mod label;
mod reader;
mod types;
mod writer;

pub use builder::{ObjectSpec, SnapshotBuilder};
pub use error::{Error, Result};
pub use format::FORMAT_VERSION;
pub use label::{redacted_key_placeholder, truncate_capture};
pub use reader::Snapshot;
pub use types::*;
pub use writer::{ObjectInput, SnapshotWriter, WriteStats};

/// Conventional file extension for snapshots.
pub const FILE_EXTENSION: &str = "hpy";
