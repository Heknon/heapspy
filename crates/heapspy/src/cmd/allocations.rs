//! `--allocations FILE.hpya` on analyze, query and diff.
//!
//! The profile is opened (which validates it) and checked against the
//! snapshot with `heapspy_analyzer::allocations::compatibility`; each
//! mismatch is printed as a warning. `analyze` and `query --type` then join
//! the profile with the snapshot, and the joined report carries the same
//! notes. `diff` and `--retaining-path` have no allocation fields: they
//! only add the compatibility notes.

use std::path::Path;

use anyhow::Context;
use heapspy_alloc::Profile;
use heapspy_analyzer::allocations::compatibility;
use heapspy_analyzer::report::Note;
use heapspy_snapshot::Snapshot;

/// An opened and checked allocation profile.
pub(crate) struct Allocations {
    pub profile: Profile,
    /// The path as given, for the report.
    pub path: String,
    /// Compatibility notes, already printed as warnings.
    pub notes: Vec<Note>,
}

/// Open `path` and validate it, without a snapshot to check it against.
pub(crate) fn open_profile(path: &Path) -> anyhow::Result<Profile> {
    Profile::open(path)
        .with_context(|| format!("cannot open allocation profile {}", path.display()))
}

/// Print compatibility notes as warnings.
pub(crate) fn warn(notes: &[Note]) {
    for n in notes {
        eprintln!("heapspy: warning: {}", n.message);
    }
}

/// Open `path` (if given) and check it against `snap`.
pub(crate) fn open(path: Option<&Path>, snap: &Snapshot) -> anyhow::Result<Option<Allocations>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let profile = open_profile(path)?;
    let notes = compatibility(snap, &profile);
    warn(&notes);
    Ok(Some(Allocations {
        profile,
        path: super::display_path(path),
        notes,
    }))
}

/// For reports that have no allocation fields: keep the compatibility
/// notes and say that the profile is not used.
pub(crate) fn unused(a: &Allocations, notes: &mut Vec<Note>, command: &str) {
    eprintln!("heapspy: note: --allocations is checked but not used by {command}");
    notes.extend(a.notes.iter().cloned());
}
