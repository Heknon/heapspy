//! `--allocations FILE.hpya` on analyze, query and diff.
//!
//! The profile is opened (which validates it) and checked against the
//! snapshot with `heapspy_analyzer::allocations::compatibility`; each
//! mismatch is printed as a warning and added to the report's notes. The
//! join itself is not implemented yet: until it is, the plain report is
//! printed with an `allocations_not_joined` note.

use std::path::Path;

use anyhow::Context;
use heapspy_alloc::Profile;
use heapspy_analyzer::allocations::{compatibility, not_joined};
use heapspy_analyzer::report::Note;
use heapspy_snapshot::Snapshot;

/// An opened and checked allocation profile.
pub(crate) struct Allocations {
    pub profile: Profile,
    /// Compatibility notes, already printed as warnings.
    pub notes: Vec<Note>,
}

/// Open `path` (if given) and check it against `snap`.
pub(crate) fn open(path: Option<&Path>, snap: &Snapshot) -> anyhow::Result<Option<Allocations>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let profile = Profile::open(path)
        .with_context(|| format!("cannot open allocation profile {}", path.display()))?;
    let notes = compatibility(snap, &profile);
    for n in &notes {
        eprintln!("heapspy: warning: {}", n.message);
    }
    Ok(Some(Allocations { profile, notes }))
}

/// The joined report, or, while the join is unimplemented, the plain one
/// with the compatibility notes and `allocations_not_joined` appended.
pub(crate) fn joined_or_plain<T>(
    a: &Allocations,
    joined: heapspy_analyzer::Result<T>,
    plain: impl FnOnce() -> heapspy_analyzer::Result<T>,
    notes: impl FnOnce(&mut T) -> &mut Vec<Note>,
) -> anyhow::Result<T> {
    match joined {
        Ok(r) => Ok(r),
        Err(heapspy_analyzer::Error::Unimplemented(_)) => {
            let n = not_joined();
            eprintln!("heapspy: note: {}", n.message);
            let mut r = plain()?;
            let list = notes(&mut r);
            list.extend(a.notes.iter().cloned());
            list.push(n);
            Ok(r)
        }
        Err(e) => Err(e.into()),
    }
}

/// For reports that have no allocation fields: keep the compatibility
/// notes and say that the profile is not used.
pub(crate) fn unused(a: &Allocations, notes: &mut Vec<Note>, command: &str) {
    eprintln!("heapspy: note: --allocations is checked but not used by {command}");
    notes.extend(a.notes.iter().cloned());
}
