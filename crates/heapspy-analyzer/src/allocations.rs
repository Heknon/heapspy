//! Joining an allocation profile (`.hpya`, from `heapspy record`) with a
//! snapshot.
//!
//! **Status:** [`compatibility`] and the address join
//! ([`latest_covering`]) are implemented. The reports
//! ([`analyze_with_allocations`], [`query_type_with_allocations`]) is a stub
//! that returns [`Error::Unimplemented`] (M7c). Callers fall back to the
//! plain report and add [`not_joined`] to its notes, which is what the CLI
//! does.
//!
//! # What the join has to produce
//!
//! The report fields are defined in [`crate::report`] and documented in
//! `docs/json-schema.md`: `AnalyzeReport.allocations`,
//! `Retainer.allocated_at` and `Instance.allocated_at`. Design:
//! `docs/allocation-sampling.md`, "Joining with a snapshot".
//!
//! - **By address.** A sample covers `[address, address + size)`. An object
//!   whose address falls inside a sampled arena, pool or large allocation,
//!   with no later sample covering the same address, is linked to that
//!   sample (samples are sorted by time, so "later" is a higher index).
//!   Sort the samples' ranges once and binary-search per object; objects
//!   are already sorted by address, so a merge walk works too. Only some
//!   objects get a sample, because only a sample of allocations is recorded.
//! - **By site.** Group samples by their resolved stack (the sequence of
//!   `(function, location)` from `Profile::stack`, innermost first) and sum
//!   their `weight` into `estimated_bytes`. The largest groups, at most
//!   `--top`, are `allocations.top_stacks`; `linked_bytes` there is the
//!   shallow bytes of reachable objects linked to the group's samples.
//! - **Per retainer / instance.** For each listed object, group the linked
//!   objects of its dominator subtree by their sample's stack, counting
//!   objects and shallow bytes (not sample weights). The 5 largest groups
//!   by bytes are `allocated_at.stacks`, each with the rank of the same
//!   stack in `top_stacks` if it is there. Every listed object gets an
//!   `allocated_at`, with zero counts and no stacks if nothing is linked.
//! - **Coverage.** `coverage.linked_objects` / `linked_bytes` count the
//!   reachable objects linked to any sample; `linked_pct` is
//!   `linked_bytes / totals.reachable_bytes * 100`.
//! - `approximate` (block, stack, frame) is true when the samples involved
//!   have approximate frames.
//! - Add the [`compatibility`] notes to the report.

use std::collections::BinaryHeap;

use heapspy_alloc::Profile;
use heapspy_snapshot::{Snapshot, SourceKind};

use crate::report::{AnalyzeReport, Note, TypeQueryReport};
use crate::{AnalyzeOptions, Error, QueryOptions, Result};

/// "No sample" in the result of [`latest_covering`].
pub const NO_LINK: u32 = u32::MAX;

fn note(code: &str, message: String) -> Note {
    Note {
        code: code.to_string(),
        message,
    }
}

/// Checks that `profile` was recorded from the process and interpreter the
/// snapshot was taken from, and before it. Each mismatch is a note (codes
/// `allocations_pid_mismatch`, `allocations_python_mismatch`,
/// `allocations_after_snapshot`); an empty list means they line up. The
/// pid is only checked for snapshots of a live process.
pub fn compatibility(snap: &Snapshot, profile: &Profile) -> Vec<Note> {
    let s = snap.info();
    let p = profile.info();
    let mut notes = Vec::new();
    if s.source.kind == SourceKind::Pid {
        if let Ok(pid) = s.source.reference.parse::<u32>() {
            if pid != p.pid {
                notes.push(note(
                    "allocations_pid_mismatch",
                    format!(
                        "The allocation profile was recorded from pid {}, but the snapshot is of \
                         pid {pid}. Samples will not match the snapshot's objects.",
                        p.pid
                    ),
                ));
            }
        }
    }
    if s.python != p.python {
        notes.push(note(
            "allocations_python_mismatch",
            format!(
                "The allocation profile was recorded from CPython {}, but the snapshot is of \
                 CPython {}.",
                p.python, s.python
            ),
        ));
    }
    // Snapshot time is in seconds, profile times in nanoseconds.
    let start_s = p.start_ns / 1_000_000_000;
    if s.captured_at < start_s {
        notes.push(note(
            "allocations_after_snapshot",
            "The snapshot was taken before the allocation recording started, so no sampled \
             allocation can be in it. Take the snapshot at the end of the recording \
             (heapspy record --then-dump)."
                .to_string(),
        ));
    }
    notes
}

/// For each address of `addrs`, the index of the latest range in `ranges`
/// that contains it, or [`NO_LINK`].
///
/// `ranges[i]` is `(start, end)`, half-open, for sample `i`; a range with
/// `start >= end` covers nothing. "Latest" is the highest index. `addrs`
/// must be sorted ascending (snapshot objects are). Fails if there are
/// `u32::MAX` ranges or more.
pub fn latest_covering(
    addrs: impl IntoIterator<Item = u64>,
    ranges: &[(u64, u64)],
) -> Result<Vec<u32>> {
    if ranges.len() >= NO_LINK as usize {
        return Err(Error::InvalidArgument(
            "the allocation profile has more than 2^32 - 2 samples".into(),
        ));
    }
    let mut order: Vec<u32> = (0..ranges.len() as u32)
        .filter(|&i| ranges[i as usize].0 < ranges[i as usize].1)
        .collect();
    order.sort_unstable_by_key(|&i| ranges[i as usize].0);
    let addrs = addrs.into_iter();
    let mut out = Vec::with_capacity(addrs.size_hint().0);
    let mut heap: BinaryHeap<u32> = BinaryHeap::new();
    let mut next = 0;
    let mut prev = 0u64;
    for a in addrs {
        debug_assert!(a >= prev, "addresses must be sorted");
        prev = a;
        while next < order.len() && ranges[order[next] as usize].0 <= a {
            heap.push(order[next]);
            next += 1;
        }
        while let Some(&top) = heap.peek() {
            if ranges[top as usize].1 <= a {
                heap.pop();
            } else {
                break;
            }
        }
        out.push(heap.peek().copied().unwrap_or(NO_LINK));
    }
    Ok(out)
}

/// The note added when a profile was checked but not joined.
pub fn not_joined() -> Note {
    note(
        "allocations_not_joined",
        "The allocation profile was opened and checked, but joining samples with the snapshot is \
         not implemented yet, so the report has no allocation data."
            .to_string(),
    )
}

/// [`crate::analyze`] plus the `allocations` block and per-retainer
/// `allocated_at`. Stub (M7c).
pub fn analyze_with_allocations(
    snap: &Snapshot,
    path: &str,
    opts: &AnalyzeOptions,
    profile: &Profile,
) -> Result<AnalyzeReport> {
    let _ = (snap, path, opts, profile);
    Err(Error::Unimplemented(
        "joining allocation samples with a snapshot (M7c)",
    ))
}

/// [`crate::query_type`] plus per-instance `allocated_at`. Stub (M7c).
pub fn query_type_with_allocations(
    snap: &Snapshot,
    path: &str,
    type_name: &str,
    opts: &QueryOptions,
    profile: &Profile,
) -> Result<TypeQueryReport> {
    let _ = (snap, path, type_name, opts, profile);
    Err(Error::Unimplemented(
        "joining allocation samples with a snapshot (M7c)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapspy_alloc::{ProfileBuilder, PythonVersion};
    use heapspy_snapshot::SnapshotBuilder;

    fn snap(pid: &str, captured_at: u64) -> Snapshot {
        let mut b = SnapshotBuilder::new();
        b.info_mut().source.reference = pid.into();
        b.info_mut().captured_at = captured_at;
        b.build().unwrap()
    }

    fn profile(pid: u32, minor: u8, start_s: u64) -> Profile {
        let mut b = ProfileBuilder::new();
        b.info_mut().pid = pid;
        b.info_mut().python = PythonVersion::new(3, minor, 0);
        b.info_mut().start_ns = start_s * 1_000_000_000;
        b.build().unwrap()
    }

    fn codes(n: &[Note]) -> Vec<&str> {
        n.iter().map(|n| n.code.as_str()).collect()
    }

    #[test]
    fn compatible_and_not() {
        let s = snap("42", 1000);
        assert!(compatibility(&s, &profile(42, 12, 900)).is_empty());
        assert_eq!(
            codes(&compatibility(&s, &profile(7, 13, 2000))),
            [
                "allocations_pid_mismatch",
                "allocations_python_mismatch",
                "allocations_after_snapshot"
            ]
        );
        // A core file has no pid to compare.
        let mut b = SnapshotBuilder::new();
        b.info_mut().source.kind = SourceKind::Core;
        b.info_mut().source.reference = "core.1234".into();
        b.info_mut().captured_at = 1000;
        let core = b.build().unwrap();
        assert!(compatibility(&core, &profile(7, 12, 0)).is_empty());
    }

    #[test]
    fn latest_covering_basics() {
        // 0: [100, 200), 1: [150, 160), 2: empty, 3: [100, 120)
        let ranges = [(100, 200), (150, 160), (5, 5), (100, 120)];
        let got = latest_covering([0, 5, 100, 119, 120, 150, 159, 160, 199, 200], &ranges).unwrap();
        assert_eq!(
            got,
            [NO_LINK, NO_LINK, 3, 3, 0, 1, 1, 0, 0, NO_LINK],
            "{got:?}"
        );
        assert!(latest_covering([1, 2], &[])
            .unwrap()
            .iter()
            .all(|&l| l == NO_LINK));
        // A range ending at u64::MAX saturates and still covers the top.
        let got = latest_covering([u64::MAX - 1], &[(u64::MAX - 8, u64::MAX)]).unwrap();
        assert_eq!(got, [0]);
    }

    #[test]
    fn join_is_a_stub() {
        let s = snap("42", 1000);
        let p = profile(42, 12, 900);
        assert!(matches!(
            analyze_with_allocations(&s, "s.hpy", &AnalyzeOptions::default(), &p),
            Err(Error::Unimplemented(_))
        ));
        assert!(matches!(
            query_type_with_allocations(&s, "s.hpy", "dict", &QueryOptions::default(), &p),
            Err(Error::Unimplemented(_))
        ));
    }
}
