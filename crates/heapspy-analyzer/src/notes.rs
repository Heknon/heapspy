//! The `notes[]` entries. Codes are stable (see `docs/json-schema.md`);
//! messages are for people.

use heapspy_snapshot::Snapshot;

use crate::render::format_bytes;
use crate::report::Note;

fn note(code: &str, message: impl Into<String>) -> Note {
    Note {
        code: code.to_string(),
        message: message.into(),
    }
}

pub fn untracked_objects() -> Note {
    note(
        "untracked_objects",
        "Untracked objects (bare ints, short strings, raw buffers) are included only when a \
         recorded container references them.",
    )
}

pub fn outside_graph(graph: u64, rss: u64) -> Note {
    note(
        "outside_graph",
        format!(
            "Python graph accounts for {} of {} RSS. The rest is outside the object graph \
             (native allocations, C extensions, untracked objects).",
            format_bytes(graph),
            format_bytes(rss)
        ),
    )
}

pub fn native_lost(blocks: u64, bytes: u64) -> Note {
    note(
        "native_lost",
        format!(
            "{blocks} native heap blocks ({}) are not pointed to from anywhere: no Python \
             object, other block, module global or thread stack holds their address. That \
             memory is leaked. Run `heapspy record --events native` while it grows to see \
             where it is allocated.",
            format_bytes(bytes)
        ),
    )
}

pub fn keys_redacted() -> Note {
    note(
        "keys_redacted",
        "Dict keys are shown as type and length because the snapshot was taken without \
         --capture-contents.",
    )
}

pub fn truncated_snapshot() -> Note {
    note(
        "truncated_snapshot",
        "The dump did not finish or hit read errors. The graph is incomplete and all numbers \
         are lower bounds.",
    )
}

pub fn dangling_edges(n: u64) -> Note {
    note(
        "dangling_edges",
        format!(
            "{n} references point at addresses that are not objects in the snapshot; they were \
             ignored."
        ),
    )
}

pub fn missing_roots(n: u64) -> Note {
    note(
        "missing_roots",
        format!("{n} root entries point at addresses that are not objects in the snapshot."),
    )
}

pub fn identity_approximate() -> Note {
    note(
        "identity_approximate",
        "Objects are matched by type and retaining site, not by address. Per-object growth is \
         approximate.",
    )
}

pub fn unreachable_target(addr: &str) -> Note {
    note(
        "unreachable_target",
        format!(
            "{addr} is not reachable from any root: it is garbage awaiting collection, or held \
             only from outside the recorded graph."
        ),
    )
}

/// Notes that depend only on the snapshot header.
pub fn header_notes(snap: &Snapshot, out: &mut Vec<Note>) {
    if !snap.info().contents_captured {
        out.push(keys_redacted());
    }
    if snap.info().truncated {
        out.push(truncated_snapshot());
    }
}
