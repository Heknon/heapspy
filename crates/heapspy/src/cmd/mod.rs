//! One module per subcommand, so changes to one command touch one file.

use std::path::Path;

use anyhow::Context;
use heapspy_snapshot::Snapshot;

use heapspy_analyzer::render::Style;

use crate::cli::Command;

mod allocations;
mod analyze;
mod counters;
mod diff;
mod dump;
mod flamegraph;
mod query;
mod record;
mod top;
mod watch;

pub(crate) use dump::{capture, capture_unstopped};
pub(crate) use watch::human_duration;

pub fn run(command: Command, st: Style) -> anyhow::Result<()> {
    match command {
        Command::Top(a) => top::run(a, st),
        Command::Watch(a) => watch::run(a, st),
        Command::Agent(a) => crate::agent::run(a),
        Command::Dump(a) => dump::run(a),
        Command::Analyze(a) => analyze::run(a, st),
        Command::Query(a) => query::run(a),
        Command::Diff(a) => diff::run(a),
        Command::Flamegraph(a) => flamegraph::run(a),
        Command::Record(a) => record::run(a),
    }
}

/// Open a snapshot with the path in the error message.
pub(crate) fn open_snapshot(path: &Path) -> anyhow::Result<Snapshot> {
    Snapshot::open(path).with_context(|| format!("cannot open snapshot {}", path.display()))
}

/// The path as shown in reports.
pub(crate) fn display_path(path: &Path) -> String {
    path.display().to_string()
}
