//! Command-line definitions. Keep this in sync with the README.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "heapspy",
    version,
    about = "Read a CPython process's object graph from outside and find what keeps memory alive"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Capture a snapshot from a live process, an ELF core, or a minidump.
    Dump(DumpArgs),
    /// Top retainers, type histogram, and memory outside the graph.
    Analyze(AnalyzeArgs),
    /// Drill into one type or one object.
    Query(QueryArgs),
    /// Growth by type and by retaining site between two snapshots.
    Diff(DiffArgs),
}

impl Command {
    /// Whether the command was asked for JSON output (errors are then also JSON).
    pub fn json(&self) -> bool {
        match self {
            Command::Dump(_) => false,
            Command::Analyze(a) => a.json,
            Command::Query(a) => a.json,
            Command::Diff(a) => a.json,
        }
    }
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("source").required(true).args(["pid", "core", "minidump"])))]
pub struct DumpArgs {
    /// Dump a live process (brief pause while the image is taken).
    #[arg(long, value_name = "PID")]
    pub pid: Option<u32>,
    /// Convert a Linux ELF core file.
    #[arg(long, value_name = "PATH")]
    pub core: Option<PathBuf>,
    /// Convert a Windows full-memory minidump.
    #[arg(long, value_name = "PATH")]
    pub minidump: Option<PathBuf>,
    /// Output snapshot path.
    #[arg(short = 'o', long = "output", value_name = "OUT")]
    pub output: PathBuf,
    /// Record string and bytes contents and ordinary dict keys (size-capped).
    #[arg(long)]
    pub capture_contents: bool,
    /// Cap on captured text, in characters.
    #[arg(long, value_name = "N", requires = "capture_contents", default_value_t = heapspy_reader::DEFAULT_MAX_STR)]
    pub max_str: usize,
}

#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    /// Snapshot file.
    #[arg(value_name = "SNAP")]
    pub snapshot: PathBuf,
    /// Print the JSON report (schema version 1) instead of text.
    #[arg(long)]
    pub json: bool,
    /// Number of top retainers and histogram rows.
    #[arg(long, value_name = "N", default_value_t = heapspy_analyzer::DEFAULT_TOP)]
    pub top: usize,
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("what").required(true).args(["type_name", "retaining_path"])))]
pub struct QueryArgs {
    /// Snapshot file.
    #[arg(value_name = "SNAP")]
    pub snapshot: PathBuf,
    /// All instances of a type, with sample holders (e.g. app.session.Session).
    #[arg(long = "type", value_name = "T")]
    pub type_name: Option<String>,
    /// The labelled chain of references keeping one object alive.
    #[arg(long, value_name = "ADDR")]
    pub retaining_path: Option<String>,
    /// Print the JSON report (schema version 1) instead of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Earlier snapshot.
    #[arg(value_name = "BEFORE")]
    pub before: PathBuf,
    /// Later snapshot.
    #[arg(value_name = "AFTER")]
    pub after: PathBuf,
    /// Print the JSON report (schema version 1) instead of text.
    #[arg(long)]
    pub json: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn dump_needs_exactly_one_source() {
        assert!(Cli::try_parse_from(["heapspy", "dump", "-o", "x.hpy"]).is_err());
        assert!(
            Cli::try_parse_from(["heapspy", "dump", "--pid", "1", "--core", "c", "-o", "x"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["heapspy", "dump", "--pid", "1", "-o", "x"]).is_ok());
        assert!(Cli::try_parse_from([
            "heapspy",
            "dump",
            "--pid",
            "1",
            "-o",
            "x",
            "--max-str",
            "5"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "heapspy",
            "dump",
            "--pid",
            "1",
            "-o",
            "x",
            "--capture-contents",
            "--max-str",
            "5"
        ])
        .is_ok());
    }

    #[test]
    fn query_needs_exactly_one_mode() {
        assert!(Cli::try_parse_from(["heapspy", "query", "s.hpy"]).is_err());
        assert!(Cli::try_parse_from([
            "heapspy",
            "query",
            "s.hpy",
            "--type",
            "a",
            "--retaining-path",
            "0x1"
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["heapspy", "query", "s.hpy", "--type", "a.B", "--json"]).is_ok()
        );
    }
}
