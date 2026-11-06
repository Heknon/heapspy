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
    /// Retention flame graph (SVG or folded stacks), or a differential one.
    Flamegraph(FlamegraphArgs),
    /// Sample allocations with their Python stacks for a bounded window.
    Record(RecordArgs),
}

impl Command {
    /// Whether the command was asked for JSON output (errors are then also JSON).
    pub fn json(&self) -> bool {
        match self {
            Command::Dump(a) => a.json,
            Command::Analyze(a) => a.json,
            Command::Query(a) => a.json,
            Command::Diff(a) => a.json,
            Command::Flamegraph(_) => false,
            Command::Record(_) => false,
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
    /// Print a JSON report (schema version 1) on stdout. The summary line
    /// on stderr is printed either way.
    #[arg(long)]
    pub json: bool,
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
    /// Allocation profile from `heapspy record` to join with the snapshot.
    #[arg(long, value_name = "FILE.hpya")]
    pub allocations: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("what").required(true).args(["type_name", "retaining_path", "retaining_path_type"])))]
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
    /// Retaining paths of the largest instances of a type (up to --top).
    #[arg(long, value_name = "T")]
    pub retaining_path_type: Option<String>,
    /// Number of instances, holders, or path targets.
    #[arg(long, value_name = "N", default_value_t = heapspy_analyzer::DEFAULT_TOP)]
    pub top: usize,
    /// Maximum number of retaining paths per object.
    #[arg(long, value_name = "N", default_value_t = 3)]
    pub max_paths: usize,
    /// Print the JSON report (schema version 1) instead of text.
    #[arg(long)]
    pub json: bool,
    /// Allocation profile from `heapspy record` to join with the snapshot.
    #[arg(long, value_name = "FILE.hpya")]
    pub allocations: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Earlier snapshot.
    #[arg(value_name = "BEFORE")]
    pub before: PathBuf,
    /// Later snapshot.
    #[arg(value_name = "AFTER")]
    pub after: PathBuf,
    /// Number of rows in the by-type and by-site tables.
    #[arg(long, value_name = "N", default_value_t = heapspy_analyzer::DEFAULT_TOP)]
    pub top: usize,
    /// Print the JSON report (schema version 1) instead of text.
    #[arg(long)]
    pub json: bool,
    /// Allocation profile from `heapspy record`, checked against AFTER.
    #[arg(long, value_name = "FILE.hpya")]
    pub allocations: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct RecordArgs {
    /// Process to record.
    #[arg(long, value_name = "PID")]
    pub pid: u32,
    /// How long to record: 60s, 500ms, 5m, 1h, or seconds.
    #[arg(long, value_name = "DURATION", value_parser = heapspy_record::parse_duration)]
    pub duration: std::time::Duration,
    /// Output allocation profile (.hpya).
    #[arg(short = 'o', long = "output", value_name = "OUT")]
    pub output: PathBuf,
    /// Events to sample, comma-separated: arena, pool, large.
    #[arg(long, value_name = "KINDS", default_value = "arena,large")]
    pub events: heapspy_alloc::EventKinds,
    /// Mean bytes between large-object samples (512K, 1M; 0 keeps every one).
    #[arg(long, value_name = "BYTES", default_value = "512K", value_parser = heapspy_record::parse_bytes)]
    pub interval: u64,
    /// Most Python frames kept per sample.
    #[arg(long, value_name = "N", default_value_t = heapspy_alloc::DEFAULT_MAX_FRAMES)]
    pub max_frames: u32,
    /// Take a snapshot right after recording stops.
    #[arg(long, value_name = "SNAP")]
    pub then_dump: Option<PathBuf>,
    /// auto, ebpf, ptrace (Linux), etw, debugger (Windows).
    #[arg(long, value_name = "MECH", default_value = "auto")]
    pub mechanism: heapspy_record::MechanismChoice,
}

#[derive(Debug, Args)]
pub struct FlamegraphArgs {
    /// Snapshot file.
    #[arg(
        value_name = "SNAP",
        required_unless_present = "diff",
        conflicts_with = "diff"
    )]
    pub snapshot: Option<PathBuf>,
    /// Differential flame graph: frames that grew from BEFORE to AFTER are
    /// red, frames that shrank are blue.
    #[arg(long, num_args = 2, value_names = ["BEFORE", "AFTER"])]
    pub diff: Option<Vec<PathBuf>>,
    /// Output path. Without it the output goes to stdout.
    #[arg(short = 'o', long = "output", value_name = "OUT")]
    pub output: Option<PathBuf>,
    /// Write folded stacks (`frame;frame bytes`, or `stack before after`
    /// with --diff) instead of an SVG.
    #[arg(long)]
    pub folded: bool,
    /// Fold frames narrower than N bytes into `[other]`.
    #[arg(long, value_name = "N", conflicts_with = "min_pct")]
    pub min_bytes: Option<u64>,
    /// Fold frames narrower than P percent of the reachable bytes into
    /// `[other]` [default: 0.01].
    #[arg(long, value_name = "P", value_parser = parse_pct)]
    pub min_pct: Option<f64>,
    /// Fold objects more than N levels below a root into `[other]`.
    #[arg(long, value_name = "N", default_value_t = heapspy_analyzer::flame::DEFAULT_MAX_DEPTH,
          value_parser = clap::value_parser!(u32).range(1..))]
    pub max_depth: u32,
    /// SVG title.
    #[arg(long, value_name = "T")]
    pub title: Option<String>,
}

fn parse_pct(s: &str) -> Result<f64, String> {
    let p: f64 = s.parse().map_err(|_| format!("`{s}` is not a number"))?;
    if (0.0..=100.0).contains(&p) {
        Ok(p)
    } else {
        Err(format!("{p} is not between 0 and 100"))
    }
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
        let cli = Cli::try_parse_from(["heapspy", "dump", "--pid", "1", "-o", "x", "--json"]);
        assert!(cli.unwrap().command.json());
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
    fn record_arguments() {
        let parse = |extra: &[&str]| {
            let mut v = vec!["heapspy", "record", "--pid", "1", "-o", "a.hpya"];
            v.extend_from_slice(extra);
            Cli::try_parse_from(v)
        };
        // --duration is required.
        assert!(parse(&[]).is_err());
        let Command::Record(r) = parse(&["--duration", "60s"]).unwrap().command else {
            panic!("not record");
        };
        assert_eq!(r.duration, std::time::Duration::from_secs(60));
        assert_eq!(r.events, heapspy_alloc::EventKinds::DEFAULT);
        assert_eq!(r.interval, 512 * 1024);
        assert_eq!(r.max_frames, 64);
        assert_eq!(r.mechanism, heapspy_record::MechanismChoice::Auto);
        let Command::Record(r) = parse(&[
            "--duration=5m",
            "--events=arena,pool",
            "--interval=1M",
            "--max-frames=8",
            "--then-dump=a.hpy",
            "--mechanism=ptrace",
        ])
        .unwrap()
        .command
        else {
            panic!("not record");
        };
        assert_eq!(r.interval, 1 << 20);
        assert!(r.events.contains(heapspy_alloc::EventKind::Pool));
        assert_eq!(r.then_dump.as_deref(), Some(std::path::Path::new("a.hpy")));
        for bad in [
            &["--duration", "soon"][..],
            &["--duration", "1s", "--events", "heap"],
            &["--duration", "1s", "--interval", "lots"],
            &["--duration", "1s", "--mechanism", "dtrace"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn allocations_flag() {
        for args in [
            &["heapspy", "analyze", "s.hpy", "--allocations", "a.hpya"][..],
            &[
                "heapspy",
                "query",
                "s.hpy",
                "--type",
                "T",
                "--allocations",
                "a.hpya",
            ],
            &[
                "heapspy",
                "diff",
                "a.hpy",
                "b.hpy",
                "--allocations",
                "a.hpya",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
        }
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

    #[test]
    fn flamegraph_takes_one_snapshot_or_a_diff() {
        let ok = |a: &[&str]| Cli::try_parse_from(a).is_ok();
        assert!(ok(&["heapspy", "flamegraph", "s.hpy", "-o", "x.svg"]));
        assert!(ok(&[
            "heapspy",
            "flamegraph",
            "--diff",
            "a",
            "b",
            "-o",
            "x.svg"
        ]));
        assert!(ok(&[
            "heapspy",
            "flamegraph",
            "s.hpy",
            "--folded",
            "--min-pct",
            "1"
        ]));
        assert!(!ok(&["heapspy", "flamegraph"]));
        assert!(!ok(&["heapspy", "flamegraph", "s.hpy", "--diff", "a", "b"]));
        assert!(!ok(&["heapspy", "flamegraph", "--diff", "a"]));
        assert!(!ok(&[
            "heapspy",
            "flamegraph",
            "s",
            "--min-bytes",
            "1",
            "--min-pct",
            "1"
        ]));
        assert!(!ok(&["heapspy", "flamegraph", "s", "--min-pct", "150"]));
        assert!(!ok(&["heapspy", "flamegraph", "s", "--max-depth", "0"]));
    }
}
