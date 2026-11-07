//! Command-line definitions and help text. Keep this in sync with the
//! README and `docs/cli.md`.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// The top-level help, with the commands grouped by what they are for.
/// `tests::top_level_help_lists_every_command` keeps it complete.
const TOP_HELP: &str = "\
{before-help}{name} {version}
{about-with-newline}
{usage-heading} {usage}

\x1b[1;4mLook at a running process\x1b[0m
  top         Live view: what the memory is, what holds it, what grows
  watch       Snapshot every N seconds and print what grew, one line per round
  analyze     One readable report of a process (--pid) or of a snapshot file

\x1b[1;4mCapture\x1b[0m
  dump        Write a snapshot of a process, an ELF core or a minidump
  record      Sample allocations with their Python stacks for a time window

\x1b[1;4mDig into snapshots\x1b[0m
  query       Instances of a type, retaining paths, where code is defined
  diff        What grew between two snapshots
  flamegraph  Retention or allocation flame graph (SVG or folded stacks)

  help        Print this message or the help of a command

\x1b[1;4mOptions\x1b[0m
{options}{after-help}";

const TOP_AFTER: &str = "\
\x1b[1;4mExamples\x1b[0m
  sudo heapspy top --pid 1234                 # live view; Enter on a row for details
  sudo heapspy analyze --pid 1234             # one report, right now
  sudo heapspy watch --pid 1234 --every 30s   # is it growing, and what?
  sudo heapspy dump --pid 1234 -o app.hpy     # keep a snapshot to analyze later
  heapspy query app.hpy --retaining-path-type app.session.Session

Only commands that read a live process need privileges (ptrace on Linux,
an elevated prompt on Windows). Everything that reads a snapshot file does
not. Run `heapspy <command> --help` for details, or see docs/cli.md.";

#[derive(Debug, Parser)]
#[command(
    name = "heapspy",
    version,
    about = "Find what keeps memory alive in a running CPython process, from the outside",
    long_about = "Find what keeps memory alive in a running CPython process, from the outside.\n\n\
        heapspy reads the target's memory the way py-spy reads its stacks: nothing is injected \
        or imported into it. It rebuilds the object graph, walks the native (malloc) heap, and \
        tells you what the process's memory is, which objects hold it, and what is growing.",
    help_template = TOP_HELP,
    after_help = TOP_AFTER,
    disable_help_subcommand = false,
    max_term_width = 100
)]
pub struct Cli {
    /// When to color text output.
    #[arg(long, value_name = "WHEN", default_value = "auto", global = true)]
    pub color: ColorChoice,
    #[command(subcommand)]
    pub command: Command,
}

/// `--color`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    /// Color when writing to a terminal and NO_COLOR is not set.
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Live view of a process's memory: what it is, what holds it, what grows.
    #[command(
        long_about = "Live view of a process's memory: what it is, what holds it, what grows.\n\n\
            The top panel splits the process's memory into Python objects, native memory in \
            use, leaked native blocks, free memory the allocator keeps, and code/files/stacks, \
            with a sparkline and a growth rate for each. Below it, tabs list holders (Python and \
            native, ranked by what they retain), types, native blocks and threads.\n\n\
            How it reads the process:\n  \
            - Every second: memory totals from the OS and each thread's Python stack. These \
            reads do not stop the process.\n  \
            - Every --every seconds: a full snapshot (the same walk as `heapspy dump`). By \
            default the process is stopped for the walk, as `dump` does, and the pause is \
            shown in the header. With --no-stop it keeps running and the numbers are \
            approximate.\n  \
            - With --alloc: allocation sampling (`heapspy record`) for a bounded window, so the \
            Allocated tab can say which code allocated what is still alive.",
        after_long_help = "\x1b[1;4mKeys\x1b[0m\n  \
            1-5 / Tab   switch tab: Holders, Types, Native, Threads, Allocated\n  \
            ↑ ↓ / j k   move the selection        Enter   details of the selected row\n  \
            s           change the sort column    Esc     close details\n  \
            d           take a snapshot now       w       save the latest snapshot to a file\n  \
            a           start/stop allocation sampling (needs eBPF on Linux)\n  \
            space       pause refreshing          q       quit\n\n\
            \x1b[1;4mExamples\x1b[0m\n  \
            sudo heapspy top --pid 1234\n  \
            sudo heapspy top --pid 1234 --every 60s           # a large heap: walk less often\n  \
            sudo heapspy top --pid 1234 --no-stop             # never pause the process\n  \
            sudo heapspy top --pid 1234 --alloc --alloc-for 2m"
    )]
    Top(TopArgs),
    /// Snapshot a process every N seconds and print what grew.
    #[command(
        long_about = "Snapshot a process every N seconds and print what grew.\n\n\
            One line per snapshot: RSS, the Python graph, native memory, how long the process \
            was stopped, and the holder that grew most since the last round. Plain lines, so \
            it works over SSH, in a log file or in CI. Stop it with Ctrl-C (or --rounds): it \
            then prints the growth of each holder over the whole run with a verdict:\n  \
            grows every round  → likely a leak\n  \
            grows in steps     → keep watching (a cache filling, batches)\n  \
            flat or shrinking  → fine\n\n\
            The first and the latest snapshot are kept in --dir, ready for `heapspy diff`.",
        after_long_help = "\x1b[1;4mExamples\x1b[0m\n  \
            sudo heapspy watch --pid 1234\n  \
            sudo heapspy watch --pid 1234 --every 5m --rounds 12 > growth.log\n  \
            sudo heapspy watch --pid 1234 --max-pause 300ms   # back off when pauses get long\n  \
            heapspy diff watch-1234/first.hpy watch-1234/last.hpy"
    )]
    Watch(WatchArgs),
    /// Capture a snapshot from a live process, an ELF core, or a minidump.
    #[command(
        long_about = "Capture a snapshot from a live process, an ELF core, or a minidump.\n\n\
            A snapshot holds the object graph (types, sizes, references, roots), the native \
            heap blocks, and the process's memory map. Every other command can read it, \
            without privileges and on another machine. With --pid the process is stopped for \
            the walk (a pause of a fraction of a second to a few seconds, printed when done). \
            String and bytes contents are not recorded unless --capture-contents is given.",
        after_long_help = "\x1b[1;4mExamples\x1b[0m\n  \
            sudo heapspy dump --pid 1234 -o app.hpy\n  \
            heapspy dump --core core.1234 -o app.hpy\n  \
            heapspy dump --minidump app.dmp -o app.hpy\n  \
            sudo heapspy dump --pid 1234 --capture-contents --max-str 64 -o app.hpy"
    )]
    Dump(DumpArgs),
    /// One readable report: what the memory is and what holds it.
    #[command(
        long_about = "One readable report: what the memory is and what holds it.\n\n\
            Reads a snapshot file, or takes one from a live process with --pid (kept only with \
            --keep). The report shows:\n  \
            - where the process's memory is: Python objects, native memory in use, leaked \
            native blocks, allocator free space, pymalloc free space, code/files/stacks;\n  \
            - what holds it: the objects with the largest retained size, split into Python and \
            native bytes, with their path from a root;\n  \
            - the biggest types, leaked native blocks by size, and, with --pid, what each \
            thread is running.",
        after_long_help = "\x1b[1;4mExamples\x1b[0m\n  \
            sudo heapspy analyze --pid 1234\n  \
            sudo heapspy analyze --pid 1234 --keep app.hpy    # and keep the snapshot\n  \
            heapspy analyze app.hpy --top 40\n  \
            heapspy analyze app.hpy --allocations app.hpya    # who allocated what is alive\n  \
            heapspy analyze app.hpy --json | jq '.top_retainers[0]'"
    )]
    Analyze(AnalyzeArgs),
    /// Drill into one type or one object.
    #[command(
        long_about = "Drill into one type or one object of a snapshot.\n\n  \
            --type T                  instances of T, the largest first, and what holds them\n  \
            --retaining-path ADDR     the chain of references keeping one object alive\n  \
            --retaining-path-type T   the same for the largest instances of T\n  \
            --locate NAME             where a type, function or module is defined",
        after_long_help = "\x1b[1;4mExamples\x1b[0m\n  \
            heapspy query app.hpy --type app.session.Session\n  \
            heapspy query app.hpy --type Session            # unqualified names match too\n  \
            heapspy query app.hpy --retaining-path 0x7f3a2c41b0d0\n  \
            heapspy query app.hpy --retaining-path-type Session --top 3\n  \
            heapspy query app.hpy --locate app.cache.Store.get"
    )]
    Query(QueryArgs),
    /// Growth by type and by retaining site between two snapshots.
    #[command(
        long_about = "Growth by type and by retaining site between two snapshots of the same \
            process.\n\n\
            Objects are matched by type and by the path that holds them, never by address \
            (addresses change between dumps), so the result is a set of aggregates.",
        after_long_help = "\x1b[1;4mExamples\x1b[0m\n  \
            heapspy diff before.hpy after.hpy\n  \
            heapspy diff before.hpy after.hpy --top 40 --json"
    )]
    Diff(DiffArgs),
    /// Retention flame graph (SVG or folded stacks), or a differential one.
    #[command(
        long_about = "Retention flame graph (SVG or folded stacks), a differential one, or an \
            allocation flame graph.\n\n\
            A retention flame graph draws the dominator tree: each frame is one hop of a \
            retaining path and its width is the bytes it keeps alive. An allocation flame \
            graph (--allocations) draws sampled Python stacks, width = bytes allocated.",
        after_long_help = "\x1b[1;4mExamples\x1b[0m\n  \
            heapspy flamegraph app.hpy -o app.svg\n  \
            heapspy flamegraph --diff before.hpy after.hpy -o grew.svg\n  \
            heapspy flamegraph --allocations app.hpya -o alloc.svg\n  \
            heapspy flamegraph --allocations app.hpya --retained app.hpy -o alive.svg\n  \
            heapspy flamegraph app.hpy --folded > app.folded"
    )]
    Flamegraph(FlamegraphArgs),
    /// Sample allocations with their Python stacks for a bounded window.
    #[command(
        long_about = "Sample allocations with their Python stacks for a bounded window, from \
            outside the process, and write an allocation profile (.hpya).\n\n\
            Linux uses eBPF (root or CAP_BPF + CAP_PERFMON, kernel 5.8+), or ptrace for \
            arenas as a fallback. Windows uses ETW, or a debugger with --mechanism debugger. \
            Only allocations made while recording are seen. Join the profile with a snapshot \
            (analyze/query --allocations) to see which code allocated the memory still alive.",
        after_long_help = "\x1b[1;4mExamples\x1b[0m\n  \
            sudo heapspy record --pid 1234 --duration 60s -o app.hpya --then-dump app.hpy\n  \
            heapspy analyze app.hpy --allocations app.hpya\n  \
            sudo heapspy record --pid 1234 --duration 30s --events arena -o cheap.hpya\n  \
            heapspy record --prepare python.exe            # Windows, before --events native"
    )]
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
            Command::Flamegraph(_) | Command::Top(_) => false,
            Command::Record(a) => a.json,
            Command::Watch(a) => a.json,
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
    /// With --pid: do not stop the process (Linux). The walk races with it,
    /// so the snapshot is approximate: objects can be missed, sizes can be
    /// off, and a walk can fail. Use when even a short pause is not an option.
    #[arg(long, requires = "pid")]
    pub no_stop: bool,
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
#[command(group(clap::ArgGroup::new("input").required(true).args(["snapshot", "pid"])))]
pub struct AnalyzeArgs {
    /// Snapshot file.
    #[arg(value_name = "SNAP")]
    pub snapshot: Option<PathBuf>,
    /// Take a snapshot of this live process and report on it. The process is
    /// stopped while the snapshot is taken, as with `heapspy dump`.
    #[arg(long, value_name = "PID")]
    pub pid: Option<u32>,
    /// With --pid: keep the snapshot at this path (otherwise it is deleted).
    #[arg(long, value_name = "OUT", conflicts_with = "snapshot")]
    pub keep: Option<PathBuf>,
    /// With --pid: record string and bytes contents and dict keys.
    #[arg(long, conflicts_with = "snapshot")]
    pub capture_contents: bool,
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
pub struct TopArgs {
    /// Process to watch.
    #[arg(long, value_name = "PID")]
    pub pid: u32,
    /// How often to take a full snapshot (holders, types, native blocks):
    /// 10s, 1m, ... The memory totals and thread stacks refresh every second
    /// regardless.
    #[arg(long, value_name = "DURATION", default_value = "10s", value_parser = parse_duration)]
    pub every: Duration,
    /// Do not stop the process for snapshots. The walk then races with the
    /// process, so counts and sizes are approximate and a walk can fail.
    #[arg(long)]
    pub no_stop: bool,
    /// Skip a scheduled snapshot when the last one stopped the process for
    /// longer than this (the header says so). `d` still takes one.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub max_pause: Option<Duration>,
    /// Start allocation sampling (as `heapspy record`) right away, for
    /// --alloc-for. `a` toggles it too.
    #[arg(long)]
    pub alloc: bool,
    /// How long allocation sampling runs before it stops by itself.
    #[arg(long, value_name = "DURATION", default_value = "60s", value_parser = parse_duration)]
    pub alloc_for: Duration,
    /// Allocation events to sample: arena, large, pool, native (see
    /// `heapspy record --help`).
    #[arg(long, value_name = "KINDS", default_value = "arena,large")]
    pub alloc_events: heapspy_alloc::EventKinds,
    /// Rows per table.
    #[arg(long, value_name = "N", default_value_t = 50)]
    pub top: usize,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    /// Process to watch.
    #[arg(long, value_name = "PID")]
    pub pid: u32,
    /// Time between snapshots: 30s, 5m, 1h, ...
    #[arg(long, value_name = "DURATION", default_value = "30s", value_parser = parse_duration)]
    pub every: Duration,
    /// Stop after this many snapshots (default: until Ctrl-C).
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(2..))]
    pub rounds: Option<u32>,
    /// When a snapshot stops the process for longer than this, double the
    /// time between snapshots (printed when it happens).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub max_pause: Option<Duration>,
    /// Where the first and the latest snapshot are kept
    /// [default: ./watch-<PID>].
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// Rows in the summary printed at the end.
    #[arg(long, value_name = "N", default_value_t = 10)]
    pub top: usize,
    /// Print one JSON document per round (JSON Lines) instead of text, and a
    /// final summary document.
    #[arg(long)]
    pub json: bool,
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let d = heapspy_record::parse_duration(s)?;
    if d.is_zero() {
        Err("must be more than zero".into())
    } else {
        Ok(d)
    }
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("what").required(true).args(["type_name", "retaining_path", "retaining_path_type", "locate"])))]
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
    /// Where the type, function or module with this full name is defined
    /// (e.g. app.session.Session, app.cache.Store.get).
    #[arg(long, value_name = "NAME")]
    pub locate: Option<String>,
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
    /// Process to record. Not needed with --prepare/--unprepare.
    #[arg(long, value_name = "PID", required_unless_present_any = ["prepare", "unprepare"])]
    pub pid: Option<u32>,
    /// How long to record: 60s, 500ms, 5m, 1h, or seconds.
    #[arg(long, value_name = "DURATION", value_parser = heapspy_record::parse_duration, required_unless_present_any = ["prepare", "unprepare"])]
    pub duration: Option<std::time::Duration>,
    /// Output allocation profile (.hpya).
    #[arg(short = 'o', long = "output", value_name = "OUT", required_unless_present_any = ["prepare", "unprepare"])]
    pub output: Option<PathBuf>,
    /// Turn on Windows heap tracing for an executable (by file name, e.g.
    /// python.exe), so `--events native` can see its C-heap allocations.
    /// Sets an Image File Execution Options registry value; needs admin and
    /// applies only to processes started afterwards. Undo with --unprepare.
    #[arg(long, value_name = "IMAGE.exe", conflicts_with = "unprepare")]
    pub prepare: Option<String>,
    /// Remove the heap-tracing setting added by --prepare for an executable.
    #[arg(long, value_name = "IMAGE.exe")]
    pub unprepare: Option<String>,
    /// Events to sample, comma-separated: arena, pool, large, native.
    /// `native` traces the C heap (Windows only) and needs the target
    /// prepared before it starts (`--prepare`).
    #[arg(long, value_name = "KINDS", default_value = "arena,large")]
    pub events: heapspy_alloc::EventKinds,
    /// Mean bytes between large-object and native samples (512K, 1M; 0 keeps
    /// every one).
    #[arg(long, value_name = "BYTES", default_value = "512K", value_parser = heapspy_record::parse_bytes)]
    pub interval: u64,
    /// Smallest native heap allocation sampled (`--events native`): smaller
    /// requests are ignored so the trap rate stays bounded. Default 4K.
    #[arg(long, value_name = "BYTES", default_value = "4K", value_parser = heapspy_record::parse_bytes)]
    pub native_min_size: u64,
    /// Most Python frames kept per sample.
    #[arg(long, value_name = "N", default_value_t = heapspy_alloc::DEFAULT_MAX_FRAMES)]
    pub max_frames: u32,
    /// Take a snapshot right after recording stops.
    #[arg(long, value_name = "SNAP")]
    pub then_dump: Option<PathBuf>,
    /// auto, ebpf, ptrace (Linux), etw, debugger (Windows). On Windows,
    /// auto is etw; debugger (exact stacks) stops the target's threads at
    /// every breakpoint, for most of the window, and is used only when
    /// asked for.
    #[arg(long, value_name = "MECH", default_value = "auto")]
    pub mechanism: heapspy_record::MechanismChoice,
    /// Print a JSON report (schema version 1) on stdout. The summary lines
    /// on stderr are printed either way.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct FlamegraphArgs {
    /// Snapshot file.
    #[arg(
        value_name = "SNAP",
        required_unless_present_any = ["diff", "allocations"],
        conflicts_with_all = ["diff", "allocations"]
    )]
    pub snapshot: Option<PathBuf>,
    /// Differential flame graph: frames that grew from BEFORE to AFTER are
    /// red, frames that shrank are blue.
    #[arg(long, num_args = 2, value_names = ["BEFORE", "AFTER"])]
    pub diff: Option<Vec<PathBuf>>,
    /// Allocation flame graph of a profile from `heapspy record`: frames are
    /// Python functions, width is estimated bytes allocated.
    #[arg(long, value_name = "FILE.hpya", conflicts_with = "diff")]
    pub allocations: Option<PathBuf>,
    /// With --allocations: weigh each stack by the bytes of the objects in
    /// SNAP linked to its samples (where the memory still alive was
    /// allocated).
    #[arg(
        long,
        value_name = "SNAP",
        requires = "allocations",
        conflicts_with_all = ["snapshot", "diff"]
    )]
    pub retained: Option<PathBuf>,
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
    /// Fold frames narrower than P percent of the reachable bytes (with
    /// --allocations: of the total width) into `[other]` [default: 0.01].
    #[arg(long, value_name = "P", value_parser = parse_pct)]
    pub min_pct: Option<f64>,
    /// Fold objects more than N levels below a root into `[other]`. Not
    /// used with --allocations: allocation stacks are never cut.
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
    fn top_level_help_lists_every_command() {
        for c in Cli::command().get_subcommands() {
            let name = c.get_name();
            assert!(
                TOP_HELP.contains(&format!("\n  {name} ")),
                "{name} is missing from TOP_HELP"
            );
        }
    }

    #[test]
    fn analyze_takes_a_file_or_a_pid() {
        let ok = |a: &[&str]| Cli::try_parse_from(a).is_ok();
        assert!(ok(&["heapspy", "analyze", "s.hpy"]));
        assert!(ok(&["heapspy", "analyze", "--pid", "1"]));
        assert!(ok(&["heapspy", "analyze", "--pid", "1", "--keep", "a.hpy"]));
        assert!(!ok(&["heapspy", "analyze"]));
        assert!(!ok(&["heapspy", "analyze", "s.hpy", "--pid", "1"]));
        assert!(!ok(&["heapspy", "analyze", "s.hpy", "--keep", "a.hpy"]));
    }

    #[test]
    fn top_and_watch_arguments() {
        let Command::Top(t) = Cli::try_parse_from(["heapspy", "top", "--pid", "7"])
            .unwrap()
            .command
        else {
            panic!("not top");
        };
        assert_eq!(t.every, Duration::from_secs(10));
        assert!(!t.no_stop && !t.alloc);
        let Command::Watch(w) =
            Cli::try_parse_from(["heapspy", "watch", "--pid", "7", "--every", "5m"])
                .unwrap()
                .command
        else {
            panic!("not watch");
        };
        assert_eq!(w.every, Duration::from_secs(300));
        assert!(Cli::try_parse_from(["heapspy", "watch", "--pid", "7", "--every", "0s"]).is_err());
        assert!(Cli::try_parse_from(["heapspy", "watch", "--pid", "7", "--rounds", "1"]).is_err());
        assert!(Cli::try_parse_from(["heapspy", "--color", "never", "top", "--pid", "1"]).is_ok());
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
        assert_eq!(r.duration, Some(std::time::Duration::from_secs(60)));
        assert_eq!(r.pid, Some(1));
        assert_eq!(r.events, heapspy_alloc::EventKinds::DEFAULT);
        assert_eq!(r.interval, 512 * 1024);
        assert_eq!(r.native_min_size, 4096);
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
            &["--duration", "1s", "--native-min-size", "lots"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        // native is a valid event kind.
        assert!(parse(&["--duration", "1s", "--events", "native"]).is_ok());

        // --prepare / --unprepare need neither pid, duration nor output.
        let Command::Record(r) =
            Cli::try_parse_from(["heapspy", "record", "--prepare", "python.exe"])
                .unwrap()
                .command
        else {
            panic!("not record");
        };
        assert_eq!(r.prepare.as_deref(), Some("python.exe"));
        assert!(r.pid.is_none() && r.duration.is_none() && r.output.is_none());
        assert!(Cli::try_parse_from(["heapspy", "record", "--unprepare", "python.exe"]).is_ok());
        // Can't do both at once.
        assert!(Cli::try_parse_from([
            "heapspy",
            "record",
            "--prepare",
            "a.exe",
            "--unprepare",
            "a.exe"
        ])
        .is_err());
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
