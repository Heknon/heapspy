//! JSON report schema, version 1.
//!
//! These types are the stable machine interface of `heapspy ... --json`. Every
//! field is documented in `docs/json-schema.md`, with an example document per
//! report in `docs/examples/`. Rules:
//!
//! - Every report has `"schema_version": 1` and a `"kind"` string.
//! - Within schema version 1, fields are only ever *added*. Consumers must
//!   ignore fields they do not know. Removing or changing the meaning of a
//!   field requires schema version 2.
//! - Optional values are always present and `null` when unknown; they are
//!   never omitted.
//! - Byte counts and object counts are JSON integers. Addresses are lowercase
//!   hex strings with a `0x` prefix (`"0x7f3a2c41b0d0"`), because 64-bit
//!   values do not survive JSON number parsing in every language.
//! - Percentages are floats in `0.0..=100.0`.
//! - Arrays are ranked as documented (largest first) and bounded by `--top`.
//! - Fields added within version 1 are `Option`s with `#[serde(default)]`,
//!   so documents written before they existed still deserialize (to
//!   `None`). They are serialized as `null` when absent, like every other
//!   nullable field.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The current schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// `"schema_version": 1`. Deserializing any other value fails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchemaVersion;

impl Serialize for SchemaVersion {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(SCHEMA_VERSION)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = u32::deserialize(d)?;
        if v == SCHEMA_VERSION {
            Ok(SchemaVersion)
        } else {
            Err(serde::de::Error::custom(format!(
                "unsupported schema_version {v}, expected {SCHEMA_VERSION}"
            )))
        }
    }
}

macro_rules! kind_marker {
    ($(#[$m:meta])* $name:ident = $lit:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            #[default]
            #[serde(rename = $lit)]
            Kind,
        }
    };
}

kind_marker!(
    /// `"kind": "analyze"`
    AnalyzeKind = "analyze"
);
kind_marker!(
    /// `"kind": "type_query"`
    TypeQueryKind = "type_query"
);
kind_marker!(
    /// `"kind": "retaining_path"`
    RetainingPathKind = "retaining_path"
);
kind_marker!(
    /// `"kind": "diff"`
    DiffKind = "diff"
);
kind_marker!(
    /// `"kind": "dump"`
    DumpKind = "dump"
);
kind_marker!(
    /// `"kind": "record"`
    RecordKind = "record"
);
kind_marker!(
    /// `"kind": "error"`
    ErrorKind = "error"
);
kind_marker!(
    /// `"kind": "locate"`
    LocateKind = "locate"
);

/// A target address, serialized as `"0x..."` lowercase hex.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(pub u64);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl FromStr for Address {
    type Err = String;
    /// Accepts `0x`-prefixed hex (any case). Plain decimal is rejected to
    /// avoid ambiguity.
    fn from_str(s: &str) -> Result<Self, String> {
        let hex = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .ok_or_else(|| format!("address {s:?} must start with 0x"))?;
        u64::from_str_radix(hex, 16)
            .map(Address)
            .map_err(|e| format!("bad address {s:?}: {e}"))
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Where the snapshot came from (`snapshot.source`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    /// `"pid"`, `"core"` or `"minidump"`.
    pub kind: String,
    /// The PID as text, or the input path as given to `heapspy dump`.
    #[serde(rename = "ref")]
    pub reference: String,
}

/// Facts about one snapshot file (`snapshot`, or `before` / `after` in a diff).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSummary {
    /// Path of the snapshot file as given on the command line.
    pub path: String,
    pub format_version: u16,
    /// `sys.version`-style: `"3.12.4"`, `"3.13.0rc1"`.
    pub python_version: String,
    /// `"linux"`, `"windows"`, `"macos"`.
    pub os: String,
    /// `"x86_64"`, `"aarch64"`.
    pub arch: String,
    pub pointer_size: u8,
    /// Unix seconds when the memory image was taken.
    pub captured_at: u64,
    pub source: SourceRef,
    /// String/bytes contents and ordinary dict keys were captured.
    pub contents_captured: bool,
    /// The dump did not finish; the graph is incomplete.
    pub truncated: bool,
}

/// Where an object or a type is defined in the target's source, as recorded
/// in the snapshot (`source_loc`, `type_location`).
///
/// `file` is `co_filename` (or a module's `__file__`) exactly as the target
/// recorded it: relative or absolute depending on how the program was
/// started and imported.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    /// 1-based line. For a class (`via: "methods"`), the smallest
    /// `co_firstlineno` of its methods: the class statement is at or before
    /// it. `null` for a module (`via: "module_file"`).
    pub line: Option<u32>,
    /// True when `file` and `line` are the object's own recorded location;
    /// false when derived (a class located through its methods).
    pub exact: bool,
    /// How the location was found: `"code_object"`, `"function"`, `"method"`,
    /// `"methods"` or `"module_file"`.
    pub via: String,
}

impl SourceLocation {
    /// `file:line`, `file:~line` when not exact, or `file` without a line.
    pub fn display(&self) -> String {
        match (self.line, self.exact) {
            (Some(l), true) => format!("{}:{l}", self.file),
            (Some(l), false) => format!("{}:~{l}", self.file),
            (None, _) => self.file.clone(),
        }
    }
}

/// One hop of a retaining path. Paths are listed root first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathHop {
    pub address: Address,
    /// `module.qualname` of the object at this hop, e.g. `"builtins.dict"`.
    #[serde(rename = "type")]
    pub type_name: String,
    pub shallow_bytes: u64,
    /// Rendered label of the edge from the previous hop to this one, e.g.
    /// `".payload"`, `"['cache']"`, `"[3]"`. `null` on the first hop.
    pub edge: Option<String>,
    /// Root description, e.g. `"sys.modules['app.cache']"`. Only on the first hop.
    pub root_label: Option<String>,
    /// Root kind (`"module_dict"`, `"thread_locals"`, `"frame_local"`,
    /// `"interp"`, `"other"`). Only on the first hop.
    pub root_kind: Option<String>,
    /// Where the object at this hop is defined, for functions, methods,
    /// code objects, classes and modules; `null` otherwise or when unknown.
    #[serde(default)]
    pub source_loc: Option<SourceLocation>,
    /// Why `source_loc` is `null` for an object of one of those kinds (a
    /// code from the schema doc, e.g. `"no_python_methods"`); `null` when
    /// `source_loc` is set or the object is of another kind.
    #[serde(default)]
    pub source_loc_reason: Option<String>,
}

/// A path from a root to an object: `hops[0]` is the root object, the last
/// hop is the object itself.
pub type RetainingPath = Vec<PathHop>;

/// A non-fatal remark about the analysis (`notes[]`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// Stable machine-readable code, e.g. `"untracked_objects"`. See the schema doc.
    pub code: String,
    /// Human-readable text. Wording may change between releases.
    pub message: String,
}

// ---------------------------------------------------------------- analyze

/// `heapspy analyze --json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnalyzeReport {
    pub schema_version: SchemaVersion,
    pub kind: AnalyzeKind,
    pub snapshot: SnapshotSummary,
    pub totals: Totals,
    pub memory: MemoryTotals,
    /// Objects with the largest retained size, largest first. At most `--top`.
    pub top_retainers: Vec<Retainer>,
    /// Types by retained bytes, largest first. At most `--top`.
    pub type_histogram: Vec<TypeRow>,
    /// Types by their own (shallow) bytes, largest first, unreachable
    /// instances included: what the memory is made of. At most `--top`.
    /// Added in 0.3; empty in older documents.
    #[serde(default)]
    pub types_by_size: Vec<TypeRow>,
    pub notes: Vec<Note>,
    /// What an allocation profile (`--allocations`) says about where the
    /// memory came from. `null` without `--allocations`.
    #[serde(default)]
    pub allocations: Option<Allocations>,
}

/// Graph-wide counts (`totals`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub objects: u64,
    pub edges: u64,
    pub types: u64,
    pub roots: u64,
    /// Sum of shallow sizes of all objects in the snapshot.
    pub shallow_bytes: u64,
    /// Objects reachable from any root.
    pub reachable_objects: u64,
    /// Sum of shallow sizes of reachable objects.
    pub reachable_bytes: u64,
    /// Objects reachable from no root but held from outside the recorded
    /// graph, as their refcounts show: native code, C globals, memory the
    /// walker could not lay out. They appear under the root
    /// `held outside the Python graph`. 0 without refcounts.
    #[serde(default)]
    pub external_objects: u64,
    #[serde(default)]
    pub external_bytes: u64,
    /// Objects neither reachable nor held from outside. With refcounts, their
    /// owners are all each other: cyclic garbage the collector will free.
    /// Without refcounts, this also holds what `external_*` would have.
    pub unreachable_objects: u64,
    pub unreachable_bytes: u64,
    /// Edges whose target address is not an object in the snapshot.
    pub dangling_edges: u64,
    /// Whether references were checked against refcounts (snapshots from
    /// heapspy builds that record them).
    #[serde(default)]
    pub refcounts_checked: bool,
    /// Edges dropped by that check: fields of unknown layout that borrow
    /// rather than own, and out-of-line pointers that were stale.
    #[serde(default)]
    pub borrowed_edges_dropped: u64,
    #[serde(default)]
    pub stale_edges_dropped: u64,
    /// Out-of-line references kept (found in memory an object points at but
    /// does not lay out, such as a deque's blocks).
    #[serde(default)]
    pub out_of_line_edges: u64,
    /// Native heap blocks recorded (what `malloc` handed out, apart from
    /// Python objects), and their bytes. 0 when the source could not walk
    /// its heaps. They are counted in `objects` and `shallow_bytes`, and the
    /// reachable ones in `reachable_*`.
    #[serde(default)]
    pub native_blocks: u64,
    #[serde(default)]
    pub native_bytes: u64,
    /// Native blocks nothing points to: not from a Python object, another
    /// block, a module's globals or a thread's stack. Memory whose address
    /// the program no longer has anywhere: leaked. Not in `unreachable_*`.
    #[serde(default)]
    pub native_lost_blocks: u64,
    #[serde(default)]
    pub native_lost_bytes: u64,
}

/// Process memory vs. the Python graph (`memory`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryTotals {
    /// Resident set size of the process, if the source knew it.
    pub rss_bytes: Option<u64>,
    /// Bytes accounted for by the object graph (`totals.shallow_bytes`).
    pub graph_bytes: u64,
    /// `rss_bytes - graph_bytes`, floored at 0. `null` without `rss_bytes`.
    pub outside_graph_bytes: Option<u64>,
    /// `outside_graph_bytes / rss_bytes * 100`. `null` without `rss_bytes`.
    pub outside_graph_pct: Option<f64>,
    /// What the process's memory is, by kind. Empty if the source had no
    /// memory map.
    #[serde(default)]
    pub breakdown: Vec<MemoryPart>,
    /// Whether `breakdown` counts resident bytes (`"resident"`) or, where the
    /// source does not record residency (Windows), committed bytes
    /// (`"committed"`). Committed memory can be larger than RSS.
    #[serde(default)]
    pub breakdown_basis: Option<String>,
    /// Native heap blocks nothing points to (leaked), grouped by block size,
    /// most bytes first. At most `--top`. Empty without a heap walk.
    #[serde(default)]
    pub native_lost_by_size: Vec<SizeGroup>,
    /// What the heap walk found about the native allocator's free memory.
    /// `null` when the heaps were not walked or the walker does not read
    /// free lists (Windows).
    #[serde(default)]
    pub native_allocator: Option<NativeAllocator>,
}

/// One entry of `memory.native_lost_by_size`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeGroup {
    /// Block size in bytes, allocator header included.
    pub size: u64,
    pub blocks: u64,
    pub bytes: u64,
}

/// `memory.native_allocator`: memory the native allocator holds but has not
/// handed out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAllocator {
    /// Heaps or arenas found (glibc: the main arena and one per thread arena).
    pub arenas: u64,
    /// Free chunks in the heaps (bins, tcache, fastbins).
    pub free_chunks: u64,
    /// Their bytes, as the chunk headers say (may include pages that are
    /// not resident).
    pub free_bytes: u64,
    /// Bytes of the heaps' top chunks: the unused tail each heap grows into.
    pub top_bytes: u64,
}

/// One line of `memory.breakdown`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPart {
    /// `images`, `mapped_files`, `stacks`, `python_small_objects`,
    /// `pymalloc_free`, `python_large_objects`, `native_heap`,
    /// `native_unknown` (the rest of private memory, when the native heap is
    /// not split out).
    pub part: String,
    pub bytes: u64,
}

/// One entry of `top_retainers`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Retainer {
    /// 1-based position in the list.
    pub rank: u32,
    pub address: Address,
    #[serde(rename = "type")]
    pub type_name: String,
    pub shallow_bytes: u64,
    /// Bytes freed if this object were freed: the shallow size of every
    /// object it dominates, itself included.
    pub retained_bytes: u64,
    /// Number of objects it dominates, itself included.
    pub retained_objects: u64,
    /// `retained_bytes / totals.reachable_bytes * 100`.
    pub retained_pct: f64,
    /// Shortest retaining path from a root to this object.
    pub path: RetainingPath,
    /// The part of `retained_bytes` that is native heap blocks (memory C
    /// code allocated) rather than Python objects. `null` in reports
    /// written before this field existed.
    #[serde(default)]
    pub native_retained_bytes: Option<u64>,
    /// Allocation stacks of the sampled objects this entry retains. `null`
    /// without `--allocations`.
    #[serde(default)]
    pub allocated_at: Option<AllocatedAt>,
    /// Where the object's type (class) is defined.
    #[serde(default)]
    pub type_location: Option<SourceLocation>,
    /// Why `type_location` is `null`.
    #[serde(default)]
    pub type_location_reason: Option<String>,
}

/// One entry of `type_histogram`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeRow {
    #[serde(rename = "type")]
    pub type_name: String,
    pub count: u64,
    pub shallow_bytes: u64,
    /// Retained bytes of the set of all instances: the sum of `retained_bytes`
    /// over instances not dominated by another instance of the same type.
    pub retained_bytes: u64,
    /// Where the type (class) is defined.
    #[serde(default)]
    pub type_location: Option<SourceLocation>,
    /// Why `type_location` is `null`.
    #[serde(default)]
    pub type_location_reason: Option<String>,
    /// Instances nothing reaches, and their shallow bytes. For native heap
    /// blocks (`native.*`) these are leaked: nothing points to them. Added
    /// in 0.3; `null` in older documents.
    #[serde(default)]
    pub unreachable_count: Option<u64>,
    #[serde(default)]
    pub unreachable_bytes: Option<u64>,
    /// The entry of `top_retainers` (by its root path) whose dominator
    /// subtree holds the most of this type's shallow bytes, and those bytes.
    /// `null` when no listed retainer holds any instance. Added in 0.3.
    #[serde(default)]
    pub held_by: Option<String>,
    /// `rank` of that entry in `top_retainers`.
    #[serde(default)]
    pub held_by_rank: Option<u32>,
    #[serde(default)]
    pub held_by_bytes: Option<u64>,
}

// ---------------------------------------------------------------- allocations

/// `allocations` on an analyze report: the allocation profile given with
/// `--allocations`, joined with the snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Allocations {
    /// Path of the `.hpya` file as given on the command line.
    pub path: String,
    /// Process the samples were recorded from.
    pub pid: u32,
    /// `sys.version`-style CPython version recorded in the profile.
    pub python_version: String,
    /// Unix seconds when recording started.
    pub started_at: u64,
    /// Length of the recording window in milliseconds.
    pub duration_ms: u64,
    /// Mechanisms that ran: `"ebpf"`, `"ptrace"`, `"etw"`, `"debugger"`.
    pub mechanisms: Vec<String>,
    pub sampling: SamplingInfo,
    pub overhead: OverheadInfo,
    /// Recording stopped early or lost samples the overhead does not count.
    pub truncated: bool,
    /// Some Python frames were matched to events by time (ETW) rather than
    /// read at the event; stacks marked `approximate` may be off by a call.
    pub approximate: bool,
    /// Samples in the profile.
    pub samples: u64,
    /// Sum of sample weights: estimated bytes allocated through the sampled
    /// events during the window.
    pub estimated_bytes: u64,
    /// How much of the snapshot the samples explain.
    pub coverage: Coverage,
    /// Allocation stacks by `estimated_bytes`, largest first. At most `--top`.
    pub top_stacks: Vec<AllocationStack>,
}

/// `allocations.sampling`: how the recorder sampled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingInfo {
    /// Event kinds enabled: `"arena"`, `"pool"`, `"large_object"`.
    pub events: Vec<String>,
    /// Mean bytes between large-object samples; 0 means every one was kept.
    pub byte_interval: u64,
    /// Most Python frames kept per sample.
    pub max_frames: u32,
}

/// `allocations.overhead`: what recording cost, as measured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverheadInfo {
    pub samples_taken: u64,
    pub samples_dropped: u64,
    pub probe_hits: u64,
    /// Total time target threads were stopped, summed over threads.
    pub total_pause_ns: u64,
}

/// `allocations.coverage`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    /// Reachable objects whose address falls in a sampled allocation.
    pub linked_objects: u64,
    /// Their shallow bytes.
    pub linked_bytes: u64,
    /// `linked_bytes / totals.reachable_bytes * 100`.
    pub linked_pct: f64,
    /// The part of `linked_objects` linked through large-object samples,
    /// which cover exactly one allocation. The rest is linked through arena
    /// and pool samples: the most recent growth event that created the
    /// memory, not necessarily the call that allocated the object.
    pub exact_linked_objects: u64,
    /// Shallow bytes of `exact_linked_objects`.
    pub exact_linked_bytes: u64,
    /// Reachable objects that are not linked because the latest sample
    /// covering their address is a large-object sample they do not match
    /// (another start or size): the sampled block was freed and the memory
    /// reused by an allocation that was not sampled. Missing (0) in
    /// documents from heapspy versions before this field.
    #[serde(default)]
    pub unlinked_reused_objects: u64,
    /// Shallow bytes of `unlinked_reused_objects`.
    #[serde(default)]
    pub unlinked_reused_bytes: u64,
}

/// One Python frame of an allocation stack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrame {
    /// `co_qualname`, e.g. `"Cache.load"`; `"<unknown>"` if the code
    /// object could not be read.
    pub function: String,
    /// `co_filename`; `null` if unknown.
    pub file: Option<String>,
    /// Line of the executing instruction; `null` if unknown.
    pub line: Option<u32>,
    /// `file:line`, `file:?` without a line, or `"<unknown>"`.
    pub location: String,
    /// Matched to the event by time, not read at the event.
    pub approximate: bool,
}

/// One entry of `allocations.top_stacks`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationStack {
    /// 1-based position in the list.
    pub rank: u32,
    /// Innermost first: `frames[0]` is the function that allocated.
    pub frames: Vec<StackFrame>,
    /// Sum of the weights of this stack's samples.
    pub estimated_bytes: u64,
    pub samples: u64,
    /// Event kinds among the samples, sorted: `"arena"`, `"pool"`, `"large_object"`.
    pub events: Vec<String>,
    /// Shallow bytes of reachable snapshot objects linked to these samples.
    pub linked_bytes: u64,
    /// The part of `linked_bytes` linked through large-object samples
    /// (exact links); the rest came through arena and pool samples.
    pub exact_linked_bytes: u64,
    /// Any frame of any sample was approximate.
    pub approximate: bool,
}

/// `allocated_at` on a retainer or instance: which stacks allocated the
/// sampled objects in its dominator subtree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocatedAt {
    /// Objects in the subtree linked to a sample.
    pub linked_objects: u64,
    /// Their shallow bytes.
    pub linked_bytes: u64,
    /// The part of `linked_bytes` linked through large-object samples.
    pub exact_linked_bytes: u64,
    /// Stacks by `linked_bytes`, largest first. At most 5.
    pub stacks: Vec<AllocatedAtStack>,
    /// Any listed stack is approximate.
    pub approximate: bool,
}

/// One entry of `allocated_at.stacks`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocatedAtStack {
    /// Innermost first.
    pub frames: Vec<StackFrame>,
    /// Linked objects in the subtree allocated through this stack.
    pub linked_objects: u64,
    pub linked_bytes: u64,
    /// The part of `linked_bytes` linked through large-object samples.
    pub exact_linked_bytes: u64,
    /// `rank` of the same stack in `allocations.top_stacks`, if listed there.
    pub top_stack_rank: Option<u32>,
}

// ---------------------------------------------------------------- query --type

/// `heapspy query --type T --json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeQueryReport {
    pub schema_version: SchemaVersion,
    pub kind: TypeQueryKind,
    pub snapshot: SnapshotSummary,
    /// The type name as given on the command line.
    pub query: String,
    /// Full names of the types that matched (an unqualified name can match
    /// several), sorted.
    pub matched_types: Vec<String>,
    /// Where each matched type is defined, in the order of `matched_types`.
    #[serde(default)]
    pub matched_type_locations: Vec<TypeLocation>,
    pub instances: u64,
    pub shallow_bytes: u64,
    /// Retained bytes of the set of instances, as in `TypeRow::retained_bytes`.
    pub retained_bytes: u64,
    /// Largest instances by retained size, largest first.
    pub top_instances: Vec<Instance>,
    /// Who holds the instances: direct referrers grouped by referrer type and
    /// edge label, by count, largest first.
    pub holders: Vec<Holder>,
    /// The instances grouped by what keeps them alive: the holder whose
    /// dominator subtree they are in, and the path from it to them. Most
    /// bytes first, at most `--top`. Added in 0.3; empty in older documents.
    #[serde(default)]
    pub kept_by: Vec<KeptBy>,
    /// The instances grouped by shallow size, most bytes first, at most
    /// `--top`. Added in 0.3.
    #[serde(default)]
    pub by_size: Vec<SizeGroup>,
    pub notes: Vec<Note>,
}

/// One entry of `kept_by`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeptBy {
    /// `"holder"`: in the dominator subtree of `holder`, one of the largest
    /// disjoint holders of the heap (as `top_retainers` lists them).
    /// `"other"`: reachable, but under none of those (held by many small
    /// holders). `"unreachable"`: nothing reaches them (for native blocks:
    /// leaked; for Python objects: garbage awaiting collection).
    pub kind: String,
    /// Root path of the holder; `null` unless `kind` is `"holder"`.
    pub holder: Option<String>,
    pub holder_address: Option<Address>,
    /// The most common path from the holder to the instances, with keys
    /// and indices generalised and the type reached after each hop, e.g.
    /// `"[<key>] app.session.Session → .payload"`. For `"other"`, the most
    /// common path from a root. `null` for `"unreachable"`.
    pub through: Option<String>,
    /// Share of the sampled instances that `through` describes, in whole
    /// percent.
    pub through_pct: Option<u32>,
    pub instances: u64,
    /// Their shallow bytes.
    pub bytes: u64,
    /// Their sizes, most bytes first, at most 3.
    pub sizes: Vec<SizeGroup>,
}

/// One entry of `top_instances`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instance {
    pub address: Address,
    #[serde(rename = "type")]
    pub type_name: String,
    pub shallow_bytes: u64,
    pub retained_bytes: u64,
    /// `len()` if recorded.
    pub length: Option<u64>,
    /// Shortest retaining path; `null` if the instance is unreachable.
    pub path: Option<RetainingPath>,
    /// Allocation stacks of the sampled objects this instance retains.
    /// `null` without `--allocations`.
    #[serde(default)]
    pub allocated_at: Option<AllocatedAt>,
    /// Where the instance itself is defined, when it is a function, method,
    /// code object, class or module.
    #[serde(default)]
    pub source_loc: Option<SourceLocation>,
    /// Why `source_loc` is `null` for such an instance.
    #[serde(default)]
    pub source_loc_reason: Option<String>,
}

/// One entry of `matched_type_locations`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeLocation {
    #[serde(rename = "type")]
    pub type_name: String,
    pub type_location: Option<SourceLocation>,
    pub type_location_reason: Option<String>,
}

/// One entry of `holders`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holder {
    /// Type of the referring object.
    #[serde(rename = "type")]
    pub type_name: String,
    /// Rendered edge label from the referrer to the instance, e.g. `"['user:8812']"`.
    /// Dict keys and list indices are generalised (`"[<key>]"`, `"[<index>]"`)
    /// so that one container holding many instances gives one row.
    pub edge: String,
    /// Instances held this way.
    pub count: u64,
}

// ---------------------------------------------------------------- query --retaining-path

/// `heapspy query --retaining-path ADDR --json` (and the type form).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainingPathReport {
    pub schema_version: SchemaVersion,
    pub kind: RetainingPathKind,
    pub snapshot: SnapshotSummary,
    pub query: PathQuery,
    /// One entry for an address query; up to `--top` instances for a type query.
    pub targets: Vec<PathTarget>,
    pub notes: Vec<Note>,
}

/// What was asked for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathQuery {
    pub by: PathQueryBy,
    /// The address (`"0x..."`) or type name as given.
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathQueryBy {
    Address,
    Type,
}

/// One object and the paths that keep it alive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathTarget {
    pub address: Address,
    #[serde(rename = "type")]
    pub type_name: String,
    pub shallow_bytes: u64,
    pub retained_bytes: u64,
    /// False if no root reaches the object; `paths` is then empty.
    pub reachable: bool,
    /// Shortest paths first; distinct in their first differing hop.
    pub paths: Vec<RetainingPath>,
    /// Where the object's type (class) is defined.
    #[serde(default)]
    pub type_location: Option<SourceLocation>,
    /// Why `type_location` is `null`.
    #[serde(default)]
    pub type_location_reason: Option<String>,
}

// ---------------------------------------------------------------- query --locate

/// `heapspy query --locate NAME --json`: where the type, function or module
/// with that `module.qualname` is defined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocateReport {
    pub schema_version: SchemaVersion,
    pub kind: LocateKind,
    pub snapshot: SnapshotSummary,
    /// The name as given on the command line.
    pub query: String,
    /// Objects with that name: types first, then functions, then modules.
    /// Functions with the same location are listed once. At most `--top`.
    pub matches: Vec<LocateMatch>,
    pub notes: Vec<Note>,
}

/// One entry of `matches`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocateMatch {
    /// `"type"`, `"function"` or `"module"`.
    pub kind: String,
    /// The full `module.qualname`; equal to the query.
    pub name: String,
    /// The module part of `name` (for a module, `name` itself).
    pub module: String,
    /// The part after the module; empty for a module.
    pub qualname: String,
    pub address: Address,
    pub source_loc: Option<SourceLocation>,
    pub source_loc_reason: Option<String>,
}

// ---------------------------------------------------------------- diff

/// `heapspy diff BEFORE AFTER --json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    pub schema_version: SchemaVersion,
    pub kind: DiffKind,
    /// Always `true`: objects are matched by type and retaining site, not by
    /// identity, because addresses change between dumps.
    pub identity_approximate: bool,
    pub before: SnapshotSummary,
    pub after: SnapshotSummary,
    pub totals: DiffTotals,
    /// Types sorted by `delta_bytes`, largest growth first.
    pub by_type: Vec<TypeGrowth>,
    /// Retaining sites sorted by `delta_retained_bytes`, largest growth first.
    pub by_site: Vec<SiteGrowth>,
    pub notes: Vec<Note>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffTotals {
    pub before: DiffSide,
    pub after: DiffSide,
    pub delta_objects: i64,
    pub delta_shallow_bytes: i64,
    pub delta_reachable_bytes: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSide {
    pub objects: u64,
    pub shallow_bytes: u64,
    pub reachable_bytes: u64,
}

/// One entry of `by_type`. Counts and shallow bytes of all instances.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeGrowth {
    #[serde(rename = "type")]
    pub type_name: String,
    pub before_count: u64,
    pub after_count: u64,
    pub delta_count: i64,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub delta_bytes: i64,
}

/// One entry of `by_site`: an object identified by its rendered root path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteGrowth {
    /// The rendered retaining path, e.g. `"sys.modules['app.cache'].__dict__['CACHE']"`.
    /// This string is the match key between the two snapshots.
    pub site: String,
    /// Type of the object at the site in the `after` snapshot (or `before` if gone).
    #[serde(rename = "type")]
    pub type_name: String,
    pub before_retained_bytes: u64,
    pub after_retained_bytes: u64,
    pub delta_retained_bytes: i64,
    pub before_retained_objects: u64,
    pub after_retained_objects: u64,
    pub delta_retained_objects: i64,
}

// ---------------------------------------------------------------- dump

/// `heapspy dump --json`, printed after the snapshot is written.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DumpReport {
    pub schema_version: SchemaVersion,
    pub kind: DumpKind,
    /// The snapshot file written, as given with `-o`.
    pub path: String,
    pub source: SourceRef,
    /// CPython version found in the target, `sys.version` style.
    pub python_version: String,
    /// `--capture-contents` was given.
    pub contents_captured: bool,
    pub objects: u64,
    pub edges: u64,
    pub types: u64,
    pub roots: u64,
    /// Size of the snapshot file.
    pub bytes_written: u64,
    /// Reads of target memory that failed; the objects involved are partial.
    pub read_errors: u64,
    /// The snapshot is marked truncated (same as `snapshot.truncated` in the
    /// other reports).
    pub truncated: bool,
    pub image: DumpImage,
    /// How long a live target was stopped, in milliseconds. `null` for core
    /// files and minidumps, and where the backend does not measure it.
    pub pause_ms: Option<f64>,
    pub notes: Vec<Note>,
}

/// Facts about the memory image a dump read (`image`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpImage {
    /// Bytes of memory the image's own headers describe but the file does
    /// not contain (a core cut short). 0 when complete or unknown.
    pub missing_bytes: u64,
}

// ---------------------------------------------------------------- record

/// `heapspy record --json`, printed after the profile (and the
/// `--then-dump` snapshot, if asked for) is written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordReport {
    pub schema_version: SchemaVersion,
    pub kind: RecordKind,
    /// The allocation profile written, as given with `-o`.
    pub path: String,
    /// Process recorded.
    pub pid: u32,
    /// CPython version found in the target, `sys.version` style.
    pub python_version: String,
    /// Measured length of the recording window, in milliseconds.
    pub duration_ms: u64,
    /// Mechanisms that ran: `"ebpf"`, `"ptrace"`, `"etw"`, `"debugger"`.
    pub mechanisms: Vec<String>,
    /// Same as `allocations.sampling` in the analyze report.
    pub sampling: SamplingInfo,
    /// Samples written to the profile.
    pub samples: u64,
    /// Size of the profile file.
    pub bytes_written: u64,
    /// Same as `allocations.overhead` in the analyze report.
    pub overhead: OverheadInfo,
    /// Recording stopped early or lost samples the overhead does not count.
    pub truncated: bool,
    /// The `--then-dump` snapshot written, as given; `null` without it.
    pub then_dump: Option<String>,
}

// ---------------------------------------------------------------- error

/// Printed to stdout by any `--json` command that fails, before exiting non-zero.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorReport {
    pub schema_version: SchemaVersion,
    pub kind: ErrorKind,
    pub error: ErrorBody,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// A stable code from the table in `docs/json-schema.md`, e.g.
    /// `"not_found"`, `"not_python"`, `"permission_denied"`, `"internal"`.
    pub code: String,
    pub message: String,
}

impl ErrorReport {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            schema_version: SchemaVersion,
            kind: ErrorKind::Kind,
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}
