//! Public value types shared by the writer and the reader.

use std::fmt;
use std::str::FromStr;

pub use heapspy_snapshot::{Arch, Os, PythonVersion};

use crate::format::{NO_BLOB, NO_CODE, NO_STRING};

/// Index into the profile's string table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StrId(pub u32);

/// Index into the profile's blob table (raw bytes, e.g. line tables).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobId(pub u32);

/// Index into the profile's code table: the position of the entry in the
/// codes section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CodeId(pub u32);

pub(crate) fn enc_str(s: Option<StrId>) -> u32 {
    s.map_or(NO_STRING, |s| s.0)
}
pub(crate) fn dec_str(raw: u32) -> Option<StrId> {
    (raw != NO_STRING).then_some(StrId(raw))
}
pub(crate) fn enc_blob(b: Option<BlobId>) -> u32 {
    b.map_or(NO_BLOB, |b| b.0)
}
pub(crate) fn dec_blob(raw: u32) -> Option<BlobId> {
    (raw != NO_BLOB).then_some(BlobId(raw))
}
pub(crate) fn enc_code(c: Option<CodeId>) -> u32 {
    c.map_or(NO_CODE, |c| c.0)
}
pub(crate) fn dec_code(raw: u32) -> Option<CodeId> {
    (raw != NO_CODE).then_some(CodeId(raw))
}

// ---------------------------------------------------------------- events

/// What kind of allocator event a sample records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// Anything not covered below (a recorder-specific probe).
    #[default]
    Other,
    /// A pymalloc arena was mapped (`mmap` / `VirtualAlloc`, 1 MiB on 3.10+).
    Arena,
    /// pymalloc carved a new 16 KiB pool for one size class out of an arena.
    Pool,
    /// An allocation above pymalloc's small-object threshold (512 bytes) went
    /// to the system allocator.
    LargeObject,
    /// A code this build does not know. Kept so newer files still open.
    Unknown(u8),
}

impl EventKind {
    /// The kinds this build knows, in code order.
    pub const ALL: [EventKind; 4] = [
        EventKind::Other,
        EventKind::Arena,
        EventKind::Pool,
        EventKind::LargeObject,
    ];

    pub fn code(self) -> u8 {
        match self {
            EventKind::Other => 0,
            EventKind::Arena => 1,
            EventKind::Pool => 2,
            EventKind::LargeObject => 3,
            EventKind::Unknown(c) => c,
        }
    }

    pub fn from_code(code: u8) -> Self {
        match code {
            0 => EventKind::Other,
            1 => EventKind::Arena,
            2 => EventKind::Pool,
            3 => EventKind::LargeObject,
            c => EventKind::Unknown(c),
        }
    }

    /// Lowercase name used in JSON reports and on the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Other => "other",
            EventKind::Arena => "arena",
            EventKind::Pool => "pool",
            EventKind::LargeObject => "large_object",
            EventKind::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EventKind {
    type Err = String;
    /// Accepts `arena`, `pool`, `large_object` (or `large`) and `other`.
    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s {
            "arena" => EventKind::Arena,
            "pool" => EventKind::Pool,
            "large" | "large_object" => EventKind::LargeObject,
            "other" => EventKind::Other,
            _ => {
                return Err(format!(
                    "unknown event kind {s:?} (expected arena, pool, large or other)"
                ))
            }
        })
    }
}

/// A set of event kinds: bit `1 << kind.code()` for each kind. Stored in the
/// header as the kinds the recorder had enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EventKinds(pub u32);

impl EventKinds {
    pub const NONE: EventKinds = EventKinds(0);

    /// The default for `heapspy record`: arenas and large objects. Pool
    /// probes need a symbol that some builds inline, so they are opt-in.
    pub const DEFAULT: EventKinds = EventKinds((1 << 1) | (1 << 3));

    pub fn of(kinds: &[EventKind]) -> Self {
        let mut s = Self::NONE;
        for &k in kinds {
            s.insert(k);
        }
        s
    }

    pub fn insert(&mut self, k: EventKind) {
        if k.code() < 32 {
            self.0 |= 1 << k.code();
        }
    }

    pub fn contains(self, k: EventKind) -> bool {
        k.code() < 32 && self.0 & (1 << k.code()) != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The kinds in the set, in code order, including unknown bits.
    pub fn iter(self) -> impl Iterator<Item = EventKind> {
        (0..32u8)
            .filter(move |c| self.0 & (1 << c) != 0)
            .map(EventKind::from_code)
    }
}

impl FromStr for EventKinds {
    type Err = String;
    /// A comma-separated list, e.g. `arena,large`.
    fn from_str(s: &str) -> Result<Self, String> {
        let mut set = EventKinds::NONE;
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            set.insert(part.parse()?);
        }
        if set.is_empty() {
            return Err("no event kinds given".into());
        }
        Ok(set)
    }
}

// ---------------------------------------------------------------- mechanisms

/// One way of observing allocations from outside the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mechanism {
    /// Linux eBPF: tracepoints and uprobes, Python stack read in the kernel.
    Ebpf,
    /// Linux ptrace breakpoints on the arena path (fallback without eBPF).
    Ptrace,
    /// Windows Event Tracing: VirtualAlloc and heap events with native stacks.
    Etw,
    /// Windows debugger breakpoints (`DebugActiveProcess`) on the arena path.
    Debugger,
}

impl Mechanism {
    pub const ALL: [Mechanism; 4] = [
        Mechanism::Ebpf,
        Mechanism::Ptrace,
        Mechanism::Etw,
        Mechanism::Debugger,
    ];

    /// Bit in the header's `mechanisms` field.
    pub fn bit(self) -> u32 {
        match self {
            Mechanism::Ebpf => 1 << 0,
            Mechanism::Ptrace => 1 << 1,
            Mechanism::Etw => 1 << 2,
            Mechanism::Debugger => 1 << 3,
        }
    }

    /// Lowercase name used in JSON reports and on the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::Ebpf => "ebpf",
            Mechanism::Ptrace => "ptrace",
            Mechanism::Etw => "etw",
            Mechanism::Debugger => "debugger",
        }
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Mechanism {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Mechanism::ALL
            .into_iter()
            .find(|m| m.as_str() == s)
            .ok_or_else(|| {
                format!("unknown mechanism {s:?} (expected ebpf, ptrace, etw or debugger)")
            })
    }
}

/// The set of mechanisms a recording used (header `mechanisms`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Mechanisms(pub u32);

impl Mechanisms {
    pub const NONE: Mechanisms = Mechanisms(0);

    pub fn of(ms: &[Mechanism]) -> Self {
        Mechanisms(ms.iter().fold(0, |acc, m| acc | m.bit()))
    }

    pub fn insert(&mut self, m: Mechanism) {
        self.0 |= m.bit();
    }

    pub fn contains(self, m: Mechanism) -> bool {
        self.0 & m.bit() != 0
    }

    /// Known mechanisms in the set, in bit order. Unknown bits are skipped.
    pub fn iter(self) -> impl Iterator<Item = Mechanism> {
        Mechanism::ALL
            .into_iter()
            .filter(move |m| self.contains(*m))
    }

    /// Whether any mechanism in the set attributes Python frames by time
    /// rather than at the event (ETW).
    pub fn may_be_approximate(self) -> bool {
        self.contains(Mechanism::Etw)
    }
}

// ---------------------------------------------------------------- header

/// How the recorder sampled (header `events`, `byte_interval`, `max_frames`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SamplingParams {
    /// Event kinds the recorder had enabled.
    pub events: EventKinds,
    /// Mean bytes between kept large-object samples. 0 means every event was
    /// kept. Arena and pool events are never sub-sampled.
    pub byte_interval: u64,
    /// Most Python frames recorded per sample, innermost first.
    pub max_frames: u32,
}

impl SamplingParams {
    /// Provisional defaults for `heapspy record`, until the M7 spike
    /// measures the overhead: arenas and large objects, a 512 KiB byte
    /// interval, 64 frames.
    pub const DEFAULT: SamplingParams = SamplingParams {
        events: EventKinds::DEFAULT,
        byte_interval: DEFAULT_BYTE_INTERVAL,
        max_frames: DEFAULT_MAX_FRAMES,
    };
}

impl Default for SamplingParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Default `--interval`: 512 KiB.
pub const DEFAULT_BYTE_INTERVAL: u64 = 512 * 1024;
/// Default `--max-frames`.
pub const DEFAULT_MAX_FRAMES: u32 = 64;

/// What recording cost, measured by the recorder.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Overhead {
    /// Samples that reached the writer. Normally equals the samples count.
    pub samples_taken: u64,
    /// Samples lost before reaching the writer: ring buffer full, stack read
    /// failed, rate limit hit.
    pub samples_dropped: u64,
    /// Times a probe fired, including events the byte sampler skipped.
    pub probe_hits: u64,
    /// Total time target threads spent stopped by the recorder, summed over
    /// threads (ptrace and debugger breakpoints; 0 for eBPF and ETW).
    pub total_pause_ns: u64,
}

/// Everything in the fixed header, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileInfo {
    pub format_version: u16,
    /// Process id of the target.
    pub pid: u32,
    pub python: PythonVersion,
    pub pointer_size: u8,
    pub os: Os,
    pub arch: Arch,
    /// When recording started and stopped, in nanoseconds since the Unix epoch.
    pub start_ns: u64,
    pub end_ns: u64,
    pub mechanisms: Mechanisms,
    pub sampling: SamplingParams,
    pub overhead: Overhead,
    /// Recording stopped early (the target exited, the recorder failed) or
    /// lost samples in a way `overhead` does not describe.
    pub truncated: bool,
}

impl ProfileInfo {
    /// A header with defaults suitable for tests: pid 0, CPython 3.12.0 on
    /// x86_64 Linux, 8-byte pointers, eBPF, default sampling, times 0.
    pub fn new_for_test() -> Self {
        Self {
            format_version: crate::format::FORMAT_VERSION,
            pid: 0,
            python: PythonVersion::new(3, 12, 0),
            pointer_size: 8,
            os: Os::Linux,
            arch: Arch::X86_64,
            start_ns: 0,
            end_ns: 0,
            mechanisms: Mechanisms::of(&[Mechanism::Ebpf]),
            sampling: SamplingParams::DEFAULT,
            overhead: Overhead::default(),
            truncated: false,
        }
    }

    /// Recording window length in nanoseconds (0 if the times are inverted).
    pub fn duration_ns(&self) -> u64 {
        self.end_ns.saturating_sub(self.start_ns)
    }
}

// ---------------------------------------------------------------- records

/// Encoding of a code entry's line table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum LineTableFormat {
    /// No line table recorded.
    #[default]
    None,
    /// The `co_linetable` location table of CPython 3.11 to 3.14
    /// (`Objects/locations.md` in the CPython tree). Offsets are in bytes of
    /// `co_code`, 2 bytes per code unit.
    Locations311,
    /// A code this build does not know.
    Unknown(u8),
}

impl LineTableFormat {
    pub fn code(self) -> u8 {
        match self {
            LineTableFormat::None => 0,
            LineTableFormat::Locations311 => 1,
            LineTableFormat::Unknown(c) => c,
        }
    }

    pub fn from_code(c: u8) -> Self {
        match c {
            0 => LineTableFormat::None,
            1 => LineTableFormat::Locations311,
            c => LineTableFormat::Unknown(c),
        }
    }

    /// The format CPython `3.<minor>` uses, or `None` if this build cannot
    /// decode it.
    pub fn for_python(v: PythonVersion) -> Option<Self> {
        (v.major == 3 && (11..=14).contains(&v.minor)).then_some(LineTableFormat::Locations311)
    }
}

/// One code table entry, as read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeEntry {
    pub id: CodeId,
    /// Address of the code object in the target.
    pub addr: u64,
    /// `co_qualname`.
    pub qualname: Option<StrId>,
    /// `co_filename`.
    pub filename: Option<StrId>,
    /// `co_firstlineno`.
    pub firstlineno: i32,
    /// `co_linetable` bytes.
    pub linetable: Option<BlobId>,
    pub linetable_format: LineTableFormat,
    /// Only the address is known: the code object could not be read.
    pub unresolved: bool,
}

/// One allocation sample, as read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// Position in the samples section (samples are sorted by time).
    pub index: u64,
    /// Nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// OS thread id (Linux TID, Windows thread id).
    pub tid: u64,
    pub kind: EventKind,
    /// Start address of the allocated range.
    pub address: u64,
    /// Size of the allocated range in bytes.
    pub size: u64,
    /// Bytes of allocation this sample stands for (see [`sampled_weight`]).
    pub weight: u64,
    /// Return address of the allocator call in native code, if known.
    pub native_return_address: Option<u64>,
    /// Index of the first frame in the frames section.
    pub frame_start: u64,
    pub frame_count: u32,
    pub flags: SampleFlags,
}

impl Sample {
    /// `[address, address + size)`, saturating at `u64::MAX`.
    pub fn range(&self) -> std::ops::Range<u64> {
        self.address..self.address.saturating_add(self.size)
    }
}

/// Per-sample flag bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SampleFlags(pub u8);

impl SampleFlags {
    pub const NONE: SampleFlags = SampleFlags(0);
    /// Frames were matched to the event by time (ETW), not read at the event.
    pub const APPROXIMATE_FRAMES: SampleFlags = SampleFlags(crate::format::SAF_APPROXIMATE_FRAMES);
    /// The stack was deeper than `max_frames`; outermost frames are missing.
    pub const STACK_TRUNCATED: SampleFlags = SampleFlags(crate::format::SAF_STACK_TRUNCATED);
    /// The allocating thread had no Python thread state.
    pub const NO_THREAD_STATE: SampleFlags = SampleFlags(crate::format::SAF_NO_THREAD_STATE);

    pub fn contains(self, other: SampleFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for SampleFlags {
    type Output = SampleFlags;
    fn bitor(self, rhs: SampleFlags) -> SampleFlags {
        SampleFlags(self.0 | rhs.0)
    }
}

/// One Python frame of a sample's stack, as read back. Frames of a sample
/// are listed innermost first: frame 0 is the function that allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The code entry, or `None` if the frame's code object was not identified.
    pub code: Option<CodeId>,
    /// Byte offset of the executing instruction from the start of the code
    /// object's bytecode (`instr_ptr - _PyCode_CODE(co)`; `prev_instr` on
    /// 3.12). `None` if unknown or before the first instruction.
    pub instr_offset: Option<u32>,
    /// Attributed by time correlation, not read at the event.
    pub approximate: bool,
}

/// A frame with its code entry looked up and its line computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedFrame<'a> {
    /// Address of the code object, if the frame's code was identified.
    pub code_addr: Option<u64>,
    pub qualname: Option<&'a str>,
    pub filename: Option<&'a str>,
    /// Source line of the instruction, from the line table. Without an
    /// instruction offset this is `co_firstlineno`, as CPython reports it.
    pub line: Option<u32>,
    pub approximate: bool,
}

impl ResolvedFrame<'_> {
    /// `co_qualname`, or `<unknown>`.
    pub fn function(&self) -> &str {
        self.qualname.unwrap_or("<unknown>")
    }

    /// `file:line`, `file:?` without a line, `<unknown>` without a file.
    pub fn location(&self) -> String {
        match (self.filename, self.line) {
            (Some(f), Some(l)) => format!("{f}:{l}"),
            (Some(f), None) => format!("{f}:?"),
            (None, _) => "<unknown>".to_string(),
        }
    }
}

impl fmt::Display for ResolvedFrame<'_> {
    /// `qualname (file:line)`, with ` ~` appended for approximate frames.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.function(), self.location())?;
        if self.approximate {
            f.write_str(" ~")?;
        }
        Ok(())
    }
}

/// Bytes a byte-interval sample stands for.
///
/// The recorder keeps an allocation of `size` bytes with probability
/// `p = 1 - exp(-size / interval)` (a Poisson process over allocated bytes,
/// as tcmalloc and memray do). Each kept sample is then weighted by
/// `size / p`, which makes the sum of weights an unbiased estimate of the
/// bytes allocated. Large allocations are kept almost surely and weigh
/// their own size; small ones weigh about `interval`. With `interval == 0`
/// every event is kept and the weight is `size`.
pub fn sampled_weight(size: u64, interval: u64) -> u64 {
    if interval == 0 || size == 0 {
        return size;
    }
    let ratio = size as f64 / interval as f64;
    let p = -(-ratio).exp_m1();
    if p <= 0.0 {
        return interval;
    }
    let w = size as f64 / p;
    if w >= u64::MAX as f64 {
        u64::MAX
    } else {
        w.round() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kinds_parse() {
        let k: EventKinds = "arena,large".parse().unwrap();
        assert_eq!(k, EventKinds::DEFAULT);
        assert!(k.contains(EventKind::Arena));
        assert!(!k.contains(EventKind::Pool));
        assert!("arena,bogus".parse::<EventKinds>().is_err());
        assert!("".parse::<EventKinds>().is_err());
        let all: Vec<_> = "pool,other,large_object"
            .parse::<EventKinds>()
            .unwrap()
            .iter()
            .collect();
        assert_eq!(
            all,
            [EventKind::Other, EventKind::Pool, EventKind::LargeObject]
        );
    }

    #[test]
    fn mechanisms_round_trip() {
        let m = Mechanisms::of(&[Mechanism::Etw, Mechanism::Debugger]);
        assert_eq!(
            m.iter().collect::<Vec<_>>(),
            [Mechanism::Etw, Mechanism::Debugger]
        );
        assert!(m.may_be_approximate());
        assert_eq!("ptrace".parse::<Mechanism>().unwrap(), Mechanism::Ptrace);
        assert!("auto".parse::<Mechanism>().is_err());
    }

    #[test]
    fn weights() {
        assert_eq!(sampled_weight(4096, 0), 4096);
        // Much larger than the interval: weighs its own size.
        assert_eq!(sampled_weight(64 << 20, 512 << 10), 64 << 20);
        // Much smaller: weighs about one interval.
        let w = sampled_weight(1024, 512 << 10);
        assert!((512 << 10..(512 << 10) + 1024).contains(&w), "{w}");
        // Equal: size / (1 - 1/e).
        let w = sampled_weight(1000, 1000);
        assert_eq!(w, 1582);
    }
}
