//! Public value types shared by the writer and the reader.

use std::fmt;

use crate::format::{NO_STRING, UNKNOWN_TYPE};

/// Index into the snapshot's string table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StrId(pub u32);

impl StrId {
    pub(crate) fn encode(opt: Option<StrId>) -> u32 {
        opt.map_or(NO_STRING, |s| s.0)
    }
    pub(crate) fn decode(raw: u32) -> Option<StrId> {
        (raw != NO_STRING).then_some(StrId(raw))
    }
}

/// Index into the snapshot's type table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeId(pub u32);

impl TypeId {
    /// The object's type could not be read. Stored as `u32::MAX`.
    pub const UNKNOWN: TypeId = TypeId(UNKNOWN_TYPE);

    pub fn is_unknown(self) -> bool {
        self == Self::UNKNOWN
    }
}

/// Dense object id: the object's position in the address-sorted objects
/// section. The analyzer uses this as its node id.
pub type ObjectIndex = u32;

/// CPython version of the target process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PythonVersion {
    pub major: u8,
    pub minor: u8,
    pub micro: u8,
    /// `PY_RELEASE_LEVEL`: 0xA alpha, 0xB beta, 0xC candidate, 0xF final.
    pub release_level: u8,
    /// `PY_RELEASE_SERIAL`.
    pub release_serial: u8,
}

impl PythonVersion {
    pub const LEVEL_ALPHA: u8 = 0xA;
    pub const LEVEL_BETA: u8 = 0xB;
    pub const LEVEL_CANDIDATE: u8 = 0xC;
    pub const LEVEL_FINAL: u8 = 0xF;

    /// A final release, e.g. `PythonVersion::new(3, 12, 4)`.
    pub const fn new(major: u8, minor: u8, micro: u8) -> Self {
        Self {
            major,
            minor,
            micro,
            release_level: Self::LEVEL_FINAL,
            release_serial: 0,
        }
    }
}

impl fmt::Display for PythonVersion {
    /// Formats like `sys.version`: `3.12.4`, `3.13.0rc1`, `3.14.0a3`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.micro)?;
        let level = match self.release_level {
            Self::LEVEL_ALPHA => "a",
            Self::LEVEL_BETA => "b",
            Self::LEVEL_CANDIDATE => "rc",
            _ => return Ok(()),
        };
        write!(f, "{level}{}", self.release_serial)
    }
}

macro_rules! code_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident : $repr:ty { $( $(#[$vmeta:meta])* $var:ident = $code:literal => $text:literal ),* $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$vmeta])* $var, )*
            /// A code this build does not know. Kept so newer files still open.
            Unknown($repr),
        }

        impl $name {
            pub fn code(self) -> $repr {
                match self {
                    $( Self::$var => $code, )*
                    Self::Unknown(c) => c,
                }
            }
            pub fn from_code(code: $repr) -> Self {
                match code {
                    $( $code => Self::$var, )*
                    c => Self::Unknown(c),
                }
            }
            /// Lowercase name used in JSON reports and text output.
            pub fn as_str(self) -> &'static str {
                match self {
                    $( Self::$var => $text, )*
                    Self::Unknown(_) => "unknown",
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

code_enum! {
    /// Operating system of the target process.
    pub enum Os: u8 {
        Linux = 1 => "linux",
        Windows = 2 => "windows",
        Macos = 3 => "macos",
    }
}

code_enum! {
    /// CPU architecture of the target process.
    pub enum Arch: u8 {
        X86_64 = 1 => "x86_64",
        Aarch64 = 2 => "aarch64",
    }
}

code_enum! {
    /// Where the memory image came from.
    pub enum SourceKind: u8 {
        /// A live process, read directly.
        Pid = 1 => "pid",
        /// An ELF core file.
        Core = 2 => "core",
        /// A Windows minidump.
        Minidump = 3 => "minidump",
    }
}

code_enum! {
    /// Why an object is a GC root.
    pub enum RootKind: u8 {
        /// Anything not covered below.
        Other = 0 => "other",
        /// A module reachable from `sys.modules`. The root object is the
        /// module object; its `__dict__` is reached by an `Attr("__dict__")` edge.
        ModuleDict = 1 => "module_dict",
        /// Per-thread state: the thread state's dict, the current exception, etc.
        ThreadLocals = 2 => "thread_locals",
        /// A live frame's local variable. The root object is the variable's value.
        FrameLocal = 3 => "frame_local",
        /// Interpreter-wide state: builtins, `sys` attributes, caches, interned strings.
        Interp = 4 => "interp",
    }
}

code_enum! {
    /// Kind of a memory region in the memory summary.
    pub enum RegionKind: u32 {
        Other = 0 => "other",
        /// The brk heap (`[heap]` on Linux) or the process default heap on Windows.
        Heap = 1 => "heap",
        /// Private anonymous mappings not covered by a more specific kind.
        Anonymous = 2 => "anonymous",
        /// Executable images: the main binary and shared libraries / DLLs.
        Image = 3 => "image",
        /// Thread stacks.
        Stack = 4 => "stack",
        /// pymalloc arenas, if the source can identify them.
        PythonArena = 5 => "python_arena",
        /// File-backed data mappings that are not images.
        MappedFile = 6 => "mapped_file",
    }
}

/// Where the snapshot came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceInfo {
    pub kind: SourceKind,
    /// PID as decimal text, or the core / minidump path as given by the user.
    pub reference: String,
}

/// Everything in the fixed header, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub format_version: u16,
    pub python: PythonVersion,
    pub pointer_size: u8,
    /// Byte order of the *target* process. The file itself is always little-endian.
    pub target_little_endian: bool,
    pub os: Os,
    pub arch: Arch,
    /// Unix seconds when the memory image was taken.
    pub captured_at: u64,
    pub source: SourceInfo,
    /// String and bytes contents (and ordinary dict keys) were captured.
    pub contents_captured: bool,
    /// The walk stopped early or hit read errors; the graph is incomplete.
    pub truncated: bool,
    /// The target is a free-threaded (`Py_GIL_DISABLED`) build.
    pub free_threaded: bool,
    /// The target is a debug (`Py_DEBUG`) build.
    pub debug_build: bool,
}

impl SnapshotInfo {
    /// A header with defaults suitable for tests: CPython 3.12.0 on x86_64 Linux,
    /// 8-byte pointers, little-endian, source `pid 0`, captured at 0.
    pub fn new_for_test() -> Self {
        Self {
            format_version: crate::format::FORMAT_VERSION,
            python: PythonVersion::new(3, 12, 0),
            pointer_size: 8,
            target_little_endian: true,
            os: Os::Linux,
            arch: Arch::X86_64,
            captured_at: 0,
            source: SourceInfo {
                kind: SourceKind::Pid,
                reference: "0".to_string(),
            },
            contents_captured: false,
            truncated: false,
            free_threaded: false,
            debug_build: false,
        }
    }
}

/// Per-object flag bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ObjectFlags(pub u32);

impl ObjectFlags {
    pub const NONE: ObjectFlags = ObjectFlags(0);
    /// The object was found on a GC generation list (or is GC-tracked).
    pub const GC_TRACKED: ObjectFlags = ObjectFlags(1 << 0);
    /// Some of the object's references could not be read; its edge list is incomplete.
    pub const PARTIAL: ObjectFlags = ObjectFlags(1 << 1);
    /// The object is immortal (3.12+ immortal refcount).
    pub const IMMORTAL: ObjectFlags = ObjectFlags(1 << 2);
    /// The object is a type object (its address also appears in the type table).
    pub const IS_TYPE: ObjectFlags = ObjectFlags(1 << 3);

    pub fn contains(self, other: ObjectFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for ObjectFlags {
    type Output = ObjectFlags;
    fn bitor(self, rhs: ObjectFlags) -> ObjectFlags {
        ObjectFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ObjectFlags {
    fn bitor_assign(&mut self, rhs: ObjectFlags) {
        self.0 |= rhs.0;
    }
}

/// One object record, decoded. Cheap to copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Object {
    pub index: ObjectIndex,
    pub addr: u64,
    pub type_id: TypeId,
    /// Bytes owned by this object alone (`sys.getsizeof` without the GC header
    /// unless the walker chooses to include it; see the format doc).
    pub shallow_size: u64,
    pub flags: ObjectFlags,
    /// Index of the first edge in the edges section.
    pub edge_start: u64,
    pub edge_count: u32,
}

/// One entry of the type table, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeEntry {
    /// Address of the type object in the target (0 if unknown).
    pub addr: u64,
    /// `__qualname__`, e.g. `dict`, `Session`, `Outer.Inner`.
    pub qualname: StrId,
    /// `__module__`, e.g. `builtins`, `app.session`.
    pub module: StrId,
}

/// How a dict key is recorded in a `DictValue` / `DictKey` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyLabel {
    /// The key could not be read.
    Unknown,
    /// The key's `repr()` text, e.g. `'cache'`, `3`, `('a', 1)`.
    Repr(StrId),
    /// A placeholder such as `<str len=9>`; the key text was not captured.
    Redacted(StrId),
}

/// Why `source` references `target`. This is the text shown on each hop of a
/// retaining path. See `docs/snapshot-format.md` for the numeric encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EdgeLabel {
    /// Kind 0. A reference with no Python-level name; optional description.
    Other(Option<StrId>),
    /// Kind 1. The source is a dict and the target is the value stored under `key`.
    DictValue(KeyLabel),
    /// Kind 2. The source is a dict and the target is the key object itself.
    DictKey(KeyLabel),
    /// Kind 3. `source[index]` for a list (or other mutable sequence).
    ListItem(u32),
    /// Kind 4. `source[index]` for a tuple.
    TupleItem(u32),
    /// Kind 5. The target is an element of a set or frozenset.
    SetItem,
    /// Kind 6. A named attribute: inline instance value, `__slots__` entry, or a
    /// C struct member with a Python name (`__dict__`, `__globals__`, `f_back`).
    Attr(StrId),
    /// Kind 7. `ob_type`: the target is the source's type.
    Type,
    /// Kind 8. The source is a cell; the target is its contents.
    CellContents,
    /// Kind 9. The source is a function; the target is `__closure__[index]`.
    ClosureCell(u32),
    /// Kind 10. The source is a frame; the target is the local named `name`.
    FrameLocal(StrId),
    /// A kind code this build does not know. Rendered as `<edge kind=N>`.
    Unknown { kind: u8, flags: u8, operand: u32 },
}

/// One edge, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edge {
    /// Address of the referenced object. It may not be in the snapshot (for
    /// example an untracked object the walker did not record); resolve it with
    /// [`crate::Snapshot::find_object`].
    pub target: u64,
    pub label: EdgeLabel,
    pub origin: EdgeOrigin,
}

/// How the walker knows an edge is a reference.
///
/// Stored in the edge record's `edge_flags`. Readers that predate it see
/// reserved bytes and treat every edge as [`EdgeOrigin::Exact`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum EdgeOrigin {
    /// Read from a layout the walker knows: a dict entry, a list item, a
    /// frame local. The source owns the target.
    #[default]
    Exact,
    /// A field of an object whose layout the walker does not know, that
    /// points at an object. Usually an owned reference; a field that only
    /// borrows would over-count, which the target's refcount can show.
    Scanned,
    /// A pointer found in memory an object points at but does not lay out
    /// (an out-of-line array or block). It may be a stale slot, so it is
    /// only a reference if the target has owners nothing else accounts for.
    Speculative,
}

impl EdgeOrigin {
    pub fn code(self) -> u16 {
        match self {
            EdgeOrigin::Exact => 0,
            EdgeOrigin::Scanned => 1,
            EdgeOrigin::Speculative => 2,
        }
    }

    pub fn from_code(c: u16) -> EdgeOrigin {
        match c & 3 {
            1 => EdgeOrigin::Scanned,
            2 => EdgeOrigin::Speculative,
            _ => EdgeOrigin::Exact,
        }
    }
}

impl Edge {
    /// An edge read from a known layout.
    pub fn exact(target: u64, label: EdgeLabel) -> Edge {
        Edge {
            target,
            label,
            origin: EdgeOrigin::Exact,
        }
    }
}

/// One root, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root {
    pub addr: u64,
    pub kind: RootKind,
    /// Rendered root description, e.g. `sys.modules['app.cache']`,
    /// `frame main:leak_forever`.
    pub label: StrId,
}

/// Optional per-object data. Missing fields are `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectExtras {
    /// `len()` of str, bytes, bytearray, list, tuple, dict, set, frozenset.
    pub length: Option<u64>,
    /// Qualified name for modules, functions, code objects and types.
    pub qualname: Option<StrId>,
    /// Source location such as `app/cache.py:88` (functions, code, frames).
    pub source_loc: Option<StrId>,
    /// Captured content (repr, capped at `max_str`). Only when contents were captured.
    pub content: Option<StrId>,
    /// `content` was cut at `max_str`.
    pub content_truncated: bool,
}

impl ObjectExtras {
    pub fn is_empty(&self) -> bool {
        self.length.is_none()
            && self.qualname.is_none()
            && self.source_loc.is_none()
            && self.content.is_none()
    }
}

/// Mapped and resident bytes for one kind of memory region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub kind: RegionKind,
    pub mapped_bytes: u64,
    /// `None` when the source cannot tell (e.g. some minidumps).
    pub resident_bytes: Option<u64>,
}
