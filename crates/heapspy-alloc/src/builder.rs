//! Build small synthetic allocation profiles for tests and examples, the
//! way `SnapshotBuilder` does for snapshots.
//!
//! ```
//! use heapspy_alloc::{EventKind, ProfileBuilder};
//!
//! let mut b = ProfileBuilder::new();
//! b.info_mut().pid = 4242;
//! // `load` starts on line 10; bytes 0..8 are line 10, 8..16 line 12.
//! let load = b.code_with_lines(0x7f00_1000, "Cache.load", "app/cache.py", 10, &[(8, 10), (8, 12)]);
//! let main = b.code_with_lines(0x7f00_2000, "main", "app/main.py", 1, &[(64, 3)]);
//! b.sample(EventKind::Arena, 0x7f10_0000_0000, 1 << 20)
//!     .at(1_000)
//!     .tid(7)
//!     .frame(load, 10)
//!     .frame(main, 4);
//!
//! let p = b.build().unwrap();
//! let s = p.sample(0).unwrap();
//! let stack: Vec<String> = p.stack(&s).map(|f| f.to_string()).collect();
//! assert_eq!(stack, ["Cache.load (app/cache.py:12)", "main (app/main.py:3)"]);
//! ```

use std::path::Path;

use crate::error::Result;
use crate::linetable;
use crate::reader::Profile;
use crate::types::*;
use crate::writer::{AllocWriter, CodeInput, FrameInput, SampleInput, WriteStats};

#[derive(Clone, Debug)]
struct CodeSpec {
    addr: u64,
    qualname: Option<String>,
    filename: Option<String>,
    firstlineno: i32,
    linetable: Option<Vec<u8>>,
    format: LineTableFormat,
}

/// One sample being built. Returned by [`ProfileBuilder::sample`]; methods chain.
#[derive(Clone, Debug)]
pub struct SampleSpec {
    input: SampleInput,
    frames: Vec<FrameInput>,
    weight_set: bool,
}

impl SampleSpec {
    /// Timestamp in nanoseconds since the Unix epoch (default: the sample's
    /// position, so samples stay in insertion order).
    pub fn at(&mut self, timestamp_ns: u64) -> &mut Self {
        self.input.timestamp_ns = timestamp_ns;
        self
    }
    pub fn tid(&mut self, tid: u64) -> &mut Self {
        self.input.tid = tid;
        self
    }
    /// Bytes this sample stands for (default: its size).
    pub fn weight(&mut self, w: u64) -> &mut Self {
        self.input.weight = w;
        self.weight_set = true;
        self
    }
    pub fn native_return(&mut self, addr: u64) -> &mut Self {
        self.input.native_return_address = Some(addr);
        self
    }
    pub fn flags(&mut self, f: SampleFlags) -> &mut Self {
        self.input.flags = self.input.flags | f;
        self
    }
    /// Append a frame (innermost first) at byte offset `instr_offset`.
    pub fn frame(&mut self, code: CodeId, instr_offset: u32) -> &mut Self {
        self.frames.push(FrameInput {
            code: Some(code),
            instr_offset: Some(instr_offset),
            approximate: false,
        });
        self
    }
    /// Append a frame attributed by time correlation.
    pub fn approximate_frame(&mut self, code: CodeId, instr_offset: u32) -> &mut Self {
        self.frames.push(FrameInput {
            code: Some(code),
            instr_offset: Some(instr_offset),
            approximate: true,
        });
        self
    }
    /// Append a frame with no instruction offset (resolves to `co_firstlineno`).
    pub fn frame_no_offset(&mut self, code: CodeId) -> &mut Self {
        self.frames.push(FrameInput {
            code: Some(code),
            instr_offset: None,
            approximate: false,
        });
        self
    }
    /// Append a frame whose code object was not identified.
    pub fn unknown_frame(&mut self) -> &mut Self {
        self.frames.push(FrameInput::default());
        self
    }
}

/// Collects codes and samples, then writes and reopens a profile.
#[derive(Clone, Debug)]
pub struct ProfileBuilder {
    info: ProfileInfo,
    codes: Vec<CodeSpec>,
    samples: Vec<SampleSpec>,
    meta: Vec<(String, String)>,
}

impl Default for ProfileBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileBuilder {
    /// A builder with [`ProfileInfo::new_for_test`] as the header.
    pub fn new() -> Self {
        Self {
            info: ProfileInfo::new_for_test(),
            codes: Vec::new(),
            samples: Vec::new(),
            meta: Vec::new(),
        }
    }

    pub fn info_mut(&mut self) -> &mut ProfileInfo {
        &mut self.info
    }

    fn push_code(&mut self, c: CodeSpec) -> CodeId {
        self.codes.push(c);
        CodeId(self.codes.len() as u32 - 1)
    }

    /// A code entry with a real `co_linetable` (CPython 3.11+ format).
    pub fn code(
        &mut self,
        addr: u64,
        qualname: &str,
        filename: &str,
        firstlineno: i32,
        linetable: &[u8],
    ) -> CodeId {
        self.push_code(CodeSpec {
            addr,
            qualname: Some(qualname.into()),
            filename: Some(filename.into()),
            firstlineno,
            linetable: Some(linetable.into()),
            format: LineTableFormat::Locations311,
        })
    }

    /// A code entry whose line table maps consecutive `(byte length, line)`
    /// runs of bytecode to lines. See [`linetable::encode_lines`].
    pub fn code_with_lines(
        &mut self,
        addr: u64,
        qualname: &str,
        filename: &str,
        firstlineno: i32,
        runs: &[(u32, u32)],
    ) -> CodeId {
        let runs: Vec<(u32, Option<u32>)> = runs.iter().map(|&(n, l)| (n, Some(l))).collect();
        let t = linetable::encode_lines(firstlineno, &runs);
        self.code(addr, qualname, filename, firstlineno, &t)
    }

    /// An address-only code entry, as a recorder leaves it when it could not
    /// read the code object.
    pub fn unresolved_code(&mut self, addr: u64) -> CodeId {
        self.push_code(CodeSpec {
            addr,
            qualname: None,
            filename: None,
            firstlineno: 0,
            linetable: None,
            format: LineTableFormat::None,
        })
    }

    /// Start a sample of `size` bytes at `address`. Chain frames onto it.
    pub fn sample(&mut self, kind: EventKind, address: u64, size: u64) -> &mut SampleSpec {
        let ts = self.samples.len() as u64;
        self.samples.push(SampleSpec {
            input: SampleInput {
                timestamp_ns: ts,
                kind,
                address,
                size,
                weight: size,
                ..SampleInput::default()
            },
            frames: Vec::new(),
            weight_set: false,
        });
        self.samples.last_mut().expect("just pushed")
    }

    pub fn meta(&mut self, key: &str, value: &str) -> &mut Self {
        self.meta.push((key.into(), value.into()));
        self
    }

    fn writer(&self) -> Result<AllocWriter> {
        let mut info = self.info.clone();
        if info.overhead.samples_taken == 0 {
            info.overhead.samples_taken = self.samples.len() as u64;
        }
        let mut w = AllocWriter::new(info)?;
        for c in &self.codes {
            if c.qualname.is_none() && c.linetable.is_none() {
                w.add_unresolved_code(c.addr)?;
                continue;
            }
            w.add_code(&CodeInput {
                addr: c.addr,
                qualname: c.qualname.as_deref(),
                filename: c.filename.as_deref(),
                firstlineno: c.firstlineno,
                linetable: c.linetable.as_deref(),
                linetable_format: c.format,
            })?;
        }
        for s in &self.samples {
            let mut input = s.input;
            if !s.weight_set {
                input.weight = input.size;
            }
            w.add_sample(&input, &s.frames)?;
        }
        for (k, v) in &self.meta {
            w.add_meta(k, v)?;
        }
        Ok(w)
    }

    /// Encode to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.writer()?.finish_to_vec()
    }

    /// Write to `path`.
    pub fn write_to(&self, path: impl AsRef<Path>) -> Result<WriteStats> {
        self.writer()?.finish_to_path(path)
    }

    /// Encode and reopen in memory.
    pub fn build(&self) -> Result<Profile> {
        Profile::from_bytes(self.to_bytes()?)
    }
}
