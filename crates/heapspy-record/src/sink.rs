//! Where recorders put samples.
//!
//! A recorder sees code objects only as addresses. [`SampleSink`] maps each
//! address to a code entry of the profile the first time it appears, and
//! reads the code object right away (qualname, filename, first line,
//! `co_linetable`) while the frame that uses it is still executing, so the
//! object is alive. Later samples with the same address reuse the entry.
//!
//! A code object can be freed during a recording and another allocated at
//! the same address. The sink cannot see that cheaply. A recorder that can
//! (for example by noticing that the `co_qualname` pointer changed) calls
//! [`SampleSink::refresh_code`] to start a new entry.

use std::collections::HashMap;

use heapspy_alloc::{
    AllocWriter, CodeId, CodeInput, FrameInput, LineTableFormat, SampleFlags, SampleInput,
};
use heapspy_reader::cpython::frames::{self, FrameOffsets, RawFrame};
use heapspy_reader::MemorySource;

use crate::error::Result;

/// Counters kept by the sink.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SinkStats {
    pub samples: u64,
    pub frames: u64,
    /// Code objects read.
    pub code_reads: u64,
    /// Code objects that could not be read; their entries stay unresolved.
    pub code_read_errors: u64,
}

/// Collects samples into an [`AllocWriter`]. See the module docs.
pub struct SampleSink<'a> {
    writer: AllocWriter,
    src: &'a dyn MemorySource,
    offsets: FrameOffsets,
    format: Option<LineTableFormat>,
    max_frames: usize,
    codes: HashMap<u64, CodeId>,
    buf: Vec<FrameInput>,
    stats: SinkStats,
}

impl<'a> SampleSink<'a> {
    /// `format` is the line table encoding of the target's CPython
    /// ([`LineTableFormat::for_python`]); `None` stores tables without a
    /// format, which readers cannot decode.
    pub fn new(
        writer: AllocWriter,
        src: &'a dyn MemorySource,
        offsets: FrameOffsets,
        format: Option<LineTableFormat>,
        max_frames: u32,
    ) -> Self {
        Self {
            writer,
            src,
            offsets,
            format,
            max_frames: max_frames as usize,
            codes: HashMap::new(),
            buf: Vec::new(),
            stats: SinkStats::default(),
        }
    }

    /// The code entry for the code object at `addr`, reading it if new.
    pub fn code(&mut self, addr: u64) -> Result<CodeId> {
        if let Some(&id) = self.codes.get(&addr) {
            return Ok(id);
        }
        let id = self.writer.add_unresolved_code(addr)?;
        self.codes.insert(addr, id);
        self.read_into(id, addr)?;
        Ok(id)
    }

    /// Start a new entry for `addr` and read the code object again: the old
    /// one was freed and the address reused.
    pub fn refresh_code(&mut self, addr: u64) -> Result<CodeId> {
        let id = self.writer.add_unresolved_code(addr)?;
        self.codes.insert(addr, id);
        self.read_into(id, addr)?;
        Ok(id)
    }

    fn read_into(&mut self, id: CodeId, addr: u64) -> Result<()> {
        self.stats.code_reads += 1;
        let info = match frames::read_code(self.src, &self.offsets, addr) {
            Ok(i) => i,
            Err(_) => {
                self.stats.code_read_errors += 1;
                return Ok(());
            }
        };
        self.writer.set_code(
            id,
            &CodeInput {
                addr,
                qualname: info.qualname.as_deref(),
                filename: info.filename.as_deref(),
                firstlineno: info.firstlineno,
                linetable: info.linetable.as_deref(),
                linetable_format: self.format.unwrap_or_default(),
            },
        )?;
        Ok(())
    }

    /// Add one sample with its raw Python frames, innermost first. Frames
    /// past `max_frames` are dropped and the sample marked
    /// `STACK_TRUNCATED`. With `approximate`, the frames were matched to the
    /// event by time and are marked so.
    pub fn add(&mut self, sample: &SampleInput, raw: &[RawFrame], approximate: bool) -> Result<()> {
        let mut s = *sample;
        let keep = raw.len().min(self.max_frames);
        if raw.len() > keep {
            s.flags = s.flags | SampleFlags::STACK_TRUNCATED;
        }
        if approximate {
            s.flags = s.flags | SampleFlags::APPROXIMATE_FRAMES;
        }
        let mut buf = std::mem::take(&mut self.buf);
        buf.clear();
        for f in &raw[..keep] {
            buf.push(FrameInput {
                code: Some(self.code(f.code)?),
                instr_offset: f.instr_offset,
                approximate,
            });
        }
        let r = self.writer.add_sample(&s, &buf);
        self.stats.frames += buf.len() as u64;
        self.buf = buf;
        r?;
        self.stats.samples += 1;
        Ok(())
    }

    /// Add a sample from a thread with no Python thread state (a native
    /// thread): no frames, flag `NO_THREAD_STATE`.
    pub fn add_native(&mut self, sample: &SampleInput) -> Result<()> {
        let mut s = *sample;
        s.flags = s.flags | SampleFlags::NO_THREAD_STATE;
        self.writer.add_sample(&s, &[])?;
        self.stats.samples += 1;
        Ok(())
    }

    pub fn stats(&self) -> SinkStats {
        self.stats
    }

    /// The writer, for header fields and meta.
    pub fn writer_mut(&mut self) -> &mut AllocWriter {
        &mut self.writer
    }

    /// Give back the writer and the counters.
    pub fn into_parts(self) -> (AllocWriter, SinkStats) {
        (self.writer, self.stats)
    }
}
