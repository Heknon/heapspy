//! A minidump writer for tests: builds MINIDUMP files byte by byte, so the
//! parser can be tested without a Windows machine.
//!
//! It writes only what [`super::Minidump`] reads, in the same layouts as
//! `minidumpapiset.h`. There is no padding anywhere: every byte after the
//! header is referenced by the directory or by a stream, so any truncation
//! of the output removes something the parser must find.

use super::parse::{cpu, stream, HEADER_SIZE, SIGNATURE, VERSION};
use super::MemoryInfo;

#[derive(Clone, Debug)]
pub(crate) struct SynthModule {
    pub base: u64,
    pub size: u32,
    /// Full path; written as a UTF-16 `MINIDUMP_STRING`.
    pub path: String,
    /// Raw CodeView record bytes.
    pub codeview: Option<Vec<u8>>,
    /// `(dwFileVersionMS, dwFileVersionLS)`.
    pub file_version: Option<(u32, u32)>,
}

impl SynthModule {
    pub fn new(base: u64, size: u32, path: &str) -> Self {
        Self {
            base,
            size,
            path: path.into(),
            codeview: None,
            file_version: None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SynthThread {
    pub tid: u32,
    pub teb: u64,
    pub stack_start: u64,
    pub stack_size: u32,
    /// If set, a CONTEXT record with this stack pointer is written.
    pub sp: Option<u64>,
}

/// The CodeView RSDS record for `guid`, `age` and `pdb`.
pub(crate) fn rsds(guid: [u8; 16], age: u32, pdb: &str) -> Vec<u8> {
    let mut v = b"RSDS".to_vec();
    v.extend_from_slice(&guid);
    v.extend_from_slice(&age.to_le_bytes());
    v.extend_from_slice(pdb.as_bytes());
    v.push(0);
    v
}

/// Where a stream ended up in the built file.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamPos {
    pub stream_type: u32,
    /// Offset of this stream's directory entry.
    pub dir_entry: usize,
    pub size: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct DumpBuilder {
    pub timestamp: u32,
    pub flags: u64,
    pub processor_architecture: u16,
    pub platform_id: u32,
    pub system_info: bool,
    pub memory64: Option<Vec<(u64, Vec<u8>)>>,
    pub memory_list: Option<Vec<(u64, Vec<u8>)>>,
    pub modules: Option<Vec<SynthModule>>,
    pub threads: Option<Vec<SynthThread>>,
    pub thread_names: Option<Vec<(u32, String)>>,
    pub memory_info: Option<Vec<MemoryInfo>>,
    /// `(process id, process create time)`.
    pub misc: Option<(u32, u32)>,
    /// Put the raw memory bytes right after the directory instead of at the
    /// end of the file (where `MiniDumpWriteDump` puts them).
    pub data_first: bool,
    /// Memory64 descriptors `(start, size)` whose bytes the caller appends
    /// to the output itself, in order, right after [`DumpBuilder::build`]
    /// returns. Replaces `memory64`; requires `data_first == false`. Lets a
    /// test stream gigabytes of memory into a file without holding it.
    pub memory64_external: Option<Vec<(u64, u64)>>,
}

impl Default for DumpBuilder {
    fn default() -> Self {
        Self {
            timestamp: 1_700_000_000,
            flags: 0x1806, // FullMemory | HandleData | FullMemoryInfo | ThreadInfo
            processor_architecture: cpu::AMD64,
            platform_id: 2,
            system_info: true,
            memory64: Some(Vec::new()),
            memory_list: None,
            modules: None,
            threads: None,
            thread_names: None,
            memory_info: None,
            misc: None,
            data_first: false,
            memory64_external: None,
        }
    }
}

enum Patch {
    /// u32 RVA at `pos`.
    Rva32(usize),
    /// u64 RVA at `pos`.
    Rva64(usize),
    /// Location descriptor (size u32, rva u32) at `pos`.
    Loc(usize),
}

struct Out {
    buf: Vec<u8>,
    /// Blobs to append after the streams, and what to patch with their RVA.
    extras: Vec<(Patch, Vec<u8>)>,
}

impl Out {
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn zeros(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }
    fn set_u32(&mut self, pos: usize, v: u32) {
        self.buf[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn set_u64(&mut self, pos: usize, v: u64) {
        self.buf[pos..pos + 8].copy_from_slice(&v.to_le_bytes());
    }
    /// Reserve a u32 RVA here, pointing at `blob` once extras are written.
    fn later32(&mut self, blob: Vec<u8>) {
        let pos = self.buf.len();
        self.u32(0);
        self.extras.push((Patch::Rva32(pos), blob));
    }
    fn later64(&mut self, blob: Vec<u8>) {
        let pos = self.buf.len();
        self.u64(0);
        self.extras.push((Patch::Rva64(pos), blob));
    }
    fn later_loc(&mut self, blob: Option<Vec<u8>>) {
        let pos = self.buf.len();
        self.u32(0);
        self.u32(0);
        if let Some(b) = blob {
            self.extras.push((Patch::Loc(pos), b));
        }
    }
    fn rva(&self) -> u32 {
        u32::try_from(self.buf.len()).expect("synthetic dump over 4 GiB")
    }
}

fn md_string(s: &str) -> Vec<u8> {
    let units: Vec<u16> = s.encode_utf16().collect();
    let mut v = ((units.len() * 2) as u32).to_le_bytes().to_vec();
    for u in units {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

impl DumpBuilder {
    pub fn build(&self) -> Vec<u8> {
        self.build_with_layout().0
    }

    pub fn build_with_layout(&self) -> (Vec<u8>, Vec<StreamPos>) {
        let mut types = Vec::new();
        if self.system_info {
            types.push(stream::SYSTEM_INFO);
        }
        if self.memory64.is_some() || self.memory64_external.is_some() {
            types.push(stream::MEMORY64_LIST);
        }
        if self.memory_list.is_some() {
            types.push(stream::MEMORY_LIST);
        }
        if self.modules.is_some() {
            types.push(stream::MODULE_LIST);
        }
        if self.threads.is_some() {
            types.push(stream::THREAD_LIST);
        }
        if self.thread_names.is_some() {
            types.push(stream::THREAD_NAMES);
        }
        if self.memory_info.is_some() {
            types.push(stream::MEMORY_INFO_LIST);
        }
        if self.misc.is_some() {
            types.push(stream::MISC_INFO);
        }

        let mut o = Out {
            buf: Vec::new(),
            extras: Vec::new(),
        };
        o.u32(SIGNATURE);
        o.u32(VERSION);
        o.u32(types.len() as u32);
        o.u32(HEADER_SIZE as u32);
        o.u32(0);
        o.u32(self.timestamp);
        o.u64(self.flags);
        let dir = o.buf.len();
        o.zeros(types.len() * 12);

        // Positions to patch with memory data RVAs: (Memory64 BaseRva pos),
        // (MemoryList descriptor rva pos, index).
        let mut mem64_base_pos = None;
        let mut memlist_pos = Vec::new();
        let mut mem64_base = 0u64;
        let mut memlist_rvas = Vec::new();
        let write_data = |o: &mut Out, base: &mut u64, rvas: &mut Vec<u32>| {
            if self.memory64_external.is_some() {
                *base = o.buf.len() as u64;
            } else if let Some(r) = &self.memory64 {
                *base = o.buf.len() as u64;
                for (_, b) in r {
                    o.buf.extend_from_slice(b);
                }
            }
            if let Some(r) = &self.memory_list {
                for (_, b) in r {
                    rvas.push(o.rva());
                    o.buf.extend_from_slice(b);
                }
            }
        };
        if self.data_first {
            write_data(&mut o, &mut mem64_base, &mut memlist_rvas);
        }

        let mut layout = Vec::new();
        for (i, &ty) in types.iter().enumerate() {
            let start = o.buf.len();
            match ty {
                stream::SYSTEM_INFO => {
                    o.u16(self.processor_architecture);
                    o.u16(6); // level
                    o.u16(0); // revision
                    o.buf.push(8); // processors
                    o.buf.push(1); // product type
                    o.u32(10);
                    o.u32(0);
                    o.u32(22631);
                    o.u32(self.platform_id);
                    o.u32(0); // CSDVersionRva
                    o.u16(0);
                    o.u16(0);
                    o.zeros(24); // CPU_INFORMATION
                }
                stream::MEMORY64_LIST => {
                    let r: Vec<(u64, u64)> = match &self.memory64_external {
                        Some(e) => e.clone(),
                        None => self
                            .memory64
                            .as_ref()
                            .unwrap()
                            .iter()
                            .map(|(s, b)| (*s, b.len() as u64))
                            .collect(),
                    };
                    o.u64(r.len() as u64);
                    mem64_base_pos = Some(o.buf.len());
                    o.u64(mem64_base);
                    for (start, size) in r {
                        o.u64(start);
                        o.u64(size);
                    }
                }
                stream::MEMORY_LIST => {
                    let r = self.memory_list.as_ref().unwrap();
                    o.u32(r.len() as u32);
                    for (k, (start, b)) in r.iter().enumerate() {
                        o.u64(*start);
                        o.u32(b.len() as u32);
                        memlist_pos.push(o.buf.len());
                        o.u32(memlist_rvas.get(k).copied().unwrap_or(0));
                    }
                }
                stream::MODULE_LIST => {
                    let ms = self.modules.as_ref().unwrap();
                    o.u32(ms.len() as u32);
                    for m in ms {
                        o.u64(m.base);
                        o.u32(m.size);
                        o.u32(0x1234); // checksum
                        o.u32(0x6500_0000); // timestamp
                        o.later32(md_string(&m.path));
                        // VS_FIXEDFILEINFO, 13 u32s.
                        match m.file_version {
                            Some((ms_, ls)) => {
                                o.u32(0xfeef_04bd);
                                o.u32(0x0001_0000);
                                o.u32(ms_);
                                o.u32(ls);
                                o.zeros(9 * 4);
                            }
                            None => o.zeros(13 * 4),
                        }
                        o.later_loc(m.codeview.clone());
                        o.later_loc(None); // MiscRecord
                        o.u64(0);
                        o.u64(0);
                    }
                }
                stream::THREAD_LIST => {
                    let ts = self.threads.as_ref().unwrap();
                    o.u32(ts.len() as u32);
                    for t in ts {
                        o.u32(t.tid);
                        o.u32(0);
                        o.u32(0x20);
                        o.u32(0);
                        o.u64(t.teb);
                        o.u64(t.stack_start);
                        o.u32(t.stack_size);
                        o.u32(0); // stack RVA: unused by the parser
                        o.later_loc(t.sp.map(|sp| self.context(sp)));
                    }
                }
                stream::THREAD_NAMES => {
                    let ns = self.thread_names.as_ref().unwrap();
                    o.u32(ns.len() as u32);
                    for (tid, name) in ns {
                        o.u32(*tid);
                        o.later64(md_string(name));
                    }
                }
                stream::MEMORY_INFO_LIST => {
                    let mi = self.memory_info.as_ref().unwrap();
                    o.u32(16);
                    o.u32(48);
                    o.u64(mi.len() as u64);
                    for m in mi {
                        o.u64(m.base);
                        o.u64(m.allocation_base);
                        o.u32(m.allocation_protect);
                        o.u32(0);
                        o.u64(m.size);
                        o.u32(m.state);
                        o.u32(m.protect);
                        o.u32(m.kind);
                        o.u32(0);
                    }
                }
                stream::MISC_INFO => {
                    let (pid, created) = self.misc.unwrap();
                    o.u32(24);
                    o.u32(3); // PROCESS_ID | PROCESS_TIMES
                    o.u32(pid);
                    o.u32(created);
                    o.u32(5);
                    o.u32(6);
                }
                _ => unreachable!(),
            }
            let size = o.buf.len() - start;
            let e = dir + i * 12;
            o.set_u32(e, ty);
            o.set_u32(e + 4, size as u32);
            o.set_u32(e + 8, start as u32);
            layout.push(StreamPos {
                stream_type: ty,
                dir_entry: e,
                size,
            });
        }

        for (patch, blob) in std::mem::take(&mut o.extras) {
            let rva = o.rva();
            match patch {
                Patch::Rva32(p) => o.set_u32(p, rva),
                Patch::Rva64(p) => o.set_u64(p, rva.into()),
                Patch::Loc(p) => {
                    o.set_u32(p, blob.len() as u32);
                    o.set_u32(p + 4, rva);
                }
            }
            o.buf.extend_from_slice(&blob);
        }

        if !self.data_first {
            write_data(&mut o, &mut mem64_base, &mut memlist_rvas);
        }
        if let Some(p) = mem64_base_pos {
            o.set_u64(p, mem64_base);
        }
        for (p, rva) in memlist_pos.into_iter().zip(memlist_rvas) {
            o.set_u32(p, rva);
        }
        (o.buf, layout)
    }

    /// A CONTEXT record for the builder's architecture with stack pointer `sp`.
    fn context(&self, sp: u64) -> Vec<u8> {
        let (size, sp_off, flags_off, flags) = match self.processor_architecture {
            cpu::ARM64 => (0x390, 0x100, 0, 0x0040_0003u32),
            _ => (0x4d0, 0x98, 0x30, 0x0010_001fu32),
        };
        let mut c = vec![0u8; size];
        c[flags_off..flags_off + 4].copy_from_slice(&flags.to_le_bytes());
        c[sp_off..sp_off + 8].copy_from_slice(&sp.to_le_bytes());
        c
    }
}
