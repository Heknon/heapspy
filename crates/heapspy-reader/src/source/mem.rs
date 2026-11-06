//! An in-memory [`MemorySource`] made of byte segments. For unit tests of the
//! walker and of symbol lookup: lay out fake objects at chosen addresses and
//! read them back through the same trait the real backends implement.

use super::{MappedRange, MemorySource, MemorySummary, Module, Perms, TargetInfo, ThreadInfo};
use crate::error::{Error, Result};

/// Segments of target memory held in memory.
#[derive(Clone, Debug)]
pub struct MemImage {
    target: TargetInfo,
    /// Sorted by start, non-overlapping.
    segments: Vec<(u64, Vec<u8>)>,
    modules: Vec<Module>,
    threads: Vec<ThreadInfo>,
    summary: Option<MemorySummary>,
}

impl MemImage {
    pub fn new(target: TargetInfo) -> Self {
        Self {
            target,
            segments: Vec::new(),
            modules: Vec::new(),
            threads: Vec::new(),
            summary: None,
        }
    }

    /// Map `bytes` at `addr`. Panics if it overlaps an existing segment
    /// (this is a test helper; overlaps are a test bug).
    pub fn map(&mut self, addr: u64, bytes: Vec<u8>) -> &mut Self {
        let end = addr
            .checked_add(bytes.len() as u64)
            .expect("segment overflows u64");
        for (s, b) in &self.segments {
            let e = s + b.len() as u64;
            assert!(
                end <= *s || addr >= e,
                "segment {addr:#x}..{end:#x} overlaps {s:#x}..{e:#x}"
            );
        }
        let pos = self.segments.partition_point(|(s, _)| *s < addr);
        self.segments.insert(pos, (addr, bytes));
        self
    }

    pub fn add_module(&mut self, m: Module) -> &mut Self {
        self.modules.push(m);
        self
    }

    pub fn add_thread(&mut self, t: ThreadInfo) -> &mut Self {
        self.threads.push(t);
        self
    }

    pub fn set_memory_summary(&mut self, s: MemorySummary) -> &mut Self {
        self.summary = Some(s);
        self
    }
}

impl MemorySource for MemImage {
    fn target(&self) -> TargetInfo {
        self.target
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        let unmapped = Error::Unmapped {
            addr,
            len: buf.len(),
        };
        if buf.is_empty() {
            return Ok(());
        }
        let Some(end) = addr.checked_add(buf.len() as u64) else {
            return Err(unmapped);
        };
        let mut cur = addr;
        let mut i = self
            .segments
            .partition_point(|(s, b)| s + b.len() as u64 <= addr);
        while cur < end {
            let Some((s, b)) = self.segments.get(i) else {
                return Err(unmapped);
            };
            if *s > cur {
                return Err(unmapped);
            }
            let seg_end = s + b.len() as u64;
            let take_end = end.min(seg_end);
            let src = &b[(cur - s) as usize..(take_end - s) as usize];
            let dst = (cur - addr) as usize;
            buf[dst..dst + src.len()].copy_from_slice(src);
            cur = take_end;
            i += 1;
        }
        Ok(())
    }

    fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
        Ok(self
            .segments
            .iter()
            .map(|(s, b)| MappedRange {
                start: *s,
                size: b.len() as u64,
                perms: Perms {
                    read: true,
                    write: true,
                    exec: false,
                },
                file: None,
            })
            .collect())
    }

    fn modules(&self) -> Result<Vec<Module>> {
        Ok(self.modules.clone())
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Ok(self.threads.clone())
    }

    fn memory_summary(&self) -> Option<MemorySummary> {
        self.summary.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySourceExt;

    #[test]
    fn reads_within_and_across_segments() {
        let mut m = MemImage::new(TargetInfo::LINUX_X86_64);
        m.map(0x1000, vec![1, 2, 3, 4])
            .map(0x1004, vec![5, 6])
            .map(0x2000, b"hi\0".to_vec());
        let mut b = [0u8; 6];
        m.read(0x1000, &mut b).unwrap();
        assert_eq!(b, [1, 2, 3, 4, 5, 6]);
        assert!(matches!(
            m.read(0x1003, &mut [0u8; 4]),
            Err(Error::Unmapped { .. })
        ));
        assert!(m.read(0xfff, &mut [0u8; 1]).is_err());
        assert!(m.read(u64::MAX, &mut [0u8; 2]).is_err());
        m.read(0x5000, &mut []).unwrap();
        assert_eq!(m.read_u32(0x1000).unwrap(), 0x0403_0201);
        assert_eq!(m.read_cstr(0x2000, 100).unwrap(), b"hi");
        assert_eq!(m.read_cstr(0x2000, 1).unwrap(), b"h");
    }

    #[test]
    fn helpers_work_through_dyn() {
        let mut m = MemImage::new(TargetInfo::LINUX_X86_64);
        m.map(
            0x10,
            0xdead_beef_u64
                .to_le_bytes()
                .iter()
                .chain(&7u64.to_le_bytes())
                .copied()
                .collect(),
        );
        let d: &dyn MemorySource = &m;
        assert_eq!(d.read_ptr(0x10).unwrap(), 0xdead_beef);
        assert_eq!(d.read_ptrs(0x10, 2).unwrap(), vec![0xdead_beef, 7]);
        assert!(d.read_ptr(0x18 + 1).is_err());
    }
}
