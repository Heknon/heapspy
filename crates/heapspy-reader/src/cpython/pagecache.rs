//! A small page cache in front of a [`MemorySource`]. The walker makes many
//! small reads close to each other (an object header, then its fields); on a
//! live process each read is a system call, so caching 4 KiB pages cuts the
//! number of calls by an order of magnitude. Reads that a whole-page read
//! cannot serve (a mapping that ends inside the page) go to the source
//! directly, so results are identical to uncached reads.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::Result;
use crate::source::{MappedRange, MemorySource, MemorySummary, Module, TargetInfo, ThreadInfo};

const PAGE: u64 = 4096;
/// Pages kept before the cache is cleared (16 MiB).
const MAX_PAGES: usize = 4096;

pub struct PageCache<'a> {
    inner: &'a dyn MemorySource,
    /// `None` marks a page that could not be read whole.
    pages: Mutex<HashMap<u64, Option<Box<[u8]>>>>,
}

impl<'a> PageCache<'a> {
    pub fn new(inner: &'a dyn MemorySource) -> Self {
        Self {
            inner,
            pages: Mutex::new(HashMap::new()),
        }
    }

    /// Copy `buf.len()` bytes at `addr` from cached pages. `false` if some
    /// page is not readable as a whole.
    fn read_cached(&self, addr: u64, buf: &mut [u8]) -> bool {
        let Some(end) = addr.checked_add(buf.len() as u64) else {
            return false;
        };
        let mut pages = self.pages.lock().unwrap_or_else(|e| e.into_inner());
        let mut cur = addr;
        while cur < end {
            let page = cur & !(PAGE - 1);
            if !pages.contains_key(&page) {
                if pages.len() >= MAX_PAGES {
                    pages.clear();
                }
                let mut b = vec![0u8; PAGE as usize].into_boxed_slice();
                let v = self.inner.read(page, &mut b).is_ok().then_some(b);
                pages.insert(page, v);
            }
            let Some(Some(data)) = pages.get(&page) else {
                return false;
            };
            let off = (cur - page) as usize;
            let n = ((PAGE - (cur - page)).min(end - cur)) as usize;
            let dst = (cur - addr) as usize;
            buf[dst..dst + n].copy_from_slice(&data[off..off + n]);
            cur += n as u64;
        }
        true
    }
}

impl MemorySource for PageCache<'_> {
    fn target(&self) -> TargetInfo {
        self.inner.target()
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        // Large reads bypass the cache.
        if buf.len() as u64 <= 2 * PAGE && self.read_cached(addr, buf) {
            return Ok(());
        }
        self.inner.read(addr, buf)
    }

    fn mapped_ranges(&self) -> Result<Vec<MappedRange>> {
        self.inner.mapped_ranges()
    }

    fn modules(&self) -> Result<Vec<Module>> {
        self.inner.modules()
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        self.inner.threads()
    }

    fn memory_summary(&self) -> Option<MemorySummary> {
        self.inner.memory_summary()
    }

    fn native_blocks(&self) -> Result<Option<Vec<crate::source::NativeBlock>>> {
        self.inner.native_blocks()
    }

    fn find_symbol(&self, module: &Module, name: &str) -> Result<Option<u64>> {
        self.inner.find_symbol(module, name)
    }
}
