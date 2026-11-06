//! Attaching ETW events to sampled Python stacks by time. Pure code.
//!
//! ETW cannot read the target's memory when an event fires, so a side
//! thread samples every Python thread's stack at a fixed rate. Each event
//! takes the stack sample of the same thread nearest in time, if one is
//! within `max_distance_ns`; otherwise it gets no frames. Frames found this
//! way are approximate (`APPROXIMATE_FRAMES`).

use std::collections::{HashMap, VecDeque};

use heapspy_reader::cpython::frames::RawFrame;

/// One stack sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackSample {
    pub ts_ns: u64,
    pub frames: Vec<RawFrame>,
    pub truncated: bool,
}

/// Recent stack samples per thread.
#[derive(Debug)]
pub struct StackHistory {
    per_thread: HashMap<u64, VecDeque<StackSample>>,
    /// Samples older than the newest by more than this are dropped.
    keep_ns: u64,
    pub max_distance_ns: u64,
}

impl StackHistory {
    pub fn new(keep_ns: u64, max_distance_ns: u64) -> Self {
        Self {
            per_thread: HashMap::new(),
            keep_ns,
            max_distance_ns,
        }
    }

    /// Add a sample. Samples of one thread must come in time order.
    pub fn push(&mut self, tid: u64, s: StackSample) {
        let q = self.per_thread.entry(tid).or_default();
        let newest = s.ts_ns;
        q.push_back(s);
        while q
            .front()
            .is_some_and(|f| newest.saturating_sub(f.ts_ns) > self.keep_ns)
        {
            q.pop_front();
        }
    }

    /// The sample of `tid` nearest to `ts_ns`, if within the distance.
    pub fn nearest(&self, tid: u64, ts_ns: u64) -> Option<&StackSample> {
        let q = self.per_thread.get(&tid)?;
        let i = q.partition_point(|s| s.ts_ns < ts_ns);
        let mut best: Option<&StackSample> = None;
        for j in [i.wrapping_sub(1), i] {
            if let Some(s) = q.get(j) {
                if best.is_none_or(|b| s.ts_ns.abs_diff(ts_ns) < b.ts_ns.abs_diff(ts_ns)) {
                    best = Some(s);
                }
            }
        }
        best.filter(|s| s.ts_ns.abs_diff(ts_ns) <= self.max_distance_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(ts: u64, code: u64) -> StackSample {
        StackSample {
            ts_ns: ts,
            frames: vec![RawFrame {
                code,
                instr_offset: None,
            }],
            truncated: false,
        }
    }

    #[test]
    fn nearest_same_thread_within_distance() {
        let mut h = StackHistory::new(1_000, 15);
        h.push(1, s(100, 0xa));
        h.push(1, s(110, 0xb));
        h.push(1, s(130, 0xc));
        h.push(2, s(105, 0xd));
        assert_eq!(h.nearest(1, 104).unwrap().frames[0].code, 0xa);
        assert_eq!(h.nearest(1, 106).unwrap().frames[0].code, 0xb);
        assert_eq!(h.nearest(1, 125).unwrap().frames[0].code, 0xc);
        assert_eq!(h.nearest(1, 90).unwrap().frames[0].code, 0xa);
        assert!(h.nearest(1, 50).is_none(), "too far");
        assert!(h.nearest(1, 200).is_none(), "too far");
        assert_eq!(h.nearest(2, 110).unwrap().frames[0].code, 0xd);
        assert!(h.nearest(3, 100).is_none(), "other thread");
    }

    #[test]
    fn old_samples_age_out() {
        let mut h = StackHistory::new(50, 1_000);
        h.push(1, s(0, 1));
        h.push(1, s(40, 2));
        h.push(1, s(100, 3));
        // 0 and 40 are more than 50 older than 100: only 100 is left.
        assert_eq!(h.per_thread[&1].len(), 1);
        assert_eq!(h.nearest(1, 60).unwrap().frames[0].code, 3);
    }
}
