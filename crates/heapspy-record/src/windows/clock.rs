//! ETW timestamps to Unix-epoch nanoseconds. Pure code, tested everywhere.
//!
//! A real-time ETW consumer gets `EVENT_HEADER.TimeStamp` as a `FILETIME`
//! (100 ns ticks since 1601-01-01 UTC) unless it asks for raw timestamps;
//! with `PROCESS_TRACE_MODE_RAW_TIMESTAMP` it is the session clock, which
//! for `ClientContext = 1` is QPC ticks. Both conversions are here; the
//! recorder uses FILETIME. The snapshot's `captured_at` is the system
//! clock, so FILETIME needs no correction; QPC is anchored once at start
//! with a pair of (QPC, system time) readings taken together.

/// 100 ns ticks from 1601-01-01 to 1970-01-01.
pub const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// FILETIME ticks to Unix ns; times before 1970 clamp to 0.
pub fn filetime_to_unix_ns(ft: u64) -> u64 {
    ft.saturating_sub(FILETIME_UNIX_EPOCH).saturating_mul(100)
}

/// QPC ticks to Unix ns, given one simultaneous reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QpcClock {
    /// QPC ticks per second.
    pub freq: u64,
    pub anchor_qpc: u64,
    pub anchor_unix_ns: u64,
}

impl QpcClock {
    pub fn to_unix_ns(&self, qpc: u64) -> u64 {
        if self.freq == 0 {
            return self.anchor_unix_ns;
        }
        let d = qpc as i128 - self.anchor_qpc as i128;
        let ns = d * 1_000_000_000 / self.freq as i128;
        (self.anchor_unix_ns as i128 + ns).clamp(0, u64::MAX as i128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime() {
        assert_eq!(filetime_to_unix_ns(FILETIME_UNIX_EPOCH), 0);
        // 2024-01-01T00:00:00Z = 1704067200 s.
        let ft = FILETIME_UNIX_EPOCH + 1_704_067_200 * 10_000_000 + 5;
        assert_eq!(filetime_to_unix_ns(ft), 1_704_067_200_000_000_500);
        assert_eq!(filetime_to_unix_ns(0), 0);
    }

    #[test]
    fn qpc() {
        let c = QpcClock {
            freq: 10_000_000,
            anchor_qpc: 1_000,
            anchor_unix_ns: 5_000_000_000,
        };
        assert_eq!(c.to_unix_ns(1_000), 5_000_000_000);
        assert_eq!(c.to_unix_ns(11_000), 5_001_000_000);
        assert_eq!(c.to_unix_ns(0), 4_999_900_000);
        let z = QpcClock { freq: 0, ..c };
        assert_eq!(z.to_unix_ns(123), 5_000_000_000);
    }
}
