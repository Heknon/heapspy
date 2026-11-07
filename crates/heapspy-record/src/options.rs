//! What the user asked `heapspy record` to do.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use heapspy_alloc::{EventKind, Mechanism, SamplingParams};

use crate::error::{Error, Result};

/// Longest recording window accepted.
pub const MAX_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
/// Largest `--max-frames` accepted. Recorders may clamp lower (the eBPF
/// verifier bounds loops) and must then say so in their module docs.
pub const MAX_FRAMES_LIMIT: u32 = 1024;

/// `--mechanism`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MechanismChoice {
    /// Linux: eBPF, falling back to ptrace. Windows: ETW alone (the
    /// debugger pauses the target, so it runs only when asked for).
    #[default]
    Auto,
    /// Only this mechanism. On Windows, `etw` alone gives approximate
    /// frames for every event, and `debugger` alone records only arenas.
    Only(Mechanism),
}

impl fmt::Display for MechanismChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MechanismChoice::Auto => f.write_str("auto"),
            MechanismChoice::Only(m) => write!(f, "{m}"),
        }
    }
}

impl FromStr for MechanismChoice {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if s == "auto" {
            return Ok(MechanismChoice::Auto);
        }
        s.parse::<Mechanism>()
            .map(MechanismChoice::Only)
            .map_err(|_| {
                format!("unknown mechanism {s:?} (expected auto, ebpf, ptrace, etw or debugger)")
            })
    }
}

/// Everything `heapspy record` needs. Build with [`RecordOptions::new`] and
/// adjust the fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordOptions {
    /// Target process.
    pub pid: u32,
    /// Recording window. Required on the command line; recording stops
    /// when it elapses (or earlier if the target exits).
    pub duration: Duration,
    /// Event kinds, byte interval and frame limit.
    pub sampling: SamplingParams,
    /// The `.hpya` file to write.
    pub output: PathBuf,
    /// Take a snapshot of the target right after recording stops, so the
    /// samples and the snapshot line up in time.
    pub then_dump: Option<PathBuf>,
    pub mechanism: MechanismChoice,
}

impl RecordOptions {
    /// Default sampling ([`SamplingParams::DEFAULT`]), automatic mechanism,
    /// no final snapshot.
    pub fn new(pid: u32, duration: Duration, output: impl Into<PathBuf>) -> Self {
        Self {
            pid,
            duration,
            sampling: SamplingParams::DEFAULT,
            output: output.into(),
            then_dump: None,
            mechanism: MechanismChoice::Auto,
        }
    }

    /// Check ranges. Called by [`crate::record`] before anything touches the
    /// target.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::InvalidOption(m));
        if self.pid == 0 {
            return bad("pid must be a process id, not 0".into());
        }
        if self.duration.is_zero() {
            return bad("duration must be greater than zero".into());
        }
        if self.duration > MAX_DURATION {
            return bad(format!(
                "duration {:?} is longer than the {}-hour limit",
                self.duration,
                MAX_DURATION.as_secs() / 3600
            ));
        }
        let s = &self.sampling;
        if s.events.is_empty() {
            return bad("no event kinds selected".into());
        }
        if let Some(k) = s.events.iter().find(|k| {
            !matches!(
                k,
                EventKind::Arena | EventKind::Pool | EventKind::LargeObject | EventKind::Native
            )
        }) {
            return bad(format!("event kind {k} cannot be recorded"));
        }
        if s.max_frames == 0 || s.max_frames > MAX_FRAMES_LIMIT {
            return bad(format!(
                "max frames must be between 1 and {MAX_FRAMES_LIMIT}, not {}",
                s.max_frames
            ));
        }
        if self.then_dump.as_ref() == Some(&self.output) {
            return bad("--then-dump and -o name the same file".into());
        }
        Ok(())
    }
}

/// Parse a duration such as `60s`, `500ms`, `5m`, `1h`, or a bare number of
/// seconds (`90`). Fractions are allowed (`1.5s`).
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num
        .parse()
        .map_err(|_| format!("bad duration {s:?} (expected e.g. 60s, 500ms, 5m)"))?;
    let secs = match unit {
        "" | "s" => n,
        "ms" => n / 1000.0,
        "m" | "min" => n * 60.0,
        "h" => n * 3600.0,
        _ => {
            return Err(format!(
                "bad duration unit {unit:?} in {s:?} (use ms, s, m or h)"
            ))
        }
    };
    if !secs.is_finite() || !(0.0..=1e9).contains(&secs) {
        return Err(format!("duration {s:?} is out of range"));
    }
    Ok(Duration::from_secs_f64(secs))
}

/// Parse a byte count such as `524288`, `512K`, `512KiB`, `1M`, `1MiB`.
/// `K`/`M`/`G` are powers of 1024.
pub fn parse_bytes(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("bad byte count {s:?} (expected e.g. 524288 or 512K)"))?;
    let mult: u64 = match unit.to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" | "KIB" => 1 << 10,
        "M" | "MB" | "MIB" => 1 << 20,
        "G" | "GB" | "GIB" => 1 << 30,
        _ => return Err(format!("bad byte unit {unit:?} in {s:?} (use K, M or G)")),
    };
    n.checked_mul(mult)
        .ok_or_else(|| format!("byte count {s:?} is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapspy_alloc::EventKinds;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        for bad in ["", "s", "10x", "-1s", "1e3s", "1..2s"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bytes() {
        assert_eq!(parse_bytes("4096").unwrap(), 4096);
        assert_eq!(parse_bytes("512K").unwrap(), 512 << 10);
        assert_eq!(parse_bytes("1MiB").unwrap(), 1 << 20);
        assert_eq!(parse_bytes("2g").unwrap(), 2 << 30);
        assert_eq!(parse_bytes("0").unwrap(), 0);
        for bad in ["", "K", "1.5M", "12Q", "99999999999999999999G"] {
            assert!(parse_bytes(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn mechanism_choice() {
        assert_eq!(
            "auto".parse::<MechanismChoice>().unwrap(),
            MechanismChoice::Auto
        );
        assert_eq!(
            "etw".parse::<MechanismChoice>().unwrap(),
            MechanismChoice::Only(Mechanism::Etw)
        );
        assert!("bpf".parse::<MechanismChoice>().is_err());
    }

    #[test]
    fn validation() {
        let ok = RecordOptions::new(1234, Duration::from_secs(60), "a.hpya");
        ok.validate().unwrap();
        let check = |f: &dyn Fn(&mut RecordOptions)| {
            let mut o = ok.clone();
            f(&mut o);
            assert!(
                matches!(o.validate(), Err(Error::InvalidOption(_))),
                "{o:?}"
            );
        };
        check(&|o| o.pid = 0);
        check(&|o| o.duration = Duration::ZERO);
        check(&|o| o.duration = MAX_DURATION + Duration::from_secs(1));
        check(&|o| o.sampling.events = EventKinds::NONE);
        check(&|o| o.sampling.events = EventKinds::of(&[EventKind::Other]));
        check(&|o| o.sampling.max_frames = 0);
        check(&|o| o.sampling.max_frames = MAX_FRAMES_LIMIT + 1);
        check(&|o| o.then_dump = Some("a.hpya".into()));
    }
}
