//! Plain-text rendering of reports for the terminal. The rendering functions
//! are **stubs**; [`format_bytes`] is implemented.
//!
//! Text output is for people and may change at any time. Tools must use
//! `--json`.

use crate::report::{AnalyzeReport, DiffReport, RetainingPathReport, TypeQueryReport};
use crate::{Error, Result};

/// `heapspy analyze` text output. **Stub.**
pub fn analyze(_r: &AnalyzeReport) -> Result<String> {
    Err(Error::Unimplemented("text rendering of analyze"))
}

/// `heapspy query --type` text output. **Stub.**
pub fn type_query(_r: &TypeQueryReport) -> Result<String> {
    Err(Error::Unimplemented("text rendering of query --type"))
}

/// `heapspy query --retaining-path` text output. **Stub.**
pub fn retaining_path(_r: &RetainingPathReport) -> Result<String> {
    Err(Error::Unimplemented(
        "text rendering of query --retaining-path",
    ))
}

/// `heapspy diff` text output. **Stub.**
pub fn diff(_r: &DiffReport) -> Result<String> {
    Err(Error::Unimplemented("text rendering of diff"))
}

/// Binary-unit size with one decimal: `412.6 MiB`, `1.1 KiB`, `512 B`.
pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1126), "1.1 KiB");
        assert_eq!(format_bytes(432_643_686), "412.6 MiB");
        assert_eq!(format_bytes(u64::MAX), "16.0 EiB");
    }
}
