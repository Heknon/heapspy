//! Printing reports and errors.

use std::io::Write;
use std::process::ExitCode;

use heapspy_analyzer::report::ErrorReport;
use serde::Serialize;

/// Print a report as pretty JSON on stdout.
pub fn print_json<T: Serialize>(report: &T) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, report)?;
    writeln!(out)?;
    Ok(())
}

/// Machine-readable error code for the JSON error report.
pub fn error_code(err: &anyhow::Error) -> &'static str {
    for cause in err.chain() {
        if let Some(e) = cause.downcast_ref::<heapspy_analyzer::Error>() {
            return match e {
                heapspy_analyzer::Error::Unimplemented(_) => "unimplemented",
                heapspy_analyzer::Error::NotFound(_) => "not_found",
                heapspy_analyzer::Error::InvalidArgument(_) => "invalid_argument",
                heapspy_analyzer::Error::Snapshot(s) => snapshot_code(s),
            };
        }
        if let Some(e) = cause.downcast_ref::<heapspy_reader::Error>() {
            return match e {
                heapspy_reader::Error::Unimplemented(_) => "unimplemented",
                heapspy_reader::Error::PermissionDenied(_) => "permission_denied",
                heapspy_reader::Error::Io(_) => "io",
                heapspy_reader::Error::Snapshot(s) => snapshot_code(s),
                _ => "internal",
            };
        }
        if let Some(e) = cause.downcast_ref::<heapspy_snapshot::Error>() {
            return snapshot_code(e);
        }
        if let Some(e) = cause.downcast_ref::<heapspy_alloc::Error>() {
            return alloc_code(e);
        }
        if let Some(e) = cause.downcast_ref::<heapspy_record::Error>() {
            match e {
                heapspy_record::Error::Unimplemented(_) => return "unimplemented",
                heapspy_record::Error::PermissionDenied(_) => return "permission_denied",
                heapspy_record::Error::InvalidOption(_) => return "invalid_argument",
                heapspy_record::Error::Alloc(a) => return alloc_code(a),
                heapspy_record::Error::Io(_) => return "io",
                // The source error is next in the chain.
                heapspy_record::Error::Reader(_) => continue,
                heapspy_record::Error::Unsupported(_) => return "internal",
            }
        }
        if cause.is::<InvalidArgument>() {
            return "invalid_argument";
        }
        if cause.downcast_ref::<std::io::Error>().is_some() {
            return "io";
        }
    }
    "internal"
}

fn alloc_code(e: &heapspy_alloc::Error) -> &'static str {
    match e {
        heapspy_alloc::Error::Io(_) => "io",
        _ => "invalid_allocations",
    }
}

fn snapshot_code(e: &heapspy_snapshot::Error) -> &'static str {
    match e {
        heapspy_snapshot::Error::Io(_) => "io",
        _ => "invalid_snapshot",
    }
}

/// A bad command-line value that clap could not check (e.g. an address).
#[derive(Debug)]
pub struct InvalidArgument(pub String);

impl std::fmt::Display for InvalidArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidArgument {}

/// Print `err` and return the failure exit code (1). With `json`, an
/// `ErrorReport` is also printed on stdout.
pub fn report_error(err: &anyhow::Error, json: bool) -> ExitCode {
    if json {
        let r = ErrorReport::new(error_code(err), format!("{err:#}"));
        let _ = print_json(&r);
    }
    eprintln!("heapspy: error: {err:#}");
    ExitCode::from(1)
}
