//! Printing reports and errors.

use std::io::Write;
use std::process::ExitCode;

use heapspy_analyzer::report::ErrorReport;
use heapspy_snapshot::SourceKind;
use serde::Serialize;

/// How to style text on stdout for `--color`.
pub fn style(choice: crate::cli::ColorChoice) -> heapspy_analyzer::render::Style {
    use std::io::IsTerminal;
    let tty = std::io::stdout().is_terminal();
    let color = match choice {
        crate::cli::ColorChoice::Always => true,
        crate::cli::ColorChoice::Never => false,
        crate::cli::ColorChoice::Auto => tty && std::env::var_os("NO_COLOR").is_none(),
    };
    let width = if tty {
        crossterm::terminal::size().map_or(100, |(w, _)| w as usize)
    } else {
        100
    };
    heapspy_analyzer::render::Style { color, width }
}

/// Print a report as pretty JSON on stdout.
pub fn print_json<T: Serialize>(report: &T) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, report)?;
    writeln!(out)?;
    Ok(())
}

/// Machine-readable error code for the JSON error report. The codes are
/// listed in `docs/json-schema.md`; `internal` is for bugs.
pub fn error_code(err: &anyhow::Error) -> &'static str {
    // A dump that failed on an image cut short reports that first: the
    // error underneath (no runtime found, unreadable memory) follows from it.
    if err.downcast_ref::<TruncatedImage>().is_some() {
        return "truncated_image";
    }
    let source = err.downcast_ref::<DumpSource>().map(|s| s.kind);
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
            return reader_code(e, source);
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
                // `Reader` is transparent: the wrapped error is not a link of
                // its own in the chain, so map it here.
                heapspy_record::Error::Reader(r) => return reader_code(r, source),
                heapspy_record::Error::Unsupported(_) => return "unsupported",
            }
        }
        if cause.is::<InvalidArgument>() {
            return "invalid_argument";
        }
        if let Some(e) = cause.downcast_ref::<std::io::Error>() {
            return io_code(e, source);
        }
    }
    "internal"
}

/// Code for an error from `heapspy-alloc`. Reading a profile can only fail
/// with I/O or a format error; the writer's own checks
/// (`InvalidArgument`, `LimitExceeded`) only reach here through `record`.
fn alloc_code(e: &heapspy_alloc::Error) -> &'static str {
    use heapspy_alloc::Error as E;
    match e {
        E::Io(_) => "io",
        E::BadMagic
        | E::UnsupportedVersion { .. }
        | E::Truncated(_)
        | E::Corrupt(_)
        | E::MissingSection(_)
        | E::UnknownRequiredSection(_)
        | E::InvalidString(_)
        | E::InvalidBlob(_)
        | E::InvalidCode(_) => "invalid_allocations",
        // The recording is larger than the format can hold.
        E::LimitExceeded(_) => "unsupported",
        // A recorder passed the writer inconsistent data: a bug.
        E::InvalidArgument(_) => "internal",
    }
}

/// Code for an error from `heapspy-reader`. `source` is the kind of dump
/// source the error came from, if known.
fn reader_code(e: &heapspy_reader::Error, source: Option<SourceKind>) -> &'static str {
    use heapspy_reader::Error as E;
    let file_image = matches!(source, Some(SourceKind::Core | SourceKind::Minidump));
    match e {
        E::Unimplemented(_) => "unimplemented",
        // For a core or minidump this is an image format heapspy does not
        // read (32-bit, big-endian, another CPU).
        E::Unsupported(_) if file_image => "invalid_image",
        E::Unsupported(_) => "unsupported",
        E::Unmapped { .. } | E::Format(_) => "invalid_image",
        E::Truncated(_) => "truncated_image",
        E::NoSuchProcess(_) => "no_such_process",
        E::PermissionDenied(_) => "permission_denied",
        E::NotPython(_) => "not_python",
        E::UnsupportedPython(_) => "unsupported_python",
        E::Io(io) => io_code(io, source),
        E::Snapshot(s) => snapshot_code(s),
    }
}

/// An I/O error while reading a live process (`/proc/<pid>/...`) is about
/// the process; any other I/O error is about a file.
fn io_code(e: &std::io::Error, source: Option<SourceKind>) -> &'static str {
    match (source, e.kind()) {
        (Some(SourceKind::Pid), std::io::ErrorKind::PermissionDenied) => "permission_denied",
        (Some(SourceKind::Pid), std::io::ErrorKind::NotFound) => "no_such_process",
        _ => "io",
    }
}

fn snapshot_code(e: &heapspy_snapshot::Error) -> &'static str {
    match e {
        heapspy_snapshot::Error::Io(_) => "io",
        _ => "invalid_snapshot",
    }
}

/// Context on an error from opening or reading a dump source: the text
/// shown (e.g. "cannot open core core.1234") and the kind of source.
#[derive(Debug)]
pub struct DumpSource {
    pub kind: SourceKind,
    pub text: String,
}

impl std::fmt::Display for DumpSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Context on a failed dump of an image that is missing memory its own
/// headers describe (a core file cut short).
#[derive(Debug)]
pub struct TruncatedImage {
    pub missing_bytes: u64,
}

impl std::fmt::Display for TruncatedImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the image is missing {} bytes of memory its headers describe (cut short?)",
            self.missing_bytes
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use heapspy_reader::Error as E;
    use std::io::ErrorKind;

    fn dump_err(kind: SourceKind, e: E) -> anyhow::Error {
        Err::<(), _>(e)
            .context(DumpSource {
                kind,
                text: "cannot open".into(),
            })
            .unwrap_err()
    }

    fn io(kind: ErrorKind) -> E {
        E::Io(std::io::Error::new(kind, "x"))
    }

    #[test]
    fn reader_errors_have_specific_codes() {
        use SourceKind::{Core, Minidump, Pid};
        let snapshot_io = || E::Snapshot(heapspy_snapshot::Error::Io(std::io::Error::other("x")));
        let cases = [
            (Pid, E::Unimplemented("x"), "unimplemented"),
            (
                Pid,
                E::Unsupported("cannot dump itself".into()),
                "unsupported",
            ),
            (
                Core,
                E::Unsupported("32-bit ELF cores".into()),
                "invalid_image",
            ),
            (
                Minidump,
                E::Unsupported("32-bit x86".into()),
                "invalid_image",
            ),
            (Core, E::Unmapped { addr: 1, len: 8 }, "invalid_image"),
            (Minidump, E::Format("bad stream".into()), "invalid_image"),
            (Core, E::Truncated("PT_NOTE".into()), "truncated_image"),
            (Minidump, E::Truncated("stream".into()), "truncated_image"),
            (Pid, E::NoSuchProcess("pid 1".into()), "no_such_process"),
            // ptrace EPERM on Linux and ERROR_ACCESS_DENIED on Windows both
            // become PermissionDenied in the reader.
            (
                Pid,
                E::PermissionDenied("ptrace".into()),
                "permission_denied",
            ),
            (Pid, E::NotPython("no _PyRuntime".into()), "not_python"),
            (Core, E::NotPython("no _PyRuntime".into()), "not_python"),
            (
                Pid,
                E::UnsupportedPython("debug build".into()),
                "unsupported_python",
            ),
            (Pid, io(ErrorKind::PermissionDenied), "permission_denied"),
            (Pid, io(ErrorKind::NotFound), "no_such_process"),
            (Pid, io(ErrorKind::Other), "io"),
            (Core, io(ErrorKind::NotFound), "io"),
            (Core, io(ErrorKind::PermissionDenied), "io"),
            (Pid, snapshot_io(), "io"),
        ];
        for (kind, e, code) in cases {
            let text = e.to_string();
            assert_eq!(error_code(&dump_err(kind, e)), code, "{kind:?} {text}");
        }
    }

    #[test]
    fn truncated_image_is_reported_first() {
        let err = Err::<(), _>(E::NotPython("no _PyRuntime".into()))
            .context(TruncatedImage { missing_bytes: 10 })
            .context(DumpSource {
                kind: SourceKind::Core,
                text: "dump failed".into(),
            })
            .unwrap_err();
        assert_eq!(error_code(&err), "truncated_image");
        let text = format!("{err:#}");
        assert!(text.contains("missing 10 bytes"), "{text}");
        assert!(text.contains("not a CPython process"), "{text}");
    }

    /// `heapspy_record::Error::Reader` is `#[error(transparent)]`, so the
    /// reader error it wraps is not a separate link in the cause chain.
    #[test]
    fn record_errors_have_specific_codes() {
        use heapspy_record::Error as R;
        let cases = [
            (R::Unimplemented("eBPF"), "unimplemented"),
            (R::Unsupported("eBPF needs Linux".into()), "unsupported"),
            (R::PermissionDenied("CAP_BPF".into()), "permission_denied"),
            (R::InvalidOption("duration".into()), "invalid_argument"),
            (
                R::Reader(E::NoSuchProcess("pid 1".into())),
                "no_such_process",
            ),
            (
                R::Reader(E::NotPython("no _PyRuntime".into())),
                "not_python",
            ),
            (
                R::Reader(E::UnsupportedPython("debug build".into())),
                "unsupported_python",
            ),
            (
                R::Reader(E::PermissionDenied("ptrace".into())),
                "permission_denied",
            ),
            (R::Reader(E::Unimplemented("live::open")), "unimplemented"),
            (
                R::Reader(io(ErrorKind::PermissionDenied)),
                "permission_denied",
            ),
            (
                R::Alloc(heapspy_alloc::Error::LimitExceeded("samples")),
                "unsupported",
            ),
            (R::Io(std::io::Error::other("disk full")), "io"),
        ];
        for (e, code) in cases {
            let text = e.to_string();
            let err = Err::<(), _>(e)
                .context(DumpSource {
                    kind: SourceKind::Pid,
                    text: "cannot record pid 1".into(),
                })
                .unwrap_err();
            assert_eq!(error_code(&err), code, "{text}");
        }
    }

    #[test]
    fn other_errors_keep_their_codes() {
        let err = anyhow::Error::from(InvalidArgument("bad".into()));
        assert_eq!(error_code(&err), "invalid_argument");
        assert_eq!(error_code(&anyhow::anyhow!("bug")), "internal");
        let err = anyhow::Error::from(std::io::Error::other("x"));
        assert_eq!(error_code(&err), "io");
        // Without a dump source, a reader I/O error is about a file.
        let err = anyhow::Error::from(io(ErrorKind::NotFound));
        assert_eq!(error_code(&err), "io");
    }
}
