//! `heapspy dump`: the `--json` report, the stderr summary line, and the
//! error codes of failed dumps.
//!
//! The live-process tests need `/usr/bin/python3.12` (or `HEAPSPY_PY312`)
//! and permission to ptrace a sibling process, which in practice means root
//! or `kernel.yama.ptrace_scope` 0. Without them they print why and pass.

use std::path::Path;
use std::process::{Command, Output};

use heapspy_analyzer::report::DumpReport;

fn heapspy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_heapspy"))
        .args(args)
        .output()
        .expect("run heapspy")
}

/// Run a dump that must fail with `--json`; return the error code. Checks
/// the exit status, the error document and the stderr message.
fn dump_error_code(args: &[&str]) -> String {
    let out = heapspy(args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
    assert!(stderr.starts_with("heapspy: error: "), "{args:?}: {stderr}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{args:?}: stdout is not JSON ({e}): {stderr}"));
    assert_eq!(v["schema_version"], 1, "{v}");
    assert_eq!(v["kind"], "error", "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(stderr.contains(message), "{message} / {stderr}");
    v["error"]["code"].as_str().unwrap().to_string()
}

/// The summary line heapspy-mcp parses, built from the report's numbers.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn summary_line(r: &DumpReport) -> String {
    format!(
        "wrote {}: {} objects, {} edges, {} roots, {} bytes{}",
        r.path,
        r.objects,
        r.edges,
        r.roots,
        r.bytes_written,
        if r.truncated { " (truncated)" } else { "" }
    )
}

#[test]
fn junk_and_missing_images_have_specific_codes() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("o.hpy");
    let out = out.to_str().unwrap();
    let junk = dir.path().join("junk");
    std::fs::write(
        &junk,
        b"this is not a core file or a minidump\n".repeat(200),
    )
    .unwrap();
    let junk = junk.to_str().unwrap();
    assert_eq!(
        dump_error_code(&["dump", "--core", junk, "-o", out, "--json"]),
        "invalid_image"
    );
    assert_eq!(
        dump_error_code(&["dump", "--minidump", junk, "-o", out, "--json"]),
        "invalid_image"
    );
    let missing = dir.path().join("missing.core");
    let missing = missing.to_str().unwrap();
    assert_eq!(
        dump_error_code(&["dump", "--core", missing, "-o", out, "--json"]),
        "io"
    );
    assert!(!Path::new(out).exists());
}

#[test]
fn a_core_cut_in_its_headers_is_truncated_image() {
    // An x86-64 ELF core header that announces 4 program headers, with the
    // file ending right after the header.
    let mut b = vec![0u8; 64];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; // 64-bit
    b[5] = 1; // little-endian
    b[6] = 1;
    b[0x10..0x12].copy_from_slice(&4u16.to_le_bytes()); // ET_CORE
    b[0x12..0x14].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    b[0x38..0x3a].copy_from_slice(&4u16.to_le_bytes()); // e_phnum
    let dir = tempfile::tempdir().unwrap();
    let core = dir.path().join("cut.core");
    std::fs::write(&core, &b).unwrap();
    let out = dir.path().join("o.hpy");
    let args = [
        "dump",
        "--core",
        core.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--json",
    ];
    assert_eq!(dump_error_code(&args), "truncated_image");
    // Without --json: the same failure, nothing on stdout.
    let r = heapspy(&args[..5]);
    assert_eq!(r.status.code(), Some(1));
    assert!(r.stdout.is_empty());
    assert!(String::from_utf8_lossy(&r.stderr).contains("image cut short"));
}

#[cfg(target_os = "linux")]
mod live {
    use std::io::{BufRead, BufReader};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    use super::*;

    /// A child process, killed on drop.
    struct Victim(Child);

    impl Victim {
        fn pid(&self) -> String {
            self.0.id().to_string()
        }
    }

    impl Drop for Victim {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn python312() -> Option<PathBuf> {
        let p: PathBuf = std::env::var_os("HEAPSPY_PY312")
            .map(Into::into)
            .unwrap_or_else(|| "/usr/bin/python3.12".into());
        if p.exists() {
            Some(p)
        } else {
            eprintln!("skipped: {} not found (set HEAPSPY_PY312)", p.display());
            None
        }
    }

    /// `python3.12 -c "import time; time.sleep(30)"`, once the interpreter
    /// is up (it prints a line first).
    fn sleeping_python() -> Option<Victim> {
        let mut child = Command::new(python312()?)
            .args([
                "-c",
                "import time; print('ready', flush=True); time.sleep(30)",
            ])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn python3.12");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ready");
        Some(Victim(child))
    }

    fn sleep30() -> Victim {
        Victim(
            Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn sleep"),
        )
    }

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            == Some("0")
    }

    /// Whether this environment lets heapspy ptrace a sibling process.
    fn can_trace(out: &Output) -> bool {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.code() == Some(1) && stdout.contains("\"permission_denied\"") {
            eprintln!(
                "skipped: ptrace not permitted here: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return false;
        }
        true
    }

    #[test]
    fn dump_json_of_a_live_process() {
        let Some(victim) = sleeping_python() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().join("live.hpy");
        let snap = snap.to_str().unwrap();
        let pid = victim.pid();

        let out = heapspy(&["dump", "--pid", &pid, "-o", snap, "--json"]);
        if !can_trace(&out) {
            return;
        }
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(0), "{stderr}");

        // Schema round trip: every field is known, none is missing.
        let original: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let r: DumpReport = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(serde_json::to_value(&r).unwrap(), original);

        assert_eq!(original["schema_version"], 1);
        assert_eq!(original["kind"], "dump");
        assert_eq!(r.path, snap);
        assert_eq!(r.source.kind, "pid");
        assert_eq!(r.source.reference, pid);
        assert!(
            r.python_version.starts_with("3.12."),
            "{}",
            r.python_version
        );
        assert!(!r.contents_captured);
        assert!(r.objects > 1000 && r.edges > r.objects / 2, "{r:?}");
        assert!(r.types > 50 && r.roots > 0, "{r:?}");
        assert_eq!(r.bytes_written, std::fs::metadata(snap).unwrap().len());
        assert!(!r.truncated);
        assert_eq!(r.image.missing_bytes, 0);
        let pause = r.pause_ms.expect("a live dump measures its pause");
        assert!(pause > 0.0 && pause < 30_000.0, "{pause}");
        assert!(r.notes.iter().all(|n| n.code != "truncated_snapshot"));

        // The stderr summary line is unchanged, and the last line.
        assert_eq!(stderr.lines().last(), Some(summary_line(&r).as_str()));
        assert!(stderr.ends_with('\n'));

        // Without --json: nothing on stdout, the same kind of summary line.
        let out = heapspy(&["dump", "--pid", &pid, "-o", snap]);
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(0), "{stderr}");
        assert!(out.stdout.is_empty());
        let line = stderr.lines().last().unwrap();
        let prefix = format!("wrote {snap}: ");
        let rest = line
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("{line}"));
        let words: Vec<&str> = rest.split(", ").collect();
        assert_eq!(words.len(), 4, "{line}");
        for (w, unit) in words.iter().zip(["objects", "edges", "roots", "bytes"]) {
            let (n, u) = w.split_once(' ').unwrap();
            assert!(n.parse::<u64>().is_ok() && u == unit, "{line}");
        }
    }

    #[test]
    fn a_process_that_is_not_python() {
        let victim = sleep30();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("o.hpy");
        let args = [
            "dump",
            "--pid",
            &victim.pid(),
            "-o",
            out_path.to_str().unwrap(),
            "--json",
        ];
        if !can_trace(&heapspy(&args)) {
            return;
        }
        assert_eq!(dump_error_code(&args), "not_python");
        assert!(!out_path.exists());
    }

    #[test]
    fn a_pid_that_does_not_exist() {
        // Above the largest pid_max Linux allows (2^22).
        assert_eq!(
            dump_error_code(&["dump", "--pid", "1073741823", "-o", "x.hpy", "--json"]),
            "no_such_process"
        );
    }

    /// As root, run heapspy as `nobody` against a root-owned process:
    /// ptrace refuses with EPERM.
    #[test]
    fn permission_denied_without_ptrace_rights() {
        use std::os::unix::process::CommandExt;
        if !is_root() {
            eprintln!("skipped: needs root to run heapspy as another user");
            return;
        }
        let victim = sleep30();
        let out = Command::new(env!("CARGO_BIN_EXE_heapspy"))
            .args(["dump", "--pid", &victim.pid(), "-o", "/nonexistent/x.hpy"])
            .arg("--json")
            .uid(65534)
            .gid(65534)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["error"]["code"], "permission_denied", "{v}");
        assert!(stderr.contains("CAP_SYS_PTRACE"), "{stderr}");
    }

    /// A gcore core of a Python process, cut short: gcore writes the notes
    /// last, so the cut removes them.
    #[test]
    fn a_cut_gcore_core_is_truncated_image() {
        let Some(victim) = sleeping_python() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("core");
        let g = Command::new("gcore")
            .arg("-o")
            .arg(&prefix)
            .arg(victim.pid())
            .output();
        let core = PathBuf::from(format!("{}.{}", prefix.display(), victim.pid()));
        match g {
            Ok(o) if o.status.success() && core.exists() => {}
            _ => {
                eprintln!("skipped: gcore not available or not permitted");
                return;
            }
        }
        drop(victim);
        let out = dir.path().join("o.hpy");
        let out = out.to_str().unwrap();
        let full = core.to_str().unwrap();
        let ok = heapspy(&["dump", "--core", full, "-o", out, "--json"]);
        assert_eq!(ok.status.code(), Some(0));
        let r: DumpReport = serde_json::from_slice(&ok.stdout).unwrap();
        assert_eq!(r.source.kind, "core");
        assert_eq!(r.pause_ms, None);

        let data = std::fs::read(&core).unwrap();
        let cut = dir.path().join("cut.core");
        std::fs::write(&cut, &data[..data.len() / 2]).unwrap();
        std::fs::remove_file(out).unwrap();
        let code = dump_error_code(&["dump", "--core", cut.to_str().unwrap(), "-o", out, "--json"]);
        assert_eq!(code, "truncated_image");
        assert!(!Path::new(out).exists());
    }
}
