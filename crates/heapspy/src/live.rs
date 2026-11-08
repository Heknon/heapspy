//! What a running target is doing right now, read without stopping it:
//! each thread's Python stack, and the process's memory from the OS.
//!
//! Used by `analyze --pid`, `watch` and `top`. Every read may race with the
//! target; a failed or odd read leaves a frame or a number out rather than
//! failing the command.

use std::collections::HashMap;

use heapspy_alloc::linetable::line_for;
use heapspy_alloc::LineTableFormat;
use heapspy_reader::cpython::frames::{self, CodeInfo};
use heapspy_reader::MemorySource;
use heapspy_record::Target;

/// One Python frame, innermost first in [`PyThread::frames`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyFrame {
    pub function: String,
    pub file: String,
    pub line: Option<u32>,
}

impl PyFrame {
    /// `file:line` with the file shortened to its last two components.
    pub fn location(&self) -> String {
        let file = short_file(&self.file);
        match self.line {
            Some(l) => format!("{file}:{l}"),
            None => file,
        }
    }
}

/// `site-packages/app/cache.py` → `app/cache.py`.
pub fn short_file(path: &str) -> String {
    let parts: Vec<&str> = path.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    if parts.len() <= 2 {
        return path.to_string();
    }
    parts[parts.len() - 2..].join("/")
}

/// One thread of the target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyThread {
    /// OS thread id.
    pub tid: u64,
    /// OS thread name (`/proc/<pid>/task/<tid>/comm`), when known.
    pub name: Option<String>,
    /// Scheduler state: `running`, `sleeping`, `disk`, `stopped`, … when known.
    pub state: Option<&'static str>,
    /// Python frames, innermost first. Empty when the thread is not running
    /// Python code.
    pub frames: Vec<PyFrame>,
    /// The process's main thread (its tid is the pid).
    pub is_main: bool,
}

/// How to name a thread in a table: its OS name when the program set one,
/// else `main` or `tid N`.
pub fn thread_label(t: &PyThread) -> String {
    let main = t.is_main;
    match &t.name {
        Some(n) if !n.starts_with("python") && !n.is_empty() => n.clone(),
        _ if main => "main".to_string(),
        _ => format!("tid {}", t.tid),
    }
}

/// Reads the Python stacks of a running process again and again.
pub struct StackReader {
    pid: u32,
    src: Box<dyn MemorySource>,
    target: Target,
    format: LineTableFormat,
    /// Code objects by address. A freed code object's address can be reused,
    /// so the cache is dropped now and then.
    codes: HashMap<u64, Option<CodeInfo>>,
    reads: u32,
}

impl StackReader {
    /// Open `pid` for reading without stopping it, and find its runtime.
    pub fn open(pid: u32) -> anyhow::Result<StackReader> {
        let src = heapspy_record::live::open(pid)?;
        let target = Target::locate(src.as_ref(), pid)?;
        let format = LineTableFormat::for_python(target.runtime.version).unwrap_or_default();
        Ok(StackReader {
            pid,
            src,
            target,
            format,
            codes: HashMap::new(),
            reads: 0,
        })
    }

    /// Every Python thread's stack, at most `max_frames` frames each.
    pub fn read(&mut self, max_frames: usize) -> Vec<PyThread> {
        self.reads += 1;
        if self.reads % 64 == 0 {
            self.codes.clear();
        }
        let fo = self.target.offsets;
        let states =
            frames::thread_states(self.src.as_ref(), &fo, self.target.runtime.runtime_addr)
                .unwrap_or_default();
        let mut out = Vec::new();
        for ts in states {
            let raw =
                frames::read_stack(self.src.as_ref(), &fo, ts.addr, max_frames).unwrap_or_default();
            let mut fr = Vec::new();
            for f in raw.frames {
                let src = self.src.as_ref();
                let code = self
                    .codes
                    .entry(f.code)
                    .or_insert_with(|| frames::read_code(src, &fo, f.code).ok());
                let Some(c) = code else { continue };
                let line = c
                    .linetable
                    .as_deref()
                    .and_then(|t| line_for(self.format, t, c.firstlineno, f.instr_offset))
                    .or_else(|| u32::try_from(c.firstlineno).ok());
                fr.push(PyFrame {
                    function: c.qualname.clone().unwrap_or_else(|| "?".into()),
                    file: c.filename.clone().unwrap_or_else(|| "?".into()),
                    line,
                });
            }
            let (name, state) = os_thread(self.pid, ts.native_thread_id);
            out.push(PyThread {
                tid: ts.native_thread_id,
                name,
                state,
                frames: fr,
                is_main: ts.native_thread_id == u64::from(self.pid),
            });
        }
        out
    }
}

/// Name and state of an OS thread.
#[cfg(target_os = "linux")]
fn os_thread(pid: u32, tid: u64) -> (Option<String>, Option<&'static str>) {
    let base = format!("/proc/{pid}/task/{tid}");
    let name = std::fs::read_to_string(format!("{base}/comm"))
        .ok()
        .map(|s| s.trim().to_string());
    let state = std::fs::read_to_string(format!("{base}/stat"))
        .ok()
        .and_then(|s| {
            // `tid (comm) S ...`: the comm may hold spaces and parentheses.
            let rest = &s[s.rfind(')')? + 1..];
            rest.split_whitespace().next().map(str::to_string)
        })
        .map(|s| match s.as_str() {
            "R" => "running",
            "S" => "sleeping",
            "D" => "disk",
            "T" | "t" => "stopped",
            "Z" => "zombie",
            _ => "other",
        });
    (name, state)
}

#[cfg(not(target_os = "linux"))]
fn os_thread(_pid: u32, _tid: u64) -> (Option<String>, Option<&'static str>) {
    (None, None)
}

/// Memory numbers the OS keeps for a process. Cheap: no reads of the
/// target's memory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcMemory {
    pub rss: u64,
    /// Resident memory backed by files (code and data of libraries, mapped
    /// files).
    pub file: u64,
    /// Resident anonymous memory (heaps, arenas, stacks).
    pub anon: u64,
    pub threads: u32,
}

/// Read `/proc/<pid>/status`. `None` when the process is gone.
#[cfg(target_os = "linux")]
pub fn proc_memory(pid: u32) -> Option<ProcMemory> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let kb = |key: &str| -> u64 {
        s.lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
            .unwrap_or(0)
            * 1024
    };
    Some(ProcMemory {
        rss: kb("VmRSS:"),
        file: kb("RssFile:") + kb("RssShmem:"),
        anon: kb("RssAnon:"),
        threads: s
            .lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
    })
}

/// The working set and private commit on Windows; no file/anon split.
#[cfg(not(target_os = "linux"))]
pub fn proc_memory(pid: u32) -> Option<ProcMemory> {
    let (ws, private) = heapspy_record::live::windows_memory(pid)?;
    Some(ProcMemory {
        rss: ws,
        anon: private,
        file: 0,
        threads: 0,
    })
}

/// Whether `pid` still runs. Linux reads `/proc`; elsewhere the OS's
/// memory numbers stand in (they fail once the process is gone).
pub fn process_alive(pid: u32) -> bool {
    if cfg!(target_os = "linux") {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    } else {
        heapspy_record::live::windows_memory(pid).is_some()
    }
}

/// The process's command line, for headers. Linux only.
pub fn command_line(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let s: Vec<String> = raw
            .split(|&b| b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        (!s.is_empty()).then(|| s.join(" "))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_file_keeps_two_components() {
        assert_eq!(
            short_file("/usr/lib/python3.13/app/cache.py"),
            "app/cache.py"
        );
        assert_eq!(short_file("cache.py"), "cache.py");
        assert_eq!(short_file("C:\\app\\x\\y.py"), "x/y.py");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_own_memory() {
        let m = proc_memory(std::process::id()).unwrap();
        assert!(m.rss > 0 && m.threads >= 1);
    }
}
