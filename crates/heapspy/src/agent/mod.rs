//! `heapspy agent`: collect memory profiles of Python processes
//! continuously and send them to Pyroscope.
//!
//! Each watched process gets a collector thread per kind of profile it was
//! asked for; all of them hand their profiles to one sender thread
//! ([`push::sender`]), so a slow server never delays a reading.
//!
//! | profile | flag | sample type | `heapspy_profile` | stops the process |
//! |---|---|---|---|---|
//! | where the memory is | `--memory` (the default) | `inuse_space:bytes` | `memory` | never |
//! | who holds it | `--retained` | `inuse_space:bytes` | `retained` | only with `--stop` |
//! | what allocated it | `--alloc` | `alloc_space:bytes` | `allocations` | never (eBPF / ETW) |
//!
//! All are named `memory` (`__name__`). Grafana graphs a profile as a gauge
//! in bytes only when its whole type is one it knows,
//! `memory:inuse_space:bytes:space:bytes`; any other name, sample type or
//! period type is graphed as bytes per second. So the RSS breakdown and the
//! retained snapshot share that type and the `heapspy_profile` label tells
//! them apart.
//!
//! Processes are given with `--pid`, or found with `--discover`: every
//! few seconds the process list is read and each new CPython process whose
//! command line contains the text is picked up. A process that exits is
//! let go.

pub mod pprof;
pub mod push;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use heapspy_analyzer::{FlameOptions, MinWidth};
use heapspy_reader::{DumpOptions, SourceSpec};

use crate::cli::AgentArgs;
use crate::live;
use crate::sample::{sleep_until, Sample, Sampler};
use pprof::Builder;
use push::{Http, Push, Sink};

/// Print one line about what the agent does, to stderr.
pub fn log(msg: &str) {
    eprintln!("heapspy agent: {msg}");
}

/// How often `--discover` reads the process list.
const DISCOVER_EVERY: Duration = Duration::from_secs(10);

/// What to collect, from the command line.
#[derive(Clone, Debug)]
struct Plan {
    memory: Option<Duration>,
    retained: Option<Duration>,
    stop: bool,
    alloc: Option<(Duration, Duration)>,
    alloc_events: heapspy_alloc::EventKinds,
    once: bool,
    app_name: Option<String>,
    tags: Vec<(String, String)>,
    hostname: String,
}

pub fn run(args: AgentArgs) -> anyhow::Result<()> {
    let sink = match (&args.server, &args.dry_run) {
        (_, Some(dir)) => {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
            Sink::Dir(dir.clone())
        }
        (Some(server), None) => Sink::Pyroscope(Http::new(
            server,
            authorization(args.basic_auth_user.as_deref())?,
            args.tenant_id.clone(),
        )?),
        (None, None) => unreachable!("clap requires --server or --dry-run"),
    };
    // Nothing chosen: the profile that never pauses the process.
    let memory = args.memory || !(args.retained || args.alloc);
    let plan = Plan {
        memory: memory.then_some(args.memory_every),
        retained: args.retained.then_some(args.retained_every),
        stop: args.stop,
        alloc: args.alloc.then_some((args.alloc_every, args.alloc_for)),
        alloc_events: args.alloc_events,
        once: args.once,
        app_name: args.app_name.clone(),
        tags: args.tags.clone(),
        hostname: hostname(),
    };
    let mut what = Vec::new();
    if let Some(d) = plan.memory {
        what.push(format!("memory every {}", human(d)));
    }
    if let Some(d) = plan.retained {
        what.push(format!(
            "retained every {} ({})",
            human(d),
            if plan.stop {
                "stopping the process for each snapshot"
            } else {
                "not stopped: approximate"
            }
        ));
    }
    if let Some((every, window)) = plan.alloc {
        what.push(format!(
            "allocations for {} every {}",
            human(window),
            human(every)
        ));
    }
    let to = match (&args.server, &args.dry_run) {
        (_, Some(d)) => format!("files in {}", d.display()),
        (Some(s), None) => s.clone(),
        _ => String::new(),
    };
    log(&format!("collecting {}; sending to {to}", what.join(", ")));

    let stop = heapspy_record::stop_on_signals();
    let (tx, rx) = mpsc::channel::<Push>();
    let sender = std::thread::spawn(move || push::sender(sink, rx, stop));

    let mut targets: HashMap<u32, Vec<JoinHandle<()>>> = HashMap::new();
    // Discovered processes that are not CPython, so they are not probed again.
    let mut not_python: HashSet<u32> = HashSet::new();
    let mut next_scan = Instant::now();
    loop {
        let mut wanted: Vec<u32> = args.pids.clone();
        if let Some(text) = &args.discover {
            if Instant::now() >= next_scan {
                next_scan = Instant::now() + DISCOVER_EVERY;
                let found = discover(text);
                not_python.retain(|p| found.contains(p));
                wanted.extend(found);
            }
        }
        for pid in wanted {
            if targets.contains_key(&pid) || not_python.contains(&pid) {
                continue;
            }
            match start(pid, &plan, &tx, stop) {
                Ok(h) => {
                    targets.insert(pid, h);
                }
                Err(e) if args.pids.contains(&pid) => {
                    // A pid given by hand that cannot be read is an error.
                    stop.store(true, Ordering::Relaxed);
                    drop(tx);
                    let _ = sender.join();
                    return Err(e.context(format!("cannot watch pid {pid}")));
                }
                Err(_) => {
                    not_python.insert(pid);
                }
            }
        }
        // Let go of processes whose collectors have all finished.
        targets.retain(|_, hs| !hs.iter().all(JoinHandle::is_finished));
        let done = plan.once && targets.is_empty() && args.discover.is_none();
        if done || stop.load(Ordering::Relaxed) {
            break;
        }
        if plan.once && args.discover.is_some() {
            // One scan, then wait for those collectors.
            for (_, hs) in targets.drain() {
                for h in hs {
                    let _ = h.join();
                }
            }
            break;
        }
        if args.discover.is_none() && targets.is_empty() {
            log("every watched process has exited");
            break;
        }
        sleep_until(Instant::now() + Duration::from_millis(500), || {
            stop.load(Ordering::Relaxed)
        });
    }
    stop.store(true, Ordering::Relaxed);
    for (_, hs) in targets {
        for h in hs {
            let _ = h.join();
        }
    }
    drop(tx);
    // Once asked to exit, the sender gets one more try per profile.
    let s = sender.join().unwrap_or_default();
    log(&format!(
        "sent {} profiles{}",
        s.sent,
        if s.dropped > 0 {
            format!(", dropped {}", s.dropped)
        } else {
            String::new()
        }
    ));
    Ok(())
}

/// The `Authorization` header: `--basic-auth-user` with
/// `HEAPSPY_PYROSCOPE_PASSWORD`, or a bearer `HEAPSPY_PYROSCOPE_TOKEN`.
/// Secrets come from the environment, never the command line, where
/// other users can read them.
fn authorization(user: Option<&str>) -> anyhow::Result<Option<String>> {
    let password = std::env::var("HEAPSPY_PYROSCOPE_PASSWORD").ok();
    let token = std::env::var("HEAPSPY_PYROSCOPE_TOKEN").ok();
    Ok(match (user, password, token) {
        (Some(u), Some(p), _) => Some(format!(
            "Basic {}",
            push::base64(format!("{u}:{p}").as_bytes())
        )),
        (Some(_), None, _) => {
            anyhow::bail!("--basic-auth-user needs the password in HEAPSPY_PYROSCOPE_PASSWORD")
        }
        (None, _, Some(t)) => Some(format!("Bearer {t}")),
        (None, _, None) => None,
    })
}

/// Start the collectors of one process. Fails when it is not a CPython
/// heapspy can read.
fn start(
    pid: u32,
    plan: &Plan,
    tx: &Sender<Push>,
    stop: &'static AtomicBool,
) -> anyhow::Result<Vec<JoinHandle<()>>> {
    let sampler = Sampler::open(pid)?;
    if let Some(e) = &sampler.counters_error {
        anyhow::bail!("{e}");
    }
    let cmd = live::command_line(pid).unwrap_or_default();
    let app = plan.app_name.clone().unwrap_or_else(|| app_name(&cmd, pid));
    let mut labels = vec![
        ("service_name".to_string(), app.clone()),
        ("pid".to_string(), pid.to_string()),
    ];
    if !plan.hostname.is_empty() {
        labels.push(("hostname".to_string(), plan.hostname.clone()));
    }
    labels.extend(plan.tags.iter().cloned());
    log(&format!("watching pid {pid} as {app}"));
    let t = Target {
        pid,
        labels,
        tx: tx.clone(),
        stop,
        once: plan.once,
    };
    let mut hs = Vec::new();
    if let Some(every) = plan.memory {
        let t = t.clone();
        let mut sampler = Some(sampler);
        hs.push(std::thread::spawn(move || {
            memory_loop(&t, sampler.take().expect("sampler"), every)
        }));
    }
    if let Some(every) = plan.retained {
        let (t, stop_it) = (t.clone(), plan.stop);
        hs.push(std::thread::spawn(move || {
            retained_loop(&t, every, stop_it)
        }));
    }
    if let Some((every, window)) = plan.alloc {
        let (t, events) = (t.clone(), plan.alloc_events);
        hs.push(std::thread::spawn(move || {
            alloc_loop(&t, every, window, events)
        }));
    }
    Ok(hs)
}

/// One watched process, as its collectors see it.
#[derive(Clone)]
struct Target {
    pid: u32,
    /// `service_name` first, then the rest.
    labels: Vec<(String, String)>,
    tx: Sender<Push>,
    stop: &'static AtomicBool,
    once: bool,
}

impl Target {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn alive(&self) -> bool {
        live::process_alive(self.pid)
    }

    /// Queue a profile, named `memory` and labelled `heapspy_profile=what`.
    fn send(&self, what: &'static str, extra: &[(&str, &str)], p: &Builder) {
        if p.is_empty() {
            return;
        }
        let mut labels = vec![
            ("__name__".to_string(), "memory".to_string()),
            ("heapspy_profile".to_string(), what.to_string()),
        ];
        labels.extend(self.labels.iter().cloned());
        labels.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        let _ = self.tx.send(Push {
            what,
            pid: self.pid,
            labels,
            pprof: p.encode(),
        });
    }

    /// Wait until `t`; false when the agent is stopping.
    fn wait(&self, t: Instant) -> bool {
        sleep_until(t, || self.stopped());
        !self.stopped()
    }
}

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i64)
}

/// `--memory`: a breakdown of where the process's memory is, from the
/// counters, every `every`.
fn memory_loop(t: &Target, mut sampler: Sampler, every: Duration) {
    let mut next = Instant::now();
    loop {
        let Some(s) = sampler.sample() else {
            log(&format!("pid {} exited", t.pid));
            return;
        };
        let p = memory_profile(&s, now_nanos(), every);
        t.send("memory", &[], &p);
        if t.once {
            return;
        }
        next += every;
        if !t.wait(next.max(Instant::now())) {
            return;
        }
    }
}

/// The memory of one sample as stacks: where each byte of RSS is.
///
/// The type is `memory:inuse_space:bytes:space:bytes`, Go's heap profile,
/// the one Grafana graphs as a gauge (bytes at one moment); see the module
/// documentation.
pub fn memory_profile(s: &Sample, time_nanos: i64, every: Duration) -> Builder {
    let mut p = Builder::new(
        &[("inuse_space", "bytes")],
        ("space", "bytes"),
        time_nanos,
        every.as_nanos() as i64,
    );
    let rss = s.rss().unwrap_or(0);
    let mut accounted = 0u64;
    if let Some(a) = s.python.as_ref().and_then(|p| p.allocator.as_ref()) {
        for c in &a.size_classes {
            let b = c.blocks * u64::from(c.size);
            p.add(
                &["python objects (pymalloc)", &format!("{} B blocks", c.size)],
                &[b as i64],
            );
            accounted += b;
        }
        p.add(&["pymalloc free"], &[a.free_bytes as i64]);
        accounted += a.free_bytes;
    }
    if let Some(n) = s.native {
        p.add(&["malloc heaps"], &[n.heap_bytes as i64]);
        accounted += n.heap_bytes;
    }
    p.add(
        &["other (code, stacks, large buffers)"],
        &[rss.saturating_sub(accounted) as i64],
    );
    p
}

/// `--retained`: a snapshot every `every`, as stacks of holders weighted
/// by retained bytes.
fn retained_loop(t: &Target, every: Duration, stop_it: bool) {
    let mut next = Instant::now();
    loop {
        if !t.alive() {
            return;
        }
        let started = now_nanos();
        match retained_profile(t.pid, stop_it, started, every) {
            Ok(p) => {
                let how = if stop_it { "stopped" } else { "approximate" };
                t.send("retained", &[("heapspy_snapshot", how)], &p);
            }
            Err(e) if t.alive() => {
                log(&format!("retained snapshot of pid {} failed: {e:#}", t.pid));
                if !stop_it && !cfg!(target_os = "linux") {
                    log("snapshots without stopping need Linux; add --stop to take them here");
                    return;
                }
            }
            Err(_) => return,
        }
        if t.once {
            return;
        }
        next += every;
        if !t.wait(next.max(Instant::now())) {
            return;
        }
    }
}

fn retained_profile(
    pid: u32,
    stop_it: bool,
    time: i64,
    every: Duration,
) -> anyhow::Result<Builder> {
    let path = tempfile::Builder::new()
        .prefix(&format!("heapspy-agent-{pid}-"))
        .suffix(".hpy")
        .tempfile()?
        .into_temp_path();
    let spec = SourceSpec::Pid(pid);
    let opts = DumpOptions {
        source_kind: spec.kind(),
        source_ref: spec.reference(),
        ..DumpOptions::default()
    };
    if stop_it {
        crate::cmd::capture(&spec, &opts, &path, true)?;
    } else {
        crate::cmd::capture_unstopped(pid, &opts, &path)?;
    }
    let snap = crate::cmd::open_snapshot(&path)?;
    let folded = heapspy_analyzer::folded_stacks(&snap, &FlameOptions::default())?;
    let mut p = Builder::new(
        &[("inuse_space", "bytes")],
        ("space", "bytes"),
        time,
        every.as_nanos() as i64,
    );
    for l in &folded.lines {
        p.add_folded(&l.stack, &[l.bytes as i64]);
    }
    Ok(p)
}

/// `--alloc`: sample allocations for `window`, every `every`, as stacks
/// weighted by the bytes they allocated.
fn alloc_loop(t: &Target, every: Duration, window: Duration, events: heapspy_alloc::EventKinds) {
    let mut next = Instant::now();
    loop {
        if !t.alive() {
            return;
        }
        let started = now_nanos();
        match alloc_profile(t.pid, window, events, t.stop, started) {
            Ok(p) => t.send("allocations", &[], &p),
            Err(e) if t.alive() && !t.stopped() => {
                log(&format!(
                    "allocation sampling of pid {} failed: {e:#}",
                    t.pid
                ));
                if e.to_string().contains("permission")
                    || e.to_string().contains("not supported")
                    || e.to_string().contains("unsupported")
                {
                    log("allocation sampling is off for this process");
                    return;
                }
            }
            Err(_) => return,
        }
        if t.once {
            return;
        }
        next += every.max(window);
        if !t.wait(next.max(Instant::now())) {
            return;
        }
    }
}

fn alloc_profile(
    pid: u32,
    window: Duration,
    events: heapspy_alloc::EventKinds,
    stop: &'static AtomicBool,
    time: i64,
) -> anyhow::Result<Builder> {
    let path = tempfile::Builder::new()
        .prefix(&format!("heapspy-agent-{pid}-"))
        .suffix(".hpya")
        .tempfile()?
        .into_temp_path();
    let mut opts = heapspy_record::RecordOptions::new(pid, window, &path);
    opts.sampling = heapspy_alloc::SamplingParams {
        events,
        ..heapspy_alloc::SamplingParams::DEFAULT
    };
    // Only mechanisms that never stop the process.
    opts.mechanism = heapspy_record::MechanismChoice::Only(if cfg!(windows) {
        heapspy_alloc::Mechanism::Etw
    } else {
        heapspy_alloc::Mechanism::Ebpf
    });
    heapspy_record::record(&opts, stop)?;
    let profile = heapspy_alloc::Profile::open(&path)?;
    let folded = heapspy_analyzer::allocations::folded_allocations(&profile, MinWidth::Bytes(0))?;
    let mut p = Builder::new(
        &[("alloc_space", "bytes")],
        ("space", "bytes"),
        time,
        window.as_nanos() as i64,
    );
    for l in &folded.lines {
        p.add_folded(&l.stack, &[l.bytes as i64]);
    }
    Ok(p)
}

/// CPython processes whose command line (Windows: executable name)
/// contains `text`, ignoring case. Not checked for CPython yet.
fn discover(text: &str) -> Vec<u32> {
    let text = text.to_lowercase();
    let me = std::process::id();
    let mut out = Vec::new();
    if cfg!(target_os = "linux") {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return out;
        };
        for e in dir.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            if pid == me {
                continue;
            }
            if live::command_line(pid).is_some_and(|c| c.to_lowercase().contains(&text)) {
                out.push(pid);
            }
        }
    } else {
        for (pid, exe) in heapspy_record::live::windows_processes() {
            if pid != me && exe.to_lowercase().contains(&text) {
                out.push(pid);
            }
        }
    }
    out.sort_unstable();
    out
}

/// A service name from a command line: the script (`app/server.py` →
/// `server`), the module of `-m` (`-m uvicorn` → `uvicorn`), else the
/// executable's name, else `python-PID`.
pub fn app_name(cmd: &str, pid: u32) -> String {
    let parts = split_args(cmd);
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    let base = |s: &str| -> String {
        let f = s.rsplit(['/', '\\']).next().unwrap_or(s);
        let f = f
            .strip_suffix(".exe")
            .or_else(|| f.strip_suffix(".EXE"))
            .unwrap_or(f);
        f.strip_suffix(".py").unwrap_or(f).to_string()
    };
    let mut i = 1;
    while i < parts.len() {
        let a = parts[i];
        if a == "-m" {
            if let Some(m) = parts.get(i + 1) {
                return clean(m);
            }
        }
        if a == "-c" {
            break;
        }
        if !a.starts_with('-') {
            return clean(&base(a));
        }
        // Options that take a value.
        if matches!(a, "-W" | "-X" | "-Q") {
            i += 1;
        }
        i += 1;
    }
    match parts.first() {
        Some(exe) if !exe.is_empty() => clean(&base(exe)),
        _ => format!("python-{pid}"),
    }
}

/// Split a command line into arguments at whitespace, keeping what is
/// inside double quotes together (Windows quotes paths with spaces).
fn split_args(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut quoted, mut any) = (false, false);
    for c in cmd.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                any = false;
            }
            c => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Pyroscope's service names are free text, but keep them to what shows
/// cleanly in a URL and a label: letters, digits, `-`, `_`, `.`.
fn clean(s: &str) -> String {
    let c: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if c.is_empty() {
        "python".into()
    } else {
        c
    }
}

fn hostname() -> String {
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        return h.trim().to_string();
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default()
}

fn human(d: Duration) -> String {
    crate::cmd::human_duration(d)
}

/// Parse `--tag key=value`. Keys follow Pyroscope's label rules
/// (`[a-zA-Z_][a-zA-Z0-9_]*`, no `.`), and may not be one the agent sets.
pub fn parse_tag(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("bad tag {s:?} (expected KEY=VALUE)"))?;
    let ok = k
        .chars()
        .enumerate()
        .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()));
    if k.is_empty() || !ok {
        return Err(format!(
            "bad tag key {k:?}: use letters, digits and _, not starting with a digit"
        ));
    }
    if matches!(k, "__name__" | "service_name" | "pid") {
        return Err(format!("tag {k:?} is set by the agent"));
    }
    Ok((k.to_string(), v.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_names_from_command_lines() {
        assert_eq!(
            app_name("/usr/bin/python3 app/server.py --port 80", 1),
            "server"
        );
        assert_eq!(app_name("python3 -u -X dev worker.py", 1), "worker");
        assert_eq!(app_name("python -m uvicorn app:main", 1), "uvicorn");
        assert_eq!(app_name("/usr/bin/python3.12", 1), "python3.12");
        assert_eq!(app_name("python -c print(1)", 1), "python");
        assert_eq!(app_name("", 9), "python-9");
        assert_eq!(app_name("python my app.py", 1), "my");
        assert_eq!(
            app_name(
                r#""C:\Program Files\Python314\python.exe" -E -s "D:\a\my app\growing_list.py" x"#,
                1
            ),
            "growing_list"
        );
        assert_eq!(app_name(r#""C:\Python\python.exe""#, 1), "python");
    }

    #[test]
    fn tags_follow_label_rules() {
        assert_eq!(
            parse_tag("env=prod").unwrap(),
            ("env".into(), "prod".into())
        );
        assert_eq!(parse_tag("a_1=x=y").unwrap().1, "x=y");
        assert!(parse_tag("env").is_err());
        assert!(parse_tag("1env=x").is_err());
        assert!(parse_tag("my.env=x").is_err());
        assert!(parse_tag("service_name=x").is_err());
    }

    #[test]
    fn the_memory_profile_adds_up_to_rss() {
        let s = crate::sample::fake(1, 0.0, 100 << 20, 10 << 20, 0);
        let p = memory_profile(&s, 1, Duration::from_secs(10));
        let d = pprof::decode::decode(&p.encode());
        assert_eq!(d.sample_types, vec![("inuse_space".into(), "bytes".into())]);
        let total: i64 = d.samples.iter().map(|s| s.1[0]).sum();
        // Every slice is subtracted from RSS once: they add up to it.
        assert_eq!(total, 100 << 20, "{:?}", d.samples);
        assert!(d
            .samples
            .iter()
            .any(|s| s.0 == vec!["other (code, stacks, large buffers)".to_string()]));
    }

    #[test]
    fn credentials_come_from_the_environment() {
        // Not set in the test environment.
        if std::env::var("HEAPSPY_PYROSCOPE_PASSWORD").is_err()
            && std::env::var("HEAPSPY_PYROSCOPE_TOKEN").is_err()
        {
            assert_eq!(authorization(None).unwrap(), None);
            assert!(authorization(Some("123")).is_err());
        }
    }
}
