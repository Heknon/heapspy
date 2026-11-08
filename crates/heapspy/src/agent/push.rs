//! Sending profiles to Pyroscope, or writing them to a directory.
//!
//! Profiles go to Pyroscope's push API, `POST /push.v1.PusherService/Push`
//! (Connect, JSON encoding), the endpoint Grafana Alloy uses. Each request
//! holds one series: its labels (`__name__` names the profile, e.g.
//! `memory`; `service_name` the application) and one pprof profile, base64
//! encoded. Pyroscope reads the profile's sample types for the rest of the
//! profile type (`memory:inuse_space:bytes:space:bytes`).
//!
//! One thread sends, so collectors never wait on the network. A request
//! that fails for a reason that may pass (no connection, a timeout, HTTP
//! 429 or 5xx) is kept and tried again with a growing delay; the queue is
//! bounded, so when the server stays away the oldest profiles are dropped.
//! Any other refusal (a 4xx: bad credentials, a rejected profile) drops the
//! profile and says why.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::log;

/// One profile to send.
#[derive(Clone, Debug)]
pub struct Push {
    /// What it is, for messages: `memory`, `retained`, `allocations`.
    pub what: &'static str,
    pub pid: u32,
    /// Labels, `__name__` and `service_name` first.
    pub labels: Vec<(String, String)>,
    /// The pprof profile.
    pub pprof: Vec<u8>,
}

/// Where profiles go.
pub enum Sink {
    Pyroscope(Http),
    /// `--dry-run DIR`: each request as a `.pprof` and a `.json` file.
    Dir(PathBuf),
}

pub struct Http {
    agent: ureq::Agent,
    url: String,
    authorization: Option<String>,
    tenant: Option<String>,
    headers: Vec<(String, String)>,
}

impl Http {
    /// A client for the Pyroscope at `server` (`http://host:4040`, or the
    /// URL of a Grafana Cloud stack).
    pub fn new(
        server: &str,
        authorization: Option<String>,
        tenant: Option<String>,
        headers: Vec<(String, String)>,
    ) -> anyhow::Result<Http> {
        let server = server.trim_end_matches('/');
        if !(server.starts_with("http://") || server.starts_with("https://")) {
            anyhow::bail!("--server must start with http:// or https:// (got {server:?})");
        }
        if server.starts_with("https://") && !cfg!(feature = "tls") {
            anyhow::bail!(
                "this heapspy was built without TLS (the `tls` feature); use an http:// server \
                 or a build with TLS"
            );
        }
        Ok(Http {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .user_agent(concat!("heapspy/", env!("CARGO_PKG_VERSION")))
                .build(),
            url: format!("{server}/push.v1.PusherService/Push"),
            authorization,
            tenant,
            headers,
        })
    }
}

#[derive(Serialize)]
struct Label<'a> {
    name: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct RawSample {
    #[serde(rename = "rawProfile")]
    raw_profile: String,
}

#[derive(Serialize)]
struct Series<'a> {
    labels: Vec<Label<'a>>,
    samples: Vec<RawSample>,
}

#[derive(Serialize)]
struct PushRequest<'a> {
    series: Vec<Series<'a>>,
}

/// The JSON body of a push request.
pub fn request_body(p: &Push) -> String {
    let req = PushRequest {
        series: vec![Series {
            labels: p
                .labels
                .iter()
                .map(|(n, v)| Label { name: n, value: v })
                .collect(),
            samples: vec![RawSample {
                raw_profile: base64(&p.pprof),
            }],
        }],
    };
    serde_json::to_string(&req).expect("serializable")
}

/// Why a send failed.
enum Failure {
    /// Worth trying again later.
    Retry(String),
    /// Will fail again: drop the profile.
    Drop(String),
}

impl Sink {
    fn send(&self, p: &Push, seq: u64) -> Result<(), Failure> {
        match self {
            Sink::Dir(dir) => {
                let stem = dir.join(format!("{seq:06}-{}-{}", p.pid, p.what));
                let labels: serde_json::Map<String, serde_json::Value> = p
                    .labels
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect();
                std::fs::write(stem.with_extension("pprof"), &p.pprof)
                    .and_then(|()| {
                        std::fs::write(
                            stem.with_extension("json"),
                            serde_json::to_string_pretty(&labels).unwrap_or_default(),
                        )
                    })
                    .map_err(|e| Failure::Drop(format!("cannot write {}: {e}", stem.display())))
            }
            Sink::Pyroscope(h) => {
                let mut r = h
                    .agent
                    .post(&h.url)
                    .set("Content-Type", "application/json")
                    .set("Connect-Protocol-Version", "1");
                if let Some(a) = &h.authorization {
                    r = r.set("Authorization", a);
                }
                if let Some(t) = &h.tenant {
                    r = r.set("X-Scope-OrgID", t);
                }
                for (name, value) in &h.headers {
                    r = r.set(name, value);
                }
                match r.send_string(&request_body(p)) {
                    Ok(_) => Ok(()),
                    Err(ureq::Error::Status(code, resp)) => {
                        let body: String = resp
                            .into_string()
                            .unwrap_or_default()
                            .chars()
                            .take(300)
                            .collect();
                        let msg = format!("HTTP {code} from {}: {}", h.url, body.trim());
                        if code == 429 || code >= 500 {
                            Err(Failure::Retry(msg))
                        } else {
                            Err(Failure::Drop(msg))
                        }
                    }
                    // ureq's transport errors name the URL themselves.
                    Err(e) => Err(Failure::Retry(e.to_string())),
                }
            }
        }
    }
}

/// Most profiles kept while the server cannot be reached.
pub const MAX_QUEUE: usize = 512;

/// What the sender did, for the summary on exit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sent {
    pub sent: u64,
    pub dropped: u64,
}

/// Send what arrives on `rx` until it closes, then try what is left once.
/// `stop` cuts the retries short when the agent is asked to exit.
pub fn sender(sink: Sink, rx: Receiver<Push>, stop: &AtomicBool) -> Sent {
    let mut queue: VecDeque<Push> = VecDeque::new();
    let mut stats = Sent::default();
    let mut seq = 0u64;
    let mut backoff = Duration::from_secs(1);
    let mut retry_at: Option<Instant> = None;
    let mut last_error: Option<(Instant, String)> = None;
    let mut closed = false;
    loop {
        // Take what arrived; wait a little when there is nothing to do.
        let wait = match retry_at {
            Some(t) => t.saturating_duration_since(Instant::now()),
            None if queue.is_empty() => Duration::from_millis(500),
            None => Duration::ZERO,
        };
        if !closed {
            match rx.recv_timeout(wait.min(Duration::from_millis(500))) {
                Ok(p) => queue.push_back(p),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => closed = true,
            }
            while let Ok(p) = rx.try_recv() {
                queue.push_back(p);
            }
        } else if wait > Duration::ZERO && !stop.load(Ordering::Relaxed) {
            std::thread::sleep(wait.min(Duration::from_millis(200)));
        }
        while queue.len() > MAX_QUEUE {
            queue.pop_front();
            stats.dropped += 1;
        }
        if closed && (queue.is_empty() || stop.load(Ordering::Relaxed) && retry_at.is_some()) {
            stats.dropped += queue.len() as u64;
            return stats;
        }
        if retry_at.is_some_and(|t| Instant::now() < t) {
            continue;
        }
        retry_at = None;
        while let Some(p) = queue.pop_front() {
            seq += 1;
            match sink.send(&p, seq) {
                Ok(()) => {
                    stats.sent += 1;
                    backoff = Duration::from_secs(1);
                    if last_error.take().is_some() {
                        log("sending profiles again");
                    }
                }
                Err(Failure::Drop(e)) => {
                    stats.dropped += 1;
                    log(&format!(
                        "dropped a {} profile of pid {}: {e}",
                        p.what, p.pid
                    ));
                }
                Err(Failure::Retry(e)) => {
                    // Say it once a minute, not on every attempt.
                    if last_error
                        .as_ref()
                        .is_none_or(|(t, m)| *m != e || t.elapsed() > Duration::from_secs(60))
                    {
                        log(&format!(
                            "cannot send profiles ({e}); {} waiting, trying again in {}s",
                            queue.len() + 1,
                            backoff.as_secs()
                        ));
                        last_error = Some((Instant::now(), e));
                    }
                    queue.push_front(p);
                    retry_at = Some(Instant::now() + backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                    break;
                }
            }
        }
    }
}

/// Standard base64 with padding.
pub fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    #[test]
    fn the_request_is_one_series_with_its_labels() {
        let p = Push {
            what: "memory",
            pid: 7,
            labels: vec![
                ("__name__".into(), "memory".into()),
                ("service_name".into(), "app".into()),
            ],
            pprof: vec![1, 2, 3],
        };
        let v: serde_json::Value = serde_json::from_str(&request_body(&p)).unwrap();
        assert_eq!(v["series"][0]["labels"][0]["name"], "__name__");
        assert_eq!(v["series"][0]["labels"][1]["value"], "app");
        assert_eq!(v["series"][0]["samples"][0]["rawProfile"], "AQID");
    }

    #[test]
    fn servers_must_be_http_urls() {
        assert!(Http::new("pyroscope:4040", None, None, Vec::new()).is_err());
        assert!(Http::new("http://pyroscope:4040/", None, None, Vec::new()).is_ok());
    }

    /// A server that answers each request with the next status of
    /// `statuses` (then 200), and reports each request's head and body.
    fn mock(statuses: Vec<u16>) -> (String, std::sync::mpsc::Receiver<(String, String)>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut statuses = statuses.into_iter();
            for c in l.incoming() {
                let Ok(mut c) = c else { return };
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut head = String::new();
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    head.push_str(&line);
                }
                let mut body = vec![0u8; len];
                let _ = r.read_exact(&mut body);
                let code = statuses.next().unwrap_or(200);
                let _ = write!(
                    c,
                    "HTTP/1.1 {code} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                );
                let _ = tx.send((head, String::from_utf8_lossy(&body).into_owned()));
            }
        });
        (url, rx)
    }

    fn push(what: &'static str) -> Push {
        Push {
            what,
            pid: 3,
            labels: vec![("__name__".into(), "memory".into())],
            pprof: vec![1],
        }
    }

    #[test]
    fn a_server_error_is_retried_and_a_refusal_is_not() {
        let (url, got) = mock(vec![503, 401]);
        let http = Http::new(
            &url,
            Some("Bearer t".into()),
            Some("team-a".into()),
            vec![("X-Extra".into(), "1".into())],
        )
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(push("memory")).unwrap();
        tx.send(push("retained")).unwrap();
        drop(tx);
        let s = sender(Sink::Pyroscope(http), rx, &AtomicBool::new(false));
        // 503 → kept and sent again (200); the next one is refused (401).
        // Requests: memory (503), memory (401), retained (200).
        let reqs: Vec<(String, String)> = got.try_iter().collect();
        assert_eq!(reqs.len(), 3, "{reqs:?}");
        assert_eq!(
            s,
            Sent {
                sent: 1,
                dropped: 1
            }
        );
        let (head, body) = &reqs[0];
        assert!(
            head.starts_with("POST /push.v1.PusherService/Push HTTP/1.1"),
            "{head}"
        );
        let h = head.to_ascii_lowercase();
        assert!(h.contains("authorization: bearer t"), "{head}");
        assert!(h.contains("x-scope-orgid: team-a"), "{head}");
        assert!(h.contains("x-extra: 1"), "{head}");
        assert!(h.contains("content-type: application/json"), "{head}");
        assert!(body.contains("\"rawProfile\":\"AQ==\""), "{body}");
    }

    #[test]
    fn a_directory_sink_writes_each_profile() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        for what in ["memory", "retained"] {
            tx.send(Push {
                what,
                pid: 9,
                labels: vec![("service_name".into(), "app".into())],
                pprof: vec![0x0a],
            })
            .unwrap();
        }
        drop(tx);
        let s = sender(
            Sink::Dir(dir.path().to_path_buf()),
            rx,
            &AtomicBool::new(false),
        );
        assert_eq!(
            s,
            Sent {
                sent: 2,
                dropped: 0
            }
        );
        assert!(dir.path().join("000001-9-memory.pprof").exists());
        assert!(dir.path().join("000002-9-retained.json").exists());
    }
}
