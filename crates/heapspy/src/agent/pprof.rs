//! A minimal pprof encoder: folded stacks to a `perftools.profiles.Profile`
//! protobuf, the format Pyroscope ingests.
//!
//! Only what Pyroscope reads is written: the string table, sample types,
//! samples with their location ids (leaf first), one location per distinct
//! frame with one line, one function per distinct frame, the period type
//! and the time. The protobuf is written by hand (varints and
//! length-delimited fields), so no code generator or dependency is needed.
//! See <https://github.com/google/pprof/blob/main/proto/profile.proto>.

use std::collections::HashMap;

/// A sample type: `(type, unit)`, e.g. `("inuse_space", "bytes")`.
pub type ValueType = (&'static str, &'static str);

/// A profile under construction.
pub struct Builder {
    strings: Vec<String>,
    string_ids: HashMap<String, u64>,
    sample_types: Vec<(u64, u64)>,
    period_type: (u64, u64),
    /// Distinct frames, each one function and one location (same id).
    frames: HashMap<String, u64>,
    functions: Vec<(u64, u64, u64, i64)>, // id, name, filename, line
    samples: Vec<(Vec<u64>, Vec<i64>)>,
    time_nanos: i64,
    duration_nanos: i64,
}

impl Builder {
    /// A profile with these sample types, taken at `time_nanos` (Unix) and
    /// covering `duration_nanos`.
    pub fn new(
        sample_types: &[ValueType],
        period_type: ValueType,
        time_nanos: i64,
        duration_nanos: i64,
    ) -> Builder {
        let mut b = Builder {
            strings: vec![String::new()],
            string_ids: HashMap::from([(String::new(), 0)]),
            sample_types: Vec::new(),
            period_type: (0, 0),
            frames: HashMap::new(),
            functions: Vec::new(),
            samples: Vec::new(),
            time_nanos,
            duration_nanos,
        };
        b.sample_types = sample_types
            .iter()
            .map(|(t, u)| (b.string(t), b.string(u)))
            .collect();
        b.period_type = (b.string(period_type.0), b.string(period_type.1));
        b
    }

    fn string(&mut self, s: &str) -> u64 {
        if let Some(&i) = self.string_ids.get(s) {
            return i;
        }
        let i = self.strings.len() as u64;
        self.strings.push(s.to_string());
        self.string_ids.insert(s.to_string(), i);
        i
    }

    fn frame(&mut self, f: &str) -> u64 {
        if let Some(&id) = self.frames.get(f) {
            return id;
        }
        // The whole frame is the name, as Pyroscope's Python profilers
        // write them (`handle (app/server.py:42)`): Pyroscope groups
        // frames by name, so two lines of one function stay apart. The
        // file and line are also given in their own fields.
        let (_, file, line) = split_frame(f);
        let id = self.functions.len() as u64 + 1;
        let (n, fl) = (self.string(f), self.string(file));
        self.functions.push((id, n, fl, line));
        self.frames.insert(f.to_string(), id);
        id
    }

    /// Add one stack, root first, with one value per sample type.
    pub fn add<S: AsRef<str>>(&mut self, stack: &[S], values: &[i64]) {
        debug_assert_eq!(values.len(), self.sample_types.len());
        if values.iter().all(|&v| v == 0) || stack.is_empty() {
            return;
        }
        let ids: Vec<u64> = stack.iter().rev().map(|f| self.frame(f.as_ref())).collect();
        self.samples.push((ids, values.to_vec()));
    }

    /// Add a folded line (`a;b;c`) with its values.
    pub fn add_folded(&mut self, folded: &str, values: &[i64]) {
        let frames: Vec<&str> = folded.split(';').filter(|f| !f.is_empty()).collect();
        self.add(&frames, values);
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The encoded profile.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for &(t, u) in &self.sample_types {
            let mut m = Vec::new();
            uint(&mut m, 1, t);
            uint(&mut m, 2, u);
            bytes(&mut out, 1, &m);
        }
        for (locs, values) in &self.samples {
            let mut m = Vec::new();
            let mut packed = Vec::new();
            for &l in locs {
                varint(&mut packed, l);
            }
            bytes(&mut m, 1, &packed);
            let mut packed = Vec::new();
            for &v in values {
                varint(&mut packed, v as u64);
            }
            bytes(&mut m, 2, &packed);
            bytes(&mut out, 2, &m);
        }
        for &(id, _, _, line) in &self.functions {
            // Location: id, then one Line { function_id, line }.
            let mut l = Vec::new();
            uint(&mut l, 1, id);
            if line > 0 {
                uint(&mut l, 2, line as u64);
            }
            let mut m = Vec::new();
            uint(&mut m, 1, id);
            bytes(&mut m, 4, &l);
            bytes(&mut out, 4, &m);
        }
        for &(id, name, file, line) in &self.functions {
            let mut m = Vec::new();
            uint(&mut m, 1, id);
            uint(&mut m, 2, name);
            uint(&mut m, 3, name);
            if file != 0 {
                uint(&mut m, 4, file);
            }
            if line > 0 {
                uint(&mut m, 5, line as u64);
            }
            bytes(&mut out, 5, &m);
        }
        for s in &self.strings {
            bytes(&mut out, 6, s.as_bytes());
        }
        uint(&mut out, 9, self.time_nanos as u64);
        uint(&mut out, 10, self.duration_nanos as u64);
        let mut m = Vec::new();
        uint(&mut m, 1, self.period_type.0);
        uint(&mut m, 2, self.period_type.1);
        bytes(&mut out, 11, &m);
        uint(&mut out, 12, 1);
        out
    }
}

/// `qualname (file:line)` → (`qualname`, `file`, line). Other frames are
/// names alone.
fn split_frame(f: &str) -> (&str, &str, i64) {
    if let Some(rest) = f.strip_suffix(')') {
        if let Some(i) = rest.rfind(" (") {
            let (name, loc) = (&rest[..i], &rest[i + 2..]);
            if let Some((file, line)) = loc.rsplit_once(':') {
                if let Ok(n) = line.parse::<i64>() {
                    return (name, file, n);
                }
            }
            if !loc.contains(' ') && (loc.ends_with(".py") || loc.contains('/')) {
                return (name, loc, 0);
            }
        }
    }
    (f, "", 0)
}

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn key(out: &mut Vec<u8>, field: u32, wire: u8) {
    varint(out, (u64::from(field) << 3) | u64::from(wire));
}

fn uint(out: &mut Vec<u8>, field: u32, v: u64) {
    if v != 0 {
        key(out, field, 0);
        varint(out, v);
    }
}

fn bytes(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    key(out, field, 2);
    varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// A decoder for tests: the stacks (root first, frame names) and values of
/// an encoded profile, and its sample types.
#[cfg(test)]
pub mod decode {
    use std::collections::HashMap;

    fn varint(b: &[u8], i: &mut usize) -> u64 {
        let mut v = 0u64;
        let mut s = 0;
        loop {
            let x = b[*i];
            *i += 1;
            v |= u64::from(x & 0x7f) << s;
            if x < 0x80 {
                return v;
            }
            s += 7;
        }
    }

    /// (field, wire type, varint value or bytes) of each field of `b`.
    fn fields(b: &[u8]) -> Vec<(u64, u64, u64, &[u8])> {
        let mut i = 0;
        let mut out = Vec::new();
        while i < b.len() {
            let k = varint(b, &mut i);
            let (f, w) = (k >> 3, k & 7);
            match w {
                0 => out.push((f, w, varint(b, &mut i), &b[0..0])),
                2 => {
                    let n = varint(b, &mut i) as usize;
                    out.push((f, w, 0, &b[i..i + n]));
                    i += n;
                }
                _ => panic!("wire type {w}"),
            }
        }
        out
    }

    fn packed(b: &[u8]) -> Vec<u64> {
        let mut i = 0;
        let mut v = Vec::new();
        while i < b.len() {
            v.push(varint(b, &mut i));
        }
        v
    }

    pub struct Decoded {
        pub sample_types: Vec<(String, String)>,
        /// Root-first frame names, and values.
        pub samples: Vec<(Vec<String>, Vec<i64>)>,
        /// Function name → (file, line).
        pub functions: HashMap<String, (String, i64)>,
        pub time_nanos: u64,
    }

    pub fn decode(b: &[u8]) -> Decoded {
        let f = fields(b);
        let strings: Vec<String> = f
            .iter()
            .filter(|x| x.0 == 6)
            .map(|x| String::from_utf8(x.3.to_vec()).unwrap())
            .collect();
        let s = |i: u64| strings[i as usize].clone();
        let mut fun: HashMap<u64, (String, String, i64)> = HashMap::new();
        for x in f.iter().filter(|x| x.0 == 5) {
            let (mut id, mut name, mut file, mut line) = (0, 0, 0, 0);
            for y in fields(x.3) {
                match y.0 {
                    1 => id = y.2,
                    2 => name = y.2,
                    4 => file = y.2,
                    5 => line = y.2,
                    _ => {}
                }
            }
            fun.insert(id, (s(name), s(file), line as i64));
        }
        let mut loc: HashMap<u64, u64> = HashMap::new();
        for x in f.iter().filter(|x| x.0 == 4) {
            let (mut id, mut func) = (0, 0);
            for y in fields(x.3) {
                match y.0 {
                    1 => id = y.2,
                    4 => {
                        for z in fields(y.3) {
                            if z.0 == 1 {
                                func = z.2;
                            }
                        }
                    }
                    _ => {}
                }
            }
            loc.insert(id, func);
        }
        let sample_types = f
            .iter()
            .filter(|x| x.0 == 1)
            .map(|x| {
                let v = fields(x.3);
                let get = |n| v.iter().find(|y| y.0 == n).map_or(0, |y| y.2);
                (s(get(1)), s(get(2)))
            })
            .collect();
        let samples = f
            .iter()
            .filter(|x| x.0 == 2)
            .map(|x| {
                let v = fields(x.3);
                let ids = v.iter().find(|y| y.0 == 1).map(|y| packed(y.3)).unwrap();
                let vals = v.iter().find(|y| y.0 == 2).map(|y| packed(y.3)).unwrap();
                let mut names: Vec<String> = ids.iter().map(|i| fun[&loc[i]].0.clone()).collect();
                names.reverse();
                (names, vals.into_iter().map(|v| v as i64).collect())
            })
            .collect();
        Decoded {
            sample_types,
            samples,
            functions: fun.into_values().map(|(n, f, l)| (n, (f, l))).collect(),
            time_nanos: f.iter().find(|x| x.0 == 9).map_or(0, |x| x.2),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_the_decoder() {
        let mut b = Builder::new(
            &[("inuse_space", "bytes"), ("inuse_objects", "count")],
            ("space", "bytes"),
            1_700_000_000_000_000_000,
            10_000_000_000,
        );
        b.add_folded("sys.modules['app'];CACHE;[<key>]", &[4096, 3]);
        b.add_folded("sys.modules['app'];CACHE", &[100, 1]);
        b.add_folded(
            "handle (app/server.py:42);make (app/cache.py:7)",
            &[1 << 40, 1],
        );
        b.add_folded("nothing", &[0, 0]); // dropped
        let d = decode::decode(&b.encode());
        assert_eq!(
            d.sample_types,
            vec![
                ("inuse_space".to_string(), "bytes".to_string()),
                ("inuse_objects".to_string(), "count".to_string())
            ]
        );
        assert_eq!(d.samples.len(), 3);
        assert_eq!(
            d.samples[0].0,
            vec!["sys.modules['app']", "CACHE", "[<key>]"]
        );
        assert_eq!(d.samples[0].1, vec![4096, 3]);
        assert_eq!(d.samples[1].0, vec!["sys.modules['app']", "CACHE"]);
        assert_eq!(
            d.samples[2].0,
            vec!["handle (app/server.py:42)", "make (app/cache.py:7)"]
        );
        assert_eq!(d.samples[2].1[0], 1 << 40);
        assert_eq!(
            d.functions["make (app/cache.py:7)"],
            ("app/cache.py".to_string(), 7)
        );
        assert_eq!(d.time_nanos, 1_700_000_000_000_000_000);
    }

    #[test]
    fn frames_with_and_without_locations() {
        assert_eq!(split_frame("f (a/b.py:3)"), ("f", "a/b.py", 3));
        assert_eq!(split_frame("f (a/b.py)"), ("f", "a/b.py", 0));
        assert_eq!(
            split_frame("CACHE[<str len=3>] (12 objects)"),
            ("CACHE[<str len=3>] (12 objects)", "", 0)
        );
        assert_eq!(split_frame("plain"), ("plain", "", 0));
    }
}
