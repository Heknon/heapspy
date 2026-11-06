//! Retention flame graphs as folded stacks.
//!
//! A snapshot has no call stacks, so the "stacks" here are paths in the
//! dominator tree. Each frame is one hop: the root label for a root object,
//! and the label of the entering edge plus the object's type for anything
//! else. Every object belongs to exactly one frame, and a frame's self bytes
//! are the shallow sizes of its objects. Since the objects under a frame are
//! exactly the dominator subtrees of its objects, a frame's width (self plus
//! descendants) is the retained size of everything merged into it.
//!
//! Edge choice follows diff sites (see the `diff` module): the BFS entry edge,
//! written with a `...` prefix when the BFS parent is not the immediate
//! dominator, and an object dominated only by the super-root but reached
//! through an ordinary edge becomes a top-level `...` frame.
//!
//! Siblings with the same frame are merged: list and tuple indices are
//! written as `[<index>]`, redacted keys with the same placeholder render the
//! same, and merged frames merge their children in turn, like a trie.
//!
//! The work is done in two stages so that no string is built per object:
//!
//! 1. A label tree keyed by `(parent frame, edge label, type)` with indices
//!    normalised. One pass over the dominator tree in preorder assigns each
//!    object to a frame; the depth cap applies here.
//! 2. The label tree is rendered into a text tree, one string per surviving
//!    frame. Frames narrower than the cutoff are folded into an `[other]`
//!    sibling here, and frames with the same text merge.
//!
//! Neither stage recurses; both rely on parents having smaller ids than their
//! children.
//!
//! A differential adds both snapshots' label trees to one text tree, so the
//! frames of the two dumps are matched by frame text, never by address, and
//! then applies the cutoff to the wider side of each frame.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{self, Write};

use heapspy_snapshot::{EdgeLabel, Snapshot, StrId};

use crate::analysis::Analysis;
use crate::dominators::NONE;
use crate::{Error, Result};

/// Default `--max-depth`: frames below this depth fold into `[other]`.
pub const DEFAULT_MAX_DEPTH: u32 = 32;
/// Default `--min-pct`: frames narrower than this share of the reachable
/// bytes fold into `[other]`.
pub const DEFAULT_MIN_PCT: f64 = 0.01;
/// Text of the frame that collects folded objects.
pub const OTHER_FRAME: &str = "[other]";

/// Minimum frame width.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MinWidth {
    Bytes(u64),
    /// Percent of the reachable bytes (for a diff, of the larger snapshot).
    Pct(f64),
}

/// Options for [`folded_stacks`] and [`folded_diff`].
#[derive(Clone, Debug, PartialEq)]
pub struct FlameOptions {
    /// Deepest dominator-tree level that gets its own frame. Objects below
    /// it are counted in an `[other]` frame under their ancestor at this
    /// level. At least 1.
    pub max_depth: u32,
    pub min_width: MinWidth,
}

impl Default for FlameOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            min_width: MinWidth::Pct(DEFAULT_MIN_PCT),
        }
    }
}

impl FlameOptions {
    fn validate(&self) -> Result<()> {
        if self.max_depth == 0 {
            return Err(Error::InvalidArgument(
                "max depth must be at least 1".into(),
            ));
        }
        if let MinWidth::Pct(p) = self.min_width {
            if !(0.0..=100.0).contains(&p) {
                return Err(Error::InvalidArgument(format!(
                    "min percentage must be between 0 and 100, got {p}"
                )));
            }
        }
        Ok(())
    }

    fn min_bytes(&self, reachable: u64) -> u64 {
        match self.min_width {
            MinWidth::Bytes(b) => b,
            MinWidth::Pct(p) => (reachable as f64 * p / 100.0).ceil() as u64,
        }
    }
}

/// One folded line: `stack` is the frames joined by `;`, root first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldedLine {
    pub stack: String,
    /// Self bytes of the last frame.
    pub bytes: u64,
}

/// Folded stacks of one snapshot, sorted by stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldedStacks {
    pub lines: Vec<FoldedLine>,
    pub reachable_bytes: u64,
    pub reachable_objects: u64,
    /// The cutoff that was applied, in bytes.
    pub min_bytes: u64,
}

impl FoldedStacks {
    /// Write `stack bytes` lines.
    pub fn write_to(&self, mut w: impl Write) -> io::Result<()> {
        for l in &self.lines {
            writeln!(w, "{} {}", l.stack, l.bytes)?;
        }
        Ok(())
    }
}

/// One line of a differential: self bytes of the last frame in each snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffLine {
    pub stack: String,
    pub before: u64,
    pub after: u64,
}

/// Differential folded stacks, sorted by stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldedDiff {
    pub lines: Vec<DiffLine>,
    pub before_reachable_bytes: u64,
    pub after_reachable_bytes: u64,
    pub before_reachable_objects: u64,
    pub after_reachable_objects: u64,
    pub min_bytes: u64,
}

impl FoldedDiff {
    /// Write `stack before after` lines, the input format of inferno's (and
    /// FlameGraph's) differential mode.
    pub fn write_to(&self, mut w: impl Write) -> io::Result<()> {
        for l in &self.lines {
            writeln!(w, "{} {} {}", l.stack, l.before, l.after)?;
        }
        Ok(())
    }
}

// ---- stage 1: label tree ----

/// A small multiplicative hasher. Keys are a few integers, and the default
/// SipHash is the bulk of the label-tree pass on large heaps.
#[derive(Default)]
struct Fx(u64);

impl Hasher for Fx {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(b as u64);
        }
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.write_u64(i as u64);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.write_u64(i as u64);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0 = (self.0.rotate_left(5) ^ i).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<Fx>>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    /// A root object: its root label.
    Root(StrId),
    /// An edge label with list and tuple indices zeroed, whether it was
    /// reached through other objects (`...`), and the object's type group.
    Edge {
        label: EdgeLabel,
        dots: bool,
        group: u32,
    },
    /// Everything below the depth cap.
    Other,
}

struct Frame {
    parent: u32,
    key: Key,
    depth: u32,
    self_bytes: u64,
    total: u64,
}

struct LabelTree {
    frames: Vec<Frame>,
}

fn normalise(l: EdgeLabel) -> EdgeLabel {
    match l {
        EdgeLabel::ListItem(_) => EdgeLabel::ListItem(0),
        EdgeLabel::TupleItem(_) => EdgeLabel::TupleItem(0),
        other => other,
    }
}

fn label_tree(a: &Analysis, max_depth: u32) -> LabelTree {
    let root = a.root();
    let n = a.g.n as usize + 1;
    let mut frame_of = vec![NONE; n];
    let mut frames: Vec<Frame> = Vec::new();
    let mut index: FxMap<(u32, Key), u32> = FxMap::default();
    let mut get = |frames: &mut Vec<Frame>, parent: u32, key: Key| -> u32 {
        *index.entry((parent, key)).or_insert_with(|| {
            let depth = if parent == NONE {
                1
            } else {
                frames[parent as usize].depth + 1
            };
            frames.push(Frame {
                parent,
                key,
                depth,
                self_bytes: 0,
                total: 0,
            });
            frames.len() as u32 - 1
        })
    };
    for &v in &a.order[1..] {
        let vi = v as usize;
        let p = a.idom[vi];
        let e = a.via[vi];
        let f = if p == root {
            let key = match a.g.root_entry(e) {
                Some(r) => Key::Root(r.label),
                // Dominated only by the super-root but reached through an
                // ordinary edge: shared by several roots, owned by none.
                None => Key::Edge {
                    label: normalise(a.snap.edge(e as u64).label),
                    dots: true,
                    group: a.group(v),
                },
            };
            get(&mut frames, NONE, key)
        } else {
            let pf = frame_of[p as usize];
            let pframe = &frames[pf as usize];
            if pframe.key == Key::Other {
                pf
            } else if pframe.depth >= max_depth {
                get(&mut frames, pf, Key::Other)
            } else {
                let key = Key::Edge {
                    label: normalise(a.snap.edge(e as u64).label),
                    dots: a.g.csr.source_of(e) != p,
                    group: a.group(v),
                };
                get(&mut frames, pf, key)
            }
        };
        frame_of[vi] = f;
        frames[f as usize].self_bytes += a.snap.object(v).shallow_size;
    }
    drop(frame_of);
    for f in (0..frames.len()).rev() {
        frames[f].total += frames[f].self_bytes;
        let (p, t) = (frames[f].parent, frames[f].total);
        if p != NONE {
            frames[p as usize].total += t;
        }
    }
    LabelTree { frames }
}

/// `builtins.dict` -> `dict`; other names are kept whole.
fn compact_type(name: &str) -> &str {
    name.strip_prefix("builtins.").unwrap_or(name)
}

/// Make a frame safe for the folded format: `;` separates frames and a line
/// break ends the line, so neither may appear inside one.
fn sanitise(s: &mut String) {
    if s.contains([';', '\n', '\r']) {
        *s = s
            .chars()
            .map(|c| match c {
                ';' => ':',
                '\n' | '\r' => ' ',
                c => c,
            })
            .collect();
    }
}

fn frame_text(a: &Analysis, key: Key) -> Result<String> {
    let mut s = match key {
        Key::Root(l) => a.snap.string(l)?.to_string(),
        Key::Other => return Ok(OTHER_FRAME.to_string()),
        Key::Edge { label, dots, group } => {
            let mut s = String::new();
            if dots {
                s.push_str("...");
            }
            match label {
                EdgeLabel::ListItem(_) | EdgeLabel::TupleItem(_) => s.push_str("[<index>]"),
                l => s.push_str(&a.snap.render_label(l)?),
            }
            s.push(' ');
            s.push_str(compact_type(&a.types.names[group as usize]));
            s
        }
    };
    sanitise(&mut s);
    Ok(s)
}

// ---- stage 2: text tree ----

struct Node {
    parent: u32,
    text: u32,
    self_bytes: [u64; 2],
}

/// Frames keyed by `(parent, text)`, with self bytes for up to two
/// snapshots (slot 0 is "before", or the only snapshot).
#[derive(Default)]
struct TextTree {
    texts: Vec<Box<str>>,
    text_ids: HashMap<Box<str>, u32>,
    nodes: Vec<Node>,
    index: FxMap<(u32, u32), u32>,
}

impl TextTree {
    fn child(&mut self, parent: u32, text: &str) -> u32 {
        let t = match self.text_ids.get(text) {
            Some(&t) => t,
            None => {
                let b: Box<str> = text.into();
                self.texts.push(b.clone());
                self.text_ids.insert(b, self.texts.len() as u32 - 1);
                self.texts.len() as u32 - 1
            }
        };
        let nodes = &mut self.nodes;
        *self.index.entry((parent, t)).or_insert_with(|| {
            nodes.push(Node {
                parent,
                text: t,
                self_bytes: [0; 2],
            });
            nodes.len() as u32 - 1
        })
    }

    /// Add one snapshot's label tree in `slot`. Frames narrower than
    /// `min_bytes` are folded, with their descendants, into an `[other]`
    /// child of their parent.
    fn add(&mut self, a: &Analysis, lt: &LabelTree, slot: usize, min_bytes: u64) -> Result<()> {
        let mut map = vec![NONE; lt.frames.len()];
        for (f, fr) in lt.frames.iter().enumerate() {
            let parent = if fr.parent == NONE {
                NONE
            } else {
                match map[fr.parent as usize] {
                    // Folded with an ancestor, already counted there.
                    NONE => continue,
                    p => p,
                }
            };
            if fr.key == Key::Other {
                let o = self.child(parent, OTHER_FRAME);
                self.nodes[o as usize].self_bytes[slot] += fr.self_bytes;
                map[f] = o;
            } else if fr.total < min_bytes {
                let o = self.child(parent, OTHER_FRAME);
                self.nodes[o as usize].self_bytes[slot] += fr.total;
            } else {
                let node = self.child(parent, &frame_text(a, fr.key)?);
                self.nodes[node as usize].self_bytes[slot] += fr.self_bytes;
                map[f] = node;
            }
        }
        Ok(())
    }

    /// Width of every node per slot.
    fn totals(&self) -> Vec<[u64; 2]> {
        let mut t: Vec<[u64; 2]> = self.nodes.iter().map(|n| n.self_bytes).collect();
        for i in (0..self.nodes.len()).rev() {
            let p = self.nodes[i].parent;
            if p != NONE {
                let c = t[i];
                t[p as usize][0] += c[0];
                t[p as usize][1] += c[1];
            }
        }
        t
    }

    /// A copy with every node narrower than `min_bytes` in both slots folded
    /// into an `[other]` sibling.
    fn pruned(&self, min_bytes: u64) -> TextTree {
        let totals = self.totals();
        let mut out = TextTree::default();
        let mut map = vec![NONE; self.nodes.len()];
        for (i, n) in self.nodes.iter().enumerate() {
            let parent = if n.parent == NONE {
                NONE
            } else {
                match map[n.parent as usize] {
                    NONE => continue,
                    p => p,
                }
            };
            let text = &*self.texts[n.text as usize];
            let [b, a] = totals[i];
            if text != OTHER_FRAME && b.max(a) < min_bytes {
                let o = out.child(parent, OTHER_FRAME);
                out.nodes[o as usize].self_bytes[0] += b;
                out.nodes[o as usize].self_bytes[1] += a;
            } else {
                let m = out.child(parent, text);
                out.nodes[m as usize].self_bytes[0] += n.self_bytes[0];
                out.nodes[m as usize].self_bytes[1] += n.self_bytes[1];
                map[i] = m;
            }
        }
        out
    }

    /// `(stack, self bytes)` for every node with self bytes in either slot,
    /// sorted by stack.
    fn lines(&self) -> Vec<(String, [u64; 2])> {
        let mut out = Vec::new();
        let mut path: Vec<u32> = Vec::new();
        for n in &self.nodes {
            if n.self_bytes == [0, 0] {
                continue;
            }
            path.clear();
            path.push(n.text);
            let mut p = n.parent;
            while p != NONE {
                path.push(self.nodes[p as usize].text);
                p = self.nodes[p as usize].parent;
            }
            let mut s = String::new();
            for (k, &t) in path.iter().rev().enumerate() {
                if k > 0 {
                    s.push(';');
                }
                s.push_str(&self.texts[t as usize]);
            }
            out.push((s, n.self_bytes));
        }
        out.sort_unstable_by(|x, y| x.0.cmp(&y.0));
        out
    }
}

/// Folded stacks of one snapshot.
pub fn folded_stacks(snap: &Snapshot, opts: &FlameOptions) -> Result<FoldedStacks> {
    opts.validate()?;
    let a = Analysis::new(snap)?;
    let reachable_bytes = a.reachable_bytes();
    let min_bytes = opts.min_bytes(reachable_bytes);
    let lt = label_tree(&a, opts.max_depth);
    let mut tt = TextTree::default();
    tt.add(&a, &lt, 0, min_bytes)?;
    drop(lt);
    let lines = tt
        .lines()
        .into_iter()
        .map(|(stack, b)| FoldedLine { stack, bytes: b[0] })
        .collect();
    Ok(FoldedStacks {
        lines,
        reachable_bytes,
        reachable_objects: a.reachable_objects(),
        min_bytes,
    })
}

/// Differential folded stacks: both snapshots are folded into one tree by
/// frame text, then the cutoff is applied to the wider of the two widths, so
/// a frame is either shown on both sides or folded on both sides.
pub fn folded_diff(before: &Snapshot, after: &Snapshot, opts: &FlameOptions) -> Result<FoldedDiff> {
    opts.validate()?;
    let mut tt = TextTree::default();
    let mut reach = [(0u64, 0u64); 2];
    // One analysis at a time, so peak memory is that of the larger snapshot.
    for (slot, snap) in [before, after].into_iter().enumerate() {
        let a = Analysis::new(snap)?;
        reach[slot] = (a.reachable_bytes(), a.reachable_objects());
        let lt = label_tree(&a, opts.max_depth);
        tt.add(&a, &lt, slot, 0)?;
    }
    let min_bytes = opts.min_bytes(reach[0].0.max(reach[1].0));
    let tt = if min_bytes > 0 {
        tt.pruned(min_bytes)
    } else {
        tt
    };
    let lines = tt
        .lines()
        .into_iter()
        .map(|(stack, b)| DiffLine {
            stack,
            before: b[0],
            after: b[1],
        })
        .collect();
    Ok(FoldedDiff {
        lines,
        before_reachable_bytes: reach[0].0,
        after_reachable_bytes: reach[1].0,
        before_reachable_objects: reach[0].1,
        after_reachable_objects: reach[1].1,
        min_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_replaces_separators() {
        let mut s = "['a;b\nc']".to_string();
        sanitise(&mut s);
        assert_eq!(s, "['a:b c']");
    }

    #[test]
    fn compact_type_strips_builtins() {
        assert_eq!(compact_type("builtins.dict"), "dict");
        assert_eq!(compact_type("app.session.Session"), "app.session.Session");
    }

    #[test]
    fn options_are_validated() {
        let bad = FlameOptions {
            max_depth: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
        let bad = FlameOptions {
            min_width: MinWidth::Pct(101.0),
            ..Default::default()
        };
        assert!(bad.validate().is_err());
        let bad = FlameOptions {
            min_width: MinWidth::Pct(f64::NAN),
            ..Default::default()
        };
        assert!(bad.validate().is_err());
        assert_eq!(FlameOptions::default().min_bytes(1_000_000), 100);
    }
}
