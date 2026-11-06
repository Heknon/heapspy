//! `diff`: growth by type and by retaining site between two snapshots.
//!
//! Addresses are not stable between dumps, so objects are never matched one
//! to one. Instead each snapshot is reduced to aggregates keyed by strings
//! that do survive a re-dump: type names, and *sites*.
//!
//! A site is a position in the dominator tree named by labels. The site of a
//! root object is its root label. The site of any other object `v` is the
//! site of its immediate dominator `d` followed by the label of the edge
//! into `v`:
//!
//! - if `v`'s shortest-path parent is `d` itself, that edge's label
//!   (`['CACHE']`, `.listeners`);
//! - otherwise `v` is reached through objects that `d` dominates, and the
//!   label is `...` followed by the label of the last edge into `v`.
//!
//! List and tuple indices are generalised to `[<index>]`, since positions
//! shift as containers change. Only objects at most [`MAX_SITE_DEPTH`] levels
//! below the super-root get a site; deeper objects are already counted in the
//! retained size of their ancestor's site. Objects that end up with the same
//! site (all values of one redacted-key dict, all items of one list) are
//! summed, so a site's numbers are the total retained by everything at that
//! position.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use heapspy_snapshot::{EdgeLabel, Snapshot};

use crate::analysis::{Analysis, CHAIN_RATIO};
use crate::dominators::NONE;
use crate::report::{
    DiffKind, DiffReport, DiffSide, DiffTotals, SchemaVersion, SiteGrowth, TypeGrowth,
};
use crate::{notes, push_edge, snapshot_summary, DiffOptions, Result};

/// Deepest dominator-tree level that gets its own site. Level 1 is the root
/// objects; `module -> __dict__ -> CACHE -> entry -> entry.__dict__ ->
/// value` reaches level 6.
pub const MAX_SITE_DEPTH: u8 = 6;

struct Site {
    parent: u32,
    label: String,
    bytes: u64,
    objects: u64,
    /// How many objects share this site.
    members: u64,
    /// Type of the largest contributor, and its retained bytes.
    type_group: u32,
    type_bytes: u64,
}

#[derive(Clone, Debug, Default)]
struct SiteStat {
    type_name: String,
    bytes: u64,
    objects: u64,
    members: u64,
    parent: Option<String>,
}

struct Side {
    totals: DiffSide,
    types: HashMap<String, (u64, u64)>,
    sites: HashMap<String, SiteStat>,
}

fn site_edge_label(snap: &Snapshot, l: EdgeLabel) -> Result<String> {
    Ok(match l {
        EdgeLabel::ListItem(_) | EdgeLabel::TupleItem(_) => "[<index>]".to_string(),
        other => snap.render_label(other)?,
    })
}

fn render_site(sites: &[Site], mut id: u32) -> String {
    let mut labels = Vec::new();
    while id != NONE {
        labels.push(sites[id as usize].label.as_str());
        id = sites[id as usize].parent;
    }
    let mut s = String::new();
    for (i, l) in labels.iter().rev().enumerate() {
        if i == 0 {
            s.push_str(l);
        } else {
            push_edge(&mut s, l);
        }
    }
    s
}

fn sites(a: &Analysis) -> Result<HashMap<String, SiteStat>> {
    let root = a.root();
    let n = a.g.n as usize + 1;
    let mut site_of = vec![NONE; n];
    let mut depth = vec![0u8; n];
    let mut trie: HashMap<(u32, String), u32> = HashMap::new();
    let mut sites: Vec<Site> = Vec::new();
    for &v in &a.order[1..] {
        let vi = v as usize;
        let p = a.idom[vi];
        let d = if p == root {
            1
        } else {
            depth[p as usize].saturating_add(1)
        };
        depth[vi] = d;
        if d > MAX_SITE_DEPTH {
            continue;
        }
        let e = a.via[vi];
        let (parent, label) = if p == root {
            match a.g.root_entry(e) {
                Some(r) => (NONE, a.snap.string(r.label)?.to_string()),
                // Dominated only by the super-root but reached through an
                // ordinary edge: the object hangs off several roots and none
                // of them owns it. Name the site by the edge alone.
                None => {
                    let l = site_edge_label(a.snap, a.snap.edge(e as u64).label)?;
                    (NONE, format!("...{l}"))
                }
            }
        } else {
            let l = site_edge_label(a.snap, a.snap.edge(e as u64).label)?;
            let l = if a.g.csr.source_of(e) == p {
                l
            } else {
                format!("...{l}")
            };
            (site_of[p as usize], l)
        };
        let bytes = a.retained[vi];
        let id = match trie.entry((parent, label)) {
            Entry::Occupied(o) => *o.get(),
            Entry::Vacant(slot) => {
                sites.push(Site {
                    parent,
                    label: slot.key().1.clone(),
                    bytes: 0,
                    objects: 0,
                    members: 0,
                    type_group: a.group(v),
                    type_bytes: bytes,
                });
                *slot.insert(sites.len() as u32 - 1)
            }
        };
        site_of[vi] = id;
        let s = &mut sites[id as usize];
        s.bytes += bytes;
        s.objects += a.retained_count[vi] as u64;
        s.members += 1;
        if bytes > s.type_bytes {
            s.type_group = a.group(v);
            s.type_bytes = bytes;
        }
    }
    drop(trie);
    let mut out = HashMap::with_capacity(sites.len());
    for (id, s) in sites.iter().enumerate() {
        let key = render_site(&sites, id as u32);
        out.insert(
            key,
            SiteStat {
                type_name: a.types.names[s.type_group as usize].clone(),
                bytes: s.bytes,
                objects: s.objects,
                members: s.members,
                parent: (s.parent != NONE).then(|| render_site(&sites, s.parent)),
            },
        );
    }
    Ok(out)
}

fn side(snap: &Snapshot) -> Result<Side> {
    let a = Analysis::new(snap)?;
    let types = a
        .type_rows()
        .into_iter()
        .map(|r| (r.type_name, (r.count, r.shallow_bytes)))
        .collect();
    Ok(Side {
        totals: DiffSide {
            objects: snap.object_count() as u64,
            shallow_bytes: a.shallow_total,
            reachable_bytes: a.reachable_bytes(),
        },
        types,
        sites: sites(&a)?,
    })
}

fn delta(before: u64, after: u64) -> i64 {
    after as i64 - before as i64
}

pub fn diff(
    before: &Snapshot,
    before_path: &str,
    after: &Snapshot,
    after_path: &str,
    opts: &DiffOptions,
) -> Result<DiffReport> {
    // One analysis at a time, so peak memory is that of the larger snapshot.
    let b = side(before)?;
    let a = side(after)?;

    let mut names: Vec<&String> = b.types.keys().chain(a.types.keys()).collect();
    names.sort();
    names.dedup();
    let mut by_type: Vec<TypeGrowth> = names
        .into_iter()
        .map(|name| {
            let (bc, bb) = b.types.get(name).copied().unwrap_or_default();
            let (ac, ab) = a.types.get(name).copied().unwrap_or_default();
            TypeGrowth {
                type_name: name.clone(),
                before_count: bc,
                after_count: ac,
                delta_count: delta(bc, ac),
                before_bytes: bb,
                after_bytes: ab,
                delta_bytes: delta(bb, ab),
            }
        })
        .filter(|t| t.delta_count != 0 || t.delta_bytes != 0)
        .collect();
    by_type.sort_by(|x, y| {
        y.delta_bytes
            .cmp(&x.delta_bytes)
            .then_with(|| y.delta_count.cmp(&x.delta_count))
            .then_with(|| x.type_name.cmp(&y.type_name))
    });
    by_type.truncate(opts.top);

    let mut keys: Vec<&String> = b.sites.keys().chain(a.sites.keys()).collect();
    keys.sort();
    keys.dedup();
    let empty = SiteStat::default();
    let mut rows: Vec<(SiteGrowth, Option<String>, bool)> = keys
        .into_iter()
        .map(|k| {
            let (bs, as_) = (b.sites.get(k), a.sites.get(k));
            let (x, y) = (bs.unwrap_or(&empty), as_.unwrap_or(&empty));
            let present = as_.or(bs).expect("key from one side");
            let row = SiteGrowth {
                site: k.clone(),
                type_name: present.type_name.clone(),
                before_retained_bytes: x.bytes,
                after_retained_bytes: y.bytes,
                delta_retained_bytes: delta(x.bytes, y.bytes),
                before_retained_objects: x.objects,
                after_retained_objects: y.objects,
                delta_retained_objects: delta(x.objects, y.objects),
            };
            let single = x.members.max(y.members) <= 1;
            (row, present.parent.clone(), single)
        })
        .filter(|(r, _, _)| r.delta_retained_bytes != 0 || r.delta_retained_objects != 0)
        .collect();

    // A site whose change is (almost) all in one child site only restates
    // that child: `module`, `module.__dict__` and `['CACHE']` all grow by
    // the same amount, and only `['CACHE']` is worth showing. Same 90% rule
    // as for top retainers, applied to the deltas. Only a child site that is
    // a single object counts: a child that sums many objects (all values of
    // CACHE under one redacted key) is an aggregate, not a wrapper, and its
    // parent stays listed.
    let mut child_extreme: HashMap<&str, (i64, i64)> = HashMap::new();
    for (r, parent, single) in &rows {
        if let (Some(p), true) = (parent, single) {
            let e = child_extreme.entry(p.as_str()).or_default();
            e.0 = e.0.max(r.delta_retained_bytes);
            e.1 = e.1.min(r.delta_retained_bytes);
        }
    }
    let restates: Vec<bool> = rows
        .iter()
        .map(|(r, _, _)| {
            let d = r.delta_retained_bytes as f64;
            let (hi, lo) = child_extreme
                .get(r.site.as_str())
                .copied()
                .unwrap_or_default();
            (d > 0.0 && hi as f64 >= CHAIN_RATIO * d) || (d < 0.0 && lo as f64 <= CHAIN_RATIO * d)
        })
        .collect();
    drop(child_extreme);
    let mut by_site: Vec<SiteGrowth> = rows
        .drain(..)
        .zip(restates)
        .filter(|(_, skip)| !skip)
        .map(|((r, _, _), _)| r)
        .collect();
    by_site.sort_by(|x, y| {
        y.delta_retained_bytes
            .cmp(&x.delta_retained_bytes)
            .then_with(|| x.site.cmp(&y.site))
    });
    by_site.truncate(opts.top);

    let mut notes = vec![notes::identity_approximate()];
    if !before.info().contents_captured || !after.info().contents_captured {
        notes.push(notes::keys_redacted());
    }
    if before.info().truncated || after.info().truncated {
        notes.push(notes::truncated_snapshot());
    }

    Ok(DiffReport {
        schema_version: SchemaVersion,
        kind: DiffKind::Kind,
        identity_approximate: true,
        before: snapshot_summary(before, before_path),
        after: snapshot_summary(after, after_path),
        totals: DiffTotals {
            delta_objects: delta(b.totals.objects, a.totals.objects),
            delta_shallow_bytes: delta(b.totals.shallow_bytes, a.totals.shallow_bytes),
            delta_reachable_bytes: delta(b.totals.reachable_bytes, a.totals.reachable_bytes),
            before: b.totals,
            after: a.totals,
        },
        by_type,
        by_site,
        notes,
    })
}
