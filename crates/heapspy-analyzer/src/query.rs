//! `query --type` and `query --retaining-path`.

use std::collections::HashMap;

use heapspy_snapshot::{EdgeLabel, Snapshot};

use crate::analysis::Analysis;
use crate::dominators::NONE;
use crate::report::{
    self, Address, Holder, Instance, KeptBy, PathQuery, PathQueryBy, RetainingPath,
    RetainingPathKind, RetainingPathReport, SchemaVersion, SizeGroup, TypeLocation, TypeQueryKind,
    TypeQueryReport,
};
use crate::{format_address, notes, snapshot_summary, Error, PathTarget, QueryOptions, Result};

/// Edge label with the per-entry part replaced, so that one container
/// holding many instances is one holder row: dict keys become `[<key>]`,
/// list and tuple indices `[<index>]`.
fn generalised_label(snap: &Snapshot, l: EdgeLabel) -> Result<String> {
    Ok(match l {
        EdgeLabel::DictValue(_) => "[<key>]".to_string(),
        EdgeLabel::DictKey(_) => "<key [<key>]>".to_string(),
        EdgeLabel::ListItem(_) | EdgeLabel::TupleItem(_) => "[<index>]".to_string(),
        other => snap.render_label(other)?,
    })
}

/// All objects whose type is in one of `groups`, by node id.
fn instances(a: &Analysis, groups: &[u32]) -> Vec<u32> {
    let mut want = vec![false; a.types.names.len()];
    for &g in groups {
        want[g as usize] = true;
    }
    (0..a.g.n).filter(|&v| want[a.group(v) as usize]).collect()
}

/// Largest by retained size first, then by address.
fn rank_by_retained(a: &Analysis, nodes: &mut [u32], top: usize) {
    let cmp = |x: &u32, y: &u32| {
        a.retained[*y as usize]
            .cmp(&a.retained[*x as usize])
            .then(x.cmp(y))
    };
    if top < nodes.len() {
        nodes.select_nth_unstable_by(top, cmp);
    }
    let k = top.min(nodes.len());
    nodes[..k].sort_unstable_by(cmp);
}

fn matched_groups(a: &Analysis, type_name: &str) -> Result<Vec<u32>> {
    let groups = a.types.matching(type_name);
    if groups.is_empty() {
        return Err(Error::NotFound(format!(
            "no type named {type_name:?} in the snapshot"
        )));
    }
    Ok(groups)
}

/// The type query report of an analysed snapshot, and the node of each
/// entry of `top_instances`, in order.
pub(crate) fn query_type(
    a: &Analysis,
    path: &str,
    type_name: &str,
    opts: &QueryOptions,
) -> Result<(TypeQueryReport, Vec<u32>)> {
    let snap = a.snap;
    let groups = matched_groups(a, type_name)?;
    let mut inst = instances(a, &groups);
    let shallow_bytes = inst.iter().map(|&v| snap.object(v).shallow_size).sum();
    let retained_bytes = a.set_retained(&inst);

    // Holders: every reference into an instance, grouped by the referrer's
    // type and the generalised label.
    let mut member = vec![false; a.g.n as usize + 1];
    for &v in &inst {
        member[v as usize] = true;
    }
    let mut held: HashMap<(u32, String), u64> = HashMap::new();
    for u in 0..a.g.n {
        for e in a.g.csr.range(u) {
            let t = a.g.csr.targets[e];
            if t != NONE && member[t as usize] {
                let label = generalised_label(snap, snap.edge(e as u64).label)?;
                *held.entry((a.group(u), label)).or_default() += 1;
            }
        }
    }
    drop(member);
    let mut holders: Vec<Holder> = held
        .into_iter()
        .map(|((g, edge), count)| Holder {
            type_name: a.types.names[g as usize].clone(),
            edge,
            count,
        })
        .collect();
    holders.sort_by(|x, y| {
        y.count
            .cmp(&x.count)
            .then_with(|| x.type_name.cmp(&y.type_name))
            .then_with(|| x.edge.cmp(&y.edge))
    });
    holders.truncate(opts.top);

    let (kept_by, by_size) = kept_by(a, &inst, opts.top)?;

    let total = inst.len() as u64;
    rank_by_retained(a, &mut inst, opts.top);
    inst.truncate(opts.top);
    let mut top_instances = Vec::new();
    for &v in inst.iter().take(opts.top) {
        let o = snap.object(v);
        let (source_loc, source_loc_reason) = a.source_loc(v)?;
        top_instances.push(Instance {
            address: Address(o.addr),
            type_name: a.type_name(v).to_string(),
            shallow_bytes: o.shallow_size,
            retained_bytes: a.retained[v as usize],
            length: snap.extras(v).and_then(|x| x.length),
            path: a.path(v)?,
            allocated_at: None,
            source_loc,
            source_loc_reason,
        });
    }

    let mut notes = Vec::new();
    notes::header_notes(snap, &mut notes);
    let mut sorted = groups.clone();
    sorted.sort_by(|&x, &y| a.types.names[x as usize].cmp(&a.types.names[y as usize]));
    let matched_types: Vec<String> = sorted
        .iter()
        .map(|&g| a.types.names[g as usize].clone())
        .collect();
    let mut matched_type_locations = Vec::with_capacity(sorted.len());
    for &g in &sorted {
        let (type_location, type_location_reason) = a.group_location(g)?;
        matched_type_locations.push(TypeLocation {
            type_name: a.types.names[g as usize].clone(),
            type_location,
            type_location_reason,
        });
    }
    let report = TypeQueryReport {
        schema_version: SchemaVersion,
        kind: TypeQueryKind::Kind,
        snapshot: snapshot_summary(snap, path),
        query: type_name.to_string(),
        matched_types,
        matched_type_locations,
        instances: total,
        shallow_bytes,
        retained_bytes,
        top_instances,
        holders,
        kept_by,
        by_size,
        notes,
    };
    Ok((report, inst))
}

/// Holders a type's instances are attributed to: the heap's largest
/// disjoint holders, as `top_retainers` picks them.
const KEEPERS: usize = 64;
/// Instances per group whose paths are rendered to find the common one.
const THROUGH_SAMPLES: usize = 256;

#[derive(Default)]
struct KeptAgg {
    instances: u64,
    bytes: u64,
    sizes: HashMap<u64, (u64, u64)>,
    samples: Vec<u32>,
}

/// Size groups from `(size → (count, bytes))`, most bytes first.
fn size_groups(m: &HashMap<u64, (u64, u64)>, top: usize) -> Vec<SizeGroup> {
    let mut v: Vec<SizeGroup> = m
        .iter()
        .map(|(&size, &(blocks, bytes))| SizeGroup {
            size,
            blocks,
            bytes,
        })
        .collect();
    v.sort_by(|x, y| y.bytes.cmp(&x.bytes).then(x.size.cmp(&y.size)));
    v.truncate(top);
    v
}

/// The instances grouped by what keeps them alive (`kept_by`), and by size
/// (`by_size`).
fn kept_by(a: &Analysis, inst: &[u32], top: usize) -> Result<(Vec<KeptBy>, Vec<SizeGroup>)> {
    let snap = a.snap;
    let keepers = a.top_retainers(KEEPERS)?;
    // Each node's listed ancestor in the dominator tree (or itself).
    let n = a.root() as usize;
    let mut holder = vec![u32::MAX; n + 1];
    for (k, &v) in keepers.iter().enumerate() {
        holder[v as usize] = k as u32;
    }
    for &v in &a.order[1..] {
        if holder[v as usize] == u32::MAX {
            let p = a.idom[v as usize];
            if p != NONE {
                holder[v as usize] = holder[p as usize];
            }
        }
    }
    // Group key: keeper index, or OTHER, or UNREACHABLE.
    const OTHER: u32 = u32::MAX - 1;
    const UNREACHABLE: u32 = u32::MAX;
    let mut groups: HashMap<u32, KeptAgg> = HashMap::new();
    let mut all_sizes: HashMap<u64, (u64, u64)> = HashMap::new();
    for &v in inst {
        let size = snap.object(v).shallow_size;
        let key = if !a.reachable(v) {
            UNREACHABLE
        } else if holder[v as usize] == u32::MAX {
            OTHER
        } else {
            holder[v as usize]
        };
        let g = groups.entry(key).or_default();
        g.instances += 1;
        g.bytes += size;
        let e = g.sizes.entry(size).or_default();
        e.0 += 1;
        e.1 += size;
        if g.samples.len() < THROUGH_SAMPLES {
            g.samples.push(v);
        }
        let e = all_sizes.entry(size).or_default();
        e.0 += 1;
        e.1 += size;
    }
    let mut out = Vec::new();
    for (key, g) in groups {
        let (kind, keeper) = match key {
            UNREACHABLE => ("unreachable", None),
            OTHER => ("other", None),
            k => ("holder", Some(keepers[k as usize])),
        };
        let (through, through_pct) = if key == UNREACHABLE {
            (None, None)
        } else {
            let mut paths: HashMap<String, u64> = HashMap::new();
            for &v in &g.samples {
                *paths.entry(through_path(a, keeper, v)?).or_default() += 1;
            }
            let best = paths
                .into_iter()
                .max_by(|x, y| x.1.cmp(&y.1).then_with(|| y.0.cmp(&x.0)));
            match best {
                Some((p, c)) => (
                    Some(p),
                    Some((c * 100 / g.samples.len().max(1) as u64) as u32),
                ),
                None => (None, None),
            }
        };
        let (holder_path, holder_name, holder_address) = match keeper {
            Some(k) => {
                let p = a.path(k)?;
                (
                    p.as_ref().map(|p| crate::root_path_string(p)),
                    p.as_ref().map(|p| crate::render::summary::readable_path(p)),
                    Some(Address(snap.object(k).addr)),
                )
            }
            None => (None, None, None),
        };
        out.push(KeptBy {
            kind: kind.to_string(),
            holder: holder_path,
            holder_name,
            holder_address,
            through,
            through_pct,
            instances: g.instances,
            bytes: g.bytes,
            sizes: size_groups(&g.sizes, 3),
        });
    }
    out.sort_by(|x, y| y.bytes.cmp(&x.bytes).then_with(|| x.holder.cmp(&y.holder)));
    let mut out = fold_kept_by(out);
    out.truncate(top);
    Ok((out, size_groups(&all_sizes, top)))
}

/// Holders below this share of the type's bytes are folded into `other`.
const SMALL_GROUP_PCT: u64 = 1;

/// Fold the interpreter's own holders into one `interpreter` group, and
/// holders with less than [`SMALL_GROUP_PCT`] of the bytes into `other`.
/// The unreachable group is never folded.
fn fold_kept_by(groups: Vec<KeptBy>) -> Vec<KeptBy> {
    let total: u64 = groups.iter().map(|g| g.bytes).sum();
    let mut out = Vec::new();
    let mut interp: Option<KeptBy> = None;
    let mut other: Option<KeptBy> = None;
    let merge = |into: &mut Option<KeptBy>, g: KeptBy, kind: &str| {
        let t = into.get_or_insert_with(|| KeptBy {
            kind: kind.to_string(),
            holder: None,
            holder_name: None,
            holder_address: None,
            through: None,
            through_pct: None,
            instances: 0,
            bytes: 0,
            sizes: Vec::new(),
        });
        t.instances += g.instances;
        t.bytes += g.bytes;
        let mut sizes: HashMap<u64, (u64, u64)> = HashMap::new();
        for s in t.sizes.iter().chain(g.sizes.iter()) {
            let e = sizes.entry(s.size).or_default();
            e.0 += s.blocks;
            e.1 += s.bytes;
        }
        t.sizes = size_groups(&sizes, 3);
    };
    for g in groups {
        let interpreter = g.kind == "holder"
            && g.holder
                .as_deref()
                .is_some_and(crate::is_interpreter_holder);
        if interpreter {
            merge(&mut interp, g, "interpreter");
        } else if g.kind == "other"
            || (g.kind == "holder" && g.bytes * 100 < total * SMALL_GROUP_PCT)
        {
            merge(&mut other, g, "other");
        } else {
            out.push(g);
        }
    }
    out.extend(interp);
    out.extend(other);
    out.sort_by_key(|x| std::cmp::Reverse(x.bytes));
    out
}

/// How a raw pointer into native memory reads in a path: a field of the
/// Python object it is in (`C field +104`, or `C data` for memory the
/// object points to but does not lay out), else part of a run of native
/// blocks (`C memory`).
pub(crate) fn c_step(label: &str, from_python: bool) -> String {
    if !from_python {
        return "C memory".to_string();
    }
    match label.strip_prefix("<+").and_then(|r| r.strip_suffix('>')) {
        Some(off) => format!("C field +{off}"),
        None => "C data".to_string(),
    }
}

/// The path from `keeper` to `v`, generalised: `[<key>] app.Session → .payload`.
/// Taken from `v`'s shortest path, from just after `keeper`; if that path
/// does not pass through `keeper` (or there is no keeper), the whole path
/// from its root.
fn through_path(a: &Analysis, keeper: Option<u32>, v: u32) -> Result<String> {
    let chain = a.bfs_chain(v);
    let start = keeper
        .and_then(|k| chain.iter().position(|&(x, _)| x == k))
        .map_or(0, |i| i + 1);
    let mut out = String::new();
    // Hops into native memory through raw words (`<+16>`, `<contents>`)
    // say nothing to a reader: a run of them is one `C memory` step, after
    // a `C field +N` when the run starts in a Python object's own struct.
    // 0: not in native memory, 1: after a `C field`, 2: after `C memory`.
    let mut in_c = 0u8;
    for (i, &(x, e)) in chain.iter().enumerate().skip(start) {
        let native = a
            .snap
            .object(x)
            .flags
            .contains(heapspy_snapshot::ObjectFlags::NATIVE);
        match a.edge_label(e) {
            Some(l) => {
                let label = generalised_label(a.snap, l)?;
                let raw = native && (label.starts_with("<+") || label == "<contents>");
                // The pointer's owner: the previous hop, or the keeper.
                let from = if i > 0 { Some(chain[i - 1].0) } else { keeper };
                let from_python = from.is_some_and(|f| {
                    !a.snap
                        .object(f)
                        .flags
                        .contains(heapspy_snapshot::ObjectFlags::NATIVE)
                });
                if raw && in_c == 2 {
                    continue;
                }
                if !out.is_empty() {
                    out.push_str(" → ");
                }
                if raw {
                    // Out of a Python object's own C struct: name the field
                    // by its offset; the object's type is the hop before.
                    let step = if in_c == 1 {
                        "C memory".to_string()
                    } else {
                        c_step(&label, from_python)
                    };
                    in_c = if step == "C memory" { 2 } else { 1 };
                    out.push_str(&step);
                    continue;
                }
                in_c = 0;
                out.push_str(match label.as_str() {
                    "<address>" => "its value as an address",
                    l => l,
                });
            }
            None => {
                if let Some((label, _)) = a.g.root_label(a.snap, e)? {
                    out.push_str(&label);
                }
                in_c = 0;
            }
        }
        // Name the type reached after each hop but the last (that is the
        // queried type itself); native blocks are named by `C memory`.
        if i + 1 < chain.len() && !native {
            let t = a.type_name(x);
            out.push(' ');
            out.push_str(t.strip_prefix("builtins.").unwrap_or(t));
        }
    }
    if out.is_empty() {
        out.push_str("(directly)");
    }
    // A module's namespace reads as code does: `sys.modules['m'] module →
    // .__dict__ dict → [<key>]` is `m.<global>`.
    if let Some(rest) = out.strip_prefix("sys.modules['") {
        const NS: &str = "'] module → .__dict__ dict → [<key>]";
        if let Some(i) = rest.find(NS) {
            out = format!("{}.<global>{}", &rest[..i], &rest[i + NS.len()..]);
        }
    }
    Ok(out)
}

/// Up to `max` distinct shortest paths to each target: the BFS path, then
/// the shortest path through each other direct referrer, by length. Paths
/// that would pass through the target twice are skipped. One scan of all
/// edges serves every target. `targets` must be distinct.
fn paths_to(a: &Analysis, targets: &[u32], max: usize) -> Result<Vec<Vec<RetainingPath>>> {
    let slot: HashMap<u32, usize> = targets
        .iter()
        .enumerate()
        .filter(|(_, &t)| a.reachable(t))
        .map(|(i, &t)| (t, i))
        .collect();
    let mut refs: Vec<Vec<(u32, u32)>> = vec![Vec::new(); targets.len()];
    if max > 0 && !slot.is_empty() {
        for u in 0..=a.g.n {
            if a.dist[u as usize] == NONE {
                continue;
            }
            for e in a.g.csr.range(u) {
                let t = a.g.csr.targets[e];
                if t == NONE || t == u {
                    continue;
                }
                if let Some(&i) = slot.get(&t) {
                    refs[i].push((u, e as u32));
                }
            }
        }
    }
    let mut out = Vec::with_capacity(targets.len());
    for (i, &t) in targets.iter().enumerate() {
        let mut cands = std::mem::take(&mut refs[i]);
        let via = a.via[t as usize];
        // The BFS path first: it starts at the best root kind (a module
        // before a frame, both before native memory). Then the others by
        // length, a pointer from native memory (a C global, a stack word)
        // or an external root after every Python referrer: such a word may
        // be a cache or a stale slot, and a direct root edge would otherwise
        // always be shortest.
        let late = |e: u32| {
            a.g.root_phases[crate::graph::EXTERNAL_PHASE - 1].contains(&e)
                || a.g.root_phases[crate::graph::EXTERNAL_PHASE].contains(&e)
        };
        cands.sort_unstable_by_key(|&(u, e)| (e != via, late(e), a.dist[u as usize], e));
        let mut paths: Vec<RetainingPath> = Vec::new();
        for (u, e) in cands {
            if paths.len() >= max {
                break;
            }
            if let Some(p) = a.path_via(u, e, t)? {
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
        out.push(paths);
    }
    Ok(out)
}

pub fn retaining_path(
    snap: &Snapshot,
    path: &str,
    target: &PathTarget,
    opts: &QueryOptions,
) -> Result<RetainingPathReport> {
    let a = Analysis::new(snap)?;
    let (query, nodes) = match target {
        PathTarget::Address(addr) => {
            let v = snap.find_object(*addr).ok_or_else(|| {
                Error::NotFound(format!(
                    "no object at {} in the snapshot",
                    format_address(*addr)
                ))
            })?;
            let q = PathQuery {
                by: PathQueryBy::Address,
                value: format_address(*addr),
            };
            (q, vec![v])
        }
        PathTarget::Type(name) => {
            let groups = matched_groups(&a, name)?;
            let mut inst = instances(&a, &groups);
            rank_by_retained(&a, &mut inst, opts.top);
            inst.truncate(opts.top);
            let q = PathQuery {
                by: PathQueryBy::Type,
                value: name.clone(),
            };
            (q, inst)
        }
    };

    let all_paths = paths_to(&a, &nodes, opts.max_paths)?;
    let mut notes = Vec::new();
    let mut targets = Vec::with_capacity(nodes.len());
    for (&v, paths) in nodes.iter().zip(all_paths) {
        let o = snap.object(v);
        let reachable = a.reachable(v);
        if !reachable {
            notes.push(notes::unreachable_target(&format_address(o.addr)));
        }
        let (type_location, type_location_reason) = a.type_location(v)?;
        targets.push(report::PathTarget {
            address: Address(o.addr),
            type_name: a.type_name(v).to_string(),
            shallow_bytes: o.shallow_size,
            retained_bytes: a.retained[v as usize],
            reachable,
            paths,
            type_location,
            type_location_reason,
        });
    }
    notes::header_notes(snap, &mut notes);
    Ok(RetainingPathReport {
        schema_version: SchemaVersion,
        kind: RetainingPathKind::Kind,
        snapshot: snapshot_summary(snap, path),
        query,
        targets,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(kind: &str, holder: Option<&str>, bytes: u64) -> KeptBy {
        KeptBy {
            kind: kind.into(),
            holder: holder.map(String::from),
            holder_name: None,
            holder_address: None,
            through: None,
            through_pct: None,
            instances: 1,
            bytes,
            sizes: vec![SizeGroup {
                size: bytes,
                blocks: 1,
                bytes,
            }],
        }
    }

    #[test]
    fn interpreter_and_small_holders_fold() {
        let out = fold_kept_by(vec![
            g("holder", Some("sys.modules['app'].__dict__['CACHE']"), 900),
            g("unreachable", None, 50),
            g("holder", Some("python3.13: _PyRuntime"), 30),
            g("holder", Some("interp sys['modules']"), 10),
            g("holder", Some("sys.modules['app'].__dict__['TINY']"), 5),
            g("other", None, 5),
        ]);
        let kinds: Vec<(&str, u64)> = out.iter().map(|k| (k.kind.as_str(), k.bytes)).collect();
        assert_eq!(
            kinds,
            [
                ("holder", 900),
                ("unreachable", 50),
                ("interpreter", 40),
                ("other", 10)
            ]
        );
    }
}
