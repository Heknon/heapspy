//! `query --type` and `query --retaining-path`.

use std::collections::HashMap;

use heapspy_snapshot::{EdgeLabel, Snapshot};

use crate::analysis::Analysis;
use crate::dominators::NONE;
use crate::report::{
    self, Address, Holder, Instance, PathQuery, PathQueryBy, RetainingPath, RetainingPathKind,
    RetainingPathReport, SchemaVersion, TypeLocation, TypeQueryKind, TypeQueryReport,
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

pub fn query_type(
    snap: &Snapshot,
    path: &str,
    type_name: &str,
    opts: &QueryOptions,
) -> Result<TypeQueryReport> {
    let a = Analysis::new(snap)?;
    let groups = matched_groups(&a, type_name)?;
    let mut inst = instances(&a, &groups);
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

    let total = inst.len() as u64;
    rank_by_retained(&a, &mut inst, opts.top);
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
    Ok(TypeQueryReport {
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
        notes,
    })
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
        cands.sort_unstable_by_key(|&(u, e)| (a.dist[u as usize], e != via, e));
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
