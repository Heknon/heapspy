//! `query --locate NAME`: where the type, function or module named
//! `module.qualname` is defined.
//!
//! This needs no dominator tree: one pass over the objects finds modules and
//! functions, and the type table finds types.

use std::collections::{HashMap, HashSet};

use heapspy_snapshot::{EdgeLabel, ObjectIndex, Snapshot};

use crate::analysis::TypeTable;
use crate::report::{Address, LocateKind, LocateMatch, LocateReport, SchemaVersion};
use crate::source::{Kind, Locator};
use crate::{notes, snapshot_summary, Error, QueryOptions, Result};

/// Target of the first `.name` edge of `v`.
fn attr_target(snap: &Snapshot, v: ObjectIndex, name: &str) -> Result<Option<u64>> {
    for e in snap.edges(v) {
        if let EdgeLabel::Attr(s) = e.label {
            if snap.string(s)? == name {
                return Ok(Some(e.target));
            }
        }
    }
    Ok(None)
}

pub fn locate(
    snap: &Snapshot,
    path: &str,
    name: &str,
    opts: &QueryOptions,
) -> Result<LocateReport> {
    let types = TypeTable::new(snap)?;
    let loc = Locator::new(snap)?;
    let mut matches = Vec::new();
    let one = |kind: &str, module: &str, qualname: &str, v: ObjectIndex| -> Result<LocateMatch> {
        let (source_loc, source_loc_reason) = loc.object(v)?.split();
        Ok(LocateMatch {
            kind: kind.to_string(),
            name: name.to_string(),
            module: module.to_string(),
            qualname: qualname.to_string(),
            address: Address(snap.object(v).addr),
            source_loc,
            source_loc_reason,
        })
    };

    // Types: every type object with that display name.
    if let Some(g) = types.find(name) {
        for t in types.type_ids(g) {
            let e = snap.type_entry(t).expect("type id in range");
            let Some(v) = (e.addr != 0).then(|| snap.find_object(e.addr)).flatten() else {
                continue;
            };
            matches.push(one(
                "type",
                snap.string(e.module)?,
                snap.string(e.qualname)?,
                v,
            )?);
        }
    }

    // Modules by name, and module dict address -> module name for functions.
    let mut module_of_dict: HashMap<u64, &str> = HashMap::new();
    let mut modules = Vec::new();
    let mut functions = Vec::new();
    for v in 0..snap.object_count() as ObjectIndex {
        match loc.kind(v) {
            Kind::Module => {
                let Some(m) = snap.opt_string(snap.extras(v).and_then(|x| x.qualname))? else {
                    continue;
                };
                if let Some(d) = attr_target(snap, v, "__dict__")? {
                    module_of_dict.insert(d, m);
                }
                if m == name {
                    modules.push(v);
                }
            }
            Kind::Function => functions.push(v),
            _ => {}
        }
    }

    // Functions: `__module__` is the name of the module whose dict is the
    // function's `__globals__`. Closures created many times share a
    // location and are listed once. A decorator wrapper made with
    // `functools.wraps` has the wrapped function's `__qualname__` but its own
    // code; when some match also has that name as its code object's
    // `co_qualname`, only those are listed.
    let mut seen = HashSet::new();
    let mut found: Vec<(LocateMatch, bool)> = Vec::new();
    for f in functions {
        let Some(q) = snap.opt_string(snap.extras(f).and_then(|x| x.qualname))? else {
            continue;
        };
        if !name.ends_with(q) {
            continue;
        }
        let Some(m) = attr_target(snap, f, "__globals__")?.and_then(|g| module_of_dict.get(&g))
        else {
            continue;
        };
        if name.strip_prefix(m).and_then(|r| r.strip_prefix('.')) != Some(q) {
            continue;
        }
        let item = one("function", m, q, f)?;
        if seen.insert(item.source_loc.clone()) {
            let code_q = match attr_target(snap, f, "__code__")?.and_then(|c| snap.find_object(c)) {
                Some(c) => snap.opt_string(snap.extras(c).and_then(|x| x.qualname))?,
                None => None,
            };
            found.push((item, code_q == Some(q)));
        }
    }
    let own_code = found.iter().any(|(_, own)| *own);
    matches.extend(
        found
            .into_iter()
            .filter(|(_, own)| *own || !own_code)
            .map(|(m, _)| m),
    );

    for v in modules {
        matches.push(one("module", name, "", v)?);
    }

    if matches.is_empty() {
        return Err(Error::NotFound(format!(
            "no type, function or module named {name:?} in the snapshot"
        )));
    }
    matches.truncate(opts.top.max(1));
    let mut notes = Vec::new();
    notes::header_notes(snap, &mut notes);
    Ok(LocateReport {
        schema_version: SchemaVersion,
        kind: LocateKind::Kind,
        snapshot: snapshot_summary(snap, path),
        query: name.to_string(),
        matches,
        notes,
    })
}
