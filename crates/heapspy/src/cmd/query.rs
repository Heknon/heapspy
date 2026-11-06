use heapspy_analyzer::report::Address;
use heapspy_analyzer::{render, PathTarget, QueryOptions};

use super::{allocations, display_path, open_snapshot};
use crate::cli::QueryArgs;
use crate::output::{print_json, InvalidArgument};

pub fn run(args: QueryArgs) -> anyhow::Result<()> {
    // Validate arguments before touching the file.
    let addr = match &args.retaining_path {
        Some(s) => Some(s.parse::<Address>().map_err(InvalidArgument)?),
        None => None,
    };
    let snap = open_snapshot(&args.snapshot)?;
    let alloc = allocations::open(args.allocations.as_deref(), &snap)?;
    let path = display_path(&args.snapshot);
    let opts = QueryOptions {
        top: args.top,
        max_paths: args.max_paths,
    };

    let target = match (args.type_name, addr, args.retaining_path_type) {
        (Some(t), None, None) => {
            let report = match &alloc {
                None => heapspy_analyzer::query_type(&snap, &path, &t, &opts)?,
                Some(a) => heapspy_analyzer::allocations::query_type_with_allocations(
                    &snap, &path, &t, &opts, &a.profile,
                )?,
            };
            return if args.json {
                print_json(&report)
            } else {
                print!("{}", render::type_query(&report)?);
                Ok(())
            };
        }
        (None, Some(a), None) => PathTarget::Address(a.0),
        (None, None, Some(t)) => PathTarget::Type(t),
        _ => unreachable!("clap enforces exactly one query mode"),
    };
    let mut report = heapspy_analyzer::retaining_path(&snap, &path, &target, &opts)?;
    if let Some(a) = &alloc {
        allocations::unused(a, &mut report.notes, "--retaining-path");
    }
    if args.json {
        print_json(&report)
    } else {
        print!("{}", render::retaining_path(&report)?);
        Ok(())
    }
}
