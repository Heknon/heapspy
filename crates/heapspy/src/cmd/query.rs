use heapspy_analyzer::report::Address;
use heapspy_analyzer::{render, PathTarget, QueryOptions};

use super::{display_path, open_snapshot};
use crate::cli::QueryArgs;
use crate::output::{print_json, InvalidArgument};

pub fn run(args: QueryArgs) -> anyhow::Result<()> {
    // Validate arguments before touching the file.
    let addr = match &args.retaining_path {
        Some(s) => Some(s.parse::<Address>().map_err(InvalidArgument)?),
        None => None,
    };
    let snap = open_snapshot(&args.snapshot)?;
    let path = display_path(&args.snapshot);
    let opts = QueryOptions::default();

    match (args.type_name, addr) {
        (Some(t), None) => {
            let report = heapspy_analyzer::query_type(&snap, &path, &t, &opts)?;
            if args.json {
                print_json(&report)
            } else {
                print!("{}", render::type_query(&report)?);
                Ok(())
            }
        }
        (None, Some(a)) => {
            let report =
                heapspy_analyzer::retaining_path(&snap, &path, &PathTarget::Address(a.0), &opts)?;
            if args.json {
                print_json(&report)
            } else {
                print!("{}", render::retaining_path(&report)?);
                Ok(())
            }
        }
        _ => unreachable!("clap enforces exactly one of --type / --retaining-path"),
    }
}
