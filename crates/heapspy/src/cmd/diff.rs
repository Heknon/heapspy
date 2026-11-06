use heapspy_analyzer::{render, DiffOptions};

use super::{display_path, open_snapshot};
use crate::cli::DiffArgs;
use crate::output::print_json;

pub fn run(args: DiffArgs) -> anyhow::Result<()> {
    let before = open_snapshot(&args.before)?;
    let after = open_snapshot(&args.after)?;
    let report = heapspy_analyzer::diff(
        &before,
        &display_path(&args.before),
        &after,
        &display_path(&args.after),
        &DiffOptions { top: args.top },
    )?;
    if args.json {
        print_json(&report)
    } else {
        print!("{}", render::diff(&report)?);
        Ok(())
    }
}
