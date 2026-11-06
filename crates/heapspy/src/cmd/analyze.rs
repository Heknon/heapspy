use heapspy_analyzer::{render, AnalyzeOptions};

use super::{allocations, display_path, open_snapshot};
use crate::cli::AnalyzeArgs;
use crate::output::print_json;

pub fn run(args: AnalyzeArgs) -> anyhow::Result<()> {
    let snap = open_snapshot(&args.snapshot)?;
    let alloc = allocations::open(args.allocations.as_deref(), &snap)?;
    let opts = AnalyzeOptions { top: args.top };
    let path = display_path(&args.snapshot);
    let report = match &alloc {
        None => heapspy_analyzer::analyze(&snap, &path, &opts)?,
        Some(a) => allocations::joined_or_plain(
            a,
            heapspy_analyzer::allocations::analyze_with_allocations(
                &snap, &path, &opts, &a.profile,
            ),
            || heapspy_analyzer::analyze(&snap, &path, &opts),
            |r| &mut r.notes,
        )?,
    };
    if args.json {
        print_json(&report)
    } else {
        print!("{}", render::analyze(&report)?);
        Ok(())
    }
}
