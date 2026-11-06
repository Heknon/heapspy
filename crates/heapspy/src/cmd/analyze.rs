use heapspy_analyzer::{render, AnalyzeOptions};

use super::{display_path, open_snapshot};
use crate::cli::AnalyzeArgs;
use crate::output::print_json;

pub fn run(args: AnalyzeArgs) -> anyhow::Result<()> {
    let snap = open_snapshot(&args.snapshot)?;
    let opts = AnalyzeOptions { top: args.top };
    let report = heapspy_analyzer::analyze(&snap, &display_path(&args.snapshot), &opts)?;
    if args.json {
        print_json(&report)
    } else {
        print!("{}", render::analyze(&report)?);
        Ok(())
    }
}
