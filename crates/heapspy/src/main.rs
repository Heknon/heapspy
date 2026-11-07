use std::process::ExitCode;

use clap::Parser;

mod cli;
mod cmd;
mod output;

fn main() -> ExitCode {
    // `heapspy __guardian`, started by the Windows recorder: not a command.
    if let Some(code) = heapspy_record::windows::guardian_main_if_requested() {
        return ExitCode::from(code.clamp(0, 255) as u8);
    }
    let cli = cli::Cli::parse();
    let json = cli.command.json();
    match cmd::run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => output::report_error(&err, json),
    }
}
