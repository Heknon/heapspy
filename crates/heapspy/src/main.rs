use std::process::ExitCode;

use clap::Parser;

mod cli;
mod cmd;
mod output;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    let json = cli.command.json();
    match cmd::run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => output::report_error(&err, json),
    }
}
