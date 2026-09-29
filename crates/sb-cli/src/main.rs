//! `shieldbk`: the visible face of `ShieldBackups`.
//!
//! This file does nothing but start up. Parsing the arguments lives in [`cli`],
//! deciding what runs in [`commands`], and how the result is told in
//! [`output`]. What is left here is only the order in which they are chained
//! and the single decision that fits in none of the three: **which exit code
//! the process ends with**.
//!
//! That code is what makes the tool automatable. A `cron` that only tells
//! "zero" from "non-zero" ends up sending the same alert when a comma is
//! missing in the TOML as when the database does not answer, so
//! [`error::CliError`] separates the three cases and this function translates
//! them.

mod artifacts;
mod cli;
mod commands;
mod context;
mod error;
mod logging;
mod output;
mod paths;
mod plugins;
mod retention;

use std::process::ExitCode;

use clap::Parser as _;

use crate::cli::Cli;
use crate::output::Output;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Tracing is switched on before anything else: configuration loading
    // failures also deserve context when somebody asks for `-v`.
    logging::init(cli.verbose);

    let output = Output::new(cli.format);

    // The runtime is built here and not with `#[tokio::main]` so that the exit
    // code remains the last thing this file decides: a macro wrapping `main`
    // would force returning the error through `Termination` and giving up on
    // telling its three classes apart.
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(source) => {
            let error =
                error::CliError::operation(format!("could not start the async runtime: {source}"));
            output.failure(&error);
            return ExitCode::from(u8::try_from(error.code()).unwrap_or(1));
        }
    };

    match runtime.block_on(commands::run(&cli)) {
        // A report can carry a failure inside: that is what tells "I could not
        // do it" from "I did it and this is what I found".
        Ok(report) => {
            output.emit(&report);
            ExitCode::from(u8::try_from(report.code()).unwrap_or(1))
        }
        Err(error) => {
            output.failure(&error);
            ExitCode::from(u8::try_from(error.code()).unwrap_or(1))
        }
    }
}
