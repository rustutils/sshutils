mod args;
mod common;
mod error;
mod fingerprint;
mod generate;
mod public;

use std::process::ExitCode;

use args::{Args, Mode, USAGE};
use error::Error;

fn main() -> ExitCode {
    let args: Args = sshutils_core::cli::parse(&USAGE);
    let result = match args.mode() {
        Mode::Generate => generate::run(&args),
        Mode::Fingerprint => fingerprint::run(&args),
        Mode::PrintPublic => public::run(&args),
        Mode::Unimplemented(letter) => {
            Err(Error::fatal(format!("-{letter} is not implemented yet")))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => err.report(),
    }
}
