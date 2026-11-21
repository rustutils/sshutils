mod args;
mod comment;
mod common;
mod error;
mod fingerprint;
mod generate;
mod known_hosts;
mod passphrase;
mod public;
mod save;

use std::process::ExitCode;

use args::{Args, Mode, USAGE};
use error::Error;

fn main() -> ExitCode {
    let args: Args = sshutils_core::cli::parse(&USAGE);
    let result = match args.mode() {
        Mode::Generate => generate::run(&args),
        Mode::Fingerprint => fingerprint::run(&args),
        Mode::PrintPublic => public::run(&args),
        Mode::ChangePassphrase => passphrase::run(&args),
        Mode::ChangeComment => comment::run(&args),
        Mode::FindHost => known_hosts::find(&args, args.find_host.as_deref().unwrap_or_default()),
        Mode::RemoveHost => {
            known_hosts::remove(&args, args.remove_host.as_deref().unwrap_or_default())
        }
        Mode::HashKnownHosts => known_hosts::hash(&args),
        Mode::Unimplemented(letter) => {
            Err(Error::fatal(format!("-{letter} is not implemented yet")))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => err.report(),
    }
}
