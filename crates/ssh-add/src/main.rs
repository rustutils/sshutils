//! `ssh-add`: manage the identities held by an SSH agent.

mod args;
mod error;
mod identities;
mod keys;

use std::process::ExitCode;

use args::{Args, USAGE};
use error::{Error, Result};
use russh::keys::agent::client::AgentClient;
use sshutils_core::keyfmt::{self, FingerprintHash};
use sshutils_core::time;
use tokio::net::UnixStream;

/// Connection to the agent.
pub type Client = AgentClient<UnixStream>;

/// Validated command-line settings shared by the operations.
pub struct Settings {
    pub args: Args,
    pub hash: FingerprintHash,
    /// `-t`, in seconds; 0 means no lifetime.
    pub lifetime: u32,
}

fn main() -> ExitCode {
    let args: Args = sshutils_core::cli::parse(&USAGE);
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => err.report(),
    }
}

fn run(args: Args) -> Result<()> {
    let settings = validate(args)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|e| Error::fatal(format!("starting runtime: {e}")))?;
    runtime.block_on(async {
        let mut client = connect().await?;
        dispatch(&settings, &mut client).await
    })
}

/// Check options and their combinations before contacting the agent, in
/// the same order as OpenSSH.
fn validate(args: Args) -> Result<Settings> {
    let lifetime = match &args.lifetime {
        None => 0,
        Some(text) => time::parse_interval(text)
            .and_then(|seconds| u32::try_from(seconds).ok())
            .ok_or_else(|| Error::message(1, "Invalid lifetime"))?,
    };
    let hash = match &args.fingerprint_hash {
        None => FingerprintHash::Sha256,
        Some(name) => keyfmt::parse_hash_alg(name)
            .ok_or_else(|| Error::fatal(format!("Invalid hash algorithm \"{name}\"")))?,
    };
    if args.list_fingerprints + args.list_keys > 1 {
        let flag = if args.list_fingerprints > 0 { 'l' } else { 'L' };
        return Err(Error::fatal(format!("-{flag} flag already specified")));
    }
    if args.lock + args.unlock > 1 {
        let flag = if args.lock > 0 { 'x' } else { 'X' };
        return Err(Error::fatal(format!("-{flag} flag already specified")));
    }
    let actions = [
        args.lock + args.unlock > 0,
        args.list_fingerprints + args.list_keys > 0,
        args.delete_all,
        args.query,
    ];
    if actions.iter().filter(|&&a| a).count() > 1 {
        return Err(Error::fatal("Invalid combination of actions"));
    }
    let unsupported = [
        (
            args.add_pkcs11.is_some() || args.remove_pkcs11.is_some(),
            "PKCS#11 (-s, -e)",
        ),
        (
            args.resident || args.sk_provider.is_some(),
            "FIDO security keys (-K, -S)",
        ),
        (
            !args.destinations.is_empty() || !args.hostkey_files.is_empty(),
            "destination constraints (-h, -H)",
        ),
    ];
    if let Some((_, what)) = unsupported.iter().find(|(used, _)| *used) {
        return Err(Error::message(1, format!("{what} not supported yet")));
    }
    Ok(Settings {
        args,
        hash,
        lifetime,
    })
}

/// Connect to the agent named by `SSH_AUTH_SOCK`.
async fn connect() -> Result<Client> {
    let socket = std::env::var_os("SSH_AUTH_SOCK")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::message(
                2,
                "Could not open a connection to your authentication agent.",
            )
        })?;
    let stream = UnixStream::connect(&socket).await.map_err(|e| {
        Error::message(
            2,
            format!("Error connecting to agent: {}", error::io_message(&e)),
        )
    })?;
    Ok(AgentClient::connect(stream))
}

async fn dispatch(settings: &Settings, client: &mut Client) -> Result<()> {
    let args = &settings.args;
    if args.lock + args.unlock > 0 {
        identities::lock(client, args.lock > 0).await
    } else if args.list_fingerprints + args.list_keys > 0 {
        identities::list(client, args.list_fingerprints > 0, settings.hash).await
    } else if args.query {
        identities::query(client).await
    } else if args.delete_all {
        identities::delete_all(client, args.quiet).await
    } else if args.test {
        keys::test(client, &args.files).await
    } else {
        let files = if args.files.is_empty() {
            keys::default_identities()
        } else {
            args.files.clone()
        };
        if files.is_empty() {
            return Err(Error::Exit(1));
        }
        if args.delete {
            keys::delete(client, settings, &files).await
        } else {
            keys::add(client, settings, &files).await
        }
    }
}
