//! `ssh-agent`: hold private keys and sign with them for SSH clients.

mod args;
mod server;
mod store;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use args::{Args, USAGE};
use server::Cleanup;
use sshutils_core::{keyfmt, time};
use store::Store;

fn main() -> ExitCode {
    let args: Args = sshutils_core::cli::parse(&USAGE);
    match run(args) {
        Ok(code) => code,
        Err((code, message)) => {
            if !message.is_empty() {
                eprintln!("{message}");
            }
            ExitCode::from(code)
        }
    }
}

type Failure = (u8, String);

fn usage_error(message: &str) -> Failure {
    let mut text = String::new();
    if !message.is_empty() {
        text.push_str(message);
        text.push('\n');
    }
    text.push_str("usage: ");
    text.push_str(USAGE.text);
    (1, text)
}

fn run(args: Args) -> Result<ExitCode, Failure> {
    if args.version {
        eprintln!("sshutils ssh-agent {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(name) = &args.fingerprint_hash
        && keyfmt::parse_hash_alg(name).is_none()
    {
        return Err((255, format!("Invalid hash algorithm \"{name}\"")));
    }
    let default_lifetime = match &args.lifetime {
        None => None,
        Some(text) => Some(
            time::parse_interval(text)
                .and_then(|seconds| u32::try_from(seconds).ok())
                .ok_or_else(|| usage_error("Invalid lifetime"))?,
        ),
    };
    if (args.csh && args.sh) || (args.foreground && args.debug) {
        return Err(usage_error(""));
    }

    let not_yet = |what: &str| Err((1, format!("ssh-agent: {what} is not implemented yet")));
    if args.kill {
        return not_yet("-k");
    }
    if args.cleanup_only > 0 {
        return not_yet("-u");
    }
    if !args.command.is_empty() {
        return not_yet("running a command");
    }
    if !(args.foreground || args.debug) {
        return not_yet("running in the background (use -D or -d)");
    }

    let (socket, directory) = socket_path(&args)?;
    let listener = server::bind(&socket).map_err(|e| {
        if let Some(directory) = &directory {
            let _ = std::fs::remove_dir(directory);
        }
        (
            1,
            format!(
                "unix_listener: cannot bind to path {}: {}",
                socket.display(),
                io_message(&e)
            ),
        )
    })?;
    let cleanup = Cleanup { socket, directory };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| (1, format!("starting runtime: {e}")))?;
    let result = runtime.block_on(server::run(
        listener,
        Store::new(default_lifetime),
        args.debug,
        || print_environment(&args, &cleanup.socket),
    ));
    cleanup.run();
    match result {
        Ok(signal) => {
            eprintln!("exiting on signal {signal}");
            Ok(ExitCode::from(2))
        }
        Err(e) => Err((1, format!("ssh-agent: {e}"))),
    }
}

/// The socket to bind: `-a`, or with `-T` a fresh private directory in
/// `$TMPDIR` holding `agent.<parent pid>`.
fn socket_path(args: &Args) -> Result<(PathBuf, Option<PathBuf>), Failure> {
    if let Some(path) = &args.bind_address {
        return Ok((path.clone(), None));
    }
    if !args.temporary {
        return Err((
            1,
            "ssh-agent: sockets in ~/.ssh/agent are not implemented yet (use -a or -T)".into(),
        ));
    }
    let base = std::env::var_os("TMPDIR")
        .filter(|dir| !dir.is_empty())
        .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
    let directory = make_private_directory(&base).map_err(|e| {
        (
            1,
            format!("mkdtemp: private socket dir: {}", io_message(&e)),
        )
    })?;
    // SAFETY: getppid has no preconditions.
    let parent = unsafe { libc::getppid() };
    let socket = directory.join(format!("agent.{parent}"));
    Ok((socket, Some(directory)))
}

/// Create a private (0700) directory in `base` named like OpenSSH's:
/// OpenSSH passes the template `ssh-XXXXXXXXXXXX` to `mkdtemp`, which (in
/// glibc) only replaces the last six `X`s, giving `ssh-XXXXXX` followed by
/// six random characters.
fn make_private_directory(base: &std::path::Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    use russh::keys::ssh_key::rand_core::Rng;

    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = russh::keys::key::safe_rng();
    loop {
        let suffix: String = (0..6)
            .map(|_| CHARS[(rng.next_u32() as usize) % CHARS.len()] as char)
            .collect();
        let path = base.join(format!("ssh-XXXXXX{suffix}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Print the shell commands that point clients at this agent.
fn print_environment(args: &Args, socket: &std::path::Path) {
    let csh = args.csh
        || (!args.sh
            && std::env::var_os("SHELL")
                .is_some_and(|shell| shell.to_string_lossy().ends_with("csh")));
    let socket = socket.display();
    let pid = std::process::id();
    let mut out = std::io::stdout().lock();
    if csh {
        let _ = writeln!(out, "setenv SSH_AUTH_SOCK {socket};");
    } else {
        let _ = writeln!(out, "SSH_AUTH_SOCK={socket}; export SSH_AUTH_SOCK;");
    }
    let _ = writeln!(out, "echo Agent pid {pid};");
    let _ = out.flush();
}

fn io_message(err: &std::io::Error) -> String {
    let message = err.to_string();
    match message.find(" (os error ") {
        Some(i) => message[..i].to_string(),
        None => message,
    }
}
