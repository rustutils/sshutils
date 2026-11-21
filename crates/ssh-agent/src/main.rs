//! `ssh-agent`: hold private keys and sign with them for SSH clients.

mod args;
mod daemon;
mod server;
mod socket;
mod store;

use std::ffi::OsString;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use args::{Args, USAGE};
use daemon::Forked;
use server::{Options, Stop};
use socket::Socket;
use sshutils_core::{keyfmt, paths, time};
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

fn fatal(message: impl std::fmt::Display) -> Failure {
    (255, message.to_string())
}

/// Shell syntax for printed commands.
#[derive(Clone, Copy)]
enum Shell {
    Bourne,
    C,
}

fn run(args: Args) -> Result<ExitCode, Failure> {
    if args.version {
        eprintln!("sshutils ssh-agent {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(name) = &args.fingerprint_hash
        && keyfmt::parse_hash_alg(name).is_none()
    {
        return Err(fatal(format!("Invalid hash algorithm \"{name}\"")));
    }
    let default_lifetime = match &args.lifetime {
        None => None,
        Some(text) => Some(
            time::parse_interval(text)
                .and_then(|seconds| u32::try_from(seconds).ok())
                .ok_or_else(|| usage_error("Invalid lifetime"))?,
        ),
    };
    let foreground = args.foreground || args.debug;
    let has_command = !args.command.is_empty();
    if (args.csh && args.sh)
        || (args.foreground && args.debug)
        || (has_command && (args.csh || args.sh || args.kill || foreground))
    {
        return Err(usage_error(""));
    }
    let shell = if args.csh
        || (!args.sh
            && std::env::var_os("SHELL").is_some_and(|s| s.to_string_lossy().ends_with("csh")))
    {
        Shell::C
    } else {
        Shell::Bourne
    };

    if args.kill {
        return kill_agent(shell);
    }
    let home = || {
        paths::current_user()
            .map(|user| user.home)
            .ok_or_else(|| fatal("Couldn't determine home directory"))
    };
    let host_prefix = || format!("s.{}.", socket::hostname_hash(&paths::hostname()));
    if args.cleanup_only > 0 {
        let prefix = (args.cleanup_only < 2).then(host_prefix);
        socket::cleanup_stale(
            &home()?.join(socket::USER_SOCKET_DIR),
            prefix.as_deref(),
            SystemTime::now(),
        );
        println!(
            "Deleted stale agent sockets in ~/{}",
            socket::USER_SOCKET_DIR
        );
        return Ok(ExitCode::SUCCESS);
    }

    // The listening socket: handed over by systemd, or bound here.
    let activated = if args.bind_address.is_none() && !has_command && foreground {
        activated_listener()?
    } else {
        None
    };
    let socket = match activated {
        Some(_) => None,
        None => Some(if let Some(path) = &args.bind_address {
            socket::bind_explicit(path).map_err(|e| {
                (
                    1,
                    format!(
                        "unix_listener: cannot bind to path {}: {}",
                        path.display(),
                        io_message(&e)
                    ),
                )
            })?
        } else if args.temporary {
            let tmpdir = std::env::var_os("TMPDIR")
                .filter(|dir| !dir.is_empty())
                .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
            socket::bind_temporary(&tmpdir)
                .map_err(|e| (1, format!("unix_listener: {}", io_message(&e))))?
        } else {
            let dir = home()?.join(socket::USER_SOCKET_DIR);
            let prefix = host_prefix();
            if !args.no_cleanup {
                socket::cleanup_stale(&dir, Some(&prefix), SystemTime::now());
            }
            let hash = prefix.trim_start_matches("s.").trim_end_matches('.');
            socket::bind_user(&dir, hash).map_err(|e| {
                fatal(format!(
                    "ssh-agent: Couldn't prepare agent socket: {}",
                    io_message(&e)
                ))
            })?
        }),
    };
    let listener = match (activated, &socket) {
        (Some(listener), _) => listener,
        (None, Some(socket)) => socket
            .listener
            .try_clone()
            .map_err(|e| (1, format!("ssh-agent: {}", io_message(&e))))?,
        (None, None) => unreachable!("either activated or bound"),
    };
    let fingerprint_hash = args
        .fingerprint_hash
        .as_deref()
        .and_then(keyfmt::parse_hash_alg)
        .unwrap_or(keyfmt::FingerprintHash::Sha256);
    let store = Store::new(default_lifetime, fingerprint_hash);

    if foreground {
        let options = Options {
            debug: args.debug,
            handle_interrupt: true,
            parent: None,
        };
        let pid = std::process::id();
        return serve(listener, store, options, socket.as_ref(), || {
            if let Some(socket) = &socket {
                print_environment(shell, &socket.path, None, pid);
            }
        });
    }

    // The parent prints the environment or runs the command; the child
    // becomes the agent.
    let socket = socket.expect("background agents bind their own socket");
    let parent = std::process::id();
    match daemon::fork().map_err(|e| (1, format!("fork: {}", io_message(&e))))? {
        Forked::Parent { child } => {
            drop(listener);
            if has_command {
                let e = daemon::exec_command(&args.command, &socket.path, child);
                return Err((
                    1,
                    format!("{}: {}", display(&args.command[0]), io_message(&e)),
                ));
            }
            print_environment(shell, &socket.path, Some(child), child);
            Ok(ExitCode::SUCCESS)
        }
        Forked::Child => {
            if let Err(e) = daemon::detach() {
                socket.cleanup();
                return Err((1, format!("ssh-agent: {}", io_message(&e))));
            }
            let options = Options {
                debug: false,
                handle_interrupt: false,
                parent: has_command.then_some(parent),
            };
            serve(listener, store, options, Some(&socket), || {})
        }
    }
}

/// Run the agent until it stops, then clean up.
fn serve(
    listener: UnixListener,
    store: Store,
    options: Options,
    socket: Option<&Socket>,
    ready: impl FnOnce(),
) -> Result<ExitCode, Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| (1, format!("starting runtime: {e}")))?;
    let result = runtime.block_on(server::run(listener, store, options, ready));
    if let Some(socket) = socket {
        socket.cleanup();
    }
    match result {
        Ok(Stop::Signal(signal)) => {
            eprintln!("exiting on signal {signal}");
            // A socket-activated agent stopped by its service manager
            // exits successfully.
            let code = if signal == libc::SIGTERM && socket.is_none() {
                0
            } else {
                2
            };
            Ok(ExitCode::from(code))
        }
        Ok(Stop::ParentExited) => Ok(ExitCode::from(2)),
        Err(e) => Err((1, format!("ssh-agent: {e}"))),
    }
}

/// The listening socket passed by systemd socket activation, if any
/// (`LISTEN_PID` is us and `LISTEN_FDS=1`: the socket is fd 3).
fn activated_listener() -> Result<Option<UnixListener>, Failure> {
    let (Some(pid), Some(fds)) = (
        std::env::var("LISTEN_PID").ok(),
        std::env::var("LISTEN_FDS").ok(),
    ) else {
        return Ok(None);
    };
    if fds != "1" {
        return Err(fatal(format!(
            "unexpected LISTEN_FDS contents (want: \"1\" got\"{fds}\""
        )));
    }
    // SAFETY: fcntl only queries the descriptor's flags.
    if unsafe { libc::fcntl(3, libc::F_GETFL) } == -1 {
        return Err(fatal("LISTEN_FDS set but fd 3 unavailable"));
    }
    let pid: u32 = pid
        .parse()
        .map_err(|e| fatal(format!("invalid LISTEN_PID: {e}")))?;
    if pid != std::process::id() {
        return Err(fatal(format!(
            "bad LISTEN_PID: {pid} vs pid {}",
            std::process::id()
        )));
    }
    // SAFETY: systemd handed us fd 3 as our listening socket and nothing
    // else in this process owns it.
    Ok(Some(unsafe { UnixListener::from_raw_fd(3) }))
}

/// `-k`: stop the agent named by `SSH_AGENT_PID`.
fn kill_agent(shell: Shell) -> Result<ExitCode, Failure> {
    let Some(text) = std::env::var_os("SSH_AGENT_PID") else {
        return Err((1, "SSH_AGENT_PID not set, cannot kill agent".into()));
    };
    let text = text.to_string_lossy();
    let pid = match text.parse::<libc::pid_t>() {
        Ok(pid) if pid >= 2 => pid,
        Ok(_) => {
            return Err((
                1,
                format!("SSH_AGENT_PID=\"{text}\", which is not a good PID: too small"),
            ));
        }
        Err(_) => {
            return Err((
                1,
                format!("SSH_AGENT_PID=\"{text}\", which is not a good PID: invalid"),
            ));
        }
    };
    // SAFETY: kill(2) with a validated pid.
    if unsafe { libc::kill(pid, libc::SIGTERM) } == -1 {
        let e = std::io::Error::last_os_error();
        return Err((1, format!("kill: {}", io_message(&e))));
    }
    let unset = |name: &str| match shell {
        Shell::Bourne => println!("unset {name};"),
        Shell::C => println!("unsetenv {name};"),
    };
    unset("SSH_AUTH_SOCK");
    unset("SSH_AGENT_PID");
    println!("echo Agent pid {pid} killed;");
    Ok(ExitCode::SUCCESS)
}

/// Print the shell commands that point clients at this agent.
fn print_environment(shell: Shell, socket: &Path, agent_pid: Option<u32>, echo_pid: u32) {
    let mut out = std::io::stdout().lock();
    let mut set = |name: &str, value: &str| match shell {
        Shell::Bourne => writeln!(out, "{name}={value}; export {name};"),
        Shell::C => writeln!(out, "setenv {name} {value};"),
    };
    let _ = set("SSH_AUTH_SOCK", &shell_quote(&socket.display().to_string()));
    if let Some(pid) = agent_pid {
        let _ = set("SSH_AGENT_PID", &pid.to_string());
    }
    let _ = writeln!(out, "echo Agent pid {echo_pid};");
    let _ = out.flush();
}

/// Quote a value for the shell like OpenSSH's `argv_assemble`: backslashes
/// and quotes are escaped with a backslash, and values containing blanks
/// are wrapped in double quotes.
fn shell_quote(value: &str) -> String {
    let mut quoted = String::new();
    for c in value.chars() {
        if matches!(c, '\\' | '\'' | '"') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    if value.contains([' ', '\t']) {
        format!("\"{quoted}\"")
    } else {
        quoted
    }
}

fn display(value: &OsString) -> String {
    value.to_string_lossy().into_owned()
}

fn io_message(err: &std::io::Error) -> String {
    let message = err.to_string();
    match message.find(" (os error ") {
        Some(i) => message[..i].to_string(),
        None => message,
    }
}

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn quotes_like_openssh() {
        assert_eq!(shell_quote("/tmp/ssh-x/agent.1"), "/tmp/ssh-x/agent.1");
        assert_eq!(shell_quote("/a b/s"), "\"/a b/s\"");
        assert_eq!(shell_quote("it's"), "it\\'s");
        assert_eq!(shell_quote("a\\b\"c"), "a\\\\b\\\"c");
        assert_eq!(shell_quote("$HOME;x"), "$HOME;x");
    }
}
