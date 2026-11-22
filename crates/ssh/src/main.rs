//! `ssh`: the OpenSSH remote login client.
//!
//! So far this reads the command line and the configuration, `-G` prints
//! the result and `-Q` lists the supported algorithms. Connecting comes
//! next.

mod args;
mod query;

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;

use args::{Arguments, Item, USAGE, UsageError};
use sshutils_config::algorithms::{self, Kind};
use sshutils_config::expand::expand_tilde;
use sshutils_config::forward::{
    Endpoint, Uri, parse_forward, parse_ssh_uri, valid_hostname, valid_user,
};
use sshutils_config::options::set_once;
use sshutils_config::values::*;
use sshutils_config::{Context, Options, Reader, Request};

/// `PORT_STREAMLOCAL`: the port of a forward to a Unix socket.
const PORT_STREAMLOCAL: i32 = -2;

/// Why `ssh` stopped.
#[derive(Debug)]
enum Exit {
    /// A command-line error: the message (if any) and the usage text,
    /// status 255.
    Usage(String),
    /// Print the message (if not empty) and exit with the status.
    Message(u8, String),
    /// Print the text on stdout and exit successfully (`-Q`).
    Print(String),
}

impl Exit {
    /// OpenSSH's `fatal()`: status 255.
    fn fatal(message: impl Into<String>) -> Self {
        Exit::Message(255, message.into())
    }
}

impl From<UsageError> for Exit {
    fn from(err: UsageError) -> Self {
        Exit::Usage(err.0)
    }
}

impl From<sshutils_config::Fatal> for Exit {
    fn from(err: sshutils_config::Fatal) -> Self {
        Exit::fatal(err.0)
    }
}

/// Where log messages go: stderr, a file (`-E`) or syslog (`-y`).
enum Log {
    Stderr,
    File(std::fs::File),
    Syslog,
}

impl Log {
    fn error(&mut self, message: &str) {
        match self {
            Log::Stderr => eprintln!("{message}"),
            Log::File(file) => {
                let _ = writeln!(file, "{message}");
            }
            Log::Syslog => {
                if let Ok(message) = std::ffi::CString::new(message) {
                    // SAFETY: both strings are NUL-terminated, and the format
                    // consumes exactly one string argument.
                    unsafe { libc::syslog(libc::LOG_ERR, c"%s".as_ptr(), message.as_ptr()) };
                }
            }
        }
    }
}

/// What the command line asked for besides configuration options.
#[derive(Default)]
struct Cli {
    host: Option<String>,
    user_on_command_line: bool,
    config_file: Option<String>,
    debug_flag: u8,
    config_test: bool,
    dump_pubkeys: bool,
    use_syslog: bool,
    log_file: Option<String>,
    mux_command: Option<String>,
}

fn main() -> ExitCode {
    let mut log = Log::Stderr;
    match run(&mut log) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Exit::Usage(message)) => {
            if !message.is_empty() {
                eprintln!("ssh: {message}");
            }
            eprintln!("{USAGE}");
            ExitCode::from(255)
        }
        Err(Exit::Print(text)) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(Exit::Message(status, message)) => {
            if !message.is_empty() {
                log.error(&message);
            }
            ExitCode::from(status)
        }
    }
}

fn run(log: &mut Log) -> Result<(), Exit> {
    let mut argv = std::env::args_os();
    let argv0 = argv
        .next()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ssh".into());
    let mut arguments = Arguments::new(argv.collect::<Vec<OsString>>());

    let mut options = Options::default();
    let mut cli = Cli::default();
    while let Some(item) = arguments.next_item()? {
        match item {
            Item::Destination(destination) => {
                set_destination(&mut options, &mut cli, &destination)?
            }
            Item::Option(letter, value) => {
                apply_option(&mut options, &mut cli, letter, value.as_deref())?;
            }
        }
    }
    let Some(host) = cli.host.clone() else {
        return Err(Exit::Usage(String::new()));
    };

    if let Some(user) = &options.user
        && !valid_user(user)
    {
        return Err(Exit::fatal("remote username contains invalid characters"));
    }
    if !valid_hostname(&host) {
        return Err(Exit::fatal("hostname contains invalid characters"));
    }
    let command = arguments.command().join(" ");
    if command.is_empty() && options.session_type == Some(SESSION_TYPE_SUBSYSTEM) {
        eprintln!("You must specify a subsystem to invoke.");
        return Err(Exit::Usage(String::new()));
    }

    if cli.use_syslog && cli.log_file.is_some() {
        return Err(Exit::fatal("Can't specify both -y and -E"));
    }
    if let Some(path) = &cli.log_file {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                Exit::Message(
                    1,
                    format!("Couldn't open logfile {path}: {}", io_message(&e)),
                )
            })?;
        *log = Log::File(file);
    } else if cli.use_syslog {
        // SAFETY: the identity is a static NUL-terminated string.
        unsafe { libc::openlog(c"ssh".as_ptr(), libc::LOG_PID, libc::LOG_USER) };
        *log = Log::Syslog;
    }

    let request = Request {
        host,
        command,
        config_file: cli.config_file.clone().map(Into::into),
        user_on_command_line: cli.user_on_command_line,
        argv0,
        debug_flag: cli.debug_flag,
    };
    let mut warnings = Vec::new();
    let resolved = sshutils_config::resolve(options, &request, &mut warnings);
    for warning in &warnings {
        log.error(warning);
    }
    let resolved = resolved?;

    if cli.config_test {
        print!("{}", resolved.options.dump(&resolved.host));
        return Ok(());
    }
    if cli.mux_command.is_some() && resolved.options.control_path.is_none() {
        return Err(Exit::fatal("No ControlPath specified for \"-O\" command"));
    }
    if cli.dump_pubkeys {
        return Err(Exit::fatal("-Z is not supported yet"));
    }
    Err(Exit::fatal("connecting is not supported yet"))
}

/// Take the destination: `ssh://[user@]host[:port]` or `[user@]host`.
fn set_destination(options: &mut Options, cli: &mut Cli, destination: &str) -> Result<(), Exit> {
    match parse_ssh_uri(destination) {
        Uri::Invalid => return Err(Exit::Usage(String::new())),
        Uri::Valid(uri) => {
            if options.user.is_none()
                && let Some(user) = uri.user
            {
                options.user = Some(user);
                cli.user_on_command_line = true;
            }
            if options.port.is_none()
                && let Some(port) = uri.port
            {
                options.port = Some(port);
            }
            cli.host = Some(uri.host);
        }
        Uri::NotUri => match destination.rsplit_once('@') {
            Some(("", _)) => return Err(Exit::Usage(String::new())),
            Some((user, host)) => {
                if options.user.is_none() {
                    options.user = Some(user.to_string());
                    cli.user_on_command_line = true;
                }
                cli.host = Some(host.to_string());
            }
            None => cli.host = Some(destination.to_string()),
        },
    }
    Ok(())
}

/// Apply one option, like the `getopt` loop in OpenSSH's `ssh.c`.
fn apply_option(
    o: &mut Options,
    cli: &mut Cli,
    letter: char,
    value: Option<&str>,
) -> Result<(), Exit> {
    let arg = value.unwrap_or("");
    // Errors OpenSSH prints itself before exiting with 255.
    let bad = |message: String| Exit::Message(255, message);
    match letter {
        '1' => return Err(Exit::fatal("SSH protocol v.1 is no longer supported")),
        '2' => {}
        '4' => o.address_family = Some(AF_INET),
        '6' => o.address_family = Some(AF_INET6),
        'n' => o.stdin_null = Some(1),
        'f' => {
            o.fork_after_authentication = Some(1);
            o.stdin_null = Some(1);
        }
        'x' => o.forward_x11 = Some(0),
        'X' => o.forward_x11 = Some(1),
        'y' => cli.use_syslog = true,
        'E' => cli.log_file = Some(arg.to_string()),
        'G' => cli.config_test = true,
        'Y' => {
            o.forward_x11 = Some(1);
            o.forward_x11_trusted = Some(1);
        }
        'Z' => cli.dump_pubkeys = true,
        'g' => o.gateway_ports = Some(1),
        'O' => {
            if o.stdio_forward.is_some() {
                return Err(Exit::fatal("Cannot specify multiplexing command with -W"));
            }
            if cli.mux_command.is_some() {
                return Err(Exit::fatal("Multiplexing command already specified"));
            }
            const COMMANDS: &[&str] = &[
                "check", "conninfo", "channels", "forward", "exit", "stop", "cancel", "proxy",
            ];
            if !COMMANDS.contains(&arg) {
                return Err(Exit::fatal("Invalid multiplex command."));
            }
            cli.mux_command = Some(arg.to_string());
        }
        'P' => set_once(&mut o.tag, arg.to_string()),
        'Q' => {
            // Answered right away, before the rest of the command line.
            return Err(match query::query(arg) {
                Some(text) => Exit::Print(text),
                None => Exit::fatal(format!("Unsupported query \"{arg}\"")),
            });
        }
        'a' => o.forward_agent = Some(0),
        'A' => o.forward_agent = Some(1),
        'k' => o.gss_deleg_creds = Some(0),
        'K' => {
            o.gss_authentication = Some(1);
            o.gss_deleg_creds = Some(1);
        }
        'i' => {
            let path = expand_tilde(arg).map_err(Exit::fatal)?;
            match std::fs::metadata(&path) {
                Err(e) => eprintln!(
                    "Warning: Identity file {path} not accessible: {}.",
                    io_message(&e)
                ),
                Ok(_) => o.add_identity_file(path, true),
            }
        }
        'I' => o.pkcs11_provider = Some(arg.to_string()),
        'J' => {
            if o.jump_host.is_some() {
                return Err(Exit::fatal(
                    "Only a single -J option is permitted (use commas to separate multiple jump hops)",
                ));
            }
            if o.proxy_command.is_some() {
                return Err(Exit::fatal("Cannot specify -J with ProxyCommand"));
            }
            let context = Context::command_line(cli.host.as_deref().unwrap_or(""));
            if !Reader::new(o, &context).apply_jump(arg, true, true) {
                return Err(Exit::fatal("Invalid -J argument"));
            }
        }
        't' => {
            o.request_tty = Some(if o.request_tty == Some(REQUEST_TTY_YES) {
                REQUEST_TTY_FORCE
            } else {
                REQUEST_TTY_YES
            });
        }
        'v' => {
            if cli.debug_flag == 0 {
                cli.debug_flag = 1;
                o.log_level = Some(LOG_LEVEL_DEBUG1);
            } else {
                // After -q the level is QUIET, and -v counts up from there.
                let level = o.log_level.unwrap_or(-1);
                if level < LOG_LEVEL_DEBUG3 {
                    cli.debug_flag += 1;
                    o.log_level = Some(level + 1);
                }
            }
        }
        'V' => {
            eprintln!("sshutils_{}, russh", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        'w' => {
            set_once(&mut o.tun_open, TUNNEL_DEFAULT);
            let devices =
                parse_tunnel_device(arg).ok_or_else(|| bad(format!("Bad tun device '{arg}'")))?;
            o.tun_devices = Some(devices);
        }
        'W' => {
            if o.stdio_forward.is_some() {
                return Err(Exit::fatal("stdio forward already specified"));
            }
            if cli.mux_command.is_some() {
                return Err(Exit::fatal("Cannot specify stdio forward with -O"));
            }
            let forward = parse_forward(arg, true, false)
                .ok_or_else(|| bad(format!("Bad stdio forwarding specification '{arg}'")))?;
            o.stdio_forward = match forward.listen {
                Endpoint::Path(path) => Some((path, PORT_STREAMLOCAL)),
                // Without a host OpenSSH ends up with no stdio forward.
                Endpoint::Tcp { host, port } => host.map(|host| (host, port)),
            };
            o.request_tty = Some(REQUEST_TTY_NO);
            o.session_type = Some(SESSION_TYPE_NONE);
        }
        'q' => o.log_level = Some(LOG_LEVEL_QUIET),
        'e' => {
            let escape = parse_escape_char(arg)
                .ok_or_else(|| bad(format!("Bad escape character '{arg}'.")))?;
            o.escape_char = Some(escape);
        }
        'c' => {
            let names = arg.strip_prefix(['+', '^']).unwrap_or(arg);
            if !algorithms::known(Kind::Cipher, names) {
                return Err(bad(format!("Unknown cipher type '{arg}'")));
            }
            o.ciphers = Some(arg.to_string());
        }
        'm' => {
            if !algorithms::known(Kind::Mac, arg) {
                return Err(bad(format!("Unknown mac type '{arg}'")));
            }
            o.macs = Some(arg.to_string());
        }
        'M' => {
            o.control_master = Some(if o.control_master == Some(CONTROL_MASTER_YES) {
                CONTROL_MASTER_ASK
            } else {
                CONTROL_MASTER_YES
            });
        }
        'p' => {
            if o.port.is_none() {
                let port = parse_port(arg)
                    .filter(|&p| p > 0)
                    .ok_or_else(|| bad(format!("Bad port '{arg}'")))?;
                o.port = Some(port);
            }
        }
        'l' => {
            if o.user.is_none() {
                o.user = Some(arg.to_string());
                cli.user_on_command_line = true;
            }
        }
        'L' => {
            let forward = parse_forward(arg, false, false)
                .ok_or_else(|| bad(format!("Bad local forwarding specification '{arg}'")))?;
            o.add_local_forward(forward);
        }
        'R' => {
            let forward = parse_forward(arg, false, true)
                .or_else(|| parse_forward(arg, true, true))
                .ok_or_else(|| bad(format!("Bad remote forwarding specification '{arg}'")))?;
            o.add_remote_forward(forward);
        }
        'D' => {
            let forward = parse_forward(arg, true, false)
                .ok_or_else(|| bad(format!("Bad dynamic forwarding specification '{arg}'")))?;
            o.add_local_forward(forward);
        }
        'C' => o.compression = Some(COMPRESSION_ZLIB),
        'N' => {
            if o.session_type.is_some_and(|t| t != SESSION_TYPE_NONE) {
                return Err(Exit::fatal("Cannot specify -N with -s/SessionType"));
            }
            o.session_type = Some(SESSION_TYPE_NONE);
            o.request_tty = Some(REQUEST_TTY_NO);
        }
        'T' => o.request_tty = Some(REQUEST_TTY_NO),
        'o' => {
            let context = Context::command_line(cli.host.as_deref().unwrap_or(""));
            let mut reader = Reader::new(o, &context);
            let result = reader.command_line(arg);
            for error in &reader.errors {
                eprintln!("{error}");
            }
            result?;
        }
        's' => {
            if o.session_type.is_some_and(|t| t != SESSION_TYPE_SUBSYSTEM) {
                return Err(Exit::fatal("Cannot specify -s with -N/SessionType"));
            }
            o.session_type = Some(SESSION_TYPE_SUBSYSTEM);
        }
        'S' => o.control_path = Some(arg.to_string()),
        'b' => o.bind_address = Some(arg.to_string()),
        'B' => o.bind_interface = Some(arg.to_string()),
        'F' => cli.config_file = Some(arg.to_string()),
        other => unreachable!("option -{other} is in the table but not handled"),
    }
    Ok(())
}

/// An I/O error as `strerror` would describe it.
fn io_message(err: &std::io::Error) -> String {
    let message = err.to_string();
    match message.find(" (os error ") {
        Some(i) => message[..i].to_string(),
        None => message,
    }
}
