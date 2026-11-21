//! Command-line parsing with OpenSSH semantics, on top of clap.
//!
//! Each tool declares its options as a `#[derive(clap::Parser)]` struct using
//! short options only, and parses them with [`parse`]. This module adjusts
//! clap's defaults to behave like the `getopt(3)` that OpenSSH uses:
//!
//! - No automatic `-h`/`--help` or `-V`/`--version`. Several tools use those
//!   letters for other things (`ssh-keygen -h` signs host certificates), and
//!   `ssh -V` has its own output.
//! - Repeating a single-valued option is not an error; the last one wins
//!   (`ssh-keygen -t rsa -t ed25519` generates an ed25519 key).
//! - An option's value may start with a hyphen (`ssh-keygen -C -foo` sets the
//!   comment to `-foo`), because getopt takes the next word unconditionally.
//! - Errors print the tool's own usage text and exit with the tool's own exit
//!   status (255 for `ssh`, 1 for most others) instead of clap's 2.
//!
//! What clap already does like getopt: clustered flags (`-lv`), attached and
//! detached values (`-fkey`, `-f key`), empty values (`-N ''`), and `--`.
//!
//! Field attributes still needed per tool:
//!
//! - Counted flags (`-v`, `-t`): `action = ArgAction::Count`.
//! - Repeatable options (`-o`, `-i`, `-L`): a `Vec<_>` field. Values keep
//!   their command-line order, which matters because OpenSSH applies the first
//!   value given for most configuration options.
//! - A remote command after the destination (`ssh host ls -l`): a trailing
//!   `Vec<OsString>` positional with `trailing_var_arg = true` and
//!   `allow_hyphen_values = true`.

use std::ffi::OsString;

use clap::{Command, Parser};

/// How a tool presents command-line errors.
#[derive(Clone, Copy, Debug)]
pub struct Usage {
    /// Usage synopsis shown after an error, without a leading `usage:`.
    pub text: &'static str,
    /// Exit status for command-line errors.
    pub exit_code: i32,
}

/// Apply the OpenSSH-compatible settings to a clap command.
pub fn configure(cmd: Command, usage: &Usage) -> Command {
    cmd.disable_help_flag(true)
        .disable_version_flag(true)
        .args_override_self(true)
        .override_usage(usage.text)
        .mut_args(|arg| {
            if !arg.is_positional() && arg.get_action().takes_values() {
                arg.allow_hyphen_values(true)
            } else {
                arg
            }
        })
}

/// Parse `args` (including the program name) into `T`.
pub fn try_parse_from<T, I, A>(usage: &Usage, args: I) -> Result<T, clap::Error>
where
    T: Parser,
    I: IntoIterator<Item = A>,
    A: Into<OsString> + Clone,
{
    let mut cmd = configure(T::command(), usage);
    let mut matches = cmd.try_get_matches_from_mut(args)?;
    T::from_arg_matches_mut(&mut matches).map_err(|e| e.format(&mut cmd))
}

/// Parse the process arguments into `T`. On error, print the message and
/// usage to stderr and exit with `usage.exit_code`.
pub fn parse<T: Parser>(usage: &Usage) -> T {
    match try_parse_from(usage, std::env::args_os()) {
        Ok(parsed) => parsed,
        Err(err) => {
            let _ = err.print();
            std::process::exit(usage.exit_code);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::ArgAction;
    use clap::error::ErrorKind;

    use super::*;

    const USAGE: Usage = Usage {
        text: "test [-lv] [-f file]",
        exit_code: 1,
    };

    /// A subset of `ssh-keygen`'s options.
    #[derive(Parser, Debug)]
    #[command(name = "ssh-keygen")]
    struct Keygen {
        #[arg(short = 'l')]
        fingerprint: bool,
        #[arg(short = 'v', action = ArgAction::Count)]
        verbose: u8,
        #[arg(short = 'f')]
        file: Option<PathBuf>,
        #[arg(short = 'N')]
        new_passphrase: Option<String>,
        #[arg(short = 't')]
        key_type: Option<String>,
        #[arg(short = 'C')]
        comment: Option<String>,
        #[arg(short = 'h')]
        host_certificate: bool,
    }

    /// A subset of `ssh`'s options.
    #[derive(Parser, Debug)]
    #[command(name = "ssh")]
    struct Ssh {
        #[arg(short = '4')]
        ipv4: bool,
        #[arg(short = 'p')]
        port: Option<u16>,
        #[arg(short = 'l')]
        login: Option<String>,
        #[arg(short = 'o')]
        options: Vec<String>,
        #[arg(short = 't', action = ArgAction::Count)]
        tty: u8,
        destination: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    }

    fn keygen(args: &[&str]) -> Result<Keygen, clap::Error> {
        try_parse_from(
            &USAGE,
            std::iter::once("ssh-keygen").chain(args.iter().copied()),
        )
    }

    fn ssh(args: &[&str]) -> Result<Ssh, clap::Error> {
        try_parse_from(&USAGE, std::iter::once("ssh").chain(args.iter().copied()))
    }

    #[test]
    fn clustered_flags_with_attached_value() {
        let k = keygen(&["-lvvfkey"]).unwrap();
        assert!(k.fingerprint);
        assert_eq!(k.verbose, 2);
        assert_eq!(k.file, Some(PathBuf::from("key")));
    }

    #[test]
    fn detached_and_empty_values() {
        let k = keygen(&["-f", "key", "-N", ""]).unwrap();
        assert_eq!(k.file, Some(PathBuf::from("key")));
        assert_eq!(k.new_passphrase.as_deref(), Some(""));
    }

    #[test]
    fn repeated_option_last_wins() {
        let k = keygen(&["-t", "rsa", "-t", "ed25519"]).unwrap();
        assert_eq!(k.key_type.as_deref(), Some("ed25519"));
    }

    #[test]
    fn value_may_start_with_hyphen() {
        let k = keygen(&["-C", "-foo", "-l"]).unwrap();
        assert_eq!(k.comment.as_deref(), Some("-foo"));
        assert!(k.fingerprint);
    }

    #[test]
    fn h_and_v_are_ordinary_options() {
        let k = keygen(&["-h", "-v"]).unwrap();
        assert!(k.host_certificate);
        assert_eq!(k.verbose, 1);
        assert!(keygen(&["--help"]).is_err());
        assert!(keygen(&["--version"]).is_err());
    }

    #[test]
    fn errors() {
        assert_eq!(
            keygen(&["-x"]).unwrap_err().kind(),
            ErrorKind::UnknownArgument
        );
        assert!(keygen(&["-f"]).is_err());
    }

    #[test]
    fn remote_command_keeps_its_options() {
        let s = ssh(&["-p", "2222", "host", "ls", "-l", "-p", "3"]).unwrap();
        assert_eq!(s.port, Some(2222));
        assert_eq!(s.login, None);
        assert_eq!(s.destination, "host");
        assert_eq!(s.command, ["ls", "-l", "-p", "3"]);
    }

    #[test]
    fn options_after_destination() {
        // OpenSSH accepts options between the destination and the command.
        let s = ssh(&["host", "-l", "me", "-tt", "uptime"]).unwrap();
        assert_eq!(s.login.as_deref(), Some("me"));
        assert_eq!(s.tty, 2);
        assert_eq!(s.command, ["uptime"]);
    }

    #[test]
    fn repeated_options_keep_order() {
        let s = ssh(&["-o", "Port=1", "-4", "-oPort=2", "host"]).unwrap();
        assert!(s.ipv4);
        assert_eq!(s.options, ["Port=1", "Port=2"]);
    }

    #[test]
    fn double_dash_ends_options() {
        let s = ssh(&["--", "host", "-l"]).unwrap();
        assert_eq!(s.destination, "host");
        assert_eq!(s.command, ["-l"]);
    }
}
