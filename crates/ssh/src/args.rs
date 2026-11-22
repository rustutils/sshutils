//! `ssh` command line.
//!
//! `ssh` applies its options in command-line order, and the order changes
//! the result (`-4 -6`, `-o Port=1 -p 2`), so the arguments are read one at
//! a time with [`lexopt`] rather than collected by clap. Like OpenSSH:
//!
//! - Options end at the first word that isn't one, the destination.
//!   Options may follow the destination too, up to the next non-option
//!   word, which starts the remote command (`ssh host -v ls -l`).
//! - `--` before the destination ends option parsing for good; after the
//!   destination it ends it before the command.
//! - An option's value is the rest of the word or the next word, whatever
//!   it looks like (`-o -x`, `-p=22` has the value `=22`).
//!
//! The table of options, [`OPTIONS`], also describes them for clap
//! ([`command`]), which gives help text and man pages from one source.

use std::ffi::OsString;

/// One option letter.
// `help` is only read through `command`.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct Spec {
    pub letter: char,
    /// The value's name, for options that take one.
    pub value: Option<&'static str>,
    pub help: &'static str,
}

const fn flag(letter: char, help: &'static str) -> Spec {
    Spec {
        letter,
        value: None,
        help,
    }
}

const fn valued(letter: char, value: &'static str, help: &'static str) -> Spec {
    Spec {
        letter,
        value: Some(value),
        help,
    }
}

/// Every option `ssh` accepts, in the order of the usage text.
pub const OPTIONS: &[Spec] = &[
    flag('1', "Protocol version 1 (no longer supported)."),
    flag('2', "Protocol version 2 (ignored, it is the only version)."),
    flag('4', "Use IPv4 addresses only."),
    flag('6', "Use IPv6 addresses only."),
    flag('A', "Forward the connection to the authentication agent."),
    flag('a', "Don't forward the authentication agent."),
    flag('C', "Compress the connection."),
    flag(
        'f',
        "Go to the background after authentication (implies -n).",
    ),
    flag('G', "Print the configuration for the destination and exit."),
    flag('g', "Let remote hosts connect to local forwarded ports."),
    flag(
        'K',
        "Use GSSAPI authentication and forward (delegate) GSSAPI credentials.",
    ),
    flag('k', "Don't forward (delegate) GSSAPI credentials."),
    flag(
        'M',
        "Become a connection-sharing master; twice to confirm each use.",
    ),
    flag('N', "Don't run a remote command (for forwarding only)."),
    flag('n', "Read stdin from /dev/null."),
    flag('q', "Quiet: suppress most warnings and diagnostics."),
    flag('s', "Invoke a subsystem on the remote host."),
    flag('T', "Don't allocate a pseudo-terminal."),
    flag(
        't',
        "Allocate a pseudo-terminal; twice to force one without a local terminal.",
    ),
    flag('V', "Print the version and exit."),
    flag('v', "Verbose: print debugging messages; up to three times."),
    flag('X', "Enable X11 forwarding."),
    flag('x', "Disable X11 forwarding."),
    flag('Y', "Enable trusted X11 forwarding."),
    flag('y', "Send log messages to syslog instead of stderr."),
    flag(
        'Z',
        "Print the public keys that would be offered for authentication and exit.",
    ),
    valued(
        'B',
        "bind_interface",
        "Bind to the address of this interface.",
    ),
    valued('b', "bind_address", "Connect from this local address."),
    valued(
        'c',
        "cipher_spec",
        "Ciphers to use, in order of preference.",
    ),
    valued(
        'D',
        "[bind_address:]port",
        "Forward a local port as a SOCKS proxy.",
    ),
    valued('E', "log_file", "Append log messages to this file."),
    valued(
        'e',
        "escape_char",
        "Escape character for interactive sessions (\"none\" disables it).",
    ),
    valued(
        'F',
        "configfile",
        "Read this configuration file instead of the user and system ones.",
    ),
    valued('I', "pkcs11", "PKCS#11 library for keys on a token."),
    valued(
        'i',
        "identity_file",
        "Private key file for public key authentication; may be repeated.",
    ),
    valued(
        'J',
        "destination",
        "Connect through these jump hosts (comma-separated).",
    ),
    valued(
        'L',
        "address",
        "Forward a local port or socket to a remote address.",
    ),
    valued('l', "login_name", "User to log in as."),
    valued(
        'm',
        "mac_spec",
        "MAC algorithms to use, in order of preference.",
    ),
    valued(
        'O',
        "ctl_cmd",
        "Send a command to a connection-sharing master: check, conninfo, channels, forward, cancel, exit, stop or proxy.",
    ),
    valued(
        'o',
        "option",
        "A configuration option, in ssh_config format; may be repeated.",
    ),
    valued('P', "tag", "Tag for Match tagged in the configuration."),
    valued('p', "port", "Port to connect to."),
    valued(
        'Q',
        "query_option",
        "List the supported algorithms of a kind and exit.",
    ),
    valued(
        'R',
        "address",
        "Forward a remote port or socket to a local address, or as a SOCKS proxy.",
    ),
    valued('S', "ctl_path", "Control socket for connection sharing."),
    valued(
        'W',
        "host:port",
        "Connect stdin and stdout to this address on the remote side.",
    ),
    valued('w', "local_tun[:remote_tun]", "Forward a tunnel device."),
];

/// The usage text printed after command-line errors.
pub const USAGE: &str = "\
usage: ssh [-46AaCfGgKkMNnqsTtVvXxYyZ] [-B bind_interface] [-b bind_address]
           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]
           [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]
           [-J destination] [-L address] [-l login_name] [-m mac_spec]
           [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]
           [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]
           destination [command [argument ...]]
       ssh [-Q query_option]";

/// The options as a clap command, for help text and man pages. It is not
/// used to parse the command line. (Nothing uses it yet but the tests; man
/// page generation will.)
#[allow(dead_code)]
pub fn command() -> clap::Command {
    let mut command = clap::Command::new("ssh")
        .about("OpenSSH-compatible remote login client")
        .override_usage(USAGE.trim_start_matches("usage: "))
        .disable_help_flag(true)
        .disable_version_flag(true);
    for spec in OPTIONS {
        // Ids must be static without clap's "string" feature; this runs once
        // per man page or help text.
        let id: &'static str = spec.letter.to_string().leak();
        let arg = clap::Arg::new(id).short(spec.letter).help(spec.help);
        let arg = match spec.value {
            Some(name) => arg.value_name(name).action(clap::ArgAction::Append),
            None => arg.action(clap::ArgAction::Count),
        };
        command = command.arg(arg);
    }
    command
        .arg(
            clap::Arg::new("destination")
                .help("Where to connect: [user@]hostname[:port] or ssh://[user@]hostname[:port]."),
        )
        .arg(
            clap::Arg::new("command")
                .num_args(0..)
                .help("Command to run on the remote host instead of a shell."),
        )
}

fn spec(letter: char) -> Option<&'static Spec> {
    OPTIONS.iter().find(|s| s.letter == letter)
}

/// One piece of the command line, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// An option and its value, if it takes one.
    Option(char, Option<String>),
    /// The destination.
    Destination(String),
}

/// A command-line error: print it and the usage text, exit 255.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

enum State {
    /// Before the destination.
    Start,
    /// After the destination, still reading options.
    AfterDestination,
    /// All options read.
    Done,
}

/// Reads the command line one item at a time, so options can be applied
/// (and `-V`, `-Q` act) before later arguments are looked at.
pub struct Arguments {
    /// Everything after the program name.
    args: Vec<OsString>,
    parser: lexopt::Parser,
    state: State,
    /// The words of the remote command, once options are done.
    command: Vec<String>,
}

fn new_parser(args: Vec<OsString>) -> lexopt::Parser {
    let mut parser = lexopt::Parser::from_args(args);
    parser.set_short_equals(false);
    parser
}

fn utf8(arg: OsString) -> Result<String, UsageError> {
    arg.into_string()
        .map_err(|arg| UsageError(format!("invalid argument encoding: {}", arg.display())))
}

impl Arguments {
    /// The process's arguments, without the program name.
    pub fn new(args: Vec<OsString>) -> Self {
        Arguments {
            parser: new_parser(args.clone()),
            args,
            state: State::Start,
            command: Vec::new(),
        }
    }

    /// The next option or the destination. `None` once options are done;
    /// then [`command`](Self::command) holds the remote command.
    pub fn next_item(&mut self) -> Result<Option<Item>, UsageError> {
        if matches!(self.state, State::Done) {
            return Ok(None);
        }
        let arg = self.parser.next().map_err(|e| UsageError(e.to_string()))?;
        match arg {
            None => {
                self.state = State::Done;
                Ok(None)
            }
            Some(lexopt::Arg::Short(letter)) => {
                let spec = spec(letter)
                    .ok_or_else(|| UsageError(format!("unknown option -- {letter}")))?;
                let value = match spec.value {
                    None => None,
                    Some(_) => {
                        let value = self.parser.value().map_err(|_| {
                            UsageError(format!("option requires an argument -- {letter}"))
                        })?;
                        Some(utf8(value)?)
                    }
                };
                Ok(Some(Item::Option(letter, value)))
            }
            Some(lexopt::Arg::Long(name)) => Err(UsageError(format!("unknown option -- -{name}"))),
            Some(lexopt::Arg::Value(word)) => {
                let rest: Vec<OsString> = self
                    .parser
                    .raw_args()
                    .map_err(|e| UsageError(e.to_string()))?
                    .collect();
                match self.state {
                    State::Start => {
                        // OpenSSH stops reading options for good if the word
                        // before the destination is "--".
                        let index = self.args.len() - rest.len() - 1;
                        let terminated = index > 0 && self.args[index - 1] == "--";
                        if terminated || rest.is_empty() {
                            self.command = rest.into_iter().map(utf8).collect::<Result<_, _>>()?;
                            self.state = State::Done;
                        } else {
                            self.args = rest.clone();
                            self.parser = new_parser(rest);
                            self.state = State::AfterDestination;
                        }
                        Ok(Some(Item::Destination(utf8(word)?)))
                    }
                    State::AfterDestination | State::Done => {
                        self.command = std::iter::once(word)
                            .chain(rest)
                            .map(utf8)
                            .collect::<Result<_, _>>()?;
                        self.state = State::Done;
                        Ok(None)
                    }
                }
            }
        }
    }

    /// The remote command's words (empty for none). Complete once
    /// [`next_item`](Self::next_item) has returned `None`.
    pub fn command(&self) -> &[String] {
        &self.command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse to completion: the items in order, and the command.
    fn parse(args: &[&str]) -> Result<(Vec<Item>, Vec<String>), UsageError> {
        let mut arguments = Arguments::new(args.iter().map(OsString::from).collect());
        let mut items = Vec::new();
        while let Some(item) = arguments.next_item()? {
            items.push(item);
        }
        Ok((items, arguments.command().to_vec()))
    }

    fn opt(letter: char, value: Option<&str>) -> Item {
        Item::Option(letter, value.map(String::from))
    }

    fn dest(host: &str) -> Item {
        Item::Destination(host.into())
    }

    #[test]
    fn order_is_kept() {
        let (items, command) =
            parse(&["-vv", "-o", "A=1", "host", "-4", "-v", "-oB=2", "ls", "-l"]).unwrap();
        assert_eq!(
            items,
            [
                opt('v', None),
                opt('v', None),
                opt('o', Some("A=1")),
                dest("host"),
                opt('4', None),
                opt('v', None),
                opt('o', Some("B=2")),
            ]
        );
        assert_eq!(command, ["ls", "-l"]);
    }

    #[test]
    fn values_are_taken_as_they_are() {
        let (items, _) = parse(&["-o", "-x", "-p=22", "-vlme", "host"]).unwrap();
        assert_eq!(
            items,
            [
                opt('o', Some("-x")),
                opt('p', Some("=22")),
                opt('v', None),
                opt('l', Some("me")),
                dest("host"),
            ]
        );
    }

    #[test]
    fn double_dash() {
        // Before the destination: nothing after it is an option.
        let (items, command) = parse(&["--", "host", "-l", "bob", "ls"]).unwrap();
        assert_eq!(items, [dest("host")]);
        assert_eq!(command, ["-l", "bob", "ls"]);
        // After it: the command starts.
        let (items, command) = parse(&["host", "-v", "--", "-l"]).unwrap();
        assert_eq!(items, [dest("host"), opt('v', None)]);
        assert_eq!(command, ["-l"]);
        // Only the word right before the destination counts, even as a
        // value.
        let (items, command) = parse(&["-o", "--", "host", "-v"]).unwrap();
        assert_eq!(items, [opt('o', Some("--")), dest("host")]);
        assert_eq!(command, ["-v"]);
    }

    #[test]
    fn errors() {
        assert!(parse(&["-h"]).is_err());
        assert!(parse(&["host", "-p"]).is_err());
        assert!(parse(&["--port", "1", "host"]).is_err());
        assert_eq!(parse(&[]).unwrap(), (vec![], vec![]));
    }

    #[test]
    fn clap_description_has_every_option() {
        let command = command();
        for spec in OPTIONS {
            let arg = command
                .get_arguments()
                .find(|a| a.get_short() == Some(spec.letter))
                .unwrap();
            assert_eq!(arg.get_action().takes_values(), spec.value.is_some());
        }
        command.debug_assert();
    }
}
