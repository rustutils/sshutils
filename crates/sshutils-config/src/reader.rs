//! Processing configuration lines and files, as OpenSSH's `readconf.c`.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::algorithms::{self, Kind};
use crate::expand::{self, connection_hash, expand_tilde};
use crate::forward::{parse_forward, parse_jump, split_host};
use crate::keywords::{self, Opcode};
use crate::lexer::{split_args, split_line};
use crate::matching::{match_hostname, match_pattern, match_pattern_list};
use crate::network::{local_addresses, parse_network_list};
use crate::options::{Options, PermittedCname, set_once};
use crate::values::*;

/// Deepest `Include` nesting.
const MAX_DEPTH: usize = 16;
/// Limits on list options, as in OpenSSH.
const MAX_IDENTITY_FILES: usize = 100;
const MAX_CERTIFICATE_FILES: usize = 100;
const MAX_HOSTS_FILES: usize = 32;
/// The OpenSSH release `Match version` compares against.
pub const SSH_RELEASE: &str = "OpenSSH_10.5";

/// Who is connecting, and to what: everything `Host` and `Match` look at.
#[derive(Debug, Clone)]
pub struct Context {
    /// The host name `Host` lines match (the destination as given on the
    /// first pass, the canonical name on the final pass).
    pub host: String,
    /// The destination as given on the command line (`%n`,
    /// `Match originalhost`).
    pub original_host: String,
    /// The remote command, if any (`Match command`).
    pub remote_command: Option<String>,
    pub local_user: String,
    pub home: String,
    pub uid: u32,
}

/// How a file is read.
#[derive(Debug, Clone, Copy, Default)]
pub struct Flags {
    /// A user configuration file (relative includes go to `~/.ssh`, `~` is
    /// allowed in include paths).
    pub user_config: bool,
    /// Refuse files writable by others.
    pub check_permissions: bool,
    /// The final pass (after canonicalization or `Match final`).
    pub final_pass: bool,
    /// Parse only; nothing matches (includes inside inactive blocks).
    pub never_match: bool,
}

/// A problem that stops configuration processing (OpenSSH's `fatal()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fatal(pub String);

impl std::fmt::Display for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fatal {}

/// Applies configuration lines to options.
pub struct Reader<'a> {
    pub options: &'a mut Options,
    pub context: &'a Context,
    /// Set when a `Match final` asks for a second pass.
    pub want_final_pass: bool,
    /// Errors reported so far (OpenSSH prints these as they happen).
    pub errors: Vec<String>,
}

/// Where a line came from, for messages.
struct Origin<'a> {
    file: &'a str,
    line: usize,
}

impl<'a> Reader<'a> {
    pub fn new(options: &'a mut Options, context: &'a Context) -> Self {
        Reader {
            options,
            context,
            want_final_pass: false,
            errors: Vec::new(),
        }
    }

    /// Apply a `-o` option. Fails (after recording an error) if the line is
    /// invalid.
    pub fn command_line(&mut self, line: &str) -> Result<(), Fatal> {
        let mut active = true;
        let origin = Origin {
            file: "command-line",
            line: 0,
        };
        let flags = Flags {
            user_config: true,
            ..Flags::default()
        };
        match self.process(line, &origin, &mut active, true, flags, 0)? {
            true => Ok(()),
            false => Err(Fatal(String::new())),
        }
    }

    /// Read a configuration file. Returns `Ok(false)` if it can't be
    /// opened.
    pub fn read_file(&mut self, path: &Path, flags: Flags) -> Result<bool, Fatal> {
        let mut active = true;
        self.read_file_depth(path, flags, &mut active, 0)
    }

    fn read_file_depth(
        &mut self,
        path: &Path,
        flags: Flags,
        active: &mut bool,
        depth: usize,
    ) -> Result<bool, Fatal> {
        if depth > MAX_DEPTH {
            return Err(Fatal("Too many recursive configuration includes".into()));
        }
        let Ok(bytes) = std::fs::read(path) else {
            return Ok(false);
        };
        let name = path.display().to_string();
        if flags.check_permissions {
            let meta = std::fs::metadata(path).map_err(|e| Fatal(format!("fstat {name}: {e}")))?;
            // SAFETY: getuid has no preconditions.
            let uid = unsafe { libc::getuid() };
            if (meta.uid() != 0 && meta.uid() != uid) || meta.mode() & 0o022 != 0 {
                return Err(Fatal(format!("Bad owner or permissions on {name}")));
            }
        }
        let text = String::from_utf8_lossy(&bytes);
        let mut bad = 0;
        for (index, line) in text.split('\n').enumerate() {
            let origin = Origin {
                file: &name,
                line: index + 1,
            };
            if !self.process(line, &origin, active, false, flags, depth)? {
                bad += 1;
            }
        }
        if bad > 0 {
            return Err(Fatal(format!(
                "{name}: terminating, {bad} bad configuration options"
            )));
        }
        Ok(true)
    }

    fn error(&mut self, origin: &Origin<'_>, message: impl std::fmt::Display) {
        self.errors
            .push(format!("{} line {}: {message}", origin.file, origin.line));
    }

    /// Process one line. Returns `Ok(false)` for a bad line (counted by the
    /// caller), `Err` for fatal problems.
    fn process(
        &mut self,
        line: &str,
        origin: &Origin<'_>,
        active: &mut bool,
        command_line: bool,
        flags: Flags,
        depth: usize,
    ) -> Result<bool, Fatal> {
        let Some(parsed) = split_line(line) else {
            return Ok(true);
        };
        let keyword = parsed.keyword;
        let rest = parsed.rest;
        if rest.is_empty() {
            self.error(origin, format!("no argument after keyword \"{keyword}\""));
            return Ok(false);
        }
        let opcode = match keywords::lookup(&keyword) {
            Some(opcode) => Some(opcode),
            None if keywords::DISTRIBUTION_KEYWORDS.contains(&keyword.as_str()) => None,
            None => {
                let ignored = self
                    .options
                    .ignored_unknown
                    .as_deref()
                    .is_some_and(|patterns| match_pattern_list(&keyword, patterns, true) == 1);
                if !ignored {
                    self.errors.push(format!(
                        "{}: line {}: Bad configuration option: {keyword}",
                        origin.file, origin.line
                    ));
                    return Ok(false);
                }
                None
            }
        };
        let args = match split_args(rest) {
            Ok(args) => args,
            Err(_) => {
                self.error(origin, "invalid quotes");
                return Ok(false);
            }
        };
        let Some(opcode) = opcode else {
            // Ignored unknown or distribution-specific keyword.
            return Ok(true);
        };
        let mut args = Args::new(args);
        let ok = self.apply(
            opcode,
            &keyword,
            rest,
            &mut args,
            origin,
            active,
            command_line,
            flags,
            depth,
        )?;
        if !ok {
            return Ok(false);
        }
        if !args.is_empty() {
            self.error(
                origin,
                format!("keyword {keyword} extra arguments at end of line"),
            );
            return Ok(false);
        }
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply(
        &mut self,
        opcode: Opcode,
        keyword: &str,
        rest: &str,
        args: &mut Args,
        origin: &Origin<'_>,
        active: &mut bool,
        command_line: bool,
        flags: Flags,
        depth: usize,
    ) -> Result<bool, Fatal> {
        let on = *active;
        let o = &mut *self.options;

        macro_rules! fail {
            ($($message:tt)*) => {{
                let message = format!($($message)*);
                self.error(origin, message);
                return Ok(false);
            }};
        }
        macro_rules! fatal {
            ($($message:tt)*) => {{
                return Err(Fatal(format!("{} line {}: {}", origin.file, origin.line, format!($($message)*))));
            }};
        }
        // A required single argument.
        macro_rules! required {
            () => {
                match args.next() {
                    Some(arg) if !arg.is_empty() => arg,
                    _ => fail!("Missing argument."),
                }
            };
        }
        macro_rules! multistate {
            ($field:ident, $table:expr) => {{
                let arg = args.next().unwrap_or_default();
                match parse_multistate($table, &arg) {
                    Some(value) => {
                        if on {
                            set_once(&mut o.$field, value);
                        }
                    }
                    None if arg.is_empty() => fail!("missing argument."),
                    None => fail!("unsupported option \"{arg}\"."),
                }
            }};
        }
        macro_rules! flag {
            ($field:ident) => {
                multistate!($field, FLAG)
            };
        }
        macro_rules! string {
            ($field:ident) => {{
                let arg = required!();
                if on {
                    set_once(&mut o.$field, arg);
                }
            }};
        }
        macro_rules! time {
            ($field:ident) => {{
                let arg = match args.next() {
                    Some(arg) if !arg.is_empty() => arg,
                    _ => fail!("missing time value."),
                };
                let value = if arg == "none" {
                    None
                } else {
                    match sshutils_core::time::parse_interval(&arg) {
                        Some(v) if v <= i32::MAX as u64 => Some(v as i64),
                        _ => fail!("invalid time value."),
                    }
                };
                if let (true, Some(value)) = (on, value) {
                    set_once(&mut o.$field, value);
                }
            }};
        }
        macro_rules! int {
            ($field:ident) => {{
                let arg = args.next().unwrap_or_default();
                match parse_int(&arg) {
                    Ok(value) => {
                        if on {
                            set_once(&mut o.$field, value);
                        }
                    }
                    Err(e) => fail!("integer value {e}."),
                }
            }};
        }
        macro_rules! command {
            ($field:ident) => {{
                let value = rest.trim_start_matches([' ', '\t', '\r', '\n', '=']);
                if on {
                    set_once(&mut o.$field, value.to_string());
                }
                args.consume();
            }};
        }
        macro_rules! algorithms {
            ($field:ident, $kind:expr, $what:expr) => {{
                let arg = required!();
                if !algorithms::valid($kind, &arg) {
                    fail!("{} '{arg}'.", $what);
                }
                if on {
                    set_once(&mut o.$field, arg);
                }
            }};
        }
        /// A list set as a whole by its first matching line; "none" only
        /// alone.
        macro_rules! list_once {
            ($field:ident, $max:expr, $check:expr) => {{
                let was_empty = o.$field.is_empty();
                let mut values = Vec::new();
                let total = args.len();
                while let Some(arg) = args.next() {
                    if arg.is_empty() {
                        fail!("keyword {keyword} empty argument");
                    }
                    if arg.eq_ignore_ascii_case("none") && total > 1 {
                        fail!("keyword {keyword} \"none\" argument must appear alone.");
                    }
                    let check: &dyn Fn(&str) -> Result<(), String> = &$check;
                    if let Err(e) = check(&arg) {
                        fail!("{e}");
                    }
                    values.push(arg);
                }
                if values.is_empty() {
                    fatal!("no {keyword} specified");
                }
                if on && was_empty {
                    if values.len() > $max {
                        fail!("too many {keyword} entries.");
                    }
                    o.$field = values;
                }
            }};
        }
        let any = |_: &str| -> Result<(), String> { Ok(()) };

        match opcode {
            Opcode::Ignore | Opcode::Deprecated => args.consume(),
            Opcode::Unsupported => {
                self.error(origin, format!("Unsupported option \"{keyword}\""));
                args.consume();
            }
            Opcode::ConnectTimeout => time!(connection_timeout),
            Opcode::ForwardAgent => {
                let arg = required!();
                match parse_multistate(FLAG, &arg) {
                    Some(value) => {
                        if on {
                            set_once(&mut o.forward_agent, value);
                        }
                    }
                    None => {
                        // A socket path or environment variable.
                        if !valid_agent_path(&arg) {
                            fail!("Invalid environment expansion {arg}.");
                        }
                        if on {
                            set_once(&mut o.forward_agent, 1);
                            set_once(&mut o.forward_agent_sock_path, arg);
                        }
                    }
                }
            }
            Opcode::ForwardX11 => flag!(forward_x11),
            Opcode::ForwardX11Trusted => flag!(forward_x11_trusted),
            Opcode::ForwardX11Timeout => time!(forward_x11_timeout),
            Opcode::GatewayPorts => flag!(gateway_ports),
            Opcode::ExitOnForwardFailure => flag!(exit_on_forward_failure),
            Opcode::PasswordAuthentication => flag!(password_authentication),
            Opcode::KbdInteractiveAuthentication => flag!(kbd_interactive_authentication),
            Opcode::KbdInteractiveDevices => string!(kbd_interactive_devices),
            Opcode::PubkeyAuthentication => multistate!(pubkey_authentication, PUBKEY_AUTH),
            Opcode::HostbasedAuthentication => flag!(hostbased_authentication),
            Opcode::GssAuthentication => flag!(gss_authentication),
            Opcode::GssDelegateCreds => flag!(gss_deleg_creds),
            Opcode::BatchMode => flag!(batch_mode),
            Opcode::CheckHostIP => flag!(check_host_ip),
            Opcode::VerifyHostKeyDNS => multistate!(verify_host_key_dns, YES_NO_ASK),
            Opcode::StrictHostKeyChecking => multistate!(strict_host_key_checking, STRICT_HOSTKEY),
            Opcode::Compression => multistate!(compression, COMPRESSION),
            Opcode::TCPKeepAlive => flag!(tcp_keep_alive),
            Opcode::NoHostAuthenticationForLocalhost => flag!(no_host_authentication_for_localhost),
            Opcode::NumberOfPasswordPrompts => int!(number_of_password_prompts),
            Opcode::RekeyLimit => {
                let arg = required!();
                let limit = if arg == "default" {
                    0
                } else {
                    match parse_scaled(&arg) {
                        Some(v) if v == 0 || v >= 16 => v,
                        Some(_) => fail!("RekeyLimit too small"),
                        None => fail!("Bad number '{arg}'"),
                    }
                };
                if on {
                    set_once(&mut o.rekey_limit, limit);
                }
                if let Some(interval) = args.peek() {
                    if interval == "none" {
                        args.next();
                    } else {
                        time!(rekey_interval);
                    }
                }
            }
            Opcode::IdentityFile => {
                let arg = required!();
                if on {
                    if o.identity_files.len() >= MAX_IDENTITY_FILES {
                        fail!("Too many identity files specified (max {MAX_IDENTITY_FILES}).");
                    }
                    o.add_identity_file(arg, flags.user_config);
                }
            }
            Opcode::CertificateFile => {
                let arg = required!();
                if on {
                    if o.certificate_files.len() >= MAX_CERTIFICATE_FILES {
                        fail!(
                            "Too many certificate files specified (max {MAX_CERTIFICATE_FILES})."
                        );
                    }
                    o.add_certificate_file(arg, flags.user_config);
                }
            }
            Opcode::XAuthLocation => string!(xauth_location),
            Opcode::User => string!(user),
            Opcode::GlobalKnownHostsFile => list_once!(system_hostfiles, MAX_HOSTS_FILES, any),
            Opcode::UserKnownHostsFile => list_once!(user_hostfiles, MAX_HOSTS_FILES, any),
            Opcode::Hostname => string!(hostname),
            Opcode::Tag => string!(tag),
            Opcode::HostKeyAlias => string!(host_key_alias),
            Opcode::PreferredAuthentications => string!(preferred_authentications),
            Opcode::BindAddress => string!(bind_address),
            Opcode::BindInterface => string!(bind_interface),
            Opcode::PKCS11Provider => string!(pkcs11_provider),
            Opcode::SecurityKeyProvider => string!(sk_provider),
            Opcode::KnownHostsCommand => command!(known_hosts_command),
            Opcode::ProxyCommand => command!(proxy_command),
            Opcode::LocalCommand => command!(local_command),
            Opcode::RemoteCommand => command!(remote_command),
            Opcode::ProxyJump => {
                let value = rest.trim_start_matches([' ', '\t', '\r', '\n', '=']);
                if !self.apply_jump(value, command_line, on) {
                    fail!("Invalid ProxyJump \"{value}\"");
                }
                args.consume();
            }
            Opcode::Port => {
                let arg = required!();
                match parse_port(&arg).filter(|&p| p > 0) {
                    Some(port) => {
                        if on {
                            set_once(&mut o.port, port);
                        }
                    }
                    None => fail!("Bad port '{arg}'."),
                }
            }
            Opcode::ConnectionAttempts => int!(connection_attempts),
            Opcode::Ciphers => algorithms!(ciphers, Kind::Cipher, "Bad SSH2 cipher spec"),
            Opcode::Macs => algorithms!(macs, Kind::Mac, "Bad SSH2 MAC spec"),
            Opcode::KexAlgorithms => {
                algorithms!(kex_algorithms, Kind::Kex, "Bad SSH2 KexAlgorithms")
            }
            Opcode::HostKeyAlgorithms => algorithms!(
                hostkey_algorithms,
                Kind::Key { ca_only: false },
                "Bad key types"
            ),
            Opcode::CASignatureAlgorithms => algorithms!(
                ca_sign_algorithms,
                Kind::Key { ca_only: true },
                "Bad key types"
            ),
            Opcode::HostbasedAcceptedAlgorithms => algorithms!(
                hostbased_accepted_algorithms,
                Kind::Key { ca_only: false },
                "Bad key types"
            ),
            Opcode::PubkeyAcceptedAlgorithms => algorithms!(
                pubkey_accepted_algorithms,
                Kind::Key { ca_only: false },
                "Bad key types"
            ),
            Opcode::LogLevel => {
                let arg = args.next().unwrap_or_default();
                match parse_multistate(LOG_LEVELS, &arg) {
                    Some(level) => {
                        if on {
                            set_once(&mut o.log_level, level);
                        }
                    }
                    None => fail!("unsupported log level '{arg}'"),
                }
            }
            Opcode::LogFacility => {
                let arg = args.next().unwrap_or_default();
                match parse_multistate(LOG_FACILITIES, &arg) {
                    // Sic: OpenSSH applies this even in inactive blocks.
                    Some(facility) => set_once(&mut o.log_facility, facility),
                    None => fail!("unsupported log facility '{arg}'"),
                }
            }
            Opcode::LogVerbose => {
                let total = args.len();
                let mut values = Vec::new();
                while let Some(arg) = args.next() {
                    if arg.is_empty() {
                        fail!("keyword {keyword} empty argument");
                    }
                    if arg.eq_ignore_ascii_case("none") && total > 1 {
                        fail!("keyword {keyword} \"none\" argument must appear alone.");
                    }
                    values.push(arg);
                }
                if on && o.log_verbose.is_empty() {
                    o.log_verbose = values;
                }
            }
            Opcode::LocalForward | Opcode::RemoteForward | Opcode::DynamicForward => {
                let first = required!();
                let remote = opcode == Opcode::RemoteForward;
                let mut dynamic = opcode == Opcode::DynamicForward;
                let mut spec = first.clone();
                if !dynamic {
                    match args.next() {
                        Some(target) if !target.is_empty() => spec = format!("{first}:{target}"),
                        _ if remote => dynamic = true,
                        _ => fail!("Missing target argument."),
                    }
                }
                let Some(forward) = parse_forward(&spec, dynamic, remote) else {
                    fail!("Bad forwarding specification.");
                };
                if on {
                    if remote {
                        o.add_remote_forward(forward);
                    } else {
                        o.add_local_forward(forward);
                    }
                }
            }
            Opcode::PermitRemoteOpen => {
                let was_empty = o.permitted_remote_opens.is_empty();
                let total = args.len();
                let mut values = Vec::new();
                while let Some(arg) = args.next() {
                    if arg.eq_ignore_ascii_case("none") || arg.eq_ignore_ascii_case("any") {
                        if total > 1 {
                            fail!("keyword {keyword} \"{arg}\" argument must appear alone.");
                        }
                    } else {
                        let Some(destination) = parse_permit_open(&arg) else {
                            fatal!("missing host in {}", keywords::name(opcode));
                        };
                        if !destination {
                            fatal!("bad port number in {}", keywords::name(opcode));
                        }
                    }
                    values.push(arg);
                }
                if values.is_empty() {
                    fatal!("missing {} specification", keywords::name(opcode));
                }
                if on && was_empty {
                    o.permitted_remote_opens = values;
                }
            }
            Opcode::ClearAllForwardings => flag!(clear_forwardings),
            Opcode::Host => {
                if command_line {
                    self.errors
                        .push("Host directive not supported as a command-line option".into());
                    return Ok(false);
                }
                *active = false;
                while let Some(arg) = args.next() {
                    if arg.is_empty() {
                        fail!("keyword {keyword} empty argument");
                    }
                    if flags.never_match {
                        args.consume();
                        break;
                    }
                    let (negated, pattern) = match arg.strip_prefix('!') {
                        Some(p) => (true, p),
                        None => (false, arg.as_str()),
                    };
                    if match_pattern(&self.context.host, pattern) {
                        if negated {
                            *active = false;
                            args.consume();
                            break;
                        }
                        *active = true;
                    }
                }
            }
            Opcode::Match => {
                if command_line {
                    self.errors
                        .push("Match directive not supported as a command-line option".into());
                    return Ok(false);
                }
                match self.evaluate_match(args, flags.final_pass, origin)? {
                    Some(result) => *active = !flags.never_match && result,
                    None => fail!("Bad Match condition"),
                }
            }
            Opcode::EscapeChar => {
                let arg = required!();
                match parse_escape_char(&arg) {
                    Some(value) => {
                        if on {
                            set_once(&mut o.escape_char, value);
                        }
                    }
                    None => fail!("Bad escape character."),
                }
            }
            Opcode::AddressFamily => multistate!(address_family, ADDRESS_FAMILY),
            Opcode::EnableSSHKeysign => flag!(enable_ssh_keysign),
            Opcode::IdentitiesOnly => flag!(identities_only),
            Opcode::ServerAliveInterval => time!(server_alive_interval),
            Opcode::ServerAliveCountMax => int!(server_alive_count_max),
            Opcode::SendEnv => {
                let mut found = false;
                while let Some(arg) = args.next() {
                    if arg.is_empty() || arg.contains('=') {
                        fail!("Invalid environment name.");
                    }
                    found = true;
                    if !on {
                        continue;
                    }
                    if let Some(pattern) = arg.strip_prefix('-') {
                        // Remove matching names added so far.
                        o.send_env.retain(|name| !match_pattern(name, pattern));
                        continue;
                    }
                    o.send_env.push(arg);
                }
                if !found {
                    fatal!("no {keyword} specified");
                }
            }
            Opcode::SetEnv => {
                let was_empty = o.setenv.is_empty();
                let mut values: Vec<String> = Vec::new();
                while let Some(arg) = args.next() {
                    let Some((name, _)) = arg.split_once('=') else {
                        fail!("Invalid SetEnv.");
                    };
                    if values.iter().any(|v| v.split('=').next() == Some(name)) {
                        continue;
                    }
                    values.push(arg);
                }
                if values.is_empty() {
                    fatal!("no {keyword} specified");
                }
                if on && was_empty {
                    o.setenv = values;
                }
            }
            Opcode::ControlPath => string!(control_path),
            Opcode::ControlMaster => multistate!(control_master, CONTROL_MASTER),
            Opcode::ControlPersist => {
                let arg = match args.next() {
                    Some(arg) if !arg.is_empty() => arg,
                    _ => fail!("Missing ControlPersist argument."),
                };
                let (value, timeout) = match arg.as_str() {
                    "no" | "false" => (0, 0),
                    "yes" | "true" => (1, 0),
                    _ => match sshutils_core::time::parse_interval(&arg) {
                        Some(t) => (1, t as i64),
                        None => fail!("Bad ControlPersist argument."),
                    },
                };
                if on && o.control_persist.is_none() {
                    o.control_persist = Some(value);
                    o.control_persist_timeout = timeout;
                }
            }
            Opcode::HashKnownHosts => flag!(hash_known_hosts),
            Opcode::Tunnel => multistate!(tun_open, TUNNEL),
            Opcode::TunnelDevice => {
                let arg = required!();
                match parse_tunnel_device(&arg) {
                    Some(devices) => {
                        if on {
                            set_once(&mut o.tun_devices, devices);
                        }
                    }
                    None => fail!("Bad tun device."),
                }
            }
            Opcode::PermitLocalCommand => flag!(permit_local_command),
            Opcode::VisualHostKey => flag!(visual_host_key),
            Opcode::Include => {
                if command_line {
                    self.errors
                        .push("Include directive not supported as a command-line option".into());
                    return Ok(false);
                }
                let mut failed = false;
                while let Some(arg) = args.next() {
                    if arg.is_empty() {
                        fail!("keyword {keyword} empty argument");
                    }
                    let path = match self.expand_exec_or_include(&arg, flags.final_pass, true) {
                        Ok(path) => path,
                        Err(_) => {
                            self.error(
                                origin,
                                format!("Unable to expand user config file '{arg}'"),
                            );
                            continue;
                        }
                    };
                    if path.starts_with('~') && !flags.user_config {
                        fail!("bad include path {path}.");
                    }
                    let path = if !path.starts_with('/') && !path.starts_with('~') {
                        if flags.user_config {
                            format!("~/.ssh/{path}")
                        } else {
                            format!("/etc/ssh/{path}")
                        }
                    } else {
                        path
                    };
                    let path = expand_tilde(&path).map_err(|e| Fatal(format!("{path}: {e}")))?;
                    let mut files: Vec<_> = match glob::glob(&path) {
                        Ok(paths) => paths.filter_map(Result::ok).collect(),
                        Err(_) => fail!("glob failed for {path}."),
                    };
                    files.sort();
                    let was_active = *active;
                    for file in files {
                        let nested = Flags {
                            check_permissions: true,
                            never_match: flags.never_match || !was_active,
                            ..flags
                        };
                        let opened = self.read_file_depth(&file, nested, active, depth + 1)?;
                        if !opened && file.exists() {
                            fail!(
                                "Can't open user config file {}: Permission denied",
                                file.display()
                            );
                        }
                        // A Match in an included file doesn't change the
                        // including file's state.
                        *active = was_active;
                        if !opened {
                            failed = true;
                        }
                    }
                }
                if failed {
                    return Ok(false);
                }
            }
            Opcode::IPQoS => {
                let first = args.next().unwrap_or_default();
                let Some(mut interactive) = parse_ipqos(&first) else {
                    fail!("Bad IPQoS value: {first}");
                };
                if interactive == i32::MIN {
                    interactive = i32::MAX;
                }
                let bulk = match args.next() {
                    None => interactive,
                    Some(second) => match parse_ipqos(&second) {
                        Some(i32::MIN) => i32::MAX,
                        Some(value) => value,
                        None => fail!("Bad IPQoS value: {second}"),
                    },
                };
                if on {
                    set_once(&mut o.ip_qos, (interactive, bulk));
                }
            }
            Opcode::RequestTTY => multistate!(request_tty, REQUEST_TTY),
            Opcode::SessionType => multistate!(session_type, SESSION_TYPE),
            Opcode::StdinNull => flag!(stdin_null),
            Opcode::ForkAfterAuthentication => flag!(fork_after_authentication),
            Opcode::IgnoreUnknown => string!(ignored_unknown),
            Opcode::ProxyUseFdpass => flag!(proxy_use_fdpass),
            Opcode::CanonicalDomains => list_once!(canonical_domains, usize::MAX, |arg: &str| {
                if arg.eq_ignore_ascii_case("none") {
                    Ok(())
                } else {
                    valid_domain(arg)
                }
            }),
            Opcode::CanonicalizePermittedCNAMEs => {
                let was_empty = o.permitted_cnames.is_empty();
                let total = args.len();
                let mut values = Vec::new();
                while let Some(arg) = args.next() {
                    let cname = if arg.eq_ignore_ascii_case("none") {
                        if total > 1 {
                            fail!("keyword {keyword} \"none\" argument must appear alone.");
                        }
                        PermittedCname {
                            source: arg.clone(),
                            target: String::new(),
                        }
                    } else if arg == "*" {
                        PermittedCname {
                            source: arg.clone(),
                            target: arg.clone(),
                        }
                    } else {
                        let lower = arg.to_ascii_lowercase();
                        match lower.split_once(':') {
                            Some((source, target)) if !target.is_empty() => PermittedCname {
                                source: source.to_string(),
                                target: target.to_string(),
                            },
                            _ => fail!("Invalid permitted CNAME \"{arg}\""),
                        }
                    };
                    values.push(cname);
                }
                if values.is_empty() {
                    fatal!("no {keyword} specified");
                }
                if on && was_empty {
                    o.permitted_cnames = values;
                }
            }
            Opcode::CanonicalizeHostname => {
                multistate!(canonicalize_hostname, CANONICALIZE_HOSTNAME)
            }
            Opcode::CanonicalizeMaxDots => int!(canonicalize_max_dots),
            Opcode::CanonicalizeFallbackLocal => flag!(canonicalize_fallback_local),
            Opcode::StreamLocalBindMask => {
                let arg = match args.next() {
                    Some(arg) if !arg.is_empty() => arg,
                    _ => fail!("Missing StreamLocalBindMask argument."),
                };
                match parse_octal_prefix(&arg) {
                    Some(mask) if mask <= 0o777 => {
                        // Sic: OpenSSH sets this without first-match-wins.
                        o.streamlocal_bind_mask = Some(mask);
                    }
                    _ => fail!("Bad mask."),
                }
            }
            Opcode::StreamLocalBindUnlink => flag!(streamlocal_bind_unlink),
            Opcode::RevokedHostKeys => list_once!(revoked_host_keys, usize::MAX, any),
            Opcode::FingerprintHash => {
                let arg = required!();
                match parse_multistate(FINGERPRINT_HASHES, &arg) {
                    Some(hash) => {
                        if on {
                            set_once(&mut o.fingerprint_hash, hash);
                        }
                    }
                    None => fail!("Invalid hash algorithm \"{arg}\"."),
                }
            }
            Opcode::UpdateHostkeys => multistate!(update_hostkeys, YES_NO_ASK),
            Opcode::AddKeysToAgent => {
                let first = args.next().unwrap_or_default();
                let second = args.next();
                let state = parse_multistate(YES_NO_ASK_CONFIRM, &first);
                let (value, lifespan) = match (state, &second) {
                    (Some(3), Some(time)) => match sshutils_core::time::parse_interval(time) {
                        Some(t) => (3, t as i64),
                        None => fail!("invalid time value."),
                    },
                    (Some(value), None) => (value, 0),
                    (None, None) => match sshutils_core::time::parse_interval(&first) {
                        Some(t) => (1, t as i64),
                        None => fail!("unsupported option"),
                    },
                    _ => fail!("unsupported option"),
                };
                if on && o.add_keys_to_agent.is_none() {
                    o.add_keys_to_agent = Some(value);
                    o.add_keys_to_agent_lifespan = lifespan;
                }
            }
            Opcode::IdentityAgent => {
                let arg = required!();
                if !valid_agent_path(&arg) {
                    fail!("Invalid environment expansion {arg}.");
                }
                if on {
                    set_once(&mut o.identity_agent, arg);
                }
            }
            Opcode::EnableEscapeCommandline => flag!(enable_escape_commandline),
            Opcode::RequiredRSASize => int!(required_rsa_size),
            Opcode::WarnWeakCrypto => multistate!(warn_weak_crypto, WARN_WEAK_CRYPTO),
            Opcode::ObscureKeystrokeTiming => {
                let mut value = None;
                while let Some(arg) = args.next() {
                    if value.is_some() {
                        fail!("invalid arguments");
                    }
                    value = Some(match arg.as_str() {
                        "yes" | "true" => crate::options::KEYSTROKE_DEFAULT_INTERVAL_MS,
                        "no" | "false" => 0,
                        _ => match arg.strip_prefix("interval:") {
                            Some(ms) => match parse_int(ms) {
                                Ok(ms) if (1..=1000).contains(&ms) => ms,
                                Ok(_) => fail!("value out of range."),
                                Err(e) => fail!("integer value {e}."),
                            },
                            None => fail!("unsupported argument \"{arg}\""),
                        },
                    });
                }
                let Some(value) = value else {
                    fail!("missing argument");
                };
                if on {
                    set_once(&mut o.obscure_keystroke_timing, value);
                }
            }
            Opcode::ChannelTimeout => list_once!(channel_timeouts, usize::MAX, |arg: &str| {
                if arg.eq_ignore_ascii_case("none") || valid_channel_timeout(arg) {
                    Ok(())
                } else {
                    Err(format!("invalid channel timeout {arg}"))
                }
            }),
            Opcode::VersionAddendum => {
                let value = rest.trim_start_matches([' ', '\t', '\r', '\n']);
                if value.contains('\r') {
                    fatal!("Invalid {keyword} argument");
                }
                let value = match value.find('#') {
                    Some(i) => value[..i].trim_end(),
                    None => value,
                };
                if on && o.version_addendum.is_none() {
                    o.version_addendum = Some(if value.eq_ignore_ascii_case("none") {
                        String::new()
                    } else {
                        value.to_string()
                    });
                }
                args.consume();
            }
            Opcode::RefuseConnection => {
                let arg = required!();
                if on {
                    fatal!("RefuseConnection: {arg}");
                }
            }
        }
        Ok(true)
    }

    /// `ProxyJump` / `-J`: set the jump host unless already set (or a
    /// `ProxyCommand` is). Returns false if the value is invalid.
    pub fn apply_jump(&mut self, spec: &str, strict: bool, active: bool) -> bool {
        let o = &mut *self.options;
        if spec.eq_ignore_ascii_case("none") {
            if active && o.jump_host.is_none() {
                o.jump_host = Some("none".into());
                o.jump_port = Some(0);
            }
            return true;
        }
        let Some(jump) = parse_jump(spec, strict) else {
            return false;
        };
        if active && o.proxy_command.is_none() && o.jump_host.is_none() {
            o.jump_user = jump.user;
            o.jump_host = Some(jump.host);
            o.jump_port = jump.port;
            o.jump_extra = jump.extra;
            o.proxy_command = Some("none".into());
        }
        true
    }

    /// Evaluate a `Match` line. `None` means the condition is invalid.
    fn evaluate_match(
        &mut self,
        args: &mut Args,
        final_pass: bool,
        origin: &Origin<'_>,
    ) -> Result<Option<bool>, Fatal> {
        let context = self.context;
        let ruser = self
            .options
            .user
            .clone()
            .unwrap_or_else(|| context.local_user.clone());
        let host = self
            .match_host(final_pass)
            .map_err(|e| Fatal(format!("{} line {}: {e}", origin.file, origin.line)))?;
        let mut result = true;
        let mut attributes = 0;
        while let Some(attribute) = args.next() {
            if attribute.starts_with('#') {
                args.consume();
                break;
            }
            let (negate, name) = match attribute.strip_prefix('!') {
                Some(name) => (true, name.to_string()),
                None => (false, attribute.clone()),
            };
            if name.eq_ignore_ascii_case("all") {
                let next = args.next();
                if attributes > 1
                    || next
                        .as_deref()
                        .is_some_and(|n| !n.is_empty() && !n.starts_with('#'))
                {
                    self.errors.push(format!(
                        "{} line {}: '{attribute}' cannot be combined with other Match attributes",
                        origin.file, origin.line
                    ));
                    return Ok(None);
                }
                if next.as_deref().is_some_and(|n| n.starts_with('#')) {
                    args.consume();
                }
                if result {
                    result = !negate;
                }
                return Ok(Some(result));
            }
            attributes += 1;
            if name.eq_ignore_ascii_case("canonical") || name.eq_ignore_ascii_case("final") {
                if name.eq_ignore_ascii_case("final") && !negate {
                    self.want_final_pass = true;
                }
                if final_pass == negate {
                    result = false;
                }
                continue;
            }
            let lower = name.to_ascii_lowercase();
            let with_value = [
                "host=",
                "originalhost=",
                "user=",
                "localuser=",
                "localnetwork=",
                "version=",
                "tagged=",
                "command=",
                "exec=",
            ];
            let (criterion, value) = if with_value.iter().any(|p| lower.starts_with(p)) {
                let (key, value) = name.split_once('=').expect("prefix contains '='");
                (key.to_ascii_lowercase(), Some(value.to_string()))
            } else {
                match args.next() {
                    Some(value) => (lower.clone(), Some(value)),
                    None => {
                        self.errors.push(format!(
                            "{} line {}: missing argument for Match '{attribute}'",
                            origin.file, origin.line
                        ));
                        return Ok(None);
                    }
                }
            };
            let value =
                value.filter(|v| !v.is_empty() || criterion == "tagged" || criterion == "command");
            let Some(value) = value.filter(|v| !v.starts_with('#')) else {
                self.errors
                    .push(format!("Missing Match criteria for {criterion}"));
                return Ok(None);
            };
            let matched = match criterion.as_str() {
                "host" => match_hostname(&host, &value) == 1,
                "originalhost" => match_hostname(&context.original_host, &value) == 1,
                "user" => match_pattern_list(&ruser, &value, false) == 1,
                "localuser" => match_pattern_list(&context.local_user, &value, false) == 1,
                "version" => match_pattern_list(SSH_RELEASE, &value, false) == 1,
                "tagged" => {
                    let tag = self.options.tag.clone().unwrap_or_default();
                    if tag.is_empty() {
                        value.is_empty()
                    } else {
                        match_pattern_list(&tag, &value, false) == 1
                    }
                }
                "command" => {
                    let command = context.remote_command.clone().unwrap_or_default();
                    if command.is_empty() {
                        value.is_empty()
                    } else {
                        match_pattern_list(&command, &value, false) == 1
                    }
                }
                "sessiontype" => {
                    let kind = match self.options.session_type {
                        Some(SESSION_TYPE_SUBSYSTEM) => "subsystem",
                        Some(SESSION_TYPE_NONE) => "none",
                        _ if context
                            .remote_command
                            .as_deref()
                            .is_some_and(|c| !c.is_empty()) =>
                        {
                            "exec"
                        }
                        _ => "shell",
                    };
                    match_pattern_list(kind, &value, false) == 1
                }
                "exec" => {
                    let command = self
                        .expand_exec_or_include(&value, final_pass, false)
                        .map_err(|_| {
                            Fatal(format!(
                                "{} line {}: failed to expand match exec '{value}'",
                                origin.file, origin.line
                            ))
                        })?;
                    if !result {
                        // A previous criterion already failed.
                        continue;
                    }
                    match run_shell(&command) {
                        Some(status) => status == 0,
                        None => {
                            return Err(Fatal(format!(
                                "{} line {}: match exec '{command}' error",
                                origin.file, origin.line
                            )));
                        }
                    }
                }
                "localnetwork" => {
                    let networks = match parse_network_list(&value) {
                        Ok(networks) => networks,
                        Err(error) => {
                            self.errors.push(error);
                            return Ok(None);
                        }
                    };
                    match local_addresses() {
                        Ok(addresses) => addresses
                            .iter()
                            .any(|a| networks.iter().any(|n| n.contains(a))),
                        Err(e) => {
                            self.errors
                                .push(format!("match localnetwork: getifaddrs failed: {e}"));
                            false
                        }
                    }
                }
                _ => {
                    self.errors
                        .push(format!("Unsupported Match attribute {criterion}"));
                    return Ok(None);
                }
            };
            if matched == negate {
                result = false;
            }
        }
        if attributes == 0 {
            self.errors
                .push("One or more attributes required for Match".into());
            return Ok(None);
        }
        Ok(Some(result))
    }

    /// The host `Match host` and `%h` refer to while reading: the expanded
    /// `Hostname` if set, else the destination.
    fn match_host(&self, final_pass: bool) -> Result<String, expand::ExpandError> {
        let o = &self.options;
        if final_pass {
            return Ok(o.hostname.clone().unwrap_or_default());
        }
        match &o.hostname {
            Some(hostname) => {
                expand::expand(hostname, &[('h', &self.context.original_host)], false)
            }
            None => Ok(self.context.original_host.clone()),
        }
    }

    /// Expand tokens in a `Match exec` command or an `Include` path (which
    /// also gets `${VAR}`).
    fn expand_exec_or_include(
        &self,
        text: &str,
        final_pass: bool,
        include: bool,
    ) -> Result<String, expand::ExpandError> {
        let o = &self.options;
        let context = self.context;
        let host = self.match_host(final_pass)?;
        let port = o.port.filter(|&p| p > 0).unwrap_or(22).to_string();
        let ruser = o.user.clone().unwrap_or_else(|| context.local_user.clone());
        let local = sshutils_core::paths::hostname();
        let short = local.split('.').next().unwrap_or("").to_string();
        let jump = match o.jump_host.as_deref() {
            None | Some("none") => String::new(),
            Some(jump) => jump.to_string(),
        };
        let hash = connection_hash(&local, &host, &port, &ruser, &jump);
        let key_alias = o.host_key_alias.clone().unwrap_or_else(|| host.clone());
        let uid = context.uid.to_string();
        let tokens = [
            ('C', hash.as_str()),
            ('L', short.as_str()),
            ('d', context.home.as_str()),
            ('h', host.as_str()),
            ('k', key_alias.as_str()),
            ('l', local.as_str()),
            ('n', context.original_host.as_str()),
            ('p', port.as_str()),
            ('r', ruser.as_str()),
            ('u', context.local_user.as_str()),
            ('i', uid.as_str()),
            ('j', jump.as_str()),
        ];
        expand::expand(text, &tokens, include)
    }
}

/// Run `command` with `$SHELL -c` (stdin and stdout on /dev/null). Returns
/// its exit status, or `None` if it didn't exit normally.
fn run_shell(command: &str) -> Option<i32> {
    use std::process::{Command, Stdio};
    let shell = std::env::var_os("SHELL").unwrap_or_else(|| "/bin/sh".into());
    let status = Command::new(&shell)
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .ok()?;
    status.code()
}

/// `IdentityAgent`/`ForwardAgent` paths may use `${VAR}` (which must be
/// set); a legacy `$VAR` must be a valid name.
fn valid_agent_path(arg: &str) -> bool {
    if expand::expand_dollar(arg).is_err() {
        return false;
    }
    if let Some(name) = arg.strip_prefix('$')
        && !name.starts_with('{')
    {
        return !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    }
    true
}

/// `PermitRemoteOpen host:port`: `None` without a host, `Some(false)` for
/// a missing or bad port (`*` is allowed).
fn parse_permit_open(arg: &str) -> Option<bool> {
    let (_, rest) = split_host(arg)?;
    Some(match rest {
        Some((_, port)) => port == "*" || parse_port(port).is_some_and(|p| p > 0),
        None => false,
    })
}

/// A domain name for `CanonicalDomains`.
fn valid_domain(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("empty domain name".into());
    }
    let first = name.chars().next().unwrap_or(' ');
    if !first.is_ascii_alphanumeric() && first != '_' {
        return Err(format!(
            "domain name \"{name}\" starts with invalid character"
        ));
    }
    if name.contains("..") {
        return Err(format!(
            "domain name \"{name}\" contains consecutive separators"
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(format!(
            "domain name \"{name}\" contains invalid characters"
        ));
    }
    Ok(())
}

/// `type=interval` for `ChannelTimeout`.
fn valid_channel_timeout(arg: &str) -> bool {
    match arg.split_once('=') {
        Some((pattern, interval)) => {
            !pattern.is_empty() && sshutils_core::time::parse_interval(interval).is_some()
        }
        None => false,
    }
}

/// Parse a leading octal number like `strtol(s, &end, 8)` (trailing text
/// is ignored).
fn parse_octal_prefix(text: &str) -> Option<u32> {
    let digits: String = text
        .chars()
        .take_while(|c| ('0'..='7').contains(c))
        .collect();
    if digits.is_empty() {
        return None;
    }
    u32::from_str_radix(&digits, 8).ok()
}

/// Arguments of a line, consumed from the front.
struct Args {
    args: std::collections::VecDeque<String>,
}

impl Args {
    fn new(args: Vec<String>) -> Self {
        Args { args: args.into() }
    }
    fn next(&mut self) -> Option<String> {
        self.args.pop_front()
    }
    fn peek(&self) -> Option<&str> {
        self.args.front().map(String::as_str)
    }
    fn len(&self) -> usize {
        self.args.len()
    }
    fn is_empty(&self) -> bool {
        self.args.is_empty()
    }
    fn consume(&mut self) {
        self.args.clear();
    }
}
