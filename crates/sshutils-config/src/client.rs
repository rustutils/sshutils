//! Resolving the client configuration the way `ssh` does: command-line
//! options first, then configuration files (with an optional final pass),
//! defaults, and token expansion.

use std::path::PathBuf;

use crate::canonical::{self, Resolver, SystemResolver};
use crate::expand::{self, connection_hash, expand_tilde};
use crate::forward::{Endpoint, valid_user};
use crate::options::Options;
use crate::reader::{Context, Fatal, Flags, Reader};
use crate::values::*;

/// What `ssh` was asked to do, beyond the options set on its command line.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// The destination host as given (after splitting off `user@`).
    pub host: String,
    /// The remote command from the command line (words joined by spaces).
    pub command: String,
    /// `-F`: a configuration file instead of the user and system ones.
    pub config_file: Option<PathBuf>,
    /// The user came from the command line (`-l`, `user@host`).
    pub user_on_command_line: bool,
    /// How `ssh` was invoked, for the `ProxyCommand` built from
    /// `ProxyJump`.
    pub argv0: String,
    /// Number of `-v` flags, passed on to jump hosts.
    pub debug_flag: u8,
}

/// The fully resolved configuration.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub options: Options,
    /// The host to connect to (after `Hostname`, lowercased).
    pub host: String,
    /// The remote command, including an expanded `RemoteCommand`.
    pub command: String,
    /// The host's addresses, if canonicalization already looked them up.
    /// (Their port is the one at the time of the lookup.)
    pub addresses: Option<Vec<std::net::SocketAddr>>,
}

/// Where the user and system configurations live.
const USER_CONFIG: &str = ".ssh/config";
const SYSTEM_CONFIG: &str = "/etc/ssh/ssh_config";

fn local_user() -> (String, String, u32) {
    let user = sshutils_core::paths::current_user();
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    match user {
        Some(user) => (user.name, user.home.to_string_lossy().into_owned(), uid),
        None => (String::new(), "/".into(), uid),
    }
}

/// Read the configuration files for one pass.
fn read_files(
    options: &mut Options,
    context: &Context,
    request: &Request,
    final_pass: bool,
    warnings: &mut Vec<String>,
) -> Result<bool, Fatal> {
    let mut reader = Reader::new(options, context);
    let result = (|| {
        if let Some(path) = &request.config_file {
            if !path.as_os_str().eq_ignore_ascii_case("none") {
                let flags = Flags {
                    user_config: true,
                    final_pass,
                    ..Flags::default()
                };
                if !reader.read_file(path, flags)? {
                    let error = std::fs::File::open(path)
                        .err()
                        .map(|e| io_message(&e))
                        .unwrap_or_default();
                    return Err(Fatal(format!(
                        "Can't open user config file {}: {error}",
                        path.display()
                    )));
                }
            }
        } else {
            let user_config = PathBuf::from(&context.home).join(USER_CONFIG);
            reader.read_file(
                &user_config,
                Flags {
                    user_config: true,
                    check_permissions: true,
                    final_pass,
                    ..Flags::default()
                },
            )?;
            reader.read_file(
                std::path::Path::new(SYSTEM_CONFIG),
                Flags {
                    final_pass,
                    ..Flags::default()
                },
            )?;
        }
        Ok(())
    })();
    warnings.append(&mut reader.errors);
    result.map(|()| reader.want_final_pass)
}

impl Context {
    /// The context for `-o` options: the destination if it is known yet,
    /// no remote command.
    pub fn command_line(host: &str) -> Context {
        let (local_user, home, uid) = local_user();
        Context {
            host: host.to_string(),
            original_host: host.to_string(),
            remote_command: None,
            local_user,
            home,
            uid,
        }
    }
}

/// Resolve the configuration for `request`, starting from `options` (which
/// hold what the command line set, including `-o` options). Problems that
/// OpenSSH reports without stopping are added to `warnings`, also when
/// resolving fails.
pub fn resolve(
    options: Options,
    request: &Request,
    warnings: &mut Vec<String>,
) -> Result<Resolved, Fatal> {
    resolve_with(&SystemResolver, options, request, warnings)
}

/// [`resolve`] with another resolver for host names.
pub fn resolve_with(
    resolver: &dyn Resolver,
    mut options: Options,
    request: &Request,
    warnings: &mut Vec<String>,
) -> Result<Resolved, Fatal> {
    let (local_user, home, uid) = local_user();
    options.host_arg = Some(request.host.clone());
    let remote_command = Some(request.command.clone());

    let mut context = Context {
        host: request.host.clone(),
        original_host: request.host.clone(),
        remote_command: remote_command.clone(),
        local_user: local_user.clone(),
        home: home.clone(),
        uid,
    };
    let mut want_final_pass = read_files(&mut options, &context, request, false, warnings)?;

    // Canonicalization needs these.
    set_once(&mut options.canonicalize_max_dots, 1);
    set_once(&mut options.canonicalize_fallback_local, 1);
    set_once(&mut options.canonicalize_hostname, CANONICALIZE_NO);

    let mut host = request.host.clone();
    if let Some(hostname) = &options.hostname {
        host = expand::expand(hostname, &[('h', &host)], false)
            .map_err(|e| Fatal(format!("percent_expand: {e}")))?;
        options.hostname = Some(host.clone());
    }
    let was_address = canonical::is_address(resolver, &options, &host);
    if !was_address {
        host = host.to_ascii_lowercase();
    }
    let mut addresses = None;
    if options.canonicalize_hostname != Some(CANONICALIZE_NO) || was_address {
        addresses = canonical::canonicalize(resolver, &options, &mut host, warnings)?;
    }
    if addresses.is_none() {
        addresses = canonical::follow_aliases(resolver, &options, &mut host, warnings)?;
    }
    // With canonicalization enabled the configuration is read again, as
    // new blocks may match the canonical name.
    if options.canonicalize_hostname != Some(CANONICALIZE_NO) {
        want_final_pass = true;
    }
    if want_final_pass {
        options.hostname = Some(host.clone());
        context.host = host.clone();
        read_files(&mut options, &context, request, true, warnings)?;
    }

    options.fill_defaults().map_err(Fatal)?;
    let user_was_default = options.user.is_none();
    if user_was_default {
        options.user = Some(local_user.clone());
    }

    if let Some(jump_host) = options.jump_host.clone() {
        let port = options.port.filter(|&p| p > 0).unwrap_or(22);
        let jump_port = options.jump_port.filter(|&p| p > 0).unwrap_or(22);
        let user = options.user.clone().unwrap_or_default();
        let jump_user = options.jump_user.clone().unwrap_or_else(|| user.clone());
        if jump_host == host && port == jump_port && user == jump_user {
            return Err(Fatal(format!("jumphost loop via {jump_host}")));
        }
        if options
            .proxy_command
            .as_deref()
            .is_some_and(|c| !c.eq_ignore_ascii_case("none"))
        {
            return Err(Fatal("inconsistent options: ProxyCommand+ProxyJump".into()));
        }
        options.proxy_use_fdpass = Some(0);
        let mut command = request.argv0.clone();
        if let Some(jump_user) = &options.jump_user {
            command.push_str(&format!(" -l {jump_user}"));
        }
        if let Some(jump_port) = options.jump_port.filter(|&p| p > 0) {
            command.push_str(&format!(" -p {jump_port}"));
        }
        if let Some(extra) = &options.jump_extra {
            command.push_str(&format!(" -J {extra}"));
        }
        if let Some(config) = &request.config_file {
            command.push_str(&format!(" -F {}", config.display()));
        }
        if request.debug_flag > 0 {
            command.push_str(&format!(
                " -{}",
                "v".repeat(usize::from(request.debug_flag.min(3)))
            ));
        }
        command.push_str(&format!(" -W '[%h]:%p' {jump_host}"));
        options.proxy_command = Some(command);
    }

    if options.port == Some(0) {
        options.port = Some(22);
    }
    if let Some(alias) = &mut options.host_key_alias {
        *alias = alias.to_ascii_lowercase();
    }
    if options.proxy_command.as_deref() == Some("-") && options.proxy_use_fdpass == Some(1) {
        return Err(Fatal(
            "ProxyCommand=- and ProxyUseFDPass are incompatible".into(),
        ));
    }
    let mut command = request.command.clone();
    if options.update_hostkeys == Some(2) {
        let persistent_control =
            options.control_persist.unwrap_or(0) != 0 && options.control_path.is_some();
        if persistent_control
            || !command.is_empty()
            || options.remote_command.is_some()
            || options.request_tty == Some(REQUEST_TTY_NO)
            || options.log_level.unwrap_or(LOG_LEVEL_INFO) < LOG_LEVEL_INFO
        {
            options.update_hostkeys = Some(0);
        }
    }
    if options.connection_attempts.unwrap_or(1) <= 0 {
        return Err(Fatal("Invalid number of ConnectionAttempts".into()));
    }
    if !command.is_empty() && options.remote_command.is_some() {
        return Err(Fatal(
            "Cannot execute command-line and remote command.".into(),
        ));
    }
    if options.fork_after_authentication == Some(1)
        && command.is_empty()
        && options.remote_command.is_none()
        && options.session_type != Some(SESSION_TYPE_NONE)
    {
        return Err(Fatal(
            "Cannot fork into background without a command to execute.".into(),
        ));
    }

    // Values for %-tokens.
    let this_host = sshutils_core::paths::hostname();
    let short_host = this_host.split('.').next().unwrap_or("").to_string();
    let port = options.port.unwrap_or(22).to_string();
    let uid_string = uid.to_string();
    let key_alias = options
        .host_key_alias
        .clone()
        .unwrap_or_else(|| request.host.clone());
    let jump_host = options.jump_host.clone().unwrap_or_default();
    let base_tokens = |user_tokens: Option<(&str, &str)>| {
        let mut tokens: Vec<(char, String)> = vec![
            ('L', short_host.clone()),
            ('i', uid_string.clone()),
            ('k', key_alias.clone()),
            ('l', this_host.clone()),
            ('n', request.host.clone()),
            ('p', port.clone()),
            ('d', home.clone()),
            ('h', host.clone()),
            ('u', local_user.clone()),
            ('j', jump_host.clone()),
        ];
        if let Some((hash, user)) = user_tokens {
            tokens.push(('C', hash.to_string()));
            tokens.push(('r', user.to_string()));
        }
        tokens
    };
    let expand_with = |text: &str, tokens: &[(char, String)], dollar: bool| {
        let tokens: Vec<(char, &str)> = tokens.iter().map(|(k, v)| (*k, v.as_str())).collect();
        expand::expand(text, &tokens, dollar)
    };

    let mut user = options.user.clone().unwrap_or_default();
    let mut user_expanded = false;
    if !request.user_on_command_line && !user_was_default {
        let expanded = expand_with(&user, &base_tokens(None), true)
            .map_err(|_| Fatal("invalid environment variable expansion".into()))?;
        user_expanded = expanded != user;
        user = expanded;
    }
    if (request.user_on_command_line || user_expanded) && !valid_user(&user) {
        return Err(Fatal("remote username contains invalid characters".into()));
    }
    options.user = Some(user.clone());
    let hash = connection_hash(&this_host, &host, &port, &user, &jump_host);
    let tokens = base_tokens(Some((&hash, &user)));

    if let Some(remote) = options.remote_command.clone() {
        let expanded =
            expand_with(&remote, &tokens, false).map_err(fatal_expand("RemoteCommand"))?;
        command.push_str(&expanded);
        options.remote_command = Some(expanded);
    }
    let tilde = |path: &str| expand_tilde(path).map_err(|e| Fatal(format!("{path}: {e}")));
    let path_option =
        |value: &Option<String>, what: &'static str| -> Result<Option<String>, Fatal> {
            match value {
                None => Ok(None),
                Some(value) => {
                    let expanded =
                        expand_with(&tilde(value)?, &tokens, true).map_err(fatal_expand(what))?;
                    Ok(Some(expanded))
                }
            }
        };
    options.control_path = path_option(&options.control_path, "ControlPath")?;
    options.identity_agent = path_option(&options.identity_agent, "IdentityAgent")?;
    options.revoked_host_keys = options
        .revoked_host_keys
        .iter()
        .map(|p| Ok(path_option(&Some(p.clone()), "RevokedHostKeys")?.unwrap_or_default()))
        .collect::<Result<_, Fatal>>()?;
    if let Some(path) = path_option(&options.forward_agent_sock_path, "ForwardAgent")? {
        if let Err(e) = std::fs::metadata(&path) {
            warnings.push(format!(
                "Cannot forward agent socket path \"{path}\": {}",
                io_message(&e)
            ));
            if options.exit_on_forward_failure == Some(1) {
                return Err(Fatal(String::new()));
            }
        }
        options.forward_agent_sock_path = Some(path);
    }
    if let Some(addendum) = &options.version_addendum {
        options.version_addendum =
            Some(expand_with(addendum, &tokens, true).map_err(fatal_expand("VersionAddendum"))?);
    }
    for (files, what) in [
        (&mut options.system_hostfiles, "GlobalKnownHostsFiles"),
        (&mut options.user_hostfiles, "UserKnownHostsFiles"),
    ] {
        if files
            .first()
            .is_some_and(|f| f.eq_ignore_ascii_case("none"))
        {
            if files.len() > 1 {
                return Err(Fatal(format!(
                    "Invalid {what}: \"none\" appears with other entries"
                )));
            }
            files.clear();
        }
    }
    options.user_hostfiles = options
        .user_hostfiles
        .iter()
        .map(|f| expand_with(&tilde(f)?, &tokens, true).map_err(fatal_expand("UserKnownHostsFile")))
        .collect::<Result<_, Fatal>>()?;
    options.setenv = options
        .setenv
        .iter()
        .map(|entry| {
            let (name, value) = entry.split_once('=').unwrap_or((entry, ""));
            let value = expand_with(value, &tokens, true).map_err(fatal_expand("SetEnv"))?;
            Ok(format!("{name}={value}"))
        })
        .collect::<Result<_, Fatal>>()?;
    for forward in options
        .local_forwards
        .iter_mut()
        .chain(options.remote_forwards.iter_mut())
    {
        for endpoint in std::iter::once(&mut forward.listen).chain(forward.connect.as_mut()) {
            if let Endpoint::Path(path) = endpoint {
                *path = expand_with(path, &tokens, false).map_err(fatal_expand("forward path"))?;
            }
        }
    }

    Ok(Resolved {
        options,
        host,
        command,
        addresses,
    })
}

/// Turn an expansion error for `what` into a fatal error.
fn fatal_expand(what: &'static str) -> impl Fn(expand::ExpandError) -> Fatal {
    move |e| Fatal(format!("{what}: {e}"))
}

fn set_once<T>(slot: &mut Option<T>, value: T) {
    crate::options::set_once(slot, value);
}

fn io_message(err: &std::io::Error) -> String {
    let message = err.to_string();
    match message.find(" (os error ") {
        Some(i) => message[..i].to_string(),
        None => message,
    }
}
