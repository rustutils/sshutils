//! The client options, their defaults and `ssh -G` output.
//!
//! Fields mirror OpenSSH's `Options`: `None` (or an empty list) means "not
//! set yet". Configuration is first-match-wins, so values are only set when
//! still unset; [`Options::fill_defaults`] supplies the rest.

use std::fmt::Write as _;

use crate::algorithms;
use crate::forward::{Forward, format_endpoint};
use crate::keywords::{Opcode, name};
use crate::values::*;

/// `PermittedCNAMEs` entry: source and target domain patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermittedCname {
    pub source: String,
    pub target: String,
}

/// An identity or certificate file and whether the user named it (as
/// opposed to the defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFile {
    pub path: String,
    pub user_provided: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub host_arg: Option<String>,
    pub forward_agent: Option<i32>,
    pub forward_agent_sock_path: Option<String>,
    pub forward_x11: Option<i32>,
    pub forward_x11_trusted: Option<i32>,
    pub forward_x11_timeout: Option<i64>,
    pub exit_on_forward_failure: Option<i32>,
    pub clear_forwardings: Option<i32>,
    pub xauth_location: Option<String>,
    pub gateway_ports: Option<i32>,
    pub streamlocal_bind_mask: Option<u32>,
    pub streamlocal_bind_unlink: Option<i32>,
    pub pubkey_authentication: Option<i32>,
    pub gss_authentication: Option<i32>,
    pub gss_deleg_creds: Option<i32>,
    pub password_authentication: Option<i32>,
    pub kbd_interactive_authentication: Option<i32>,
    pub kbd_interactive_devices: Option<String>,
    pub hostbased_authentication: Option<i32>,
    pub batch_mode: Option<i32>,
    pub check_host_ip: Option<i32>,
    pub strict_host_key_checking: Option<i32>,
    pub compression: Option<i32>,
    pub tcp_keep_alive: Option<i32>,
    pub port: Option<i32>,
    pub address_family: Option<i32>,
    pub connection_attempts: Option<i32>,
    pub connection_timeout: Option<i64>,
    pub number_of_password_prompts: Option<i32>,
    pub ciphers: Option<String>,
    pub macs: Option<String>,
    pub kex_algorithms: Option<String>,
    pub hostkey_algorithms: Option<String>,
    pub ca_sign_algorithms: Option<String>,
    pub hostbased_accepted_algorithms: Option<String>,
    pub pubkey_accepted_algorithms: Option<String>,
    pub hostname: Option<String>,
    pub host_key_alias: Option<String>,
    pub proxy_command: Option<String>,
    pub user: Option<String>,
    pub escape_char: Option<i32>,
    pub log_level: Option<i32>,
    pub log_facility: Option<i32>,
    pub log_verbose: Vec<String>,
    pub preferred_authentications: Option<String>,
    pub bind_address: Option<String>,
    pub bind_interface: Option<String>,
    pub pkcs11_provider: Option<String>,
    pub sk_provider: Option<String>,
    pub known_hosts_command: Option<String>,
    pub identity_files: Vec<KeyFile>,
    pub certificate_files: Vec<KeyFile>,
    pub add_keys_to_agent: Option<i32>,
    pub add_keys_to_agent_lifespan: i64,
    pub identity_agent: Option<String>,
    pub system_hostfiles: Vec<String>,
    pub user_hostfiles: Vec<String>,
    pub local_forwards: Vec<Forward>,
    pub remote_forwards: Vec<Forward>,
    pub permitted_remote_opens: Vec<String>,
    pub identities_only: Option<i32>,
    pub enable_ssh_keysign: Option<i32>,
    pub no_host_authentication_for_localhost: Option<i32>,
    pub rekey_limit: Option<i64>,
    pub rekey_interval: Option<i64>,
    pub verify_host_key_dns: Option<i32>,
    pub update_hostkeys: Option<i32>,
    pub server_alive_interval: Option<i64>,
    pub server_alive_count_max: Option<i32>,
    pub send_env: Vec<String>,
    pub setenv: Vec<String>,
    pub control_path: Option<String>,
    pub control_master: Option<i32>,
    pub control_persist: Option<i32>,
    pub control_persist_timeout: i64,
    pub hash_known_hosts: Option<i32>,
    pub tun_open: Option<i32>,
    pub tun_devices: Option<(i64, i64)>,
    pub local_command: Option<String>,
    pub permit_local_command: Option<i32>,
    pub remote_command: Option<String>,
    pub visual_host_key: Option<i32>,
    pub ip_qos: Option<(i32, i32)>,
    pub request_tty: Option<i32>,
    pub session_type: Option<i32>,
    pub stdin_null: Option<i32>,
    pub fork_after_authentication: Option<i32>,
    pub proxy_use_fdpass: Option<i32>,
    pub ignored_unknown: Option<String>,
    pub canonical_domains: Vec<String>,
    pub canonicalize_hostname: Option<i32>,
    pub canonicalize_max_dots: Option<i32>,
    pub canonicalize_fallback_local: Option<i32>,
    pub permitted_cnames: Vec<PermittedCname>,
    pub revoked_host_keys: Vec<String>,
    pub fingerprint_hash: Option<i32>,
    pub enable_escape_commandline: Option<i32>,
    pub required_rsa_size: Option<i32>,
    pub warn_weak_crypto: Option<i32>,
    pub obscure_keystroke_timing: Option<i32>,
    pub channel_timeouts: Vec<String>,
    pub version_addendum: Option<String>,
    pub tag: Option<String>,
    pub jump_host: Option<String>,
    pub jump_user: Option<String>,
    pub jump_port: Option<i32>,
    pub jump_extra: Option<String>,
    /// `-W host:port`.
    pub stdio_forward: Option<(String, i32)>,
}

/// Default lifetime of `ObscureKeystrokeTiming` packets, in milliseconds.
pub const KEYSTROKE_DEFAULT_INTERVAL_MS: i32 = 20;
/// Smallest RSA key OpenSSH accepts by default.
pub const RSA_MINIMUM_MODULUS_SIZE: i32 = 1024;
/// Where `xauth` lives on Linux systems.
const XAUTH_PATH: &str = "/usr/bin/xauth";

/// Set `slot` if unset (first match wins).
pub fn set_once<T>(slot: &mut Option<T>, value: T) {
    if slot.is_none() {
        *slot = Some(value);
    }
}

impl Options {
    /// Add an identity file, ignoring exact duplicates.
    pub fn add_identity_file(&mut self, path: String, user_provided: bool) {
        add_key_file(&mut self.identity_files, path, user_provided);
    }

    /// Add a certificate file, ignoring exact duplicates.
    pub fn add_certificate_file(&mut self, path: String, user_provided: bool) {
        add_key_file(&mut self.certificate_files, path, user_provided);
    }

    /// Add a local or dynamic forward, ignoring duplicates.
    pub fn add_local_forward(&mut self, forward: Forward) {
        if !self.local_forwards.contains(&forward) {
            self.local_forwards.push(forward);
        }
    }

    /// Add a remote forward, ignoring duplicates.
    pub fn add_remote_forward(&mut self, forward: Forward) {
        if !self.remote_forwards.contains(&forward) {
            self.remote_forwards.push(forward);
        }
    }

    /// Fill in OpenSSH's defaults for options still unset, and resolve
    /// algorithm lists. Fails if an algorithm list resolves to nothing.
    pub fn fill_defaults(&mut self) -> Result<(), String> {
        set_once(&mut self.forward_agent, 0);
        set_once(&mut self.forward_x11, 0);
        set_once(&mut self.forward_x11_trusted, 0);
        set_once(&mut self.forward_x11_timeout, 1200);
        // stdio forwarding (-W) changes these defaults.
        let stdio = i32::from(self.stdio_forward.is_some());
        set_once(&mut self.exit_on_forward_failure, stdio);
        set_once(&mut self.clear_forwardings, stdio);
        if self.clear_forwardings == Some(1) {
            self.local_forwards.clear();
            self.remote_forwards.clear();
        }
        set_once(&mut self.xauth_location, XAUTH_PATH.to_string());
        set_once(&mut self.gateway_ports, 0);
        set_once(&mut self.streamlocal_bind_mask, 0o177);
        set_once(&mut self.streamlocal_bind_unlink, 0);
        set_once(&mut self.pubkey_authentication, PUBKEY_AUTH_ALL);
        set_once(&mut self.gss_authentication, 0);
        set_once(&mut self.gss_deleg_creds, 0);
        set_once(&mut self.password_authentication, 1);
        set_once(&mut self.kbd_interactive_authentication, 1);
        set_once(&mut self.hostbased_authentication, 0);
        set_once(&mut self.batch_mode, 0);
        set_once(&mut self.check_host_ip, 0);
        set_once(&mut self.strict_host_key_checking, STRICT_HOSTKEY_ASK);
        set_once(&mut self.compression, 0);
        set_once(&mut self.tcp_keep_alive, 1);
        set_once(&mut self.port, 0);
        set_once(&mut self.address_family, AF_UNSPEC);
        set_once(&mut self.connection_attempts, 1);
        set_once(&mut self.number_of_password_prompts, 3);
        if self.add_keys_to_agent.is_none() {
            self.add_keys_to_agent = Some(0);
            self.add_keys_to_agent_lifespan = 0;
        }
        if self.identity_files.is_empty() {
            for name in [
                "id_rsa",
                "id_ecdsa",
                "id_ecdsa_sk",
                "id_ed25519",
                "id_ed25519_sk",
                "id_mldsa44_ed25519",
            ] {
                self.add_identity_file(format!("~/.ssh/{name}"), false);
            }
        }
        set_once(&mut self.escape_char, i32::from(b'~'));
        if self.system_hostfiles.is_empty() {
            self.system_hostfiles = vec![
                "/etc/ssh/ssh_known_hosts".into(),
                "/etc/ssh/ssh_known_hosts2".into(),
            ];
        }
        if self.update_hostkeys.is_none() {
            let default_files = self.user_hostfiles.is_empty()
                || (self.user_hostfiles.len() == 1
                    && self.user_hostfiles[0] == "~/.ssh/known_hosts");
            let dns = self.verify_host_key_dns.unwrap_or(0);
            self.update_hostkeys = Some(i32::from(dns <= 0 && default_files));
        }
        if self.user_hostfiles.is_empty() {
            self.user_hostfiles = vec!["~/.ssh/known_hosts".into(), "~/.ssh/known_hosts2".into()];
        }
        set_once(&mut self.log_level, LOG_LEVEL_INFO);
        set_once(&mut self.log_facility, LOG_FACILITY_USER);
        set_once(&mut self.no_host_authentication_for_localhost, 0);
        set_once(&mut self.identities_only, 0);
        set_once(&mut self.enable_ssh_keysign, 0);
        set_once(&mut self.rekey_limit, 0);
        set_once(&mut self.rekey_interval, 0);
        set_once(&mut self.verify_host_key_dns, 0);
        set_once(&mut self.server_alive_interval, 0);
        set_once(&mut self.server_alive_count_max, 3);
        set_once(&mut self.control_master, CONTROL_MASTER_NO);
        if self.control_persist.is_none() {
            self.control_persist = Some(0);
            self.control_persist_timeout = 0;
        }
        set_once(&mut self.hash_known_hosts, 0);
        set_once(&mut self.tun_open, TUNNEL_NO);
        set_once(&mut self.tun_devices, (TUNID_ANY, TUNID_ANY));
        set_once(&mut self.permit_local_command, 0);
        set_once(&mut self.visual_host_key, 0);
        set_once(&mut self.ip_qos, (IPQOS_EF, IPQOS_CS0));
        set_once(&mut self.request_tty, REQUEST_TTY_AUTO);
        set_once(&mut self.session_type, SESSION_TYPE_DEFAULT);
        set_once(&mut self.stdin_null, 0);
        set_once(&mut self.fork_after_authentication, 0);
        set_once(&mut self.proxy_use_fdpass, 0);
        set_once(&mut self.canonicalize_max_dots, 1);
        set_once(&mut self.canonicalize_fallback_local, 1);
        set_once(&mut self.canonicalize_hostname, CANONICALIZE_NO);
        set_once(&mut self.fingerprint_hash, FINGERPRINT_SHA256);
        set_once(&mut self.sk_provider, "internal".to_string());
        set_once(&mut self.required_rsa_size, RSA_MINIMUM_MODULUS_SIZE);
        set_once(&mut self.warn_weak_crypto, 1);
        set_once(&mut self.enable_escape_commandline, 0);
        set_once(
            &mut self.obscure_keystroke_timing,
            KEYSTROKE_DEFAULT_INTERVAL_MS,
        );

        let assemble = |list: &Option<String>, default: &str, all: &str, what: &str| {
            algorithms::assemble(list.as_deref(), default, all)
                .ok_or_else(|| format!("{what}: invalid argument"))
        };
        self.ciphers = Some(assemble(
            &self.ciphers,
            algorithms::DEFAULT_CIPHERS,
            algorithms::ALL_CIPHERS,
            "ciphers",
        )?);
        self.macs = Some(assemble(
            &self.macs,
            algorithms::DEFAULT_MACS,
            algorithms::ALL_MACS,
            "macs",
        )?);
        self.kex_algorithms = Some(assemble(
            &self.kex_algorithms,
            algorithms::DEFAULT_KEX,
            algorithms::ALL_KEX,
            "kex_algorithms",
        )?);
        self.hostbased_accepted_algorithms = Some(assemble(
            &self.hostbased_accepted_algorithms,
            algorithms::DEFAULT_KEY,
            algorithms::ALL_KEY,
            "hostbased_accepted_algos",
        )?);
        self.pubkey_accepted_algorithms = Some(assemble(
            &self.pubkey_accepted_algorithms,
            algorithms::DEFAULT_KEY,
            algorithms::ALL_KEY,
            "pubkey_accepted_algos",
        )?);
        self.ca_sign_algorithms = Some(assemble(
            &self.ca_sign_algorithms,
            algorithms::DEFAULT_CA_SIG,
            algorithms::ALL_SIG,
            "ca_sign_algorithms",
        )?);

        // "none" clears these.
        for slot in [
            &mut self.local_command,
            &mut self.remote_command,
            &mut self.proxy_command,
            &mut self.control_path,
            &mut self.pkcs11_provider,
            &mut self.sk_provider,
            &mut self.known_hosts_command,
        ] {
            if slot
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case("none"))
            {
                *slot = None;
            }
        }
        for list in [&mut self.channel_timeouts, &mut self.revoked_host_keys] {
            if list.len() == 1 && list[0].eq_ignore_ascii_case("none") {
                list.clear();
            }
        }
        if self.jump_host.as_deref() == Some("none")
            && self.jump_port.unwrap_or(0) == 0
            && self.jump_user.is_none()
        {
            self.jump_host = None;
        }
        // `CanonicalizePermittedCNAMEs none`.
        if self.permitted_cnames.len() == 1 && !crate::canonical::has_permitted_cnames(self) {
            self.permitted_cnames.clear();
        }
        Ok(())
    }

    /// The `ssh -G` output, given the final host name.
    pub fn dump(&self, host: &str) -> String {
        let mut out = String::new();
        let mut line = |opcode: Opcode, value: &str| {
            let _ = writeln!(out, "{} {value}", name(opcode));
        };
        let flag = |v: Option<i32>| v.map_or("unset", format_flag);
        let state =
            |table: Multistate, v: Option<i32>| v.map_or("unset", |v| format_multistate(table, v));

        // Expand HostKeyAlgorithms like OpenSSH does just for printing.
        let hostkey_algorithms = algorithms::assemble(
            self.hostkey_algorithms.as_deref(),
            algorithms::DEFAULT_KEY,
            algorithms::ALL_KEY,
        );

        if let Some(host_arg) = &self.host_arg {
            line(Opcode::Host, host_arg);
        }
        if let Some(user) = &self.user {
            line(Opcode::User, user);
        }
        line(Opcode::Hostname, host);
        line(Opcode::Port, &self.port.unwrap_or(-1).to_string());

        line(
            Opcode::AddressFamily,
            state(ADDRESS_FAMILY, self.address_family),
        );
        line(Opcode::BatchMode, flag(self.batch_mode));
        line(
            Opcode::CanonicalizeFallbackLocal,
            flag(self.canonicalize_fallback_local),
        );
        line(
            Opcode::CanonicalizeHostname,
            state(CANONICALIZE_HOSTNAME, self.canonicalize_hostname),
        );
        line(Opcode::CheckHostIP, flag(self.check_host_ip));
        line(Opcode::Compression, state(COMPRESSION, self.compression));
        line(
            Opcode::ControlMaster,
            state(CONTROL_MASTER, self.control_master),
        );
        line(Opcode::EnableSSHKeysign, flag(self.enable_ssh_keysign));
        line(Opcode::ClearAllForwardings, flag(self.clear_forwardings));
        line(
            Opcode::ExitOnForwardFailure,
            flag(self.exit_on_forward_failure),
        );
        line(
            Opcode::FingerprintHash,
            state(FINGERPRINT_HASHES, self.fingerprint_hash),
        );
        line(Opcode::ForwardX11, flag(self.forward_x11));
        line(Opcode::ForwardX11Trusted, flag(self.forward_x11_trusted));
        line(Opcode::GatewayPorts, flag(self.gateway_ports));
        line(Opcode::GssAuthentication, flag(self.gss_authentication));
        line(Opcode::GssDelegateCreds, flag(self.gss_deleg_creds));
        line(Opcode::HashKnownHosts, flag(self.hash_known_hosts));
        line(
            Opcode::HostbasedAuthentication,
            flag(self.hostbased_authentication),
        );
        line(Opcode::IdentitiesOnly, flag(self.identities_only));
        line(
            Opcode::KbdInteractiveAuthentication,
            flag(self.kbd_interactive_authentication),
        );
        line(
            Opcode::NoHostAuthenticationForLocalhost,
            flag(self.no_host_authentication_for_localhost),
        );
        line(
            Opcode::PasswordAuthentication,
            flag(self.password_authentication),
        );
        line(Opcode::PermitLocalCommand, flag(self.permit_local_command));
        line(Opcode::ProxyUseFdpass, flag(self.proxy_use_fdpass));
        line(
            Opcode::PubkeyAuthentication,
            state(PUBKEY_AUTH, self.pubkey_authentication),
        );
        line(Opcode::RequestTTY, state(REQUEST_TTY, self.request_tty));
        line(Opcode::SessionType, state(SESSION_TYPE, self.session_type));
        line(Opcode::StdinNull, flag(self.stdin_null));
        line(
            Opcode::ForkAfterAuthentication,
            flag(self.fork_after_authentication),
        );
        line(
            Opcode::StreamLocalBindUnlink,
            flag(self.streamlocal_bind_unlink),
        );
        line(
            Opcode::StrictHostKeyChecking,
            state(STRICT_HOSTKEY, self.strict_host_key_checking),
        );
        line(Opcode::TCPKeepAlive, flag(self.tcp_keep_alive));
        line(Opcode::Tunnel, state(TUNNEL, self.tun_open));
        line(
            Opcode::VerifyHostKeyDNS,
            state(YES_NO_ASK, self.verify_host_key_dns),
        );
        line(Opcode::VisualHostKey, flag(self.visual_host_key));
        line(
            Opcode::UpdateHostkeys,
            state(YES_NO_ASK, self.update_hostkeys),
        );
        line(
            Opcode::EnableEscapeCommandline,
            flag(self.enable_escape_commandline),
        );
        line(Opcode::WarnWeakCrypto, flag(self.warn_weak_crypto));

        let int = |v: Option<i64>| v.unwrap_or(-1).to_string();
        line(
            Opcode::CanonicalizeMaxDots,
            &int(self.canonicalize_max_dots.map(i64::from)),
        );
        line(
            Opcode::ConnectionAttempts,
            &int(self.connection_attempts.map(i64::from)),
        );
        line(Opcode::ForwardX11Timeout, &int(self.forward_x11_timeout));
        line(
            Opcode::NumberOfPasswordPrompts,
            &int(self.number_of_password_prompts.map(i64::from)),
        );
        line(
            Opcode::ServerAliveCountMax,
            &int(self.server_alive_count_max.map(i64::from)),
        );
        line(
            Opcode::ServerAliveInterval,
            &int(self.server_alive_interval),
        );
        line(
            Opcode::RequiredRSASize,
            &int(self.required_rsa_size.map(i64::from)),
        );
        let obscure = match self.obscure_keystroke_timing {
            Some(0) => "no".to_string(),
            Some(KEYSTROKE_DEFAULT_INTERVAL_MS) => "yes".to_string(),
            other => int(other.map(i64::from)),
        };
        line(Opcode::ObscureKeystrokeTiming, &obscure);

        let mut string = |opcode: Opcode, value: Option<&str>| {
            if let Some(value) = value {
                line(opcode, value);
            }
        };
        string(Opcode::BindAddress, self.bind_address.as_deref());
        string(Opcode::BindInterface, self.bind_interface.as_deref());
        string(Opcode::Ciphers, self.ciphers.as_deref());
        string(Opcode::ControlPath, self.control_path.as_deref());
        string(Opcode::HostKeyAlgorithms, hostkey_algorithms.as_deref());
        string(Opcode::HostKeyAlias, self.host_key_alias.as_deref());
        string(
            Opcode::HostbasedAcceptedAlgorithms,
            self.hostbased_accepted_algorithms.as_deref(),
        );
        string(Opcode::IdentityAgent, self.identity_agent.as_deref());
        string(Opcode::IgnoreUnknown, self.ignored_unknown.as_deref());
        string(
            Opcode::KbdInteractiveDevices,
            self.kbd_interactive_devices.as_deref(),
        );
        string(Opcode::KexAlgorithms, self.kex_algorithms.as_deref());
        string(
            Opcode::CASignatureAlgorithms,
            self.ca_sign_algorithms.as_deref(),
        );
        string(Opcode::LocalCommand, self.local_command.as_deref());
        string(Opcode::RemoteCommand, self.remote_command.as_deref());
        let log_level = self.log_level.map(|v| format_multistate(LOG_LEVELS, v));
        string(Opcode::LogLevel, Some(log_level.unwrap_or("UNKNOWN")));
        string(Opcode::Macs, self.macs.as_deref());
        string(Opcode::PKCS11Provider, self.pkcs11_provider.as_deref());
        string(Opcode::SecurityKeyProvider, self.sk_provider.as_deref());
        string(
            Opcode::PreferredAuthentications,
            self.preferred_authentications.as_deref(),
        );
        string(
            Opcode::PubkeyAcceptedAlgorithms,
            self.pubkey_accepted_algorithms.as_deref(),
        );
        string(Opcode::XAuthLocation, self.xauth_location.as_deref());
        string(
            Opcode::KnownHostsCommand,
            self.known_hosts_command.as_deref(),
        );
        string(Opcode::Tag, self.tag.as_deref());
        string(Opcode::VersionAddendum, self.version_addendum.as_deref());

        dump_forwards(&mut out, &self.local_forwards, &self.remote_forwards);

        let mut each = |opcode: Opcode, values: &[String]| {
            for value in values {
                let _ = writeln!(out, "{} {value}", name(opcode));
            }
        };
        let identity_files: Vec<String> =
            self.identity_files.iter().map(|f| f.path.clone()).collect();
        each(Opcode::IdentityFile, &identity_files);
        oneline(&mut out, Opcode::CanonicalDomains, &self.canonical_domains);
        let certificate_files: Vec<String> = self
            .certificate_files
            .iter()
            .map(|f| f.path.clone())
            .collect();
        for file in &certificate_files {
            let _ = writeln!(out, "{} {file}", name(Opcode::CertificateFile));
        }
        oneline(
            &mut out,
            Opcode::GlobalKnownHostsFile,
            &self.system_hostfiles,
        );
        oneline(&mut out, Opcode::UserKnownHostsFile, &self.user_hostfiles);
        oneline(&mut out, Opcode::RevokedHostKeys, &self.revoked_host_keys);
        for value in &self.send_env {
            let _ = writeln!(out, "{} {value}", name(Opcode::SendEnv));
        }
        for value in &self.setenv {
            let _ = writeln!(out, "{} {value}", name(Opcode::SetEnv));
        }
        oneline(&mut out, Opcode::LogVerbose, &self.log_verbose);
        oneline(&mut out, Opcode::ChannelTimeout, &self.channel_timeouts);

        if self.permitted_remote_opens.is_empty() {
            let _ = writeln!(out, "{} any", name(Opcode::PermitRemoteOpen));
        } else {
            oneline(
                &mut out,
                Opcode::PermitRemoteOpen,
                &self.permitted_remote_opens,
            );
        }

        let add_keys = self.add_keys_to_agent;
        if self.add_keys_to_agent_lifespan <= 0 {
            let value = add_keys.map_or("unset", |v| format_multistate(YES_NO_ASK_CONFIRM, v));
            let _ = writeln!(out, "addkeystoagent {value}");
        } else {
            let confirm = if add_keys == Some(3) { " confirm" } else { "" };
            let _ = writeln!(
                out,
                "addkeystoagent{confirm} {}",
                self.add_keys_to_agent_lifespan
            );
        }

        match &self.forward_agent_sock_path {
            None => {
                let _ = writeln!(out, "forwardagent {}", flag(self.forward_agent));
            }
            Some(path) => {
                let _ = writeln!(out, "forwardagent {path}");
            }
        }

        match self.connection_timeout {
            None => {
                let _ = writeln!(out, "connecttimeout none");
            }
            Some(timeout) => {
                let _ = writeln!(out, "connecttimeout {timeout}");
            }
        }

        let (local, remote) = self.tun_devices.unwrap_or((TUNID_ANY, TUNID_ANY));
        let tun = |id: i64| {
            if id == TUNID_ANY {
                "any".to_string()
            } else {
                id.to_string()
            }
        };
        let _ = writeln!(out, "tunneldevice {}:{}", tun(local), tun(remote));

        // Sic: OpenSSH 10.5 prints this name with odd capitalisation.
        let _ = write!(out, "canonicalizePermittedcnames");
        if self.permitted_cnames.is_empty() {
            let _ = write!(out, " none");
        }
        for cname in &self.permitted_cnames {
            let _ = write!(out, " {}:{}", cname.source, cname.target);
        }
        let _ = writeln!(out);

        if self.control_persist.unwrap_or(0) == 0 || self.control_persist_timeout == 0 {
            let _ = writeln!(out, "controlpersist {}", flag(self.control_persist));
        } else {
            let _ = writeln!(out, "controlpersist {}", self.control_persist_timeout);
        }

        let escape = self
            .escape_char
            .map_or("unset".to_string(), format_escape_char);
        let _ = writeln!(out, "escapechar {escape}");

        let (interactive, bulk) = self.ip_qos.unwrap_or((-1, -1));
        let _ = writeln!(
            out,
            "ipqos {} {}",
            format_ipqos(interactive),
            format_ipqos(bulk)
        );
        let _ = writeln!(
            out,
            "rekeylimit {} {}",
            self.rekey_limit.unwrap_or(0),
            self.rekey_interval.unwrap_or(0)
        );
        let _ = writeln!(
            out,
            "streamlocalbindmask 0{:o}",
            self.streamlocal_bind_mask.unwrap_or(0o177)
        );
        let facility = self
            .log_facility
            .map_or("UNKNOWN", |v| format_multistate(LOG_FACILITIES, v));
        let _ = writeln!(out, "syslogfacility {facility}");

        match &self.jump_host {
            None => {
                if let Some(command) = &self.proxy_command {
                    let _ = writeln!(out, "proxycommand {command}");
                }
            }
            Some(jump_host) => {
                let numeric = jump_host.contains(':')
                    || jump_host.chars().all(|c| c.is_ascii_digit() || c == '.');
                let mut spec = String::new();
                if let Some(extra) = &self.jump_extra {
                    spec.push_str(extra);
                    spec.push(',');
                }
                if let Some(user) = &self.jump_user {
                    spec.push_str(user);
                    spec.push('@');
                }
                if numeric {
                    let _ = write!(spec, "[{jump_host}]");
                } else {
                    spec.push_str(jump_host);
                }
                if let Some(port) = self.jump_port.filter(|&p| p > 0) {
                    let _ = write!(spec, ":{port}");
                }
                let _ = writeln!(out, "proxyjump {spec}");
            }
        }
        out
    }
}

fn add_key_file(files: &mut Vec<KeyFile>, path: String, user_provided: bool) {
    if !files
        .iter()
        .any(|f| f.user_provided == user_provided && f.path == path)
    {
        files.push(KeyFile {
            path,
            user_provided,
        });
    }
}

/// `keyword a b c` or `keyword none`.
fn oneline(out: &mut String, opcode: Opcode, values: &[String]) {
    let _ = write!(out, "{}", name(opcode));
    if values.is_empty() {
        let _ = write!(out, " none");
    }
    for value in values {
        let _ = write!(out, " {value}");
    }
    let _ = writeln!(out);
}

/// Dynamic, local and remote forwards, as `ssh -G` prints them.
fn dump_forwards(out: &mut String, local: &[Forward], remote: &[Forward]) {
    let print = |out: &mut String, opcode: Opcode, forward: &Forward, with_connect: bool| {
        let _ = write!(out, "{} {}", name(opcode), format_endpoint(&forward.listen));
        if with_connect {
            match &forward.connect {
                Some(connect) => {
                    let _ = write!(out, " {}", format_endpoint(connect));
                }
                // OpenSSH stores a dynamic forward's target as host
                // "socks", port 0.
                None => {
                    let _ = write!(out, " [socks]:0");
                }
            }
        }
        let _ = writeln!(out);
    };
    for forward in local.iter().filter(|f| f.is_dynamic()) {
        print(out, Opcode::DynamicForward, forward, false);
    }
    for forward in local.iter().filter(|f| !f.is_dynamic()) {
        print(out, Opcode::LocalForward, forward, true);
    }
    for forward in remote {
        print(out, Opcode::RemoteForward, forward, true);
    }
}
