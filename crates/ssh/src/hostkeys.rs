//! Host keys: what the `known_hosts` files say about a host, the order of
//! host key algorithms that follows from it, and the decision whether to
//! trust the key the server presents (OpenSSH's `check_host_key`).
//!
//! `VerifyHostKeyDNS` and `KnownHostsCommand` are not supported yet.

use std::net::SocketAddr;

use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Algorithm, Certificate, EcdsaCurve, PublicKey};
use sshutils_config::Options;
use sshutils_config::expand::expand_tilde;
use sshutils_config::matching::{match_pattern, match_pattern_list};
use sshutils_config::values::*;
use sshutils_core::keyfmt::{self, FingerprintHash};
use sshutils_core::known_hosts::{Line, Marker};
use sshutils_core::krl;

use crate::connect::DEFAULT_PORT;
use crate::log;

/// A matching line of a `known_hosts` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: PublicKey,
    pub marker: Marker,
    pub file: String,
    pub line: usize,
}

/// The `known_hosts` entries for one name.
#[derive(Debug, Default)]
pub struct HostKeys {
    entries: Vec<Entry>,
}

/// The key a server presented: a plain key or a certificate.
#[derive(Debug, Clone)]
pub enum HostKey {
    Plain(PublicKey),
    Certificate(Box<Certificate>),
}

impl HostKey {
    /// The key itself (for a certificate, the key it certifies).
    pub fn key_data(&self) -> &KeyData {
        match self {
            HostKey::Plain(key) => key.key_data(),
            HostKey::Certificate(certificate) => certificate.public_key(),
        }
    }

    pub fn is_certificate(&self) -> bool {
        matches!(self, HostKey::Certificate(_))
    }

    /// OpenSSH's type label: `ED25519`, or `ED25519-CERT` for a certificate.
    fn label(&self) -> String {
        let label = keyfmt::type_label(self.key_data());
        match self {
            HostKey::Plain(_) => label.to_string(),
            HostKey::Certificate(_) => format!("{label}-CERT"),
        }
    }

    /// The algorithm name, as in `ssh-ed25519-cert-v01@openssh.com`.
    fn name(&self) -> String {
        match self {
            HostKey::Plain(key) => key.algorithm().as_str().to_string(),
            HostKey::Certificate(certificate) => {
                certificate.algorithm().to_certificate_type().to_string()
            }
        }
    }
}

/// What the `known_hosts` files say about a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status<'a> {
    /// Known and matching.
    Ok(&'a Entry),
    /// Not known.
    New,
    /// Other keys are known for the host (the last one found).
    Changed(&'a Entry),
    /// Marked `@revoked`.
    Revoked,
}

impl HostKeys {
    /// Load the entries for `name` from `files` (missing files are
    /// skipped, unparseable lines ignored).
    pub fn load(name: &str, files: &[String]) -> HostKeys {
        let mut entries = Vec::new();
        for file in files {
            let text = match std::fs::read(file) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(err) => {
                    log::debug(&format!(
                        "load_hostkeys: fopen {file}: {}",
                        crate::io_message(&err)
                    ));
                    continue;
                }
            };
            for (index, line) in text.lines().enumerate() {
                match Line::parse(line) {
                    Line::Entry(entry) if entry.matches(name) => entries.push(Entry {
                        key: entry.key,
                        marker: entry.marker,
                        file: file.clone(),
                        line: index + 1,
                    }),
                    Line::Invalid => log::debug(&format!(
                        "{file}:{}: parse error in hostkeys file",
                        index + 1
                    )),
                    _ => {}
                }
            }
        }
        HostKeys { entries }
    }

    /// Look a key up (`check_key_in_hostkeys`). A plain key is known if
    /// an entry has it; otherwise any other key for the host, whatever its
    /// type, means it changed. A certificate is known if an
    /// `@cert-authority` entry has the key that signed it. Either is
    /// revoked if an `@revoked` entry has the key (or a certificate's CA).
    pub fn check(&self, key: &HostKey) -> Status<'_> {
        let mut status = Status::New;
        match key {
            HostKey::Plain(key) => {
                for entry in self.entries.iter().filter(|e| e.marker == Marker::None) {
                    if entry.key.key_data() == key.key_data() {
                        status = Status::Ok(entry);
                        break;
                    }
                    status = Status::Changed(entry);
                }
            }
            HostKey::Certificate(certificate) => {
                if let Some(entry) = self.entries.iter().find(|e| {
                    e.marker == Marker::CertAuthority
                        && e.key.key_data() == certificate.signature_key()
                }) {
                    status = Status::Ok(entry);
                }
            }
        }
        let revoked = |data: &KeyData| {
            self.entries
                .iter()
                .any(|e| e.marker == Marker::Revoked && e.key.key_data() == data)
        };
        let ca_revoked = match key {
            HostKey::Certificate(certificate) => revoked(certificate.signature_key()),
            HostKey::Plain(_) => false,
        };
        if revoked(key.key_data()) || ca_revoked {
            return Status::Revoked;
        }
        status
    }

    /// Is a plain key of this algorithm known (`lookup_key_in_hostkeys_by_type`)?
    /// ECDSA keys must also be on the same curve; RSA signature variants
    /// all match RSA keys.
    fn has_key_type(&self, algorithm: &Algorithm) -> bool {
        self.entries
            .iter()
            .filter(|e| e.marker == Marker::None)
            .any(|e| same_key_type(&e.key.algorithm(), algorithm))
    }
}

fn same_key_type(a: &Algorithm, b: &Algorithm) -> bool {
    match (a, b) {
        (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }) => true,
        (Algorithm::Ecdsa { curve: a }, Algorithm::Ecdsa { curve: b }) => a == b,
        (a, b) => a == b,
    }
}

/// The plain key algorithm a host key algorithm name stands for
/// (certificate names stand for the key they certify).
pub fn key_algorithm(name: &str) -> Option<Algorithm> {
    let plain = name.strip_suffix("-cert-v01@openssh.com").unwrap_or(name);
    Some(match plain {
        "ssh-ed25519" => Algorithm::Ed25519,
        "ecdsa-sha2-nistp256" => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        "ecdsa-sha2-nistp384" => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        "ecdsa-sha2-nistp521" => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
        "ssh-rsa" => Algorithm::Rsa { hash: None },
        "rsa-sha2-256" => Algorithm::Rsa {
            hash: Some(russh::keys::HashAlg::Sha256),
        },
        "rsa-sha2-512" => Algorithm::Rsa {
            hash: Some(russh::keys::HashAlg::Sha512),
        },
        _ => return None,
    })
}

/// `host` or `[host]:port` for a non-default port (`put_host_port`).
pub fn host_port(host: &str, port: u16) -> String {
    if port == 0 || port == DEFAULT_PORT {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// The `known_hosts` files, user files first, with `~` expanded.
pub fn files(options: &Options) -> (Vec<String>, Vec<String>) {
    let expand = |files: &[String]| -> Vec<String> {
        files
            .iter()
            .map(|f| expand_tilde(f).unwrap_or_else(|_| f.clone()))
            .collect()
    };
    (
        expand(&options.user_hostfiles),
        expand(&options.system_hostfiles),
    )
}

/// The name host keys are recorded under: `HostKeyAlias`, or the host
/// with a non-default port.
pub fn lookup_name(host: &str, port: u16, options: &Options) -> String {
    match &options.host_key_alias {
        Some(alias) => alias.clone(),
        None => host_port(host, port),
    }
}

/// Order `HostKeyAlgorithms` by what is known for the host
/// (`order_hostkeyalgs`): if a key of the most preferred type is known,
/// the list stays as it is; otherwise algorithms with known keys move to
/// the front, keeping their relative order.
pub fn order_algorithms(algorithms: &str, known: &HostKeys) -> String {
    let names: Vec<&str> = algorithms.split(',').filter(|n| !n.is_empty()).collect();
    let Some(best) = names.first() else {
        return algorithms.to_string();
    };
    if key_algorithm(best).is_some_and(|a| known.has_key_type(&a)) {
        log::debug3(&format!(
            "order_hostkeyalgs: have matching best-preference key type {best}, using HostkeyAlgorithms verbatim"
        ));
        return algorithms.to_string();
    }
    let has_ca = known
        .entries
        .iter()
        .any(|e| e.marker == Marker::CertAuthority);
    let (first, last): (Vec<&str>, Vec<&str>) = names.iter().partition(|name| {
        (has_ca && name.ends_with("-cert-v01@openssh.com"))
            || key_algorithm(name).is_some_and(|a| known.has_key_type(&a))
    });
    if first.is_empty() {
        log::debug3("order_hostkeyalgs: no algorithms matched; accept original");
    } else {
        log::debug3(&format!(
            "order_hostkeyalgs: prefer hostkeyalgs: {}",
            first.join(",")
        ));
    }
    first.into_iter().chain(last).collect::<Vec<_>>().join(",")
}

fn fingerprint_hash(options: &Options) -> FingerprintHash {
    match options.fingerprint_hash {
        Some(0) => FingerprintHash::Md5,
        Some(1) => FingerprintHash::Sha1,
        Some(4) => FingerprintHash::Sha512,
        _ => FingerprintHash::Sha256,
    }
}

/// Is the address on the loopback network?
fn is_local(address: SocketAddr) -> bool {
    address.ip().is_loopback()
}

/// Characters that never go into a `known_hosts` file.
const INVALID_HOST_CHARACTERS: &[char] = &['@', '?', '*', '#', '[', ']', '|', '\'', '"', '\\'];

/// How far a check may change the `known_hosts` files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    ReadWrite,
    ReadOnly,
    /// Read-only, and a changed key fails without the warning (the second
    /// look-up without the port).
    Quiet,
}

/// What a check of the host key works with.
struct Context {
    /// The host name (lowercased).
    hostname: String,
    port: u16,
    /// Whether this is the second look-up, without the port.
    clobber_port: bool,
    /// The name keys are recorded under, and the address.
    host: String,
    ip: String,
    check_host_ip: bool,
    host_keys: HostKeys,
    ip_keys: Option<HostKeys>,
    user_files: Vec<String>,
    system_files: Vec<String>,
    all_files: Vec<String>,
}

/// The decision about the server's host key (OpenSSH's `verify_host_key`
/// and `check_host_key`).
///
/// Like OpenSSH it changes the options it works with: a host key that is
/// accepted although it changed turns off password authentication and
/// forwarding, and `UpdateHostKeys` is turned off for keys that aren't
/// trusted.
pub struct Verifier<'a> {
    pub options: &'a mut Options,
    /// The address connected to.
    pub peer: SocketAddr,
    /// Ask a yes/no question; the fingerprint, if given, counts as yes.
    pub confirm: &'a mut dyn FnMut(&str, Option<&str>) -> bool,
}

impl Verifier<'_> {
    /// Decide whether to trust `key`, the host key of `host` (lowercased)
    /// on `port`. Messages are logged; `false` means the caller fails with
    /// "Host key verification failed.".
    pub fn verify(&mut self, host: &str, port: u16, key: &HostKey) -> bool {
        let hash = fingerprint_hash(self.options);
        let fingerprint = keyfmt::fingerprint(key.key_data(), hash);
        match key {
            HostKey::Plain(_) => {
                log::debug(&format!("Server host key: {} {fingerprint}", key.name()));
            }
            HostKey::Certificate(certificate) => {
                log::debug(&format!(
                    "Server host certificate: {} {fingerprint}, serial {} ID \"{}\" CA {} {} valid {}",
                    key.name(),
                    certificate.serial(),
                    certificate.key_id(),
                    certificate.signature_key().algorithm().as_str(),
                    keyfmt::fingerprint(certificate.signature_key(), hash),
                    validity(certificate)
                ));
                for principal in certificate.valid_principals() {
                    log::debug2(&format!("Server host certificate hostname: {principal}"));
                }
                // OpenSSH checks the CA's signature when it reads the
                // certificate, and gives up on the connection if it's bad.
                // Whether the CA is trusted is decided below.
                if certificate.verify_signature().is_err() {
                    log::fatal(&format!(
                        "ssh_dispatch_run_fatal: Connection to {} port {}: incorrect signature",
                        self.peer.ip(),
                        self.peer.port()
                    ));
                    std::process::exit(255);
                }
            }
        }
        let certificate = match key {
            HostKey::Certificate(certificate) => Some(&**certificate),
            HostKey::Plain(_) => None,
        };
        let files: Vec<String> = self
            .options
            .revoked_host_keys
            .iter()
            .map(|f| expand_tilde(f).unwrap_or_else(|_| f.clone()))
            .collect();
        for file in &files {
            match revoked_by_file(file, key.key_data(), certificate) {
                Ok(false) => {}
                Ok(true) => {
                    log::error(&format!(
                        "Host key {} {fingerprint} revoked by file {file}",
                        key.label()
                    ));
                    return false;
                }
                Err(err) => {
                    if let Some(detail) = &err.detail {
                        log::error(detail);
                    }
                    log::error(&format!(
                        "Error checking host key {} {fingerprint} in revoked keys file {file}: {}",
                        key.label(),
                        err.reason
                    ));
                    return false;
                }
            }
        }
        self.check(host, port, key, Access::ReadWrite, false)
    }

    fn check(
        &mut self,
        hostname: &str,
        port: u16,
        key: &HostKey,
        mut access: Access,
        clobber_port: bool,
    ) -> bool {
        let local = is_local(self.peer);
        if self.options.no_host_authentication_for_localhost == Some(1)
            && local
            && self.options.host_key_alias.is_none()
        {
            log::debug("Forcing accepting of host key for loopback/localhost.");
            self.options.update_hostkeys = Some(0);
            return true;
        }
        if hostname.contains(INVALID_HOST_CHARACTERS) {
            log::debug(&format!(
                "check_host_key: invalid hostname \"{hostname}\"; will not record"
            ));
            access = Access::ReadOnly;
        }

        let lookup_port = if clobber_port { 0 } else { port };
        let host = match &self.options.host_key_alias {
            Some(alias) => {
                log::debug(&format!("using hostkeyalias: {alias}"));
                alias.clone()
            }
            None => host_port(hostname, lookup_port),
        };
        let ip = host_port(&self.peer.ip().to_string(), lookup_port);
        if self.options.check_host_ip == Some(1) && (local || hostname == ip) {
            self.options.check_host_ip = Some(0);
        }
        let check_host_ip = self.options.check_host_ip == Some(1);

        let (user_files, system_files) = files(self.options);
        let all_files: Vec<String> = user_files.iter().chain(&system_files).cloned().collect();
        let host_keys = HostKeys::load(&host, &all_files);
        // Addresses are not checked for certificates, nor (as in OpenSSH)
        // for the plain key of a certificate that wasn't accepted.
        let ip_keys =
            (check_host_ip && !key.is_certificate()).then(|| HostKeys::load(&ip, &all_files));
        let context = Context {
            hostname: hostname.to_string(),
            port,
            clobber_port,
            host,
            ip,
            check_host_ip,
            host_keys,
            ip_keys,
            user_files,
            system_files,
            all_files,
        };

        let mut key = key.clone();
        loop {
            if self.decide(&context, &key, &mut access) {
                return true;
            }
            // A certificate that wasn't accepted is tried as a plain key,
            // unless it was revoked.
            match &key {
                HostKey::Certificate(certificate)
                    if context.host_keys.check(&key) != Status::Revoked =>
                {
                    log::debug("No matching CA found. Retry with plain key");
                    key = HostKey::Plain(PublicKey::new(certificate.public_key().clone(), ""));
                }
                _ => return false,
            }
        }
    }

    /// One pass of `check_host_key` for `key`.
    fn decide(&mut self, context: &Context, key: &HostKey, access: &mut Access) -> bool {
        let Context {
            hostname,
            host,
            ip,
            host_keys,
            ip_keys,
            user_files,
            system_files,
            all_files,
            ..
        } = context;
        let (port, clobber_port, check_host_ip) =
            (context.port, context.clobber_port, context.check_host_ip);
        let want_cert = key.is_certificate();
        let hash = fingerprint_hash(self.options);
        let label = key.label();
        let strict = self
            .options
            .strict_host_key_checking
            .unwrap_or(STRICT_HOSTKEY_ASK);

        let host_status = host_keys.check(key);
        if *access == Access::ReadWrite && user_files.is_empty() {
            *access = Access::ReadOnly;
        }
        let mut host_ip_differ = false;
        let ip_status = match &ip_keys {
            Some(ip_keys) => {
                let ip_status = ip_keys.check(key);
                if let Status::Changed(host_found) = &host_status {
                    host_ip_differ = match &ip_status {
                        Status::Changed(ip_found) => {
                            ip_found.key.key_data() != host_found.key.key_data()
                        }
                        _ => true,
                    };
                }
                ip_status
            }
            None => host_status.clone(),
        };

        let mut trusted = false;
        let mut unsafe_continue = false;
        match &host_status {
            Status::Ok(found) => {
                let what = if want_cert { "certificate" } else { "key" };
                log::debug(&format!(
                    "Host '{host}' is known and matches the {label} host {what}."
                ));
                let what = if want_cert { "CA key" } else { "key" };
                log::debug(&format!("Found {what} in {}:{}", found.file, found.line));
                if let HostKey::Certificate(certificate) = key {
                    let name = self.options.host_key_alias.as_deref().unwrap_or(hostname);
                    if let Err(reason) = check_certificate(
                        certificate,
                        name,
                        self.options.ca_sign_algorithms.as_deref(),
                    ) {
                        log::error(reason);
                        return false;
                    }
                    if self.options.update_hostkeys != Some(0) {
                        self.options.update_hostkeys = Some(0);
                        log::debug3(
                            "check_host_key: certificate host key in use; disabling UpdateHostkeys",
                        );
                    }
                }
                let in_system = |entry: &Entry| system_files.contains(&entry.file);
                if self.options.update_hostkeys != Some(0)
                    && (in_system(found)
                        || matches!(&ip_status, Status::Ok(ip_found) if in_system(ip_found)))
                {
                    self.options.update_hostkeys = Some(0);
                    log::debug3(
                        "check_host_key: host key found in GlobalKnownHostsFile; disabling UpdateHostkeys",
                    );
                }
                if check_host_ip && ip_status == Status::New {
                    if *access != Access::ReadWrite {
                        log::info(&format!(
                            "{label} host key for IP address '{}' not in list of known hosts.",
                            truncate(ip, 128)
                        ));
                    } else if !add_host(&user_files[0], ip, key.key_data(), self.hash_known_hosts())
                    {
                        log::info(&format!(
                            "Failed to add the {label} host key for IP address '{}' to the list of known hosts ({}).",
                            truncate(ip, 128),
                            truncate(&user_files[0], 500)
                        ));
                    } else {
                        log::info(&format!(
                            "Warning: Permanently added the {label} host key for IP address '{}' to the list of known hosts.",
                            truncate(ip, 128)
                        ));
                    }
                } else if self.options.visual_host_key == Some(1) {
                    log::info(&format!(
                        "Host key fingerprint is: {}\n{}",
                        keyfmt::fingerprint(key.key_data(), hash),
                        keyfmt::randomart(key.key_data(), hash)
                    ));
                }
                trusted = true;
            }
            Status::New => 'new: {
                if self.options.host_key_alias.is_none()
                    && port != 0
                    && port != DEFAULT_PORT
                    && !clobber_port
                {
                    log::debug("checking without port identifier");
                    if self.check(hostname, 0, key, Access::Quiet, true) {
                        log::debug("found matching key w/out port");
                        break 'new;
                    }
                }
                if *access != Access::ReadWrite || want_cert {
                    return false;
                }
                if strict == STRICT_HOSTKEY_YES {
                    log::error(&format!(
                        "No {label} host key is known for {} and you have requested strict checking.",
                        truncate(host, 200)
                    ));
                    return false;
                }
                if strict == STRICT_HOSTKEY_ASK {
                    let fingerprint = keyfmt::fingerprint(key.key_data(), hash);
                    let mut message = format!(
                        "The authenticity of host '{} ({ip})' can't be established.\n\
                         {label} key fingerprint is: {fingerprint}",
                        truncate(host, 200)
                    );
                    if self.options.visual_host_key == Some(1) {
                        message.push('\n');
                        message.push_str(&keyfmt::randomart(key.key_data(), hash));
                    }
                    message.push('\n');
                    message.push_str(&other_names_message(host, key, all_files));
                    message.push_str(
                        "\nAre you sure you want to continue connecting (yes/no/[fingerprint])? ",
                    );
                    if !(self.confirm)(&message, Some(&fingerprint)) {
                        return false;
                    }
                    trusted = true;
                }
                // Record the key (`accept-new`, `off`, or confirmed).
                let store_hash = self.hash_known_hosts();
                let file = &user_files[0];
                let (added, recorded) = if check_host_ip && ip_status == Status::New {
                    let line = format!("{host},{ip}");
                    let added = if store_hash {
                        add_host(file, host, key.key_data(), true)
                            && add_host(file, ip, key.key_data(), true)
                    } else {
                        add_host(file, &line, key.key_data(), false)
                    };
                    (added, line)
                } else {
                    (
                        add_host(file, host, key.key_data(), store_hash),
                        host.clone(),
                    )
                };
                if added {
                    log::info(&format!(
                        "Warning: Permanently added '{}' ({label}) to the list of known hosts.",
                        truncate(&recorded, 200)
                    ));
                } else {
                    log::info(&format!(
                        "Failed to add the host to the list of known hosts ({}).",
                        truncate(file, 500)
                    ));
                }
            }
            Status::Revoked => {
                log::error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                log::error("@       WARNING: REVOKED HOST KEY DETECTED!               @");
                log::error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                log::error(&format!(
                    "The {label} host key for {host} is marked as revoked."
                ));
                log::error("This could mean that a stolen key is being used to");
                log::error("impersonate this host.");
                if strict != STRICT_HOSTKEY_OFF {
                    log::error(&format!(
                        "{label} host key for {} was revoked and you have requested strict checking.",
                        truncate(host, 200)
                    ));
                    return false;
                }
                unsafe_continue = true;
            }
            Status::Changed(found) => {
                if want_cert {
                    log::debug(&format!(
                        "Host certificate authority does not match @cert-authority in {}:{}",
                        found.file, found.line
                    ));
                    return false;
                }
                if *access == Access::Quiet {
                    return false;
                }
                if check_host_ip && host_ip_differ {
                    let key_message = match &ip_status {
                        Status::New => "is unknown",
                        Status::Ok(_) => "is unchanged",
                        _ => "has a different value",
                    };
                    log::error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                    log::error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
                    log::error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                    log::error(&format!("The {label} host key for {host} has changed,"));
                    log::error(&format!(
                        "and the key for the corresponding IP address {ip}"
                    ));
                    log::error(&format!("{key_message}. This could either mean that"));
                    log::error("DNS SPOOFING is happening or the IP address for the host");
                    log::error("and its host key have changed at the same time.");
                    if let Status::Ok(ip_found) | Status::Changed(ip_found) = &ip_status {
                        log::error(&format!(
                            "Offending key for IP in {}:{}",
                            ip_found.file, ip_found.line
                        ));
                    }
                }
                warn_changed_key(key.key_data(), hash);
                if let Some(file) = user_files.first().or(system_files.first()) {
                    log::error(&format!(
                        "Add correct host key in {} to get rid of this message.",
                        truncate(file, 100)
                    ));
                }
                log::error(&format!(
                    "Offending {} key in {}:{}",
                    keyfmt::type_label(found.key.key_data()),
                    found.file,
                    found.line
                ));
                if strict != STRICT_HOSTKEY_OFF {
                    log::error(&format!(
                        "Host key for {} has changed and you have requested strict checking.",
                        truncate(host, 200)
                    ));
                    return false;
                }
                unsafe_continue = true;
            }
        }
        if unsafe_continue && !self.continue_unsafely() {
            return false;
        }

        if check_host_ip
            && !matches!(host_status, Status::Changed(_))
            && let Status::Changed(ip_found) = &ip_status
        {
            let mut message = format!(
                "Warning: the {label} host key for '{}' differs from the key for the IP address '{}'\n\
                 Offending key for IP in {}:{}",
                truncate(host, 200),
                truncate(ip, 128),
                ip_found.file,
                ip_found.line
            );
            if let Status::Ok(host_found) = &host_status {
                message.push_str(&format!(
                    "\nMatching host key in {}:{}",
                    host_found.file, host_found.line
                ));
            }
            if strict == STRICT_HOSTKEY_ASK {
                message.push_str("\nAre you sure you want to continue connecting (yes/no)? ");
                if !(self.confirm)(&message, None) {
                    return false;
                }
            } else if strict != STRICT_HOSTKEY_OFF {
                log::info(&message);
                log::error("Exiting, you have requested strict checking.");
                return false;
            } else {
                log::info(&message);
            }
        }

        if !trusted && self.options.update_hostkeys != Some(0) {
            log::debug(
                "check_host_key: hostkey not known or explicitly trusted: disabling UpdateHostkeys",
            );
            self.options.update_hostkeys = Some(0);
        }
        true
    }

    fn hash_known_hosts(&self) -> bool {
        self.options.hash_known_hosts == Some(1)
    }

    /// Continue although the host key changed or was revoked, but without
    /// what a man in the middle could abuse. `false` if forwarding was
    /// required (`ExitOnForwardFailure`).
    fn continue_unsafely(&mut self) -> bool {
        let o = &mut *self.options;
        let mut cancelled_forwarding = false;
        let disable = |what: &str, cancelled: &mut bool| {
            log::error(&format!(
                "{what} is disabled to avoid man-in-the-middle attacks."
            ));
            *cancelled = true;
        };
        if o.password_authentication != Some(0) {
            disable("Password authentication", &mut cancelled_forwarding);
            o.password_authentication = Some(0);
        }
        if o.kbd_interactive_authentication != Some(0) {
            disable(
                "Keyboard-interactive authentication",
                &mut cancelled_forwarding,
            );
            o.kbd_interactive_authentication = Some(0);
        }
        if o.forward_agent.is_some_and(|f| f != 0) {
            disable("Agent forwarding", &mut cancelled_forwarding);
            o.forward_agent = Some(0);
        }
        if o.forward_x11.is_some_and(|f| f != 0) {
            disable("X11 forwarding", &mut cancelled_forwarding);
            o.forward_x11 = Some(0);
        }
        if !o.local_forwards.is_empty() || !o.remote_forwards.is_empty() {
            disable("Port forwarding", &mut cancelled_forwarding);
            o.local_forwards.clear();
            o.remote_forwards.clear();
        }
        if o.tun_open.is_some_and(|t| t != TUNNEL_NO) {
            disable("Tunnel forwarding", &mut cancelled_forwarding);
            o.tun_open = Some(TUNNEL_NO);
        }
        if o.update_hostkeys != Some(0) {
            log::error("UpdateHostkeys is disabled because the host key is not trusted.");
            o.update_hostkeys = Some(0);
        }
        if o.exit_on_forward_failure == Some(1) && cancelled_forwarding {
            log::fatal("Error: forwarding disabled due to host key check failure");
            std::process::exit(255);
        }
        true
    }
}

/// Whether a `RevokedHostKeys` file (a KRL or a list of keys) revokes the
/// key (`sshkey_check_revoked`).
fn revoked_by_file(
    file: &str,
    key: &KeyData,
    certificate: Option<&Certificate>,
) -> Result<bool, krl::Error> {
    let data = std::fs::read(file).map_err(|err| krl::Error {
        detail: None,
        reason: crate::io_message(&err),
    })?;
    if krl::is_krl(&data) {
        log::debug2(&format!("ssh_krl_file_contains_key: checking KRL {file}"));
        return Ok(krl::Krl::parse(&data)?.is_revoked(key, certificate));
    }
    krl::key_list_contains(&String::from_utf8_lossy(&data), key, certificate)
}

/// Most other names listed for a key.
const MAX_OTHER_NAMES: usize = 8;

/// The names `key` is known under besides `host` (`other_hostkeys_message`).
fn other_names_message(host: &str, key: &HostKey, files: &[String]) -> String {
    let mut names = Vec::new();
    for file in files {
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        for (index, line) in text.lines().enumerate() {
            let Line::Entry(entry) = Line::parse(line) else {
                continue;
            };
            if entry.marker != Marker::None
                || entry.matches(host)
                || entry.key.key_data() != key.key_data()
            {
                continue;
            }
            let hosts = if entry.is_hashed() {
                "[hashed name]"
            } else {
                entry.hosts
            };
            names.push(format!("{}:{}: {hosts}", tilde_unexpand(file), index + 1));
        }
    }
    if names.is_empty() {
        return "This key is not known by any other names.".to_string();
    }
    let mut message = "This host key is known by the following other names/addresses:".to_string();
    for name in names.iter().take(MAX_OTHER_NAMES) {
        message.push_str(&format!("\n    {name}"));
    }
    if names.len() > MAX_OTHER_NAMES {
        message.push_str(&format!(
            "\n    ({} additional names omitted)",
            names.len() - MAX_OTHER_NAMES
        ));
    }
    message
}

/// Replace a `$HOME` prefix by `~/` (`try_tilde_unexpand`).
fn tilde_unexpand(path: &str) -> String {
    let Some(home) = std::env::var("HOME").ok().filter(|h| !h.is_empty()) else {
        return path.to_string();
    };
    if !path.starts_with('/') {
        return path.to_string();
    }
    let Some(rest) = path.strip_prefix(home.as_str()) else {
        return path.to_string();
    };
    if !home.ends_with('/') && !rest.starts_with('/') {
        return path.to_string();
    }
    format!("~/{}", rest.strip_prefix('/').unwrap_or(rest))
}

/// Append an entry for `host` (lowercased, or hashed) to `file`, creating
/// `~/.ssh` if that is where it goes (`add_host_to_hostfile`).
fn add_host(file: &str, host: &str, key: &KeyData, store_hash: bool) -> bool {
    use std::io::{Read, Seek, SeekFrom, Write};

    create_user_ssh_dir(file);
    let Ok(mut f) = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(file)
    else {
        return false;
    };
    // Make sure the file ends with a newline.
    let mut last = [0u8];
    let needs_newline =
        f.seek(SeekFrom::End(-1)).is_ok() && f.read_exact(&mut last).is_ok() && last[0] != b'\n';
    if needs_newline && let Err(err) = f.write_all(b"\n") {
        log::error(&format!(
            "Failed to add terminating newline to {file}: {}",
            crate::io_message(&err)
        ));
        return false;
    }
    let host = host.to_ascii_lowercase();
    let name = if store_hash {
        let mut salt = [0u8; 20];
        russh::keys::ssh_key::rand_core::Rng::fill_bytes(
            &mut russh::keys::key::safe_rng(),
            &mut salt,
        );
        sshutils_core::known_hosts::hash_host(&host, &salt)
    } else {
        host
    };
    let Ok(text) = PublicKey::new(key.clone(), "").to_openssh() else {
        return false;
    };
    if let Err(err) = f.write_all(format!("{name} {text}\n").as_bytes()) {
        log::error(&format!(
            "write_host_entry: fwrite: {}",
            crate::io_message(&err)
        ));
        return false;
    }
    true
}

/// Create `~/.ssh` (mode 0700) when `file` is directly inside it and it
/// doesn't exist yet (`hostfile_create_user_ssh_dir`).
fn create_user_ssh_dir(file: &str) {
    use std::os::unix::fs::DirBuilderExt;

    let Some((directory, _)) = file.rsplit_once('/') else {
        return;
    };
    let Ok(ssh_dir) = expand_tilde("~/.ssh") else {
        return;
    };
    if directory != ssh_dir {
        return;
    }
    match std::fs::metadata(&ssh_dir) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if let Err(err) = std::fs::DirBuilder::new().mode(0o700).create(&ssh_dir) {
                log::error(&format!(
                    "Could not create directory '{}' ({}).",
                    truncate(&ssh_dir, 200),
                    crate::io_message(&err)
                ));
            }
        }
        Err(err) => log::error(&format!(
            "Could not stat {ssh_dir}: {}",
            crate::io_message(&err)
        )),
    }
}

/// Whether a host certificate signed by a trusted CA is good for `name`
/// (`sshkey_cert_check_host`), or why not.
fn check_certificate(
    certificate: &Certificate,
    name: &str,
    ca_algorithms: Option<&str>,
) -> Result<(), &'static str> {
    if certificate.cert_type() != CertType::Host {
        return Err("Certificate invalid: not a host certificate");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if now < certificate.valid_after() {
        return Err("Certificate invalid: not yet valid");
    }
    if now >= certificate.valid_before() {
        return Err("Certificate invalid: expired");
    }
    if certificate.valid_principals().is_empty() {
        return Err("Certificate lacks principal list");
    }
    if !certificate
        .valid_principals()
        .iter()
        .any(|principal| match_pattern(name, principal))
    {
        return Err("Certificate invalid: name is not a listed principal");
    }
    if !certificate.critical_options().is_empty() {
        return Err("Certificate contains unsupported critical options");
    }
    if let Some(allowed) = ca_algorithms {
        let algorithm = certificate.signature().algorithm();
        if match_pattern_list(algorithm.as_str(), allowed, false) != 1 {
            return Err("Certificate signed with disallowed algorithm");
        }
    }
    Ok(())
}

/// A certificate's validity period, as OpenSSH's debug output shows it.
fn validity(certificate: &Certificate) -> String {
    let format = |seconds: u64| {
        let time = i64::try_from(seconds).unwrap_or(i64::MAX);
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let mut text = [0 as libc::c_char; 64];
        // SAFETY: localtime_r and strftime write only into the buffers given.
        unsafe {
            if libc::localtime_r(&time, &mut tm).is_null()
                || libc::strftime(
                    text.as_mut_ptr(),
                    text.len(),
                    c"%Y-%m-%dT%H:%M:%S".as_ptr(),
                    &tm,
                ) == 0
            {
                return seconds.to_string();
            }
            std::ffi::CStr::from_ptr(text.as_ptr())
                .to_string_lossy()
                .into_owned()
        }
    };
    match (certificate.valid_after(), certificate.valid_before()) {
        (0, u64::MAX) => "forever".to_string(),
        (0, before) => format!("before {}", format(before)),
        (after, u64::MAX) => format!("after {}", format(after)),
        (after, before) => format!("from {} to {}", format(after), format(before)),
    }
}

/// The "REMOTE HOST IDENTIFICATION HAS CHANGED" banner.
fn warn_changed_key(key: &KeyData, hash: FingerprintHash) {
    let fingerprint = keyfmt::fingerprint(key, hash);
    for line in [
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
        "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @",
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
        "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!",
        "Someone could be eavesdropping on you right now (man-in-the-middle attack)!",
        "It is also possible that a host key has just been changed.",
    ] {
        log::error(line);
    }
    log::error(&format!(
        "The fingerprint for the {} key sent by the remote host is\n{fingerprint}.",
        keyfmt::type_label(key)
    ));
    log::error("Please contact your system administrator.");
}

/// OpenSSH prints some paths with `%.100s`.
fn truncate(text: &str, max: usize) -> &str {
    match text.char_indices().nth(max) {
        Some((i, _)) => &text[..i],
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICzo7zTJEbePEgO0sq4yBF4spoOByo+Vd+uu/J4ZTzpX";
    const ED25519_THIRD: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKNEhTVokCZn10o+KQKcsMUa93wLHsJNgqwV90PzPWHq";
    const ED25519_OTHER: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPcINqp0sLD2kaOJ3Vl21d61LH7dgfdOimuimh+4G7M6";

    fn key(text: &str) -> PublicKey {
        PublicKey::from_openssh(text).unwrap()
    }

    fn known(lines: &str) -> (tempfile::TempDir, HostKeys) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, lines).unwrap();
        let keys = HostKeys::load("host", &[path.display().to_string()]);
        (dir, keys)
    }

    #[test]
    fn statuses() {
        let (_dir, keys) = known(&format!("host {ED25519}\n"));
        assert!(matches!(keys.check(&HostKey::Plain(key(ED25519))), Status::Ok(e) if e.line == 1));
        assert!(matches!(
            keys.check(&HostKey::Plain(key(ED25519_OTHER))),
            Status::Changed(_)
        ));

        let (_dir, keys) = known(&format!("other {ED25519}\n"));
        assert_eq!(keys.check(&HostKey::Plain(key(ED25519))), Status::New);

        // A match anywhere wins over a different key before it.
        let (_dir, keys) = known(&format!("host {ED25519_OTHER}\nhost {ED25519}\n"));
        assert!(matches!(keys.check(&HostKey::Plain(key(ED25519))), Status::Ok(e) if e.line == 2));

        let (_dir, keys) = known(&format!("host {ED25519}\n@revoked host {ED25519}\n"));
        assert_eq!(keys.check(&HostKey::Plain(key(ED25519))), Status::Revoked);

        // CA keys don't count for plain keys.
        let (_dir, keys) = known(&format!("@cert-authority host {ED25519_OTHER}\n"));
        assert_eq!(keys.check(&HostKey::Plain(key(ED25519))), Status::New);
    }

    #[test]
    fn algorithm_order() {
        let (_dir, none) = known("");
        let list = "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ssh-ed25519,rsa-sha2-512";
        assert_eq!(order_algorithms(list, &none), list);

        let (_dir, ed25519) = known(&format!("host {ED25519}\n"));
        // The best preference (a certificate for an Ed25519 key) is known.
        assert_eq!(order_algorithms(list, &ed25519), list);
        let list = "ecdsa-sha2-nistp256,rsa-sha2-512,ssh-ed25519-cert-v01@openssh.com,ssh-ed25519";
        assert_eq!(
            order_algorithms(list, &ed25519),
            "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512"
        );

        let (_dir, ca) = known(&format!("@cert-authority host {ED25519}\n"));
        assert_eq!(
            order_algorithms(list, &ca),
            "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,rsa-sha2-512,ssh-ed25519"
        );
    }

    #[test]
    fn names() {
        assert_eq!(host_port("h", 22), "h");
        assert_eq!(host_port("h", 2222), "[h]:2222");
        assert!(same_key_type(
            &key_algorithm("rsa-sha2-256").unwrap(),
            &Algorithm::Rsa { hash: None }
        ));
        assert!(!same_key_type(
            &key_algorithm("ecdsa-sha2-nistp384").unwrap(),
            &key_algorithm("ecdsa-sha2-nistp256").unwrap()
        ));
        assert_eq!(truncate("abcdef", 3), "abc");
    }

    /// Run the verifier for host `h` at 192.0.2.1 with `known` as the
    /// user's known_hosts and `CheckHostIP` on. Returns whether the key was
    /// accepted, the messages, the questions asked, and the file afterwards.
    fn verify_ip(
        known: &str,
        port: u16,
        strict: i32,
        hash: bool,
        answer: bool,
    ) -> (bool, Vec<String>, Vec<String>, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, known).unwrap();
        let mut options = Options {
            user_hostfiles: vec![path.display().to_string()],
            system_hostfiles: vec![],
            check_host_ip: Some(1),
            strict_host_key_checking: Some(strict),
            hash_known_hosts: Some(i32::from(hash)),
            ..Options::default()
        };
        options.fill_defaults().unwrap();
        // Not the system's files.
        options.system_hostfiles.clear();
        let mut questions = Vec::new();
        let mut confirm = |prompt: &str, fingerprint: Option<&str>| {
            assert_eq!(fingerprint, None);
            questions.push(prompt.to_string());
            answer
        };
        log::capture();
        let accepted = Verifier {
            options: &mut options,
            peer: "192.0.2.1:22".parse().unwrap(),
            confirm: &mut confirm,
        }
        .verify("h", port, &HostKey::Plain(key(ED25519)));
        let messages = log::captured();
        let file = std::fs::read_to_string(&path).unwrap();
        (accepted, messages, questions, file)
    }

    #[test]
    fn check_host_ip() {
        // The host is known; its address gets added.
        let (ok, messages, _, file) = verify_ip(
            &format!("h {ED25519}\n"),
            22,
            STRICT_HOSTKEY_YES,
            false,
            true,
        );
        assert!(ok);
        assert_eq!(
            messages,
            [
                "Warning: Permanently added the ED25519 host key for IP address '192.0.2.1' to the list of known hosts."
            ]
        );
        assert_eq!(file, format!("h {ED25519}\n192.0.2.1 {ED25519}\n"));

        // Both new: one entry for both names, or one hashed line each.
        let (ok, messages, _, file) = verify_ip("", 22, STRICT_HOSTKEY_NEW, false, true);
        assert!(ok);
        assert_eq!(
            messages,
            ["Warning: Permanently added 'h,192.0.2.1' (ED25519) to the list of known hosts."]
        );
        assert_eq!(file, format!("h,192.0.2.1 {ED25519}\n"));
        let (_, _, _, file) = verify_ip("", 22, STRICT_HOSTKEY_NEW, true, true);
        let lines: Vec<&str> = file.lines().collect();
        assert_eq!(lines.len(), 2);
        for (line, name) in lines.iter().zip(["h", "192.0.2.1"]) {
            let Line::Entry(entry) = Line::parse(line) else {
                panic!("{line}");
            };
            assert!(entry.is_hashed() && entry.matches(name), "{line}");
        }

        // Ports are part of both names.
        let (_, messages, _, file) = verify_ip("", 2222, STRICT_HOSTKEY_NEW, false, true);
        assert_eq!(
            messages,
            [
                "Warning: Permanently added '[h]:2222,[192.0.2.1]:2222' (ED25519) to the list of known hosts."
            ]
        );
        assert_eq!(file, format!("[h]:2222,[192.0.2.1]:2222 {ED25519}\n"));

        // The host's key changed, but the address still has this key.
        let (ok, messages, _, _) = verify_ip(
            &format!("h {ED25519_OTHER}\n192.0.2.1 {ED25519}\n"),
            22,
            STRICT_HOSTKEY_YES,
            false,
            true,
        );
        assert!(!ok);
        assert_eq!(
            messages[1],
            "@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @"
        );
        assert_eq!(messages[3], "The ED25519 host key for h has changed,");
        assert_eq!(
            messages[4],
            "and the key for the corresponding IP address 192.0.2.1"
        );
        assert_eq!(messages[5], "is unchanged. This could either mean that");
        assert!(messages[8].starts_with("Offending key for IP in ") && messages[8].ends_with(":2"));
        assert_eq!(
            messages[10],
            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @"
        );
        // Both changed, to different keys.
        let (_, messages, _, _) = verify_ip(
            &format!("h {ED25519_OTHER}\n192.0.2.1 {ED25519_THIRD}\n"),
            22,
            STRICT_HOSTKEY_YES,
            false,
            true,
        );
        assert_eq!(
            messages[5],
            "has a different value. This could either mean that"
        );
        // Both changed the same way: no spoofing warning.
        let (_, messages, _, _) = verify_ip(
            &format!("h,192.0.2.1 {ED25519_OTHER}\n"),
            22,
            STRICT_HOSTKEY_YES,
            false,
            true,
        );
        assert_eq!(
            messages[1],
            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @"
        );

        // The host matches but the address has another key.
        let known = format!("h {ED25519}\n192.0.2.1 {ED25519_OTHER}\n");
        let (ok, messages, questions, _) = verify_ip(&known, 22, STRICT_HOSTKEY_YES, false, true);
        assert!(!ok);
        assert!(questions.is_empty());
        assert!(messages[0].starts_with(
            "Warning: the ED25519 host key for 'h' differs from the key for the IP address '192.0.2.1'\nOffending key for IP in "
        ));
        assert!(messages[0].contains(":2\nMatching host key in "));
        assert_eq!(messages[1], "Exiting, you have requested strict checking.");
        let (ok, messages, questions, _) = verify_ip(&known, 22, STRICT_HOSTKEY_ASK, false, true);
        assert!(ok && messages.is_empty());
        assert!(
            questions[0].ends_with(":1\nAre you sure you want to continue connecting (yes/no)? ")
        );
        let (ok, _, _, _) = verify_ip(&known, 22, STRICT_HOSTKEY_ASK, false, false);
        assert!(!ok);
        let (ok, messages, _, _) = verify_ip(&known, 22, STRICT_HOSTKEY_NEW, false, true);
        assert!(!ok && messages[1] == "Exiting, you have requested strict checking.");
        let (ok, messages, _, _) = verify_ip(&known, 22, STRICT_HOSTKEY_OFF, false, true);
        assert!(ok && messages.len() == 1);

        // Not done when the host name is the address.
        let mut options = Options::default();
        options.fill_defaults().unwrap();
        options.user_hostfiles = vec![];
        options.check_host_ip = Some(1);
        options.no_host_authentication_for_localhost = Some(0);
        let mut no = |_: &str, _: Option<&str>| false;
        log::capture();
        Verifier {
            options: &mut options,
            peer: "192.0.2.1:22".parse().unwrap(),
            confirm: &mut no,
        }
        .verify("192.0.2.1", 22, &HostKey::Plain(key(ED25519)));
        log::captured();
        assert_eq!(options.check_host_ip, Some(0));
    }
}
