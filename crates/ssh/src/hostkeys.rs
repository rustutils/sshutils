//! Host keys: what the `known_hosts` files say about a host, the order of
//! host key algorithms that follows from it, and the decision whether to
//! trust the key the server presents (OpenSSH's `check_host_key`).
//!
//! So far keys are only checked, never added: a host whose key isn't known
//! is refused.

use std::net::SocketAddr;

use russh::keys::{Algorithm, EcdsaCurve, PublicKey};
use sshutils_config::Options;
use sshutils_config::expand::expand_tilde;
use sshutils_config::values::*;
use sshutils_core::keyfmt::{self, FingerprintHash};
use sshutils_core::known_hosts::{Line, Marker};

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

/// What the `known_hosts` files say about a key.
#[derive(Debug, PartialEq, Eq)]
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

    /// Look a plain key up (`check_key_in_hostkeys`): a matching key makes
    /// it known; otherwise any other key for the host, whatever its type,
    /// means it changed. A key marked `@revoked` is revoked regardless.
    pub fn check(&self, key: &PublicKey) -> Status<'_> {
        let mut status = Status::New;
        for entry in self.entries.iter().filter(|e| e.marker == Marker::None) {
            if entry.key.key_data() == key.key_data() {
                status = Status::Ok(entry);
                break;
            }
            status = Status::Changed(entry);
        }
        if self
            .entries
            .iter()
            .any(|e| e.marker == Marker::Revoked && e.key.key_data() == key.key_data())
        {
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

/// Decide whether to trust `key`, the server's host key (`verify_host_key`
/// and `check_host_key`). Messages are logged; `false` means the caller
/// fails with "Host key verification failed.".
pub fn verify(host: &str, peer: SocketAddr, port: u16, key: &PublicKey, options: &Options) -> bool {
    let hash = fingerprint_hash(options);
    let fingerprint = keyfmt::fingerprint(key.key_data(), hash);
    log::debug(&format!(
        "Server host key: {} {fingerprint}",
        key.algorithm().as_str()
    ));

    if options.no_host_authentication_for_localhost == Some(1)
        && is_local(peer)
        && options.host_key_alias.is_none()
    {
        log::debug("Forcing accepting of host key for loopback/localhost.");
        return true;
    }

    let (user_files, system_files) = files(options);
    let all_files: Vec<String> = user_files.iter().chain(&system_files).cloned().collect();
    let name = lookup_name(host, port, options);
    let known = HostKeys::load(&name, &all_files);
    let label = keyfmt::type_label(key.key_data());
    let strict = options
        .strict_host_key_checking
        .unwrap_or(STRICT_HOSTKEY_ASK);

    match known.check(key) {
        Status::Ok(entry) => {
            log::debug(&format!(
                "Host '{name}' is known and matches the {label} host key."
            ));
            log::debug(&format!("Found key in {}:{}", entry.file, entry.line));
            if options.visual_host_key == Some(1) {
                log::info(&format!(
                    "Host key fingerprint is: {fingerprint}\n{}",
                    keyfmt::randomart(key.key_data(), hash)
                ));
            }
            true
        }
        Status::New => {
            if options.host_key_alias.is_none() && port != DEFAULT_PORT {
                log::debug("checking without port identifier");
                let bare = HostKeys::load(host, &all_files);
                if let Status::Ok(entry) = bare.check(key) {
                    log::debug(&format!(
                        "Host '{host}' is known and matches the {label} host key."
                    ));
                    log::debug(&format!("Found key in {}:{}", entry.file, entry.line));
                    log::debug("found matching key w/out port");
                    return true;
                }
            }
            if strict == STRICT_HOSTKEY_YES {
                log::error(&format!(
                    "No {label} host key is known for {name} and you have requested strict checking."
                ));
            } else {
                log::error(&format!(
                    "No {label} host key is known for {name}, and adding host keys is not supported yet."
                ));
            }
            false
        }
        Status::Revoked => {
            log::error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            log::error("@       WARNING: REVOKED HOST KEY DETECTED!               @");
            log::error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            log::error(&format!(
                "The {label} host key for {name} is marked as revoked."
            ));
            log::error("This could mean that a stolen key is being used to");
            log::error("impersonate this host.");
            if strict != STRICT_HOSTKEY_OFF {
                log::error(&format!(
                    "{label} host key for {name} was revoked and you have requested strict checking."
                ));
            } else {
                log::error("Connecting despite a revoked host key is not supported yet.");
            }
            false
        }
        Status::Changed(entry) => {
            warn_changed_key(key, hash);
            if let Some(file) = user_files.first().or(system_files.first()) {
                log::error(&format!(
                    "Add correct host key in {} to get rid of this message.",
                    truncate(file, 100)
                ));
            }
            log::error(&format!(
                "Offending {} key in {}:{}",
                keyfmt::type_label(entry.key.key_data()),
                entry.file,
                entry.line
            ));
            if strict != STRICT_HOSTKEY_OFF {
                log::error(&format!(
                    "Host key for {name} has changed and you have requested strict checking."
                ));
            } else {
                log::error("Connecting despite a changed host key is not supported yet.");
            }
            false
        }
    }
}

/// The "REMOTE HOST IDENTIFICATION HAS CHANGED" banner.
fn warn_changed_key(key: &PublicKey, hash: FingerprintHash) {
    let fingerprint = keyfmt::fingerprint(key.key_data(), hash);
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
        keyfmt::type_label(key.key_data())
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
        assert!(matches!(keys.check(&key(ED25519)), Status::Ok(e) if e.line == 1));
        assert!(matches!(
            keys.check(&key(ED25519_OTHER)),
            Status::Changed(_)
        ));

        let (_dir, keys) = known(&format!("other {ED25519}\n"));
        assert_eq!(keys.check(&key(ED25519)), Status::New);

        // A match anywhere wins over a different key before it.
        let (_dir, keys) = known(&format!("host {ED25519_OTHER}\nhost {ED25519}\n"));
        assert!(matches!(keys.check(&key(ED25519)), Status::Ok(e) if e.line == 2));

        let (_dir, keys) = known(&format!("host {ED25519}\n@revoked host {ED25519}\n"));
        assert_eq!(keys.check(&key(ED25519)), Status::Revoked);

        // CA keys don't count for plain keys.
        let (_dir, keys) = known(&format!("@cert-authority host {ED25519_OTHER}\n"));
        assert_eq!(keys.check(&key(ED25519)), Status::New);
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
}
