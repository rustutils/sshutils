//! Identities for public key authentication, like OpenSSH: the public
//! halves of `IdentityFile` and `CertificateFile` are loaded before
//! connecting (`load_public_identity_files`), and ordered and filtered
//! when public key authentication starts (`pubkey_prepare`). Private keys
//! are only read when a signature is needed.

use std::fs;
use std::path::Path;

use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Algorithm, Certificate, PublicKey};
use sshutils_config::Options;
use sshutils_config::expand::{expand, expand_tilde};
use sshutils_config::matching::match_pattern_list;
use sshutils_core::keyfile;
use sshutils_core::keyfmt;

use crate::hostkeys::fingerprint_hash;
use crate::log;

/// A public key or certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Public {
    Key(PublicKey),
    Certificate(Box<Certificate>),
}

impl Public {
    /// The plain key (a certificate's subject key).
    pub fn key_data(&self) -> &KeyData {
        match self {
            Public::Key(key) => key.key_data(),
            Public::Certificate(cert) => cert.public_key(),
        }
    }

    pub fn is_certificate(&self) -> bool {
        matches!(self, Public::Certificate(_))
    }

    fn algorithm(&self) -> Algorithm {
        self.key_data().algorithm()
    }

    pub fn is_rsa(&self) -> bool {
        matches!(self.algorithm(), Algorithm::Rsa { .. })
    }

    /// OpenSSH's `sshkey_ssh_name`: `ssh-ed25519`,
    /// `ssh-rsa-cert-v01@openssh.com`, ...
    pub fn ssh_name(&self) -> String {
        let algorithm = match self.algorithm() {
            Algorithm::Rsa { .. } => Algorithm::Rsa { hash: None },
            other => other,
        };
        match self {
            Public::Key(_) => algorithm.as_str().to_string(),
            Public::Certificate(_) => algorithm.to_certificate_type().to_string(),
        }
    }

    /// OpenSSH's `sshkey_type`: `ED25519`, `RSA-CERT`, ...
    pub fn type_label(&self) -> String {
        let label = keyfmt::type_label(self.key_data());
        match self {
            Public::Key(_) => label.to_string(),
            Public::Certificate(_) => format!("{label}-CERT"),
        }
    }

    /// The number of OpenSSH's key type (`enum sshkey_types`), for debug
    /// messages.
    fn type_number(&self) -> i32 {
        let plain = match self.algorithm() {
            Algorithm::Rsa { .. } => 0,
            Algorithm::Ecdsa { .. } => 1,
            Algorithm::Ed25519 => 2,
            Algorithm::SkEcdsaSha2NistP256 => 6,
            Algorithm::SkEd25519 => 8,
            _ => return 12,
        };
        match (self, plain) {
            (Public::Key(_), n) => n,
            (Public::Certificate(_), n @ 0..=2) => n + 3,
            (Public::Certificate(_), n) => n + 1,
        }
    }

    pub fn fingerprint(&self, options: &Options) -> String {
        keyfmt::fingerprint(self.key_data(), fingerprint_hash(options))
    }

    /// Too small an RSA key for `RequiredRSASize`?
    fn too_short(&self, options: &Options) -> bool {
        self.is_rsa()
            && i64::from(keyfmt::bits(self.key_data()))
                < i64::from(options.required_rsa_size.unwrap_or(1024))
    }
}

/// One key to try.
#[derive(Clone, Debug)]
pub struct Identity {
    /// Where it came from: for a certificate found next to an identity
    /// file, the identity (private key) file.
    pub filename: String,
    /// The public key, if it could be read without the private key.
    pub key: Option<Public>,
    /// Named by the user (command line or configuration), not a default.
    pub user_provided: bool,
    /// Tried since the last partial success.
    pub tried: bool,
}

impl Identity {
    /// OpenSSH's `format_identity`, for debug messages.
    pub fn describe(&self, options: &Options) -> String {
        let mut text = self.filename.clone();
        if let Some(key) = &self.key {
            text.push_str(&format!(
                " {} {}",
                key.type_label(),
                key.fingerprint(options)
            ));
        } else {
            text.push(' ');
        }
        if self.user_provided {
            text.push_str(" explicit");
        }
        text
    }
}

/// The identities from the configuration, with their public keys.
#[derive(Debug, Default)]
pub struct Identities {
    pub files: Vec<Identity>,
    pub certificates: Vec<Identity>,
}

/// Expand `%` tokens and environment variables in a path, like OpenSSH's
/// `default_client_percent_dollar_expand`; `Err` once the error is logged.
fn expand_path(path: &str, tokens: &[(char, String)]) -> Result<String, String> {
    let path = expand_tilde(path)?;
    let tokens: Vec<(char, &str)> = tokens.iter().map(|(k, v)| (*k, v.as_str())).collect();
    expand(&path, &tokens, true).map_err(|e| {
        log::error(&format!("vdollar_percent_expand: {e}"));
        "percent_dollar_expand: failed".to_string()
    })
}

/// Load the public halves of the identity and certificate files, like
/// OpenSSH's `load_public_identity_files`. `Err` is a fatal message.
pub fn load(options: &Options, tokens: &[(char, String)]) -> Result<Identities, String> {
    let mut identities = Identities::default();
    for file in &options.identity_files {
        if file.path.eq_ignore_ascii_case("none") {
            continue;
        }
        let filename = expand_path(&file.path, tokens)?;
        let key = checked(load_public(&filename), &filename, "pubkey", options);
        log::debug(&format!(
            "identity file {filename} type {}",
            key.as_ref().map_or(-1, Public::type_number)
        ));
        identities.files.push(Identity {
            filename: filename.clone(),
            key,
            user_provided: file.user_provided,
            tried: false,
        });
        // Without CertificateFile, a certificate next to the key.
        if !options.certificate_files.is_empty() {
            continue;
        }
        let cert_path = format!("{filename}-cert");
        let cert = checked(
            load_public(&cert_path),
            &filename,
            "identity pubkey",
            options,
        );
        match cert {
            Some(cert @ Public::Certificate(_)) => identities.files.push(Identity {
                filename,
                key: Some(cert),
                user_provided: file.user_provided,
                tried: false,
            }),
            Some(key) => log::debug(&format!(
                "load_public_identity_files: key {cert_path} type {} is not a certificate",
                key.type_label()
            )),
            None => {}
        }
    }
    for file in &options.certificate_files {
        let filename = expand_path(&file.path, tokens)?;
        match checked(load_public(&filename), &filename, "identity cert", options) {
            Some(cert @ Public::Certificate(_)) => identities.certificates.push(Identity {
                filename,
                key: Some(cert),
                user_provided: file.user_provided,
                tried: false,
            }),
            Some(key) => log::debug(&format!(
                "load_public_identity_files: key {filename} type {} is not a certificate",
                key.type_label()
            )),
            None => {}
        }
    }
    Ok(identities)
}

/// OpenSSH's `check_load`: drop RSA keys below `RequiredRSASize`.
fn checked(key: Option<Public>, path: &str, what: &str, options: &Options) -> Option<Public> {
    let key = key?;
    if key.too_short(options) {
        log::error(&format!("load {what} \"{path}\": Invalid key length"));
        log::debug(&format!("no {what} loaded from {path}"));
        return None;
    }
    log::debug(&format!(
        "loaded {what} from {path}: {} {}",
        key.type_label(),
        key.fingerprint(options)
    ));
    Some(key)
}

/// OpenSSH's `sshkey_load_public`: the file as a public key file, then
/// `<file>.pub`, then the public half of an OpenSSH private key.
pub fn load_public(path: &str) -> Option<Public> {
    load_public_file(path)
        .or_else(|| load_public_file(&format!("{path}.pub")))
        .or_else(|| keyfile::public_from_private_file(Path::new(path)).map(Public::Key))
}

/// OpenSSH's `sshkey_try_load_public`: the first line that holds a key,
/// stopping at what looks like a private key.
fn load_public_file(path: &str) -> Option<Public> {
    let text = fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&text);
    for line in text.split_inclusive('\n') {
        if line.starts_with(['#', '\n']) || line.is_empty() {
            continue;
        }
        if line.starts_with("-----BEGIN") || line == "SSH PRIVATE KEY FILE" {
            return None;
        }
        if let Some(key) = parse_public(line.trim_start_matches([' ', '\t'])) {
            return Some(key);
        }
    }
    None
}

/// `<type> <base64> ...` as a key or certificate.
pub fn parse_public(line: &str) -> Option<Public> {
    let mut fields = line.split([' ', '\t']).filter(|f| !f.is_empty());
    let (kind, blob) = (fields.next()?, fields.next()?);
    let blob = blob.trim_end_matches(['\r', '\n']);
    let text = format!("{kind} {blob}");
    if kind.ends_with("-cert-v01@openssh.com") {
        Certificate::from_openssh(&text)
            .ok()
            .map(|c| Public::Certificate(Box::new(c)))
    } else {
        PublicKey::from_openssh(&text).ok().map(Public::Key)
    }
}

/// Is `key` allowed by `PubkeyAcceptedAlgorithms` (OpenSSH's
/// `key_type_allowed`)? RSA keys also by their SHA-2 signature names.
fn allowed_by_config(key: &Public, options: &Options) -> bool {
    let list = options.pubkey_accepted_algorithms.as_deref().unwrap_or("");
    let allowed = |name: &str| match_pattern_list(name, list, false) == 1;
    if allowed(&key.ssh_name()) {
        return true;
    }
    match (key.is_rsa(), key) {
        (true, Public::Key(_)) => allowed("rsa-sha2-512") || allowed("rsa-sha2-256"),
        (true, Public::Certificate(_)) => {
            allowed("rsa-sha2-512-cert-v01@openssh.com")
                || allowed("rsa-sha2-256-cert-v01@openssh.com")
        }
        _ => false,
    }
}

/// The signature algorithm for `key`, like OpenSSH's `key_sig_algorithm`:
/// for RSA with `server-sig-algs`, the first RSA entry of
/// `PubkeyAcceptedAlgorithms` the server supports; otherwise the key's own
/// name, if accepted.
pub fn signature_algorithm(
    key: &Public,
    options: &Options,
    server_sig_algs: Option<&[String]>,
) -> Option<String> {
    let accepted = options.pubkey_accepted_algorithms.as_deref().unwrap_or("");
    let Some(server) = server_sig_algs.filter(|_| key.is_rsa()) else {
        let name = key.ssh_name();
        return accepted.split(',').any(|a| a == name).then_some(name);
    };
    accepted
        .split(',')
        .find(|name| {
            let (plain, cert) = match name.strip_suffix("-cert-v01@openssh.com") {
                Some(plain) => (plain, true),
                None => (*name, false),
            };
            cert == key.is_certificate()
                && matches!(plain, "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512")
                && server.iter().any(|s| s == plain)
        })
        .map(str::to_string)
}

/// OpenSSH's `order_identities_by_prio`: certificates before plain keys,
/// except that identities the user named keep their places.
fn order_by_priority(list: &mut [Identity]) {
    let slots: Vec<usize> = (0..list.len())
        .filter(|&i| !list[i].user_provided)
        .collect();
    let mut sorted: Vec<Identity> = slots.iter().map(|&i| list[i].clone()).collect();
    sorted.sort_by_key(|id| match &id.key {
        Some(key) if key.is_certificate() => 1,
        _ => 3,
    });
    for (slot, id) in slots.into_iter().zip(sorted) {
        list[slot] = id;
    }
}

/// The keys to try, in order, like OpenSSH's `pubkey_prepare` (without
/// agent keys yet): certificates from `CertificateFile`, then identity
/// files; minus what `PubkeyAcceptedAlgorithms` and the server's
/// `server-sig-algs` exclude.
pub fn prepare(
    identities: &Identities,
    options: &Options,
    server_sig_algs: Option<&[String]>,
) -> Vec<Identity> {
    let mut files: Vec<Identity> = Vec::new();
    for id in &identities.files {
        if let Some(Public::Certificate(cert)) = &id.key
            && cert.cert_type() != CertType::User
        {
            log::debug(&format!(
                "pubkey_prepare: ignoring certificate {}: not a user certificate",
                id.filename
            ));
            continue;
        }
        files.push(id.clone());
    }
    let mut certificates: Vec<Identity> = Vec::new();
    for (i, id) in identities.certificates.iter().enumerate() {
        if let Some(Public::Certificate(cert)) = &id.key
            && cert.cert_type() != CertType::User
        {
            // OpenSSH names the identity file at the same index here.
            let name = identities
                .files
                .get(i)
                .map_or("(null)", |f| f.filename.as_str());
            log::debug(&format!(
                "pubkey_prepare: ignoring certificate {name}: not a user certificate"
            ));
            continue;
        }
        certificates.push(id.clone());
    }
    order_by_priority(&mut certificates);
    order_by_priority(&mut files);
    let mut preferred = certificates;
    preferred.extend(files);
    preferred.retain(|id| {
        let Some(key) = &id.key else {
            return true;
        };
        if !allowed_by_config(key, options) {
            log::debug(&format!(
                "Skipping {} key {} - corresponding algorithm not in PubkeyAcceptedAlgorithms",
                key.ssh_name(),
                id.filename
            ));
            return false;
        }
        if server_sig_algs.is_some() && signature_algorithm(key, options, server_sig_algs).is_none()
        {
            log::debug(&format!(
                "Skipping {} key {} - corresponding algorithm not supported by server",
                key.ssh_name(),
                id.filename
            ));
            return false;
        }
        true
    });
    for id in &preferred {
        log::debug(&format!("Will attempt key: {}", id.describe(options)));
    }
    log::debug2("pubkey_prepare: done");
    preferred
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICzo7zTJEbePEgO0sq4yBF4spoOByo+Vd+uu/J4ZTzpX";

    fn identity(name: &str, cert: bool, user_provided: bool) -> Identity {
        let key = parse_public(ED25519).unwrap();
        let key = if cert {
            // Only the kind matters for ordering.
            Some(Public::Certificate(Box::new(test_certificate())))
        } else {
            Some(key)
        };
        Identity {
            filename: name.to_string(),
            key,
            user_provided,
            tried: false,
        }
    }

    fn test_certificate() -> Certificate {
        use russh::keys::ssh_key::certificate::Builder;
        let mut rng = russh::keys::key::safe_rng();
        let ca = russh::keys::PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let subject = parse_public(ED25519).unwrap();
        let mut builder =
            Builder::new_with_random_nonce(&mut rng, subject.key_data().clone(), 0, u64::MAX)
                .unwrap();
        builder.cert_type(CertType::User).unwrap();
        builder.all_principals_valid().unwrap();
        builder.sign(&ca).unwrap()
    }

    fn names(list: &[Identity]) -> Vec<String> {
        list.iter()
            .map(|id| {
                let cert = id.key.as_ref().is_some_and(Public::is_certificate);
                format!("{}{}", id.filename, if cert { "-cert" } else { "" })
            })
            .collect()
    }

    #[test]
    fn priorities() {
        // Defaults: certificates first.
        let mut list = vec![
            identity("a", false, false),
            identity("a", true, false),
            identity("b", false, false),
        ];
        order_by_priority(&mut list);
        assert_eq!(names(&list), ["a-cert", "a", "b"]);
        // Named by the user: their order, around which defaults move.
        let mut list = vec![
            identity("a", false, true),
            identity("a", true, true),
            identity("b", false, false),
            identity("c", true, false),
        ];
        order_by_priority(&mut list);
        assert_eq!(names(&list), ["a", "a-cert", "c-cert", "b"]);
    }

    fn options(accepted: &str) -> Options {
        Options {
            pubkey_accepted_algorithms: Some(accepted.to_string()),
            ..Options::default()
        }
    }

    #[test]
    fn signature_algorithms() {
        let rsa = parse_public(RSA).unwrap();
        let server: Vec<String> = vec!["rsa-sha2-256".into(), "ssh-ed25519".into()];
        let options = options("ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa");
        assert_eq!(
            signature_algorithm(&rsa, &options, Some(&server)).as_deref(),
            Some("rsa-sha2-256")
        );
        // Without server-sig-algs, only the key's own name.
        assert_eq!(
            signature_algorithm(&rsa, &options, None).as_deref(),
            Some("ssh-rsa")
        );
        let sha2_only = self::options("rsa-sha2-512,rsa-sha2-256");
        assert_eq!(signature_algorithm(&rsa, &sha2_only, None), None);
        assert_eq!(
            signature_algorithm(&rsa, &sha2_only, Some(&["ssh-rsa".to_string()])),
            None
        );
        let ed = parse_public(ED25519).unwrap();
        assert_eq!(
            signature_algorithm(&ed, &options, Some(&[])).as_deref(),
            Some("ssh-ed25519")
        );
        assert!(allowed_by_config(&rsa, &sha2_only));
        assert!(!allowed_by_config(&ed, &sha2_only));
        assert!(allowed_by_config(&ed, &self::options("ssh-ed*")));
    }

    const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCUqVP39Elw2LeM9XgnIoGXPWDUZIfuYk9psJ7pbbyA+qR3KLPa2L1i0q+02RgLwL0L+hBDZJL37u6xpAcBEhUe2EfuD8/CcqvJZqUYMetqqWTKgYrODb5lnrHBgYGekV+nKgZQJ2HstzqLUahb5DYXin17gPP0NDYBzssQW3CVxtf7aqeqZdOjlzvm9pDuDl1AKf3UZe4hze6KsNAWcRyWcVvoRnkTW3SnauC2mL9yB28tiCEnPLdEn69YnT9a7OvKhmkyfuFIVhwh8ibJbcH3MfpwpAZptcXic8FA88yZQnjk2HXwInYVelQxusA/SBM1MRLESvfOpN0Yu0i6496h";

    #[test]
    fn public_lines() {
        assert!(matches!(parse_public(ED25519), Some(Public::Key(_))));
        assert!(matches!(
            parse_public(&format!("{ED25519} comment\n")),
            Some(Public::Key(_))
        ));
        assert!(parse_public("ssh-ed25519 notbase64").is_none());
        let ed = parse_public(ED25519).unwrap();
        assert_eq!(ed.ssh_name(), "ssh-ed25519");
        assert_eq!(ed.type_label(), "ED25519");
        assert_eq!(ed.type_number(), 2);
        let rsa = parse_public(RSA).unwrap();
        assert_eq!(rsa.ssh_name(), "ssh-rsa");
        let cert = Public::Certificate(Box::new(test_certificate()));
        assert_eq!(cert.ssh_name(), "ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(cert.type_label(), "ED25519-CERT");
        assert_eq!(cert.type_number(), 5);
    }
}
