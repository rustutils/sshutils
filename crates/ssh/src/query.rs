//! `ssh -Q`: the algorithms this implementation supports.
//!
//! The lists follow OpenSSH 10.5's names and order, restricted to what
//! russh implements, so `ssh -Q` answers what this `ssh` can actually use.

use std::collections::HashSet;

use russh::keys::key::ALL_KEY_TYPES;
use russh::keys::{Algorithm, HashAlg};
use sshutils_config::algorithms::{ALL_CIPHERS, ALL_KEX, ALL_KEY, ALL_MACS, ALL_SIG};

/// OpenSSH's compression methods (`compression_alg_list`).
const ALL_COMPRESSION: &str = "none,zlib@openssh.com";

/// The queries `-Q help` lists.
const HELP: &str = "cipher\ncipher-auth\ncompression\nkex\nkey\nkey-cert\nkey-plain\nkey-sig\nmac\n\
protocol-version\nsig";

/// Answer a query, one name per line, or `None` for an unknown query.
/// Some queries also accept the matching config keyword, ignoring case.
pub fn query(name: &str) -> Option<String> {
    let is = |keyword: &str| name.eq_ignore_ascii_case(keyword);
    let list = match name {
        "cipher" => filter(ALL_CIPHERS, cipher),
        _ if is("Ciphers") => filter(ALL_CIPHERS, cipher),
        "cipher-auth" => filter(ALL_CIPHERS, |n| cipher(n) && authenticated(n)),
        "mac" => filter(ALL_MACS, mac),
        _ if is("MACs") => filter(ALL_MACS, mac),
        "kex" => filter(ALL_KEX, kex),
        _ if is("KexAlgorithms") => filter(ALL_KEX, kex),
        "key" => keys(key_type),
        "key-cert" => keys(|n| key_type(n) && certificate(n)),
        "key-plain" => keys(|n| key_type(n) && !certificate(n)),
        "key-sig" => keys(|_| true),
        _ if [
            "PubkeyAcceptedKeyTypes",
            "PubkeyAcceptedAlgorithms",
            "HostKeyAlgorithms",
            "HostbasedKeyTypes",
            "HostbasedAcceptedKeyTypes",
            "HostbasedAcceptedAlgorithms",
        ]
        .into_iter()
        .any(is) =>
        {
            keys(|_| true)
        }
        "sig" | "key-ca-sign" => signatures(),
        _ if is("CASignatureAlgorithms") => signatures(),
        "compression" => filter(ALL_COMPRESSION, compression),
        "protocol-version" => vec!["2"],
        "help" => vec![HELP],
        _ => return None,
    };
    Some(list.join("\n"))
}

/// The names of `all` that `supported` accepts, in order.
fn filter(all: &'static str, supported: impl Fn(&str) -> bool) -> Vec<&'static str> {
    all.split(',').filter(|name| supported(name)).collect()
}

fn cipher(name: &str) -> bool {
    russh::cipher::Name::try_from(name).is_ok()
}

/// Ciphers that authenticate the data themselves (AEAD), needing no MAC.
fn authenticated(name: &str) -> bool {
    name.ends_with("-gcm@openssh.com") || name == "chacha20-poly1305@openssh.com"
}

fn mac(name: &str) -> bool {
    russh::mac::Name::try_from(name).is_ok()
}

fn kex(name: &str) -> bool {
    russh::kex::Name::try_from(name).is_ok()
}

fn compression(name: &str) -> bool {
    russh::compression::Name::try_from(name).is_ok()
}

/// Key algorithms (`key-sig`): plain keys, certificates and the RSA
/// signature variants, as far as they are supported and `select` takes them.
fn keys(select: impl Fn(&str) -> bool) -> Vec<&'static str> {
    let supported = supported_keys();
    filter(ALL_KEY, |n| supported.contains(n) && select(n))
}

/// Signature algorithms (`sig`, `key-ca-sign`).
fn signatures() -> Vec<&'static str> {
    let supported = supported_keys();
    filter(ALL_SIG, |n| supported.contains(n))
}

/// Key types proper, as opposed to the RSA signature variants and WebAuthn
/// signatures, which only name a signature format.
fn key_type(name: &str) -> bool {
    !name.starts_with("rsa-sha2-") && !name.starts_with("webauthn-")
}

fn certificate(name: &str) -> bool {
    name.ends_with("-cert-v01@openssh.com")
}

/// The names of the key algorithms russh can verify and sign with in
/// software, plain and as certificates. Security keys (`sk-*`) wait for
/// hardware token support; DSA is no longer part of OpenSSH.
fn supported_keys() -> HashSet<String> {
    ALL_KEY_TYPES
        .iter()
        .filter(|algorithm| {
            matches!(
                algorithm,
                Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. }
            )
        })
        .flat_map(|algorithm| {
            let name = match algorithm {
                // ssh-key names RSA keys by their signature hash; the
                // certificate types follow the same names.
                Algorithm::Rsa { hash: None } => "ssh-rsa".to_string(),
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                } => "rsa-sha2-256".to_string(),
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                } => "rsa-sha2-512".to_string(),
                other => other.as_str().to_string(),
            };
            let certificate = format!("{name}-cert-v01@openssh.com");
            [name, certificate]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(name: &str) -> Vec<String> {
        query(name).unwrap().lines().map(str::to_string).collect()
    }

    #[test]
    fn keyword_aliases() {
        assert_eq!(query("Ciphers"), query("cipher"));
        assert_eq!(query("ciphers"), query("cipher"));
        assert_eq!(query("hostkeyalgorithms"), query("key-sig"));
        assert_eq!(query("CASignatureAlgorithms"), query("sig"));
        // Query names themselves are case-sensitive.
        assert_eq!(query("Cipher"), None);
        assert_eq!(query("KEY"), None);
        assert_eq!(query("bogus"), None);
    }

    #[test]
    fn key_lists() {
        let key = lines("key");
        assert!(key.contains(&"ssh-ed25519".into()));
        assert!(key.contains(&"ssh-rsa-cert-v01@openssh.com".into()));
        assert!(!key.contains(&"rsa-sha2-256".into()));
        assert!(lines("key-cert").iter().all(|n| certificate(n)));
        assert!(lines("key-plain").iter().all(|n| !certificate(n)));
        let sig = lines("key-sig");
        assert!(sig.contains(&"rsa-sha2-512-cert-v01@openssh.com".into()));
        assert!(!sig.iter().any(|n| n.starts_with("sk-")));
        assert_eq!(
            lines("sig"),
            [
                "ssh-ed25519",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
                "ssh-rsa",
                "rsa-sha2-256",
                "rsa-sha2-512"
            ]
        );
    }

    #[test]
    fn transport_lists() {
        assert_eq!(
            lines("cipher-auth"),
            [
                "aes128-gcm@openssh.com",
                "aes256-gcm@openssh.com",
                "chacha20-poly1305@openssh.com"
            ]
        );
        assert!(lines("cipher").contains(&"3des-cbc".into()));
        assert!(lines("kex").contains(&"mlkem768x25519-sha256".into()));
        // russh extras that OpenSSH doesn't offer stay out.
        assert!(!lines("kex").contains(&"diffie-hellman-group15-sha512".into()));
        assert_eq!(lines("compression"), ["none", "zlib@openssh.com"]);
    }
}
