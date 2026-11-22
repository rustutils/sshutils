//! Algorithm name lists: OpenSSH 10.5's known names and defaults, and the
//! `Ciphers`/`KexAlgorithms`/… list syntax.
//!
//! A list is either explicit (`a,b,c`, entries may be wildcard patterns),
//! or modifies the default list: `+a,b` appends, `-a,b` removes (patterns
//! allowed), `^a,b` puts entries first.

use crate::matching::match_pattern_list;

/// Every name OpenSSH 10.5 knows, in its internal order (`ssh -Q`).
pub const ALL_CIPHERS: &str = "3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,\
aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com";

pub const ALL_MACS: &str = "hmac-sha1,hmac-sha1-96,hmac-sha2-256,hmac-sha2-512,hmac-md5,hmac-md5-96,\
umac-64@openssh.com,umac-128@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-md5-etm@openssh.com,\
hmac-md5-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com";

pub const ALL_KEX: &str = "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,\
diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,\
diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp256,\
ecdh-sha2-nistp384,ecdh-sha2-nistp521,curve25519-sha256,curve25519-sha256@libssh.org,\
sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,\
mlkem768nistp256-sha256,mlkem1024nistp384-sha384";

/// Public key and certificate algorithms (`ssh -Q key-sig`).
pub const ALL_KEY: &str = "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,\
sk-ssh-ed25519-cert-v01@openssh.com,ssh-mldsa44-ed25519@openssh.com,\
ssh-mldsa44-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,\
ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,\
ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521,\
ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,\
sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com,\
webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com,\
rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com";

/// Signature algorithms (`ssh -Q sig`).
pub const ALL_SIG: &str = "ssh-ed25519,sk-ssh-ed25519@openssh.com,ssh-mldsa44-ed25519@openssh.com,\
ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,\
webauthn-sk-ecdsa-sha2-nistp256@openssh.com,ssh-rsa,rsa-sha2-256,rsa-sha2-512";

/// Default client lists of upstream OpenSSH 10.5 (`myproposal.h`).
pub const DEFAULT_KEX: &str = "mlkem768x25519-sha256,sntrup761x25519-sha512,\
sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,\
ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,\
diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256";

pub const DEFAULT_KEY: &str = "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,\
ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,\
sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,\
webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,\
rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,\
ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,\
webauthn-sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256";

pub const DEFAULT_CIPHERS: &str = "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,\
aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr";

pub const DEFAULT_MACS: &str = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,\
umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1";

pub const DEFAULT_CA_SIG: &str = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,\
ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,\
webauthn-sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256";

/// Which kind of list, for validating configured values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Cipher,
    Mac,
    Kex,
    /// Public key algorithms; `ca_only` for `CASignatureAlgorithms`.
    Key {
        ca_only: bool,
    },
}

impl Kind {
    fn all(self) -> &'static str {
        match self {
            Kind::Cipher => ALL_CIPHERS,
            Kind::Mac => ALL_MACS,
            Kind::Kex => ALL_KEX,
            Kind::Key { ca_only: false } => ALL_KEY,
            Kind::Key { ca_only: true } => ALL_SIG,
        }
    }
}

/// Validate a configured list like OpenSSH: lists that remove (`-`) are
/// not checked; otherwise (after a `+` or `^`) every entry must be a known
/// name, or for key algorithms a pattern.
pub fn valid(kind: Kind, list: &str) -> bool {
    if list.starts_with('-') {
        return true;
    }
    let names = list.strip_prefix(['+', '^']).unwrap_or(list);
    if matches!(kind, Kind::Key { .. }) {
        let all: Vec<&str> = kind.all().split(',').collect();
        return !names.is_empty()
            && names
                .split(',')
                .all(|name| name.contains(['*', '?']) || all.contains(&name));
    }
    known(kind, names)
}

/// Is `names` a non-empty list of known names (no prefix, no patterns)?
pub fn known(kind: Kind, names: &str) -> bool {
    let all: Vec<&str> = kind.all().split(',').collect();
    !names.is_empty() && names.split(',').all(|name| all.contains(&name))
}

/// Append `extra` to `list`, skipping names already present.
fn concat(list: &str, extra: &str) -> String {
    let mut names: Vec<&str> = list.split(',').filter(|n| !n.is_empty()).collect();
    for name in extra.split(',').filter(|n| !n.is_empty()) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names.join(",")
}

/// The names in `proposal` that match (or, with `deny`, don't match)
/// `filter`.
fn filter_list(proposal: &str, filter: &str, deny: bool) -> String {
    proposal
        .split(',')
        .filter(|name| {
            let matched = match_pattern_list(name, filter, false) == 1;
            matched != deny
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Resolve a configured list against its defaults and all known names,
/// like OpenSSH's `kex_assemble_names`. `None` (unset) gives the default;
/// the result is `None` if the list is invalid.
pub fn assemble(list: Option<&str>, default: &str, all: &str) -> Option<String> {
    let list = match list {
        None | Some("") => return Some(default.to_string()),
        Some(list) => list,
    };
    let list = if let Some(extra) = list.strip_prefix('+') {
        concat(default, extra)
    } else if let Some(remove) = list.strip_prefix('-') {
        return Some(filter_list(default, remove, true));
    } else if let Some(first) = list.strip_prefix('^') {
        concat(first, default)
    } else {
        list.to_string()
    };
    let mut result = String::new();
    for pattern in list.split(',') {
        if pattern.starts_with('!') {
            return None;
        }
        result = concat(&result, &filter_list(all, pattern, false));
    }
    (!result.is_empty()).then_some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembling() {
        let def = "a,b,c";
        let all = "a,b,c,d,e";
        assert_eq!(assemble(None, def, all).unwrap(), "a,b,c");
        assert_eq!(assemble(Some("e,a"), def, all).unwrap(), "e,a");
        assert_eq!(assemble(Some("+d,a"), def, all).unwrap(), "a,b,c,d");
        assert_eq!(assemble(Some("-b"), def, all).unwrap(), "a,c");
        assert_eq!(assemble(Some("-*"), def, all).unwrap(), "");
        assert_eq!(assemble(Some("^d,b"), def, all).unwrap(), "d,b,a,c");
        assert_eq!(assemble(Some("*"), def, all).unwrap(), "a,b,c,d,e");
        assert!(assemble(Some("x"), def, all).is_none());
    }

    #[test]
    fn validation() {
        assert!(valid(Kind::Cipher, "aes128-ctr,aes256-ctr"));
        assert!(valid(Kind::Cipher, "+aes128-cbc"));
        assert!(valid(Kind::Cipher, "-whatever*"));
        assert!(!valid(Kind::Cipher, "aes*"));
        assert!(!valid(Kind::Mac, "nonsense"));
        assert!(known(Kind::Mac, "hmac-sha1,hmac-sha2-256"));
        assert!(!known(Kind::Mac, "+hmac-sha1"));
        assert!(!known(Kind::Cipher, ""));
        assert!(valid(Kind::Key { ca_only: false }, "ssh-ed25519*"));
        assert!(!valid(
            Kind::Key { ca_only: true },
            "ssh-rsa-cert-v01@openssh.com"
        ));
    }
}
