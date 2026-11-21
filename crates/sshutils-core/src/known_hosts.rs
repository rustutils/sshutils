//! `known_hosts` files: parsing, host matching and hashing.
//!
//! Each line is one of:
//!
//! ```text
//! # comment
//! host1,host2,[host3]:2222 ssh-ed25519 AAAA... optional comment
//! !bad.example.com,*.example.com ssh-ed25519 AAAA...
//! |1|<base64 salt>|<base64 HMAC-SHA1(salt, host)> ssh-ed25519 AAAA...
//! @cert-authority *.example.com ssh-ed25519 AAAA...
//! @revoked host1 ssh-ed25519 AAAA...
//! ```

use base64ct::{Base64, Encoding};
use hmac::{Hmac, KeyInit, Mac};
use russh::keys::ssh_key::PublicKey;
use sha1::Sha1;

/// Prefix of a hashed host name.
const HASH_MAGIC: &str = "|1|";
/// Length of the salt and of the HMAC-SHA1 in a hashed host name.
const HASH_LEN: usize = 20;

/// The `@` marker at the start of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    None,
    /// `@cert-authority`: the key is a CA for host certificates.
    CertAuthority,
    /// `@revoked`: the key must never be accepted.
    Revoked,
}

/// One line of a `known_hosts` file.
#[derive(Debug, Clone)]
pub enum Line<'a> {
    /// Empty or a `#` comment.
    Comment,
    /// Not a valid entry. OpenSSH refuses to rewrite files containing these.
    Invalid,
    Entry(Entry<'a>),
}

/// A host key entry.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
    pub marker: Marker,
    /// The host field: comma-separated patterns, or one hashed name.
    pub hosts: &'a str,
    /// Everything after the host field: key type, key and comment, as
    /// written in the file.
    pub key_text: &'a str,
    pub key: PublicKey,
}

impl Line<'_> {
    /// Parse one line (without its line terminator).
    pub fn parse(line: &str) -> Line<'_> {
        let line = line.trim_end_matches('\r');
        let rest = line.trim_start_matches([' ', '\t']);
        if rest.is_empty() || rest.starts_with('#') {
            return Line::Comment;
        }
        let (marker, rest) = match split_field(rest) {
            ("@cert-authority", rest) => (Marker::CertAuthority, rest),
            ("@revoked", rest) => (Marker::Revoked, rest),
            (field, _) if field.starts_with('@') => return Line::Invalid,
            _ => (Marker::None, rest),
        };
        let (hosts, key_text) = split_field(rest);
        if hosts.is_empty() || key_text.is_empty() {
            return Line::Invalid;
        }
        if hosts.starts_with(HASH_MAGIC) && decode_hashed(hosts).is_none() {
            return Line::Invalid;
        }
        let mut key_fields = key_text.splitn(3, [' ', '\t']);
        let (Some(algorithm), Some(blob)) = (key_fields.next(), key_fields.next()) else {
            return Line::Invalid;
        };
        let Ok(key) = PublicKey::from_openssh(&format!("{algorithm} {blob}")) else {
            return Line::Invalid;
        };
        Line::Entry(Entry {
            marker,
            hosts,
            key_text,
            key,
        })
    }
}

impl Entry<'_> {
    /// The comment after the key, if any.
    pub fn comment(&self) -> Option<&str> {
        let mut fields = self.key_text.splitn(3, [' ', '\t']);
        fields
            .nth(2)
            .map(|c| c.trim_matches([' ', '\t']))
            .filter(|c| !c.is_empty())
    }

    /// Whether the host field is a hashed name.
    pub fn is_hashed(&self) -> bool {
        self.hosts.starts_with(HASH_MAGIC)
    }

    /// Whether the host field contains patterns (`*`, `?`, `!`), which
    /// can't be hashed.
    pub fn has_wildcards(&self) -> bool {
        !self.is_hashed() && self.hosts.contains(['*', '?', '!'])
    }

    /// Whether this entry applies to `host` (a name, or `[name]:port` for
    /// non-default ports). Plain patterns match case-insensitively; a
    /// hashed name only matches exactly the string that was hashed.
    pub fn matches(&self, host: &str) -> bool {
        if self.is_hashed() {
            let Some((salt, hash)) = decode_hashed(self.hosts) else {
                return false;
            };
            return hmac_sha1(&salt, host) == hash;
        }
        match_host_patterns(&host.to_ascii_lowercase(), self.hosts)
    }
}

/// Split off the first blank-separated field, skipping the blanks after it.
fn split_field(s: &str) -> (&str, &str) {
    match s.find([' ', '\t']) {
        Some(i) => (&s[..i], s[i..].trim_start_matches([' ', '\t'])),
        None => (s, ""),
    }
}

/// Match a lowercase host against a comma-separated pattern list like
/// OpenSSH's `match_hostname`: any matching negated pattern (`!pattern`)
/// rejects the host; otherwise at least one positive pattern must match.
pub fn match_host_patterns(host: &str, patterns: &str) -> bool {
    let mut matched = false;
    for pattern in patterns.split(',') {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, pattern),
        };
        if glob_match(host.as_bytes(), pattern.to_ascii_lowercase().as_bytes()) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// Shell-style matching with `*` (any sequence) and `?` (any character).
pub fn glob_match(text: &[u8], pattern: &[u8]) -> bool {
    let (mut t, mut p) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                backtrack = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || c == text[t] => {
                t += 1;
                p += 1;
            }
            _ => match backtrack {
                Some((star, start)) => {
                    p = star + 1;
                    t = start + 1;
                    backtrack = Some((star, start + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// Decode `|1|salt|hash` into its 20-byte salt and hash.
fn decode_hashed(field: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let rest = field.strip_prefix(HASH_MAGIC)?;
    let (salt, hash) = rest.split_once('|')?;
    let salt = Base64::decode_vec(salt).ok()?;
    let hash = Base64::decode_vec(hash).ok()?;
    (salt.len() == HASH_LEN && hash.len() == HASH_LEN).then_some((salt, hash))
}

fn hmac_sha1(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Hash a host name for `known_hosts` with the given 20-byte salt:
/// `|1|<base64 salt>|<base64 HMAC-SHA1>`.
pub fn hash_host(host: &str, salt: &[u8; HASH_LEN]) -> String {
    format!(
        "{HASH_MAGIC}{}|{}",
        Base64::encode_string(salt),
        Base64::encode_string(&hmac_sha1(salt, host))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAk7shWwUfM2IBq7V0QnZZSORfGadoAfaU8uT8ZHkMv6";

    fn entry(line: &str) -> Entry<'_> {
        match Line::parse(line) {
            Line::Entry(e) => e,
            other => panic!("not an entry: {other:?}"),
        }
    }

    #[test]
    fn parses_lines() {
        assert!(matches!(Line::parse(""), Line::Comment));
        assert!(matches!(Line::parse("  # x"), Line::Comment));
        assert!(matches!(Line::parse("garbage"), Line::Invalid));
        assert!(matches!(
            Line::parse("host ssh-ed25519 notbase64"),
            Line::Invalid
        ));
        assert!(matches!(
            Line::parse(&format!("@unknown host {KEY}")),
            Line::Invalid
        ));
        assert!(matches!(
            Line::parse(&format!("|1|x|y {KEY}")),
            Line::Invalid
        ));

        let line = format!("a,b\t{KEY}  comment here\r");
        let e = entry(&line);
        assert_eq!(e.marker, Marker::None);
        assert_eq!(e.hosts, "a,b");
        assert_eq!(e.key_text, format!("{KEY}  comment here"));
        assert_eq!(e.comment(), Some("comment here"));

        let line = format!("@revoked host1 {KEY}");
        let e = entry(&line);
        assert_eq!(e.marker, Marker::Revoked);
        assert_eq!(e.hosts, "host1");
    }

    #[test]
    fn matches_patterns() {
        let line = format!("host1,HOST2,[host3]:2222 {KEY}");
        let e = entry(&line);
        assert!(e.matches("host1"));
        assert!(e.matches("Host2"));
        assert!(e.matches("[host3]:2222"));
        assert!(!e.matches("host3"));

        let line = format!("!bad.example.com,*.example.com {KEY}");
        let e = entry(&line);
        assert!(e.matches("www.example.com"));
        assert!(!e.matches("bad.example.com"));
        assert!(!e.matches("example.com"));
        assert!(e.has_wildcards());

        let line = format!("10.0.0.? {KEY}");
        let e = entry(&line);
        assert!(e.matches("10.0.0.5"));
        assert!(!e.matches("10.0.0.55"));
    }

    #[test]
    fn glob() {
        assert!(glob_match(b"abc", b"a*c"));
        assert!(glob_match(b"abbbc", b"a*b*c"));
        assert!(glob_match(b"", b"*"));
        assert!(!glob_match(b"ab", b"a*c"));
        assert!(glob_match(b"a.b.c", b"*.c"));
    }

    #[test]
    fn hashed_names() {
        // Produced by OpenSSH 10.5: `ssh-keygen -H` on a line for "host1".
        let line = format!("|1|zgOqz16GtoCP2WHrLKp1wy+gDro=|/lMAgEe74xc87vUuQqvIyS5H8Ss= {KEY}");
        let e = entry(&line);
        assert!(e.is_hashed());
        assert!(!e.has_wildcards());
        assert!(e.matches("host1"));
        assert!(!e.matches("host2"));

        let salt = [7u8; 20];
        let hashed = hash_host("host1", &salt);
        let line = format!("{hashed} {KEY}");
        let e = entry(&line);
        assert!(e.matches("host1"));
        assert!(!e.matches("HOST1"));
        assert!(!e.matches("host2"));
    }
}
