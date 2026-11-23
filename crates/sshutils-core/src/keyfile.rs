//! Reading key files the way OpenSSH does.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use russh::keys::ssh_key::{PrivateKey, PublicKey};

/// Why a private key couldn't be loaded.
#[derive(Debug)]
pub enum LoadError {
    Io(io::Error),
    /// The file is accessible by other users; OpenSSH refuses to use it.
    BadPermissions,
    /// The key is encrypted and no passphrase was given.
    Encrypted,
    /// The key is encrypted and the passphrase didn't decrypt it.
    WrongPassphrase,
    /// Not a private key in any format we understand.
    InvalidFormat,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "{e}"),
            LoadError::BadPermissions => write!(f, "bad permissions"),
            LoadError::Encrypted => write!(f, "key is encrypted"),
            LoadError::WrongPassphrase => {
                write!(f, "incorrect passphrase supplied to decrypt private key")
            }
            LoadError::InvalidFormat => write!(f, "invalid format"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Check that a private key file is only accessible by its owner, like
/// OpenSSH's `sshkey_perm_ok`: a file we own must not be readable or
/// writable by group or others. Prints OpenSSH's warning when it is.
pub fn check_private_permissions(path: &Path) -> Result<(), LoadError> {
    match permissions_warning(path)? {
        Some(lines) => {
            eprintln!("{}", lines.join("\n"));
            Err(LoadError::BadPermissions)
        }
        None => Ok(()),
    }
}

/// OpenSSH's warning, line by line, if the private key file at `path` is
/// accessible by others (see [`check_private_permissions`]).
pub fn permissions_warning(path: &Path) -> Result<Option<Vec<String>>, LoadError> {
    let meta = fs::metadata(path).map_err(LoadError::Io)?;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let mode = meta.mode() & 0o777;
    if meta.uid() != uid || mode & 0o077 == 0 {
        return Ok(None);
    }
    Ok(Some(vec![
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@".into(),
        "@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @".into(),
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@".into(),
        format!(
            "Permissions {mode:04o} for '{}' are too open.",
            path.display()
        ),
        "It is required that your private key files are NOT accessible by others.".into(),
        "This private key will be ignored.".into(),
    ]))
}

/// Load a private key: OpenSSH format, or PEM/PKCS#8/PuTTY via russh.
/// Checks file permissions first. `passphrase` of `None` only loads
/// unencrypted keys.
pub fn load_private(path: &Path, passphrase: Option<&str>) -> Result<PrivateKey, LoadError> {
    check_private_permissions(path)?;
    let text = fs::read_to_string(path).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidData => LoadError::InvalidFormat,
        _ => LoadError::Io(e),
    })?;
    decode_private(&text, passphrase)
}

/// Decode a private key from its text.
pub fn decode_private(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, LoadError> {
    if let Ok(key) = PrivateKey::from_openssh(text) {
        if !key.is_encrypted() {
            return Ok(key);
        }
        return match passphrase {
            None => Err(LoadError::Encrypted),
            Some(pass) => key.decrypt(pass).map_err(|_| LoadError::WrongPassphrase),
        };
    }

    // Other formats. russh can't tell us "wrong passphrase" directly, so
    // decide from whether the key needs one at all.
    match russh::keys::decode_secret_key(text, None) {
        Ok(key) => Ok(key),
        Err(russh::keys::Error::KeyIsEncrypted) => match passphrase {
            None => Err(LoadError::Encrypted),
            Some(pass) => russh::keys::decode_secret_key(text, Some(pass))
                .map_err(|_| LoadError::WrongPassphrase),
        },
        Err(_) if text.contains("ENCRYPTED") => match passphrase {
            None => Err(LoadError::Encrypted),
            Some(pass) => russh::keys::decode_secret_key(text, Some(pass))
                .map_err(|_| LoadError::WrongPassphrase),
        },
        Err(_) => Err(LoadError::InvalidFormat),
    }
}

/// The public half of an OpenSSH-format private key file, which is stored
/// unencrypted even when the private half is encrypted. The comment is only
/// available for unencrypted keys.
pub fn public_from_private_file(path: &Path) -> Option<PublicKey> {
    let text = fs::read_to_string(path).ok()?;
    PrivateKey::from_openssh(&text)
        .ok()
        .map(|key| key.public_key().clone())
}

/// `<path>.pub`
pub fn public_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// A public key parsed from one line of a public key, `authorized_keys` or
/// `known_hosts` file.
#[derive(Debug, Clone)]
pub struct KeyLine {
    pub key: PublicKey,
    /// What came before the key: `authorized_keys` options or `known_hosts`
    /// host patterns.
    pub preamble: Option<String>,
    /// Text after the key, unless empty or starting with `#`.
    pub comment: Option<String>,
}

impl KeyLine {
    /// Parse a line holding a public key, optionally preceded by options or
    /// host patterns (anything up to the first unquoted blank). Returns
    /// `None` for blank lines, comments, marker lines (`@cert-authority`)
    /// and anything that isn't a key.
    pub fn parse(line: &str) -> Option<KeyLine> {
        let line = line.trim_end_matches(['\r', '\n']);
        let line = line.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        if let Some((key, comment)) = parse_bare_key(line) {
            return Some(KeyLine {
                key,
                preamble: None,
                comment,
            });
        }
        let (preamble, rest) = split_preamble(line);
        let (key, comment) = parse_bare_key(rest.trim_start_matches([' ', '\t']))?;
        Some(KeyLine {
            key,
            preamble: Some(preamble.to_string()),
            comment,
        })
    }

    /// The label `ssh-keygen -l` shows: the comment, else the preamble.
    pub fn label(&self) -> Option<&str> {
        self.comment.as_deref().or(self.preamble.as_deref())
    }
}

/// `<type> <base64> [comment]`
fn parse_bare_key(line: &str) -> Option<(PublicKey, Option<String>)> {
    let mut parts = line.splitn(3, [' ', '\t']);
    let algorithm = parts.next()?;
    let blob = parts.next()?;
    let key = PublicKey::from_openssh(&format!("{algorithm} {blob}")).ok()?;
    let comment = parts
        .next()
        .map(|c| c.trim_start_matches([' ', '\t']).trim_end())
        .filter(|c| !c.is_empty() && !c.starts_with('#'))
        .map(str::to_string);
    Some((key, comment))
}

/// Split off everything up to the first blank that isn't inside double
/// quotes (`authorized_keys` options may contain quoted blanks).
fn split_preamble(line: &str) -> (&str, &str) {
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => return (&line[..i], &line[i..]),
            _ => {}
        }
    }
    (line, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAk7shWwUfM2IBq7V0QnZZSORfGadoAfaU8uT8ZHkMv6";

    #[test]
    fn bare_key_with_and_without_comment() {
        let k = KeyLine::parse(&format!("{KEY} my comment\r\n")).unwrap();
        assert_eq!(k.comment.as_deref(), Some("my comment"));
        assert_eq!(k.preamble, None);
        let k = KeyLine::parse(&format!("  {KEY}")).unwrap();
        assert_eq!(k.label(), None);
        let k = KeyLine::parse(&format!("{KEY}   # not a comment")).unwrap();
        assert_eq!(k.label(), None);
    }

    #[test]
    fn known_hosts_line() {
        let k = KeyLine::parse(&format!("host1,[host2]:22 {KEY}")).unwrap();
        assert_eq!(k.label(), Some("host1,[host2]:22"));
        let k = KeyLine::parse(&format!("host1 {KEY} trailing")).unwrap();
        assert_eq!(k.label(), Some("trailing"));
    }

    #[test]
    fn authorized_keys_options_with_quoted_blanks() {
        let line = format!(r#"no-pty,command="echo \" hi" {KEY}"#);
        let k = KeyLine::parse(&line).unwrap();
        assert_eq!(
            k.preamble.as_deref(),
            Some(r#"no-pty,command="echo \" hi""#)
        );
    }

    #[test]
    fn non_keys() {
        assert!(KeyLine::parse("").is_none());
        assert!(KeyLine::parse("# comment").is_none());
        assert!(KeyLine::parse("garbage").is_none());
        assert!(KeyLine::parse("ssh-ed25519 notbase64 x").is_none());
        assert!(KeyLine::parse(&format!("@cert-authority *.example {KEY}")).is_none());
    }
}
