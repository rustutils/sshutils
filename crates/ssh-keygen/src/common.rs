//! Helpers shared by several modes.

use std::path::{Path, PathBuf};

use russh::keys::ssh_key::PrivateKey;
use sshutils_core::keyfile::{self, LoadError};

use sshutils_core::keyfmt::{self, FingerprintHash};
use sshutils_core::{paths, tty};

use crate::args::Args;
use crate::error::{Error, Result};
use crate::generate::{DEFAULT_TYPE, KeyType};

/// Ask for a key file name, offering `~/.ssh/id_<type>` as the default
/// (the type from `-t`, or ed25519). Exits with status 1 on end of input.
pub fn ask_filename(question: &str, key_type: KeyType) -> Result<PathBuf> {
    let default = paths::ssh_dir().join(key_type.default_file_name());
    let answer = tty::prompt_line(&format!("{question} ({}): ", default.display()))
        .map_err(|_| Error::Exit(1))?;
    Ok(if answer.is_empty() {
        default
    } else {
        PathBuf::from(answer)
    })
}

/// The key file for modes that read an existing key: `-f`, or ask.
pub fn existing_key_file(args: &Args) -> Result<PathBuf> {
    if let Some(file) = &args.file {
        return Ok(file.clone());
    }
    let key_type = args
        .key_type
        .as_deref()
        .and_then(|t| KeyType::parse(t).ok())
        .unwrap_or_else(|| KeyType::parse(DEFAULT_TYPE).expect("default type is valid"));
    ask_filename("Enter file in which the key is", key_type)
}

/// The `-E` fingerprint hash, SHA256 by default.
pub fn fingerprint_hash(args: &Args) -> Result<FingerprintHash> {
    match args.fingerprint_hash.as_deref() {
        None => Ok(FingerprintHash::Sha256),
        Some(name) => keyfmt::parse_hash_alg(name)
            .ok_or_else(|| Error::fatal(format!("Invalid hash algorithm \"{name}\""))),
    }
}

/// An I/O error as `strerror` would describe it, without Rust's
/// "(os error N)" suffix.
pub fn io_message(err: &std::io::Error) -> String {
    let message = err.to_string();
    match message.find(" (os error ") {
        Some(i) => message[..i].to_string(),
        None => message,
    }
}

/// Parse a positive integer option value.
pub fn parse_positive(value: &str, what: &str) -> Result<u32> {
    match value.parse::<u32>() {
        Ok(0) => Err(Error::fatal(format!(
            "{what} has bad value {value} (too small)"
        ))),
        Ok(n) => Ok(n),
        Err(_) => Err(Error::fatal(format!(
            "{what} has bad value {value} (invalid)"
        ))),
    }
}

/// Whether `path` is in OpenSSH's own private key format, the only one
/// that stores a comment.
pub fn has_comment_field(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|text| text.contains("BEGIN OPENSSH PRIVATE KEY"))
}

/// Fail like OpenSSH if the key file doesn't exist.
pub fn require_exists(path: &Path) -> Result<()> {
    std::fs::metadata(path)
        .map(drop)
        .map_err(|e| Error::fatal(format!("{}: {}", path.display(), io_message(&e))))
}

/// Load a private key. Tries without a passphrase first; if the key is
/// encrypted, uses `given` (from `-P`) or asks with `prompt`. Returns the
/// key and the passphrase that worked (empty if none was needed).
pub fn load_private_key(
    path: &Path,
    given: Option<&str>,
    prompt: &str,
) -> std::result::Result<(PrivateKey, String), LoadError> {
    match keyfile::load_private(path, None) {
        Ok(key) => Ok((key, String::new())),
        Err(LoadError::Encrypted) => {
            let passphrase = match given {
                Some(passphrase) => passphrase.to_string(),
                None => tty::read_passphrase(prompt).map_err(LoadError::Io)?,
            };
            let key = keyfile::load_private(path, Some(&passphrase))?;
            Ok((key, passphrase))
        }
        Err(e) => Err(e),
    }
}
