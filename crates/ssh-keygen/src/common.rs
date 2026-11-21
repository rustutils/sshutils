//! Helpers shared by several modes.

use std::path::PathBuf;

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
