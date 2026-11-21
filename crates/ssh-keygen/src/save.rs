//! Writing key files.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use russh::keys::key::safe_rng;
use russh::keys::ssh_key::rand_core::Rng;
use russh::keys::ssh_key::{Cipher, Kdf, LineEnding, PrivateKey};

use crate::args::Args;
use crate::common;
use crate::error::{Error, Result};

const DEFAULT_ROUNDS: u32 = 16;

/// How to encrypt private keys: `-Z cipher` and `-a rounds`.
#[derive(Debug, Clone, Copy)]
pub struct Encryption {
    pub cipher: Cipher,
    pub rounds: u32,
}

impl Encryption {
    pub fn from_args(args: &Args) -> Result<Self> {
        let rounds = args
            .rounds
            .as_deref()
            .map(|r| common::parse_positive(r, "Invalid number of rounds"))
            .transpose()?
            .unwrap_or(DEFAULT_ROUNDS);
        let cipher = match args.cipher.as_deref() {
            None => Cipher::Aes256Ctr,
            Some(name) => match Cipher::new(name) {
                Ok(cipher) if cipher != Cipher::None => cipher,
                _ => return Err(Error::fatal(format!("unknown cipher {name}"))),
            },
        };
        Ok(Encryption { cipher, rounds })
    }

    fn encrypt(&self, key: &PrivateKey, passphrase: &str) -> Result<PrivateKey> {
        let mut rng = safe_rng();
        let mut salt = vec![0u8; 16];
        rng.fill_bytes(&mut salt);
        let kdf = Kdf::Bcrypt {
            salt,
            rounds: self.rounds,
        };
        key.encrypt_with(self.cipher, kdf, rng.next_u32(), passphrase)
            .map_err(|e| Error::fatal(format!("encrypting key failed: {e}")))
    }
}

/// Write `key` in OpenSSH format with mode 0600, encrypted unless
/// `passphrase` is empty. `key` must be unencrypted.
pub fn save_private(
    key: &PrivateKey,
    path: &Path,
    passphrase: &str,
    encryption: &Encryption,
) -> Result<()> {
    let encrypted;
    let to_save = if passphrase.is_empty() {
        key
    } else {
        encrypted = encryption.encrypt(key, passphrase)?;
        &encrypted
    };
    let failed = |e: String| Error::fatal(format!("Saving key \"{}\" failed: {e}", path.display()));
    let pem = to_save
        .to_openssh(LineEnding::LF)
        .map_err(|e| failed(e.to_string()))?;
    write_file(path, pem.as_bytes(), 0o600).map_err(|e| failed(common::io_message(&e)))?;
    // An existing file keeps its old mode when truncated; never leave a
    // private key readable by others.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| failed(common::io_message(&e)))
}

/// Write the public half of `key` as a one-line `.pub` file (mode 0644).
pub fn save_public(key: &PrivateKey, path: &Path) -> Result<()> {
    let failed = |e: String| {
        Error::fatal(format!(
            "Unable to save public key to {}: {e}",
            path.display()
        ))
    };
    // OpenSSH always writes the separator before the comment, even when the
    // comment is empty.
    let mut line = key
        .public_key()
        .to_openssh()
        .map_err(|e| failed(e.to_string()))?;
    if key.comment().is_empty() {
        line.push(' ');
    }
    write_file(path, format!("{line}\n").as_bytes(), 0o644)
        .map_err(|e| failed(common::io_message(&e)))
}

fn write_file(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    file.write_all(contents)
}
