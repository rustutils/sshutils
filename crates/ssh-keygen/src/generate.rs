//! Key generation: `ssh-keygen [-q] [-a rounds] [-b bits] [-C comment]
//! [-f file] [-N passphrase] [-t type] [-Z cipher]`.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use russh::keys::key::safe_rng;
use russh::keys::ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
use russh::keys::ssh_key::rand_core::Rng;
use russh::keys::ssh_key::{Cipher, EcdsaCurve, Kdf, LineEnding, PrivateKey};
use sshutils_core::keyfmt::{self, FingerprintHash};
use sshutils_core::{paths, tty};

use crate::args::Args;
use crate::error::{Error, Result};

const DEFAULT_TYPE: &str = "ed25519";
const DEFAULT_RSA_BITS: u32 = 3072;
const MIN_RSA_BITS: u32 = 1024;
const MAX_RSA_BITS: u32 = 16384;
const DEFAULT_ROUNDS: u32 = 16;

/// Key types we can generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyType {
    Rsa,
    /// ECDSA; the curve is fixed if the full algorithm name was given.
    Ecdsa(Option<EcdsaCurve>),
    Ed25519,
}

impl KeyType {
    /// Parse a `-t` argument. Accepts the short names and full algorithm
    /// names, case-insensitively, like OpenSSH.
    fn parse(name: &str) -> Result<Self> {
        let key_type = match name.to_ascii_lowercase().as_str() {
            "rsa" | "ssh-rsa" => KeyType::Rsa,
            "ecdsa" => KeyType::Ecdsa(None),
            "ecdsa-sha2-nistp256" => KeyType::Ecdsa(Some(EcdsaCurve::NistP256)),
            "ecdsa-sha2-nistp384" => KeyType::Ecdsa(Some(EcdsaCurve::NistP384)),
            "ecdsa-sha2-nistp521" => KeyType::Ecdsa(Some(EcdsaCurve::NistP521)),
            "ed25519" | "ssh-ed25519" => KeyType::Ed25519,
            "ecdsa-sk"
            | "ed25519-sk"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
            | "sk-ssh-ed25519@openssh.com" => {
                return Err(Error::fatal(
                    "security key (FIDO) types are not supported yet",
                ));
            }
            "mldsa44-ed25519" => {
                return Err(Error::fatal(format!(
                    "key type {name} is not supported yet"
                )));
            }
            _ => return Err(Error::fatal(format!("unknown key type {name}"))),
        };
        Ok(key_type)
    }

    /// Default file name in `~/.ssh`.
    fn default_file_name(self) -> &'static str {
        match self {
            KeyType::Rsa => "id_rsa",
            KeyType::Ecdsa(_) => "id_ecdsa",
            KeyType::Ed25519 => "id_ed25519",
        }
    }
}

/// Everything about the key to generate, validated before doing any work.
#[derive(Debug)]
struct Plan {
    type_name: String,
    key_type: KeyType,
    rsa_bits: u32,
    curve: EcdsaCurve,
    rounds: u32,
    cipher: Cipher,
    hash: FingerprintHash,
}

impl Plan {
    fn from_args(args: &Args) -> Result<Self> {
        let type_name = args.key_type.as_deref().unwrap_or(DEFAULT_TYPE).to_string();
        let key_type = KeyType::parse(&type_name)?;

        let bits = args
            .bits
            .as_deref()
            .map(|b| parse_positive(b, "Bits"))
            .transpose()?;

        let rsa_bits = bits.unwrap_or(DEFAULT_RSA_BITS);
        if key_type == KeyType::Rsa {
            if rsa_bits < MIN_RSA_BITS {
                return Err(Error::fatal(format!(
                    "Invalid RSA key length: minimum is {MIN_RSA_BITS} bits"
                )));
            }
            if rsa_bits > MAX_RSA_BITS {
                return Err(Error::fatal(format!(
                    "Invalid RSA key length: maximum is {MAX_RSA_BITS} bits"
                )));
            }
        }

        let curve = match (key_type, bits) {
            (KeyType::Ecdsa(Some(curve)), _) => curve,
            (KeyType::Ecdsa(None), None | Some(256)) => EcdsaCurve::NistP256,
            (KeyType::Ecdsa(None), Some(384)) => EcdsaCurve::NistP384,
            (KeyType::Ecdsa(None), Some(521)) => EcdsaCurve::NistP521,
            (KeyType::Ecdsa(None), Some(_)) => {
                return Err(Error::fatal(
                    "Invalid ECDSA key length: valid lengths are 256, 384 or 521 bits",
                ));
            }
            _ => EcdsaCurve::NistP256,
        };

        let rounds = args
            .rounds
            .as_deref()
            .map(|r| parse_positive(r, "Invalid number of rounds"))
            .transpose()?
            .unwrap_or(DEFAULT_ROUNDS);

        let cipher = match args.cipher.as_deref() {
            None => Cipher::Aes256Ctr,
            Some(name) => match Cipher::new(name) {
                Ok(cipher) if cipher != Cipher::None => cipher,
                _ => return Err(Error::fatal(format!("unknown cipher {name}"))),
            },
        };

        let hash = match args.fingerprint_hash.as_deref() {
            None => FingerprintHash::Sha256,
            Some(name) => keyfmt::parse_hash_alg(name)
                .ok_or_else(|| Error::fatal(format!("Invalid hash algorithm \"{name}\"")))?,
        };

        Ok(Plan {
            type_name,
            key_type,
            rsa_bits,
            curve,
            rounds,
            cipher,
            hash,
        })
    }

    fn generate(&self) -> Result<PrivateKey> {
        let mut rng = safe_rng();
        let keypair = match self.key_type {
            KeyType::Rsa => KeypairData::Rsa(
                RsaKeypair::random(&mut rng, self.rsa_bits as usize)
                    .map_err(|e| Error::fatal(format!("key generation failed: {e}")))?,
            ),
            KeyType::Ecdsa(_) => KeypairData::Ecdsa(
                EcdsaKeypair::random(&mut rng, self.curve)
                    .map_err(|e| Error::fatal(format!("key generation failed: {e}")))?,
            ),
            KeyType::Ed25519 => KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)),
        };
        PrivateKey::new(keypair, "")
            .map_err(|e| Error::fatal(format!("key generation failed: {e}")))
    }
}

/// Parse a positive integer option value.
fn parse_positive(value: &str, what: &str) -> Result<u32> {
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

pub fn run(args: &Args) -> Result<()> {
    let plan = Plan::from_args(args)?;

    if !args.quiet {
        println!("Generating public/private {} key pair.", plan.type_name);
    }
    let mut key = plan.generate()?;

    let path = match &args.file {
        Some(path) => path.clone(),
        None => ask_filename(plan.key_type)?,
    };
    create_ssh_dir_if_needed(&path, args.quiet)?;
    confirm_overwrite(&path)?;

    let passphrase = match &args.new_passphrase {
        Some(passphrase) => passphrase.clone(),
        None => ask_new_passphrase(&path)?,
    };
    let comment = args.comment.clone().unwrap_or_else(paths::default_comment);
    key.set_comment(comment.as_str());

    let to_save = if passphrase.is_empty() {
        key.clone()
    } else {
        encrypt(&key, &passphrase, plan.cipher, plan.rounds)?
    };
    save_private(&to_save, &path)?;
    let pub_path = public_path(&path);
    save_public(&key, &pub_path)?;

    if !args.quiet {
        let public = key.public_key().key_data();
        println!("Your identification has been saved in {}", path.display());
        println!("Your public key has been saved in {}", pub_path.display());
        println!("The key fingerprint is:");
        println!("{} {comment}", keyfmt::fingerprint(public, plan.hash));
        println!("The key's randomart image is:");
        println!("{}", keyfmt::randomart(public, plan.hash));
    }
    Ok(())
}

/// Ask where to save the key, offering `~/.ssh/<default>`.
fn ask_filename(key_type: KeyType) -> Result<PathBuf> {
    let default = paths::ssh_dir().join(key_type.default_file_name());
    let answer = tty::prompt_line(&format!(
        "Enter file in which to save the key ({}): ",
        default.display()
    ))
    .map_err(|_| Error::Exit(1))?;
    Ok(if answer.is_empty() {
        default
    } else {
        PathBuf::from(answer)
    })
}

/// If the key goes into a missing `~/.ssh`, create it (mode 0700).
fn create_ssh_dir_if_needed(path: &Path, quiet: bool) -> Result<()> {
    let ssh_dir = paths::ssh_dir();
    if !path.starts_with(&ssh_dir) || ssh_dir.exists() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&ssh_dir)
        .map_err(|e| {
            Error::fatal(format!(
                "Could not create directory '{}': {e}",
                ssh_dir.display()
            ))
        })?;
    if !quiet {
        println!("Created directory '{}'.", ssh_dir.display());
    }
    Ok(())
}

/// If `path` exists, ask before overwriting it. Anything but `y...` exits 1.
fn confirm_overwrite(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_err() {
        return Ok(());
    }
    println!("{} already exists.", path.display());
    match tty::prompt_line("Overwrite (y/n)? ") {
        Ok(answer) if answer.starts_with('y') => Ok(()),
        _ => Err(Error::Exit(1)),
    }
}

/// Ask for a new passphrase twice until both entries match.
fn ask_new_passphrase(path: &Path) -> Result<String> {
    loop {
        let first = tty::read_passphrase(&format!(
            "Enter passphrase for \"{}\" (empty for no passphrase): ",
            path.display()
        ))
        .map_err(|e| Error::fatal(format!("reading passphrase: {e}")))?;
        let second = tty::read_passphrase("Enter same passphrase again: ")
            .map_err(|e| Error::fatal(format!("reading passphrase: {e}")))?;
        if first == second {
            return Ok(first);
        }
        println!("Passphrases do not match.  Try again.");
    }
}

fn encrypt(key: &PrivateKey, passphrase: &str, cipher: Cipher, rounds: u32) -> Result<PrivateKey> {
    let mut rng = safe_rng();
    let mut salt = vec![0u8; 16];
    rng.fill_bytes(&mut salt);
    let kdf = Kdf::Bcrypt { salt, rounds };
    key.encrypt_with(cipher, kdf, rng.next_u32(), passphrase)
        .map_err(|e| Error::fatal(format!("encrypting key failed: {e}")))
}

/// `<path>.pub`
fn public_path(path: &Path) -> PathBuf {
    let mut pub_path = OsString::from(path.as_os_str());
    pub_path.push(".pub");
    PathBuf::from(pub_path)
}

fn save_private(key: &PrivateKey, path: &Path) -> Result<()> {
    let failed = |e: &dyn std::fmt::Display| {
        Error::fatal(format!("Saving key \"{}\" failed: {e}", path.display()))
    };
    let pem = key.to_openssh(LineEnding::LF).map_err(|e| failed(&e))?;
    write_file(path, pem.as_bytes(), 0o600).map_err(|e| failed(&e))?;
    // An existing file keeps its old mode when truncated; never leave a
    // private key readable by others.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| failed(&e))
}

fn save_public(key: &PrivateKey, path: &Path) -> Result<()> {
    let failed = |e: &dyn std::fmt::Display| {
        Error::fatal(format!(
            "Unable to save public key to {}: {e}",
            path.display()
        ))
    };
    let line = key.public_key().to_openssh().map_err(|e| failed(&e))?;
    write_file(path, format!("{line}\n").as_bytes(), 0o644).map_err(|e| failed(&e))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_type_names() {
        assert_eq!(KeyType::parse("RSA").unwrap(), KeyType::Rsa);
        assert_eq!(KeyType::parse("ssh-ed25519").unwrap(), KeyType::Ed25519);
        assert_eq!(
            KeyType::parse("ecdsa-sha2-nistp384").unwrap(),
            KeyType::Ecdsa(Some(EcdsaCurve::NistP384))
        );
        assert!(KeyType::parse("dsa").is_err());
        assert!(KeyType::parse("ed25519-sk").is_err());
    }

    #[test]
    fn public_path_appends_suffix() {
        assert_eq!(public_path(Path::new("dir/key")), Path::new("dir/key.pub"));
    }
}
