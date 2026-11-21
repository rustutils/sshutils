//! Operations on key files: adding (the default), `-d` and `-T`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use russh::keys::agent::Constraint;
use russh::keys::key::safe_rng;
use russh::keys::signature::Verifier;
use russh::keys::ssh_key::rand_core::Rng;
use russh::keys::ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};
use sshutils_core::keyfile::{self, KeyLine, LoadError};
use sshutils_core::{keyfmt, paths, time, tty};

use crate::error::{Error, Result, agent_message, io_message};
use crate::{Client, Settings};

/// Extra time OpenSSH gives a certificate in the agent past its expiry.
const CERTIFICATE_GRACE: u64 = 5 * 60;

/// Key files tried when none are given, in OpenSSH's order.
const DEFAULT_IDENTITIES: &[&str] = &[
    "id_rsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
];

/// The default identities that exist.
pub fn default_identities() -> Vec<PathBuf> {
    let dir = paths::ssh_dir();
    DEFAULT_IDENTITIES
        .iter()
        .map(|name| dir.join(name))
        .filter(|path| path.exists())
        .collect()
}

/// `<path>-cert.pub`
fn certificate_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push("-cert.pub");
    PathBuf::from(name)
}

/// Add each file's key (and its certificate, if any) to the agent.
pub async fn add(client: &mut Client, settings: &Settings, files: &[PathBuf]) -> Result<()> {
    // Like OpenSSH, a passphrase that worked for one file is tried first
    // for the following ones.
    let mut last_passphrase = None;
    let mut failed = false;
    for path in files {
        if !add_file(client, settings, path, &mut last_passphrase).await {
            failed = true;
        }
    }
    if failed { Err(Error::Exit(1)) } else { Ok(()) }
}

/// Add one file. Returns whether its plain key was added; OpenSSH reports
/// success by that alone, so certificates-only mode (`-C`) always "fails".
async fn add_file(
    client: &mut Client,
    settings: &Settings,
    path: &Path,
    last_passphrase: &mut Option<String>,
) -> bool {
    let args = &settings.args;
    let from_stdin = path.as_os_str() == "-";
    let name = if from_stdin {
        "(stdin)".to_string()
    } else {
        path.display().to_string()
    };

    let Some(mut key) = load_key(path, &name, from_stdin, last_passphrase) else {
        return false;
    };
    if key.comment().is_empty() {
        key.set_comment(name.as_str());
    }
    let comment = key.comment().as_str_lossy().to_string();

    let mut added = false;
    if !args.certificates_only {
        let constraints = constraints(settings.lifetime, args.confirm);
        match client.add_identity(&key, &constraints).await {
            Ok(()) => {
                added = true;
                if !args.quiet {
                    eprintln!("Identity added: {name} ({comment})");
                    report_constraints(settings.lifetime, args.confirm);
                }
            }
            Err(e) => eprintln!("Could not add identity \"{name}\": {}", agent_message(&e)),
        }
    }

    if !args.keys_only && !from_stdin {
        add_certificate(client, settings, path, &key).await;
    }
    added
}

/// Read and, if needed, decrypt a private key, prompting for the
/// passphrase until it works or an empty one is entered.
fn load_key(
    path: &Path,
    name: &str,
    from_stdin: bool,
    last_passphrase: &mut Option<String>,
) -> Option<PrivateKey> {
    let text = if from_stdin {
        let mut text = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut text) {
            eprintln!("Error loading key \"{name}\": {}", io_message(&e));
            return None;
        }
        text
    } else {
        if let Err(e) = std::fs::metadata(path) {
            eprintln!("{name}: {}", io_message(&e));
            return None;
        }
        if keyfile::check_private_permissions(path).is_err() {
            return None;
        }
        match std::fs::read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => {
                eprintln!("Error loading key \"{name}\": {}", io_message(&e));
                return None;
            }
        }
    };

    match keyfile::decode_private(&text, None) {
        Ok(key) => return Some(key),
        Err(LoadError::Encrypted) => {}
        Err(e) => {
            eprintln!("Error loading key \"{name}\": {e}");
            return None;
        }
    }
    if let Some(passphrase) = last_passphrase.as_deref()
        && let Ok(key) = keyfile::decode_private(&text, Some(passphrase))
    {
        return Some(key);
    }
    let mut prompt = format!("Enter passphrase for {name}: ");
    loop {
        let passphrase = tty::read_passphrase(&prompt).unwrap_or_default();
        if passphrase.is_empty() {
            return None;
        }
        match keyfile::decode_private(&text, Some(&passphrase)) {
            Ok(key) => {
                *last_passphrase = Some(passphrase);
                return Some(key);
            }
            Err(LoadError::WrongPassphrase) => {
                prompt = format!("Bad passphrase, try again for {name}: ");
            }
            Err(e) => {
                eprintln!("Error loading key \"{name}\": {e}");
                return None;
            }
        }
    }
}

/// Add `<path>-cert.pub` for `key`, if it exists and is usable.
async fn add_certificate(client: &mut Client, settings: &Settings, path: &Path, key: &PrivateKey) {
    let args = &settings.args;
    let cert_path = certificate_path(path);
    if !cert_path.exists() {
        return;
    }
    let cert_name = cert_path.display().to_string();
    let certificate = match Certificate::read_file(&cert_path) {
        Ok(certificate) => certificate,
        Err(e) => {
            eprintln!("Failed to load certificate \"{cert_name}\": {e}");
            return;
        }
    };
    if certificate.public_key() != key.public_key().key_data() {
        eprintln!(
            "Certificate {cert_name} does not match private key {}",
            path.display()
        );
        return;
    }

    let mut lifetime = settings.lifetime;
    if !args.no_certificate_lifetime && certificate.valid_before() != u64::MAX {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if certificate.valid_before() <= now {
            eprintln!("Certificate {cert_name} has already expired; ignored");
            return;
        }
        let remaining = certificate.valid_before() - now + CERTIFICATE_GRACE;
        let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
        lifetime = if lifetime == 0 {
            remaining
        } else {
            lifetime.min(remaining)
        };
    }

    let constraints = constraints(lifetime, args.confirm);
    match client
        .add_identity_with_certificate(key, &certificate, &constraints)
        .await
    {
        Ok(()) => {
            if !args.quiet {
                eprintln!("Certificate added: {cert_name} ({})", certificate.key_id());
                report_constraints(lifetime, args.confirm);
            }
        }
        Err(e) => eprintln!(
            "Certificate {cert_name} ({}) add failed: {}",
            certificate.key_id(),
            agent_message(&e)
        ),
    }
}

fn constraints(lifetime: u32, confirm: bool) -> Vec<Constraint> {
    let mut constraints = Vec::new();
    if lifetime > 0 {
        constraints.push(Constraint::KeyLifetime { seconds: lifetime });
    }
    if confirm {
        constraints.push(Constraint::Confirm);
    }
    constraints
}

fn report_constraints(lifetime: u32, confirm: bool) {
    if lifetime > 0 {
        eprintln!(
            "Lifetime set to {}",
            time::format_interval(u64::from(lifetime))
        );
    }
    if confirm {
        eprintln!("The user must confirm each use of the key");
    }
}

/// A public key for `path` like OpenSSH's `sshkey_load_public`: the file
/// itself, else `<path>.pub`, else the public half of a private key file.
/// Returns the key and its comment (the file name if it has none).
fn load_public(path: &Path) -> std::io::Result<(PublicKey, String)> {
    let from_lines = |file: &Path| -> std::io::Result<Option<KeyLine>> {
        let text = std::fs::read(file)?;
        Ok(String::from_utf8_lossy(&text)
            .lines()
            .find_map(KeyLine::parse))
    };
    if let Some(line) = from_lines(path)? {
        let comment = line.comment.unwrap_or_else(|| path.display().to_string());
        return Ok((line.key, comment));
    }
    let pub_path = keyfile::public_path(path);
    if let Ok(Some(line)) = from_lines(&pub_path) {
        let comment = line
            .comment
            .unwrap_or_else(|| pub_path.display().to_string());
        return Ok((line.key, comment));
    }
    if let Some(key) = keyfile::public_from_private_file(path) {
        let comment = match key.comment().as_str_lossy() {
            "" => path.display().to_string(),
            comment => comment.to_string(),
        };
        return Ok((key, comment));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid format",
    ))
}

/// `-d`: remove each file's key (and certificate) from the agent.
pub async fn delete(client: &mut Client, settings: &Settings, files: &[PathBuf]) -> Result<()> {
    let args = &settings.args;
    let mut failed = false;
    for path in files {
        let name = path.display().to_string();
        let (key, comment) = match load_public(path) {
            Ok(loaded) => loaded,
            Err(e) => {
                // OpenSSH prints this one to stdout.
                println!("Bad key file {name}: {}", io_message(&e));
                failed = true;
                continue;
            }
        };
        let label = keyfmt::type_label(key.key_data());

        if !args.certificates_only {
            match client.remove_identity(&key).await {
                Ok(()) => {
                    if !args.quiet {
                        eprintln!("Identity removed: {name} {label} ({comment})");
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Could not remove identity \"{name}\": {}",
                        agent_message(&e)
                    );
                    failed = true;
                }
            }
        }

        if !args.keys_only {
            let cert_path = certificate_path(path);
            let Ok(certificate) = Certificate::read_file(&cert_path) else {
                continue;
            };
            let cert_name = cert_path.display().to_string();
            match client.remove_certificate(&certificate).await {
                Ok(()) => {
                    if !args.quiet {
                        eprintln!("Identity removed: {cert_name} {label}-CERT ({comment})");
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Could not remove identity \"{cert_name}\": {}",
                        agent_message(&e)
                    );
                    failed = true;
                }
            }
        }
    }
    if failed { Err(Error::Exit(1)) } else { Ok(()) }
}

/// `-T`: check that the agent can make valid signatures with each key.
pub async fn test(client: &mut Client, files: &[PathBuf]) -> Result<()> {
    if files.is_empty() {
        return Err(Error::fatal("no keys to test"));
    }
    let mut failed = false;
    for path in files {
        let name = path.display().to_string();
        let key = match std::fs::read(path).map(|text| {
            String::from_utf8_lossy(&text)
                .lines()
                .find_map(KeyLine::parse)
        }) {
            Ok(Some(line)) => line.key,
            Ok(None) => {
                eprintln!("Couldn't read public key {name}: invalid format");
                failed = true;
                continue;
            }
            Err(e) => {
                eprintln!("Couldn't read public key {name}: {}", io_message(&e));
                failed = true;
                continue;
            }
        };

        let mut data = [0u8; 32];
        safe_rng().fill_bytes(&mut data);
        let hash_alg = match key.algorithm() {
            Algorithm::Rsa { .. } => Some(HashAlg::Sha512),
            _ => None,
        };
        let signature = match client.sign_request_signature(&key, hash_alg, &data).await {
            Ok(signature) => signature,
            Err(e) => {
                eprintln!("Agent signature failed for {name}: {}", agent_message(&e));
                failed = true;
                continue;
            }
        };
        if let Err(e) = key.key_data().verify(&data, &signature) {
            eprintln!("Signature verification failed for {name}: {e}");
            failed = true;
        }
    }
    if failed { Err(Error::Exit(1)) } else { Ok(()) }
}
