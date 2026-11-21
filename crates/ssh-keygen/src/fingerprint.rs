//! `ssh-keygen -l [-v] [-E hash] [-f file]`: show key fingerprints.
//!
//! The file may be a public key, a private key, or an `authorized_keys` or
//! `known_hosts` file with one key per line; `-` reads from stdin.

use std::io::Read;
use std::path::Path;

use russh::keys::ssh_key::public::KeyData;
use sshutils_core::keyfile::{self, KeyLine};
use sshutils_core::keyfmt::{self, FingerprintHash};

use crate::args::Args;
use crate::common;
use crate::error::{Error, Result};

pub fn run(args: &Args) -> Result<()> {
    let hash = common::fingerprint_hash(args)?;
    let path = common::existing_key_file(args)?;
    let show = |key: &KeyData, label: Option<&str>| print_key(key, label, hash, args.verbose > 0);

    if path.as_os_str() == "-" {
        let mut text = String::new();
        let _ = std::io::stdin().read_to_string(&mut text);
        return fingerprint_lines(&text, "(stdin)", show);
    }

    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::fatal(format!(
                "{}: {}",
                path.display(),
                common::io_message(&e)
            )));
        }
        // Directories and unreadable files aren't key files.
        Err(_) => Vec::new(),
    };
    let text = String::from_utf8_lossy(&bytes);

    // Like OpenSSH: a file whose first line mentions a private key is one.
    let first_line = text.lines().next().unwrap_or_default();
    if first_line.contains("PRIVATE KEY") {
        return fingerprint_private(&path, show);
    }
    fingerprint_lines(&text, &path.display().to_string(), show)
}

/// Every key in a public key, `authorized_keys` or `known_hosts` file.
fn fingerprint_lines(text: &str, name: &str, show: impl Fn(&KeyData, Option<&str>)) -> Result<()> {
    let mut found = false;
    for line in text.lines() {
        if let Some(parsed) = KeyLine::parse(line) {
            show(parsed.key.key_data(), parsed.label());
            found = true;
        }
    }
    if found {
        Ok(())
    } else {
        Err(Error::fatal(format!("{name} is not a public key file.")))
    }
}

/// A private key file: prefer `<file>.pub`, then the unencrypted private
/// key, then the public half stored in the private key file.
fn fingerprint_private(path: &Path, show: impl Fn(&KeyData, Option<&str>)) -> Result<()> {
    let pub_path = keyfile::public_path(path);
    if let Some(parsed) = std::fs::read_to_string(&pub_path)
        .ok()
        .and_then(|text| text.lines().find_map(KeyLine::parse))
    {
        // An empty comment shows the .pub file's name instead.
        let name = pub_path.display().to_string();
        show(
            parsed.key.key_data(),
            Some(parsed.comment.as_deref().unwrap_or(&name)),
        );
        return Ok(());
    }
    if let Ok(key) = keyfile::load_private(path, None) {
        // Only OpenSSH's own format stores a comment; for PEM and PKCS#8
        // keys OpenSSH shows "no comment" rather than an empty one.
        let comment = common::has_comment_field(path).then(|| key.comment().as_str_lossy());
        show(key.public_key().key_data(), comment);
        return Ok(());
    }
    if let Some(public) = keyfile::public_from_private_file(path) {
        show(public.key_data(), None);
        return Ok(());
    }
    Err(Error::fatal(format!(
        "{} is not a key file.",
        path.display()
    )))
}

/// `256 SHA256:... comment (ED25519)`, plus randomart with `-v`.
fn print_key(key: &KeyData, label: Option<&str>, hash: FingerprintHash, randomart: bool) {
    println!(
        "{} {} {} ({})",
        keyfmt::bits(key),
        keyfmt::fingerprint(key, hash),
        label.unwrap_or("no comment"),
        keyfmt::type_label(key),
    );
    if randomart {
        println!("{}", keyfmt::randomart(key, hash));
    }
}
