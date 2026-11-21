//! `known_hosts` operations:
//!
//! - `ssh-keygen -F host [-lv] [-H] [-f file]`: show entries for a host
//! - `ssh-keygen -R host [-f file]`: remove entries for a host
//! - `ssh-keygen -H [-f file]`: hash all host names
//!
//! The file defaults to `~/.ssh/known_hosts`. Files are rewritten like
//! OpenSSH does: the new contents go to a temporary file with the original
//! mode, the original is kept as `<file>.old`, and the new file is renamed
//! into place.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use russh::keys::key::safe_rng;
use russh::keys::ssh_key::rand_core::Rng;
use sshutils_core::known_hosts::{self, Entry, Line, Marker};
use sshutils_core::{keyfmt, paths};

use crate::args::Args;
use crate::common;
use crate::error::{Error, Result};

/// `-F host`: print matching entries. Exits 1 if there are none.
pub fn find(args: &Args, host: &str) -> Result<()> {
    let hash = common::fingerprint_hash(args)?;
    let (_, text) = read_known_hosts(args)?;
    let mut found = false;
    for (number, raw) in lines(&text) {
        let Line::Entry(entry) = Line::parse(raw) else {
            continue;
        };
        if !entry.matches(host) {
            continue;
        }
        found = true;
        let marker = match entry.marker {
            Marker::None => "",
            Marker::CertAuthority => "CA",
            Marker::Revoked => "REVOKED",
        };
        println!("# Host {host} found: line {number} {marker}");
        let key = entry.key.key_data();
        if args.fingerprint {
            let comment = entry.comment().map(|c| format!(" {c}")).unwrap_or_default();
            println!(
                "{host} {} {}{comment}",
                keyfmt::type_label(key),
                keyfmt::fingerprint(key, hash)
            );
            if args.verbose > 0 {
                println!("{}", keyfmt::randomart(key, hash));
            }
        } else if args.hash_known_hosts && can_hash(&entry) {
            for line in hashed_lines(&entry) {
                println!("{line}");
            }
        } else {
            println!("{}", raw.trim_end_matches('\r'));
        }
    }
    if found { Ok(()) } else { Err(Error::Exit(1)) }
}

/// `-R host`: remove entries for `host` (marker lines are kept).
pub fn remove(args: &Args, host: &str) -> Result<()> {
    let (path, text) = read_known_hosts(args)?;
    let mut kept = Vec::new();
    let mut invalid = Vec::new();
    let mut removed = false;
    for (number, raw) in lines(&text) {
        match Line::parse(raw) {
            Line::Entry(entry) if entry.marker == Marker::None && entry.matches(host) => {
                println!("# Host {host} found: line {number}");
                removed = true;
            }
            Line::Invalid => {
                invalid.push(number);
                kept.push(raw.to_string());
            }
            _ => kept.push(raw.to_string()),
        }
    }
    refuse_if_invalid(&path, &invalid)?;
    if !removed {
        eprintln!("Host {host} not found in {}", path.display());
        return Ok(());
    }
    replace_file(&path, &kept)?;
    print_updated(&path);
    Ok(())
}

/// `-H`: replace every plain host name with its hash.
pub fn hash(args: &Args) -> Result<()> {
    let (path, text) = read_known_hosts(args)?;
    let mut output = Vec::new();
    let mut invalid = Vec::new();
    let mut hashed_any = false;
    for (number, raw) in lines(&text) {
        match Line::parse(raw) {
            Line::Entry(entry) if can_hash(&entry) => {
                output.extend(hashed_lines(&entry));
                hashed_any = true;
            }
            Line::Entry(entry) => {
                if entry.has_wildcards() {
                    eprintln!(
                        "{}:{number}: ignoring host name with wildcard: {}",
                        path.display(),
                        entry.hosts
                    );
                }
                output.push(raw.to_string());
            }
            Line::Invalid => {
                invalid.push(number);
                output.push(raw.to_string());
            }
            Line::Comment => output.push(raw.to_string()),
        }
    }
    refuse_if_invalid(&path, &invalid)?;
    replace_file(&path, &output)?;
    print_updated(&path);
    if hashed_any {
        eprintln!(
            "WARNING: {}.old contains unhashed entries\n\
             Delete this file to ensure privacy of hostnames",
            path.display()
        );
    }
    Ok(())
}

/// Plain entries without wildcards can be hashed; marker lines are left
/// alone, as in OpenSSH.
fn can_hash(entry: &Entry<'_>) -> bool {
    entry.marker == Marker::None && !entry.is_hashed() && !entry.has_wildcards()
}

/// One hashed line per host name in the entry, with a fresh salt each.
fn hashed_lines(entry: &Entry<'_>) -> Vec<String> {
    let mut rng = safe_rng();
    entry
        .hosts
        .split(',')
        .filter(|name| !name.is_empty())
        .map(|name| {
            let mut salt = [0u8; 20];
            rng.fill_bytes(&mut salt);
            let hashed = known_hosts::hash_host(&name.to_ascii_lowercase(), &salt);
            format!("{hashed} {}", entry.key_text)
        })
        .collect()
}

/// `(line number, line)` pairs.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().map(|(i, line)| (i + 1, line))
}

/// The `-f` file or `~/.ssh/known_hosts`, and its contents.
fn read_known_hosts(args: &Args) -> Result<(PathBuf, String)> {
    let path = args
        .file
        .clone()
        .unwrap_or_else(|| paths::ssh_dir().join("known_hosts"));
    let bytes = fs::read(&path).map_err(|e| {
        Error::fatal(format!(
            "Cannot stat {}: {}",
            path.display(),
            common::io_message(&e)
        ))
    })?;
    Ok((path, String::from_utf8_lossy(&bytes).into_owned()))
}

fn refuse_if_invalid(path: &Path, invalid: &[usize]) -> Result<()> {
    if invalid.is_empty() {
        return Ok(());
    }
    for number in invalid {
        eprintln!("{}:{number}: invalid line", path.display());
    }
    eprintln!(
        "{} is not a valid known_hosts file.\n\
         Not replacing existing known_hosts file because of errors",
        path.display()
    );
    Err(Error::Exit(1))
}

fn print_updated(path: &Path) {
    println!("{} updated.", path.display());
    println!("Original contents retained as {}.old", path.display());
}

/// Replace `path` with `lines`, keeping the original as `<path>.old`.
fn replace_file(path: &Path, lines: &[String]) -> Result<()> {
    let failed = |what: &str, e: std::io::Error| {
        Error::fatal(format!(
            "{what} {}: {}",
            path.display(),
            common::io_message(&e)
        ))
    };
    let mode = fs::metadata(path)
        .map_err(|e| failed("Cannot stat", e))?
        .permissions()
        .mode()
        & 0o7777;

    let (temp_path, mut temp) = create_temp(path, mode).map_err(|e| failed("mkstemp for", e))?;
    let mut contents = String::new();
    for line in lines {
        contents.push_str(line);
        contents.push('\n');
    }
    let result = temp
        .write_all(contents.as_bytes())
        .and_then(|()| temp.sync_all())
        // Like the file itself, the temporary file gets the original mode
        // regardless of the umask.
        .and_then(|()| fs::set_permissions(&temp_path, fs::Permissions::from_mode(mode)));
    if let Err(e) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(failed("Writing", e));
    }

    let old = with_suffix(path, ".old");
    let swap = || -> std::io::Result<()> {
        match fs::remove_file(&old) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        // A hard link (not following symlinks, like link(2)) keeps the
        // original in place until the rename, so the file never vanishes.
        fs::hard_link(path, &old)?;
        fs::rename(&temp_path, path)
    };
    swap().map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        failed("Replacing", e)
    })
}

/// Create `<path>.<random>` exclusively, with `mode`.
fn create_temp(path: &Path, mode: u32) -> std::io::Result<(PathBuf, fs::File)> {
    let mut rng = safe_rng();
    loop {
        let candidate = with_suffix(path, &format!(".{:08x}", rng.next_u32()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
