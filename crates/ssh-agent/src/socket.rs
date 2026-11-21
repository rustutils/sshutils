//! Agent socket locations, as in OpenSSH 10.5:
//!
//! - `-a path`: exactly `path`.
//! - `-T`: `$TMPDIR/ssh-XXXXXX??????/agent.<pid>` in a fresh 0700
//!   directory (OpenSSH's `mkdtemp` template leaves six literal `X`s).
//! - default: `~/.ssh/agent/s.<hostname hash>.agent.<10 random chars>`.
//!
//! Sockets are created with mode 0600 and existing files are never
//! replaced.

use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use russh::keys::ssh_key::rand_core::Rng;
use russh::keys::ssh_key::sha2::{Digest, Sha512};

/// Characters OpenSSH uses for random and hashed parts of socket names.
const PRESENTATION: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Length of the hostname hash in socket names.
const HOSTNAME_HASH_LEN: usize = 10;

/// Sockets younger than this are never considered stale.
const STALE_AGE: Duration = Duration::from_secs(60 * 60);

/// The default socket directory, relative to the home directory.
pub const USER_SOCKET_DIR: &str = ".ssh/agent";

/// A bound agent socket and what to remove when the agent exits.
pub struct Socket {
    pub listener: UnixListener,
    pub path: PathBuf,
    /// Directory created for the socket (`-T`), removed with it.
    pub directory: Option<PathBuf>,
}

impl Socket {
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.path);
        if let Some(directory) = &self.directory {
            let _ = std::fs::remove_dir(directory);
        }
    }
}

/// OpenSSH's hash of a host name for socket names: the first bytes of its
/// SHA-512, each mapped onto [`PRESENTATION`].
pub fn hostname_hash(hostname: &str) -> String {
    Sha512::digest(hostname.as_bytes())
        .iter()
        .take(HOSTNAME_HASH_LEN)
        .map(|b| PRESENTATION[usize::from(*b) % PRESENTATION.len()] as char)
        .collect()
}

fn random_chars(len: usize) -> String {
    let mut rng = russh::keys::key::safe_rng();
    (0..len)
        .map(|_| PRESENTATION[(rng.next_u32() as usize) % PRESENTATION.len()] as char)
        .collect()
}

/// Bind `path` with mode 0600 (OpenSSH sets a umask of 0177 around bind).
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    // SAFETY: umask only changes this process's file creation mask; it is
    // restored right after binding, while the process is single-threaded.
    let previous = unsafe { libc::umask(0o177) };
    let result = UnixListener::bind(path);
    unsafe { libc::umask(previous) };
    result
}

/// `-a path`.
pub fn bind_explicit(path: &Path) -> io::Result<Socket> {
    Ok(Socket {
        listener: bind(path)?,
        path: path.to_path_buf(),
        directory: None,
    })
}

/// `-T`: a socket in a fresh private directory under `tmpdir`.
pub fn bind_temporary(tmpdir: &Path) -> io::Result<Socket> {
    let directory = loop {
        let path = tmpdir.join(format!("ssh-XXXXXX{}", random_chars(6)));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => break path,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let path = directory.join(format!("agent.{}", std::process::id()));
    match bind(&path) {
        Ok(listener) => Ok(Socket {
            listener,
            path,
            directory: Some(directory),
        }),
        Err(e) => {
            let _ = std::fs::remove_dir(&directory);
            Err(e)
        }
    }
}

/// Default: a randomly named socket in `dir` (created with mode 0700 if
/// needed), named after the host's `hash`.
pub fn bind_user(dir: &Path, hash: &str) -> io::Result<Socket> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(dir)?;
    loop {
        let path = dir.join(format!("s.{hash}.agent.{}", random_chars(10)));
        match bind(&path) {
            Ok(listener) => {
                return Ok(Socket {
                    listener,
                    path,
                    directory: None,
                });
            }
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Remove stale sockets in `dir`, like OpenSSH: sockets last modified more
/// than an hour before `now` that nothing listens on anymore. With
/// `prefix`, only names starting with it (sockets from this host).
pub fn cleanup_stale(dir: &Path, prefix: Option<&str>, now: SystemTime) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let cutoff = now.checked_sub(STALE_AGE).unwrap_or(SystemTime::UNIX_EPOCH);
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if prefix.is_some_and(|prefix| !name.starts_with(prefix)) {
            continue;
        }
        let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !metadata.file_type().is_socket() {
            continue;
        }
        let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.mtime().max(0) as u64);
        if modified > cutoff {
            continue;
        }
        // Something still listening means the socket is in use.
        if UnixStream::connect(entry.path()).is_err() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn hostname_hash_matches_openssh() {
        // `fedora` gives the hash in OpenSSH 10.5's socket names on such a
        // host (s.9ShwXHKxSA.*).
        assert_eq!(hostname_hash("fedora"), "9ShwXHKxSA");
    }

    #[test]
    fn user_sockets_are_private_and_named_like_openssh() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".ssh/agent");
        let socket = bind_user(&dir, "HASH").unwrap();
        let name = socket
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(name.starts_with("s.HASH.agent."), "{name}");
        assert_eq!(name.len(), "s.HASH.agent.".len() + 10);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&socket.path), 0o600);
        socket.cleanup();
        assert!(!socket.path.exists());
        assert!(dir.exists(), "the directory stays");
    }

    #[test]
    fn stale_sockets_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // A socket nobody listens on, one still in use, one from another
        // host, and a regular file.
        let stale = d.join("s.HOST.agent.stale");
        drop(UnixListener::bind(&stale).unwrap());
        let active = d.join("s.HOST.agent.active");
        let _listener = UnixListener::bind(&active).unwrap();
        let other = d.join("s.OTHER.agent.stale");
        drop(UnixListener::bind(&other).unwrap());
        let file = d.join("s.HOST.agent.file");
        std::fs::write(&file, "").unwrap();

        // Too recent: nothing is removed.
        cleanup_stale(d, Some("s.HOST."), SystemTime::now());
        assert!(stale.exists());

        let later = SystemTime::now() + STALE_AGE + Duration::from_secs(60);
        cleanup_stale(d, Some("s.HOST."), later);
        assert!(!stale.exists());
        assert!(active.exists());
        assert!(other.exists());
        assert!(file.exists());

        // Without a prefix, other hosts' stale sockets go too.
        cleanup_stale(d, None, later);
        assert!(!other.exists());
        assert!(active.exists());
    }
}
