//! User, host and path conventions shared with OpenSSH.

use std::ffi::CStr;
use std::path::PathBuf;

/// Passwd entry of the invoking user. OpenSSH uses `getpwuid(getuid())`
/// rather than `$HOME`, so we do too.
pub struct User {
    pub name: String,
    pub home: PathBuf,
}

pub fn current_user() -> Option<User> {
    // SAFETY: getpwuid returns a pointer into static storage or NULL; we copy
    // the strings out immediately. We are not multi-threaded at this point in
    // any binary that calls this, but even so the window is tiny.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() {
            return None;
        }
        let name = CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned();
        let home = CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
        Some(User {
            name,
            home: PathBuf::from(home),
        })
    }
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// `~/.ssh`
pub fn ssh_dir() -> PathBuf {
    current_user()
        .map(|u| u.home)
        .or_else(std::env::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ssh")
}

/// Expand a leading `~` or `~/` like OpenSSH's `tilde_expand_filename`.
pub fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        return ssh_dir().parent().map(PathBuf::from).unwrap_or_default();
    }
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = ssh_dir().parent()
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}

/// Default comment for new keys: `user@hostname`.
pub fn default_comment() -> String {
    let user = current_user().map(|u| u.name).unwrap_or_default();
    format!("{user}@{}", hostname())
}
