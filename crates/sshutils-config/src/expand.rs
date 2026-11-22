//! `%` token and `${VAR}` expansion, `~` expansion, and the connection hash
//! used for `%C`.

use sha1::{Digest, Sha1};
use sshutils_core::paths;

/// Why an expansion failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandError {
    /// `%x` with no value for `x`.
    UnknownToken(char),
    /// A `%` at the end of the string.
    InvalidFormat,
    /// `${` without `}`, or `${}`.
    BadVariable,
    /// `${NAME}` with `NAME` not set.
    MissingVariable(String),
}

impl std::fmt::Display for ExpandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpandError::UnknownToken(c) => write!(f, "unknown key %{c}"),
            ExpandError::InvalidFormat => write!(f, "invalid format"),
            ExpandError::BadVariable => write!(f, "invalid environment variable"),
            ExpandError::MissingVariable(name) => write!(f, "env var ${{{name}}} has no value"),
        }
    }
}

impl std::error::Error for ExpandError {}

/// Expand `%x` tokens from `tokens` (`%%` is a literal `%`) and, with
/// `dollar`, `${VAR}` environment variables.
pub fn expand(text: &str, tokens: &[(char, &str)], dollar: bool) -> Result<String, ExpandError> {
    let mut out = String::new();
    let mut missing = None;
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if dollar && rest.starts_with("${") {
            let inner = &rest[2..];
            let end = inner.find('}').ok_or(ExpandError::BadVariable)?;
            let name = &inner[..end];
            if name.is_empty() {
                return Err(ExpandError::BadVariable);
            }
            match std::env::var(name) {
                Ok(value) => out.push_str(&value),
                Err(_) => missing = Some(name.to_string()),
            }
            rest = &inner[end + 1..];
            continue;
        }
        rest = &rest[c.len_utf8()..];
        if c != '%' || tokens.is_empty() {
            out.push(c);
            continue;
        }
        let Some(key) = rest.chars().next() else {
            return Err(ExpandError::InvalidFormat);
        };
        rest = &rest[key.len_utf8()..];
        if key == '%' {
            out.push('%');
            continue;
        }
        match tokens.iter().find(|(k, _)| *k == key) {
            Some((_, value)) => out.push_str(value),
            None => return Err(ExpandError::UnknownToken(key)),
        }
    }
    match missing {
        Some(name) => Err(ExpandError::MissingVariable(name)),
        None => Ok(out),
    }
}

/// Expand only `${VAR}` (OpenSSH's `dollar_expand`).
pub fn expand_dollar(text: &str) -> Result<String, ExpandError> {
    expand(text, &[], true)
}

/// Expand a leading `~` or `~user` like OpenSSH's `tilde_expand_filename`.
pub fn expand_tilde(path: &str) -> Result<String, String> {
    let Some(rest) = path.strip_prefix('~') else {
        return Ok(path.to_string());
    };
    let (user, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let home = if user.is_empty() {
        paths::current_user()
            .map(|u| u.home)
            .ok_or_else(|| "No such user".to_string())?
    } else {
        user_home(user).ok_or_else(|| format!("No such user {user}"))?
    };
    let home = home.to_string_lossy();
    let home = home.trim_end_matches('/');
    let tail = tail.trim_start_matches('/');
    Ok(format!("{home}/{tail}"))
}

fn user_home(user: &str) -> Option<std::path::PathBuf> {
    let name = std::ffi::CString::new(user).ok()?;
    // SAFETY: getpwnam returns static storage or NULL; we copy the home
    // directory out immediately.
    unsafe {
        let pw = libc::getpwnam(name.as_ptr());
        if pw.is_null() {
            return None;
        }
        let dir = std::ffi::CStr::from_ptr((*pw).pw_dir);
        Some(std::path::PathBuf::from(dir.to_string_lossy().into_owned()))
    }
}

/// OpenSSH's connection hash (`%C`): hex SHA-1 of the local host name,
/// remote host, port, remote user and jump host.
pub fn connection_hash(
    local_host: &str,
    host: &str,
    port: &str,
    user: &str,
    jump_host: &str,
) -> String {
    let mut hasher = Sha1::new();
    for part in [local_host, host, port, user, jump_host] {
        hasher.update(part.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let tokens = [('h', "host"), ('p', "22")];
        assert_eq!(expand("%h:%p %%", &tokens, false).unwrap(), "host:22 %");
        assert_eq!(
            expand("%x", &tokens, false),
            Err(ExpandError::UnknownToken('x'))
        );
        assert_eq!(
            expand("50%", &tokens, false),
            Err(ExpandError::InvalidFormat)
        );
        assert_eq!(expand("no tokens %x", &[], false).unwrap(), "no tokens %x");
    }

    #[test]
    fn variables() {
        // SAFETY: tests in this module don't read this variable concurrently.
        unsafe { std::env::set_var("SSHUTILS_EXPAND_TEST", "value") };
        assert_eq!(
            expand_dollar("a${SSHUTILS_EXPAND_TEST}b").unwrap(),
            "avalueb"
        );
        assert_eq!(
            expand_dollar("${SSHUTILS_EXPAND_UNSET}"),
            Err(ExpandError::MissingVariable("SSHUTILS_EXPAND_UNSET".into()))
        );
        assert_eq!(
            expand_dollar("${unterminated"),
            Err(ExpandError::BadVariable)
        );
        assert_eq!(expand_dollar("$HOME"), Ok("$HOME".into()));
    }

    #[test]
    fn hash() {
        // sha1("") for empty inputs.
        assert_eq!(
            connection_hash("", "", "", "", ""),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }
}
