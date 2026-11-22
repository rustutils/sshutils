//! Forwarding specifications, jump hosts and `user@host:port` forms.

use crate::expand::expand_dollar;
use crate::values::parse_port;

/// Longest Unix socket path (`sun_path`).
const MAX_SOCKET_PATH: usize = 108;
/// Longest host name (`NI_MAXHOST`).
const MAX_HOST: usize = 1025;

/// One end of a forward: a TCP port (with optional bind host) or a Unix
/// socket path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Tcp { host: Option<String>, port: i32 },
    Path(String),
}

/// A `LocalForward`, `RemoteForward` or `DynamicForward`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    pub listen: Endpoint,
    /// `None` for dynamic (SOCKS) forwards.
    pub connect: Option<Endpoint>,
}

impl Forward {
    pub fn is_dynamic(&self) -> bool {
        self.connect.is_none()
    }
}

/// One field of a forward spec and whether it looks like a path.
struct Field {
    text: String,
    is_path: bool,
}

/// Split the next `:`-separated field. A field in `[...]` is taken
/// literally; otherwise backslash escapes the next character.
fn next_field(rest: &mut &str) -> Option<Result<Field, ()>> {
    if rest.is_empty() {
        return None;
    }
    if let Some(inner) = rest.strip_prefix('[') {
        let Some(end) = inner.find(']') else {
            return Some(Err(()));
        };
        let after = &inner[end + 1..];
        if !(after.is_empty() || after.starts_with(':')) {
            return Some(Err(()));
        }
        let text = &inner[..end];
        *rest = after.strip_prefix(':').unwrap_or(after);
        return Some(Ok(Field {
            text: text.to_string(),
            is_path: text.contains('/'),
        }));
    }
    let mut text = String::new();
    let mut is_path = false;
    let mut chars = rest.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some((_, escaped)) => text.push(escaped),
                None => return Some(Err(())),
            },
            '/' => {
                is_path = true;
                text.push(c);
            }
            ':' => {
                *rest = &rest[i + 1..];
                return Some(Ok(Field { text, is_path }));
            }
            _ => text.push(c),
        }
    }
    *rest = "";
    Some(Ok(Field { text, is_path }))
}

/// Parse a forward spec like OpenSSH's `parse_forward`:
/// `[bind:]port:host:hostport`, socket paths, or for dynamic forwards
/// `[bind:]port`. `${VAR}` is expanded first.
pub fn parse_forward(spec: &str, dynamic: bool, remote: bool) -> Option<Forward> {
    let expanded = expand_dollar(spec).ok()?;
    let mut rest = expanded.trim_start();
    let mut fields = Vec::new();
    while fields.len() < 4 {
        match next_field(&mut rest)? {
            Ok(field) => fields.push(field),
            Err(()) => return None,
        }
        if rest.is_empty() {
            break;
        }
    }
    if !rest.is_empty() {
        return None;
    }
    let port = |field: &Field| parse_port(&field.text).unwrap_or(-1);
    let tcp = |host: Option<&Field>, port_field: &Field| Endpoint::Tcp {
        host: host.map(|h| h.text.clone()),
        port: port(port_field),
    };
    let path = |field: &Field| Endpoint::Path(field.text.clone());

    let (listen, connect) = match fields.as_slice() {
        [a] => (if a.is_path { path(a) } else { tcp(None, a) }, None),
        [a, b] if a.is_path && b.is_path => (path(a), Some(path(b))),
        [a, b] if b.is_path => (tcp(None, a), Some(path(b))),
        [a, b] => (tcp(Some(a), b), None),
        [a, b, c] if a.is_path => (path(a), Some(tcp(Some(b), c))),
        [a, b, c] if c.is_path => (tcp(Some(a), b), Some(path(c))),
        [a, b, c] => (tcp(None, a), Some(tcp(Some(b), c))),
        [a, b, c, d] => (tcp(Some(a), b), Some(tcp(Some(c), d))),
        _ => return None,
    };

    let count = fields.len();
    if dynamic {
        if !(count == 1 || count == 2) || connect.is_some() {
            return None;
        }
    } else {
        let has_path =
            matches!(listen, Endpoint::Path(_)) || matches!(connect, Some(Endpoint::Path(_)));
        if !(count == 3 || count == 4) && !has_path {
            return None;
        }
        match &connect {
            Some(Endpoint::Tcp { port, .. }) if *port <= 0 => return None,
            None => return None,
            _ => {}
        }
    }
    match &listen {
        Endpoint::Tcp { port, .. } if *port < 0 || (!remote && *port == 0) => return None,
        _ => {}
    }
    for endpoint in std::iter::once(&listen).chain(connect.as_ref()) {
        match endpoint {
            Endpoint::Path(p) if p.len() >= MAX_SOCKET_PATH => return None,
            Endpoint::Tcp { host: Some(h), .. } if h.len() >= MAX_HOST => return None,
            _ => {}
        }
    }
    Some(Forward { listen, connect })
}

/// Format one end of a forward like `ssh -G`.
pub fn format_endpoint(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Path(path) => path.clone(),
        Endpoint::Tcp { host: None, port } => port.to_string(),
        Endpoint::Tcp {
            host: Some(host),
            port,
        } => format!("[{host}]:{port}"),
    }
}

/// Characters OpenSSH never allows in host names given on the command
/// line or in `ProxyJump`.
pub fn valid_hostname(host: &str) -> bool {
    !host.starts_with('-')
        && !host
            .chars()
            .any(|c| "'`\"$\\;&<>|(){},".contains(c) || c.is_whitespace() || c.is_control())
}

/// Characters OpenSSH never allows in user names given on the command
/// line.
pub fn valid_user(user: &str) -> bool {
    if user.starts_with('-') {
        return false;
    }
    let chars: Vec<char> = user.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c.is_control() || "'`\";&<>|(){}".contains(c) {
            return false;
        }
        if c.is_whitespace() && chars.get(i + 1) == Some(&'-') {
            return false;
        }
        if c == '\\' && i + 1 == chars.len() {
            return false;
        }
    }
    true
}

/// A destination: optional user, host and optional port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<i32>,
}

/// Split off the host (bracketed, or up to `:` or `/`) like OpenSSH's
/// `hpdelim`; returns the host and the rest after the delimiter.
pub(crate) fn split_host(text: &str) -> Option<(&str, Option<(char, &str)>)> {
    let end = if text.starts_with('[') {
        text.find(']')? + 1
    } else {
        text.find([':', '/']).unwrap_or(text.len())
    };
    let host = &text[..end];
    let rest = &text[end..];
    match rest.chars().next() {
        None => Some((host, None)),
        Some(c @ (':' | '/')) => Some((host, Some((c, &rest[1..])))),
        Some(_) => None,
    }
}

/// Remove `[...]` around an address.
fn clean_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Parse `[user@]host[:port]` (the last `@` separates the user).
pub fn parse_user_host_port(text: &str) -> Option<Destination> {
    let (user, rest) = match text.rfind('@') {
        Some(0) => return None,
        Some(i) => (Some(text[..i].to_string()), &text[i + 1..]),
        None => (None, text),
    };
    let (host, after) = split_host(rest)?;
    if host.is_empty() {
        return None;
    }
    let port = match after {
        Some((_, port)) if !port.is_empty() => Some(parse_port(port).filter(|&p| p > 0)?),
        _ => None,
    };
    Some(Destination {
        user,
        host: clean_host(host).to_string(),
        port,
    })
}

/// The outcome of [`parse_ssh_uri`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uri {
    /// Not an `ssh://` URI.
    NotUri,
    Invalid,
    Valid(Destination),
}

/// Parse `ssh://[user[;params]@]host[:port]` (no path allowed).
pub fn parse_ssh_uri(text: &str) -> Uri {
    let Some(rest) = text.strip_prefix("ssh://") else {
        return Uri::NotUri;
    };
    let (user, rest) = match rest.find('@') {
        Some(i) => {
            let info = &rest[..i];
            let user = info.split(';').next().unwrap_or("");
            if user.is_empty() {
                return Uri::Invalid;
            }
            match url_decode(user) {
                Some(user) => (Some(user), &rest[i + 1..]),
                None => return Uri::Invalid,
            }
        }
        None => (None, rest),
    };
    let Some((host, after)) = split_host(rest) else {
        return Uri::Invalid;
    };
    let host = clean_host(host);
    if host.is_empty() || !valid_domain(host) {
        return Uri::Invalid;
    }
    let mut port = None;
    match after {
        None => {}
        Some((':', rest)) => {
            let (port_text, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i + 1..]),
                None => (rest, ""),
            };
            if !port_text.is_empty() || !path.is_empty() {
                match parse_port(port_text).filter(|&p| p > 0) {
                    Some(p) => port = Some(p),
                    None => return Uri::Invalid,
                }
            }
            if !path.is_empty() {
                return Uri::Invalid;
            }
        }
        Some((_, path)) if !path.is_empty() => return Uri::Invalid,
        Some(_) => {}
    }
    Uri::Valid(Destination {
        user,
        host: host.to_string(),
        port,
    })
}

fn url_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = text.get(i + 1..i + 3)?;
                let value = u8::from_str_radix(hex, 16).ok()?;
                if value == 0 {
                    return None;
                }
                out.push(value);
                i += 3;
            }
            b'+' => return None,
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// A host name in an `ssh://` URI: letters, digits, `-`, `_`, `.`.
fn valid_domain(name: &str) -> bool {
    let first = name.chars().next();
    if !first.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// A parsed `ProxyJump`: the first hop in detail, the rest as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jump {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<i32>,
    /// Hops before the last one (`a,b` of `a,b,c`), passed on to the jump
    /// host's own `ssh -J`.
    pub extra: Option<String>,
}

/// Parse a `ProxyJump` value (not `none`) like OpenSSH's `parse_jump`.
/// Every hop is checked; `strict` also validates names.
pub fn parse_jump(spec: &str, strict: bool) -> Option<Jump> {
    let spec = spec.split('#').next().unwrap_or("").trim_end();
    let mut first = None;
    for hop in spec.rsplit(',') {
        let destination = match parse_ssh_uri(hop) {
            Uri::Valid(destination) => destination,
            Uri::Invalid => return None,
            Uri::NotUri => parse_user_host_port(hop)?,
        };
        if strict
            && (!valid_hostname(&destination.host)
                || destination.user.as_deref().is_some_and(|u| !valid_user(u)))
        {
            return None;
        }
        if first.is_none() {
            first = Some(destination);
        }
    }
    let last = first?;
    let extra = spec.rfind(',').map(|i| spec[..i].to_string());
    Some(Jump {
        user: last.user,
        host: last.host,
        port: last.port,
        extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(host: Option<&str>, port: i32) -> Endpoint {
        Endpoint::Tcp {
            host: host.map(str::to_string),
            port,
        }
    }

    #[test]
    fn forwards() {
        let f = parse_forward("8080:localhost:80", false, false).unwrap();
        assert_eq!(f.listen, tcp(None, 8080));
        assert_eq!(f.connect, Some(tcp(Some("localhost"), 80)));
        let f = parse_forward("[::1]:8080:[::2]:80", false, false).unwrap();
        assert_eq!(f.listen, tcp(Some("::1"), 8080));
        assert_eq!(f.connect, Some(tcp(Some("::2"), 80)));
        let f = parse_forward("/tmp/sock:/remote/sock", false, false).unwrap();
        assert_eq!(f.listen, Endpoint::Path("/tmp/sock".into()));
        let f = parse_forward("1080", true, false).unwrap();
        assert!(f.is_dynamic());
        let f = parse_forward("localhost:1080", true, false).unwrap();
        assert_eq!(f.listen, tcp(Some("localhost"), 1080));
        assert!(parse_forward("8080", false, false).is_none());
        assert!(parse_forward("0:host:80", false, false).is_none());
        assert!(parse_forward("0:host:80", false, true).is_some());
        assert!(parse_forward("8080:host:0", false, false).is_none());
        assert!(parse_forward("a:b:c:d:e", false, false).is_none());
    }

    #[test]
    fn destinations() {
        let d = parse_user_host_port("me@host:2222").unwrap();
        assert_eq!(
            (d.user.as_deref(), d.host.as_str(), d.port),
            (Some("me"), "host", Some(2222))
        );
        let d = parse_user_host_port("a@b@[::1]:22").unwrap();
        assert_eq!((d.user.as_deref(), d.host.as_str()), (Some("a@b"), "::1"));
        assert!(parse_user_host_port("@host").is_none());
        assert!(parse_user_host_port("host:0").is_none());
        assert_eq!(
            parse_ssh_uri("ssh://me@host:2222"),
            Uri::Valid(Destination {
                user: Some("me".into()),
                host: "host".into(),
                port: Some(2222)
            })
        );
        assert_eq!(parse_ssh_uri("ssh://host/path"), Uri::Invalid);
        assert_eq!(parse_ssh_uri("host"), Uri::NotUri);
    }

    #[test]
    fn jumps() {
        let j = parse_jump("a@one:1,two,me@three:3", true).unwrap();
        assert_eq!(
            (j.user.as_deref(), j.host.as_str(), j.port),
            (Some("me"), "three", Some(3))
        );
        assert_eq!(j.extra.as_deref(), Some("a@one:1,two"));
        assert!(parse_jump("good,bad;host", true).is_none());
    }
}
