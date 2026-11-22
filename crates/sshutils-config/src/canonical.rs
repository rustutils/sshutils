//! Hostname canonicalization (`CanonicalizeHostname` and friends), done the
//! way `ssh` does it before reading the configuration a second time.
//!
//! - Numeric addresses are always put into their canonical form (`127.1`
//!   becomes `127.0.0.1`), whether canonicalization is enabled or not.
//! - With canonicalization enabled, a name with few enough dots is looked up
//!   with each of `CanonicalDomains` appended; a name ending in a dot is
//!   looked up as it is. Names reached through a proxy are left alone unless
//!   it is `always`.
//! - `CanonicalizePermittedCNAMEs` decide which DNS aliases replace the
//!   name. With permitted CNAMEs, a name that canonicalization didn't
//!   resolve is still looked up for its aliases.

use std::ffi::{CStr, CString};
use std::net::SocketAddr;

use crate::matching::match_pattern_list;
use crate::options::Options;
use crate::reader::{Fatal, valid_domain};
use crate::values::*;

/// The result of looking a name up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lookup {
    pub addresses: Vec<SocketAddr>,
    /// The canonical name the resolver reported, if asked for.
    pub canonical_name: Option<String>,
}

/// Name resolution, so canonicalization can be tested without DNS.
pub trait Resolver {
    /// Look `name` up (`getaddrinfo`), restricted to `family` (`AF_INET`,
    /// `AF_INET6`, or `AF_UNSPEC` for both). Errors are the resolver's
    /// message.
    fn lookup(
        &self,
        name: &str,
        port: u16,
        family: i32,
        canonical_name: bool,
    ) -> Result<Lookup, String>;

    /// Parse `name` as a single numeric address. Returns its addresses and
    /// its canonical text form.
    fn numeric(&self, name: &str, port: u16, family: i32) -> Option<(Vec<SocketAddr>, String)>;
}

/// The system resolver.
pub struct SystemResolver;

/// What `getaddrinfo` returned.
struct AddrInfo {
    addresses: Vec<SocketAddr>,
    /// The canonical name, if requested and reported.
    canonical_name: Option<String>,
    /// For a single result, its numeric text form.
    numeric: Option<String>,
}

/// Run `getaddrinfo` and collect what it returned.
fn getaddrinfo(name: &str, port: u16, family: i32, flags: i32) -> Result<AddrInfo, String> {
    let name = CString::new(name).map_err(|_| "invalid name".to_string())?;
    let service = CString::new(port.to_string()).expect("digits have no NUL");
    // SAFETY: an all-zero addrinfo is valid hints; the result list is only
    // read while alive and then freed; addresses match their lengths.
    unsafe {
        let mut hints: libc::addrinfo = std::mem::zeroed();
        hints.ai_family = family;
        hints.ai_socktype = libc::SOCK_STREAM;
        hints.ai_flags = flags;
        let mut result: *mut libc::addrinfo = std::ptr::null_mut();
        let status = libc::getaddrinfo(name.as_ptr(), service.as_ptr(), &hints, &mut result);
        if status != 0 {
            let message = CStr::from_ptr(libc::gai_strerror(status));
            return Err(message.to_string_lossy().into_owned());
        }
        let mut addresses = Vec::new();
        let mut canonical_name = None;
        let mut numeric = None;
        if !result.is_null() {
            if !(*result).ai_canonname.is_null() {
                let name = CStr::from_ptr((*result).ai_canonname);
                canonical_name = Some(name.to_string_lossy().into_owned());
            }
            if (*result).ai_next.is_null() {
                let mut text = [0 as libc::c_char; libc::NI_MAXHOST as usize];
                if libc::getnameinfo(
                    (*result).ai_addr,
                    (*result).ai_addrlen,
                    text.as_mut_ptr(),
                    text.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NUMERICHOST,
                ) == 0
                {
                    numeric = Some(CStr::from_ptr(text.as_ptr()).to_string_lossy().into_owned());
                }
            }
        }
        let mut entry = result;
        while !entry.is_null() {
            if let Some(address) = socket_address((*entry).ai_addr) {
                addresses.push(address);
            }
            entry = (*entry).ai_next;
        }
        if !result.is_null() {
            libc::freeaddrinfo(result);
        }
        Ok(AddrInfo {
            addresses,
            canonical_name,
            numeric,
        })
    }
}

/// # Safety
///
/// `sa` must be null or point to a socket address of its family's size.
unsafe fn socket_address(sa: *const libc::sockaddr) -> Option<SocketAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: guaranteed by the caller.
    unsafe {
        match i32::from((*sa).sa_family) {
            libc::AF_INET => {
                let sin = &*(sa as *const libc::sockaddr_in);
                Some(SocketAddr::V4(std::net::SocketAddrV4::new(
                    u32::from_be(sin.sin_addr.s_addr).into(),
                    u16::from_be(sin.sin_port),
                )))
            }
            libc::AF_INET6 => {
                let sin6 = &*(sa as *const libc::sockaddr_in6);
                Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                    sin6.sin6_addr.s6_addr.into(),
                    u16::from_be(sin6.sin6_port),
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

impl Resolver for SystemResolver {
    fn lookup(
        &self,
        name: &str,
        port: u16,
        family: i32,
        canonical_name: bool,
    ) -> Result<Lookup, String> {
        let flags = if canonical_name {
            libc::AI_CANONNAME
        } else {
            0
        };
        let info = getaddrinfo(name, port, family, flags)?;
        Ok(Lookup {
            addresses: info.addresses,
            canonical_name: info.canonical_name,
        })
    }

    fn numeric(&self, name: &str, port: u16, family: i32) -> Option<(Vec<SocketAddr>, String)> {
        let flags = libc::AI_NUMERICHOST | libc::AI_NUMERICSERV;
        let info = getaddrinfo(name, port, family, flags).ok()?;
        Some((info.addresses, info.numeric?))
    }
}

/// The address family to look names up with.
fn family(options: &Options) -> i32 {
    match options.address_family {
        Some(AF_INET) => libc::AF_INET,
        Some(AF_INET6) => libc::AF_INET6,
        _ => libc::AF_UNSPEC,
    }
}

/// The port lookups are made for: the configured one or 22.
fn port(options: &Options) -> u16 {
    options
        .port
        .filter(|&p| p > 0)
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(22)
}

/// Can `name` only be an address, never a host name?
fn looks_like_address(name: &str) -> bool {
    name.contains(['%', ':']) || name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// Is `name` a single numeric address (OpenSSH's `is_addr`)?
pub fn is_address(resolver: &dyn Resolver, options: &Options, name: &str) -> bool {
    looks_like_address(name)
        || resolver
            .numeric(name, port(options), family(options))
            .is_some_and(|(addresses, _)| addresses.len() == 1)
}

/// Does the configuration permit any CNAMEs (`none` doesn't)?
pub fn has_permitted_cnames(options: &Options) -> bool {
    match options.permitted_cnames.as_slice() {
        [] => false,
        [only] => !(only.source.eq_ignore_ascii_case("none") && only.target.is_empty()),
        _ => true,
    }
}

/// Is the host reached directly, not through a proxy or jump host?
pub fn is_direct(options: &Options) -> bool {
    let clear = |o: &Option<String>| o.as_deref().is_none_or(|v| v.eq_ignore_ascii_case("none"));
    clear(&options.proxy_command) && clear(&options.jump_host)
}

/// The canonical name a lookup reported, if it is a valid domain name
/// (without a trailing dot). Invalid ones are reported and ignored.
fn checked_cname(name: &str, lookup: &Lookup, warnings: &mut Vec<String>) -> String {
    let Some(cname) = &lookup.canonical_name else {
        return String::new();
    };
    match valid_domain(cname) {
        Ok(()) => cname.strip_suffix('.').unwrap_or(cname).to_string(),
        Err(error) => {
            warnings.push(format!(
                "ignoring bad CNAME \"{cname}\" for host \"{name}\": {error}"
            ));
            String::new()
        }
    }
}

/// Replace `name` with `cname` if a `CanonicalizePermittedCNAMEs` rule
/// allows it. Returns whether it did.
pub fn follow_cname(options: &Options, direct: bool, name: &mut String, cname: &str) -> bool {
    if cname.is_empty() || !has_permitted_cnames(options) || name == cname {
        return false;
    }
    let canonicalize = options.canonicalize_hostname.unwrap_or(CANONICALIZE_NO);
    if canonicalize == CANONICALIZE_NO || (!direct && canonicalize != CANONICALIZE_ALWAYS) {
        return false;
    }
    let permitted = options.permitted_cnames.iter().any(|rule| {
        match_pattern_list(name, &rule.source, true) == 1
            && match_pattern_list(cname, &rule.target, true) == 1
    });
    if permitted {
        *name = cname.to_ascii_lowercase();
    }
    permitted
}

/// Canonicalize `host` like OpenSSH's `resolve_canonicalize`: addresses
/// always, names if enabled. Returns the addresses found, if any.
pub fn canonicalize(
    resolver: &dyn Resolver,
    options: &Options,
    host: &mut String,
    warnings: &mut Vec<String>,
) -> Result<Option<Vec<SocketAddr>>, Fatal> {
    let (port, family) = (port(options), family(options));
    if let Some((addresses, text)) = resolver.numeric(host, port, family)
        && addresses.len() == 1
    {
        if !host.eq_ignore_ascii_case(&text) {
            *host = text;
        }
        return Ok(Some(addresses));
    }
    // An address that didn't parse (a bad scope, say) isn't a name either.
    if looks_like_address(host) {
        return Ok(None);
    }
    let canonicalize = options.canonicalize_hostname.unwrap_or(CANONICALIZE_NO);
    if canonicalize == CANONICALIZE_NO {
        return Ok(None);
    }
    let direct = is_direct(options);
    if !direct && canonicalize != CANONICALIZE_ALWAYS {
        return Ok(None);
    }

    // Each candidate is looked up fully qualified (with a trailing dot).
    let candidates: Vec<String> = if host.ends_with('.') {
        vec![host.clone()]
    } else {
        let dots = host.matches('.').count();
        if dots > options.canonicalize_max_dots.unwrap_or(1).max(0) as usize {
            return Ok(None);
        }
        options
            .canonical_domains
            .iter()
            .take_while(|domain| !domain.eq_ignore_ascii_case("none"))
            .map(|domain| format!("{host}.{domain}."))
            .collect()
    };
    for candidate in candidates {
        let Ok(lookup) = resolver.lookup(&candidate, port, family, true) else {
            continue;
        };
        let mut name = candidate
            .strip_suffix('.')
            .unwrap_or(&candidate)
            .to_string();
        let cname = checked_cname(&candidate, &lookup, warnings);
        follow_cname(options, direct, &mut name, &cname);
        *host = name;
        return Ok(Some(lookup.addresses));
    }
    if options.canonicalize_fallback_local == Some(0) {
        return Err(Fatal(format!("Could not resolve host \"{host}\"")));
    }
    Ok(None)
}

/// After canonicalization: with permitted CNAMEs, look a name that wasn't
/// resolved yet up and follow its aliases. A direct connection to a name
/// that doesn't resolve fails.
pub fn follow_aliases(
    resolver: &dyn Resolver,
    options: &Options,
    host: &mut String,
    warnings: &mut Vec<String>,
) -> Result<Option<Vec<SocketAddr>>, Fatal> {
    let direct = is_direct(options);
    let always = options.canonicalize_hostname == Some(CANONICALIZE_ALWAYS);
    if !has_permitted_cnames(options) || !(direct || always) {
        return Ok(None);
    }
    match resolver.lookup(host, port(options), family(options), true) {
        Err(error) if direct => Err(Fatal(format!("Could not resolve hostname {host}: {error}"))),
        Err(error) => {
            warnings.push(format!("Could not resolve hostname {host}: {error}"));
            Ok(None)
        }
        Ok(lookup) => {
            let cname = checked_cname(host, &lookup, warnings);
            follow_cname(options, direct, host, &cname);
            Ok(Some(lookup.addresses))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::options::PermittedCname;

    /// Names that resolve, with their canonical names.
    struct Fake(HashMap<&'static str, Option<&'static str>>);

    impl Resolver for Fake {
        fn lookup(&self, name: &str, port: u16, _: i32, _: bool) -> Result<Lookup, String> {
            match self.0.get(name) {
                None => Err("Name or service not known".into()),
                Some(cname) => Ok(Lookup {
                    addresses: vec![SocketAddr::from(([192, 0, 2, 1], port))],
                    canonical_name: cname.map(String::from),
                }),
            }
        }

        fn numeric(&self, name: &str, port: u16, family: i32) -> Option<(Vec<SocketAddr>, String)> {
            SystemResolver.numeric(name, port, family)
        }
    }

    fn fake() -> Fake {
        Fake(HashMap::from([
            ("web.a.test.", None),
            ("web.b.test.", Some("web.b.test")),
            ("db.b.test.", Some("real.c.test.")),
            ("up.b.test.", Some("Upper.C.Test")),
            ("fq.test.", None),
            ("alias", Some("target.c.test")),
            ("bad", Some("-bad.test")),
        ]))
    }

    fn options(canonicalize: i32) -> Options {
        let mut o = Options {
            canonicalize_hostname: Some(canonicalize),
            canonicalize_max_dots: Some(1),
            canonicalize_fallback_local: Some(1),
            ..Options::default()
        };
        o.canonical_domains = vec!["a.test".into(), "b.test".into()];
        o
    }

    fn permit(o: &mut Options, source: &str, target: &str) {
        o.permitted_cnames.push(PermittedCname {
            source: source.into(),
            target: target.into(),
        });
    }

    fn run(o: &Options, host: &str) -> Result<(String, bool), Fatal> {
        let mut host = host.to_string();
        let found = canonicalize(&fake(), o, &mut host, &mut Vec::new())?;
        Ok((host, found.is_some()))
    }

    #[test]
    fn addresses() {
        let o = options(CANONICALIZE_NO);
        assert_eq!(run(&o, "127.1").unwrap(), ("127.0.0.1".into(), true));
        assert_eq!(run(&o, "::0001").unwrap(), ("::1".into(), true));
        assert_eq!(run(&o, "FE80::1").unwrap(), ("FE80::1".into(), true));
        assert_eq!(run(&o, "1:2:3").unwrap(), ("1:2:3".into(), false));
    }

    #[test]
    fn domains() {
        let o = options(CANONICALIZE_YES);
        assert_eq!(run(&o, "web").unwrap(), ("web.a.test".into(), true));
        assert_eq!(run(&o, "db").unwrap(), ("db.b.test".into(), true));
        assert_eq!(run(&o, "fq.test.").unwrap(), ("fq.test".into(), true));
        // Too many dots, unknown, disabled: unchanged.
        assert_eq!(run(&o, "web.x.y").unwrap(), ("web.x.y".into(), false));
        assert_eq!(run(&o, "nope").unwrap(), ("nope".into(), false));
        assert_eq!(
            run(&options(CANONICALIZE_NO), "web").unwrap(),
            ("web".into(), false)
        );
        // No fallback.
        let mut strict = options(CANONICALIZE_YES);
        strict.canonicalize_fallback_local = Some(0);
        assert!(run(&strict, "nope").is_err());
        assert!(run(&strict, "nope.test.").is_err());
        // "CanonicalDomains none" (which must appear alone).
        let mut none = options(CANONICALIZE_YES);
        none.canonical_domains = vec!["none".into()];
        assert_eq!(run(&none, "web").unwrap(), ("web".into(), false));
    }

    #[test]
    fn proxies() {
        let mut o = options(CANONICALIZE_YES);
        o.proxy_command = Some("nc %h %p".into());
        assert_eq!(run(&o, "web").unwrap(), ("web".into(), false));
        o.proxy_command = Some("none".into());
        assert_eq!(run(&o, "web").unwrap(), ("web.a.test".into(), true));
        o.jump_host = Some("jump".into());
        assert_eq!(run(&o, "web").unwrap(), ("web".into(), false));
        o.canonicalize_hostname = Some(CANONICALIZE_ALWAYS);
        assert_eq!(run(&o, "web").unwrap(), ("web.a.test".into(), true));
    }

    #[test]
    fn cnames() {
        let mut o = options(CANONICALIZE_YES);
        assert_eq!(run(&o, "db").unwrap().0, "db.b.test");
        permit(&mut o, "*.b.test", "*.d.test");
        assert_eq!(run(&o, "db").unwrap().0, "db.b.test");
        permit(&mut o, "*.b.test", "*.c.test");
        assert_eq!(run(&o, "db").unwrap().0, "real.c.test");
        // Patterns are lowercased, names aren't (as in OpenSSH).
        assert_eq!(run(&o, "up").unwrap().0, "up.b.test");

        // Aliases of a name canonicalization didn't resolve.
        let aliases = |o: &Options, host: &str| {
            let mut host = host.to_string();
            follow_aliases(&fake(), o, &mut host, &mut Vec::new()).map(|_| host)
        };
        let mut o = options(CANONICALIZE_NO);
        permit(&mut o, "*", "*");
        // Looked up, but only followed with canonicalization enabled.
        assert_eq!(aliases(&o, "alias").unwrap(), "alias");
        assert!(aliases(&o, "unknown").is_err());
        o.canonicalize_hostname = Some(CANONICALIZE_YES);
        assert_eq!(aliases(&o, "alias").unwrap(), "target.c.test");
        // Invalid canonical names are ignored.
        let mut warnings = Vec::new();
        let mut host = "bad".to_string();
        follow_aliases(&fake(), &o, &mut host, &mut warnings).unwrap();
        assert_eq!(host, "bad");
        assert_eq!(warnings.len(), 1);
        // Through a proxy: not looked up, so no error.
        o.proxy_command = Some("nc %h %p".into());
        assert_eq!(aliases(&o, "unknown").unwrap(), "unknown");
        // "none" permits nothing.
        let mut o = options(CANONICALIZE_YES);
        permit(&mut o, "none", "");
        assert_eq!(aliases(&o, "unknown").unwrap(), "unknown");
    }
}
