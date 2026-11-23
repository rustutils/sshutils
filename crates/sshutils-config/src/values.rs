//! Value types of `ssh_config` options and their textual forms.
//!
//! Options with a fixed set of values ("multistate" options) are stored as
//! integers, like OpenSSH, with a table mapping names to values. `ssh -G`
//! prints the first name listed for a value, so the tables keep OpenSSH's
//! order.

/// A name ↔ value table for a multistate option.
pub type Multistate = &'static [(&'static str, i32)];

pub const FLAG: Multistate = &[("true", 1), ("false", 0), ("yes", 1), ("no", 0)];
pub const YES_NO_ASK: Multistate = &[("true", 1), ("false", 0), ("yes", 1), ("no", 0), ("ask", 2)];
pub const YES_NO_ASK_CONFIRM: Multistate = &[
    ("true", 1),
    ("false", 0),
    ("yes", 1),
    ("no", 0),
    ("ask", 2),
    ("confirm", 3),
];
/// `AddKeysToAgent` values (`YES_NO_ASK_CONFIRM`).
pub const ADD_KEYS_NO: i32 = 0;
pub const ADD_KEYS_YES: i32 = 1;
pub const ADD_KEYS_ASK: i32 = 2;
pub const ADD_KEYS_CONFIRM: i32 = 3;

pub const STRICT_HOSTKEY_OFF: i32 = 0;
pub const STRICT_HOSTKEY_NEW: i32 = 1;
pub const STRICT_HOSTKEY_YES: i32 = 2;
pub const STRICT_HOSTKEY_ASK: i32 = 3;
pub const STRICT_HOSTKEY: Multistate = &[
    ("true", STRICT_HOSTKEY_YES),
    ("false", STRICT_HOSTKEY_OFF),
    ("yes", STRICT_HOSTKEY_YES),
    ("no", STRICT_HOSTKEY_OFF),
    ("ask", STRICT_HOSTKEY_ASK),
    ("off", STRICT_HOSTKEY_OFF),
    ("accept-new", STRICT_HOSTKEY_NEW),
];

pub const AF_UNSPEC: i32 = 0;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;
pub const ADDRESS_FAMILY: Multistate =
    &[("inet", AF_INET), ("inet6", AF_INET6), ("any", AF_UNSPEC)];

pub const CONTROL_MASTER_NO: i32 = 0;
pub const CONTROL_MASTER_YES: i32 = 1;
pub const CONTROL_MASTER_AUTO: i32 = 2;
pub const CONTROL_MASTER_ASK: i32 = 3;
pub const CONTROL_MASTER_AUTO_ASK: i32 = 4;
pub const CONTROL_MASTER: Multistate = &[
    ("true", CONTROL_MASTER_YES),
    ("yes", CONTROL_MASTER_YES),
    ("false", CONTROL_MASTER_NO),
    ("no", CONTROL_MASTER_NO),
    ("auto", CONTROL_MASTER_AUTO),
    ("ask", CONTROL_MASTER_ASK),
    ("autoask", CONTROL_MASTER_AUTO_ASK),
];

pub const TUNNEL_NO: i32 = 0;
pub const TUNNEL_POINTOPOINT: i32 = 1;
pub const TUNNEL_ETHERNET: i32 = 2;
pub const TUNNEL_DEFAULT: i32 = TUNNEL_POINTOPOINT;
pub const TUNNEL: Multistate = &[
    ("ethernet", TUNNEL_ETHERNET),
    ("point-to-point", TUNNEL_POINTOPOINT),
    ("true", TUNNEL_DEFAULT),
    ("yes", TUNNEL_DEFAULT),
    ("false", TUNNEL_NO),
    ("no", TUNNEL_NO),
];

pub const REQUEST_TTY_AUTO: i32 = 0;
pub const REQUEST_TTY_NO: i32 = 1;
pub const REQUEST_TTY_YES: i32 = 2;
pub const REQUEST_TTY_FORCE: i32 = 3;
pub const REQUEST_TTY: Multistate = &[
    ("true", REQUEST_TTY_YES),
    ("yes", REQUEST_TTY_YES),
    ("false", REQUEST_TTY_NO),
    ("no", REQUEST_TTY_NO),
    ("force", REQUEST_TTY_FORCE),
    ("auto", REQUEST_TTY_AUTO),
];

pub const SESSION_TYPE_NONE: i32 = 0;
pub const SESSION_TYPE_SUBSYSTEM: i32 = 1;
pub const SESSION_TYPE_DEFAULT: i32 = 2;
pub const SESSION_TYPE: Multistate = &[
    ("none", SESSION_TYPE_NONE),
    ("subsystem", SESSION_TYPE_SUBSYSTEM),
    ("default", SESSION_TYPE_DEFAULT),
];

pub const CANONICALIZE_NO: i32 = 0;
pub const CANONICALIZE_YES: i32 = 1;
pub const CANONICALIZE_ALWAYS: i32 = 2;
pub const CANONICALIZE_HOSTNAME: Multistate = &[
    ("true", CANONICALIZE_YES),
    ("false", CANONICALIZE_NO),
    ("yes", CANONICALIZE_YES),
    ("no", CANONICALIZE_NO),
    ("always", CANONICALIZE_ALWAYS),
];

pub const PUBKEY_AUTH_NO: i32 = 0;
pub const PUBKEY_AUTH_UNBOUND: i32 = 1;
pub const PUBKEY_AUTH_HOST_BOUND: i32 = 2;
pub const PUBKEY_AUTH_ALL: i32 = PUBKEY_AUTH_UNBOUND | PUBKEY_AUTH_HOST_BOUND;
pub const PUBKEY_AUTH: Multistate = &[
    ("true", PUBKEY_AUTH_ALL),
    ("false", PUBKEY_AUTH_NO),
    ("yes", PUBKEY_AUTH_ALL),
    ("no", PUBKEY_AUTH_NO),
    ("unbound", PUBKEY_AUTH_UNBOUND),
    ("host-bound", PUBKEY_AUTH_HOST_BOUND),
];

/// `ssh -C` sets this value, which `-G` prints as `UNKNOWN` since it isn't
/// in the table; `Compression yes` sets [`COMPRESSION_DELAYED`]. Any value
/// but 0 enables compression.
pub const COMPRESSION_ZLIB: i32 = 1;
pub const COMPRESSION_DELAYED: i32 = 2;
pub const COMPRESSION: Multistate = &[("yes", COMPRESSION_DELAYED), ("no", 0)];

pub const WARN_WEAK_CRYPTO: Multistate = &[
    ("true", 1),
    ("false", 0),
    ("yes", 1),
    ("no", 0),
    ("no-pq-kex", 0),
];

/// Look up a value by name (case-insensitively).
pub fn parse_multistate(table: Multistate, name: &str) -> Option<i32> {
    table
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|&(_, value)| value)
}

/// The first name for a value, as `ssh -G` prints it.
pub fn format_multistate(table: Multistate, value: i32) -> &'static str {
    table
        .iter()
        .find(|&&(_, v)| v == value)
        .map_or("UNKNOWN", |&(name, _)| name)
}

/// Plain yes/no formatting for flags.
pub fn format_flag(value: i32) -> &'static str {
    match value {
        0 => "no",
        1 => "yes",
        _ => "UNKNOWN",
    }
}

/// `LogLevel` names; the first name for a value is the one printed.
pub const LOG_LEVELS: Multistate = &[
    ("QUIET", 0),
    ("FATAL", 1),
    ("ERROR", 2),
    ("INFO", 3),
    ("VERBOSE", 4),
    ("DEBUG", 5),
    ("DEBUG1", 5),
    ("DEBUG2", 6),
    ("DEBUG3", 7),
];
pub const LOG_LEVEL_INFO: i32 = 3;
pub const LOG_LEVEL_QUIET: i32 = 0;
pub const LOG_LEVEL_DEBUG1: i32 = 5;
pub const LOG_LEVEL_DEBUG3: i32 = 7;

/// `SyslogFacility` names.
pub const LOG_FACILITIES: Multistate = &[
    ("DAEMON", 0),
    ("USER", 1),
    ("AUTH", 2),
    ("AUTHPRIV", 3),
    ("LOCAL0", 4),
    ("LOCAL1", 5),
    ("LOCAL2", 6),
    ("LOCAL3", 7),
    ("LOCAL4", 8),
    ("LOCAL5", 9),
    ("LOCAL6", 10),
    ("LOCAL7", 11),
];
pub const LOG_FACILITY_USER: i32 = 1;

/// `FingerprintHash` values, named like OpenSSH's digest names.
pub const FINGERPRINT_HASHES: Multistate = &[
    ("MD5", 0),
    ("SHA1", 1),
    ("SHA256", 2),
    ("SHA384", 3),
    ("SHA512", 4),
];
pub const FINGERPRINT_SHA256: i32 = 2;

/// `IPQoS` names and DSCP values. `none` is `i32::MAX` (CS0 is 0); the
/// deprecated ToS names are `i32::MIN` and mean "system default".
pub const IPQOS: Multistate = &[
    ("none", i32::MAX),
    ("af11", 0x28),
    ("af12", 0x30),
    ("af13", 0x38),
    ("af21", 0x48),
    ("af22", 0x50),
    ("af23", 0x58),
    ("af31", 0x68),
    ("af32", 0x70),
    ("af33", 0x78),
    ("af41", 0x88),
    ("af42", 0x90),
    ("af43", 0x98),
    ("cs0", 0x00),
    ("cs1", 0x20),
    ("cs2", 0x40),
    ("cs3", 0x60),
    ("cs4", 0x80),
    ("cs5", 0xa0),
    ("cs6", 0xc0),
    ("cs7", 0xe0),
    ("ef", 0xb8),
    ("le", 0x04),
    ("va", 0xb0),
    ("lowdelay", i32::MIN),
    ("throughput", i32::MIN),
    ("reliability", i32::MIN),
];
pub const IPQOS_EF: i32 = 0xb8;
pub const IPQOS_CS0: i32 = 0x00;

/// Parse an `IPQoS` value: a name or a number from 0 to 255.
pub fn parse_ipqos(text: &str) -> Option<i32> {
    parse_multistate(IPQOS, text).or_else(|| {
        let value = parse_number(text)?;
        (0..=255).contains(&value).then_some(value as i32)
    })
}

/// Format an `IPQoS` value like OpenSSH's `iptos2str`.
pub fn format_ipqos(value: i32) -> String {
    match IPQOS.iter().find(|&&(_, v)| v == value) {
        Some(&(name, _)) => name.to_string(),
        None => format!("0x{value:02x}"),
    }
}

/// `EscapeChar none`.
pub const ESCAPE_NONE: i32 = -2;

/// Parse an escape character: one character, `^X` for a control
/// character, or `none`.
pub fn parse_escape_char(text: &str) -> Option<i32> {
    if text == "none" {
        return Some(ESCAPE_NONE);
    }
    let bytes = text.as_bytes();
    match bytes {
        [c] => Some(i32::from(*c)),
        [b'^', c] if (64..128).contains(c) => Some(i32::from(c & 31)),
        _ => None,
    }
}

/// Format an escape character like `ssh -G`'s `vis(3)` call: printable
/// characters as they are, a space as `\040`, control characters as `\^X`
/// and high bytes as `\M-x`.
pub fn format_escape_char(value: i32) -> String {
    if value == ESCAPE_NONE {
        return "none".to_string();
    }
    let c = value as u8;
    match c {
        b' ' => "\\040".to_string(),
        0x21..=0x7e => (c as char).to_string(),
        0x7f => "\\^?".to_string(),
        0..=0x1f => format!("\\^{}", (c + 64) as char),
        _ => {
            let low = c & 0x7f;
            match low {
                0x7f => "\\M-^?".to_string(),
                0..=0x1f => format!("\\M^{}", (low + 64) as char),
                b' ' => "\\240".to_string(),
                _ => format!("\\M-{}", low as char),
            }
        }
    }
}

/// `TunnelDevice any`.
pub const TUNID_ANY: i64 = 0x7fff_ffff;
const TUNID_MAX: i64 = TUNID_ANY - 2;

/// Parse a tunnel device ID: a number or `any`.
fn parse_tun_id(text: &str) -> Option<i64> {
    if text.eq_ignore_ascii_case("any") {
        return Some(TUNID_ANY);
    }
    parse_number(text).filter(|&n| (0..=TUNID_MAX).contains(&n))
}

/// Parse `local[:remote]` tunnel devices.
pub fn parse_tunnel_device(text: &str) -> Option<(i64, i64)> {
    match text.split_once(':') {
        None => Some((parse_tun_id(text)?, TUNID_ANY)),
        Some((local, remote)) => Some((parse_tun_id(local)?, parse_tun_id(remote)?)),
    }
}

/// Parse a decimal number like `strtonum` (no sign, no trailing junk).
pub fn parse_number(text: &str) -> Option<i64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Parse an integer option value like OpenSSH's `atoi_err`: 0 to
/// `i32::MAX`.
pub fn parse_int(text: &str) -> Result<i32, &'static str> {
    if text.is_empty() {
        return Err("missing");
    }
    let negative = text.starts_with('-');
    let digits = text.strip_prefix(['-', '+']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid");
    }
    if negative {
        return Err("too small");
    }
    digits
        .parse::<i64>()
        .ok()
        .and_then(|v| i32::try_from(v).ok())
        .ok_or("too large")
}

/// Parse a port number like OpenSSH's `a2port`: 0 to 65535, or a service
/// name.
pub fn parse_port(text: &str) -> Option<i32> {
    if let Some(n) = parse_number(text) {
        return (n <= 65535).then_some(n as i32);
    }
    service_port(text)
}

/// Look up a TCP service name, like `getservbyname(3)`.
fn service_port(name: &str) -> Option<i32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: getservbyname takes NUL-terminated strings and returns a
    // pointer to static storage (or NULL), which we read immediately.
    unsafe {
        let entry = libc::getservbyname(name.as_ptr(), c"tcp".as_ptr());
        if entry.is_null() {
            return None;
        }
        Some(i32::from(u16::from_be((*entry).s_port as u16)))
    }
}

/// Parse a number with an optional scale suffix (`K`, `M`, `G`, `T`,
/// `P`, `E`, in powers of 1024; a fractional part is allowed), like
/// OpenBSD's `scan_scaled`.
pub fn parse_scaled(text: &str) -> Option<i64> {
    let (number, scale) = match text.chars().last()? {
        c if c.is_ascii_digit() => (text, 1i64),
        c => {
            let power = "BKMGTPE".find(c.to_ascii_uppercase())?;
            (&text[..text.len() - 1], 1024i64.checked_pow(power as u32)?)
        }
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: i64 = whole.parse().ok()?;
    let mut value = whole.checked_mul(scale)?;
    if !fraction.is_empty() && scale > 1 {
        let digits = fraction.len().min(9) as u32;
        let fraction: i64 = fraction[..digits as usize].parse().ok()?;
        value = value.checked_add(fraction * scale / 10i64.pow(digits))?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multistates() {
        assert_eq!(
            parse_multistate(STRICT_HOSTKEY, "Accept-New"),
            Some(STRICT_HOSTKEY_NEW)
        );
        assert_eq!(
            format_multistate(STRICT_HOSTKEY, STRICT_HOSTKEY_YES),
            "true"
        );
        assert_eq!(format_multistate(PUBKEY_AUTH, PUBKEY_AUTH_ALL), "true");
        assert_eq!(format_multistate(LOG_LEVELS, 5), "DEBUG");
        assert_eq!(parse_multistate(FLAG, "maybe"), None);
    }

    #[test]
    fn ipqos() {
        assert_eq!(parse_ipqos("EF"), Some(0xb8));
        assert_eq!(parse_ipqos("12"), Some(12));
        assert_eq!(parse_ipqos("256"), None);
        assert_eq!(format_ipqos(0xb8), "ef");
        assert_eq!(format_ipqos(12), "0x0c");
        assert_eq!(format_ipqos(i32::MAX), "none");
    }

    #[test]
    fn escape_chars() {
        assert_eq!(parse_escape_char("~"), Some(126));
        assert_eq!(parse_escape_char("^A"), Some(1));
        assert_eq!(parse_escape_char("none"), Some(ESCAPE_NONE));
        assert_eq!(parse_escape_char("ab"), None);
        assert_eq!(format_escape_char(126), "~");
        assert_eq!(format_escape_char(1), "\\^A");
    }

    #[test]
    fn numbers() {
        assert_eq!(parse_int("12"), Ok(12));
        assert_eq!(parse_int("-1"), Err("too small"));
        assert_eq!(parse_int("x"), Err("invalid"));
        assert_eq!(parse_port("22"), Some(22));
        assert_eq!(parse_port("ssh"), Some(22));
        assert_eq!(parse_port("70000"), None);
        assert_eq!(parse_scaled("1G"), Some(1 << 30));
        assert_eq!(parse_scaled("1.5K"), Some(1536));
        assert_eq!(parse_scaled("100"), Some(100));
        assert_eq!(parse_scaled("x"), None);
        assert_eq!(parse_tunnel_device("any:3"), Some((TUNID_ANY, 3)));
        assert_eq!(parse_tunnel_device("1"), Some((1, TUNID_ANY)));
    }
}
