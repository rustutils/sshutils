//! Address lists in CIDR notation (`Match localnetwork`), and the local
//! interface addresses they are matched against.
//!
//! Addresses are parsed by the system's `getaddrinfo` in numeric mode, like
//! OpenSSH does, so the C library's shorthand forms (`127.1`) are accepted
//! as well.

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An address with its IPv6 scope (zone) ID, 0 for none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    pub ip: IpAddr,
    pub scope: u32,
}

/// One entry of an address list: a network address and its mask length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    pub address: Address,
    pub mask: u32,
}

impl Network {
    /// Does `address` lie in this network? Addresses of different families
    /// never match, and neither do different IPv6 scopes.
    pub fn contains(&self, address: &Address) -> bool {
        if address.scope != self.address.scope {
            return false;
        }
        match (address.ip, self.address.ip) {
            (IpAddr::V4(a), IpAddr::V4(n)) => {
                let mask = u32::MAX.checked_shl(32 - self.mask).unwrap_or(0);
                u32::from(a) & mask == u32::from(n)
            }
            (IpAddr::V6(a), IpAddr::V6(n)) => {
                let mask = u128::MAX.checked_shl(128 - self.mask).unwrap_or(0);
                u128::from(a) & mask == u128::from(n)
            }
            _ => false,
        }
    }
}

/// Longest list entry accepted: an IPv6 address (`INET6_ADDRSTRLEN`, 46)
/// plus a mask.
const MAX_ENTRY: usize = 46 + 3;

/// Parse a comma-separated list of `address[/mask]` entries, like OpenSSH's
/// `addr_match_cidr_list`. Without a mask an entry is a single address.
/// Host bits set beyond the mask are an error.
pub fn parse_network_list(list: &str) -> Result<Vec<Network>, String> {
    let mut networks = Vec::new();
    for entry in list.split(',') {
        if entry.is_empty() {
            return Err(format!("empty entry in list \"{list}\""));
        }
        if entry.len() > MAX_ENTRY {
            return Err(format!("list entry \"{entry}\" too long"));
        }
        if !entry
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
        {
            return Err(format!(
                "list entry \"{entry}\" contains invalid characters"
            ));
        }
        let invalid = || format!("Invalid network entry \"{entry}\"");
        let (address, mask) = match entry.split_once('/') {
            None => (entry, None),
            Some((address, mask)) => {
                // strtonum: decimal digits within the range of an int.
                let mask = (!mask.is_empty() && mask.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| mask.parse::<i32>().ok())
                    .flatten()
                    .ok_or_else(invalid)?;
                (address, Some(mask as u32))
            }
        };
        let address = parse_numeric(address).ok_or_else(invalid)?;
        let bits = match address.ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let mask = mask.unwrap_or(bits);
        let inconsistent = || format!("Inconsistent mask length for network \"{entry}\"");
        if mask > bits {
            return Err(inconsistent());
        }
        let network = Network { address, mask };
        // The address must be the network itself: no host bits set.
        let host_bits = match address.ip {
            IpAddr::V4(ip) => u128::from(u32::from(ip) & u32::MAX.checked_shr(mask).unwrap_or(0)),
            IpAddr::V6(ip) => u128::from(ip) & u128::MAX.checked_shr(mask).unwrap_or(0),
        };
        if host_bits != 0 {
            return Err(inconsistent());
        }
        networks.push(network);
    }
    Ok(networks)
}

/// Parse a numeric address with `getaddrinfo(AI_NUMERICHOST)`.
pub fn parse_numeric(text: &str) -> Option<Address> {
    let name = CString::new(text).ok()?;
    // SAFETY: an all-zero addrinfo is a valid "no hints" value; the
    // result list is only read while it is alive and then freed.
    unsafe {
        let mut hints: libc::addrinfo = std::mem::zeroed();
        hints.ai_flags = libc::AI_NUMERICHOST;
        let mut result: *mut libc::addrinfo = std::ptr::null_mut();
        if libc::getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut result) != 0
            || result.is_null()
        {
            return None;
        }
        let address = sockaddr_address((*result).ai_addr);
        libc::freeaddrinfo(result);
        address
    }
}

/// Convert an IPv4 or IPv6 socket address.
///
/// # Safety
///
/// `sa` must be null or point to a socket address of the size its family
/// implies.
unsafe fn sockaddr_address(sa: *const libc::sockaddr) -> Option<Address> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the size matches the family.
    unsafe {
        match i32::from((*sa).sa_family) {
            libc::AF_INET => {
                let sin = &*(sa as *const libc::sockaddr_in);
                Some(Address {
                    ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))),
                    scope: 0,
                })
            }
            libc::AF_INET6 => {
                let sin6 = &*(sa as *const libc::sockaddr_in6);
                Some(Address {
                    ip: IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)),
                    scope: sin6.sin6_scope_id,
                })
            }
            _ => None,
        }
    }
}

/// The IPv4 and IPv6 addresses of the interfaces that are up.
pub fn local_addresses() -> std::io::Result<Vec<Address>> {
    let mut addresses = Vec::new();
    // SAFETY: getifaddrs allocates a list that is only read while alive and
    // then freed; each ifa_addr matches its family's size.
    unsafe {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut list) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut entry = list;
        while !entry.is_null() {
            let ifa = &*entry;
            entry = ifa.ifa_next;
            if ifa.ifa_name.is_null() || ifa.ifa_flags & (libc::IFF_UP as u32) == 0 {
                continue;
            }
            if let Some(address) = sockaddr_address(ifa.ifa_addr) {
                addresses.push(address);
            }
        }
        libc::freeifaddrs(list);
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> Address {
        parse_numeric(text).unwrap()
    }

    fn matches(list: &str, text: &str) -> bool {
        let address = address(text);
        parse_network_list(list)
            .unwrap()
            .iter()
            .any(|n| n.contains(&address))
    }

    #[test]
    fn parsing() {
        assert!(parse_network_list("10.0.0.0/8,192.168.1.1,::1,fe80::/10").is_ok());
        // The C library's shorthand forms.
        assert_eq!(address("127.1").ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(parse_network_list("127.1/32").is_ok());
        for bad in [
            "",
            "10.0.0.0/8,",
            "host",
            "10.0.0.0/",
            "10.0.0.0/x",
            "10.0.0.0/8/8",
            "10.0.0.0/33",
            "::/129",
            "10.0.0.1/8",
            "10.0.0.0/+8",
            "10.0.0.0/99999999999",
            "1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:0:1:2:3:4:5:6:7/128",
        ] {
            assert!(parse_network_list(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn matching() {
        assert!(matches("10.0.0.0/8", "10.1.2.3"));
        assert!(!matches("10.0.0.0/8", "11.0.0.1"));
        assert!(matches("192.168.0.0/16,10.0.0.0/8", "10.0.0.1"));
        assert!(matches("0.0.0.0/0", "1.2.3.4"));
        assert!(matches("1.2.3.4", "1.2.3.4"));
        assert!(!matches("1.2.3.4", "1.2.3.5"));
        assert!(matches("::/0", "::1"));
        assert!(matches("2001:db8::/32", "2001:db8::1"));
        assert!(!matches("0.0.0.0/0", "::1"));
        assert!(!matches("::/0", "127.0.0.1"));
    }

    #[test]
    fn local_interfaces_include_loopback() {
        let addresses = local_addresses().unwrap();
        assert!(
            addresses
                .iter()
                .any(|a| a.ip == IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }
}
