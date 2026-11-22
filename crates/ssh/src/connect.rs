//! Opening the TCP connection, like OpenSSH's `ssh_connect_direct`: every
//! address of the host in turn, `ConnectionAttempts` times, each within
//! `ConnectTimeout`, from `BindAddress` or `BindInterface` if set.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use sshutils_config::Options;
use sshutils_config::canonical::{Resolver, SystemResolver};
use sshutils_config::network::interface_addresses;
use sshutils_config::values::{AF_INET, AF_INET6, AF_UNSPEC};
use tokio::net::{TcpSocket, TcpStream};

use crate::io_message;
use crate::log;

/// The default SSH port.
pub const DEFAULT_PORT: u16 = 22;

/// `IPQoS none`.
const IPQOS_NONE: i32 = i32::MAX;

/// An open connection.
pub struct Connection {
    pub stream: TcpStream,
    /// The address connected to.
    pub peer: SocketAddr,
    /// What is left of `ConnectTimeout` for the banner exchange.
    pub deadline: Option<Instant>,
}

/// The port to connect to.
pub fn port(options: &Options) -> u16 {
    match options.port {
        Some(port) if port > 0 => port as u16,
        _ => DEFAULT_PORT,
    }
}

/// The address family to use (`AF_UNSPEC` for either).
fn family(options: &Options) -> i32 {
    options.address_family.unwrap_or(AF_UNSPEC)
}

/// Look the host up, like OpenSSH's `resolve_host`. On failure the error
/// has been logged.
pub fn resolve(host: &str, options: &Options) -> Result<Vec<SocketAddr>, ()> {
    log::debug2(&format!("resolving \"{host}\" port {}", port(options)));
    match SystemResolver.lookup(host, port(options), family(options), false) {
        Ok(lookup) => Ok(lookup.addresses),
        Err(error) => {
            log::error(&format!("ssh: Could not resolve hostname {host}: {error}"));
            Err(())
        }
    }
}

/// Connect to the first address that accepts. On failure the error has been
/// logged.
pub async fn connect(
    host: &str,
    addresses: &[SocketAddr],
    options: &Options,
) -> Result<Connection, ()> {
    let timeout = match options.connection_timeout {
        Some(seconds) if seconds > 0 => Some(Duration::from_secs(seconds as u64)),
        _ => None,
    };
    let attempts = options.connection_attempts.unwrap_or(1).max(1);
    // The error of the last address tried, and its port.
    let mut last_error: Option<io::Error> = None;
    let mut last_port = String::new();
    for attempt in 0..attempts {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            log::debug("Trying again...");
        }
        for &address in addresses {
            last_port = address.port().to_string();
            let wanted = family(options);
            let address_family = if address.is_ipv4() { AF_INET } else { AF_INET6 };
            if wanted != AF_UNSPEC && wanted != address_family {
                log::debug2(&format!(
                    "skipping address [{}]:{}: wrong address family",
                    address.ip(),
                    address.port()
                ));
                last_error = Some(io::Error::from_raw_os_error(libc::EAFNOSUPPORT));
                continue;
            }
            log::debug(&format!(
                "Connecting to {host} [{}] port {}.",
                address.ip(),
                address.port()
            ));
            let Some(socket) = create_socket(address, options) else {
                // The error has been logged.
                last_error = None;
                continue;
            };
            let started = Instant::now();
            let result = match timeout {
                Some(timeout) => tokio::time::timeout(timeout, socket.connect(address))
                    .await
                    .unwrap_or_else(|_| Err(io::Error::from_raw_os_error(libc::ETIMEDOUT))),
                None => socket.connect(address).await,
            };
            match result {
                Ok(stream) => {
                    log::debug("Connection established.");
                    if options.tcp_keep_alive != Some(0)
                        && let Err(err) = set_keepalive(&stream)
                    {
                        log::error(&format!("setsockopt SO_KEEPALIVE: {}", io_message(&err)));
                    }
                    return Ok(Connection {
                        stream,
                        peer: address,
                        deadline: timeout.map(|t| started + t),
                    });
                }
                Err(err) => {
                    log::debug(&format!(
                        "connect to address {} port {}: {}",
                        address.ip(),
                        address.port(),
                        io_message(&err)
                    ));
                    last_error = Some(err);
                }
            }
        }
    }
    let reason = match &last_error {
        Some(err) => io_message(err),
        None => "failure".to_string(),
    };
    log::error(&format!(
        "ssh: connect to host {host} port {last_port}: {reason}"
    ));
    Err(())
}

/// Create a socket for `address`, bound as configured. Errors are logged.
fn create_socket(address: SocketAddr, options: &Options) -> Option<TcpSocket> {
    let socket = match if address.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    } {
        Ok(socket) => socket,
        Err(err) => {
            log::error(&format!("socket: {}", io_message(&err)));
            return None;
        }
    };
    // Interactive quality of service until authentication completes.
    if let Some((interactive, _)) = options.ip_qos
        && interactive != IPQOS_NONE
    {
        set_tos(&socket, address, interactive);
    }

    let bind = if let Some(bind_address) = &options.bind_address {
        match bind_address_for(bind_address, address) {
            Ok(ip) => ip,
            Err(message) => {
                log::error(&message);
                return None;
            }
        }
    } else if let Some(interface) = &options.bind_interface {
        match interface_address(interface, address) {
            Some(ip) => ip,
            None => {
                log::info(&format!("getifaddrs: {interface}: no suitable addresses"));
                return None;
            }
        }
    } else {
        return Some(socket);
    };
    if let Err(err) = socket.bind(SocketAddr::new(bind, 0)) {
        log::error(&format!("bind {bind}: {}", io_message(&err)));
        return None;
    }
    log::debug(&format!("ssh_create_socket: bound to {bind}"));
    Some(socket)
}

/// Resolve `BindAddress` for the family of `peer`.
fn bind_address_for(bind_address: &str, peer: SocketAddr) -> Result<IpAddr, String> {
    let family = if peer.is_ipv4() { AF_INET } else { AF_INET6 };
    let lookup = SystemResolver
        .lookup(bind_address, 0, family, false)
        .map_err(|error| format!("getaddrinfo: {bind_address}: {error}"))?;
    lookup
        .addresses
        .first()
        .map(SocketAddr::ip)
        .ok_or_else(|| "getaddrinfo: no addrs".to_string())
}

/// An address of `interface` in the family of `peer`, preferring ones that
/// are neither loopback nor link-local (OpenSSH's `check_ifaddrs`).
fn interface_address(interface: &str, peer: SocketAddr) -> Option<IpAddr> {
    let addresses: Vec<IpAddr> = interface_addresses()
        .map_err(|err| log::error(&format!("getifaddrs: {interface}: {}", io_message(&err))))
        .ok()?
        .into_iter()
        .filter(|(name, address)| name == interface && address.ip.is_ipv4() == peer.is_ipv4())
        .map(|(_, address)| address.ip)
        .collect();
    let local = |ip: &IpAddr| match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unicast_link_local(),
    };
    addresses
        .iter()
        .find(|ip| !local(ip))
        .or_else(|| addresses.first())
        .copied()
}

/// Set the IP type of service (IPv4) or traffic class (IPv6).
fn set_tos(socket: &TcpSocket, peer: SocketAddr, tos: i32) {
    let (level, name, label) = if peer.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_TOS, "IP_TOS")
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS, "IPV6_TCLASS")
    };
    log::debug3(&format!(
        "set_sock_tos: set socket {} {label} 0x{tos:02x}",
        socket.as_raw_fd()
    ));
    // SAFETY: the descriptor is open, and the option takes an int.
    let status = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&raw const tos).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if status == -1 {
        let err = io::Error::last_os_error();
        log::debug(&format!(
            "set_sock_tos: setsockopt socket {} {label} {tos}: {}",
            socket.as_raw_fd(),
            io_message(&err)
        ));
    }
}

/// Turn on `SO_KEEPALIVE` (`TCPKeepAlive`).
fn set_keepalive(stream: &TcpStream) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: the descriptor is open, and the option takes an int.
    let status = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            (&raw const on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
