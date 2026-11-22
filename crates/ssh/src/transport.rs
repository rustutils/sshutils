//! The SSH transport: version exchange and key exchange through russh, with
//! the algorithms, rekeying and keepalive settings from the configuration,
//! and OpenSSH's messages when it fails.

use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use russh::client::{self, Handle};
use russh::keys::Algorithm;
use russh::{AlgorithmKind, HostKeyAlgorithm, Preferred, SshId};
use sshutils_config::Options;
use sshutils_config::algorithms::{self, ALL_KEY, DEFAULT_KEY};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Sleep;

use crate::connect::Connection;
use crate::hostkeys::{self, HostKeys};
use crate::log;

/// Environment variable replacing the software version we announce
/// (`SSH-2.0-<version>`).
pub const VERSION_VARIABLE: &str = "SSHUTILS_CLIENT_VERSION";

/// How the transport failed. Messages have been logged unless noted.
#[derive(Debug)]
pub enum Failure {
    /// The host key was not accepted; OpenSSH then exits with "Host key
    /// verification failed.".
    HostKey,
    /// Anything else, already logged.
    Logged,
}

/// Our identification string: `SSH-2.0-sshutils_<version>`, or the
/// version from [`VERSION_VARIABLE`], then the `VersionAddendum`.
fn client_id(options: &Options) -> String {
    let version = std::env::var(VERSION_VARIABLE)
        .ok()
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_graphic()))
        .unwrap_or_else(|| format!("sshutils_{}", env!("CARGO_PKG_VERSION")));
    let mut id = format!("SSH-2.0-{version}");
    if let Some(addendum) = options
        .version_addendum
        .as_deref()
        .filter(|a| !a.is_empty())
    {
        id.push(' ');
        id.push_str(addendum);
    }
    id
}

/// The names of `list` that russh implements, converted by `parse`.
fn supported<N>(list: &str, parse: impl Fn(&str) -> Option<N>) -> Vec<N> {
    list.split(',').filter_map(parse).collect()
}

/// The host key algorithms to offer: `HostKeyAlgorithms` (or the
/// default), ordered by what `known_hosts` has for the host unless the
/// list was given explicitly.
fn host_key_algorithms(options: &Options, known: &HostKeys) -> String {
    let configured = options.hostkey_algorithms.as_deref();
    let follow_known_hosts = configured.is_none_or(|l| l.starts_with(['+', '-']));
    let list = algorithms::assemble(configured, DEFAULT_KEY, ALL_KEY).unwrap_or_default();
    if follow_known_hosts {
        hostkeys::order_algorithms(&list, known)
    } else {
        list
    }
}

/// russh's configuration for this connection.
fn config(options: &Options, host_key_algorithms: &str) -> client::Config {
    let kex = supported(options.kex_algorithms.as_deref().unwrap_or(""), |n| {
        russh::kex::Name::try_from(n).ok()
    });
    let cipher = supported(options.ciphers.as_deref().unwrap_or(""), |n| {
        russh::cipher::Name::try_from(n).ok()
    });
    let mac = supported(options.macs.as_deref().unwrap_or(""), |n| {
        russh::mac::Name::try_from(n).ok()
    });
    let compression_list = if options.compression.unwrap_or(0) != 0 {
        "zlib@openssh.com,none"
    } else {
        "none,zlib@openssh.com"
    };
    let compression = supported(compression_list, |n| {
        russh::compression::Name::try_from(n).ok()
    });
    // Plain keys and certificates, interleaved in the configured order.
    let mut host_key_order: Vec<HostKeyAlgorithm> = Vec::new();
    for name in host_key_algorithms.split(',') {
        let Some(algorithm) = hostkeys::key_algorithm(name) else {
            continue;
        };
        let entry = HostKeyAlgorithm {
            algorithm,
            certificate: name.ends_with("-cert-v01@openssh.com"),
        };
        if !host_key_order.contains(&entry) {
            host_key_order.push(entry);
        }
    }
    let key: Vec<Algorithm> = host_key_order
        .iter()
        .filter(|a| !a.certificate)
        .map(|a| a.algorithm.clone())
        .collect();

    let mut limits = russh::Limits::default();
    // OpenSSH rekeys by data volume depending on the cipher unless
    // `RekeyLimit` says otherwise; russh caps it at 1 GiB.
    if let Some(bytes) = options.rekey_limit.filter(|&b| b > 0) {
        let bytes = usize::try_from(bytes).unwrap_or(usize::MAX).min(1 << 30);
        limits.rekey_write_limit = bytes;
        limits.rekey_read_limit = bytes;
    }
    limits.rekey_time_limit = match options.rekey_interval {
        Some(seconds) if seconds > 0 => Duration::from_secs(seconds as u64),
        _ => Duration::MAX,
    };

    let keepalive_interval = match options.server_alive_interval {
        Some(seconds) if seconds > 0 => Some(Duration::from_secs(seconds as u64)),
        _ => None,
    };
    client::Config {
        client_id: SshId::Standard(Cow::Owned(client_id(options))),
        limits,
        preferred: Preferred {
            kex: Cow::Owned(kex),
            key: Cow::Owned(key),
            host_key_certificates: Cow::Borrowed(&[]),
            host_key_order: Cow::Owned(host_key_order),
            cipher: Cow::Owned(cipher),
            mac: Cow::Owned(mac),
            compression: Cow::Owned(compression),
        },
        keepalive_interval,
        keepalive_max: options.server_alive_count_max.unwrap_or(3).max(0) as usize,
        inactivity_timeout: None,
        nodelay: true,
        ..Default::default()
    }
}

/// What the handler found out during key exchange.
#[derive(Default)]
struct Outcome {
    host_key_rejected: bool,
    kex: Option<String>,
    /// The options after the host key check, which may have restricted them.
    options: Option<Options>,
}

/// Checks the server's host key for russh.
pub struct Client {
    host: String,
    peer: SocketAddr,
    port: u16,
    options: Options,
    outcome: Arc<Mutex<Outcome>>,
}

/// Ask a yes/no question like OpenSSH's `confirm()`: never in batch mode;
/// otherwise until the answer is yes, no (or empty), or the fingerprint.
fn confirm(options: &Options, prompt: &str, fingerprint: Option<&str>) -> bool {
    if options.batch_mode == Some(1) {
        return false;
    }
    let mut message = prompt.to_string();
    loop {
        let answer = sshutils_core::tty::ask_terminal(&message);
        let answer = answer.trim_start_matches([' ', '\t']);
        let answer = answer.split([' ', '\t', '\n']).next().unwrap_or_default();
        if answer.is_empty() || answer.eq_ignore_ascii_case("no") {
            return false;
        }
        if answer.eq_ignore_ascii_case("yes") || fingerprint == Some(answer) {
            return true;
        }
        message = match fingerprint {
            Some(_) => "Please type 'yes', 'no' or the fingerprint: ".to_string(),
            None => "Please type 'yes' or 'no': ".to_string(),
        };
    }
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match server_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => {
                hostkeys::HostKey::Plain(key.clone())
            }
            russh::keys::PublicKeyOrCertificate::Certificate(certificate) => {
                hostkeys::HostKey::Certificate(Box::new(certificate.clone()))
            }
        };
        let mut options = self.options.clone();
        let batch = self.options.clone();
        let mut ask =
            |prompt: &str, fingerprint: Option<&str>| confirm(&batch, prompt, fingerprint);
        let accepted = hostkeys::Verifier {
            options: &mut options,
            peer: self.peer,
            confirm: &mut ask,
        }
        .verify(&self.host, self.port, &key);
        let mut outcome = self.outcome.lock().unwrap();
        outcome.host_key_rejected = !accepted;
        outcome.options = Some(options);
        Ok(accepted)
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.outcome.lock().unwrap().kex = Some(names.kex.as_ref().to_string());
        Ok(())
    }
}

/// An established, not yet authenticated connection.
#[allow(dead_code)] // Authentication comes next.
pub struct Transport {
    pub handle: Handle<Client>,
    /// The options, as the host key check left them.
    pub options: Options,
}

/// `<address> port <port>`, as OpenSSH names the peer in messages.
fn remote_id(peer: SocketAddr) -> String {
    format!("{} port {}", peer.ip(), peer.port())
}

/// Run the version and key exchange on `connection`.
pub async fn establish(
    connection: Connection,
    host: &str,
    options: Arc<Options>,
) -> Result<Transport, Failure> {
    let peer = connection.peer;
    let port = crate::connect::port(&options);
    let (user_files, system_files) = hostkeys::files(&options);
    let all_files: Vec<String> = user_files.into_iter().chain(system_files).collect();
    let known = HostKeys::load(&hostkeys::lookup_name(host, port, &options), &all_files);
    let config = config(&options, &host_key_algorithms(&options, &known));
    log::debug(&format!("Local version string {}", client_id(&options)));

    let outcome = Arc::new(Mutex::new(Outcome::default()));
    let handler = Client {
        host: host.to_string(),
        peer,
        port,
        options: (*options).clone(),
        outcome: Arc::clone(&outcome),
    };
    let identification = Arc::new(Mutex::new(None));
    let stream = BannerDeadline::new(
        connection.stream,
        connection.deadline,
        Arc::clone(&identification),
    );
    let result = client::connect_stream(Arc::new(config), stream, handler).await;
    let handle = match result {
        Ok(handle) => handle,
        Err(err) => {
            if outcome.lock().unwrap().host_key_rejected {
                return Err(Failure::HostKey);
            }
            let identification = identification.lock().unwrap().clone();
            report(&err, peer, identification.as_deref());
            return Err(Failure::Logged);
        }
    };
    let kex = outcome.lock().unwrap().kex.clone();
    if let Some(kex) = kex
        && !options.kex_algorithms_set
        && options.warn_weak_crypto != Some(0)
        && !is_post_quantum(&kex)
    {
        log::info("** WARNING: connection is not using a post-quantum key exchange algorithm.");
        log::info("** This session may be vulnerable to \"store now, decrypt later\" attacks.");
        log::info("** The server may need to be upgraded. See https://openssh.com/pq.html");
    }
    let options = outcome
        .lock()
        .unwrap()
        .options
        .take()
        .unwrap_or_else(|| (*options).clone());
    Ok(Transport { handle, options })
}

/// Key exchange methods that resist quantum computers.
fn is_post_quantum(kex: &str) -> bool {
    kex.starts_with("mlkem") || kex.starts_with("sntrup761")
}

/// Log a transport failure like OpenSSH's `sshpkt_fatal`.
/// `identification` is the server's identification line, if it was read.
fn report(err: &russh::Error, peer: SocketAddr, identification: Option<&str>) {
    let remote = remote_id(peer);
    if let Some(line) = identification
        && let Some(message) = version_mismatch(line)
    {
        log::error(&message.0);
        log::fatal(&format!(
            "banner exchange: Connection to {remote}: {}",
            message.1
        ));
        return;
    }
    let in_banner = identification.is_none();
    let io_error = match err {
        russh::Error::IO(io) => Some(io),
        _ => None,
    };
    if let Some(io) = io_error
        && io.kind() == io::ErrorKind::TimedOut
        && in_banner
    {
        log::error("Connection timed out during banner exchange");
        log::fatal(&format!("Connection to {remote} timed out"));
        return;
    }
    let closed = matches!(err, russh::Error::Disconnect | russh::Error::HUP)
        || io_error.is_some_and(|io| io.kind() == io::ErrorKind::UnexpectedEof);
    let reset = io_error.is_some_and(|io| io.kind() == io::ErrorKind::ConnectionReset);
    if closed || reset {
        if in_banner && reset {
            log::error("kex_exchange_identification: read: Connection reset by peer");
        } else if in_banner {
            log::log(
                log::VERBOSE,
                "kex_exchange_identification: Connection closed by remote host",
            );
        }
        let how = if reset { "reset" } else { "closed" };
        log::fatal(&format!("Connection {how} by {remote}"));
        return;
    }
    if let russh::Error::NoCommonAlgo { kind, theirs, .. } = err {
        let what = match kind {
            AlgorithmKind::Kex => "key exchange method",
            AlgorithmKind::Key => "host key type",
            AlgorithmKind::Cipher => "cipher",
            AlgorithmKind::Mac => "MAC",
            AlgorithmKind::Compression => "compression method",
        };
        log::fatal(&format!(
            "Unable to negotiate with {remote}: no matching {what} found. Their offer: {}",
            theirs.join(",")
        ));
        return;
    }
    log::fatal(&format!("Connection to {remote}: {err}"));
}

/// Why OpenSSH would refuse the server's identification line, if it would:
/// the error it logs and the reason it exits with.
fn version_mismatch(line: &str) -> Option<(String, &'static str)> {
    let parsed = line.strip_prefix("SSH-").and_then(|rest| {
        let (version, software) = rest.split_once('-')?;
        let (major, minor) = version.split_once('.')?;
        let number = |s: &str| {
            (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse::<u32>().ok())
                .flatten()
        };
        Some((number(major)?, number(minor)?, software))
    });
    match parsed {
        None => Some((
            format!(
                "Bad remote protocol version identification: '{}'",
                line.chars().take(100).collect::<String>()
            ),
            "invalid format",
        )),
        Some((2, _, _)) | Some((1, 99, _)) => None,
        Some((major, _, _)) => Some((
            format!("Protocol major versions differ: 2 vs. {major}"),
            "could not read protocol version",
        )),
    }
}

/// Longest identification line kept (OpenSSH allows 255 bytes).
const MAX_IDENTIFICATION: usize = 255;

/// The stream, with `ConnectTimeout`'s remainder applied to reading the
/// server's identification line, as OpenSSH does. The line itself is
/// recorded for error messages.
struct BannerDeadline {
    inner: TcpStream,
    sleep: Option<Pin<Box<Sleep>>>,
    identification: Arc<Mutex<Option<String>>>,
    /// The current line, until the identification line was seen.
    line: Option<Vec<u8>>,
}

impl BannerDeadline {
    fn new(
        inner: TcpStream,
        deadline: Option<Instant>,
        identification: Arc<Mutex<Option<String>>>,
    ) -> Self {
        BannerDeadline {
            inner,
            sleep: deadline.map(|d| Box::pin(tokio::time::sleep_until(d.into()))),
            identification,
            line: Some(Vec::new()),
        }
    }

    /// Watch the data read for the end of the identification line.
    fn scan(&mut self, data: &[u8]) {
        let Some(line) = &mut self.line else {
            return;
        };
        for &byte in data {
            if byte == b'\n' {
                if line.starts_with(b"SSH-") {
                    let text = String::from_utf8_lossy(line);
                    let text = text.strip_suffix('\r').unwrap_or(&text).to_string();
                    *self.identification.lock().unwrap() = Some(text);
                    self.line = None;
                    self.sleep = None;
                    return;
                }
                line.clear();
            } else if line.len() < MAX_IDENTIFICATION {
                line.push(byte);
            }
        }
    }
}

impl AsyncRead for BannerDeadline {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(sleep) = &mut this.sleep
            && sleep.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        if this.line.is_some() {
            let data = buf.filled()[before..].to_vec();
            this.scan(&data);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for BannerDeadline {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identification() {
        let mut options = Options::default();
        assert!(client_id(&options).starts_with("SSH-2.0-sshutils_"));
        options.version_addendum = Some("extra words".into());
        assert!(client_id(&options).ends_with(" extra words"));
    }

    #[test]
    fn algorithm_lists() {
        let mut options = Options::default();
        options.fill_defaults().unwrap();
        let config = config(
            &options,
            "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,bogus",
        );
        assert_eq!(
            config.preferred.key.as_ref(),
            [
                Algorithm::Ed25519,
                Algorithm::Rsa {
                    hash: Some(russh::keys::HashAlg::Sha512)
                }
            ]
        );
        // OpenSSH's default ciphers, all of which russh implements.
        let ciphers: Vec<&str> = config.preferred.cipher.iter().map(|c| c.as_ref()).collect();
        assert_eq!(
            ciphers.join(","),
            sshutils_config::algorithms::DEFAULT_CIPHERS
        );
        // The umac MACs are dropped.
        assert!(
            config
                .preferred
                .mac
                .iter()
                .all(|m| !m.as_ref().starts_with("umac"))
        );
        assert!(!config.preferred.mac.is_empty());
        // Certificates are offered in their place in the list.
        let config2 = super::config(
            &options,
            "ssh-ed25519,ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,umac",
        );
        let names: Vec<String> = config2
            .preferred
            .host_key_order
            .iter()
            .map(HostKeyAlgorithm::name)
            .collect();
        assert_eq!(
            names,
            [
                "ssh-ed25519",
                "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                "rsa-sha2-512-cert-v01@openssh.com"
            ]
        );
        assert_eq!(config.preferred.compression[0].as_ref(), "none");
        options.compression = Some(sshutils_config::values::COMPRESSION_DELAYED);
        let config = super::config(&options, "ssh-ed25519");
        assert_eq!(config.preferred.compression[0].as_ref(), "zlib@openssh.com");
    }

    #[test]
    fn identification_lines() {
        assert_eq!(version_mismatch("SSH-2.0-OpenSSH_10.5"), None);
        assert_eq!(version_mismatch("SSH-1.99-old"), None);
        assert_eq!(
            version_mismatch("SSH-1.5-old").unwrap().1,
            "could not read protocol version"
        );
        assert_eq!(version_mismatch("SSH-2.0").unwrap().1, "invalid format");
        assert_eq!(version_mismatch("SSH-x.0-a").unwrap().1, "invalid format");
    }

    #[test]
    fn post_quantum() {
        assert!(is_post_quantum("mlkem768x25519-sha256"));
        assert!(is_post_quantum("sntrup761x25519-sha512"));
        assert!(!is_post_quantum("curve25519-sha256"));
    }
}
