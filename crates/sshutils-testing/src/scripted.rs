//! A scripted SSH server built on russh, for what an unprivileged OpenSSH
//! `sshd` can't do in tests: accept `none`, send any list of methods, close
//! the connection mid-authentication. It records every authentication
//! request, so that tests can compare what each client sent. Once logged
//! in, every command succeeds without output.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::server::{self, Auth};
use russh::{MethodKind, MethodSet};
use tempfile::TempDir;

/// What the server does.
#[derive(Clone, Debug, Default)]
pub struct Behaviour {
    /// The methods it offers to continue with after a failure.
    pub methods: Vec<MethodKind>,
    /// Let `none` succeed.
    pub accept_none: bool,
    /// Close the connection when `none` is requested.
    pub close_on_none: bool,
    /// Sent before the first reply to an authentication request.
    pub banner: Option<String>,
    /// Public keys (`type base64`) it accepts; with `partial`, only after
    /// a partial success.
    pub keys: Vec<String>,
    /// Public keys that give a partial success, continuing with public
    /// keys.
    pub partial: Vec<String>,
    /// Certificate authorities (`type base64`) whose user certificates it
    /// accepts.
    pub authorities: Vec<String>,
}

/// A running [`Behaviour`], on a free port on 127.0.0.1, with an Ed25519
/// host key. It runs until the test process ends.
pub struct ScriptedServer {
    dir: TempDir,
    port: u16,
    log: Arc<Mutex<Vec<String>>>,
}

impl ScriptedServer {
    /// Start the server; `keygen` makes its host key.
    pub fn start(keygen: &Path, behaviour: Behaviour) -> ScriptedServer {
        let dir = tempfile::tempdir().expect("create server directory");
        let key_path = dir.path().join("host_key_ed25519");
        let status = Command::new(keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f"])
            .arg(&key_path)
            .status()
            .expect("run ssh-keygen");
        assert!(status.success(), "ssh-keygen failed");
        let key = russh::keys::load_secret_key(&key_path, None).expect("load host key");

        let mut config = server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            methods: MethodSet::from(&behaviour.methods[..]),
            ..Default::default()
        };
        config.keys.push(key);
        let config = Arc::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener
            .set_nonblocking(true)
            .expect("non-blocking listener");
        let port = listener.local_addr().expect("local address").port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let behaviour = Arc::new(behaviour);
        let shared_log = Arc::clone(&log);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        continue;
                    };
                    let handler = Connection {
                        behaviour: Arc::clone(&behaviour),
                        log: Arc::clone(&shared_log),
                        partial: false,
                    };
                    let config = Arc::clone(&config);
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, socket, handler).await {
                            let _ = session.await;
                        }
                    });
                }
            });
        });
        ScriptedServer { dir, port, log }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The host key's public half (`.pub` file).
    pub fn host_key_pub(&self) -> PathBuf {
        self.dir.path().join("host_key_ed25519.pub")
    }

    /// The requests recorded since the last call, one line each.
    pub fn take_log(&self) -> Vec<String> {
        std::mem::take(&mut self.log.lock().unwrap())
    }
}

struct Connection {
    behaviour: Arc<Behaviour>,
    log: Arc<Mutex<Vec<String>>>,
    /// A partial success happened.
    partial: bool,
}

impl Connection {
    fn record(&self, entry: String) {
        self.log.lock().unwrap().push(entry);
    }

    /// Whether `key` would be accepted (or give a partial success) now.
    fn acceptable(&self, key: &russh::keys::PublicKey) -> bool {
        let behaviour = &self.behaviour;
        (!self.partial && Connection::knows(&behaviour.partial, key))
            || ((self.partial || behaviour.partial.is_empty())
                && Connection::knows(&behaviour.keys, key))
    }

    fn knows(list: &[String], key: &russh::keys::PublicKey) -> bool {
        list.iter()
            .filter_map(|text| russh::keys::PublicKey::from_openssh(text).ok())
            .any(|known| known.key_data() == key.key_data())
    }
}

fn fingerprint(key: &russh::keys::PublicKey) -> String {
    key.fingerprint(Default::default()).to_string()
}

impl server::Handler for Connection {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.behaviour.banner.clone())
    }

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.record(format!("none {user}"));
        if self.behaviour.close_on_none {
            return Err(russh::Error::Disconnect);
        }
        Ok(if self.behaviour.accept_none {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        self.record(format!(
            "publickey {user} {} {} offered",
            offer.algorithm.as_str(),
            fingerprint(offer.public_key)
        ));
        // Only the key is known here, not whether it came in a
        // certificate: with authorities, the certificate is checked once
        // signed.
        Ok(
            if self.acceptable(offer.public_key) || !self.behaviour.authorities.is_empty() {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        self.record(format!(
            "publickey {user} {} {} signed",
            key.algorithm.as_str(),
            fingerprint(key.public_key)
        ));
        if !self.partial && Connection::knows(&self.behaviour.partial, key.public_key) {
            self.partial = true;
            return Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::PublicKey][..])),
                partial_success: true,
            });
        }
        Ok(if self.acceptable(key.public_key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &russh::keys::Certificate,
    ) -> Result<Auth, Self::Error> {
        let key = russh::keys::PublicKey::from(certificate.public_key().clone());
        let ca = russh::keys::PublicKey::from(certificate.signature_key().clone());
        self.record(format!(
            "certificate {user} {} {} signed by {}",
            certificate.algorithm().to_certificate_type(),
            fingerprint(&key),
            fingerprint(&ca)
        ));
        Ok(if Connection::knows(&self.behaviour.authorities, &ca) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    /// Every command succeeds at once, without output.
    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        _command: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}
