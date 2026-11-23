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
}

impl Connection {
    fn record(&self, entry: String) {
        self.log.lock().unwrap().push(entry);
    }
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
