use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

use crate::Openssh;
use crate::process;

/// Host alias for the server in [`Sshd::client_config`].
pub const HOST_ALIAS: &str = "sshd-test";

/// How long to wait for sshd to start listening.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// A throwaway OpenSSH server, running as the current user on a free port on
/// 127.0.0.1. Killed when dropped.
///
/// It accepts public key logins with [`user_key`](Self::user_key) for the
/// current user only (an unprivileged sshd can't switch users). Password and
/// keyboard-interactive authentication are disabled.
///
/// [`client_config`](Self::client_config) is an `ssh_config` that logs in as
/// [`HOST_ALIAS`] without touching the user's own `~/.ssh`:
///
/// ```ignore
/// let sshd = Sshd::start(&openssh);
/// Command::new(ssh).arg("-F").arg(sshd.client_config()).arg(HOST_ALIAS).arg("true");
/// ```
pub struct Sshd {
    dir: TempDir,
    port: u16,
    child: Child,
    log: Arc<Mutex<String>>,
}

impl Sshd {
    /// Generate keys and configuration and start the server with an
    /// Ed25519 host key. Panics if it doesn't come up.
    pub fn start(openssh: &Openssh) -> Sshd {
        Sshd::start_with_host_keys(openssh, &["ed25519"])
    }

    /// Like [`start`](Self::start), with a host key of each of these types
    /// (`ssh-keygen -t` names), offered in this order. The first is
    /// [`host_key_pub`](Self::host_key_pub); all are in
    /// [`host_key_pub_of`](Self::host_key_pub_of).
    pub fn start_with_host_keys(openssh: &Openssh, types: &[&str]) -> Sshd {
        let dir = tempfile::tempdir().expect("create sshd directory");
        let keygen = openssh.require_tool("ssh-keygen");
        let generate = |key: &str, key_type: &str| {
            let out = process::run(
                process::command(&keygen, dir.path())
                    .args(["-q", "-t", key_type, "-N", "", "-C"])
                    .arg(key)
                    .arg("-f")
                    .arg(key),
                b"",
            );
            assert_eq!(out.status, Some(0), "ssh-keygen failed: {}", out.stderr);
        };
        generate("user_key", "ed25519");
        let first = types.first().expect("at least one host key type");
        for key_type in types {
            generate(&format!("host_key_{key_type}"), key_type);
        }
        for suffix in ["", ".pub"] {
            std::fs::copy(
                dir.path().join(format!("host_key_{first}{suffix}")),
                dir.path().join(format!("host_key{suffix}")),
            )
            .expect("copy the first host key");
        }
        std::fs::copy(
            dir.path().join("user_key.pub"),
            dir.path().join("authorized_keys"),
        )
        .expect("write authorized_keys");

        // Binding to port 0 and releasing it races with other processes, so
        // retry a few times if the port gets taken in between.
        let mut last_log = String::new();
        for _ in 0..5 {
            let port = free_port();
            write_configs(openssh, dir.path(), port, types);
            match spawn(openssh, dir.path()) {
                Ok((child, log)) => {
                    return Sshd {
                        dir,
                        port,
                        child,
                        log,
                    };
                }
                Err(log) => last_log = log,
            }
        }
        panic!("sshd failed to start:\n{last_log}");
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Directory holding the server's and client's keys and configs.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Private key accepted by the server (unencrypted ed25519).
    pub fn user_key(&self) -> PathBuf {
        self.dir.path().join("user_key")
    }

    /// The server's (first) public host key.
    pub fn host_key_pub(&self) -> PathBuf {
        self.dir.path().join("host_key.pub")
    }

    /// The server's public host key of this type.
    pub fn host_key_pub_of(&self, key_type: &str) -> PathBuf {
        self.dir.path().join(format!("host_key_{key_type}.pub"))
    }

    /// `known_hosts` file containing the server's host key.
    pub fn known_hosts(&self) -> PathBuf {
        self.dir.path().join("known_hosts")
    }

    /// `ssh_config` with a `Host sshd-test` entry for this server.
    pub fn client_config(&self) -> PathBuf {
        self.dir.path().join("ssh_config")
    }

    /// The server's log so far (useful in assertion messages).
    pub fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("bind an ephemeral port")
        .port()
}

fn write_configs(openssh: &Openssh, dir: &Path, port: u16, types: &[&str]) {
    let d = dir.display();
    let host_keys: String = types
        .iter()
        .map(|t| format!("HostKey {d}/host_key_{t}\n"))
        .collect();
    let mut sshd_config = format!(
        "ListenAddress 127.0.0.1:{port}\n\
         {host_keys}\
         PidFile none\n\
         AuthorizedKeysFile {d}/authorized_keys\n\
         StrictModes no\n\
         PubkeyAuthentication yes\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n"
    );
    // Since 9.8, sshd blocks addresses that fail authentication repeatedly.
    // Tests deliberately fail logins from 127.0.0.1, so turn that off.
    if openssh.at_least(9, 8) {
        sshd_config.push_str("PerSourcePenalties no\n");
    }
    if let Some(sftp_server) = openssh.tool("sftp-server") {
        writeln!(sshd_config, "Subsystem sftp {}", sftp_server.display()).unwrap();
    }
    std::fs::write(dir.join("sshd_config"), sshd_config).expect("write sshd_config");

    let host_key = std::fs::read_to_string(dir.join("host_key.pub")).expect("read host key");
    std::fs::write(
        dir.join("known_hosts"),
        format!("[127.0.0.1]:{port} {host_key}"),
    )
    .expect("write known_hosts");

    let client_config = format!(
        "Host {HOST_ALIAS}\n\
         \tHostName 127.0.0.1\n\
         \tPort {port}\n\
         \tIdentityFile {d}/user_key\n\
         \tIdentitiesOnly yes\n\
         \tIdentityAgent none\n\
         \tUserKnownHostsFile {d}/known_hosts\n\
         \tGlobalKnownHostsFile /dev/null\n\
         \tStrictHostKeyChecking yes\n\
         \tUpdateHostKeys no\n\
         \tBatchMode yes\n\
         \tControlMaster no\n\
         \tControlPath none\n"
    );
    std::fs::write(dir.join("ssh_config"), client_config).expect("write ssh_config");
}

/// Start sshd and wait until it listens. On failure, returns its log.
fn spawn(openssh: &Openssh, dir: &Path) -> Result<(Child, Arc<Mutex<String>>), String> {
    // sshd re-executes itself, so it must be started by absolute path.
    let sshd = openssh.require_tool("sshd");
    let mut cmd: Command = process::command(&sshd, dir);
    cmd.arg("-D") // don't daemonize
        .arg("-e") // log to stderr
        .arg("-f")
        .arg(dir.join("sshd_config"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to start sshd: {e}"))?;

    let log = Arc::new(Mutex::new(String::new()));
    let (ready_tx, ready_rx) = mpsc::channel();
    let stderr = child.stderr.take().expect("stderr is piped");
    let log_writer = Arc::clone(&log);
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if line.contains("Server listening on") {
                let _ = ready_tx.send(());
            }
            let mut log = log_writer.lock().unwrap();
            log.push_str(&line);
            log.push('\n');
        }
    });

    match ready_rx.recv_timeout(STARTUP_TIMEOUT) {
        Ok(()) => Ok((child, log)),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            let log = log.lock().unwrap().clone();
            Err(log)
        }
    }
}
