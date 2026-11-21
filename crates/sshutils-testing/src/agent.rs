use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::Openssh;
use crate::process::{self, Outcome};

/// File name of the agent socket inside a scratch directory, for runs of a
/// [`Case`](crate::Case) with an agent.
pub const AGENT_SOCKET: &str = "agent.sock";

/// How long to wait for ssh-agent to create its socket.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// A throwaway OpenSSH `ssh-agent`, listening on a socket of our choosing.
/// Killed when dropped.
#[derive(Debug)]
pub struct Agent {
    socket: PathBuf,
    child: Child,
}

impl Agent {
    /// Start `ssh-agent -D -a <socket>` and wait for the socket to appear.
    pub fn start(openssh: &Openssh, socket: &Path) -> Agent {
        let dir = socket.parent().unwrap_or(Path::new("."));
        let child = process::command(openssh.require_tool("ssh-agent"), dir)
            .arg("-D")
            .arg("-a")
            .arg(socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start ssh-agent");
        let mut agent = Agent {
            socket: socket.to_path_buf(),
            child,
        };
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        while !agent.socket.exists() {
            if Instant::now() >= deadline || matches!(agent.child.try_wait(), Ok(Some(_))) {
                panic!("ssh-agent did not create {}", agent.socket.display());
            }
            thread::sleep(Duration::from_millis(10));
        }
        agent
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Run OpenSSH's `ssh-add` against this agent, in `dir`.
    pub fn ssh_add<I, S>(&self, openssh: &Openssh, dir: &Path, args: I) -> Outcome
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        process::run(
            process::command(openssh.require_tool("ssh-add"), dir)
                .env("SSH_AUTH_SOCK", &self.socket)
                .args(args),
            b"",
        )
    }

    /// The agent's identities as `ssh-add -L` prints them (empty if none),
    /// for comparing the state of two agents.
    pub fn identities(&self, openssh: &Openssh) -> String {
        let dir = self.socket.parent().unwrap_or(Path::new("."));
        let out = self.ssh_add(openssh, dir, ["-L"]);
        match out.status {
            Some(0) => out.stdout,
            _ => String::new(),
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
