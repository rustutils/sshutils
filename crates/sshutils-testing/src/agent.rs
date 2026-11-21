use std::ffi::OsStr;
use std::fs::File;
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
    /// Start OpenSSH's `ssh-agent -D -a <socket>` and wait for the socket to
    /// appear.
    pub fn start(openssh: &Openssh, socket: &Path) -> Agent {
        Self::start_program(&openssh.require_tool("ssh-agent"), &[], socket)
    }

    /// Start `<program> <args> -D -a <socket>` (any agent that accepts
    /// OpenSSH's options) in the socket's directory and wait for the socket
    /// to appear. Its stdout and stderr go to `<socket>.stdout` and
    /// `<socket>.stderr`.
    pub fn start_program(program: &Path, args: &[&str], socket: &Path) -> Agent {
        let dir = socket.parent().unwrap_or(Path::new("."));
        let output = |suffix: &str| {
            let mut name = socket.as_os_str().to_owned();
            name.push(suffix);
            Stdio::from(File::create(PathBuf::from(name)).expect("create agent output file"))
        };
        let child = process::command(program, dir)
            .args(args)
            .arg("-D")
            .arg("-a")
            .arg(socket)
            .stdin(Stdio::null())
            .stdout(output(".stdout"))
            .stderr(output(".stderr"))
            .spawn()
            .unwrap_or_else(|e| panic!("start {}: {e}", program.display()));
        let mut agent = Agent {
            socket: socket.to_path_buf(),
            child,
        };
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        while !agent.socket.exists() {
            if Instant::now() >= deadline || matches!(agent.child.try_wait(), Ok(Some(_))) {
                panic!(
                    "{} did not create {}",
                    program.display(),
                    agent.socket.display()
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        agent
    }

    /// Send SIGTERM and wait for the agent to exit; returns its exit code.
    pub fn terminate(mut self) -> Option<i32> {
        let pid = libc::pid_t::try_from(self.child.id()).expect("pid fits pid_t");
        // SAFETY: plain kill(2) on our own child process.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        self.child.wait().ok().and_then(|status| status.code())
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
