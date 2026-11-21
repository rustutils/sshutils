use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How long any single command may run before it's killed.
const TIMEOUT: Duration = Duration::from_secs(60);

/// Environment variables passed through to child processes. Everything else
/// is removed, in particular `SSH_AUTH_SOCK`, `SSH_ASKPASS` and `DISPLAY`.
const KEEP_ENV: &[&str] = &["PATH", "USER", "LOGNAME", "TMPDIR"];

/// The result of running a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Exit status, or `None` if killed by a signal (including our timeout).
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// A command for `program`, run in `dir`, with a clean environment and no
/// controlling terminal.
pub fn command(program: impl AsRef<OsStr>, dir: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.current_dir(dir).env_clear();
    for key in KEEP_ENV {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
    cmd.env("LC_ALL", "C").env("HOME", dir);
    // SAFETY: setsid is async-signal-safe. Starting a new session detaches
    // the child from our terminal, so passphrase prompts that open /dev/tty
    // fail (and fall back to stdin) instead of waiting for keyboard input.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd
}

/// Run `cmd` to completion, feeding it `stdin`. Kills it after a timeout.
pub fn run(cmd: &mut Command, stdin: &[u8]) -> Outcome {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to start {:?}: {e}", cmd.get_program()));

    let mut child_stdin = child.stdin.take().expect("stdin is piped");
    let input = stdin.to_vec();
    let writer = thread::spawn(move || {
        // The child may exit without reading everything; that's fine.
        let _ = child_stdin.write_all(&input);
    });
    let stdout = read_in_background(child.stdout.take().expect("stdout is piped"));
    let stderr = read_in_background(child.stderr.take().expect("stderr is piped"));

    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for child") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break child.wait().expect("wait for killed child");
        }
        thread::sleep(Duration::from_millis(10));
    };

    let _ = writer.join();
    Outcome {
        status: status.code(),
        stdout: stdout.join().expect("stdout reader"),
        stderr: stderr.join().expect("stderr reader"),
    }
}

fn read_in_background(mut pipe: impl Read + Send + 'static) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    })
}
