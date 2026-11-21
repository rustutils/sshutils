//! `ssh-agent` process management compared against OpenSSH's: running in
//! the background, `-k`, command mode, signals, socket activation and the
//! default socket location.

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use sshutils_testing::{Agent, Differential, Openssh, Outcome, command, require_openssh, run};

const OURS: &str = env!("CARGO_BIN_EXE_ssh-agent");

fn programs(openssh: &Openssh) -> [PathBuf; 2] {
    [PathBuf::from(OURS), openssh.require_tool("ssh-agent")]
}

/// Replace process IDs (any run of digits after "pid " or "PID=" or
/// "SSH_AGENT_PID ") with `<pid>`.
fn mask_pids(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = ["pid ", "PID=", "SSH_AGENT_PID "]
        .iter()
        .filter_map(|marker| rest.find(marker).map(|i| i + marker.len()))
        .min()
    {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits > 0 {
            out.push_str("<pid>");
        }
        rest = &rest[digits..];
    }
    out.push_str(rest);
    out
}

/// The value of `name` in printed sh or csh commands.
fn variable(output: &str, name: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let value = line
            .strip_prefix(&format!("{name}="))
            .or_else(|| line.strip_prefix(&format!("setenv {name} ")))?;
        Some(value.split(';').next()?.to_string())
    })
}

fn process_exists(pid: i32) -> bool {
    // SAFETY: kill with signal 0 only checks whether the process exists.
    unsafe { libc_kill(pid, 0) == 0 }
}

fn wait_until(timeout: Duration, condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    condition()
}

/// Run OpenSSH's ssh-add against `socket`.
fn ssh_add(openssh: &Openssh, dir: &Path, socket: &Path, args: &[&str]) -> Outcome {
    run(
        command(openssh.require_tool("ssh-add"), dir)
            .env("SSH_AUTH_SOCK", socket)
            .args(args),
        b"",
    )
}

#[test]
fn background_agent_and_kill() {
    let openssh = require_openssh!();
    for shell_flag in ["-s", "-c"] {
        let mut results = Vec::new();
        for program in programs(&openssh) {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("agent.sock");
            let started = run(
                command(&program, dir.path()).args([shell_flag, "-a", "agent.sock"]),
                b"",
            );
            let pid: i32 = variable(&started.stdout, "SSH_AGENT_PID")
                .and_then(|pid| pid.parse().ok())
                .unwrap_or_else(|| panic!("no SSH_AGENT_PID in {:?}", started.stdout));
            let listed = ssh_add(&openssh, dir.path(), &socket, &["-l"]);

            let killed = run(
                command(&program, dir.path())
                    .env("SSH_AGENT_PID", pid.to_string())
                    .arg(shell_flag)
                    .arg("-k"),
                b"",
            );
            let gone = wait_until(Duration::from_secs(5), || {
                !process_exists(pid) && !socket.exists()
            });
            results.push((
                started.status,
                mask_pids(&started.stdout),
                listed.status,
                killed.status,
                mask_pids(&killed.stdout),
                gone,
            ));
        }
        assert_eq!(results[0], results[1], "{shell_flag} (ours, OpenSSH)");
    }
}

#[test]
fn kill_errors() {
    let openssh = require_openssh!();
    let agent = Differential::new(OURS, openssh.require_tool("ssh-agent"));
    agent.case(["-k"]).run().assert_same_outcome();
    for pid in ["abc", "1", "-5", "2147483000"] {
        agent
            .case(["-k"])
            .env("SSH_AGENT_PID", pid)
            .run()
            .assert_same_outcome();
    }
}

#[test]
fn command_mode() {
    let openssh = require_openssh!();
    let script = r#"echo "socket=$SSH_AUTH_SOCK"; kill -0 "$SSH_AGENT_PID" && echo agent alive; ssh-add -l; echo "ssh-add status $?""#;
    let mut results = Vec::new();
    for program in programs(&openssh) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let out = run(
            command(&program, dir.path()).args(["-a", "agent.sock", "sh", "-c", script]),
            b"",
        );
        // The agent exits once the command has (OpenSSH checks every 10s).
        let gone = wait_until(Duration::from_secs(15), || !socket.exists());
        results.push((out.status, out.stdout, gone));
    }
    assert_eq!(results[0], results[1], "(ours, OpenSSH)");

    let agent = Differential::new(OURS, openssh.require_tool("ssh-agent"));
    // Commands can't be combined with output or foreground options.
    for args in [
        &["-D", "-a", "s", "true"][..],
        &["-s", "true"],
        &["-k", "true"],
    ] {
        agent.case(args).run().assert_same_outcome();
    }
    // A command that can't be run.
    let c = agent.case(["-a", "agent.sock", "./missing-command"]).run();
    assert_eq!(c.ours.outcome.status, c.theirs.outcome.status);
    assert_eq!(c.ours.outcome.stdout, c.theirs.outcome.stdout);
}

#[test]
fn sigusr1_removes_all_keys() {
    let openssh = require_openssh!();
    let mut results = Vec::new();
    for program in programs(&openssh) {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let keygen = run(
            command(openssh.require_tool("ssh-keygen"), d)
                .args(["-q", "-t", "ed25519", "-N", "", "-f", "key"]),
            b"",
        );
        assert_eq!(keygen.status, Some(0));
        let socket = d.join("agent.sock");
        let agent = Agent::start_program(&program, &[], &socket);
        assert_eq!(ssh_add(&openssh, d, &socket, &["key"]).status, Some(0));
        agent.signal(libc_sigusr1());
        let emptied = wait_until(Duration::from_secs(5), || {
            ssh_add(&openssh, d, &socket, &["-l"]).status == Some(1)
        });
        results.push(emptied);
    }
    assert_eq!(results, [true, true], "(ours, OpenSSH)");
}

#[test]
fn socket_activation() {
    let openssh = require_openssh!();
    let Some(activate) = [
        "/usr/bin/systemd-socket-activate",
        "/bin/systemd-socket-activate",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists()) else {
        eprintln!("skipping: systemd-socket-activate not installed");
        return;
    };
    let mut results = Vec::new();
    for program in programs(&openssh) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let mut child = command(&activate, dir.path())
            .arg("-l")
            .arg(&socket)
            .arg(&program)
            .arg("-D")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(wait_until(Duration::from_secs(5), || socket.exists()));
        // The agent starts on the first connection.
        let listed = ssh_add(&openssh, dir.path(), &socket, &["-l"]);
        thread::sleep(Duration::from_millis(300));
        // SAFETY: plain kill(2) on our own child (which exec'd the agent).
        unsafe { libc_kill(child.id() as i32, 15) };
        let status = child.wait().unwrap().code();
        let mut printed = String::new();
        let _ = BufReader::new(child.stdout.take().unwrap()).read_line(&mut printed);
        results.push((listed.status, listed.stdout, status, printed));
    }
    assert_eq!(results[0], results[1], "(ours, OpenSSH)");
}

/// The default socket lives in the real `~/.ssh/agent` (both
/// implementations find it through the user database), so this only runs
/// when `SSHUTILS_TEST_HOME_AGENT` is set. `-U` makes sure no existing
/// sockets are cleaned up; each agent removes its own socket on exit.
#[test]
fn default_socket_location() {
    let openssh = require_openssh!();
    if std::env::var_os("SSHUTILS_TEST_HOME_AGENT").is_none() {
        eprintln!("skipping: set SSHUTILS_TEST_HOME_AGENT=1 to use ~/.ssh/agent");
        return;
    }
    let mut results = Vec::new();
    for program in programs(&openssh) {
        let dir = tempfile::tempdir().unwrap();
        let mut child = command(&program, dir.path())
            .args(["-D", "-U", "-s"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut first = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut first)
            .unwrap();
        let socket = PathBuf::from(variable(&first, "SSH_AUTH_SOCK").unwrap());
        let name = socket.file_name().unwrap().to_string_lossy().to_string();
        let parts: Vec<&str> = name.split('.').collect();
        let shape = (
            socket.parent().unwrap().ends_with(".ssh/agent"),
            parts.len(),
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
            parts[3].len(),
            fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        );
        thread::sleep(Duration::from_millis(300));
        // SAFETY: plain kill(2) on our own child.
        unsafe { libc_kill(child.id() as i32, 15) };
        let status = child.wait().unwrap().code();
        results.push((shape, status, socket.exists()));
    }
    assert_eq!(results[0], results[1], "(ours, OpenSSH)");
}

fn libc_sigusr1() -> i32 {
    10
}

unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, signal: i32) -> i32;
}
