//! The harness shared by the tests that connect to a throwaway server with
//! both clients: OpenSSH's sshd, or a scripted russh server.

#![allow(dead_code)]

use std::fs;
use std::path::Path;

use sshutils_testing::{Behaviour, Comparison, Differential, Openssh, ScriptedServer, Sshd};

pub const OURS: &str = env!("CARGO_BIN_EXE_ssh");

/// What we print instead of running a session, which isn't supported yet.
pub const NO_SESSIONS: &str = "sessions are not supported yet";

/// Exit status and messages, cut where they must stop matching: we don't
/// run sessions yet, so after authentication succeeded our run ends with
/// [`NO_SESSIONS`] and status 255, OpenSSH's runs the command; both count
/// as success up to the "Authenticated to" line (when it is logged).
pub fn messages(outcome: &sshutils_testing::Outcome) -> (Option<i32>, Vec<String>) {
    let mut lines: Vec<String> = outcome
        .stderr
        .lines()
        .map(|line| line.trim_end_matches('\r').to_string())
        .collect();
    let mut status = outcome.status;
    if status == Some(255) && lines.last().is_some_and(|l| l == NO_SESSIONS) {
        lines.pop();
        status = Some(0);
    }
    if status == Some(0)
        && let Some(i) = lines
            .iter()
            .position(|l| l.starts_with("Authenticated to "))
    {
        lines.truncate(i + 1);
    }
    (status, lines)
}

pub fn assert_same(comparison: &Comparison) {
    let (ours, theirs) = (&comparison.ours.outcome, &comparison.theirs.outcome);
    assert!(
        messages(ours) == messages(theirs),
        "outcomes differ for args {:?}\n\
         --- ours: status {:?}\n{}\n--- OpenSSH: status {:?}\n{}",
        comparison.args,
        ours.status,
        ours.stderr,
        theirs.status,
        theirs.stderr,
    );
}

/// An askpass program that records each prompt in `prompts` (in the
/// current directory) and answers with `$ANSWER_1`, `$ANSWER_2`, ...
pub const ASKPASS: &str = r#"#!/bin/sh
printf '%s\n--\n' "$1" >> prompts
n=$(cat .answers 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > .answers
eval "printf '%s\n' \"\$ANSWER_$n\""
"#;

/// One differential run.
#[derive(Default)]
pub struct Case<'a> {
    /// Files written into each client's scratch directory first. Private
    /// keys (`-----BEGIN` ...) get mode 0600.
    pub files: Vec<(&'a str, String)>,
    /// Modes set on files afterwards.
    pub modes: Vec<(&'a str, u32)>,
    /// Options before the defaults (so they win over them).
    pub args: Vec<&'a str>,
    /// Answers to the prompts, in order; prompting is enabled if given.
    pub answers: Vec<&'a str>,
    /// Files compared afterwards (hashed names normalized).
    pub compare: Vec<&'a str>,
}

/// The server the clients connect to.
pub enum Server {
    Sshd(Sshd),
    /// Its requests are compared too.
    Scripted(ScriptedServer),
}

impl Server {
    pub fn port(&self) -> u16 {
        match self {
            Server::Sshd(sshd) => sshd.port(),
            Server::Scripted(server) => server.port(),
        }
    }

    /// The `.pub` file of the host key of this type.
    pub fn host_key_pub_of(&self, key_type: &str) -> std::path::PathBuf {
        match self {
            Server::Sshd(sshd) => sshd.host_key_pub_of(key_type),
            Server::Scripted(server) => {
                assert_eq!(
                    key_type, "ed25519",
                    "the scripted server has an Ed25519 key"
                );
                server.host_key_pub()
            }
        }
    }
}

/// Where each run's requests to a scripted server are saved.
pub const SERVER_LOG: &str = "server.log";

pub struct Harness {
    pub server: Server,
    pub ssh: Differential,
    pub keygen: std::path::PathBuf,
    askpass: tempfile::TempDir,
}

impl Harness {
    pub fn new(openssh: &Openssh, host_key_types: &[&str]) -> Harness {
        Harness::with_sshd(openssh, Sshd::start_with_host_keys(openssh, host_key_types))
    }

    pub fn with_sshd(openssh: &Openssh, sshd: Sshd) -> Harness {
        Harness::with_server(openssh, Server::Sshd(sshd))
    }

    /// A scripted server following `behaviour`.
    pub fn scripted(openssh: &Openssh, behaviour: Behaviour) -> Harness {
        let server = ScriptedServer::start(&openssh.require_tool("ssh-keygen"), behaviour);
        Harness::with_server(openssh, Server::Scripted(server))
    }

    fn with_server(openssh: &Openssh, server: Server) -> Harness {
        let askpass = tempfile::tempdir().unwrap();
        let script = askpass.path().join("askpass");
        fs::write(&script, ASKPASS).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        Harness {
            server,
            ssh: Differential::new(OURS, openssh.require_tool("ssh")),
            keygen: openssh.require_tool("ssh-keygen"),
            askpass,
        }
    }

    pub fn port(&self) -> String {
        self.server.port().to_string()
    }

    /// The server's public key of this type, as `type base64`.
    pub fn host_key(&self, key_type: &str) -> String {
        let text = fs::read_to_string(self.server.host_key_pub_of(key_type)).unwrap();
        let mut fields = text.split_whitespace();
        format!("{} {}", fields.next().unwrap(), fields.next().unwrap())
    }

    /// A key the server doesn't have.
    pub fn other_key(&self, key_type: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let status = std::process::Command::new(&self.keygen)
            .args(["-q", "-t", key_type, "-N", "", "-C", "", "-f"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let text = fs::read_to_string(path.with_extension("pub")).unwrap();
        text.trim().to_string()
    }

    /// `[127.0.0.1]:port`, the name host keys are recorded under.
    pub fn name(&self) -> String {
        format!("[127.0.0.1]:{}", self.port())
    }

    /// Connect with `known_hosts` as the user's known hosts file, plus
    /// `args` (before the destination). Files are written relative to each
    /// client's scratch directory.
    pub fn check(&self, known_hosts: &str, args: &[&str]) {
        self.check_files(&[("known_hosts", known_hosts)], args);
    }

    /// Like [`check`](Self::check), with several files. Without a `-F` in
    /// `args`, no configuration file is read.
    pub fn check_files(&self, files: &[(&str, &str)], args: &[&str]) {
        self.run(Case {
            files: files.iter().map(|(n, c)| (*n, c.to_string())).collect(),
            args: args.to_vec(),
            ..Case::default()
        });
    }

    pub fn run(&self, case: Case<'_>) {
        let mut full: Vec<String> = case.args.iter().map(|a| a.to_string()).collect();
        if !case.args.contains(&"-F") {
            full.extend(["-F".into(), "none".into()]);
        }
        for option in [
            "UserKnownHostsFile=known_hosts",
            "GlobalKnownHostsFile=/dev/null",
            "StrictHostKeyChecking=yes",
            "BatchMode=yes",
            "PreferredAuthentications=none",
            "IdentityAgent=none",
            // OpenSSH finds ~/.ssh through the passwd database, not $HOME.
            "IdentityFile=none",
            "UpdateHostKeys=no",
        ] {
            full.extend(["-o".into(), option.into()]);
        }
        full.extend(["-p".into(), self.port(), "127.0.0.1".into(), "true".into()]);
        let files: Vec<(String, String)> = case
            .files
            .iter()
            .map(|(n, c)| (n.to_string(), c.clone()))
            .collect();
        let modes: Vec<(String, u32)> = case
            .modes
            .iter()
            .map(|(n, m)| (n.to_string(), *m))
            .collect();
        let keygen = self.keygen.clone();
        let mut run = self.ssh.case(full).setup(move |dir: &Path| {
            use std::os::unix::fs::PermissionsExt;
            for (name, content) in &files {
                let path = dir.join(name);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, content).unwrap();
                if content.starts_with("-----BEGIN") {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                if name.ends_with(".hashed") {
                    let status = std::process::Command::new(&keygen)
                        .arg("-H")
                        .arg("-f")
                        .arg(&path)
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .unwrap();
                    assert!(status.success());
                }
            }
            for (name, mode) in &modes {
                fs::set_permissions(dir.join(name), fs::Permissions::from_mode(*mode)).unwrap();
            }
        });
        if let Server::Scripted(server) = &self.server {
            server.take_log();
            run = run.finish(move |dir: &Path| {
                let log: String = server.take_log().iter().map(|l| format!("{l}\n")).collect();
                fs::write(dir.join(SERVER_LOG), log).unwrap();
            });
        }
        if !case.answers.is_empty() {
            run = run
                .env("SSH_ASKPASS", self.askpass.path().join("askpass"))
                .env("SSH_ASKPASS_REQUIRE", "force");
            for (i, answer) in case.answers.iter().enumerate() {
                run = run.env(format!("ANSWER_{}", i + 1), answer);
            }
        }
        let comparison = run.run();
        assert_same(&comparison);
        let names = [self.name(), "127.0.0.1".to_string()];
        for file in case.compare.iter().chain(["prompts", SERVER_LOG].iter()) {
            let read = |run: &sshutils_testing::Run| {
                fs::read_to_string(run.path(file))
                    .ok()
                    .map(|t| normalize_hashes(&t, &names))
            };
            let (ours, theirs) = (read(&comparison.ours), read(&comparison.theirs));
            assert_eq!(
                ours, theirs,
                "{file} differs for args {:?}\n--- ours:\n{ours:?}\n--- OpenSSH:\n{theirs:?}",
                comparison.args
            );
        }
    }
}

/// Replace hashed host names by `HASHED(<name>)`, naming which of `names`
/// the hash is of.
pub fn normalize_hashes(text: &str, names: &[String]) -> String {
    use sshutils_core::known_hosts::Line;
    text.lines()
        .map(|line| match Line::parse(line) {
            Line::Entry(entry) if entry.is_hashed() => {
                let name = names
                    .iter()
                    .find(|n| entry.matches(n))
                    .map_or("?", |n| n.as_str());
                format!("HASHED({name}) {}", entry.key_text)
            }
            _ => line.to_string(),
        })
        .map(|line| line + "\n")
        .collect()
}

/// Keys made with `ssh-keygen` for a test.
pub struct Keys {
    dir: tempfile::TempDir,
    keygen: std::path::PathBuf,
}

impl Keys {
    pub fn new(openssh: &Openssh) -> Keys {
        Keys {
            dir: tempfile::tempdir().unwrap(),
            keygen: openssh.require_tool("ssh-keygen"),
        }
    }

    /// Make key `name` of `key_type` with `passphrase` and further
    /// `ssh-keygen` arguments (`-m PEM`, `-b 2048`, ...).
    pub fn make(&self, name: &str, key_type: &str, passphrase: &str, args: &[&str]) {
        let status = std::process::Command::new(&self.keygen)
            .args(["-q", "-t", key_type, "-N", passphrase, "-C", name])
            .args(args)
            .arg("-f")
            .arg(self.path(name))
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Certify `name.pub` with CA key `ca`, making `name-cert.pub`.
    pub fn certify(&self, ca: &str, name: &str, args: &[&str]) {
        let out = std::process::Command::new(&self.keygen)
            .arg("-s")
            .arg(self.path(ca))
            .args(["-I", name])
            .args(args)
            .arg(self.path(&format!("{name}.pub")))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    pub fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }

    /// The contents of a file (`name`, `name.pub`, `name-cert.pub`).
    pub fn text(&self, file: &str) -> String {
        fs::read_to_string(self.path(file)).unwrap()
    }

    /// The public key as `type base64`.
    pub fn public(&self, name: &str) -> String {
        let text = self.text(&format!("{name}.pub"));
        let mut fields = text.split_whitespace();
        format!("{} {}", fields.next().unwrap(), fields.next().unwrap())
    }
}

/// The user tests log in as: the one running them, as sshd requires.
pub fn current_user() -> String {
    // SAFETY: getpwuid returns a pointer into static storage or null; the
    // name is copied out at once.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        assert!(!pw.is_null(), "no passwd entry for the current user");
        std::ffi::CStr::from_ptr((*pw).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}
