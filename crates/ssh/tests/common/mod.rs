//! The harness shared by the tests that connect to a throwaway OpenSSH
//! server with both clients.

#![allow(dead_code)]

use std::fs;
use std::path::Path;

use sshutils_testing::{Comparison, Differential, Openssh, Sshd};

pub const OURS: &str = env!("CARGO_BIN_EXE_ssh");

/// Lines that differ only because we don't authenticate yet.
pub fn is_authentication_line(line: &str) -> bool {
    line.contains("Permission denied (") || line == "authentication is not supported yet"
}

pub fn messages(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !is_authentication_line(line))
        .map(str::to_string)
        .collect()
}

pub fn assert_same(comparison: &Comparison) {
    let (ours, theirs) = (&comparison.ours.outcome, &comparison.theirs.outcome);
    assert!(
        ours.status == theirs.status && messages(&ours.stderr) == messages(&theirs.stderr),
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
    /// Files written into each client's scratch directory first.
    pub files: Vec<(&'a str, String)>,
    /// Options before the defaults (so they win over them).
    pub args: Vec<&'a str>,
    /// Answers to the prompts, in order; prompting is enabled if given.
    pub answers: Vec<&'a str>,
    /// Files compared afterwards (hashed names normalized).
    pub compare: Vec<&'a str>,
}

pub struct Harness {
    pub sshd: Sshd,
    pub ssh: Differential,
    pub keygen: std::path::PathBuf,
    askpass: tempfile::TempDir,
}

impl Harness {
    pub fn new(openssh: &Openssh, host_key_types: &[&str]) -> Harness {
        Harness::with_sshd(openssh, Sshd::start_with_host_keys(openssh, host_key_types))
    }

    pub fn with_sshd(openssh: &Openssh, sshd: Sshd) -> Harness {
        let askpass = tempfile::tempdir().unwrap();
        let script = askpass.path().join("askpass");
        fs::write(&script, ASKPASS).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        Harness {
            sshd,
            ssh: Differential::new(OURS, openssh.require_tool("ssh")),
            keygen: openssh.require_tool("ssh-keygen"),
            askpass,
        }
    }

    pub fn port(&self) -> String {
        self.sshd.port().to_string()
    }

    /// The server's public key of this type, as `type base64`.
    pub fn host_key(&self, key_type: &str) -> String {
        let text = fs::read_to_string(self.sshd.host_key_pub_of(key_type)).unwrap();
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
        let keygen = self.keygen.clone();
        let mut run = self.ssh.case(full).setup(move |dir: &Path| {
            for (name, content) in &files {
                let path = dir.join(name);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, content).unwrap();
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
        });
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
        for file in case.compare.iter().chain(["prompts"].iter()) {
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
