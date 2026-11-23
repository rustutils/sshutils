//! Connecting and checking host keys, compared against OpenSSH's `ssh`
//! with a throwaway OpenSSH server.
//!
//! Both clients stop after the host key: OpenSSH because no
//! authentication method is allowed, ours because authentication isn't
//! implemented yet. Apart from the lines about that, their exit status and
//! messages must be the same; the messages about host keys and failed
//! connections are reproduced word for word.

use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::thread;
use std::time::Duration;

mod common;

use common::{Case, Harness, OURS, assert_same};
use sshutils_testing::{Differential, require_openssh};

#[test]
fn known_hosts_lookup() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh, &["ed25519"]);
    let name = h.name();
    let key = h.host_key("ed25519");
    let other = h.other_key("ed25519");
    let rsa = h.other_key("rsa");

    // Known, unknown, changed, and a known key of another type (which
    // OpenSSH also treats as changed).
    h.check(&format!("{name} {key}\n"), &[]);
    h.check("", &[]);
    h.check(&format!("{name} {other}\n"), &[]);
    h.check(&format!("{name} {rsa}\n"), &[]);
    h.check(&format!("{name} {other}\n{name} {key}\n"), &[]);
    h.check(&format!("# comment\n\ngarbage line\n{name} {key}\n"), &[]);

    // Host patterns.
    h.check(&format!("other,{name} {key}\n"), &[]);
    h.check(&format!("* {key}\n"), &[]);
    h.check(&format!("[127.0.0.?]:* {key}\n"), &[]);
    h.check(&format!("!{name},* {key}\n"), &[]);
    h.check(&format!("other {key}\n"), &[]);
    // Without the port: accepted, since the port is not the default.
    h.check(&format!("127.0.0.1 {key}\n"), &[]);
    h.check(&format!("127.0.0.1 {other}\n"), &[]);

    // Markers.
    h.check(&format!("{name} {key}\n@revoked {name} {key}\n"), &[]);
    h.check(&format!("@revoked * {key}\n"), &[]);
    h.check(&format!("@cert-authority {name} {key}\n"), &[]);

    // HostKeyAlias replaces the name, port included.
    h.check(&format!("alias {key}\n"), &["-o", "HostKeyAlias=alias"]);
    h.check(&format!("{name} {key}\n"), &["-o", "HostKeyAlias=alias"]);
    h.check(&format!("alias {other}\n"), &["-o", "HostKeyAlias=alias"]);

    // Localhost exemption.
    h.check("", &["-o", "NoHostAuthenticationForLocalhost=yes"]);
    h.check(
        &format!("{name} {other}\n"),
        &["-o", "NoHostAuthenticationForLocalhost=yes"],
    );
    h.check(
        "",
        &[
            "-o",
            "NoHostAuthenticationForLocalhost=yes",
            "-o",
            "HostKeyAlias=a",
        ],
    );

    // A changed key is refused in every mode but `off`.
    for mode in ["ask", "accept-new"] {
        h.check(
            &format!("{name} {other}\n"),
            &["-o", &format!("StrictHostKeyChecking={mode}")],
        );
        h.check(
            &format!("@revoked {name} {key}\n"),
            &["-o", &format!("StrictHostKeyChecking={mode}")],
        );
    }

    // Fingerprints in the warning.
    h.check(&format!("{name} {other}\n"), &["-o", "FingerprintHash=md5"]);
    // Log levels, from the command line and from the configuration.
    h.check(&format!("{name} {other}\n"), &["-q"]);
    h.check("", &["-o", "LogLevel=fatal"]);
    h.check("", &["-o", "LogLevel=error"]);
    for level in ["QUIET", "FATAL", "ERROR"] {
        h.check_files(
            &[
                ("known_hosts", &format!("{name} {other}\n")),
                ("config", &format!("LogLevel {level}\n")),
            ],
            &["-F", "config"],
        );
    }
}

#[test]
fn known_hosts_files() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh, &["ed25519"]);
    let name = h.name();
    let key = h.host_key("ed25519");
    let other = h.other_key("ed25519");
    let files = ["-o", "UserKnownHostsFile=first second"];

    h.check_files(
        &[("first", ""), ("second", &format!("{name} {key}\n"))],
        &files,
    );
    h.check_files(
        &[
            ("first", &format!("{name} {other}\n")),
            ("second", &format!("{name} {key}\n")),
        ],
        &files,
    );
    h.check_files(&[("second", &format!("{name} {other}\n"))], &files);
    h.check_files(
        &[("global", &format!("{name} {key}\n"))],
        &["-o", "GlobalKnownHostsFile=global"],
    );
    h.check_files(
        &[("global", &format!("{name} {other}\n"))],
        &["-o", "GlobalKnownHostsFile=global"],
    );
    h.check_files(
        &[("global", &format!("{name} {other}\n"))],
        &[
            "-o",
            "GlobalKnownHostsFile=global",
            "-o",
            "UserKnownHostsFile=none",
        ],
    );
    h.check_files(
        &[("known.hashed", &format!("{name} {key}\n"))],
        &["-o", "UserKnownHostsFile=known.hashed"],
    );
    h.check_files(
        &[("known.hashed", &format!("{name} {other}\n"))],
        &["-o", "UserKnownHostsFile=known.hashed"],
    );
}

#[test]
fn host_key_algorithms() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh, &["ed25519", "ecdsa", "rsa"]);
    let name = h.name();
    let ecdsa = h.host_key("ecdsa");
    let rsa = h.host_key("rsa");
    let other_rsa = h.other_key("rsa");

    // The algorithms follow what known_hosts has for the host.
    h.check(&format!("{name} {rsa}\n"), &[]);
    h.check(&format!("{name} {ecdsa}\n"), &[]);
    h.check(&format!("{name} {other_rsa}\n"), &[]);
    h.check(
        &format!("{name} {rsa}\n"),
        &["-o", "HostKeyAlgorithms=-ssh-ed25519*"],
    );
    h.check(
        &format!("{name} {rsa}\n"),
        &["-o", "HostKeyAlgorithms=+ssh-rsa"],
    );
    // Unless the list is given explicitly.
    h.check(
        &format!("{name} {rsa}\n"),
        &["-o", "HostKeyAlgorithms=ssh-ed25519,rsa-sha2-512"],
    );
    h.check(
        &format!("{name} {rsa}\n"),
        &["-o", "HostKeyAlgorithms=^rsa-sha2-256"],
    );
    h.check(
        &format!("{name} {ecdsa}\n"),
        &["-o", "HostKeyAlgorithms=ecdsa-sha2-nistp256"],
    );
    // Nothing in common.
    h.check("", &["-o", "HostKeyAlgorithms=ssh-rsa"]);
}

#[test]
fn negotiation() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh, &["ed25519"]);
    let known = format!("{} {}\n", h.name(), h.host_key("ed25519"));
    for args in [
        &["-c", "aes256-ctr"][..],
        &["-c", "3des-cbc"],
        &["-m", "hmac-sha2-512"],
        &["-o", "MACs=hmac-md5"],
        &["-o", "KexAlgorithms=curve25519-sha256"],
        &["-o", "KexAlgorithms=diffie-hellman-group1-sha1"],
        &["-o", "Ciphers=aes128-ctr", "-o", "MACs=hmac-sha2-256"],
        &["-C"],
        &["-o", "Compression=yes"],
        &["-o", "RekeyLimit=1M 10"],
        &["-o", "ServerAliveInterval=5"],
        &["-o", "TCPKeepAlive=no"],
        &["-o", "IPQoS=none"],
        &["-o", "BindAddress=127.0.0.1"],
        &["-b", "127.0.0.2"],
    ] {
        h.check(&known, args);
    }
}

/// Failures before the server answers.
#[test]
fn connection_failures() {
    let openssh = require_openssh!();
    let ssh = Differential::new(OURS, openssh.require_tool("ssh"));
    let base = [
        "-F",
        "none",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "BatchMode=yes",
    ];
    let run = |extra: &[&str]| {
        let args: Vec<&str> = base.iter().chain(extra).copied().collect();
        assert_same(&ssh.case(args).run());
    };

    // A port nobody listens on.
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port().to_string();
    drop(closed);
    run(&["-p", &port, "127.0.0.1", "true"]);
    run(&[
        "-p",
        &port,
        "-o",
        "ConnectionAttempts=2",
        "127.0.0.1",
        "true",
    ]);
    run(&["-p", &port, "-4", "::1", "true"]);
    run(&["nonexistent.invalid", "true"]);
    run(&[
        "-o",
        "BindAddress=nonexistent.invalid",
        "-p",
        &port,
        "127.0.0.1",
        "true",
    ]);
    run(&[
        "-o",
        "BindInterface=nonexistent0",
        "-p",
        &port,
        "127.0.0.1",
        "true",
    ]);

    // Addresses found by canonicalization, before the final configuration
    // restricted the address family: those of the other family are skipped.
    let config = "CanonicalizeHostname yes\nCanonicalDomains invalid\n\
                  Match canonical\n  AddressFamily inet6\n";
    let args = [
        "-F",
        "config",
        "-o",
        "BatchMode=yes",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-p",
        &port,
        "localhost.",
        "true",
    ];
    assert_same(
        &ssh.case(args)
            .setup(move |dir: &Path| fs::write(dir.join("config"), config).unwrap())
            .run(),
    );

    // A server that never sends its identification.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port().to_string();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in silent.incoming().flatten() {
            held.push(stream);
        }
    });
    run(&["-p", &port, "-o", "ConnectTimeout=1", "127.0.0.1", "true"]);

    // Servers that hang up or announce the wrong protocol.
    for reply in [
        &b""[..],
        b"SSH-1.5-old\r\n",
        b"SSH-2.0\r\n",
        b"hello\r\nSSH-9.9-x\r\n",
    ] {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port().to_string();
        thread::spawn(move || {
            use std::io::{Read, Write};
            for mut stream in server.incoming().flatten().take(2) {
                let _ = stream.write_all(reply);
                // Read the client's identification first, so closing
                // doesn't reset the connection.
                let mut buf = [0; 256];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.read(&mut buf);
            }
        });
        run(&["-p", &port, "127.0.0.1", "true"]);
    }
}

#[test]
fn new_host_keys() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh, &["ed25519"]);
    let name = h.name();
    let key = h.host_key("ed25519");
    let other = h.other_key("ed25519");
    let known = |text: &str| vec![("known_hosts", text.to_string())];

    // Added without asking.
    for mode in ["accept-new", "no", "off"] {
        let option = format!("StrictHostKeyChecking={mode}");
        h.run(Case {
            files: known(""),
            args: vec!["-o", &option],
            compare: vec!["known_hosts"],
            ..Case::default()
        });
        h.run(Case {
            files: known(""),
            args: vec!["-o", &option, "-o", "HashKnownHosts=yes"],
            compare: vec!["known_hosts"],
            ..Case::default()
        });
    }
    // The file gets a final newline first; other entries stay.
    h.run(Case {
        files: known(&format!("other {other}")),
        args: vec!["-o", "StrictHostKeyChecking=accept-new"],
        compare: vec!["known_hosts"],
        ..Case::default()
    });
    // A missing file is created, a missing directory is not.
    h.run(Case {
        args: vec!["-o", "StrictHostKeyChecking=accept-new"],
        compare: vec!["known_hosts"],
        ..Case::default()
    });
    h.run(Case {
        args: vec![
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UserKnownHostsFile=missing/known_hosts",
        ],
        compare: vec!["missing/known_hosts"],
        ..Case::default()
    });
    // With nowhere to write, new keys are refused.
    h.run(Case {
        args: vec![
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UserKnownHostsFile=none",
        ],
        ..Case::default()
    });
    // Recorded under the alias, lowercased.
    h.run(Case {
        files: known(""),
        args: vec![
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "HostKeyAlias=My.Alias",
        ],
        compare: vec!["known_hosts"],
        ..Case::default()
    });
    // Known without the port: nothing is added.
    h.run(Case {
        files: known(&format!("127.0.0.1 {key}\n")),
        args: vec!["-o", "StrictHostKeyChecking=accept-new"],
        compare: vec!["known_hosts"],
        ..Case::default()
    });
    // CheckHostIP is off for loopback addresses.
    h.run(Case {
        files: known(""),
        args: vec![
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "CheckHostIP=yes",
        ],
        compare: vec!["known_hosts"],
        ..Case::default()
    });
    // The fingerprint of a known key.
    h.check(&format!("{name} {key}\n"), &["-o", "VisualHostKey=yes"]);
}

#[test]
fn host_key_prompts() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh, &["ed25519"]);
    let key = h.host_key("ed25519");
    let fingerprint = {
        let out = std::process::Command::new(&h.keygen)
            .arg("-lf")
            .arg(h.server.host_key_pub_of("ed25519"))
            .output()
            .unwrap();
        String::from_utf8(out.stdout)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_string()
    };
    let ask = |answers: Vec<&str>, extra: &[&str], known: &str| {
        let mut args = vec!["-o", "StrictHostKeyChecking=ask", "-o", "BatchMode=no"];
        args.extend_from_slice(extra);
        h.run(Case {
            files: vec![("known_hosts", known.to_string())],
            args,
            answers,
            compare: vec!["known_hosts"],
        });
    };

    ask(vec!["yes"], &[], "");
    ask(vec!["YES"], &[], "");
    ask(vec!["  yes  "], &[], "");
    ask(vec!["no"], &[], "");
    ask(vec![""], &[], "");
    ask(vec![&fingerprint], &[], "");
    ask(vec![&fingerprint.to_lowercase()], &[], "");
    ask(vec!["maybe", "perhaps", "yes"], &[], "");
    ask(vec!["maybe", "no"], &[], "");
    ask(vec!["yes"], &["-o", "VisualHostKey=yes"], "");
    ask(vec!["yes"], &["-o", "HashKnownHosts=yes"], "");
    ask(vec!["yes"], &["-o", "FingerprintHash=md5"], "");
    // The same key under other names.
    let many: String = (0..10).map(|i| format!("other{i} {key}\n")).collect();
    ask(vec!["no"], &[], &format!("other {key}\n"));
    ask(vec!["no"], &[], &many);
    ask(vec!["no"], &[], &format!("@cert-authority other {key}\n"));
    h.run(Case {
        files: vec![("known_hosts.hashed", format!("other {key}\n"))],
        args: vec![
            "-o",
            "StrictHostKeyChecking=ask",
            "-o",
            "BatchMode=no",
            "-o",
            "UserKnownHostsFile=known_hosts.hashed",
        ],
        answers: vec!["no"],
        compare: vec![],
    });
    // Batch mode never asks.
    h.run(Case {
        files: vec![("known_hosts", String::new())],
        args: vec!["-o", "StrictHostKeyChecking=ask"],
        answers: vec!["yes"],
        compare: vec!["known_hosts"],
    });
    // Neither does a client without a terminal or askpass program.
    h.check(
        "",
        &["-o", "StrictHostKeyChecking=ask", "-o", "BatchMode=no"],
    );
}

#[test]
fn changed_keys_without_strict_checking() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh, &["ed25519"]);
    let name = h.name();
    let key = h.host_key("ed25519");
    let other = h.other_key("ed25519");
    let changed = format!("{name} {other}\n");
    let revoked = format!("@revoked {name} {key}\n");
    let off = ["-o", "StrictHostKeyChecking=off"];
    for known in [&changed, &revoked] {
        h.check(known, &off);
        h.check(
            known,
            &[
                &off[..],
                &[
                    "-o",
                    "PasswordAuthentication=no",
                    "-o",
                    "KbdInteractiveAuthentication=no",
                ],
            ]
            .concat(),
        );
        h.check(
            known,
            &[
                &off[..],
                &["-A", "-X", "-L", "1234:localhost:1", "-w", "any"],
            ]
            .concat(),
        );
        h.check(known, &[&off[..], &["-o", "UpdateHostKeys=yes"]].concat());
        h.check(
            known,
            &[
                &off[..],
                &["-o", "ExitOnForwardFailure=yes", "-R", "1234:localhost:1"],
            ]
            .concat(),
        );
        h.check(
            known,
            &[&off[..], &["-o", "ExitOnForwardFailure=yes"]].concat(),
        );
    }
}
