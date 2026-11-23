//! `ssh -Q` compared against OpenSSH's.
//!
//! The algorithm lists are those russh implements, so they are compared as
//! an ordered subset of OpenSSH's lists, as is `-Q help`, to which
//! distributions add; everything else must match.

use sshutils_testing::{Comparison, Differential, require_openssh};

const OURS: &str = env!("CARGO_BIN_EXE_ssh");

/// Is every line of `ours` in `theirs`, in the same order?
fn ordered_subset(ours: &str, theirs: &str) -> bool {
    let mut theirs = theirs.lines();
    ours.lines().all(|name| theirs.any(|t| t == name))
}

fn run(ssh: &Differential, args: &[&str]) -> Comparison {
    let comparison = ssh.case(args).run();
    assert_eq!(
        comparison.ours.outcome.status, comparison.theirs.outcome.status,
        "{comparison:?}"
    );
    comparison
}

fn same(ssh: &Differential, args: &[&str]) {
    let comparison = run(ssh, args);
    assert_eq!(
        comparison.ours.outcome.stdout, comparison.theirs.outcome.stdout,
        "{comparison:?}"
    );
}

#[test]
fn algorithm_lists() {
    let openssh = require_openssh!();
    let ssh = Differential::new(OURS, openssh.require_tool("ssh"));
    for query in [
        "cipher",
        "cipher-auth",
        "mac",
        "kex",
        "key",
        "key-cert",
        "key-plain",
        "key-ca-sign",
        "key-sig",
        "sig",
        "compression",
        "Ciphers",
        "macs",
        "KEXALGORITHMS",
        "HostKeyAlgorithms",
        "PubkeyAcceptedKeyTypes",
        "CASignatureAlgorithms",
    ] {
        let comparison = run(&ssh, &["-Q", query]);
        let (ours, theirs) = (&comparison.ours.outcome, &comparison.theirs.outcome);
        assert!(!ours.stdout.trim().is_empty(), "{comparison:?}");
        assert!(
            ordered_subset(&ours.stdout, &theirs.stdout),
            "{comparison:?}"
        );
    }
}

#[test]
fn other_queries() {
    let openssh = require_openssh!();
    let ssh = Differential::new(OURS, openssh.require_tool("ssh"));
    same(&ssh, &["-Q", "protocol-version"]);
    // Distributions add queries (Fedora's GSSAPI patch: `kex-gss`).
    let help = run(&ssh, &["-Q", "help"]);
    let (ours, theirs) = (&help.ours.outcome, &help.theirs.outcome);
    assert!(ordered_subset(&ours.stdout, &theirs.stdout), "{help:?}");
    for args in [
        &["-Q", "bogus"][..],
        &["-Q", "Cipher"],
        &["-Q", "KEY"],
        &["-Q"],
        &["-Q", ""],
    ] {
        same(&ssh, args);
    }
}

#[test]
fn queries_end_parsing() {
    let openssh = require_openssh!();
    let ssh = Differential::new(OURS, openssh.require_tool("ssh"));
    for args in [
        // Answered without a destination, and before later options.
        &["-Q", "protocol-version", "host"][..],
        &["host", "-Q", "protocol-version"],
        &["-Q", "protocol-version", "-1"],
        &["-Q", "protocol-version", "-Q", "bogus"],
        &["-Q", "bogus", "-Q", "protocol-version"],
        &["-Q", "protocol-version", "-o", "Bogus=1"],
        // Earlier errors still count.
        &["-1", "-Q", "protocol-version"],
        &["-o", "Bogus=1", "-Q", "protocol-version"],
        &["-F", "/nonexistent", "-Q", "protocol-version"],
    ] {
        same(&ssh, args);
    }
}
