//! Checks the harness itself, using only OpenSSH.

use std::fs;

use sshutils_testing::{Differential, Sshd, command, require_openssh, run};

#[test]
fn openssh_client_logs_in_to_sshd() {
    let openssh = require_openssh!();
    let sshd = Sshd::start(&openssh);
    let out = run(
        command(openssh.require_tool("ssh"), sshd.dir())
            .arg("-F")
            .arg(sshd.client_config())
            .args(["sshd-test", "echo", "hello"]),
        b"",
    );
    assert_eq!(
        out.status,
        Some(0),
        "{}\nsshd log:\n{}",
        out.stderr,
        sshd.log()
    );
    assert_eq!(out.stdout, "hello\n");
}

#[test]
fn login_fails_without_authorized_key() {
    let openssh = require_openssh!();
    let sshd = Sshd::start(&openssh);
    fs::write(sshd.dir().join("authorized_keys"), "").unwrap();
    let out = run(
        command(openssh.require_tool("ssh"), sshd.dir())
            .arg("-F")
            .arg(sshd.client_config())
            .args(["sshd-test", "true"]),
        b"",
    );
    assert_eq!(out.status, Some(255), "login should fail: {}", sshd.log());
}

#[test]
fn differential_of_openssh_with_itself_agrees() {
    let openssh = require_openssh!();
    let keygen = openssh.require_tool("ssh-keygen");
    let fixtures = tempfile::tempdir().unwrap();
    let out = run(
        command(&keygen, fixtures.path())
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "c", "-f", "k"]),
        b"",
    );
    assert_eq!(out.status, Some(0));
    let pubkey = fs::read(fixtures.path().join("k.pub")).unwrap();

    let diff = Differential::new(&keygen, &keygen);
    diff.case(["-l", "-f", "k.pub"])
        .setup(|dir| fs::write(dir.join("k.pub"), &pubkey).unwrap())
        .run()
        .assert_same_outcome();
    diff.case(["-l", "-f", "missing"])
        .run()
        .assert_same_outcome();
}

#[test]
fn differential_detects_differences() {
    let openssh = require_openssh!();
    let diff = Differential::new("/bin/true", "/bin/false");
    let comparison = diff.case(Vec::<&str>::new()).run();
    let result = std::panic::catch_unwind(|| {
        comparison.assert_same_outcome();
    });
    assert!(
        result.is_err(),
        "differing exit codes must fail ({})",
        openssh.version()
    );
}

#[test]
fn children_have_no_terminal() {
    // A passphrase prompt must not wait for keyboard input.
    let openssh = require_openssh!();
    let dir = tempfile::tempdir().unwrap();
    let keygen = openssh.require_tool("ssh-keygen");
    let out = run(
        command(&keygen, dir.path()).args(["-q", "-t", "ed25519", "-N", "secret", "-f", "k"]),
        b"",
    );
    assert_eq!(out.status, Some(0));
    let out = run(command(&keygen, dir.path()).args(["-y", "-f", "k"]), b"");
    assert_ne!(out.status, Some(0));
    assert_ne!(out.status, None, "timed out waiting for a terminal");
}

#[test]
fn cases_can_run_against_a_fresh_agent() {
    let openssh = require_openssh!();
    let keygen = openssh.require_tool("ssh-keygen");
    let fixtures = tempfile::tempdir().unwrap();
    let out = run(
        command(&keygen, fixtures.path())
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "c", "-f", "k"]),
        b"",
    );
    assert_eq!(out.status, Some(0));
    let copy = |dir: &std::path::Path| {
        for name in ["k", "k.pub"] {
            fs::copy(fixtures.path().join(name), dir.join(name)).unwrap();
        }
    };

    let ssh_add = openssh.require_tool("ssh-add");
    let diff = Differential::new(&ssh_add, &ssh_add);
    // Each run starts with an empty agent of its own.
    let c = diff.case(["-l"]).agent(&openssh).run();
    c.assert_same_outcome().assert_same_agent(&openssh);
    assert_eq!(c.ours.outcome.status, Some(1), "{}", c.ours.outcome.stderr);

    // Adding a key changes that run's agent only.
    let c = diff.case(["k"]).agent(&openssh).setup(copy).run();
    c.assert_same_outcome().assert_same_agent(&openssh);
    let agent = c.ours.agent.as_ref().unwrap();
    assert!(agent.identities(&openssh).starts_with("ssh-ed25519 "));
}
