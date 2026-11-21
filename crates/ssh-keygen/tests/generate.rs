//! Key generation, compared against OpenSSH's ssh-keygen.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sshutils_testing::{Comparison, Differential, Openssh, Sshd, command, require_openssh, run};

const OURS: &str = env!("CARGO_BIN_EXE_ssh-keygen");

fn keygen(openssh: &Openssh) -> Differential {
    Differential::new(OURS, openssh.require_tool("ssh-keygen"))
}

/// Replace the parts of ssh-keygen's output that are random by nature
/// (fingerprints and randomart) with placeholders.
fn normalize(stdout: &str) -> String {
    stdout
        .lines()
        .map(|line| {
            if line.starts_with('|') && line.ends_with('|') {
                "|<randomart>|".to_string()
            } else if let Some((hash, rest)) = line.split_once(':')
                && ["MD5", "SHA1", "SHA256", "SHA512"].contains(&hash)
            {
                let comment = rest.split_once(' ').map_or("", |(_, c)| c);
                format!("{hash}:<fingerprint> {comment}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Assert same exit status and same stdout up to random parts.
fn assert_same_normalized(c: &Comparison) {
    let (ours, theirs) = (&c.ours.outcome, &c.theirs.outcome);
    assert_eq!(
        (ours.status, normalize(&ours.stdout)),
        (theirs.status, normalize(&theirs.stdout)),
        "args {:?}\nours stderr: {}\nOpenSSH stderr: {}",
        c.args,
        ours.stderr,
        theirs.stderr,
    );
}

/// Run OpenSSH's ssh-keygen in `dir` and return its outcome.
fn openssh_keygen(openssh: &Openssh, dir: &Path, args: &[&str]) -> sshutils_testing::Outcome {
    run(
        command(openssh.require_tool("ssh-keygen"), dir).args(args),
        b"",
    )
}

/// `ssh-keygen -l` as OpenSSH reports it, minus the fingerprint itself:
/// e.g. `256 <fp> comment (ED25519)`.
fn openssh_describe(openssh: &Openssh, dir: &Path, file: &str) -> String {
    let out = openssh_keygen(openssh, dir, &["-l", "-f", file]);
    assert_eq!(
        out.status,
        Some(0),
        "OpenSSH can't read {file}: {}",
        out.stderr
    );
    let mut fields: Vec<&str> = out.stdout.split_whitespace().collect();
    fields[1] = "<fp>";
    fields.join(" ")
}

fn mode(path: impl AsRef<Path>) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn generates_each_key_type_like_openssh() {
    let openssh = require_openssh!();
    let cases: &[&[&str]] = &[
        &[],
        &["-t", "ed25519"],
        &["-t", "ssh-ed25519"],
        &["-t", "RSA", "-b", "2048"],
        &["-t", "ecdsa"],
        &["-t", "ecdsa", "-b", "384"],
        &["-t", "ecdsa-sha2-nistp521"],
        &["-E", "md5"],
        &["-E", "SHA1"],
        &["-E", "sha512"],
    ];
    for extra in cases {
        let mut args = vec!["-N", "", "-C", "comment", "-f", "key"];
        args.extend_from_slice(extra);
        let c = keygen(&openssh).case(&args).run();
        assert_same_normalized(&c);
        assert_eq!(
            openssh_describe(&openssh, c.ours.dir.path(), "key"),
            openssh_describe(&openssh, c.theirs.dir.path(), "key"),
            "args {args:?}"
        );
        for run in [&c.ours, &c.theirs] {
            assert_eq!(mode(run.path("key")), 0o600, "args {args:?}");
            assert_eq!(mode(run.path("key.pub")), 0o644, "args {args:?}");
        }
        // The public key file matches what OpenSSH derives from the private key.
        let derived = openssh_keygen(&openssh, c.ours.dir.path(), &["-y", "-f", "key"]);
        assert_eq!(
            derived.stdout,
            fs::read_to_string(c.ours.path("key.pub")).unwrap()
        );
    }
}

#[test]
fn quiet_prints_nothing() {
    let openssh = require_openssh!();
    keygen(&openssh)
        .case(["-q", "-N", "", "-f", "key"])
        .run()
        .assert_same_outcome();
}

#[test]
fn invalid_arguments_fail_like_openssh() {
    let openssh = require_openssh!();
    let cases: &[&[&str]] = &[
        &["-t", "dsa"],
        &["-t", "nonsense"],
        &["-t", "rsa", "-b", "512"],
        &["-t", "rsa", "-b", "20000"],
        &["-t", "ecdsa", "-b", "100"],
        &["-b", "abc"],
        &["-b", "0"],
        &["-a", "x", "-N", "pw"],
        &["-Z", "nonsense", "-N", "pw"],
        &["-E", "sha3"],
        &["-t", "ed25519-sk"],
    ];
    for extra in cases {
        let mut args = vec!["-q", "-f", "key"];
        args.extend_from_slice(extra);
        let c = keygen(&openssh).case(&args).run();
        c.assert_same_outcome();
        c.assert_same_file("key");
    }
}

#[test]
fn unknown_option_is_a_usage_error() {
    let openssh = require_openssh!();
    keygen(&openssh).case(["-j"]).run().assert_same_outcome();
}

#[test]
fn declining_overwrite_keeps_the_file() {
    let openssh = require_openssh!();
    for answer in ["n\n", "", "x\ny\n"] {
        let c = keygen(&openssh)
            .case(["-N", "", "-f", "key"])
            .setup(|dir| fs::write(dir.join("key"), "original").unwrap())
            .stdin(answer)
            .run();
        assert_same_normalized(&c);
        c.assert_same_file("key").assert_same_file("key.pub");
    }
}

#[test]
fn accepting_overwrite_replaces_the_file() {
    let openssh = require_openssh!();
    let c = keygen(&openssh)
        .case(["-N", "", "-C", "c", "-f", "key"])
        .setup(|dir| fs::write(dir.join("key"), "original").unwrap())
        .stdin("y\n")
        .run();
    assert_same_normalized(&c);
    openssh_describe(&openssh, c.ours.dir.path(), "key");
}

#[test]
fn prompts_for_passphrase_until_entries_match() {
    let openssh = require_openssh!();
    let c = keygen(&openssh)
        .case(["-C", "c", "-f", "key"])
        .stdin("one\ntwo\nsecret\nsecret\n")
        .run();
    assert_same_normalized(&c);
    for run in [&c.ours, &c.theirs] {
        let out = openssh_keygen(
            &openssh,
            run.dir.path(),
            &["-y", "-P", "secret", "-f", "key"],
        );
        assert_eq!(out.status, Some(0), "{}", out.stderr);
        let out = openssh_keygen(
            &openssh,
            run.dir.path(),
            &["-y", "-P", "wrong", "-f", "key"],
        );
        assert_ne!(out.status, Some(0));
    }
}

#[test]
fn prompts_for_filename() {
    let openssh = require_openssh!();
    let c = keygen(&openssh)
        .case(["-N", "", "-C", "c"])
        .stdin("chosen\n")
        .run();
    // The prompt names the user's real ~/.ssh, which is the same for both.
    assert_same_normalized(&c);
    openssh_describe(&openssh, c.ours.dir.path(), "chosen");
}

#[test]
fn default_comment_matches_openssh() {
    let openssh = require_openssh!();
    let c = keygen(&openssh).case(["-q", "-N", "", "-f", "key"]).run();
    let comment = |run: &sshutils_testing::Run| {
        let line = fs::read_to_string(run.path("key.pub")).unwrap();
        line.split_whitespace()
            .nth(2)
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(comment(&c.ours), comment(&c.theirs));
}

#[test]
fn passphrase_with_custom_rounds_and_cipher() {
    let openssh = require_openssh!();
    for cipher in [
        "aes256-ctr",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
    ] {
        let c = keygen(&openssh)
            .case(["-q", "-a", "4", "-Z", cipher, "-N", "pw", "-f", "key"])
            .run();
        c.assert_same_outcome();
        let out = openssh_keygen(
            &openssh,
            c.ours.dir.path(),
            &["-y", "-P", "pw", "-f", "key"],
        );
        assert_eq!(out.status, Some(0), "cipher {cipher}: {}", out.stderr);
    }
}

#[test]
fn generated_key_logs_in_to_openssh_server() {
    let openssh = require_openssh!();
    let sshd = Sshd::start(&openssh);
    let out = run(
        command(OURS, sshd.dir()).args(["-q", "-N", "", "-f", "ours"]),
        b"",
    );
    assert_eq!(out.status, Some(0), "{}", out.stderr);
    // Authorize only our key, so the harness's own key can't be what logs in.
    fs::copy(
        sshd.dir().join("ours.pub"),
        sshd.dir().join("authorized_keys"),
    )
    .unwrap();

    let out = run(
        command(openssh.require_tool("ssh"), sshd.dir())
            .arg("-F")
            .arg(sshd.client_config())
            .args(["-i", "ours", "sshd-test", "echo", "ok"]),
        b"",
    );
    assert_eq!(
        out.status,
        Some(0),
        "{}\nsshd log:\n{}",
        out.stderr,
        sshd.log()
    );
    assert_eq!(out.stdout, "ok\n");
}
