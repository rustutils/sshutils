//! Host certificates, compared against OpenSSH's `ssh` with a throwaway
//! OpenSSH server that presents a certificate signed by a test CA.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

use common::{Case, Harness};
use sshutils_testing::{Openssh, Sshd, require_openssh};

/// Certificate authorities for the tests.
struct Authorities {
    dir: tempfile::TempDir,
}

impl Authorities {
    fn new(keygen: &Path) -> Authorities {
        let dir = tempfile::tempdir().unwrap();
        for (name, key_type) in [
            ("ca", "ed25519"),
            ("rsa_ca", "rsa"),
            ("other_ca", "ed25519"),
        ] {
            let status = Command::new(keygen)
                .args(["-q", "-t", key_type, "-N", "", "-C", "", "-f"])
                .arg(dir.path().join(name))
                .status()
                .unwrap();
            assert!(status.success());
        }
        Authorities { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The public key, as `type base64`.
    fn public(&self, name: &str) -> String {
        let text = fs::read_to_string(self.path(&format!("{name}.pub"))).unwrap();
        let mut fields = text.split_whitespace();
        format!("{} {}", fields.next().unwrap(), fields.next().unwrap())
    }
}

/// A server whose Ed25519 host key is certified by `ca` with these
/// `ssh-keygen -s` options (`-h` and the identity are added).
fn server(openssh: &Openssh, cas: &Authorities, ca: &str, options: &[&str]) -> Harness {
    let keygen = openssh.require_tool("ssh-keygen");
    let ca = cas.path(ca);
    let options: Vec<String> = options.iter().map(|o| o.to_string()).collect();
    let sshd = Sshd::start_with(openssh, &["ed25519", "ecdsa"], move |dir| {
        let out = Command::new(&keygen)
            .arg("-s")
            .arg(&ca)
            .args(["-I", "test-host"])
            .args(&options)
            .arg(dir.join("host_key_ed25519.pub"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        format!(
            "HostCertificate {}\n",
            dir.join("host_key_ed25519-cert.pub").display()
        )
    });
    Harness::with_sshd(openssh, sshd)
}

fn check(h: &Harness, known_hosts: String, args: &[&str]) {
    h.run(Case {
        files: vec![("known_hosts", known_hosts)],
        args: args.to_vec(),
        compare: vec!["known_hosts"],
        ..Case::default()
    });
}

#[test]
fn trusted_certificates() {
    let openssh = require_openssh!();
    let keygen = openssh.require_tool("ssh-keygen");
    let cas = Authorities::new(&keygen);
    let ca = cas.public("ca");
    let other_ca = cas.public("other_ca");

    let h = server(&openssh, &cas, "ca", &["-h", "-n", "127.0.0.1,alias"]);
    let name = h.name();
    let key = h.host_key("ed25519");
    let ecdsa = h.host_key("ecdsa");

    // Trusted by host name, pattern, or alias.
    check(&h, format!("@cert-authority {name} {ca}\n"), &[]);
    check(&h, format!("@cert-authority * {ca}\n"), &[]);
    check(&h, format!("@cert-authority 127.0.0.1 {ca}\n"), &[]);
    check(
        &h,
        format!("@cert-authority alias {ca}\n"),
        &["-o", "HostKeyAlias=alias"],
    );
    check(
        &h,
        format!("@cert-authority * {ca}\n"),
        &["-o", "HostKeyAlias=nope"],
    );
    // Another CA, or none: the plain key decides.
    check(&h, format!("@cert-authority * {other_ca}\n"), &[]);
    check(
        &h,
        format!("@cert-authority * {other_ca}\n{name} {key}\n"),
        &[],
    );
    check(&h, format!("{name} {key}\n"), &[]);
    check(&h, format!("{name} {ecdsa}\n"), &[]);
    check(&h, format!("@cert-authority * {ca}\n{name} {ecdsa}\n"), &[]);
    // New plain keys are still recorded after a certificate failed.
    check(
        &h,
        format!("@cert-authority * {other_ca}\n"),
        &["-o", "StrictHostKeyChecking=accept-new"],
    );
    // Revoked: the CA, or the host key itself.
    check(
        &h,
        format!("@cert-authority * {ca}\n@revoked * {ca}\n"),
        &[],
    );
    check(
        &h,
        format!("@cert-authority * {ca}\n@revoked * {key}\n"),
        &[],
    );
    check(
        &h,
        format!("@cert-authority * {ca}\n@revoked * {ca}\n"),
        &["-o", "StrictHostKeyChecking=off"],
    );
    // Signature algorithms the CA may use.
    check(
        &h,
        format!("@cert-authority * {ca}\n"),
        &["-o", "CASignatureAlgorithms=rsa-sha2-512"],
    );
    check(
        &h,
        format!("@cert-authority * {ca}\n"),
        &["-o", "CASignatureAlgorithms=ssh-ed*"],
    );
    // Certificates not offered.
    check(
        &h,
        format!("@cert-authority * {ca}\n{name} {key}\n"),
        &["-o", "HostKeyAlgorithms=ssh-ed25519"],
    );
    check(
        &h,
        format!("@cert-authority * {ca}\n"),
        &["-o", "HostKeyAlgorithms=-*-cert-v01@openssh.com"],
    );
}

#[test]
fn invalid_certificates() {
    let openssh = require_openssh!();
    let keygen = openssh.require_tool("ssh-keygen");
    let cas = Authorities::new(&keygen);
    let ca = cas.public("ca");
    let rsa_ca = cas.public("rsa_ca");

    for (signer, trusted, options) in [
        // Not for this host.
        ("ca", &ca, &["-h", "-n", "other.example"][..]),
        ("ca", &ca, &["-h", "-n", "127.0.0.1?"]),
        // No principals at all.
        ("ca", &ca, &["-h"]),
        // A user certificate.
        ("ca", &ca, &["-n", "127.0.0.1"]),
        // Expired, and not valid yet.
        (
            "ca",
            &ca,
            &["-h", "-n", "127.0.0.1", "-V", "20000101:20010101"],
        ),
        ("ca", &ca, &["-h", "-n", "127.0.0.1", "-V", "+520w:+530w"]),
        // An RSA CA, signing with each hash.
        ("rsa_ca", &rsa_ca, &["-h", "-n", "127.0.0.1"]),
        (
            "rsa_ca",
            &rsa_ca,
            &["-h", "-n", "127.0.0.1", "-t", "rsa-sha2-256"],
        ),
    ] {
        let h = server(&openssh, &cas, signer, options);
        let name = h.name();
        let key = h.host_key("ed25519");
        check(&h, format!("@cert-authority * {trusted}\n"), &[]);
        check(
            &h,
            format!("@cert-authority * {trusted}\n{name} {key}\n"),
            &[],
        );
        check(
            &h,
            format!("@cert-authority * {trusted}\n"),
            &["-o", "CASignatureAlgorithms=rsa-sha2-256"],
        );
    }
}
