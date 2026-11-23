//! Public key authentication with key files, compared against OpenSSH's
//! `ssh`: with OpenSSH's sshd (keys in `authorized_keys`, certificates from
//! a trusted CA, two keys required), and with the scripted server, which
//! records the keys each client offered and signed with.

mod common;

use std::fs;

use common::{Case, Harness, Keys, current_user};
use sshutils_testing::{Behaviour, MethodKind, Sshd, require_openssh};

/// Options for every case: only public keys, at the verbose level that
/// names the method used.
///
/// Fedora's ssh (unlike upstream) also limits its host key algorithms to
/// PubkeyAcceptedAlgorithms, so every such list here includes the server's
/// host key type.
const PUBKEY: &[&str] = &[
    "-o",
    "PreferredAuthentications=publickey",
    "-o",
    "LogLevel=VERBOSE",
];

struct Run<'a> {
    h: &'a Harness,
    keys: &'a Keys,
    /// The server's host key type.
    host_key: &'a str,
}

impl Run<'_> {
    /// Connect with these key files from `keys` (each with its `.pub`
    /// and `-cert.pub`, if any, unless the name says which file),
    /// arguments and passphrase answers.
    fn check(&self, files: &[&str], args: &[&str], answers: &[&str]) {
        self.check_modes(files, args, answers, &[]);
    }

    fn check_modes(&self, files: &[&str], args: &[&str], answers: &[&str], modes: &[(&str, u32)]) {
        let h = self.h;
        let mut written = vec![(
            "known_hosts".to_string(),
            format!("{} {}\n", h.name(), h.host_key(self.host_key)),
        )];
        for name in files {
            let candidates = if name.contains('.') {
                vec![name.to_string()]
            } else {
                vec![
                    name.to_string(),
                    format!("{name}.pub"),
                    format!("{name}-cert.pub"),
                ]
            };
            for file in candidates {
                if self.keys.path(&file).exists() {
                    written.push((file.clone(), self.keys.text(&file)));
                }
            }
        }
        let mut all: Vec<&str> = args.to_vec();
        all.extend(PUBKEY);
        if !answers.is_empty() {
            all.extend(["-o", "BatchMode=no"]);
        }
        h.run(Case {
            files: written
                .iter()
                .map(|(n, c)| (n.as_str(), c.clone()))
                .collect(),
            args: all,
            answers: answers.to_vec(),
            modes: modes.to_vec(),
            ..Case::default()
        });
    }
}

fn authorize(h: &Harness, keys: &Keys, names: &[&str]) {
    let texts: Vec<String> = names.iter().map(|n| keys.public(n)).collect();
    authorize_texts(h, &texts);
}

fn authorize_texts(h: &Harness, keys: &[String]) {
    let common::Server::Sshd(sshd) = &h.server else {
        panic!("authorized_keys is for sshd");
    };
    let lines: String = keys.iter().map(|k| format!("{k}\n")).collect();
    fs::write(sshd.dir().join("authorized_keys"), lines).unwrap();
}

/// The public key of a private key file whose `.pub` is gone.
fn public_of(keys: &Keys, name: &str) -> String {
    let out = std::process::Command::new("ssh-keygen")
        .args(["-y", "-P", "secret", "-f"])
        .arg(keys.path(name))
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn identity_files() {
    let openssh = require_openssh!();
    let keys = Keys::new(&openssh);
    keys.make("ed", "ed25519", "", &[]);
    keys.make("ec", "ecdsa", "", &[]);
    keys.make("rsa", "rsa", "", &["-b", "3072"]);
    keys.make("small", "rsa", "", &["-b", "1024"]);
    // An ECDSA host key, so that the lists below can leave out Ed25519.
    let h = Harness::new(&openssh, &["ecdsa"]);
    authorize(&h, &keys, &["ed", "rsa", "small"]);
    let run = Run {
        h: &h,
        keys: &keys,
        host_key: "ecdsa",
    };

    run.check(&["ed"], &["-i", "ed"], &[]);
    run.check(&["ec"], &["-i", "ec"], &[]);
    run.check(&["ed", "ec"], &["-i", "ec", "-i", "ed"], &[]);
    run.check(&["ed"], &["-o", "IdentityFile=ed"], &[]);
    run.check(&["ed"], &["-o", "IdentityFile=%d/ed"], &[]);
    run.check(&["ed"], &["-o", "IdentityFile=${HOME}/ed"], &[]);
    run.check(&["ed"], &["-o", "IdentityFile=%z"], &[]);
    // RSA signatures as the server and PubkeyAcceptedAlgorithms allow.
    run.check(&["rsa"], &["-i", "rsa"], &[]);
    for accepted in [
        "rsa-sha2-256,ecdsa-sha2-nistp256",
        "ssh-rsa,ecdsa-sha2-nistp256",
        "-rsa-sha2-512",
        "ssh-ed25519,ecdsa-sha2-nistp256",
    ] {
        let option = format!("PubkeyAcceptedAlgorithms={accepted}");
        run.check(&["rsa"], &["-i", "rsa", "-o", &option], &[]);
    }
    run.check(&["small"], &["-i", "small"], &[]);
    run.check(
        &["small"],
        &["-i", "small", "-o", "RequiredRSASize=2048"],
        &[],
    );
    run.check(
        &["ed"],
        &["-i", "ed", "-o", "PubkeyAcceptedAlgorithms=ecdsa*"],
        &[],
    );
    run.check(&["ed"], &["-i", "ed", "-o", "PubkeyAuthentication=no"], &[]);
    // Missing, unreadable and mismatched files.
    run.check(&[], &["-i", "missing"], &[]);
    run.check(&[], &["-o", "IdentityFile=missing"], &[]);
    run.check(&["ed.pub"], &["-i", "ed"], &[]);
    run.check(&["ed.pub"], &["-i", "ed.pub"], &[]);
    run.check(&["ed"], &["-i", "ed.pub"], &[]);
    run.check_modes(&["ed"], &["-i", "ed"], &[], &[("ed", 0o644)]);
    run.check_modes(&["ed"], &["-i", "ed"], &[], &[("ed", 0o640)]);
    run.check_modes(&["ed"], &["-i", "ed"], &[], &[("ed", 0o000)]);
    fs::write(keys.path("garbage"), "not a key\n").unwrap();
    run.check(&["garbage"], &["-i", "garbage"], &[]);
    // The private key of one, the public key of another.
    fs::copy(keys.path("ed"), keys.path("mixed")).unwrap();
    fs::copy(keys.path("rsa.pub"), keys.path("mixed.pub")).unwrap();
    run.check(&["mixed"], &["-i", "mixed"], &[]);
}

#[test]
fn passphrases() {
    let openssh = require_openssh!();
    let keys = Keys::new(&openssh);
    keys.make("enc", "ed25519", "secret", &[]);
    keys.make("other", "ed25519", "secret", &[]);
    // Encrypted PEM EC keys are a known gap of russh's key decoding.
    keys.make("pem", "rsa", "secret", &["-m", "PEM"]);
    for name in ["bare", "bare_other"] {
        keys.make(name, "ed25519", "secret", &[]);
        fs::remove_file(keys.path(&format!("{name}.pub"))).unwrap();
    }
    let h = Harness::new(&openssh, &["ed25519"]);
    authorize_texts(
        &h,
        &[
            keys.public("enc"),
            keys.public("pem"),
            public_of(&keys, "bare"),
        ],
    );
    let run = Run {
        h: &h,
        keys: &keys,
        host_key: "ed25519",
    };

    for files in [&["enc"][..], &["enc.pub", "enc"], &["enc"]] {
        // Asked once the server accepts the key.
        run.check(files, &["-i", "enc"], &["secret"]);
        run.check(files, &["-i", "enc"], &["wrong", "secret"]);
        run.check(
            files,
            &["-i", "enc"],
            &["wrong", "wrong", "wrong", "secret"],
        );
        run.check(files, &["-i", "enc"], &["", "secret"]);
        run.check(
            files,
            &["-i", "enc", "-o", "NumberOfPasswordPrompts=1"],
            &["wrong", "secret"],
        );
        run.check(
            files,
            &["-i", "enc", "-o", "NumberOfPasswordPrompts=0"],
            &["secret"],
        );
        // Never in batch mode.
        run.check(files, &["-i", "enc", "-o", "BatchMode=yes"], &["secret"]);
    }
    // The public half of an OpenSSH private key is readable without the
    // passphrase.
    run.check(&["bare"], &["-i", "bare"], &["secret"]);
    run.check(&["bare"], &["-i", "bare"], &["wrong", "secret"]);
    run.check(&["bare_other"], &["-i", "bare_other"], &["secret"]);
    // Not asked for a key the server doesn't accept.
    run.check(&["other"], &["-i", "other"], &["secret"]);
    run.check(
        &["other", "enc"],
        &["-i", "other", "-i", "enc"],
        &["secret"],
    );
    // Without a readable public key: asked first.
    let pem = &["pem"][..];
    fs::remove_file(keys.path("pem.pub")).unwrap();
    run.check(pem, &["-i", "pem"], &["secret"]);
    run.check(pem, &["-i", "pem"], &["wrong", ""]);
}

#[test]
fn certificates() {
    let openssh = require_openssh!();
    let keys = Keys::new(&openssh);
    let user = current_user();
    keys.make("ca", "ed25519", "", &[]);
    keys.make("rsa_ca", "rsa", "", &[]);
    for (name, key_type, ca, args) in [
        ("good", "ed25519", "ca", vec!["-n", user.as_str()]),
        ("rsa", "rsa", "rsa_ca", vec!["-n", user.as_str()]),
        ("nobody", "ed25519", "ca", vec!["-n", "nobody"]),
        (
            "expired",
            "ed25519",
            "ca",
            vec!["-n", user.as_str(), "-V", "20000101:20010101"],
        ),
        ("host", "ed25519", "ca", vec!["-h", "-n", user.as_str()]),
        ("enc", "ed25519", "ca", vec!["-n", user.as_str()]),
    ] {
        let passphrase = if name == "enc" { "secret" } else { "" };
        keys.make(name, key_type, passphrase, &[]);
        keys.certify(ca, name, &args);
    }
    let cas = format!("{}\n{}\n", keys.public("ca"), keys.public("rsa_ca"));
    let sshd = Sshd::start_with(&openssh, &["ed25519"], move |dir| {
        fs::write(dir.join("user_ca"), &cas).unwrap();
        format!("TrustedUserCAKeys {}\n", dir.join("user_ca").display())
    });
    let h = Harness::with_sshd(&openssh, sshd);
    authorize(&h, &keys, &[]);
    let run = Run {
        h: &h,
        keys: &keys,
        host_key: "ed25519",
    };

    for name in ["good", "rsa", "nobody", "expired", "host"] {
        run.check(&[name], &["-i", name], &[]);
    }
    run.check(&["good"], &["-o", "IdentityFile=good"], &[]);
    run.check(&["enc"], &["-i", "enc"], &["secret"]);
    // Certificates named separately.
    run.check(
        &["good", "nobody"],
        &[
            "-i",
            "nobody",
            "-o",
            "CertificateFile=good-cert.pub",
            "-i",
            "good",
        ],
        &[],
    );
    run.check(&["good"], &["-o", "CertificateFile=good-cert.pub"], &[]);
    run.check(
        &["good"],
        &["-o", "CertificateFile=good.pub", "-i", "good"],
        &[],
    );
    run.check(
        &["good"],
        &["-o", "CertificateFile=missing-cert.pub", "-i", "good"],
        &[],
    );
    run.check(
        &["good"],
        &[
            "-i",
            "good",
            "-o",
            "PubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com,ssh-ed25519",
        ],
        &[],
    );
    run.check(
        &["rsa"],
        &[
            "-i",
            "rsa",
            "-o",
            "PubkeyAcceptedAlgorithms=rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519",
        ],
        &[],
    );
}

#[test]
fn two_keys_required() {
    let openssh = require_openssh!();
    let keys = Keys::new(&openssh);
    keys.make("first", "ed25519", "", &[]);
    keys.make("second", "ecdsa", "", &[]);
    keys.make("other", "ed25519", "", &[]);
    let sshd = Sshd::start_with(&openssh, &["ed25519"], |_| {
        "AuthenticationMethods publickey,publickey\n".to_string()
    });
    let h = Harness::with_sshd(&openssh, sshd);
    authorize(&h, &keys, &["first", "second"]);
    let run = Run {
        h: &h,
        keys: &keys,
        host_key: "ed25519",
    };

    run.check(&["first", "second"], &["-i", "first", "-i", "second"], &[]);
    run.check(
        &["first", "second", "other"],
        &["-i", "other", "-i", "first", "-i", "other", "-i", "second"],
        &[],
    );
    run.check(&["first"], &["-i", "first"], &[]);
}

#[test]
fn offered_keys() {
    let openssh = require_openssh!();
    let keys = Keys::new(&openssh);
    keys.make("a", "ed25519", "", &[]);
    keys.make("b", "ecdsa", "", &[]);
    keys.make("c", "rsa", "", &[]);
    keys.make("d", "ed25519", "secret", &[]);
    keys.make("ca", "ed25519", "", &[]);
    keys.make("e", "ed25519", "", &[]);
    keys.certify("ca", "e", &["-n", "someone"]);
    keys.make("f", "ed25519", "", &[]);
    keys.certify("ca", "f", &["-h", "-n", "someone"]);
    for (accepted, partial, authorities) in [
        (vec![], vec![], vec![]),
        (vec![keys.public("c")], vec![], vec![]),
        (vec![keys.public("d")], vec![], vec![]),
        (vec![], vec![], vec![keys.public("ca")]),
        // Keys are offered again after a partial success.
        (vec![keys.public("a")], vec![keys.public("b")], vec![]),
        (vec![keys.public("b")], vec![keys.public("a")], vec![]),
    ] {
        let h = Harness::scripted(
            &openssh,
            Behaviour {
                methods: vec![MethodKind::PublicKey, MethodKind::Password],
                keys: accepted,
                partial,
                authorities,
                ..Behaviour::default()
            },
        );
        let run = Run {
            h: &h,
            keys: &keys,
            host_key: "ed25519",
        };
        let all = ["a", "b", "c", "d", "e", "f"];
        run.check(
            &all,
            &[
                "-i", "a", "-i", "b", "-i", "c", "-i", "d", "-i", "e", "-i", "f",
            ],
            &["secret"],
        );
        run.check(
            &all,
            &["-i", "e", "-i", "c", "-o", "IdentityFile=a"],
            &["secret"],
        );
        run.check(
            &all,
            &[
                "-i",
                "c",
                "-o",
                "PubkeyAcceptedAlgorithms=rsa-sha2-256,ssh-ed25519",
            ],
            &[],
        );
    }
}

#[test]
fn server_signature_algorithms() {
    // sshd announces its PubkeyAcceptedAlgorithms in server-sig-algs.
    let openssh = require_openssh!();
    let keys = Keys::new(&openssh);
    keys.make("rsa", "rsa", "", &[]);
    keys.make("ed", "ed25519", "", &[]);
    for accepted in [
        "rsa-sha2-256,ssh-ed25519",
        "ssh-ed25519",
        "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256,ssh-ed25519",
    ] {
        let sshd = Sshd::start_with(&openssh, &["ed25519"], move |_| {
            format!("PubkeyAcceptedAlgorithms {accepted}\n")
        });
        let h = Harness::with_sshd(&openssh, sshd);
        authorize(&h, &keys, &["rsa", "ed"]);
        let run = Run {
            h: &h,
            keys: &keys,
            host_key: "ed25519",
        };
        run.check(&["rsa"], &["-i", "rsa"], &[]);
        run.check(&["rsa", "ed"], &["-i", "rsa", "-i", "ed"], &[]);
        run.check(
            &["rsa"],
            &[
                "-i",
                "rsa",
                "-o",
                "PubkeyAcceptedAlgorithms=rsa-sha2-512,ssh-ed25519",
            ],
            &[],
        );
    }
}
