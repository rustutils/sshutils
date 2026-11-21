//! `ssh-keygen -l` and `-y`, compared against OpenSSH.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sshutils_testing::{Differential, Openssh, command, require_openssh, run};
use tempfile::TempDir;

const OURS: &str = env!("CARGO_BIN_EXE_ssh-keygen");

fn keygen(openssh: &Openssh) -> Differential {
    Differential::new(OURS, openssh.require_tool("ssh-keygen"))
}

/// Key files of many kinds, generated with OpenSSH:
///
/// - `plain`, `plain.pub`: unencrypted ed25519 with comment
/// - `enc`, `enc.pub`: ed25519 encrypted with passphrase `pw`
/// - `rsa`, `rsa.pub`, `ecdsa`, `ecdsa.pub`
/// - `nocomment`, `nocomment.pub`: empty comment
/// - `lonely`: private key without `.pub`; `lonely_enc`: same, encrypted
/// - `mismatch` + `mismatch.pub`: the `.pub` holds a different key
/// - `pem`, `pkcs8`: RSA in PEM and PKCS#8 formats
/// - `authorized_keys`, `known_hosts`, `known_hosts_hashed`
/// - `garbage`, `empty`, `crlf.pub`, `open`: a private key with mode 0644
fn fixtures(openssh: &Openssh) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let keygen = |args: &[&str]| {
        let out = run(
            command(openssh.require_tool("ssh-keygen"), d).args(args),
            b"",
        );
        assert_eq!(out.status, Some(0), "{args:?}: {}", out.stderr);
    };
    keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "plain comment",
        "-f",
        "plain",
    ]);
    keygen(&[
        "-q",
        "-t",
        "ed25519",
        "-N",
        "pw",
        "-C",
        "encrypted",
        "-f",
        "enc",
    ]);
    keygen(&[
        "-q", "-t", "rsa", "-b", "1024", "-N", "", "-C", "rsa", "-f", "rsa",
    ]);
    keygen(&[
        "-q", "-t", "ecdsa", "-b", "384", "-N", "", "-C", "ec", "-f", "ecdsa",
    ]);
    keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", "nocomment"]);
    keygen(&[
        "-q", "-t", "rsa", "-b", "1024", "-m", "PEM", "-N", "", "-f", "pem",
    ]);
    keygen(&[
        "-q", "-t", "rsa", "-b", "1024", "-m", "PKCS8", "-N", "", "-f", "pkcs8",
    ]);
    fs::remove_file(d.join("pem.pub")).unwrap();
    fs::remove_file(d.join("pkcs8.pub")).unwrap();

    let copy = |from: &str, to: &str| fs::copy(d.join(from), d.join(to)).map(drop).unwrap();
    copy("plain", "lonely");
    copy("enc", "lonely_enc");
    copy("plain", "mismatch");
    copy("rsa.pub", "mismatch.pub");
    copy("plain", "open");
    fs::set_permissions(d.join("open"), fs::Permissions::from_mode(0o644)).unwrap();

    let read = |name: &str| fs::read_to_string(d.join(name)).unwrap();
    let bare = |name: &str| {
        let line = read(name);
        let fields: Vec<&str> = line.split_whitespace().take(2).collect();
        fields.join(" ")
    };
    let authorized_keys = format!(
        "# comment\n\n{}\ncommand=\"echo \\\" hi\",no-pty {}\nfrom=\"a b\" {}\ngarbage line\n{} trailing comment\n",
        read("plain.pub").trim(),
        bare("rsa.pub"),
        bare("ecdsa.pub"),
        bare("enc.pub"),
    );
    fs::write(d.join("authorized_keys"), authorized_keys).unwrap();
    let known_hosts = format!(
        "host1,host2 {}\n[host3]:2222 {} trailing\n@cert-authority *.example {}\n@revoked bad {}\n",
        bare("plain.pub"),
        bare("rsa.pub"),
        bare("ecdsa.pub"),
        bare("enc.pub"),
    );
    fs::write(d.join("known_hosts"), &known_hosts).unwrap();
    fs::write(d.join("known_hosts_hashed"), &known_hosts).unwrap();
    keygen(&["-q", "-H", "-f", "known_hosts_hashed"]);
    fs::write(d.join("garbage"), "garbage\n").unwrap();
    fs::write(d.join("empty"), "").unwrap();
    fs::write(
        d.join("crlf.pub"),
        format!("{}\r\n", read("plain.pub").trim()),
    )
    .unwrap();
    dir
}

/// Copy every fixture into `dir`, keeping file modes.
fn install(fixtures: &Path, dir: &Path) {
    for entry in fs::read_dir(fixtures).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
    }
}

const ALL_FILES: &[&str] = &[
    "plain",
    "plain.pub",
    "enc",
    "enc.pub",
    "rsa",
    "rsa.pub",
    "ecdsa",
    "ecdsa.pub",
    "nocomment",
    "nocomment.pub",
    "lonely",
    "lonely_enc",
    "mismatch",
    "pem",
    "pkcs8",
    "authorized_keys",
    "known_hosts",
    "known_hosts_hashed",
    "garbage",
    "empty",
    "crlf.pub",
    "open",
    "missing",
    ".",
];

#[test]
fn fingerprints_match_openssh() {
    let openssh = require_openssh!();
    let fixtures = fixtures(&openssh);
    let keygen = keygen(&openssh);
    for file in ALL_FILES {
        for flags in [&["-l"][..], &["-lv", "-E", "md5"], &["-l", "-E", "sha512"]] {
            let mut args = flags.to_vec();
            args.extend(["-f", file]);
            keygen
                .case(&args)
                .setup(|dir| install(fixtures.path(), dir))
                .run()
                .assert_same_outcome();
        }
    }
}

#[test]
fn fingerprint_from_stdin() {
    let openssh = require_openssh!();
    let fixtures = fixtures(&openssh);
    let keygen = keygen(&openssh);
    for file in ["plain.pub", "authorized_keys", "plain", "empty"] {
        keygen
            .case(["-l", "-f", "-"])
            .stdin(fs::read(fixtures.path().join(file)).unwrap())
            .run()
            .assert_same_outcome();
    }
}

#[test]
fn asks_for_the_key_file() {
    let openssh = require_openssh!();
    let fixtures = fixtures(&openssh);
    let keygen = keygen(&openssh);
    for mode in ["-l", "-y"] {
        for answer in ["plain\n", "missing\n", ""] {
            keygen
                .case([mode])
                .setup(|dir| install(fixtures.path(), dir))
                .stdin(answer)
                .run()
                .assert_same_outcome();
        }
    }
}

#[test]
fn print_public_matches_openssh() {
    let openssh = require_openssh!();
    let fixtures = fixtures(&openssh);
    let keygen = keygen(&openssh);
    for file in ALL_FILES {
        keygen
            .case(["-y", "-f", file])
            .setup(|dir| install(fixtures.path(), dir))
            .run()
            .assert_same_outcome();
    }
}

#[test]
fn print_public_of_encrypted_key() {
    let openssh = require_openssh!();
    let fixtures = fixtures(&openssh);
    let keygen = keygen(&openssh);
    let cases: &[(&[&str], &str)] = &[
        (&["-y", "-P", "pw", "-f", "enc"], ""),
        (&["-y", "-P", "wrong", "-f", "enc"], ""),
        (&["-y", "-f", "enc"], "pw\n"),
        (&["-y", "-f", "enc"], "wrong\n"),
        (&["-y", "-f", "enc"], ""),
        (&["-y", "-P", "ignored", "-f", "plain"], ""),
    ];
    for (args, stdin) in cases {
        keygen
            .case(*args)
            .setup(|dir| install(fixtures.path(), dir))
            .stdin(*stdin)
            .run()
            .assert_same_outcome();
    }
}
