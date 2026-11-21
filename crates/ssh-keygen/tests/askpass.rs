//! Passphrase prompts answered by an askpass program, compared against
//! OpenSSH's ssh-keygen.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sshutils_testing::{Differential, Openssh, command, require_openssh, run};
use tempfile::TempDir;

const OURS: &str = env!("CARGO_BIN_EXE_ssh-keygen");

fn keygen(openssh: &Openssh) -> Differential {
    Differential::new(OURS, openssh.require_tool("ssh-keygen"))
}

/// An encrypted key (`enc`, passphrase `pw`) and an askpass program
/// (`ok.sh`) that answers `pw` and logs its arguments.
fn fixtures(openssh: &Openssh) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let out = run(
        command(openssh.require_tool("ssh-keygen"), dir.path())
            .args(["-q", "-t", "ed25519", "-N", "pw", "-C", "enc", "-f", "enc"]),
        b"",
    );
    assert_eq!(out.status, Some(0), "{}", out.stderr);
    let script = "#!/bin/sh\nprintf 'args=[%s]\\n' \"$*\" >> askpass.log\necho pw\n";
    fs::write(dir.path().join("ok.sh"), script).unwrap();
    fs::set_permissions(dir.path().join("ok.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

/// Copy every fixture into `dir`, keeping file modes.
fn install(fixtures: &Path, dir: &Path) {
    for entry in fs::read_dir(fixtures).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
    }
}

#[test]
fn passphrase_prompts_use_askpass() {
    let openssh = require_openssh!();
    let fixtures = fixtures(&openssh);
    let cases: &[&[&str]] = &[
        &["-y", "-f", "enc"],
        &["-p", "-N", "new", "-f", "enc"],
        &["-c", "-C", "new comment", "-f", "enc"],
        &["-q", "-t", "ed25519", "-C", "c", "-f", "generated"],
    ];
    for args in cases {
        let c = keygen(&openssh)
            .case(*args)
            .setup(|dir| install(fixtures.path(), dir))
            .env("DISPLAY", ":0")
            .env("SSH_ASKPASS", "./ok.sh")
            .run();
        c.assert_same_outcome().assert_same_file("askpass.log");
    }
}
