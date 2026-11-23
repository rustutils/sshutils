//! Password and keyboard-interactive authentication, compared against
//! OpenSSH's `ssh` on a scripted server: the prompts (answered through an
//! askpass program, which records them), the retries and their messages,
//! and the requests each client sent.

mod common;

use common::{Case, Harness};
use sshutils_testing::{Behaviour, Challenge, MethodKind, require_openssh};

/// Connect with `args` and the askpass `answers`, prompting allowed.
fn check(h: &Harness, args: &[&str], answers: &[&str]) {
    let known_hosts = format!(
        "{} {key}\nalias {key}\n",
        h.name(),
        key = h.host_key("ed25519")
    );
    let mut all = args.to_vec();
    all.extend(["-o", "BatchMode=no"]);
    // The askpass program answers every prompt (an empty line once the
    // answers run out), so that nothing is asked on a terminal.
    let answers = if answers.is_empty() {
        &[""][..]
    } else {
        answers
    };
    h.run(Case {
        files: vec![("known_hosts", known_hosts)],
        args: all,
        answers: answers.to_vec(),
        ..Case::default()
    });
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn password() {
    let openssh = require_openssh!();
    let h = Harness::scripted(
        &openssh,
        Behaviour {
            methods: vec![MethodKind::Password],
            passwords: strings(&["secret"]),
            ..Behaviour::default()
        },
    );
    let password = ["-o", "PreferredAuthentications=password"];
    for (extra, answers) in [
        (&[][..], &["secret"][..]),
        (&[], &["wrong", "secret"]),
        (&[], &["one", "two", "three"]),
        (&[], &[]),
        (&["-o", "NumberOfPasswordPrompts=1"], &["wrong", "secret"]),
        (&["-o", "NumberOfPasswordPrompts=0"], &["secret"]),
        (&["-o", "LogLevel=VERBOSE"], &["wrong", "secret"]),
        (&["-q"], &["wrong", "secret"]),
        (&["-q"], &["one", "two", "three"]),
        (&["-l", "someone"], &["secret"]),
        (&["-o", "HostKeyAlias=alias"], &["wrong", "secret"]),
        (&["-o", "PasswordAuthentication=no"], &["secret"]),
    ] {
        let mut args = password.to_vec();
        args.extend(extra);
        check(&h, &args, answers);
    }
}

fn login_challenge() -> Challenge {
    Challenge {
        name: "Login".into(),
        instructions: "Answer both,\nplease.\n".into(),
        prompts: vec![("Password: ".into(), false), ("Code: ".into(), true)],
    }
}

#[test]
fn keyboard_interactive() {
    let openssh = require_openssh!();
    let h = Harness::scripted(
        &openssh,
        Behaviour {
            methods: vec![MethodKind::KeyboardInteractive],
            challenges: vec![login_challenge()],
            responses: strings(&["pw", "42"]),
            ..Behaviour::default()
        },
    );
    let kbdint = ["-o", "PreferredAuthentications=keyboard-interactive"];
    for (extra, answers) in [
        (&[][..], &["pw", "42"][..]),
        (&[], &["pw", "41", "pw", "42"]),
        (&[], &["a", "b", "c", "d", "e", "f"]),
        (
            &["-o", "NumberOfPasswordPrompts=1"],
            &["pw", "41", "pw", "42"],
        ),
        (&["-o", "NumberOfPasswordPrompts=0"], &["pw", "42"]),
        (&["-o", "LogLevel=VERBOSE"], &["pw", "42"]),
        // The name and instructions show even with -q.
        (&["-q"], &["pw", "41", "pw", "42"]),
        (
            &["-o", "HostKeyAlias=alias", "-l", "someone"],
            &["pw", "42"],
        ),
        (&["-o", "KbdInteractiveDevices=pam,bsdauth"], &["pw", "42"]),
        (&["-o", "KbdInteractiveAuthentication=no"], &["pw", "42"]),
    ] {
        let mut args = kbdint.to_vec();
        args.extend(extra);
        check(&h, &args, answers);
    }
}

#[test]
fn keyboard_interactive_rounds() {
    let openssh = require_openssh!();
    // Several requests in one attempt, one of them without prompts, and
    // text that needs escaping.
    let h = Harness::scripted(
        &openssh,
        Behaviour {
            methods: vec![MethodKind::KeyboardInteractive],
            challenges: vec![
                Challenge {
                    name: String::new(),
                    instructions: "Welcome \u{1b}[1mback\u{1b}[0m".into(),
                    prompts: vec![],
                },
                login_challenge(),
                Challenge {
                    name: "One more".into(),
                    instructions: String::new(),
                    prompts: vec![("Bell\u{7} and grüße: ".into(), true)],
                },
            ],
            responses: strings(&["pw", "42", "last"]),
            ..Behaviour::default()
        },
    );
    for answers in [&["pw", "42", "last"][..], &["pw", "42", "wrong"]] {
        check(
            &h,
            &["-o", "PreferredAuthentications=keyboard-interactive"],
            answers,
        );
    }
}

#[test]
fn both_methods() {
    let openssh = require_openssh!();
    // Keyboard-interactive is refused without an info request: it isn't
    // tried again, and password follows.
    let h = Harness::scripted(
        &openssh,
        Behaviour {
            methods: vec![MethodKind::Password, MethodKind::KeyboardInteractive],
            passwords: strings(&["secret"]),
            ..Behaviour::default()
        },
    );
    for (args, answers) in [
        (&[][..], &["secret"][..]),
        (&[], &["wrong", "wrong", "wrong"]),
        (
            &[
                "-o",
                "PreferredAuthentications=password,keyboard-interactive",
            ],
            &["wrong", "secret"],
        ),
        (
            &[
                "-o",
                "PreferredAuthentications=keyboard-interactive,password",
            ],
            &["secret"],
        ),
    ] {
        let mut args = args.to_vec();
        if !args.contains(&"-o") {
            args.extend([
                "-o",
                "PreferredAuthentications=keyboard-interactive,password",
            ]);
        }
        check(&h, &args, answers);
    }
    // Keyboard-interactive with challenges first, then password.
    let h = Harness::scripted(
        &openssh,
        Behaviour {
            methods: vec![MethodKind::KeyboardInteractive, MethodKind::Password],
            passwords: strings(&["secret"]),
            challenges: vec![login_challenge()],
            responses: strings(&["pw", "42"]),
            ..Behaviour::default()
        },
    );
    check(
        &h,
        &[
            "-o",
            "PreferredAuthentications=keyboard-interactive,password",
            "-o",
            "NumberOfPasswordPrompts=2",
        ],
        &["a", "b", "c", "d", "secret"],
    );
}

#[test]
fn password_change() {
    let openssh = require_openssh!();
    let h = Harness::scripted(
        &openssh,
        Behaviour {
            methods: vec![MethodKind::Password],
            expired: strings(&["old"]),
            change_prompt: "Your password has \u{1b}[1mexpired\u{1b}[0m.".into(),
            new_passwords: strings(&["new"]),
            ..Behaviour::default()
        },
    );
    let password = ["-o", "PreferredAuthentications=password"];
    for (extra, answers) in [
        // Password, old password, new password, retyped.
        (&[][..], &["old", "old", "new", "new"][..]),
        // A typo when retyping, then a new password the server refuses.
        (&[], &["old", "old", "new", "nwe", "new", "new"]),
        (&[], &["old", "old", "weak", "weak", "old", "new", "new"]),
        (&["-q"], &["old", "old", "new", "nwe", "new", "new"]),
        (
            &["-o", "LogLevel=ERROR"],
            &["old", "old", "new", "nwe", "new", "new"],
        ),
        // The wrong old password.
        (&[], &["old", "wrong", "new", "new", "", "", ""]),
        (
            &["-l", "someone", "-o", "HostKeyAlias=alias"],
            &["old", "old", "new", "new"],
        ),
    ] {
        let mut args = password.to_vec();
        args.extend(extra);
        check(&h, &args, answers);
    }
}
