//! Authentication, compared against OpenSSH's `ssh`: the method sequence
//! (both clients' requests are recorded by a scripted server and must
//! match), banners, and how it ends.

mod common;

use common::{Case, Harness};
use sshutils_testing::{Behaviour, MethodKind, require_openssh};

fn scripted(openssh: &sshutils_testing::Openssh, behaviour: Behaviour) -> Harness {
    Harness::scripted(openssh, behaviour)
}

/// Run `args` with a known_hosts file that trusts the server.
fn check(h: &Harness, args: &[&str]) {
    let known_hosts = format!("{} {}\n", h.name(), h.host_key("ed25519"));
    h.run(Case {
        files: vec![("known_hosts", known_hosts)],
        args: args.to_vec(),
        ..Case::default()
    });
}

/// Each argument set, at the default log level and at `VERBOSE`.
fn check_levels(h: &Harness, cases: &[&[&str]]) {
    for args in cases {
        check(h, args);
        let mut verbose = args.to_vec();
        verbose.extend(["-o", "LogLevel=VERBOSE"]);
        check(h, &verbose);
    }
}

#[test]
fn none_succeeds() {
    let openssh = require_openssh!();
    let h = scripted(
        &openssh,
        Behaviour {
            accept_none: true,
            ..Behaviour::default()
        },
    );
    check_levels(
        &h,
        &[
            &[],
            &["-l", "Somebody"],
            &["-o", "PreferredAuthentications=password"],
            &["-q"],
        ],
    );
}

#[test]
fn permission_denied() {
    let openssh = require_openssh!();
    for methods in [
        &[MethodKind::PublicKey][..],
        &[MethodKind::Password, MethodKind::KeyboardInteractive],
        &[
            MethodKind::KeyboardInteractive,
            MethodKind::PublicKey,
            MethodKind::Password,
            MethodKind::HostBased,
        ],
        &[],
    ] {
        let h = scripted(
            &openssh,
            Behaviour {
                methods: methods.to_vec(),
                ..Behaviour::default()
            },
        );
        // PreferredAuthentications is the harness's "none" unless given;
        // nothing is sent beyond "none" until methods are implemented, so
        // only methods with nothing to send are enabled.
        check_levels(
            &h,
            &[
                &[],
                &["-l", "someone"],
                &["-o", "PreferredAuthentications=bogus,password,none"],
                &[
                    "-o",
                    "PreferredAuthentications=hostbased,keyboard-interactive",
                ],
                &["-o", "PreferredAuthentications="],
                &["-q"],
                &["-o", "LogLevel=FATAL"],
                &["-o", "LogLevel=QUIET"],
            ],
        );
    }
}

#[test]
fn host_names_in_messages() {
    let openssh = require_openssh!();
    let h = scripted(
        &openssh,
        Behaviour {
            methods: vec![MethodKind::PublicKey],
            accept_none: false,
            ..Behaviour::default()
        },
    );
    let known_hosts = format!("[localhost]:{} {}\n", h.port(), h.host_key("ed25519"));
    for args in [
        &["-o", "HostName=LocalHost"][..],
        &["-o", "HostName=LOCALHOST", "-o", "LogLevel=VERBOSE"],
    ] {
        let mut args = args.to_vec();
        args.extend(["-o", "AddressFamily=inet"]);
        h.run(Case {
            files: vec![("known_hosts", known_hosts.clone())],
            args,
            ..Case::default()
        });
    }
}

#[test]
fn banners() {
    let openssh = require_openssh!();
    for banner in [
        "Welcome.\n",
        "Two\nlines\n",
        "no newline",
        "tab\tcr\r\nend\n",
        "\u{1b}[31mred\u{7}\u{8}\u{7f}\n",
        "gr\u{fc}\u{df}e \u{9b}\n",
        "back\\slash\n",
    ] {
        let h = scripted(
            &openssh,
            Behaviour {
                methods: vec![MethodKind::PublicKey],
                banner: Some(banner.to_string()),
                ..Behaviour::default()
            },
        );
        for args in [
            &[][..],
            &["-o", "LogLevel=VERBOSE"],
            &["-o", "LogLevel=ERROR"],
            &["-q"],
            &["-E", "log"],
        ] {
            check(&h, args);
        }
    }
    // Shown before success too.
    let h = scripted(
        &openssh,
        Behaviour {
            accept_none: true,
            banner: Some("Hello\n".to_string()),
            ..Behaviour::default()
        },
    );
    check_levels(&h, &[&[]]);
}

#[test]
fn connection_closed() {
    let openssh = require_openssh!();
    let h = scripted(
        &openssh,
        Behaviour {
            close_on_none: true,
            ..Behaviour::default()
        },
    );
    check_levels(&h, &[&[]]);
}

#[test]
fn openssh_server() {
    // Without keys, publickey has nothing to offer.
    let openssh = require_openssh!();
    let h = Harness::new(&openssh, &["ed25519"]);
    let known_hosts = format!("{} {}\n", h.name(), h.host_key("ed25519"));
    for args in [
        &[][..],
        &["-o", "PreferredAuthentications=publickey"],
        &[
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "LogLevel=VERBOSE",
        ],
        &["-l", "nobody-here"],
    ] {
        h.check(&known_hosts, args);
    }
}
