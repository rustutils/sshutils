//! Keys from an agent, compared against OpenSSH's `ssh`, with OpenSSH's
//! ssh-agent and with ours: which agent is used (`IdentityAgent`), the
//! order agent and file keys are offered in (`IdentitiesOnly`), signing by
//! the agent, and its refusals.

mod common;

use std::fs;

use common::{AgentKind, Case, Harness, Keys, current_user, our_agent};
use sshutils_testing::{Behaviour, MethodKind, require_openssh};

const PUBKEY: &[&str] = &[
    "-o",
    "PreferredAuthentications=publickey",
    "-o",
    "LogLevel=VERBOSE",
];

/// The agents to compare with: OpenSSH's, and ours when it was built.
fn agents() -> Vec<AgentKind> {
    let mut agents = vec![AgentKind::Openssh];
    if our_agent().is_some() {
        agents.push(AgentKind::Ours);
    } else {
        eprintln!("our ssh-agent isn't built; testing with OpenSSH's only");
    }
    agents
}

struct Run<'a> {
    h: &'a Harness,
    keys: &'a Keys,
    agent: AgentKind,
}

impl Run<'_> {
    /// Connect with these files from `keys` (with `.pub` and `-cert.pub`
    /// unless the name has a dot), `ssh-add` runs (file names) and
    /// arguments.
    fn check(&self, files: &[&str], adds: &[&[&str]], args: &[&str], answers: &[&str]) {
        self.check_after(files, adds, args, answers, &[]);
    }

    /// Like [`check`](Self::check), comparing the output of `ssh-add`
    /// runs afterwards.
    fn check_after(
        &self,
        files: &[&str],
        adds: &[&[&str]],
        args: &[&str],
        answers: &[&str],
        after: &[&[&str]],
    ) {
        let h = self.h;
        let mut written = vec![(
            "known_hosts".to_string(),
            format!("{} {}\n", h.name(), h.host_key("ed25519")),
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
            agent: Some(self.agent),
            agent_adds: adds.iter().map(|a| a.to_vec()).collect(),
            agent_after: after.iter().map(|a| a.to_vec()).collect(),
            ..Case::default()
        });
    }
}

fn make_keys(openssh: &sshutils_testing::Openssh) -> Keys {
    let keys = Keys::new(openssh);
    for (name, key_type) in [
        ("a", "ed25519"),
        ("b", "ecdsa"),
        ("c", "rsa"),
        ("d", "ed25519"),
    ] {
        keys.make(name, key_type, "", &[]);
    }
    keys.make("enc", "ed25519", "secret", &[]);
    keys.make("ca", "ed25519", "", &[]);
    keys.make("cert", "ed25519", "", &[]);
    keys.certify("ca", "cert", &["-n", &current_user()]);
    // Private keys to add on their own: without passphrase, without
    // certificate.
    // The agent's comment differs from the file's: keys match by key.
    fs::copy(keys.path("enc"), keys.path("enc.unlocked")).unwrap();
    let keygen = openssh.require_tool("ssh-keygen");
    for args in [
        &["-q", "-p", "-P", "secret", "-N", "", "-f"][..],
        &["-q", "-c", "-C", "unlocked", "-f"],
    ] {
        let status = std::process::Command::new(&keygen)
            .args(args)
            .arg(keys.path("enc.unlocked"))
            .status()
            .unwrap();
        assert!(status.success());
    }
    keys.make("small", "rsa", "", &["-b", "1024"]);
    fs::copy(keys.path("cert"), keys.path("cert.only")).unwrap();
    keys
}

#[test]
fn identity_agent() {
    let openssh = require_openssh!();
    let keys = make_keys(&openssh);
    let h = Harness::new(&openssh, &["ed25519"]);
    authorize(&h, &keys, &["a"]);
    for agent in agents() {
        let run = Run {
            h: &h,
            keys: &keys,
            agent,
        };
        let with_a: &[&[&str]] = &[&["-q", "a"]];
        for args in [
            &[][..],
            &["-o", "IdentityAgent=SSH_AUTH_SOCK"],
            &["-o", "IdentityAgent=agent.sock"],
            &["-o", "IdentityAgent=%d/agent.sock"],
            &["-o", "IdentityAgent=$SSH_AUTH_SOCK"],
            &["-o", "IdentityAgent=${SSH_AUTH_SOCK}"],
            &["-o", "IdentityAgent=$NOT_SET"],
            &["-o", "IdentityAgent=$BAD-NAME"],
            &["-o", "IdentityAgent=none"],
            &["-o", "IdentityAgent=missing.sock"],
            &["-o", "PubkeyAuthentication=no"],
        ] {
            run.check(&["a"], with_a, args, &[]);
        }
        // An empty agent, and one with other keys.
        run.check(&[], &[], &[], &[]);
        run.check(&["b", "d"], &[&["-q", "b", "d"]], &[], &[]);
    }
}

#[test]
fn agent_and_file_keys() {
    let openssh = require_openssh!();
    let keys = make_keys(&openssh);
    let ca = keys.public("ca");
    let sshd = sshutils_testing::Sshd::start_with(&openssh, &["ed25519"], move |dir| {
        fs::write(dir.join("user_ca"), format!("{ca}\n")).unwrap();
        format!("TrustedUserCAKeys {}\n", dir.join("user_ca").display())
    });
    let h = Harness::with_sshd(&openssh, sshd);
    authorize(&h, &keys, &["a", "c", "enc", "small"]);
    for agent in agents() {
        let run = Run {
            h: &h,
            keys: &keys,
            agent,
        };
        // The agent signs for a file key it holds: no passphrase.
        run.check(
            &["enc", "enc.unlocked"],
            &[&["-q", "enc.unlocked"]],
            &["-i", "enc"],
            &["secret"],
        );
        // IdentitiesOnly: only the agent's keys that are also files.
        run.check(
            &["a", "b"],
            &[&["-q", "a", "b"]],
            &["-i", "b", "-o", "IdentitiesOnly=yes"],
            &[],
        );
        run.check(
            &["a", "b"],
            &[&["-q", "a"]],
            &["-i", "b", "-o", "IdentitiesOnly=yes"],
            &[],
        );
        // RSA signatures from the agent.
        run.check(&["c"], &[&["-q", "c"]], &[], &[]);
        run.check(
            &["c"],
            &[&["-q", "c"]],
            &["-o", "PubkeyAcceptedAlgorithms=rsa-sha2-256,ssh-ed25519"],
            &[],
        );
        // Agent keys below RequiredRSASize are ignored.
        run.check(&["small"], &[&["-q", "small"]], &[], &[]);
        run.check(
            &["small"],
            &[&["-q", "small"]],
            &["-o", "RequiredRSASize=2048"],
            &[],
        );
        // A certificate in the agent, and one from a file for a key in
        // the agent.
        run.check(&["cert"], &[&["-q", "cert"]], &[], &[]);
        run.check(
            &["cert", "cert.only"],
            &[&["-q", "cert.only"]],
            &["-i", "cert"],
            &[],
        );
        // The agent refuses: it can't ask for the confirmation.
        run.check(&["a"], &[&["-q", "-c", "a"]], &[], &[]);
        run.check(&["a"], &[&["-q", "-c", "a"]], &["-i", "a"], &[]);
        // A key restricted to this host (ssh-add -h) signs only
        // host-bound requests, which PubkeyAuthentication=unbound turns
        // off. Our agent doesn't take destination constraints yet.
        if agent == AgentKind::Ours {
            continue;
        }
        let here = h.name();
        let restricted = ["-q", "-H", "known_hosts", "-h", &here, "a"];
        for args in [
            &[][..],
            &["-o", "PubkeyAuthentication=host-bound"],
            &["-o", "PubkeyAuthentication=unbound"],
        ] {
            run.check(&["a"], &[&restricted], args, &[]);
        }
    }
}

#[test]
fn offered_order() {
    let openssh = require_openssh!();
    let keys = make_keys(&openssh);
    let h = Harness::scripted(
        &openssh,
        Behaviour {
            methods: vec![MethodKind::PublicKey],
            ..Behaviour::default()
        },
    );
    for agent in agents() {
        let run = Run {
            h: &h,
            keys: &keys,
            agent,
        };
        let all = ["a", "b", "c", "d", "cert"];
        let adds: &[&[&str]] = &[&["-q", "c", "a", "cert"], &["-q", "b"]];
        for args in [
            &[][..],
            &["-i", "d", "-i", "b"],
            &["-i", "d", "-i", "b", "-o", "IdentitiesOnly=yes"],
            &["-i", "cert", "-i", "a"],
            &["-o", "CertificateFile=cert-cert.pub", "-i", "d"],
            &["-o", "PubkeyAcceptedAlgorithms=ssh-ed25519"],
        ] {
            run.check(&all, adds, args, &[]);
        }
    }
}

#[test]
fn add_keys_to_agent() {
    let openssh = require_openssh!();
    let keys = make_keys(&openssh);
    keys.make("pem", "rsa", "", &["-m", "PEM"]);
    // Private keys without their public halves: one that has it inside,
    // and a PEM key, loaded before it is offered.
    fs::copy(keys.path("a"), keys.path("a.alone")).unwrap();
    fs::copy(keys.path("pem"), keys.path("pem.alone")).unwrap();
    let ca = keys.public("ca");
    let sshd = sshutils_testing::Sshd::start_with(&openssh, &["ed25519"], move |dir| {
        fs::write(dir.join("user_ca"), format!("{ca}\n")).unwrap();
        format!("TrustedUserCAKeys {}\n", dir.join("user_ca").display())
    });
    let h = Harness::with_sshd(&openssh, sshd);
    authorize(&h, &keys, &["a", "enc", "pem"]);
    let list: &[&[&str]] = &[&["-l"]];
    for agent in agents() {
        let run = Run {
            h: &h,
            keys: &keys,
            agent,
        };
        let add = |value: &str, files: &[&str], args: &[&str], answers: &[&str]| {
            let option = format!("AddKeysToAgent={value}");
            let mut all = vec!["-o", option.as_str()];
            all.extend(args);
            run.check_after(files, &[], &all, answers, list);
        };
        for value in ["yes", "no", "1h", "confirm 30m"] {
            add(value, &["a"], &["-i", "a"], &[]);
        }
        // A passphrase, a PEM key (no comment), a key without a public
        // half, and a certificate's key.
        add("yes", &["enc"], &["-i", "enc"], &["secret"]);
        add("yes", &["pem"], &["-i", "pem"], &[]);
        add("yes", &["a.alone"], &["-i", "a.alone"], &[]);
        add("yes", &["pem.alone"], &["-i", "pem.alone"], &[]);
        add("yes", &["cert"], &["-i", "cert"], &[]);
        // Asked through askpass: an empty answer or "yes" agrees.
        for answer in ["yes", "no", ""] {
            add("ask", &["a"], &["-i", "a"], &[answer]);
        }
        add("ask", &["pem"], &["-i", "pem"], &["yes"]);
        // Without an agent, or when the agent signs.
        add("yes", &["a"], &["-i", "a", "-o", "IdentityAgent=none"], &[]);
        run.check_after(
            &["a"],
            &[&["-q", "a"]],
            &["-i", "a", "-o", "AddKeysToAgent=yes"],
            &[],
            list,
        );
        // A confirmed key: the agent can't ask, so it refuses to sign.
        run.check_after(
            &["a"],
            &[],
            &["-i", "a", "-o", "AddKeysToAgent=confirm"],
            &[],
            &[&["-l"], &["-T", "a.pub"]],
        );
    }
}

fn authorize(h: &Harness, keys: &Keys, names: &[&str]) {
    let common::Server::Sshd(sshd) = &h.server else {
        panic!("authorized_keys is for sshd");
    };
    let lines: String = names
        .iter()
        .map(|n| format!("{}\n", keys.public(n)))
        .collect();
    fs::write(sshd.dir().join("authorized_keys"), lines).unwrap();
}
