//! `ssh -G` compared against OpenSSH's: the command line, configuration
//! files, and the resolved configuration it prints.
//!
//! Distributions patch OpenSSH (Fedora adds GSSAPI key exchange options and
//! changes the default key exchange algorithms), and older releases print
//! other keywords and defaults. So each test first runs `-G` with an empty
//! configuration on both sides and leaves out the keywords that already
//! differ there. Against OpenSSH 10.5 only the known distribution keywords
//! and default algorithm lists may differ.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use sshutils_testing::{Comparison, Differential, Openssh, require_openssh};

const OURS: &str = env!("CARGO_BIN_EXE_ssh");

/// Keywords allowed to differ from OpenSSH 10.5 with an empty
/// configuration.
const MAY_DIFFER: &[&str] = &[
    // Distribution patches (GSSAPI key exchange).
    "gssapikeyexchange",
    "gssapitrustdns",
    "gssapirenewalforcesrekey",
    "gssapikexalgorithms",
    "gssapiclientidentity",
    "gssapiserveridentity",
    // Default algorithm lists, which distributions change.
    "ciphers",
    "macs",
    "kexalgorithms",
    "hostkeyalgorithms",
    "hostbasedacceptedalgorithms",
    "pubkeyacceptedalgorithms",
    "casignaturealgorithms",
];

struct Harness {
    ssh: Differential,
    /// Keywords not compared.
    skip: BTreeSet<String>,
}

/// `-G` output grouped by keyword (some keywords print several lines).
fn by_keyword(stdout: &str) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in stdout.lines() {
        let keyword = line.split(' ').next().unwrap_or("").to_string();
        map.entry(keyword).or_default().push(line.to_string());
    }
    map
}

impl Harness {
    fn new(openssh: &Openssh) -> Harness {
        let ssh = Differential::new(OURS, openssh.require_tool("ssh"));
        let baseline = ssh.case(["-F", "none", "-G", "calibrate"]).run();
        assert_eq!(baseline.ours.outcome.status, Some(0), "{baseline:?}");
        assert_eq!(baseline.theirs.outcome.status, Some(0), "{baseline:?}");
        let ours = by_keyword(&baseline.ours.outcome.stdout);
        let theirs = by_keyword(&baseline.theirs.outcome.stdout);
        let skip: BTreeSet<String> = ours
            .keys()
            .chain(theirs.keys())
            .filter(|k| ours.get(*k) != theirs.get(*k))
            .cloned()
            .collect();
        if openssh.version_number() == (10, 5) {
            let unexpected: Vec<_> = skip
                .iter()
                .filter(|k| !MAY_DIFFER.contains(&k.as_str()))
                .collect();
            assert!(
                unexpected.is_empty(),
                "-G output differs from OpenSSH 10.5 for {unexpected:?}\n\
                 --- ours:\n{}\n--- OpenSSH:\n{}",
                baseline.ours.outcome.stdout,
                baseline.theirs.outcome.stdout
            );
        } else {
            eprintln!("{}: not comparing {skip:?}", openssh.version());
        }
        Harness { ssh, skip }
    }

    fn filtered(&self, stdout: &str) -> String {
        stdout
            .lines()
            .filter(|line| !self.skip.contains(line.split(' ').next().unwrap_or("")))
            .map(|line| format!("{line}\n"))
            .collect()
    }

    fn assert_same(&self, comparison: &Comparison) {
        let (ours, theirs) = (&comparison.ours.outcome, &comparison.theirs.outcome);
        if ours.status != theirs.status
            || self.filtered(&ours.stdout) != self.filtered(&theirs.stdout)
        {
            panic!(
                "outcomes differ for args {:?}\n\
                 --- ours: status {:?}\n[stdout]\n{}\n[stderr]\n{}\n\
                 --- OpenSSH: status {:?}\n[stdout]\n{}\n[stderr]\n{}",
                comparison.args,
                ours.status,
                ours.stdout,
                ours.stderr,
                theirs.status,
                theirs.stdout,
                theirs.stderr,
            );
        }
    }

    /// Run `ssh` with these arguments (no configuration files unless the
    /// arguments name one).
    fn args(&self, args: &[&str]) {
        let mut full = vec!["-F", "none"];
        full.extend_from_slice(args);
        self.assert_same(&self.ssh.case(full).run());
    }

    /// Run `ssh -G` with `config` as the configuration file and these
    /// arguments.
    fn config(&self, config: &str, args: &[&str]) {
        self.config_with(config, args, &[], &[]);
    }

    /// Like [`config`](Self::config), with extra files in the scratch
    /// directory and environment variables.
    fn config_with(
        &self,
        config: &str,
        args: &[&str],
        files: &[(&str, &str)],
        env: &[(&str, &str)],
    ) {
        let mut full = vec!["-F", "config", "-G"];
        full.extend_from_slice(args);
        let mut case = self.ssh.case(full).setup(move |dir: &Path| {
            fs::write(dir.join("config"), config).unwrap();
            for (name, contents) in files {
                let path = dir.join(name);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, contents).unwrap();
            }
        });
        for (key, value) in env {
            case = case.env(key, value);
        }
        self.assert_same(&case.run());
    }
}

/// Skip tests that use keywords older releases don't know.
fn recent(openssh: &Openssh) -> bool {
    let recent = openssh.at_least(10, 5);
    if !recent {
        eprintln!("skipping: needs OpenSSH 10.5, found {}", openssh.version());
    }
    recent
}

#[test]
fn options_apply_in_order() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh);
    for args in [
        &["-G", "-4", "-6", "h"][..],
        &["-G", "-6", "-4", "h"],
        &["-G", "-x", "-X", "h"],
        &["-G", "-X", "-x", "h"],
        &["-G", "-Y", "-x", "h"],
        &["-G", "-a", "-A", "h"],
        &["-G", "-A", "-a", "h"],
        &["-G", "-k", "-K", "h"],
        &["-G", "-K", "-k", "h"],
        &["-G", "-o", "Port=1", "-p", "2", "h"],
        &["-G", "-p", "2", "-o", "Port=1", "h"],
        &["-G", "-p", "2", "-p", "3", "h"],
        &["-G", "-l", "a", "-o", "User=b", "h"],
        &["-G", "-o", "User=b", "-l", "a", "h"],
        &["-G", "-t", "h"],
        &["-G", "-tt", "h"],
        &["-G", "-T", "-t", "h"],
        &["-G", "-t", "-T", "h"],
        &["-G", "-N", "-t", "h"],
        &["-G", "-M", "h"],
        &["-G", "-MM", "h"],
        &["-G", "-MMM", "h"],
        &["-G", "-v", "h"],
        &["-G", "-vvvvv", "h"],
        &["-G", "-q", "h"],
        &["-G", "-q", "-v", "h"],
        &["-G", "-v", "-q", "-v", "h"],
        &["-G", "-vo", "LogLevel=error", "h"],
        &["-G", "-o", "LogLevel=error", "-v", "h"],
        &["-G", "-S", "a", "-S", "b", "h"],
        &["-G", "-P", "a", "-P", "b", "h"],
        &["-G", "-P", "a", "-o", "Tag=b", "h"],
        &["-G", "-I", "a.so", "-I", "b.so", "h"],
        &["-G", "-b", "1.2.3.4", "-B", "eth0", "-b", "5.6.7.8", "h"],
    ] {
        h.args(args);
    }
}

#[test]
fn options_after_destination() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh);
    for args in [
        &["-G", "h", "-p", "5"][..],
        &["h", "-G", "-4"],
        &["-G", "h", "-l", "bob", "ls", "-l", "alice"],
        &["-G", "h", "-o", "Port=7", "-p", "8"],
        &["-G", "h", "ls", "-p", "5"],
        &["-G", "h", "-v", "--", "-l", "bob"],
        &["-G", "--", "h", "-l", "bob"],
        &["-G", "-o", "--", "h", "-l", "bob"],
        &["-G", "h", "--"],
        &["-G", "h", "-", "-l", "bob"],
    ] {
        h.args(args);
    }
}

#[test]
fn destinations() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh);
    for args in [
        &["-G", "a@h"][..],
        &["-G", "a@b@h"],
        &["-G", "a@h", "-l", "b"],
        &["-G", "-l", "b", "a@h"],
        &["-G", "ssh://h"],
        &["-G", "ssh://u@h:7"],
        &["-G", "ssh://u;fp=x@h"],
        &["-G", "ssh://[::1]:7"],
        &["-G", "-p", "3", "-l", "x", "ssh://u@h:7"],
        &["-G", "HOST.Example"],
        &["-G", "::1"],
        &["-G", "h:22"],
        // Errors.
        &["-G", "@h"],
        &["-G", "u@"],
        &["-G", "ssh://h/path"],
        &["-G", "ssh://h:0"],
        &["-G", "h;rm"],
        &["-G", "-l", "a b", "h"],
        &["-G", "-l", "-x", "h"],
        &["-G"],
        &[],
    ] {
        h.args(args);
    }
}

#[test]
fn option_values() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh);
    for args in [
        &["-G", "-L", "8080:localhost:80", "-L", "/tmp/s:h:22", "h"][..],
        &["-G", "-L", "[::1]:8080:[::2]:80", "-L", "*:1:h:2", "h"],
        &["-G", "-R", "9000", "-R", "[::1]:1:h:2", "-R", "0:/s", "h"],
        &["-G", "-D", "localhost:1080", "-D", "1081", "h"],
        &["-G", "-W", "h:1", "h"],
        &["-G", "-W", "/sock", "h"],
        &["-G", "-w", "1:2", "h"],
        &["-G", "-w", "any", "-o", "Tunnel=ethernet", "h"],
        &["-G", "-J", "a@b:1,c", "h"],
        &["-G", "-J", "none", "h"],
        &["-G", "-J", "ssh://u@j:3", "h"],
        &["-G", "-e", "^A", "h"],
        &["-G", "-e", "^@", "h"],
        &["-G", "-e", "^[", "h"],
        &["-G", "-e", "^_", "h"],
        &["-G", "-e", "none", "h"],
        &["-G", "-e", "~", "h"],
        &["-G", "-e", " ", "h"],
        &["-G", "-e", "\t", "h"],
        &["-G", "-e", "\n", "h"],
        &["-G", "-e", "\r", "h"],
        &["-G", "-e", "\x7f", "h"],
        &["-G", "-c", "aes128-ctr,aes256-ctr", "h"],
        &["-G", "-c", "+aes128-cbc", "h"],
        &["-G", "-c", "^aes128-cbc", "h"],
        &["-G", "-m", "hmac-sha1", "h"],
        &["-G", "-s", "h", "sftp"],
        &["-G", "-f", "h", "true"],
        &["-G", "-n", "-C", "-g", "h"],
        &["-G", "-O", "check", "h"],
        &["-G", "-2", "h"],
        &["-G", "-y", "h"],
        &["-G", "-Z", "h"],
    ] {
        h.args(args);
    }
}

#[test]
fn option_errors() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh);
    for args in [
        &["-G", "-1", "h"][..],
        &["-G", "-h", "h"],
        &["-G", "--port", "1", "h"],
        &["-G", "h", "-p"],
        &["-G", "-p", "0", "h"],
        &["-G", "-p", "x", "h"],
        &["-G", "-p", "70000", "h"],
        &["-G", "-p=22", "h"],
        &["-G", "-e", "ab", "h"],
        &["-G", "-e", "^?", "h"],
        &["-G", "-c", "nope", "h"],
        &["-G", "-c", "-aes128-ctr", "h"],
        &["-G", "-c", "", "h"],
        &["-G", "-m", "+hmac-sha1", "h"],
        &["-G", "-L", "bad", "h"],
        &["-G", "-R", "a:b:c:d:e", "h"],
        &["-G", "-D", "a:b:c", "h"],
        &["-G", "-W", "x", "h"],
        &["-G", "-W", "a:1", "-W", "b:2", "h"],
        &["-G", "-w", "x", "h"],
        &["-G", "-J", "a", "-J", "b", "h"],
        &["-G", "-o", "ProxyCommand=nc %h %p", "-J", "a", "h"],
        &["-G", "-J", "a@", "h"],
        &["-G", "-O", "bogus", "h"],
        &["-G", "-W", "a:1", "-O", "check", "h"],
        &["-G", "-O", "check", "-W", "a:1", "h"],
        &["-G", "-O", "check", "-O", "exit", "h"],
        &["-G", "-N", "-s", "h", "x"],
        &["-G", "-s", "-N", "h", "x"],
        &["-G", "-s", "h"],
        &["-G", "-f", "h"],
        &["-G", "-f", "-N", "h"],
        &["-G", "-o", "RemoteCommand=x", "h", "ls"],
        &["-G", "-o", "Bogus=1", "h"],
        &["-G", "-o", "Port", "h"],
        &["-G", "-o", "Port=x", "h"],
        &["-G", "-o", "Host=x", "h"],
        &["-G", "-y", "-E", "log", "h"],
        &["-G", "-E", "/nonexistent/log", "h"],
        &["-G", "-o", "ConnectionAttempts=0", "h"],
        &["-V"],
        &["-G", "h", "-V"],
        &["-V", "-h"],
        &["-h", "-V"],
    ] {
        h.args(args);
    }
}

#[test]
fn identity_files() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh);
    let setup = |dir: &Path| fs::write(dir.join("id"), "").unwrap();
    for args in [
        &["-G", "-i", "id", "h"][..],
        &["-G", "-i", "missing", "h"],
        &[
            "-G",
            "-i",
            "id",
            "-i",
            "id",
            "-o",
            "IdentityFile=other",
            "h",
        ],
        &["-G", "-o", "IdentityFile=%d/x_%h", "h"],
        &[
            "-G",
            "-o",
            "CertificateFile=c",
            "-o",
            "CertificateFile=c",
            "h",
        ],
    ] {
        let mut full = vec!["-F", "none"];
        full.extend_from_slice(args);
        h.assert_same(&h.ssh.case(full).setup(setup).run());
    }
}

#[test]
fn host_blocks() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh);
    let config = "\
Port 2000
Host *.example !bad.example
  User example
  Port 3000
Host h* \"quoted host\"
  Hostname real-%h.test
  ForwardAgent yes
Host H1
  User upper
Host *
  User fallback
  Compression yes
  LocalForward 1 h:2
  RemoteForward 3 h:4
  DynamicForward 5
  SendEnv LANG LC_*
  SendEnv -LC_ALL
  SetEnv A=1 \"B=two words\"
";
    for host in [
        "a.example",
        "bad.example",
        "h1",
        "H1",
        "quoted host",
        "other",
        "BAD.EXAMPLE",
    ] {
        h.config(config, &[host]);
        h.config(config, &["-p", "1", "-o", "User=cmd", host]);
    }
}

#[test]
fn match_blocks() {
    let openssh = require_openssh!();
    if !recent(&openssh) {
        return;
    }
    let h = Harness::new(&openssh);
    let config = "\
Match host a,b !user root
  Port 1001
Match originalhost alias
  Hostname target
Match host target
  Port 1002
Match user bob
  Compression yes
Match localuser nobody-at-all
  Port 1003
Match tagged t1
  Port 1004
Match command \"ls *\"
  Port 1005
Match sessiontype subsystem
  Port 1006
Match exec \"test -f marker\"
  Port 1007
Match exec \"exit 1\"
  Port 1008
Match version OpenSSH_*
  ServerAliveInterval 30
Match canonical
  Port 1009
Match final
  User final
Match all
  User everyone
";
    let files = [("marker", "")];
    for args in [
        &["a"][..],
        &["A"],
        &["alias"],
        &["target"],
        &["bob@x"],
        &["-l", "bob", "x"],
        &["-P", "t1", "x"],
        &["x", "ls", "-l"],
        &["-s", "x", "sftp"],
        &["x"],
    ] {
        h.config_with(config, args, &files, &[]);
        h.config(config, args);
    }
    // Errors in Match lines.
    for bad in [
        "Match\n",
        "Match nonsense x\n",
        "Match host\n",
        "Match all host x\n",
        "Match host x all\n",
        "Match exec\n",
    ] {
        h.config(bad, &["x"]);
    }
}

#[test]
fn includes_and_tokens() {
    let openssh = require_openssh!();
    let h = Harness::new(&openssh);
    let config = "\
Include conf.d/*.conf ${INCLUDE_ME}
Host *
  ControlPath /tmp/%C-%h-%p-%r-%n-%%
  IdentityFile ~/.ssh/id_%h_%r
  UserKnownHostsFile ~/kh/%k %d/kh2
  RemoteCommand echo %h %p %r %n
  ProxyCommand nc %h %p
  LocalCommand echo %C
  User ${TEST_USER}
";
    let files = [
        ("conf.d/a.conf", "Host first\n  Port 4001\n"),
        (
            "conf.d/b.conf",
            "Host first second\n  Port 4002\n  User b\n",
        ),
        ("extra", "Host *\n  ConnectTimeout 9\n"),
    ];
    let env = [("INCLUDE_ME", "extra"), ("TEST_USER", "from_env")];
    for args in [&["first"][..], &["second"], &["-l", "cli", "other"]] {
        h.config_with(config, args, &files, &env);
    }
    // A missing variable in User is an error, an unmatched include glob
    // is not.
    h.config_with(config, &["x"], &files, &[("INCLUDE_ME", "nothing*")]);
}

#[test]
fn values_and_errors() {
    let openssh = require_openssh!();
    if !recent(&openssh) {
        return;
    }
    let h = Harness::new(&openssh);
    for config in [
        // First value wins; `=` and quoting.
        "Port=10\nPort 20\nUser \"quoted user\"\n",
        "Port = 10\n\"User\" x\nHostname=h # comment\n",
        "IgnoreUnknown Foo*\nFooBar yes\n",
        "FooBar yes\nIgnoreUnknown Foo*\n",
        "Ciphers +aes128-cbc\nMACs -hmac-sha1*\n",
        "KexAlgorithms ^curve25519-sha256\nHostKeyAlgorithms ssh-ed25519*\n",
        "PubkeyAcceptedAlgorithms -ssh-rsa*\nCASignatureAlgorithms ssh-ed25519\n",
        "ProxyJump u@j1:22,j2\n",
        "ProxyJump none\nProxyCommand nc %h %p\n",
        "ProxyCommand none\nProxyJump j\n",
        "ServerAliveInterval 1m\nConnectTimeout 1h\nRekeyLimit 1G 1h\n",
        "RekeyLimit default none\nChannelTimeout session=1m *=5s\n",
        "ObscureKeystrokeTiming interval:40\nRequiredRSASize 2048\n",
        "IPQoS af21 cs1\nEscapeChar ^B\nTunnelDevice 3:any\n",
        "ControlMaster autoask\nControlPersist 10m\n",
        "ControlPersist yes\nControlPath ~/.ssh/cm-%C\n",
        "AddKeysToAgent confirm 5m\nForwardAgent ~/agent.sock\n",
        "StrictHostKeyChecking accept-new\nUpdateHostKeys ask\n",
        "PubkeyAuthentication host-bound\nCanonicalizeHostname no\n",
        // With permitted CNAMEs OpenSSH looks the host up unless it goes
        // through a proxy (DNS isn't implemented yet).
        "CanonicalDomains a.test b.test\nCanonicalizePermittedCNAMEs *.a:*.b,*.c\n\
         ProxyCommand nc %h %p\n",
        "GlobalKnownHostsFile none\nUserKnownHostsFile none\n",
        "PermitRemoteOpen h:1 [::1]:2 *:*\nStreamLocalBindMask 0177\n",
        "LogVerbose kex.c:*:1000\nLogLevel debug2\nSyslogFacility local3\n",
        "RevokedHostKeys ~/revoked\nVersionAddendum hello %h\n",
        "WarnWeakCrypto no-pq-kex\nSessionType none\n",
        "BindAddress 127.0.0.1\nBindInterface lo\nAddressFamily inet6\n",
        "XAuthLocation /opt/xauth\nForwardX11Timeout 1h\n",
        // Deprecated and unsupported keywords.
        "Protocol 2\nUseRoaming no\nCipher des\nRSAAuthentication yes\n",
        "UsePrivilegedPort yes\nCompressionLevel 6\n",
        // Errors.
        "Port 0\n",
        "Port x\n",
        "Bogus yes\n",
        "Compression maybe\n",
        "Ciphers nope\n",
        "Ciphers\n",
        "EscapeChar xy\n",
        "LocalForward 1\n",
        "DynamicForward a:b:c\n",
        "Host\n",
        "User \"unterminated\n",
        "ConnectionAttempts 0\n",
        "UserKnownHostsFile none other\n",
        "ProxyJump a@\n",
        "IdentityFile\n",
        "Port 1 2\n",
    ] {
        h.config(config, &["h"]);
    }
}
