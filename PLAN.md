# sshutils plan

Rust reimplementations of the OpenSSH tools, built on
[`russh`](https://github.com/warp-tech/russh), licensed `MIT OR Apache-2.0`.

## Goals

- **Drop-in behavioural compatibility** with OpenSSH: same flags, same
  semantics, same exit codes, same file formats, same config files, same
  machine-readable output.
- **Usable early.** Each phase ends with tools someone can actually use day to
  day.
- **Permissively licensed** throughout, including dependencies.

## Non-goals (for now)

- Byte-identical error messages. Diagnostics on stderr may be worded
  differently.
- GNU-style long options or other CLI extensions beyond what OpenSSH accepts.
- `sshd` — deferred; see [Open questions](#open-questions).

## Compatibility definition

"Compatible" means, in decreasing order of strictness:

| Aspect | Requirement |
|---|---|
| Command-line syntax | Must accept everything OpenSSH accepts, with the same meaning (option clustering, attached/detached values, option order semantics, operand handling). |
| Exit codes | Must match. |
| Files read/written | Must interoperate both ways: keys, `known_hosts` (incl. hashed), `authorized_keys`, `ssh_config`, agent socket protocol. |
| stdout | Must match where scripts may parse it (`ssh-keygen -l/-y/-F`, `ssh -G`, `ssh-keyscan`, `ssh-add -l/-L`, `ssh-agent` env output). |
| Interactive prompts | Same prompts and order of questions, wording may differ slightly. |
| stderr diagnostics | Same *situation* reported (e.g. host key mismatch is fatal), wording free. |

Reference version: **OpenSSH 10.5**. Features OpenSSH removed (e.g. DSA keys, `scp` legacy
protocol as default) follow upstream.

## Licensing

- Project: `MIT OR Apache-2.0` (`LICENSE-MIT`, `LICENSE-APACHE`).
- OpenSSH is BSD/ISC-licensed, so reading its source and man pages for
  reference is fine. Any code ported directly keeps its original copyright
  notice.
- `ssh-copy-id` comes from OpenSSH's `contrib/` with a separate author; we
  write our own from its documented behaviour.
- `cargo-deny` in CI with a license allowlist (MIT, Apache-2.0, BSD-2/3, ISC,
  Zlib, Unicode-3.0, OpenSSL-style for `aws-lc`). Copyleft dependencies (GPL,
  LGPL) are rejected; weak copyleft (MPL-2.0, e.g. Mozilla `authenticator` for
  FIDO) needs an explicit decision.
- Crypto backend: russh's default `aws-lc-rs`; `ring` as an alternative behind
  a feature flag if desired.

## Architecture

```
sshutils/
├── Cargo.toml            workspace
├── crates/
│   ├── sshutils-core/    shared library (split into smaller crates as it grows)
│   ├── sshutils-config/  ssh_config parsing and evaluation (Phase 2)
│   ├── sshutils-testing/ test harness (differential tests, throwaway sshd/agent)
│   ├── ssh-keygen/
│   ├── ssh-add/
│   ├── ssh-agent/
│   ├── ssh/
│   ├── ssh-keyscan/
│   ├── ssh-copy-id/
│   ├── scp/
│   ├── sftp/
│   └── sftp-server/
├── vendor/russh/         our russh fork (git submodule, branch `sshutils`)
└── tests/                cross-tool and interop tests
```

Missing russh functionality is added in the fork, as small self-contained
commits meant to become upstream PRs (built first, proposed afterwards).
russh gets general-purpose protocol support and extension points; OpenSSH's
policy and behaviour stay in sshutils.

### Shared library (`sshutils-core`)

- **CLI helpers** – clap configured for OpenSSH semantics:
  - built-in `-h`/`-V` disabled (`ssh-keygen -h` means host certificate; `ssh
    -V` is custom)
  - `args_override_self(true)` so repeated options don't error
  - `trailing_var_arg` for `ssh host cmd -args`
  - `ArgAction::Count` for `-v`, `Append` for `-o`/`-i`/`-L`…
  - argument order recovered via `ArgMatches::indices_of` where it matters
    (first-wins for config options)
  - errors mapped to OpenSSH's exit codes with a hand-written usage text
- **Paths & identity** – `~/.ssh` from the passwd entry (as OpenSSH does),
  tilde expansion, default comment `user@host`.
- **Prompts** – passphrase from the controlling TTY, `SSH_ASKPASS` /
  `SSH_ASKPASS_REQUIRE`, yes/no confirmations.
- **Key handling** – loading/saving via `russh::keys` / `ssh-key`, fingerprints
  (SHA256, MD5), randomart.
- **Signer abstraction** – everything that authenticates or signs goes through
  a trait, not raw private-key bytes. Implementations: in-memory key,
  agent-held key; later FIDO (`-sk`) and PKCS#11. This is what lets hardware
  tokens be added without redesign.
- **`known_hosts`** – parse, hashed hosts, `@cert-authority`, `@revoked`,
  markers, lookup, add, remove (needed by `ssh`, `ssh-keygen -F/-R/-H`,
  `ssh-keyscan`).
- **`authorized_keys`** – parse incl. options (for `ssh-keygen` now, `sshd`
  later).

`ssh_config` handling lives in its own crate, `sshutils-config`, rather than in
russh: russh's `russh-config` is a small helper (about ten keywords, no
`Match`/`Include`), and `ssh_config` semantics are OpenSSH policy.

## Phases

Each phase ends with: tools installed side-by-side with OpenSSH, golden tests
passing, interop tests passing.

### Phase 0 – Foundation (done)

- Workspace, licenses, CI (build, test, clippy, fmt, `cargo-deny`).
- Test harness for golden tests and a throwaway OpenSSH `sshd` (see Testing).
- `sshutils-core` CLI helpers, paths, prompts, key loading, fingerprints.

### Phase 1 – Keys and agent (done, except the items noted)

Done: `ssh-keygen` generation, `-l`, `-y`, `-p`, `-c`, `-F`, `-R`, `-H`;
`ssh-add` (all but PKCS#11, FIDO and destination constraints); `ssh-agent`
(foreground and background, `-k`, `-u`, command mode, socket activation,
confirmations, hashed lock, peer checks); `SSH_ASKPASS` support. Not done yet:
`ssh-keygen -e`/`-i`/`-B`. Original scope:


- `ssh-keygen`: generate (`-t -b -C -f -N -q -a -Z`), `-l` (`-E`, `-v`), `-y`,
  `-p`, `-c`, `-F`, `-R`, `-H`, `-e`/`-i` (basic formats), `-B` if cheap.
- `ssh-agent`: socket, env output (`-s`/`-c`), `-D`/`-d`, `-k`, `-t`, `-a`,
  lifetime and confirm constraints, locking.
- `ssh-add`: add/list/delete/lock/unlock (`-l -L -d -D -x -X -t -c -E -q`),
  default identities.
- Interop: our `ssh-add` ↔ OpenSSH `ssh-agent` and vice versa.

### Phase 2 – Client

1. **`sshutils-config` and `ssh -G`.** OpenSSH's tokenising rules (quotes,
   `Key=Value`, comments); every keyword of OpenSSH 10.5, including how
   deprecated and unsupported ones are reported; `Host`, all `Match` criteria
   (including `exec`, `canonical`, `final`) and `Include`; first match wins,
   accumulating options (`IdentityFile`, forwards, `SendEnv`); `%` tokens and
   `${VAR}`; OpenSSH's defaults; algorithm-list syntax (`+`, `-`, `^`);
   hostname canonicalization. In the `ssh` binary: the full command line
   (every option mapped onto the config) and `-G`, which prints the resolved
   configuration without connecting and is compared against OpenSSH's across
   many config files and command lines.
2. **Connecting and host keys.** TCP connect (`AddressFamily`,
   `ConnectTimeout`, `BindAddress`), algorithm negotiation from the config,
   `known_hosts` verification with every `StrictHostKeyChecking` mode,
   OpenSSH's prompts and warnings, `HashKnownHosts`, `UpdateHostKeys`,
   `CheckHostIP`; `ssh -Q`.
3. **Authentication.** Methods in `PreferredAuthentications` order; keys from
   files and the agent (`IdentitiesOnly`), certificates (`CertificateFile`),
   `AddKeysToAgent`; password and keyboard-interactive; `BatchMode`; banners;
   agent session binding.
4. **Sessions.** Exec and shell, terminal handling (raw mode, window size),
   `-t`/`-T`, `-n`, `-N`, stdio and the remote exit status, `SendEnv`/`SetEnv`,
   `RemoteCommand`, escape sequences, `-q`/`-v`, `-f`. The test harness gains
   pseudo-terminal support for interactive tests.
5. **Forwarding.** `-L`, `-R`, `-D` (SOCKS4/5), `-W`, Unix socket forwards,
   `ExitOnForwardFailure`, `GatewayPorts`, agent forwarding (`-A`).
6. **`ProxyCommand` and `ProxyJump`** (`-J`, including chains).
7. **`ssh-keyscan` and `ssh-copy-id`.**

Deferred to Phase 4: connection sharing (`ControlMaster`/`-O`), tunnel devices
(`-w`), X11 forwarding, FIDO and PKCS#11 keys, `VerifyHostKeyDNS`,
`KnownHostsCommand`.

### Phase 3 – File transfer

- `sftp-server` (via `russh-sftp`), usable as a subsystem of OpenSSH `sshd`.
- `sftp`: batch mode first (`-b`), then interactive shell.
- `scp` over SFTP (default since OpenSSH 9.0); legacy `-O` protocol afterwards.

### Phase 4 – Hardware tokens and advanced features

- FIDO: `ssh-keygen -t ed25519-sk/ecdsa-sk` (incl. resident keys, `-K`), `ssh`
  and `ssh-agent` signing with `-sk` keys. Pick a FIDO crate after a license
  and maturity review.
- PKCS#11 (`-I`, `ssh-add -s`) — lower priority.
- `ssh`: `ControlMaster`/`ControlPath` multiplexing (OpenSSH's mux protocol, so
  it interoperates), X11 forwarding, tunnel devices (`-w`), `-O` control
  commands.
- `ssh-keygen`: certificates (`-s -I -n -V -z -O`, `-L`), `-Y` signatures, KRLs
  (`-k`, `-Q`), `-A`, moduli (`-M`).

### Phase 5 – `sshd` (decision pending)

- To be decided; see open questions.

## Testing

- **Unit tests** for parsers (`ssh_config`, `known_hosts`, `authorized_keys`,
  CLI).
- **Golden/differential tests**: run our tool and OpenSSH with identical inputs
  in a temp dir, compare exit code, stdout, and resulting files; stderr
  compared loosely. Skipped when OpenSSH isn't installed. Randomness (key
  generation) is tested by cross-checking: keys we generate must be accepted by
  OpenSSH and vice versa.
- **Interop tests**: start OpenSSH `sshd` unprivileged on a random localhost
  port with its own host keys and config (`sshd -D -e -f cfg`), then exercise
  our `ssh`, `scp`, `sftp`, `ssh-keyscan`, `ssh-copy-id` against it. Same for
  agent interop.
- **Fixtures**: keys of every supported type, encrypted and unencrypted, plus
  sample `known_hosts`/`authorized_keys`/`ssh_config` files, generated with
  OpenSSH and checked in.
- Later: fuzzing of the parsers (`cargo fuzz`).

## russh: gaps and status

Fixed or added in the fork (agent work, Phase 1): agent client framing bugs,
key comments and certificates when adding keys, `query`/`remove_certificate`,
typed agent protocol messages (`agent::proto`), and an in-memory agent server
that keeps order, comments and certificates.

The client already covers the protocol side of `ssh` (auth methods including
certificates and pluggable GSSAPI, all channel types, remote forwarding,
keepalives, rekeying, `hostkeys-prove`, agent session binding, connecting
over any stream). To verify early in Phase 2:

- Per-connection host-key algorithm preferences (OpenSSH orders them by
  what's in `known_hosts`; also needed for `ssh-keyscan -t`).
- `server-sig-algs` and RSA SHA-2 negotiation against OpenSSH's `sshd`.
- Algorithm coverage compared to OpenSSH (for `-Q` and the algorithm-list
  syntax).
- `ssh -f`: OpenSSH forks after authentication, while our async runtime is
  running.
- `-sk` key algorithms on the wire (Phase 4).

## Open questions

- **`sshd` design**: mirror OpenSSH's process split (`sshd` → `sshd-session` →
  `sshd-auth`) for packaging-level compatibility, or own privilege separation
  with only CLI/config compatibility? Decide before Phase 5.
- **Binary layout**: separate binaries per tool (current plan) vs. a multicall
  binary with symlinks like uutils.
- **Platforms**: Linux first. When do macOS and Windows come in?
- **FIDO crate choice** and its license.
