# sshutils

> [!WARNING]
> **This project is an early draft and does not work yet.** Nothing here is
> ready for use, and it has not been reviewed for security. Keep using
> [OpenSSH](https://www.openssh.com/) for anything real.

Rust implementations of the OpenSSH tools (`ssh`, `ssh-keygen`, `ssh-agent`,
`ssh-add`, `scp`, `sftp`, …), built on
[`russh`](https://github.com/warp-tech/russh).

## Goals

- **Drop-in compatible with OpenSSH.** Same flags, same behaviour, same exit
  codes, same config and key files, same machine-readable output. Existing
  scripts, `~/.ssh` directories and muscle memory should keep working.
  Error message wording may differ.
- **Permissively licensed.** The project and its dependencies use permissive
  licences (MIT, Apache-2.0, BSD, ISC), not GPL.
- **Built in Rust, on `russh`.** The SSH protocol comes from `russh`; this
  project provides the tools around it.

## Planned tools

| Tool | Status |
|---|---|
| `ssh-keygen` | planned |
| `ssh-agent`, `ssh-add` | planned |
| `ssh`, `ssh-keyscan`, `ssh-copy-id` | planned |
| `scp`, `sftp`, `sftp-server` | planned |
| hardware token (FIDO / PKCS#11) support | planned, later |
| `sshd` | undecided |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
