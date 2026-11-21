//! `ssh-agent` command line. All of OpenSSH's options are accepted.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, Parser};
use sshutils_core::cli::Usage;

pub const USAGE: Usage = Usage {
    exit_code: 1,
    text: "\
ssh-agent [-c | -s] [-DdTU] [-a bind_address] [-E fingerprint_hash]
                 [-O option] [-P allowed_providers] [-t life]
       ssh-agent [-TU] [-a bind_address] [-E fingerprint_hash] [-O option]
                 [-P allowed_providers] [-t life] command [arg ...]
       ssh-agent [-c | -s] -k
       ssh-agent -u
       ssh-agent -V",
};

#[derive(Parser, Debug, Default)]
#[command(name = "ssh-agent")]
pub struct Args {
    /// Socket to listen on.
    #[arg(short = 'a', value_name = "bind_address")]
    pub bind_address: Option<PathBuf>,
    /// Print C-shell commands.
    #[arg(short = 'c')]
    pub csh: bool,
    /// Foreground mode.
    #[arg(short = 'D')]
    pub foreground: bool,
    /// Debug mode (foreground, debug output on stderr).
    #[arg(short = 'd')]
    pub debug: bool,
    /// Fingerprint hash for debug output.
    #[arg(short = 'E', value_name = "fingerprint_hash")]
    pub fingerprint_hash: Option<String>,
    /// Kill the agent named by SSH_AGENT_PID.
    #[arg(short = 'k')]
    pub kill: bool,
    /// Agent options (allow-remote-pkcs11, no-restrict-websafe,
    /// websafe-allow=...).
    #[arg(short = 'O', value_name = "option")]
    pub options: Vec<String>,
    /// Allowed PKCS#11 and FIDO provider libraries.
    #[arg(short = 'P', value_name = "allowed_providers")]
    pub allowed_providers: Option<String>,
    /// Print Bourne shell commands.
    #[arg(short = 's')]
    pub sh: bool,
    /// Bind in a temporary directory instead of ~/.ssh/agent.
    #[arg(short = 'T')]
    pub temporary: bool,
    /// Default lifetime of added keys.
    #[arg(short = 't', value_name = "life")]
    pub lifetime: Option<String>,
    /// Don't clean up stale sockets.
    #[arg(short = 'U')]
    pub no_cleanup: bool,
    /// Only clean up stale sockets (twice: regardless of host name).
    #[arg(short = 'u', action = ArgAction::Count)]
    pub cleanup_only: u8,
    /// Print the version and exit.
    #[arg(short = 'V')]
    pub version: bool,

    /// Command to run with the agent's environment.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<OsString>,
}
