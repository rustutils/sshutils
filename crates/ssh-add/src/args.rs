//! `ssh-add` command line. All of OpenSSH's options are accepted.

use std::path::PathBuf;

use clap::{ArgAction, Parser};
use sshutils_core::cli::Usage;

pub const USAGE: Usage = Usage {
    exit_code: 1,
    text: "\
ssh-add [-CcDdKkLlqvXx] [-E fingerprint_hash] [-H hostkey_file]
               [-h destination_constraint] [-S provider] [-t life]
               [file ...]
       ssh-add -s pkcs11 [-Cv] [certificate ...]
       ssh-add -e pkcs11
       ssh-add -T pubkey ...",
};

#[derive(Parser, Debug, Default)]
#[command(name = "ssh-add")]
pub struct Args {
    /// Process certificates only, skipping plain keys.
    #[arg(short = 'C')]
    pub certificates_only: bool,
    /// Require confirmation for each use of added keys.
    #[arg(short = 'c')]
    pub confirm: bool,
    /// Delete all identities.
    #[arg(short = 'D')]
    pub delete_all: bool,
    /// Delete the given identities.
    #[arg(short = 'd')]
    pub delete: bool,
    /// Fingerprint hash algorithm for -l.
    #[arg(short = 'E', value_name = "fingerprint_hash")]
    pub fingerprint_hash: Option<String>,
    /// Remove keys provided by a PKCS#11 provider.
    #[arg(short = 'e', value_name = "pkcs11")]
    pub remove_pkcs11: Option<String>,
    /// Known hosts files for destination constraints.
    #[arg(short = 'H', value_name = "hostkey_file")]
    pub hostkey_files: Vec<PathBuf>,
    /// Destination constraints.
    #[arg(short = 'h', value_name = "destination_constraint")]
    pub destinations: Vec<String>,
    /// Load resident keys from a FIDO authenticator.
    #[arg(short = 'K')]
    pub resident: bool,
    /// Process plain keys only, skipping certificates.
    #[arg(short = 'k')]
    pub keys_only: bool,
    /// List public keys.
    #[arg(short = 'L', action = ArgAction::Count)]
    pub list_keys: u8,
    /// List fingerprints.
    #[arg(short = 'l', action = ArgAction::Count)]
    pub list_fingerprints: u8,
    /// Obsolete (XMSS maximum signatures); accepted and ignored.
    #[arg(short = 'M', value_name = "maxsign", hide = true)]
    pub max_signatures: Option<String>,
    /// Obsolete (XMSS minimum signatures left); accepted and ignored.
    #[arg(short = 'm', value_name = "minleft", hide = true)]
    pub min_left: Option<String>,
    /// Don't limit certificates' lifetime to their expiry.
    #[arg(short = 'N')]
    pub no_certificate_lifetime: bool,
    /// Query the agent's protocol extensions.
    #[arg(short = 'Q')]
    pub query: bool,
    /// Quiet.
    #[arg(short = 'q')]
    pub quiet: bool,
    /// FIDO security key provider.
    #[arg(short = 'S', value_name = "provider")]
    pub sk_provider: Option<String>,
    /// Add keys provided by a PKCS#11 provider.
    #[arg(short = 's', value_name = "pkcs11")]
    pub add_pkcs11: Option<String>,
    /// Test that the agent can sign with the given public keys.
    #[arg(short = 'T')]
    pub test: bool,
    /// Maximum lifetime of added identities.
    #[arg(short = 't', value_name = "life")]
    pub lifetime: Option<String>,
    /// Verbose; may be given several times.
    #[arg(short = 'v', action = ArgAction::Count)]
    pub verbose: u8,
    /// Unlock the agent.
    #[arg(short = 'X', action = ArgAction::Count)]
    pub unlock: u8,
    /// Lock the agent.
    #[arg(short = 'x', action = ArgAction::Count)]
    pub lock: u8,

    /// Key files.
    pub files: Vec<PathBuf>,
}
