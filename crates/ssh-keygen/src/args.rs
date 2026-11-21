//! `ssh-keygen` command line.
//!
//! All of OpenSSH's options are declared here, including those for modes we
//! don't implement yet, so that any valid OpenSSH command line parses.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, Parser};
use sshutils_core::cli::Usage;

pub const USAGE: Usage = Usage {
    exit_code: 1,
    text: "\
ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]
                  [-m format] [-N new_passphrase] [-O option]
                  [-t ecdsa|ecdsa-sk|ed25519|ed25519-sk|rsa]
                  [-w provider] [-Z cipher]
       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]
                   [-P old_passphrase] [-Z cipher]
       ssh-keygen -i [-f input_keyfile] [-m key_format]
       ssh-keygen -e [-f input_keyfile] [-m key_format]
       ssh-keygen -y [-f input_keyfile]
       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]
       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]
       ssh-keygen -B [-f input_keyfile]
       ssh-keygen -D pkcs11
       ssh-keygen -F hostname [-lv] [-f known_hosts_file]
       ssh-keygen -H [-f known_hosts_file]
       ssh-keygen -K [-a rounds] [-w provider]
       ssh-keygen -R hostname [-f known_hosts_file]
       ssh-keygen -r hostname [-g] [-f input_keyfile]
       ssh-keygen -M generate [-O option] output_file
       ssh-keygen -M screen [-f input_file] [-O option] output_file
       ssh-keygen -I certificate_identity -s ca_key [-hU] [-D pkcs11_provider]
                  [-n principals] [-O option] [-V validity_interval]
                  [-z serial_number] file ...
       ssh-keygen -L [-f input_keyfile]
       ssh-keygen -A [-a rounds] [-f prefix_path]
       ssh-keygen -k -f krl_file [-u] [-s ca_public] [-z version_number]
                  file ...
       ssh-keygen -Q [-l] -f krl_file [file ...]
       ssh-keygen -Y find-principals -s signature_file -f allowed_signers_file
       ssh-keygen -Y match-principals -I signer_identity -f allowed_signers_file
       ssh-keygen -Y check-novalidate -n namespace -s signature_file
       ssh-keygen -Y sign -f key_file -n namespace file [-O option] ...
       ssh-keygen -Y verify -f allowed_signers_file -I signer_identity
                  -n namespace -s signature_file [-r krl_file] [-O option]",
};

#[derive(Parser, Debug, Default)]
#[command(name = "ssh-keygen")]
pub struct Args {
    // Modes.
    /// Generate host keys of all default types.
    #[arg(short = 'A')]
    pub all_host_keys: bool,
    /// Show the bubblebabble digest of a key.
    #[arg(short = 'B')]
    pub bubblebabble: bool,
    /// Change the comment of a key.
    #[arg(short = 'c')]
    pub change_comment: bool,
    /// Export a key to another format.
    #[arg(short = 'e')]
    pub export: bool,
    /// Search a known_hosts file for a host.
    #[arg(short = 'F', value_name = "hostname")]
    pub find_host: Option<String>,
    /// Hash a known_hosts file.
    #[arg(short = 'H')]
    pub hash_known_hosts: bool,
    /// Import a key from another format.
    #[arg(short = 'i')]
    pub import: bool,
    /// Download resident keys from a FIDO authenticator.
    #[arg(short = 'K')]
    pub download_resident: bool,
    /// Manage a key revocation list.
    #[arg(short = 'k')]
    pub krl: bool,
    /// Print the contents of a certificate.
    #[arg(short = 'L')]
    pub show_certificate: bool,
    /// Show the fingerprint of a key.
    #[arg(short = 'l')]
    pub fingerprint: bool,
    /// Moduli generation or screening.
    #[arg(short = 'M', value_name = "generate|screen")]
    pub moduli: Option<String>,
    /// Change the passphrase of a key.
    #[arg(short = 'p')]
    pub change_passphrase: bool,
    /// Test keys against a key revocation list.
    #[arg(short = 'Q')]
    pub query_krl: bool,
    /// Remove a host from a known_hosts file.
    #[arg(short = 'R', value_name = "hostname")]
    pub remove_host: Option<String>,
    /// Print an SSHFP DNS record.
    #[arg(short = 'r', value_name = "hostname")]
    pub sshfp: Option<String>,
    /// Signature operations.
    #[arg(short = 'Y', value_name = "operation")]
    pub signature: Option<String>,
    /// Print the public key of a private key.
    #[arg(short = 'y')]
    pub print_public: bool,

    // Modifiers.
    /// KDF rounds for encrypted private keys.
    #[arg(short = 'a', value_name = "rounds")]
    pub rounds: Option<String>,
    /// Key size in bits.
    #[arg(short = 'b', value_name = "bits")]
    pub bits: Option<String>,
    /// Comment.
    #[arg(short = 'C', value_name = "comment")]
    pub comment: Option<String>,
    /// PKCS#11 provider.
    #[arg(short = 'D', value_name = "pkcs11")]
    pub pkcs11: Option<String>,
    /// Fingerprint hash algorithm.
    #[arg(short = 'E', value_name = "fingerprint_hash")]
    pub fingerprint_hash: Option<String>,
    /// Key file.
    #[arg(short = 'f', value_name = "filename")]
    pub file: Option<PathBuf>,
    /// Obsolete; accepted and ignored, as by OpenSSH.
    #[arg(short = 'o', hide = true)]
    pub obsolete_new_format: bool,
    /// Accepted by OpenSSH's option parser; treated like `-i`.
    #[arg(short = 'X', hide = true)]
    pub import_legacy: bool,
    /// Generic DNS record format (with `-r`).
    #[arg(short = 'g')]
    pub generic_dns: bool,
    /// Create a host certificate.
    #[arg(short = 'h')]
    pub host_certificate: bool,
    /// Certificate identity or signer identity.
    #[arg(short = 'I', value_name = "identity")]
    pub identity: Option<String>,
    /// Key format for import/export.
    #[arg(short = 'm', value_name = "format")]
    pub format: Option<String>,
    /// New passphrase.
    #[arg(short = 'N', value_name = "new_passphrase")]
    pub new_passphrase: Option<String>,
    /// Principals or namespace.
    #[arg(short = 'n', value_name = "principals")]
    pub principals: Option<String>,
    /// Mode-specific options; may be given several times.
    #[arg(short = 'O', value_name = "option")]
    pub options: Vec<String>,
    /// Old passphrase.
    #[arg(short = 'P', value_name = "passphrase")]
    pub passphrase: Option<String>,
    /// Quiet.
    #[arg(short = 'q')]
    pub quiet: bool,
    /// CA key or signature file.
    #[arg(short = 's', value_name = "ca_key")]
    pub ca_key: Option<PathBuf>,
    /// Key type.
    #[arg(short = 't', value_name = "type")]
    pub key_type: Option<String>,
    /// Use a CA key held in ssh-agent.
    #[arg(short = 'U')]
    pub ca_in_agent: bool,
    /// Update a key revocation list instead of replacing it.
    #[arg(short = 'u')]
    pub update_krl: bool,
    /// Certificate validity interval.
    #[arg(short = 'V', value_name = "validity_interval")]
    pub validity: Option<String>,
    /// Verbose; may be given several times.
    #[arg(short = 'v', action = ArgAction::Count)]
    pub verbose: u8,
    /// FIDO security key provider library.
    #[arg(short = 'w', value_name = "provider")]
    pub provider: Option<String>,
    /// Cipher for encrypted private keys.
    #[arg(short = 'Z', value_name = "cipher")]
    pub cipher: Option<String>,
    /// Serial number or KRL version.
    #[arg(short = 'z', value_name = "serial_number")]
    pub serial: Option<String>,

    /// Operands (files for certificate, KRL and signature modes).
    pub files: Vec<OsString>,
}

/// The operation selected by the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Generate,
    Fingerprint,
    PrintPublic,
    ChangePassphrase,
    ChangeComment,
    /// A mode that isn't implemented yet, named by its option letter.
    Unimplemented(char),
}

impl Args {
    /// Pick the operation. When several mode options are given, OpenSSH
    /// checks them in a fixed order and the first one wins. This order is
    /// approximate; each mode's position must be verified against OpenSSH
    /// when that mode is implemented.
    pub fn mode(&self) -> Mode {
        use Mode::{ChangeComment, ChangePassphrase, Fingerprint, PrintPublic, Unimplemented};
        let modes = [
            (self.signature.is_some(), Unimplemented('Y')),
            (self.moduli.is_some(), Unimplemented('M')),
            (self.krl, Unimplemented('k')),
            (self.query_krl, Unimplemented('Q')),
            // `-F host -l` searches known_hosts and prints fingerprints.
            (
                self.find_host.is_some() || self.remove_host.is_some(),
                Unimplemented('F'),
            ),
            (
                self.identity.is_some() && self.ca_key.is_some(),
                Unimplemented('s'),
            ),
            (self.show_certificate, Unimplemented('L')),
            (self.fingerprint, Fingerprint),
            (self.change_passphrase, ChangePassphrase),
            (self.change_comment, ChangeComment),
            (self.export, Unimplemented('e')),
            (self.import || self.import_legacy, Unimplemented('i')),
            (self.print_public, PrintPublic),
            (self.bubblebabble, Unimplemented('B')),
            (self.sshfp.is_some(), Unimplemented('r')),
            (self.hash_known_hosts, Unimplemented('H')),
            (self.pkcs11.is_some(), Unimplemented('D')),
            (self.download_resident, Unimplemented('K')),
            (self.all_host_keys, Unimplemented('A')),
        ];
        modes
            .into_iter()
            .find(|(selected, _)| *selected)
            .map_or(Mode::Generate, |(_, mode)| mode)
    }
}
