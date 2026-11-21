//! `ssh-keygen -y [-P passphrase] [-f file]`: print a private key's public
//! key.

use sshutils_core::keyfile::{self, LoadError};
use sshutils_core::tty;

use crate::args::Args;
use crate::common;
use crate::error::{Error, Result};

pub fn run(args: &Args) -> Result<()> {
    let path = common::existing_key_file(args)?;
    if let Err(e) = std::fs::metadata(&path) {
        return Err(Error::fatal(format!(
            "{}: {}",
            path.display(),
            common::io_message(&e)
        )));
    }

    let key = match keyfile::load_private(&path, None) {
        Err(LoadError::Encrypted) => {
            let passphrase = match &args.passphrase {
                Some(passphrase) => passphrase.clone(),
                None => {
                    tty::read_passphrase(&format!("Enter passphrase for \"{}\": ", path.display()))
                        .map_err(|e| Error::fatal(format!("reading passphrase: {e}")))?
                }
            };
            keyfile::load_private(&path, Some(&passphrase))
        }
        result => result,
    }
    .map_err(|e| Error::fatal(format!("Load key \"{}\": {e}", path.display())))?;

    let line = key
        .public_key()
        .to_openssh()
        .map_err(|e| Error::fatal(format!("encoding public key: {e}")))?;
    println!("{line}");
    Ok(())
}
