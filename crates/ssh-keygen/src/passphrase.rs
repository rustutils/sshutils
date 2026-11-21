//! `ssh-keygen -p [-a rounds] [-f file] [-N new] [-P old] [-Z cipher]`:
//! change a private key's passphrase.

use sshutils_core::tty;

use crate::args::Args;
use crate::common;
use crate::error::{Error, Result};
use crate::save::{self, Encryption};

pub fn run(args: &Args) -> Result<()> {
    let encryption = Encryption::from_args(args)?;
    let path = common::existing_key_file(args)?;
    common::require_exists(&path)?;

    let (key, _) =
        common::load_private_key(&path, args.passphrase.as_deref(), "Enter old passphrase: ")
            .map_err(|e| Error::fatal(format!("Failed to load key {}: {e}", path.display())))?;
    if common::has_comment_field(&path) {
        println!("Key has comment '{}'", key.comment().as_str_lossy());
    }

    let new_passphrase = match &args.new_passphrase {
        Some(passphrase) => passphrase.clone(),
        None => {
            let read = |prompt: &str| {
                tty::read_passphrase(prompt)
                    .map_err(|e| Error::fatal(format!("reading passphrase: {e}")))
            };
            let first = read("Enter new passphrase (empty for no passphrase): ")?;
            let second = read("Enter same passphrase again: ")?;
            if first != second {
                // Unlike key generation, OpenSSH gives up here.
                println!("Pass phrases do not match.  Try again.");
                return Err(Error::Exit(1));
            }
            first
        }
    };

    save::save_private(&key, &path, &new_passphrase, &encryption)?;
    println!("Your identification has been saved with the new passphrase.");
    Ok(())
}
