//! `ssh-keygen -y [-P passphrase] [-f file]`: print a private key's public
//! key.

use crate::args::Args;
use crate::common;
use crate::error::{Error, Result};

pub fn run(args: &Args) -> Result<()> {
    let path = common::existing_key_file(args)?;
    common::require_exists(&path)?;

    let prompt = format!("Enter passphrase for \"{}\": ", path.display());
    let (key, _) = common::load_private_key(&path, args.passphrase.as_deref(), &prompt)
        .map_err(|e| Error::fatal(format!("Load key \"{}\": {e}", path.display())))?;

    let line = key
        .public_key()
        .to_openssh()
        .map_err(|e| Error::fatal(format!("encoding public key: {e}")))?;
    println!("{line}");
    Ok(())
}
