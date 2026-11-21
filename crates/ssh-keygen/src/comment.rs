//! `ssh-keygen -c [-a rounds] [-C comment] [-f file] [-P passphrase]`:
//! change a private key's comment (and rewrite its `.pub` file).

use sshutils_core::{keyfile, tty};

use crate::args::Args;
use crate::common;
use crate::error::{Error, Result};
use crate::save::{self, Encryption};

pub fn run(args: &Args) -> Result<()> {
    let encryption = Encryption::from_args(args)?;
    let path = common::existing_key_file(args)?;
    common::require_exists(&path)?;

    let (mut key, passphrase) =
        common::load_private_key(&path, args.passphrase.as_deref(), "Enter passphrase: ").map_err(
            |e| {
                Error::fatal(format!(
                    "Cannot load private key \"{}\": {e}",
                    path.display()
                ))
            },
        )?;
    let old_comment = key.comment().as_str_lossy().to_string();
    if common::has_comment_field(&path) {
        println!("Old comment: {old_comment}");
    } else {
        println!("No existing comment");
    }

    let new_comment = match &args.comment {
        Some(comment) => comment.clone(),
        None => tty::prompt_line("New comment: ").map_err(|_| Error::Exit(1))?,
    };
    if new_comment == old_comment && common::has_comment_field(&path) {
        println!("No change to comment");
        return Ok(());
    }

    key.set_comment(new_comment.as_str());
    save::save_private(&key, &path, &passphrase, &encryption)?;
    save::save_public(&key, &keyfile::public_path(&path))?;
    if new_comment.is_empty() {
        println!("Comment removed");
    } else {
        println!("Comment '{new_comment}' applied");
    }
    Ok(())
}
