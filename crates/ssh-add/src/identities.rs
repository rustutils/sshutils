//! Operations on the agent as a whole: `-l`, `-L`, `-D`, `-x`, `-X`, `-Q`.

use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_key::PublicKey;
use sshutils_core::keyfmt::{self, FingerprintHash};
use sshutils_core::tty;

use crate::Client;
use crate::error::{Error, Result, agent_message};

/// `-l` (fingerprints) or `-L` (public keys).
pub async fn list(client: &mut Client, fingerprints: bool, hash: FingerprintHash) -> Result<()> {
    let identities = client.request_identities().await.map_err(|e| {
        Error::message(
            1,
            format!("error fetching identities: {}", agent_message(&e)),
        )
    })?;
    if identities.is_empty() {
        println!("The agent has no identities.");
        return Err(Error::Exit(1));
    }
    for identity in &identities {
        if fingerprints {
            let (key, suffix) = match identity {
                AgentIdentity::PublicKey { key, .. } => (key.key_data(), ""),
                AgentIdentity::Certificate { certificate, .. } => {
                    (certificate.public_key(), "-CERT")
                }
            };
            println!(
                "{} {} {} ({}{suffix})",
                keyfmt::bits(key),
                keyfmt::fingerprint(key, hash),
                identity.comment(),
                keyfmt::type_label(key),
            );
        } else {
            // The key without its own comment, then the agent's comment
            // (always preceded by a space, as OpenSSH prints it).
            let encoded = match identity {
                AgentIdentity::PublicKey { key, .. } => {
                    PublicKey::new(key.key_data().clone(), "").to_openssh()
                }
                AgentIdentity::Certificate { certificate, .. } => {
                    let mut certificate = certificate.clone();
                    certificate.set_comment("");
                    certificate.to_openssh()
                }
            }
            .map_err(|e| Error::fatal(format!("encoding key: {e}")))?;
            println!("{encoded} {}", identity.comment());
        }
    }
    Ok(())
}

/// `-D`: remove all identities.
pub async fn delete_all(client: &mut Client, quiet: bool) -> Result<()> {
    match client.remove_all_identities().await {
        Ok(()) => {
            if !quiet {
                eprintln!("All identities removed.");
            }
            Ok(())
        }
        Err(_) => Err(Error::message(1, "Failed to remove all identities.")),
    }
}

/// `-x` (lock) or `-X` (unlock).
pub async fn lock(client: &mut Client, lock: bool) -> Result<()> {
    let read = |prompt: &str| {
        tty::read_passphrase(prompt)
            .map_err(|e| Error::message(1, format!("reading password: {e}")))
    };
    let password = read("Enter lock password: ")?;
    if lock {
        let again = read("Again: ")?;
        if again != password {
            return Err(Error::message(1, "Passwords do not match."));
        }
        match client.lock(password.as_bytes()).await {
            Ok(()) => {
                eprintln!("Agent locked.");
                Ok(())
            }
            Err(e) => Err(Error::message(
                1,
                format!("Failed to lock agent: {}", agent_message(&e)),
            )),
        }
    } else {
        match client.unlock(password.as_bytes()).await {
            Ok(()) => {
                eprintln!("Agent unlocked.");
                Ok(())
            }
            Err(e) => Err(Error::message(
                1,
                format!("Failed to unlock agent: {}", agent_message(&e)),
            )),
        }
    }
}

/// `-Q`: list the agent's protocol extensions.
pub async fn query(client: &mut Client) -> Result<()> {
    let extensions = client.query_extensions().await.map_err(|e| {
        Error::message(
            1,
            format!("Unable to query agent extensions: {}", agent_message(&e)),
        )
    })?;
    for extension in extensions {
        println!("{extension}");
    }
    Ok(())
}
