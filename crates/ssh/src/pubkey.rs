//! The `publickey` method, like OpenSSH's `userauth_pubkey`: each key is
//! offered once (until a partial success), and the private key is only
//! loaded, asking for its passphrase, when the server accepts the offer.
//! A key whose public half can't be read without the private key is
//! loaded first.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use russh::client::AuthResult;
use russh::keys::agent::AgentIdentity;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use sshutils_config::Options;
use sshutils_core::keyfile::{self, LoadError};

use crate::hostkeys::truncate;
use crate::identity::{self, Identities, Identity, Public};
use crate::log;
use crate::transport::Transport;

/// The state of the method during one authentication.
pub struct Pubkey<'a> {
    options: &'a Options,
    identities: &'a Identities,
    /// The keys to try, in turn; prepared on first use.
    keys: Option<Vec<Identity>>,
}

/// What an attempt did.
pub enum Attempt {
    /// A request was sent; this is the reply.
    Replied(AuthResult),
    /// Nothing (more) to send.
    Nothing,
    /// The connection is gone.
    Closed,
}

impl<'a> Pubkey<'a> {
    pub fn new(options: &'a Options, identities: &'a Identities) -> Pubkey<'a> {
        Pubkey {
            options,
            identities,
            keys: None,
        }
    }

    /// After a partial success every key may be tried again.
    pub fn reset(&mut self) {
        for id in self.keys.iter_mut().flatten() {
            id.tried = false;
        }
    }

    /// Offer the next key, like `userauth_pubkey`.
    pub async fn attempt(&mut self, transport: &mut Transport, user: &str) -> Attempt {
        let server_sig_algs: Option<Vec<String>> = match transport.handle.server_sig_algs().await {
            Ok(algs) => algs.map(|algs| algs.iter().map(|a| a.as_str().to_string()).collect()),
            Err(_) => return Attempt::Closed,
        };
        let options = self.options;
        let keys = self.keys.get_or_insert_with(|| {
            identity::prepare(self.identities, options, server_sig_algs.as_deref())
        });
        loop {
            let Some(first) = keys.first_mut() else {
                return Attempt::Nothing;
            };
            if first.tried {
                return Attempt::Nothing;
            }
            first.tried = true;
            // To the end of the queue.
            keys.rotate_left(1);
            let id = keys.last().cloned().expect("not empty");
            let result = match &id.key {
                Some(key) => {
                    log::debug(&format!("Offering public key: {}", id.describe(options)));
                    let Some(algorithm) =
                        identity::signature_algorithm(key, options, server_sig_algs.as_deref())
                    else {
                        log::debug("send_pubkey_test: no mutual signature algorithm");
                        continue;
                    };
                    let hash = hash_alg(&algorithm);
                    let mut signer = FileSigner {
                        options,
                        id: &id,
                        signing: signing_identity(&id, keys),
                    };
                    let reply = match key {
                        Public::Key(key) => {
                            transport
                                .handle
                                .authenticate_publickey_with(user, key.clone(), hash, &mut signer)
                                .await
                        }
                        Public::Certificate(cert) => {
                            transport
                                .handle
                                .authenticate_certificate_with(
                                    user,
                                    (**cert).clone(),
                                    hash,
                                    &mut signer,
                                )
                                .await
                        }
                    };
                    match reply {
                        Ok(reply) => Ok(reply),
                        Err(SignError::Closed) => return Attempt::Closed,
                        // Accepted but not signed: the next key.
                        Err(SignError::NoKey) => continue,
                    }
                }
                None => {
                    log::debug(&format!("Trying private key: {}", id.filename));
                    let Some(private) = load_private(&id.filename, id.user_provided, options)
                    else {
                        continue;
                    };
                    let public = Public::Key(private.public_key().clone());
                    let Some(algorithm) =
                        identity::signature_algorithm(&public, options, server_sig_algs.as_deref())
                    else {
                        log::error("sign_and_send_pubkey: no mutual signature supported");
                        continue;
                    };
                    // OpenSSH sends the signed request at once; russh
                    // offers the key first, which the server can't tell
                    // apart.
                    let key = PrivateKeyWithHashAlg::new(Arc::new(private), hash_alg(&algorithm));
                    transport.handle.authenticate_publickey(user, key).await
                }
            };
            return match result {
                Ok(reply) => Attempt::Replied(reply),
                Err(_) => Attempt::Closed,
            };
        }
    }
}

/// The hash for an RSA signature algorithm (`rsa-sha2-512`, ...).
fn hash_alg(algorithm: &str) -> Option<HashAlg> {
    if algorithm.starts_with("rsa-sha2-512") {
        Some(HashAlg::Sha512)
    } else if algorithm.starts_with("rsa-sha2-256") {
        Some(HashAlg::Sha256)
    } else {
        None
    }
}

/// Which identity's file holds the private key for `id`: for a
/// certificate, a plain key of the same key, or else a key file of the
/// same name without a public key (like OpenSSH's `sign_and_send_pubkey`).
fn signing_identity(id: &Identity, keys: &[Identity]) -> Identity {
    let Some(Public::Certificate(cert)) = &id.key else {
        return id.clone();
    };
    let same_key = keys.iter().find(|other| {
        other
            .key
            .as_ref()
            .is_some_and(|key| !key.is_certificate() && key.key_data() == cert.public_key())
    });
    if let Some(other) = same_key {
        log::debug2(&format!(
            "sign_and_send_pubkey: using private key \"{}\" for certificate",
            other.filename
        ));
        return other.clone();
    }
    let same_name = keys.iter().find(|other| {
        other.key.is_none()
            && (other.filename == id.filename
                || [".pub", "-cert.pub"].iter().any(|suffix| {
                    id.filename.strip_suffix(suffix) == Some(other.filename.as_str())
                }))
    });
    if let Some(other) = same_name {
        log::debug2(&format!(
            "sign_and_send_pubkey: using private key \"{}\" for certificate",
            other.filename
        ));
        return other.clone();
    }
    log::debug(&format!(
        "sign_and_send_pubkey: no separate private key for certificate \"{}\"",
        id.filename
    ));
    id.clone()
}

#[derive(Debug)]
enum SignError {
    Closed,
    /// No private key (missing, wrong passphrase, ...).
    NoKey,
}

impl From<russh::SendError> for SignError {
    fn from(_: russh::SendError) -> Self {
        SignError::Closed
    }
}

/// Signs with the private key file, loaded when the server has accepted
/// the offered key.
struct FileSigner<'a> {
    options: &'a Options,
    /// The identity that was offered.
    id: &'a Identity,
    /// The identity whose file holds the private key.
    signing: Identity,
}

impl russh::Signer for FileSigner<'_> {
    type Error = SignError;

    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, SignError> {
        log::debug(&format!(
            "Server accepts key: {}",
            self.id.describe(self.options)
        ));
        let signing = &self.signing;
        let private = load_private(&signing.filename, signing.user_provided, self.options)
            .ok_or(SignError::NoKey)?;
        if let Some(key) = &signing.key
            && key.key_data() != private.public_key().key_data()
        {
            log::error(&format!(
                "identity_sign: private key {} contents do not match public",
                signing.filename
            ));
            return Err(SignError::NoKey);
        }
        let key = PrivateKeyWithHashAlg::new(Arc::new(private), hash_alg);
        let signature = russh::keys::sign_with_hash_alg(&key, &to_sign).map_err(|err| {
            log::error(&format!(
                "sign_and_send_pubkey: signing failed for {} \"{}\": {err}",
                keyfmt_label(&key),
                signing.filename
            ));
            SignError::NoKey
        })?;
        let length = u32::try_from(signature.len()).map_err(|_| SignError::NoKey)?;
        to_sign.extend_from_slice(&length.to_be_bytes());
        to_sign.extend_from_slice(&signature);
        Ok(to_sign)
    }
}

fn keyfmt_label(key: &PrivateKeyWithHashAlg) -> &'static str {
    sshutils_core::keyfmt::type_label(key.public_key().key_data())
}

/// Load a private key, asking for its passphrase as needed, like OpenSSH's
/// `load_identity_file`: first with an empty one, then up to
/// `NumberOfPasswordPrompts` times (never in batch mode); an empty answer
/// gives up.
pub fn load_private(filename: &str, user_provided: bool, options: &Options) -> Option<PrivateKey> {
    let path = Path::new(filename);
    if let Err(err) = fs::metadata(path) {
        let level = if user_provided {
            log::INFO
        } else {
            log::DEBUG3
        };
        log::log(
            level,
            &format!("no such identity: {filename}: {}", crate::io_message(&err)),
        );
        return None;
    }
    let prompt = format!("Enter passphrase for key '{}': ", truncate(filename, 100));
    let prompts = options.number_of_password_prompts.unwrap_or(3).max(0);
    for i in 0..=prompts {
        let passphrase = if i == 0 {
            String::new()
        } else {
            let answer = sshutils_core::tty::ask_terminal_secret(&prompt);
            if answer.is_empty() {
                log::debug2("no passphrase given, try next key");
                return None;
            }
            answer
        };
        match read_private(path, &passphrase) {
            Ok(key) => {
                let public = Public::Key(key.public_key().clone());
                if public.is_rsa()
                    && i64::from(sshutils_core::keyfmt::bits(public.key_data()))
                        < i64::from(options.required_rsa_size.unwrap_or(1024))
                {
                    log::debug(&format!("Skipping key {filename}: Invalid key length"));
                    return None;
                }
                return Some(key);
            }
            Err(LoadError::WrongPassphrase | LoadError::Encrypted) => {
                if options.batch_mode == Some(1) {
                    return None;
                }
                if i != 0 {
                    log::debug2("bad passphrase given, try again...");
                }
            }
            Err(LoadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                log::debug2(&format!(
                    "Load key \"{filename}\": {}",
                    crate::io_message(&err)
                ));
                return None;
            }
            Err(LoadError::Io(err)) => {
                log::error(&format!(
                    "Load key \"{filename}\": {}",
                    crate::io_message(&err)
                ));
                return None;
            }
            Err(err) => {
                log::error(&format!("Load key \"{filename}\": {err}"));
                return None;
            }
        }
    }
    None
}

/// Read and decrypt a private key file, refusing (with OpenSSH's warning)
/// one that others can read.
fn read_private(path: &Path, passphrase: &str) -> Result<PrivateKey, LoadError> {
    if let Some(lines) = keyfile::permissions_warning(path)? {
        for line in lines {
            log::error(&line);
        }
        return Err(LoadError::BadPermissions);
    }
    let text = fs::read_to_string(path).map_err(|err| match err.kind() {
        std::io::ErrorKind::InvalidData => LoadError::InvalidFormat,
        _ => LoadError::Io(err),
    })?;
    keyfile::decode_private(&text, Some(passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes() {
        assert_eq!(hash_alg("rsa-sha2-512"), Some(HashAlg::Sha512));
        assert_eq!(
            hash_alg("rsa-sha2-256-cert-v01@openssh.com"),
            Some(HashAlg::Sha256)
        );
        assert_eq!(hash_alg("ssh-rsa"), None);
        assert_eq!(hash_alg("ssh-ed25519"), None);
    }
}
