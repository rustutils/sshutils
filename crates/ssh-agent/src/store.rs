//! The agent's keys and its answers to protocol requests.
//!
//! Everything here is synchronous; [`crate::server`] handles connections,
//! timers, delays and confirmation prompts around it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::keys::agent::Constraint;
use russh::keys::agent::proto::{
    AddIdentity, ExtensionRequest, Identity, Request, Response, SessionBind, SignRequest,
};
use russh::keys::signature::{Signer, Verifier};
use russh::keys::ssh_key::encoding::Encode;
use russh::keys::ssh_key::private::KeypairData;
use russh::keys::ssh_key::rand_core::Rng;
use russh::keys::ssh_key::{HashAlg, PrivateKey, PublicKey, Signature};
use sshutils_core::keyfmt::{self, FingerprintHash};
use zeroize::Zeroizing;

/// `SSH_AGENT_RSA_SHA2_256` and `SSH_AGENT_RSA_SHA2_512` sign flags.
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

/// Lock passphrase hashing, as in OpenSSH: bcrypt-pbkdf with a random salt.
const LOCK_SALT_SIZE: usize = 16;
const LOCK_HASH_SIZE: usize = 32;
const LOCK_ROUNDS: u32 = 1;

/// Each failed unlock adds this much delay, up to [`MAX_UNLOCK_FAILURES`]
/// times (10 seconds).
const UNLOCK_DELAY_STEP: Duration = Duration::from_millis(100);
const MAX_UNLOCK_FAILURES: u32 = 100;

/// Extensions we answer `query` with, as OpenSSH does.
const EXTENSIONS: &[&str] = &["session-bind@openssh.com"];

/// A key held by the agent.
struct Entry {
    /// Public key blob, or certificate blob for certificate identities.
    blob: Vec<u8>,
    key: Arc<PrivateKey>,
    comment: String,
    confirm: bool,
    expires: Option<Instant>,
}

/// The salted hash of the lock passphrase.
struct Lock {
    salt: [u8; LOCK_SALT_SIZE],
    hash: Zeroizing<[u8; LOCK_HASH_SIZE]>,
}

impl Lock {
    fn new(passphrase: &[u8]) -> Option<Lock> {
        let mut salt = [0u8; LOCK_SALT_SIZE];
        russh::keys::key::safe_rng().fill_bytes(&mut salt);
        let hash = lock_hash(passphrase, &salt)?;
        Some(Lock { salt, hash })
    }

    fn matches(&self, passphrase: &[u8]) -> bool {
        lock_hash(passphrase, &self.salt)
            .is_some_and(|hash| constant_time_eq(hash.as_slice(), self.hash.as_slice()))
    }
}

fn lock_hash(passphrase: &[u8], salt: &[u8]) -> Option<Zeroizing<[u8; LOCK_HASH_SIZE]>> {
    let mut hash = Zeroizing::new([0u8; LOCK_HASH_SIZE]);
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, LOCK_ROUNDS, hash.as_mut_slice()).ok()?;
    Some(hash)
}

/// The agent's state, shared by all connections.
pub struct Store {
    /// Keys in the order they were added; re-adding a key keeps its place.
    entries: Vec<Entry>,
    /// Set while the agent is locked.
    lock: Option<Lock>,
    /// Failed unlock attempts since the last successful one.
    failed_unlocks: u32,
    /// Lifetime for keys added without one (`ssh-agent -t`).
    default_lifetime: Option<u32>,
    /// Hash for fingerprints in confirmation prompts (`ssh-agent -E`).
    fingerprint_hash: FingerprintHash,
}

/// What a connection must do around answering a request.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Followup {
    /// Purge expired keys after this long.
    pub expire_after: Option<Duration>,
    /// Wait this long before answering (after a failed unlock).
    pub delay: Option<Duration>,
}

/// The store's answer to a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Respond(Response, Followup),
    /// The key needs the user's confirmation before signing: ask with
    /// `prompt`, then call [`Store::sign_confirmed`] if allowed.
    Confirm {
        prompt: String,
        request: SignRequest,
    },
}

impl Store {
    pub fn new(default_lifetime: Option<u32>, fingerprint_hash: FingerprintHash) -> Store {
        Store {
            entries: Vec::new(),
            lock: None,
            failed_unlocks: 0,
            default_lifetime,
            fingerprint_hash,
        }
    }

    /// Answer one request.
    pub fn handle(&mut self, request: Request) -> Answer {
        if let Request::Sign(sign) = &request
            && let Some(prompt) = self.confirmation_prompt(sign)
        {
            return Answer::Confirm {
                prompt,
                request: sign.clone(),
            };
        }
        let (response, followup) = self.respond(request);
        Answer::Respond(response, followup)
    }

    /// The prompt for signing with a key that requires confirmation, or
    /// `None` if no confirmation is needed (or possible).
    fn confirmation_prompt(&self, sign: &SignRequest) -> Option<String> {
        if self.lock.is_some() {
            return None;
        }
        let entry = self.find(&sign.key_blob)?;
        if !entry.confirm {
            return None;
        }
        let fingerprint =
            keyfmt::fingerprint(entry.key.public_key().key_data(), self.fingerprint_hash);
        Some(format!(
            "Allow use of key {}?\nKey fingerprint {fingerprint}.",
            entry.comment
        ))
    }

    /// Sign after the user confirmed. The key may have been removed, or the
    /// agent locked, while asking.
    pub fn sign_confirmed(&mut self, request: &SignRequest) -> Response {
        self.remove_expired();
        if self.lock.is_some() {
            return Response::Failure;
        }
        match self.find(&request.key_blob) {
            Some(entry) => sign_response(&entry.key, request),
            None => Response::Failure,
        }
    }

    fn find(&self, blob: &[u8]) -> Option<&Entry> {
        self.entries.iter().find(|e| e.blob == blob)
    }

    fn respond(&mut self, request: Request) -> (Response, Followup) {
        self.remove_expired();
        let locked = self.lock.is_some();
        let mut followup = Followup::default();
        let response = match request {
            // A locked agent lists nothing rather than failing.
            Request::RequestIdentities if locked => Response::Identities(Vec::new()),
            Request::RequestIdentities => Response::Identities(
                self.entries
                    .iter()
                    .map(|entry| Identity {
                        key_blob: entry.blob.clone(),
                        comment: entry.comment.clone(),
                    })
                    .collect(),
            ),
            Request::Sign(sign) if !locked => self.sign(&sign),
            Request::AddIdentity(add) if !locked => {
                let (response, expire_after) = self.add(*add);
                followup.expire_after = expire_after;
                response
            }
            Request::RemoveIdentity { key_blob } if !locked => {
                let before = self.entries.len();
                self.entries.retain(|entry| entry.blob != key_blob);
                success(self.entries.len() < before)
            }
            Request::RemoveAllIdentities if !locked => {
                self.entries.clear();
                Response::Success
            }
            // Like OpenSSH, an empty passphrase can't lock the agent.
            Request::Lock { passphrase } if !locked && !passphrase.is_empty() => {
                match Lock::new(&passphrase) {
                    Some(lock) => {
                        self.lock = Some(lock);
                        Response::Success
                    }
                    None => Response::Failure,
                }
            }
            Request::Unlock { passphrase } if locked && !passphrase.is_empty() => {
                let matches = self
                    .lock
                    .as_ref()
                    .is_some_and(|lock| lock.matches(&passphrase));
                if matches {
                    self.lock = None;
                    self.failed_unlocks = 0;
                } else {
                    self.failed_unlocks = (self.failed_unlocks + 1).min(MAX_UNLOCK_FAILURES);
                    followup.delay = Some(UNLOCK_DELAY_STEP * self.failed_unlocks);
                }
                success(matches)
            }
            Request::Extension(ExtensionRequest::Query) => {
                Response::query_response(EXTENSIONS).unwrap_or(Response::Failure)
            }
            Request::Extension(ExtensionRequest::SessionBind(bind)) => {
                success(session_bind_is_valid(&bind))
            }
            _ => Response::Failure,
        };
        (response, followup)
    }

    /// Remove all keys (SIGUSR1).
    pub fn remove_all(&mut self) {
        self.entries.clear();
    }

    /// Drop keys whose lifetime has passed.
    pub fn remove_expired(&mut self) {
        let now = Instant::now();
        self.entries
            .retain(|entry| entry.expires.is_none_or(|expires| expires > now));
    }

    fn add(&mut self, add: AddIdentity) -> (Response, Option<Duration>) {
        let mut lifetime = None;
        let mut confirm = false;
        for constraint in &add.constraints {
            match constraint {
                Constraint::KeyLifetime { seconds } => {
                    if lifetime.replace(*seconds).is_some() {
                        return (Response::Failure, None);
                    }
                }
                Constraint::Confirm => confirm = true,
                // Destination constraints and FIDO providers aren't
                // supported yet; never accept a key with a constraint we
                // would ignore.
                Constraint::Extensions { .. } => return (Response::Failure, None),
            }
        }
        let lifetime = lifetime.or(self.default_lifetime).filter(|&s| s > 0);

        let blob = match &add.certificate {
            Some(certificate) => certificate.to_bytes(),
            None => add.key.public_key().to_bytes(),
        };
        let Ok(blob) = blob else {
            return (Response::Failure, None);
        };
        let expire_after = lifetime.map(|seconds| Duration::from_secs(u64::from(seconds)));
        let entry = Entry {
            blob,
            comment: add.key.comment().as_str_lossy().to_string(),
            key: Arc::new(add.key),
            confirm,
            expires: expire_after.map(|after| Instant::now() + after),
        };
        match self.entries.iter_mut().find(|e| e.blob == entry.blob) {
            Some(existing) => *existing = entry,
            None => self.entries.push(entry),
        }
        (Response::Success, expire_after)
    }

    fn sign(&self, request: &SignRequest) -> Response {
        match self.find(&request.key_blob) {
            // Keys needing confirmation are handled by `handle`; getting
            // here means asking wasn't possible.
            Some(entry) if !entry.confirm => sign_response(&entry.key, request),
            _ => Response::Failure,
        }
    }
}

fn sign_response(key: &PrivateKey, request: &SignRequest) -> Response {
    match sign(key, &request.data, request.flags) {
        Some(signature) => Response::Signature(signature),
        None => Response::Failure,
    }
}

/// Sign `data`, honouring the RSA hash flags, and encode the signature.
fn sign(key: &PrivateKey, data: &[u8], flags: u32) -> Option<Vec<u8>> {
    let signature: Signature = match key.key_data() {
        KeypairData::Rsa(rsa) => {
            let hash = if flags & RSA_SHA2_512 != 0 {
                Some(HashAlg::Sha512)
            } else if flags & RSA_SHA2_256 != 0 {
                Some(HashAlg::Sha256)
            } else {
                None
            };
            (rsa, hash).try_sign(data).ok()?
        }
        keypair => keypair.try_sign(data).ok()?,
    };
    let mut encoded = Vec::new();
    signature.encode(&mut encoded).ok()?;
    Some(encoded)
}

/// Check a `session-bind@openssh.com` request: the host key must have
/// signed the session identifier.
fn session_bind_is_valid(bind: &SessionBind) -> bool {
    let Ok(host_key) = PublicKey::from_bytes(&bind.host_key) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(bind.signature.as_slice()) else {
        return false;
    };
    host_key
        .key_data()
        .verify(&bind.session_id, &signature)
        .is_ok()
}

fn success(ok: bool) -> Response {
    if ok {
        Response::Success
    } else {
        Response::Failure
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use russh::keys::ssh_key::Algorithm;

    use super::*;

    fn key(comment: &str) -> PrivateKey {
        let mut key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        key.set_comment(comment);
        key
    }

    fn add(key: &PrivateKey, constraints: Vec<Constraint>) -> Request {
        Request::AddIdentity(Box::new(AddIdentity {
            key: key.clone(),
            certificate: None,
            constraints,
        }))
    }

    fn respond(store: &mut Store, request: Request) -> (Response, Followup) {
        match store.handle(request) {
            Answer::Respond(response, followup) => (response, followup),
            other => panic!("{other:?}"),
        }
    }

    fn comments(store: &mut Store) -> Vec<String> {
        match respond(store, Request::RequestIdentities).0 {
            Response::Identities(ids) => ids.into_iter().map(|i| i.comment).collect(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn re_adding_keeps_position() {
        let mut store = Store::new(None, FingerprintHash::Sha256);
        let (one, two) = (key("one"), key("two"));
        respond(&mut store, add(&one, vec![]));
        respond(&mut store, add(&two, vec![]));
        let mut renamed = one.clone();
        renamed.set_comment("one again");
        respond(&mut store, add(&renamed, vec![]));
        assert_eq!(comments(&mut store), ["one again", "two"]);
    }

    #[test]
    fn lifetimes() {
        let mut store = Store::new(Some(60), FingerprintHash::Sha256);
        let (response, followup) = respond(&mut store, add(&key("default"), vec![]));
        assert_eq!(response, Response::Success);
        assert_eq!(followup.expire_after, Some(Duration::from_secs(60)));

        let (_, followup) = respond(
            &mut store,
            add(&key("own"), vec![Constraint::KeyLifetime { seconds: 5 }]),
        );
        assert_eq!(followup.expire_after, Some(Duration::from_secs(5)));

        let lifetime = Constraint::KeyLifetime { seconds: 5 };
        let (response, _) = respond(
            &mut store,
            add(&key("twice"), vec![lifetime.clone(), lifetime]),
        );
        assert_eq!(response, Response::Failure);
    }

    #[test]
    fn lock_hides_and_protects_keys() {
        let mut store = Store::new(None, FingerprintHash::Sha256);
        let one = key("one");
        respond(&mut store, add(&one, vec![]));
        let lock = |p: &[u8]| Request::Lock {
            passphrase: Zeroizing::new(p.to_vec()),
        };
        let unlock = |p: &[u8]| Request::Unlock {
            passphrase: Zeroizing::new(p.to_vec()),
        };
        assert_eq!(respond(&mut store, lock(b"pw")).0, Response::Success);
        assert_eq!(respond(&mut store, lock(b"pw")).0, Response::Failure);
        assert!(comments(&mut store).is_empty());
        assert_eq!(
            respond(&mut store, add(&key("two"), vec![])).0,
            Response::Failure
        );
        assert_eq!(respond(&mut store, unlock(b"wrong")).0, Response::Failure);
        assert_eq!(respond(&mut store, unlock(b"pw")).0, Response::Success);
        assert_eq!(comments(&mut store), ["one"]);
    }

    #[test]
    fn refuses_unenforceable_constraints() {
        let mut store = Store::new(None, FingerprintHash::Sha256);
        let constraint = Constraint::Extensions {
            name: b"restrict-destination-v00@openssh.com".to_vec(),
            details: vec![],
        };
        assert_eq!(
            respond(&mut store, add(&key("k"), vec![constraint])).0,
            Response::Failure
        );
    }

    #[test]
    fn empty_lock_passphrase_is_refused() {
        let mut store = Store::new(None, FingerprintHash::Sha256);
        let lock = Request::Lock {
            passphrase: Zeroizing::new(Vec::new()),
        };
        assert_eq!(respond(&mut store, lock).0, Response::Failure);
    }

    #[test]
    fn failed_unlocks_are_delayed_increasingly() {
        let mut store = Store::new(None, FingerprintHash::Sha256);
        let request = |lock: bool, p: &[u8]| {
            let passphrase = Zeroizing::new(p.to_vec());
            if lock {
                Request::Lock { passphrase }
            } else {
                Request::Unlock { passphrase }
            }
        };
        respond(&mut store, request(true, b"pw"));
        let delays: Vec<_> = (0..3)
            .map(|_| respond(&mut store, request(false, b"wrong")).1.delay)
            .collect();
        assert_eq!(
            delays,
            [100, 200, 300].map(|ms| Some(Duration::from_millis(ms)))
        );
        let (response, followup) = respond(&mut store, request(false, b"pw"));
        assert_eq!((response, followup.delay), (Response::Success, None));
        // The count starts over after a successful unlock.
        respond(&mut store, request(true, b"pw"));
        let delay = respond(&mut store, request(false, b"wrong")).1.delay;
        assert_eq!(delay, Some(Duration::from_millis(100)));
    }

    #[test]
    fn confirmed_keys_ask_before_signing() {
        let mut store = Store::new(None, FingerprintHash::Sha256);
        let k = key("my key");
        respond(&mut store, add(&k, vec![Constraint::Confirm]));
        let sign = SignRequest {
            key_blob: k.public_key().to_bytes().unwrap(),
            data: b"data".to_vec(),
            flags: 0,
        };
        let fingerprint = keyfmt::fingerprint(k.public_key().key_data(), FingerprintHash::Sha256);
        assert_eq!(
            store.handle(Request::Sign(sign.clone())),
            Answer::Confirm {
                prompt: format!("Allow use of key my key?\nKey fingerprint {fingerprint}."),
                request: sign.clone(),
            }
        );
        assert!(matches!(
            store.sign_confirmed(&sign),
            Response::Signature(_)
        ));

        // Locked while asking: no signature.
        respond(
            &mut store,
            Request::Lock {
                passphrase: Zeroizing::new(b"pw".to_vec()),
            },
        );
        assert_eq!(store.sign_confirmed(&sign), Response::Failure);
    }
}
