//! The agent's keys and its answers to protocol requests.
//!
//! Everything here is synchronous; [`crate::server`] handles connections
//! and timers around it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::keys::agent::Constraint;
use russh::keys::agent::proto::{
    AddIdentity, ExtensionRequest, Identity, Request, Response, SessionBind, SignRequest,
};
use russh::keys::signature::{Signer, Verifier};
use russh::keys::ssh_key::encoding::Encode;
use russh::keys::ssh_key::private::KeypairData;
use russh::keys::ssh_key::{HashAlg, PrivateKey, PublicKey, Signature};
use zeroize::Zeroizing;

/// `SSH_AGENT_RSA_SHA2_256` and `SSH_AGENT_RSA_SHA2_512` sign flags.
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

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

/// The agent's state, shared by all connections.
#[derive(Default)]
pub struct Store {
    /// Keys in the order they were added; re-adding a key keeps its place.
    entries: Vec<Entry>,
    /// Lock passphrase while the agent is locked.
    lock: Option<Zeroizing<Vec<u8>>>,
    /// Lifetime for keys added without one (`ssh-agent -t`).
    default_lifetime: Option<u32>,
}

/// What a connection must do after answering a request.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Followup {
    /// Purge expired keys after this long.
    pub expire_after: Option<Duration>,
}

impl Store {
    pub fn new(default_lifetime: Option<u32>) -> Store {
        Store {
            default_lifetime,
            ..Store::default()
        }
    }

    /// Answer one request.
    pub fn handle(&mut self, request: Request) -> (Response, Followup) {
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
            Request::Lock { passphrase } if !locked => {
                self.lock = Some(passphrase);
                Response::Success
            }
            Request::Unlock { passphrase } if locked => {
                let matches = self
                    .lock
                    .as_ref()
                    .is_some_and(|lock| constant_time_eq(lock, &passphrase));
                if matches {
                    self.lock = None;
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
        let Some(entry) = self.entries.iter().find(|e| e.blob == request.key_blob) else {
            return Response::Failure;
        };
        if entry.confirm {
            // Confirmation through SSH_ASKPASS is not implemented yet;
            // without a way to ask, OpenSSH refuses too.
            return Response::Failure;
        }
        match sign(&entry.key, &request.data, request.flags) {
            Some(signature) => Response::Signature(signature),
            None => Response::Failure,
        }
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

    fn comments(store: &mut Store) -> Vec<String> {
        match store.handle(Request::RequestIdentities).0 {
            Response::Identities(ids) => ids.into_iter().map(|i| i.comment).collect(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn re_adding_keeps_position() {
        let mut store = Store::new(None);
        let (one, two) = (key("one"), key("two"));
        store.handle(add(&one, vec![]));
        store.handle(add(&two, vec![]));
        let mut renamed = one.clone();
        renamed.set_comment("one again");
        store.handle(add(&renamed, vec![]));
        assert_eq!(comments(&mut store), ["one again", "two"]);
    }

    #[test]
    fn lifetimes() {
        let mut store = Store::new(Some(60));
        let (response, followup) = store.handle(add(&key("default"), vec![]));
        assert_eq!(response, Response::Success);
        assert_eq!(followup.expire_after, Some(Duration::from_secs(60)));

        let (_, followup) = store.handle(add(
            &key("own"),
            vec![Constraint::KeyLifetime { seconds: 5 }],
        ));
        assert_eq!(followup.expire_after, Some(Duration::from_secs(5)));

        let lifetime = Constraint::KeyLifetime { seconds: 5 };
        let (response, _) = store.handle(add(&key("twice"), vec![lifetime.clone(), lifetime]));
        assert_eq!(response, Response::Failure);
    }

    #[test]
    fn lock_hides_and_protects_keys() {
        let mut store = Store::new(None);
        let one = key("one");
        store.handle(add(&one, vec![]));
        let lock = |p: &[u8]| Request::Lock {
            passphrase: Zeroizing::new(p.to_vec()),
        };
        let unlock = |p: &[u8]| Request::Unlock {
            passphrase: Zeroizing::new(p.to_vec()),
        };
        assert_eq!(store.handle(lock(b"pw")).0, Response::Success);
        assert_eq!(store.handle(lock(b"pw")).0, Response::Failure);
        assert!(comments(&mut store).is_empty());
        assert_eq!(store.handle(add(&key("two"), vec![])).0, Response::Failure);
        assert_eq!(store.handle(unlock(b"wrong")).0, Response::Failure);
        assert_eq!(store.handle(unlock(b"pw")).0, Response::Success);
        assert_eq!(comments(&mut store), ["one"]);
    }

    #[test]
    fn refuses_unenforceable_constraints() {
        let mut store = Store::new(None);
        let constraint = Constraint::Extensions {
            name: b"restrict-destination-v00@openssh.com".to_vec(),
            details: vec![],
        };
        assert_eq!(
            store.handle(add(&key("k"), vec![constraint])).0,
            Response::Failure
        );
    }
}
