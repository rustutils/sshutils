//! Listening on the agent socket and serving connections.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::agent::proto::{self, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};

use sshutils_core::tty;

use crate::store::{Answer, Followup, Store};

type Shared = Arc<Mutex<Store>>;

/// How the agent runs.
pub struct Options {
    pub debug: bool,
    /// Exit on SIGINT (foreground modes); otherwise it is ignored.
    pub handle_interrupt: bool,
    /// In command mode: exit once this process (the command) is no longer
    /// our parent.
    pub parent: Option<u32>,
}

/// Why the agent stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Signal(i32),
    ParentExited,
}

/// How often command mode checks that the command is still running.
const PARENT_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Serve until a terminating signal arrives or, in command mode, the
/// command exits.
///
/// `ready` runs once the signal handlers are in place, so anything it
/// announces (like the environment) can't race with an early SIGTERM.
pub async fn run(
    listener: std::os::unix::net::UnixListener,
    store: Store,
    options: Options,
    ready: impl FnOnce(),
) -> std::io::Result<Stop> {
    listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(listener)?;
    let debug = options.debug;
    let store: Shared = Arc::new(Mutex::new(store));
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let mut interrupt = if options.handle_interrupt {
        Some(signal(SignalKind::interrupt())?)
    } else {
        None
    };
    // SIGUSR1 removes all keys, as in OpenSSH.
    let mut drop_keys = signal(SignalKind::user_defined1())?;
    let mut parent_check = tokio::time::interval(PARENT_CHECK_INTERVAL);
    ready();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                if !peer_allowed(&stream) {
                    if debug {
                        eprintln!("debug1: refusing connection from another user");
                    }
                    continue;
                }
                if debug {
                    eprintln!("debug1: new connection");
                }
                let store = store.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(stream, store, debug).await
                        && debug
                    {
                        eprintln!("debug1: connection closed: {e}");
                    }
                });
            }
            _ = terminate.recv() => return Ok(Stop::Signal(libc::SIGTERM)),
            _ = hangup.recv() => return Ok(Stop::Signal(libc::SIGHUP)),
            Some(_) = async { interrupt.as_mut()?.recv().await } => {
                return Ok(Stop::Signal(libc::SIGINT));
            }
            _ = drop_keys.recv() => {
                eprintln!("signal {} received; removing all keys", libc::SIGUSR1);
                store.lock().unwrap_or_else(|e| e.into_inner()).remove_all();
            }
            _ = parent_check.tick(), if options.parent.is_some() => {
                // SAFETY: getppid has no preconditions.
                let parent = unsafe { libc::getppid() };
                if options.parent != u32::try_from(parent).ok() {
                    return Ok(Stop::ParentExited);
                }
            }
        }
    }
}

async fn serve_connection(
    mut stream: UnixStream,
    store: Shared,
    debug: bool,
) -> std::io::Result<()> {
    loop {
        let len = stream.read_u32().await? as usize;
        if len > proto::MAX_MESSAGE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("message of {len} bytes is too long"),
            ));
        }
        let mut payload = vec![0; len];
        stream.read_exact(&mut payload).await?;

        let answer = match Request::decode(&payload) {
            Ok(request) => {
                if debug {
                    eprintln!("debug1: request type {}", payload[0]);
                }
                store
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .handle(request)
            }
            // Malformed messages get a failure; the connection stays open.
            Err(_) => Answer::Respond(Response::Failure, Followup::default()),
        };
        let (response, followup) = match answer {
            Answer::Respond(response, followup) => (response, followup),
            Answer::Confirm { prompt, request } => {
                // Asking runs an external program; don't hold up other
                // connections meanwhile.
                let allowed = tokio::task::spawn_blocking(move || tty::ask_permission(&prompt))
                    .await
                    .unwrap_or(false);
                let response = if allowed {
                    store
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .sign_confirmed(&request)
                } else {
                    Response::Failure
                };
                (response, Followup::default())
            }
        };
        if let Some(delay) = followup.delay {
            tokio::time::sleep(delay).await;
        }
        if let Some(after) = followup.expire_after {
            let store = store.clone();
            tokio::spawn(async move {
                tokio::time::sleep(after).await;
                store
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove_expired();
            });
        }

        let encoded = response
            .encode()
            .and_then(|payload| proto::frame(&payload))
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        stream.write_all(&encoded).await?;
    }
}

/// Only the agent's own user (and root) may use it, as in OpenSSH.
fn peer_allowed(stream: &UnixStream) -> bool {
    // SAFETY: getuid has no preconditions.
    let own = unsafe { libc::getuid() };
    stream
        .peer_cred()
        .is_ok_and(|cred| allowed_uid(cred.uid(), own))
}

fn allowed_uid(peer: u32, own: u32) -> bool {
    peer == 0 || peer == own
}

#[cfg(test)]
mod tests {
    use super::allowed_uid;

    #[test]
    fn only_root_and_the_same_user_are_allowed() {
        assert!(allowed_uid(1000, 1000));
        assert!(allowed_uid(0, 1000));
        assert!(!allowed_uid(1001, 1000));
        assert!(allowed_uid(0, 0));
        assert!(!allowed_uid(1000, 0));
    }
}
