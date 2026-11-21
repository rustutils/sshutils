//! Listening on the agent socket and serving connections.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use russh::keys::agent::proto::{self, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};

use crate::store::Store;

type Shared = Arc<Mutex<Store>>;

/// Files to remove when the agent exits.
pub struct Cleanup {
    pub socket: PathBuf,
    /// Temporary directory holding the socket (`-T`).
    pub directory: Option<PathBuf>,
}

impl Cleanup {
    pub fn run(&self) {
        let _ = std::fs::remove_file(&self.socket);
        if let Some(directory) = &self.directory {
            let _ = std::fs::remove_dir(directory);
        }
    }
}

/// Bind the agent socket with mode 0600, like OpenSSH (which sets a umask
/// of 0177 around `bind`). Existing files are never replaced.
pub fn bind(path: &Path) -> std::io::Result<std::os::unix::net::UnixListener> {
    // SAFETY: umask only changes this process's file creation mask; we
    // restore it right after binding, before any other thread exists.
    let previous = unsafe { libc::umask(0o177) };
    let result = std::os::unix::net::UnixListener::bind(path);
    unsafe { libc::umask(previous) };
    let listener = result?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Serve until a terminating signal arrives; then clean up and return the
/// signal number.
///
/// `ready` runs once the signal handlers are in place, so anything it
/// announces (like the environment) can't race with an early SIGTERM.
pub async fn run(
    listener: std::os::unix::net::UnixListener,
    store: Store,
    debug: bool,
    ready: impl FnOnce(),
) -> std::io::Result<i32> {
    let listener = UnixListener::from_std(listener)?;
    let store: Shared = Arc::new(Mutex::new(store));
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    ready();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
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
            _ = terminate.recv() => return Ok(libc::SIGTERM),
            _ = hangup.recv() => return Ok(libc::SIGHUP),
            _ = interrupt.recv() => return Ok(libc::SIGINT),
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

        let (response, followup) = match Request::decode(&payload) {
            Ok(request) => {
                if debug {
                    eprintln!("debug1: request type {}", payload[0]);
                }
                let mut store = store.lock().unwrap_or_else(|e| e.into_inner());
                store.handle(request)
            }
            // Malformed messages get a failure; the connection stays open.
            Err(_) => (Response::Failure, Default::default()),
        };
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
