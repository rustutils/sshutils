use std::fmt::Display;
use std::process::ExitCode;

/// Why `ssh-add` stopped, and with which status.
#[derive(Debug)]
pub enum Error {
    /// Print the message to stderr and exit with the status.
    Message(u8, String),
    /// Exit quietly with this status (messages were already printed).
    Exit(u8),
}

impl Error {
    /// A fatal error: exits with 255, like OpenSSH's `fatal()`.
    pub fn fatal(message: impl Display) -> Self {
        Error::Message(255, message.to_string())
    }

    pub fn message(status: u8, message: impl Display) -> Self {
        Error::Message(status, message.to_string())
    }

    pub fn report(self) -> ExitCode {
        match self {
            Error::Message(status, message) => {
                eprintln!("{message}");
                ExitCode::from(status)
            }
            Error::Exit(status) => ExitCode::from(status),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An I/O error as `strerror` would describe it.
pub fn io_message(err: &std::io::Error) -> String {
    let message = err.to_string();
    match message.find(" (os error ") {
        Some(i) => message[..i].to_string(),
        None => message,
    }
}

/// An agent error as OpenSSH describes it.
pub fn agent_message(err: &russh::keys::Error) -> String {
    match err {
        russh::keys::Error::AgentFailure => "agent refused operation".to_string(),
        russh::keys::Error::IO(e) => io_message(e),
        other => other.to_string(),
    }
}
