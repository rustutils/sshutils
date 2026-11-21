use std::fmt::Display;
use std::process::ExitCode;

/// Why `ssh-keygen` stopped early.
#[derive(Debug)]
pub enum Error {
    /// An error message, printed to stderr; exits with 255 like OpenSSH's
    /// `fatal()`.
    Fatal(String),
    /// Exit quietly with this status (e.g. 1 when the user declines to
    /// overwrite a file).
    Exit(u8),
}

impl Error {
    pub fn fatal(message: impl Display) -> Self {
        Error::Fatal(message.to_string())
    }

    pub fn report(self) -> ExitCode {
        match self {
            Error::Fatal(message) => {
                eprintln!("ssh-keygen: {message}");
                ExitCode::from(255)
            }
            Error::Exit(code) => ExitCode::from(code),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
