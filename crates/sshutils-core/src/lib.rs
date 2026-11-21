//! Shared functionality for the sshutils binaries.
//!
//! Everything that must behave identically across `ssh`, `ssh-keygen`, etc.
//! (option parsing, path conventions, passphrase prompts, key display) lives
//! here so the binaries stay thin.

pub mod cli;
pub mod keyfile;
pub mod keyfmt;
pub mod known_hosts;
pub mod paths;
pub mod tty;

pub use russh::keys::ssh_key;
