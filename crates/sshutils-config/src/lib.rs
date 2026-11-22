//! `ssh_config` handling, compatible with OpenSSH 10.5.
//!
//! - [`lexer`]: splitting lines into keywords and arguments.
//! - [`keywords`]: every keyword OpenSSH knows.
//! - [`reader`]: applying lines and files to [`Options`], with `Host`,
//!   `Match` and `Include`.
//! - [`client`]: the whole resolution `ssh` performs, ending in the values
//!   `ssh -G` prints ([`Options::dump`]).

pub mod algorithms;
pub mod client;
pub mod expand;
pub mod forward;
pub mod keywords;
pub mod lexer;
pub mod matching;
pub mod network;
pub mod options;
pub mod reader;
pub mod values;

pub use client::{Request, Resolved, resolve};
pub use options::Options;
pub use reader::{Context, Fatal, Flags, Reader};
