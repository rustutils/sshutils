//! Test harness for sshutils.
//!
//! - [`Openssh`] finds the system's OpenSSH installation, so tests can skip
//!   (or, with `SSHUTILS_REQUIRE_OPENSSH=1`, fail) when it isn't installed.
//! - [`Differential`] runs one of our tools and its OpenSSH counterpart with
//!   the same arguments in identical scratch directories and compares the
//!   results.
//! - [`Agent`] starts a throwaway OpenSSH `ssh-agent`; a [`Case`] can give
//!   each implementation its own.
//! - [`Sshd`] starts a throwaway, unprivileged OpenSSH server on a free
//!   localhost port, with keys and a client config to log in to it.
//! - [`ScriptedServer`] is a russh server whose authentication follows a
//!   [`Behaviour`], for what an unprivileged sshd can't do; it records the
//!   requests clients send.
//!
//! Every process is started with a clean environment, without a controlling
//! terminal and with stdin from a pipe, so nothing from the developer's own
//! setup (agent, `~/.ssh/config`, terminal prompts) leaks into a test. OpenSSH
//! (and our tools) find `~/.ssh` through the passwd database, not `$HOME`, so
//! tests must always name their files explicitly (`-f`, `-F`, ...).

mod agent;
mod differential;
mod openssh;
mod process;
mod scripted;
mod sshd;

pub use agent::{AGENT_SOCKET, Agent};
pub use differential::{Case, Comparison, Differential, Run};
pub use openssh::Openssh;
pub use process::{Outcome, command, run};
pub use russh::MethodKind;
pub use scripted::{Behaviour, Challenge, ScriptedServer};
pub use sshd::Sshd;

/// Find OpenSSH or return from the current test.
///
/// ```ignore
/// let openssh = sshutils_testing::require_openssh!();
/// ```
#[macro_export]
macro_rules! require_openssh {
    () => {
        match $crate::Openssh::find_or_skip() {
            Some(openssh) => openssh,
            None => return,
        }
    };
}
