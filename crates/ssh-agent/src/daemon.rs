//! Process management: forking into the background and running a command.
//!
//! Forking must happen before any threads exist, so it is done before the
//! async runtime starts.

use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;

pub enum Forked {
    Parent { child: u32 },
    Child,
}

pub fn fork() -> io::Result<Forked> {
    // SAFETY: the process is single-threaded at this point (no runtime or
    // other threads have been started), so the child may continue normally.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Forked::Child),
        child => Ok(Forked::Parent {
            child: u32::try_from(child).expect("fork returns a positive pid"),
        }),
    }
}

/// Detach the forked agent like OpenSSH: new session, `/` as working
/// directory, stdio on `/dev/null`, and no core dumps (memory holds
/// unencrypted private keys). SIGINT is ignored.
pub fn detach() -> io::Result<()> {
    // SAFETY: plain system calls on our own process; the strings are
    // NUL-terminated literals.
    unsafe {
        if libc::setsid() == -1 {
            return Err(io::Error::last_os_error());
        }
        libc::chdir(c"/".as_ptr());
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            for fd in 0..=2 {
                libc::dup2(null, fd);
            }
            if null > 2 {
                libc::close(null);
            }
        }
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) == -1 {
            return Err(io::Error::last_os_error());
        }
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }
    Ok(())
}

/// Replace this process with `command`, with the agent's variables set.
/// Only returns on failure.
pub fn exec_command(command: &[OsString], socket: &Path, agent_pid: u32) -> io::Error {
    let (program, args) = command.split_first().expect("command is not empty");
    std::process::Command::new(program)
        .args(args)
        .env("SSH_AUTH_SOCK", socket)
        .env("SSH_AGENT_PID", agent_pid.to_string())
        .exec()
}
