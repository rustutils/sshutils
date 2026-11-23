//! Interactive prompts, mirroring OpenSSH's `read_passphrase`.
//!
//! Passphrases come from the terminal, from stdin when there is no
//! terminal, or from an askpass program (`SSH_ASKPASS`), following the same
//! rules as OpenSSH:
//!
//! - An askpass program is *allowed* when `DISPLAY` or `WAYLAND_DISPLAY` is
//!   non-empty, or when `SSH_ASKPASS_REQUIRE=force`;
//!   `SSH_ASKPASS_REQUIRE=never` forbids it.
//! - It is *used* if allowed and either stdin isn't a terminal,
//!   `SSH_ASKPASS_REQUIRE=force`, or `SSH_ASKPASS_REQUIRE=prefer`.
//! - The program gets the prompt as its only argument and prints the
//!   answer; exiting unsuccessfully means "cancelled" (an empty answer).

use std::ffi::OsString;
use std::io::{self, BufRead, Read, Write};
use std::process::{Command, Stdio};

/// Where askpass programs are usually installed, tried in order when
/// `SSH_ASKPASS` isn't set. Falls back to `ssh-askpass` in `PATH`.
const DEFAULT_ASKPASS: &[&str] = &[
    "/usr/libexec/openssh/ssh-askpass",
    "/usr/lib/openssh/ssh-askpass",
    "/usr/lib/ssh/ssh-askpass",
    "/usr/X11R6/bin/ssh-askpass",
];

/// Read a passphrase without echo, from an askpass program, the terminal,
/// or stdin (see the module documentation). End of input or a cancelled
/// askpass program yields an empty passphrase, as in OpenSSH.
pub fn read_passphrase(prompt: &str) -> io::Result<String> {
    let display = display();
    let require = std::env::var_os("SSH_ASKPASS_REQUIRE");
    if use_askpass(display.as_deref(), require.as_deref(), stdin_is_terminal()) {
        return Ok(run_askpass(prompt, None).unwrap_or_default());
    }
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(p),
        Err(_) => {
            eprint!("{prompt}");
            match read_line() {
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(String::new()),
                result => result,
            }
        }
    }
}

/// Ask a question on the controlling terminal with echo, like OpenSSH's
/// `read_passphrase(prompt, RP_ECHO)` (used for `ssh`'s host key
/// questions): the answer never comes from stdin. Without a terminal, an
/// allowed askpass program is asked instead; failing both, or when the
/// program is cancelled, the answer is empty.
pub fn ask_terminal(prompt: &str) -> String {
    ask_tty(prompt, true).unwrap_or_default()
}

/// Like [`ask_terminal`], without echo: OpenSSH's `read_passphrase(prompt,
/// 0)`, which `ssh` uses for passphrases and passwords.
pub fn ask_terminal_secret(prompt: &str) -> String {
    ask_tty(prompt, false).unwrap_or_default()
}

/// Like [`ask_terminal_secret`], but `None` when nothing could be asked:
/// no terminal and no askpass program, a failed read, or a cancelled
/// askpass program (OpenSSH's `RP_ALLOW_EOF`). End of input on the
/// terminal is an empty answer.
pub fn ask_terminal_secret_or_cancel(prompt: &str) -> Option<String> {
    ask_tty(prompt, false)
}

fn ask_tty(prompt: &str, echo: bool) -> Option<String> {
    let display = display();
    let require = std::env::var_os("SSH_ASKPASS_REQUIRE");
    let (allowed, preferred) = askpass_rules(display.as_deref(), require.as_deref());
    let terminal = if preferred {
        None
    } else {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()
    };
    match terminal {
        Some(mut tty) => {
            // Start the prompt at the beginning of the line.
            if tty.write_all(b"\r").is_err() || tty.write_all(prompt.as_bytes()).is_err() {
                return None;
            }
            let saved = if echo { None } else { echo_off(&tty) };
            let mut line = String::new();
            let read = io::BufReader::new(&tty).read_line(&mut line);
            if let Some(saved) = saved {
                use std::os::fd::AsRawFd;
                // SAFETY: restores the settings read from this descriptor.
                unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSAFLUSH, &saved) };
                let _ = tty.write_all(b"\n");
            }
            if read.is_err() {
                return None;
            }
            while line.ends_with(['\n', '\r']) {
                line.pop();
            }
            Some(line)
        }
        None if allowed => run_askpass(prompt, None),
        None => None,
    }
}

/// Turn off echo on `tty`, returning the settings to restore.
fn echo_off(tty: &std::fs::File) -> Option<libc::termios> {
    use std::os::fd::AsRawFd;
    let fd = tty.as_raw_fd();
    // SAFETY: termios is plain data, filled in by tcgetattr on an open
    // descriptor before it is used.
    unsafe {
        let mut saved: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut saved) != 0 {
            return None;
        }
        let mut quiet = saved;
        quiet.c_lflag &= !(libc::ECHO | libc::ECHONL);
        if libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) != 0 {
            return None;
        }
        Some(saved)
    }
}

/// Ask a yes/no question through the askpass program, like OpenSSH's
/// `ask_permission` (used for `ssh-agent` key confirmations). The program
/// gets `SSH_ASKPASS_PROMPT=confirm`; an empty answer or `yes` (any case)
/// means yes. Without an allowed askpass program, the answer is no.
pub fn ask_permission(prompt: &str) -> bool {
    let display = display();
    let require = std::env::var_os("SSH_ASKPASS_REQUIRE");
    if !askpass_rules(display.as_deref(), require.as_deref()).0 {
        return false;
    }
    match run_askpass(prompt, Some("confirm")) {
        Some(answer) => answer.is_empty() || answer.eq_ignore_ascii_case("yes"),
        None => false,
    }
}

/// `DISPLAY`, or failing that `WAYLAND_DISPLAY`.
fn display() -> Option<OsString> {
    std::env::var_os("DISPLAY")
        .filter(|d| !d.is_empty())
        .or_else(|| std::env::var_os("WAYLAND_DISPLAY"))
}

/// `(allowed, preferred)` for an askpass program given the display and
/// `SSH_ASKPASS_REQUIRE`.
fn askpass_rules(
    display: Option<&std::ffi::OsStr>,
    require: Option<&std::ffi::OsStr>,
) -> (bool, bool) {
    let allowed = display.is_some_and(|d| !d.is_empty());
    match require
        .map(|r| r.to_string_lossy().to_ascii_lowercase())
        .as_deref()
    {
        Some("force") => (true, true),
        Some("prefer") => (allowed, allowed),
        Some("never") => (false, false),
        _ => (allowed, false),
    }
}

/// Whether to ask an askpass program instead of the terminal or stdin.
fn use_askpass(
    display: Option<&std::ffi::OsStr>,
    require: Option<&std::ffi::OsStr>,
    stdin_is_terminal: bool,
) -> bool {
    let (allowed, preferred) = askpass_rules(display, require);
    allowed && (preferred || !stdin_is_terminal)
}

fn stdin_is_terminal() -> bool {
    // SAFETY: isatty has no preconditions.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// The askpass program: `SSH_ASKPASS`, or the first installed default.
fn askpass_program() -> OsString {
    if let Some(program) = std::env::var_os("SSH_ASKPASS").filter(|p| !p.is_empty()) {
        return program;
    }
    DEFAULT_ASKPASS
        .iter()
        .find(|path| std::path::Path::new(path).exists())
        .map_or_else(|| OsString::from("ssh-askpass"), OsString::from)
}

/// Run the askpass program with `prompt`, returning the first line it
/// prints, or `None` if it fails or is cancelled. `hint` is passed as
/// `SSH_ASKPASS_PROMPT` (e.g. `confirm` for yes/no questions).
pub fn run_askpass(prompt: &str, hint: Option<&str>) -> Option<String> {
    let program = askpass_program();
    let mut command = Command::new(&program);
    command.arg(prompt).stdout(Stdio::piped());
    if let Some(hint) = hint {
        command.env("SSH_ASKPASS_PROMPT", hint);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("ssh_askpass: exec({}): {e}", program.to_string_lossy());
            return None;
        }
    };
    let mut output = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_end(&mut output);
    }
    let status = child.wait().ok()?;
    if !status.success() {
        return None;
    }
    let output = String::from_utf8_lossy(&output);
    Some(output.split(['\r', '\n']).next().unwrap_or("").to_string())
}

/// Read one line from stdin (with echo), stripping the newline. Fails with
/// `UnexpectedEof` if stdin is already at end of input.
pub fn read_line() -> io::Result<String> {
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    Ok(line)
}

/// Print `prompt` to stdout and read an answer from stdin.
pub fn prompt_line(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    read_line()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn askpass_selection_matches_openssh() {
        let some = |s: &'static str| Some(OsStr::new(s));
        // (DISPLAY, SSH_ASKPASS_REQUIRE, stdin is a terminal) -> use askpass
        let cases = [
            (some(":0"), None, false, true),
            (some(":0"), None, true, false),
            (None, None, false, false),
            (some(""), None, false, false),
            (None, some("force"), true, true),
            (None, some("FORCE"), false, true),
            (some(":0"), some("never"), false, false),
            (some(":0"), some("prefer"), true, true),
            (None, some("prefer"), true, false),
            (None, some("prefer"), false, false),
            (some(":0"), some("bogus"), true, false),
        ];
        for (display, require, terminal, expected) in cases {
            assert_eq!(
                use_askpass(display, require, terminal),
                expected,
                "DISPLAY={display:?} SSH_ASKPASS_REQUIRE={require:?} terminal={terminal}"
            );
        }
    }
}
