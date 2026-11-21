//! Interactive prompts, mirroring OpenSSH's `read_passphrase`.
//!
//! Passphrases come from the terminal, from stdin when there is no
//! terminal, or from an askpass program (`SSH_ASKPASS`), following the same
//! rules as OpenSSH:
//!
//! - An askpass program is *allowed* when `DISPLAY` is non-empty, or when
//!   `SSH_ASKPASS_REQUIRE=force`; `SSH_ASKPASS_REQUIRE=never` forbids it.
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
    let display = std::env::var_os("DISPLAY");
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

/// Ask a yes/no question through the askpass program, like OpenSSH's
/// `ask_permission` (used for `ssh-agent` key confirmations). The program
/// gets `SSH_ASKPASS_PROMPT=confirm`; an empty answer or `yes` (any case)
/// means yes. Without an allowed askpass program, the answer is no.
pub fn ask_permission(prompt: &str) -> bool {
    let display = std::env::var_os("DISPLAY");
    let require = std::env::var_os("SSH_ASKPASS_REQUIRE");
    if !askpass_rules(display.as_deref(), require.as_deref()).0 {
        return false;
    }
    match run_askpass(prompt, Some("confirm")) {
        Some(answer) => answer.is_empty() || answer.eq_ignore_ascii_case("yes"),
        None => false,
    }
}

/// `(allowed, preferred)` for an askpass program given `DISPLAY` and
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
