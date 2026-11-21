//! Interactive prompts, mirroring OpenSSH's `read_passphrase`.

use std::io::{self, BufRead, Write};

/// Read a passphrase without echo. Like OpenSSH, prefer the controlling
/// terminal and fall back to stdin when there is none.
pub fn read_passphrase(prompt: &str) -> io::Result<String> {
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(p),
        Err(_) => {
            eprint!("{prompt}");
            // Like OpenSSH, end of input means an empty passphrase.
            match read_line() {
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(String::new()),
                result => result,
            }
        }
    }
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
