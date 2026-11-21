//! Interactive prompts, mirroring OpenSSH's `read_passphrase`.

use std::io::{self, BufRead, Write};

/// Read a passphrase without echo. Like OpenSSH, prefer the controlling
/// terminal and fall back to stdin when there is none.
pub fn read_passphrase(prompt: &str) -> io::Result<String> {
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(p),
        Err(_) => {
            eprint!("{prompt}");
            read_line()
        }
    }
}

/// Read one line from stdin (with echo), stripping the newline.
pub fn read_line() -> io::Result<String> {
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
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
