//! Log messages, like OpenSSH's `log.c`: a level (`LogLevel`, `-q`, `-v`)
//! decides what is shown, and messages go to stderr, a file (`-E`) or
//! syslog (`-y`).
//!
//! As in OpenSSH, lines on stderr end in `\r\n` (the terminal may be in raw
//! mode), debug messages carry a `debugN: ` prefix, and control characters
//! are escaped so that text from the server can't drive the terminal.

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::Mutex;

use sshutils_config::values::LOG_LEVEL_INFO;

/// `SYSLOG_LEVEL_*`.
pub const FATAL: i32 = 1;
pub const ERROR: i32 = 2;
pub const INFO: i32 = 3;
pub const VERBOSE: i32 = 4;
pub const DEBUG1: i32 = 5;
pub const DEBUG2: i32 = 6;
pub const DEBUG3: i32 = 7;

/// Where messages go.
pub enum Sink {
    Stderr,
    File(std::fs::File),
    Syslog,
}

struct Logger {
    sink: Sink,
    level: i32,
}

static LOGGER: Mutex<Logger> = Mutex::new(Logger {
    sink: Sink::Stderr,
    level: LOG_LEVEL_INFO,
});

fn logger() -> std::sync::MutexGuard<'static, Logger> {
    LOGGER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Send messages to `sink` from now on.
pub fn set_sink(sink: Sink) {
    logger().sink = sink;
}

/// Show messages up to `level`.
pub fn set_level(level: i32) {
    logger().level = level;
}

#[cfg(test)]
thread_local! {
    /// Messages logged by this thread while capturing (tests only).
    static CAPTURED: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

/// Collect this thread's messages at level `INFO` or more severe instead of
/// printing them, until [`captured`] is called.
#[cfg(test)]
pub fn capture() {
    CAPTURED.with(|c| *c.borrow_mut() = Some(Vec::new()));
}

/// Stop capturing and return the messages.
#[cfg(test)]
pub fn captured() -> Vec<String> {
    CAPTURED.with(|c| c.borrow_mut().take().unwrap_or_default())
}

/// Log `message` at `level`, if that level is shown.
pub fn log(level: i32, message: &str) {
    #[cfg(test)]
    {
        let captured = CAPTURED.with(|c| {
            let mut c = c.borrow_mut();
            if let Some(messages) = c.as_mut() {
                if level <= INFO {
                    messages.push(message.to_string());
                }
                true
            } else {
                false
            }
        });
        if captured {
            return;
        }
    }
    let mut logger = logger();
    if level > logger.level {
        return;
    }
    let prefix = match level {
        DEBUG1 => "debug1: ",
        DEBUG2 => "debug2: ",
        DEBUG3 => "debug3: ",
        _ => "",
    };
    let text = escape(&format!("{prefix}{message}"));
    match &mut logger.sink {
        Sink::Stderr => {
            let _ = std::io::stderr().write_all(format!("{text}\r\n").as_bytes());
        }
        Sink::File(file) => {
            let _ = file.write_all(format!("{text}\r\n").as_bytes());
        }
        Sink::Syslog => {
            let priority = match level {
                FATAL => libc::LOG_CRIT,
                ERROR => libc::LOG_ERR,
                INFO | VERBOSE => libc::LOG_INFO,
                _ => libc::LOG_DEBUG,
            };
            if let Ok(text) = std::ffi::CString::new(text) {
                // SAFETY: both strings are NUL-terminated, and the format
                // consumes exactly one string argument.
                unsafe { libc::syslog(priority, c"%s".as_ptr(), text.as_ptr()) };
            }
        }
    }
}

pub fn fatal(message: &str) {
    log(FATAL, message);
}

pub fn error(message: &str) {
    log(ERROR, message);
}

/// OpenSSH's `logit()`.
pub fn info(message: &str) {
    log(INFO, message);
}

pub fn debug(message: &str) {
    log(DEBUG1, message);
}

pub fn debug2(message: &str) {
    log(DEBUG2, message);
}

pub fn debug3(message: &str) {
    log(DEBUG3, message);
}

/// Print `text` from the server to stderr as OpenSSH's `fmprintf` does,
/// whatever the log destination, if messages at `INFO` are shown.
pub fn print_untrusted(text: &str) {
    if logger().level < INFO {
        return;
    }
    let _ = std::io::stderr().write_all(untrusted(text).as_bytes());
}

/// `text` from the server escaped for the terminal, as OpenSSH's
/// `asmprintf` and `fmprintf` do.
pub fn untrusted(text: &str) -> String {
    escape_multibyte(text, utf8_locale())
}

/// Does the locale's character encoding (`LC_CTYPE`) use UTF-8?
fn utf8_locale() -> bool {
    use std::sync::OnceLock;
    static UTF8: OnceLock<bool> = OnceLock::new();
    *UTF8.get_or_init(|| {
        // SAFETY: called once, before other threads could use the locale;
        // nl_langinfo returns a NUL-terminated string that stays valid
        // until the next setlocale.
        unsafe {
            if libc::setlocale(libc::LC_CTYPE, c"".as_ptr()).is_null() {
                return false;
            }
            let codeset = libc::nl_langinfo(libc::CODESET);
            !codeset.is_null()
                && std::ffi::CStr::from_ptr(codeset)
                    .to_bytes()
                    .eq_ignore_ascii_case(b"UTF-8")
        }
    })
}

/// Escape like OpenSSH's `vasnmprintf`: newline, return and tab pass, as
/// do printable characters (only ASCII ones outside a UTF-8 locale); every
/// byte of anything else becomes `\ooo`.
fn escape_multibyte(text: &str, utf8: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let printable = if c.is_ascii() {
            !c.is_ascii_control() || matches!(c, '\t' | '\n' | '\r')
        } else {
            utf8 && !c.is_control()
        };
        if printable {
            out.push(c);
        } else {
            let mut bytes = [0; 4];
            for byte in c.encode_utf8(&mut bytes).bytes() {
                let _ = write!(out, "\\{byte:03o}");
            }
        }
    }
    out
}

/// Escape control characters as `\ooo` octal, like `strnvis` with
/// `VIS_SAFE | VIS_OCTAL`: tab, newline, return, backspace and bell pass,
/// as does other printable text. Unlike OpenSSH, printable non-ASCII text
/// is kept rather than escaped byte by byte; C1 controls are escaped.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\u{8}' | '\u{7}') {
            let mut bytes = [0; 4];
            for byte in c.encode_utf8(&mut bytes).bytes() {
                let _ = write!(out, "\\{byte:03o}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(escape("plain text"), "plain text");
        assert_eq!(escape("a\tb\nc"), "a\tb\nc");
        assert_eq!(escape("\u{1b}[31mred"), "\\033[31mred");
        assert_eq!(escape("cr\r"), "cr\r");
        assert_eq!(escape("csi\u{9b}"), "csi\\302\\233");
        assert_eq!(escape("del\u{7f}"), "del\\177");
        assert_eq!(escape("grüße"), "grüße");
    }

    #[test]
    fn multibyte_escaping() {
        assert_eq!(escape_multibyte("a\tb\r\nc", false), "a\tb\r\nc");
        assert_eq!(
            escape_multibyte("bell\u{7}bs\u{8}", true),
            "bell\\007bs\\010"
        );
        assert_eq!(escape_multibyte("\u{1b}[1m\u{7f}", true), "\\033[1m\\177");
        assert_eq!(escape_multibyte("grüße", true), "grüße");
        assert_eq!(escape_multibyte("grüße", false), "gr\\303\\274\\303\\237e");
        assert_eq!(escape_multibyte("csi\u{9b}", true), "csi\\302\\233");
    }
}
