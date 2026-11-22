//! Splitting configuration lines into words, like OpenSSH.
//!
//! A line is `Keyword arguments...` or `Keyword=arguments...`. The keyword
//! is split off first (allowing one `=` and surrounding blanks, or a
//! double-quoted keyword); the rest is split into arguments, where single
//! or double quotes group words, a backslash escapes quotes, backslashes
//! and (outside quotes) spaces, and an unquoted `#` starts a comment.

/// A configuration line split into its keyword and the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line<'a> {
    pub keyword: String,
    /// Everything after the keyword and its separator, as written. Some
    /// keywords (`ProxyCommand`, `RemoteCommand`, …) take it verbatim.
    pub rest: &'a str,
}

/// Blanks as OpenSSH's `WHITESPACE` (space, tab, CR, LF).
fn is_blank(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Split off the keyword. Returns `None` for empty lines and comments, and
/// `Some` with an empty `rest` when the keyword has no argument.
pub fn split_line(line: &str) -> Option<Line<'_>> {
    // Trailing whitespace (and form feeds) are ignored.
    let line = line.trim_end_matches(|c: char| is_blank(c) || c == '\x0c');
    let line = line.trim_start_matches(is_blank);
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let (keyword, rest) = if let Some(quoted) = line.strip_prefix('"') {
        // A quoted keyword runs to the closing quote.
        let end = quoted.find('"')?;
        (
            &quoted[..end],
            quoted[end + 1..].trim_start_matches(is_blank),
        )
    } else {
        match line.find(|c: char| is_blank(c) || c == '=' || c == '"') {
            None => (line, ""),
            Some(end) => {
                let keyword = &line[..end];
                let mut rest = &line[end..];
                // One '=' may separate keyword and value, with blanks on
                // either side.
                rest = rest.trim_start_matches(is_blank);
                if let Some(after) = rest.strip_prefix('=') {
                    rest = after.trim_start_matches(is_blank);
                }
                (keyword, rest)
            }
        }
    };
    if keyword.is_empty() || keyword.starts_with('#') {
        return None;
    }
    Some(Line {
        keyword: keyword.to_ascii_lowercase(),
        rest,
    })
}

/// Error from [`split_args`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnterminatedQuote;

/// Split arguments like OpenSSH's `argv_split` (with comments ending the
/// line).
pub fn split_args(text: &str) -> Result<Vec<String>, UnterminatedQuote> {
    let chars: Vec<char> = text.chars().collect();
    let mut args = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ' ' || chars[i] == '\t' {
            i += 1;
            continue;
        }
        if chars[i] == '#' {
            break;
        }
        let mut arg = String::new();
        let mut quote: Option<char> = None;
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' {
                match chars.get(i + 1) {
                    Some(&next)
                        if next == '\''
                            || next == '"'
                            || next == '\\'
                            || (quote.is_none() && next == ' ') =>
                    {
                        arg.push(next);
                        i += 2;
                    }
                    // Unrecognised escapes are kept as they are.
                    _ => {
                        arg.push(c);
                        i += 1;
                    }
                }
                continue;
            }
            match quote {
                None if c == ' ' || c == '\t' => break,
                None if c == '"' || c == '\'' => quote = Some(c),
                Some(q) if c == q => quote = None,
                _ => arg.push(c),
            }
            i += 1;
        }
        if quote.is_some() {
            return Err(UnterminatedQuote);
        }
        args.push(arg);
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> Option<(String, &str)> {
        split_line(text).map(|l| (l.keyword, l.rest))
    }

    #[test]
    fn keywords_and_separators() {
        assert_eq!(line("Port 22"), Some(("port".into(), "22")));
        assert_eq!(line("  Port\t 22  "), Some(("port".into(), "22")));
        assert_eq!(line("Port=22"), Some(("port".into(), "22")));
        assert_eq!(line("Port = 22"), Some(("port".into(), "22")));
        assert_eq!(line("Port =  = 22"), Some(("port".into(), "= 22")));
        assert_eq!(line("\"Port\" 22"), Some(("port".into(), "22")));
        assert_eq!(line("Port"), Some(("port".into(), "")));
        assert_eq!(line(""), None);
        assert_eq!(line("   # comment"), None);
        assert_eq!(line("#Port 22"), None);
    }

    #[test]
    fn argument_splitting() {
        let split = |s: &str| split_args(s).unwrap();
        assert_eq!(split("a b\tc"), ["a", "b", "c"]);
        assert_eq!(split("\"a b\" 'c d'"), ["a b", "c d"]);
        assert_eq!(split("a\\ b"), ["a b"]);
        assert_eq!(split("\"a\\\"b\""), ["a\"b"]);
        assert_eq!(split("a\\nb"), ["a\\nb"]);
        assert_eq!(split("a # comment"), ["a"]);
        assert_eq!(split("a#b"), ["a#b"]);
        assert_eq!(split("pre\"mid dle\"post"), ["premid dlepost"]);
        assert_eq!(split("\"\""), [""]);
        assert_eq!(split_args("\"open"), Err(UnterminatedQuote));
    }
}
