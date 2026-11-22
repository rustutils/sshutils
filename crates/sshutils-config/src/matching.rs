//! Pattern matching as in OpenSSH's `match.c`.

use sshutils_core::known_hosts::glob_match;

/// Match `text` against one `*`/`?` pattern, case-sensitively.
pub fn match_pattern(text: &str, pattern: &str) -> bool {
    glob_match(text.as_bytes(), pattern.as_bytes())
}

/// Match `text` against a comma-separated pattern list: 1 if a positive
/// pattern matches, -1 if a negated (`!pattern`) one matches (which always
/// wins), 0 otherwise. With `lowercase`, patterns are lowercased first.
pub fn match_pattern_list(text: &str, patterns: &str, lowercase: bool) -> i32 {
    let mut positive = false;
    for pattern in patterns.split(',') {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, pattern),
        };
        let pattern = if lowercase {
            pattern.to_ascii_lowercase()
        } else {
            pattern.to_string()
        };
        if match_pattern(text, &pattern) {
            if negated {
                return -1;
            }
            positive = true;
        }
    }
    i32::from(positive)
}

/// Match a host name (lowercased) against a pattern list (lowercased).
pub fn match_hostname(host: &str, patterns: &str) -> i32 {
    match_pattern_list(&host.to_ascii_lowercase(), patterns, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists() {
        assert_eq!(match_pattern_list("web1", "web*,db*", false), 1);
        assert_eq!(match_pattern_list("web1", "!web1,web*", false), -1);
        assert_eq!(match_pattern_list("other", "web*", false), 0);
        assert_eq!(match_pattern_list("web1", "WEB*", false), 0);
        assert_eq!(match_pattern_list("web1", "WEB*", true), 1);
        assert_eq!(match_hostname("WEB1", "web?"), 1);
        assert_eq!(match_pattern_list("", "", false), 1);
    }
}
