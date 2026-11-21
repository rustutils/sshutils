//! A POSIX/BSD-compatible `getopt(3)`.
//!
//! OpenSSH parses its command lines with plain `getopt`, so to be a drop-in
//! replacement we have to accept exactly the same spellings: clustered flags
//! (`-lv`), attached arguments (`-fkey`), detached arguments (`-f key`),
//! `--` as end-of-options, and stopping at the first non-option argument.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opt {
    /// A flag that takes no argument.
    Flag(char),
    /// An option with its argument.
    Arg(char, String),
}

impl Opt {
    pub fn name(&self) -> char {
        match self {
            Opt::Flag(c) | Opt::Arg(c, _) => *c,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Unknown(char),
    MissingArgument(char),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Matches the wording OpenSSH's getopt prints.
        match self {
            Error::Unknown(c) => write!(f, "unknown option -- {c}"),
            Error::MissingArgument(c) => write!(f, "option requires an argument -- {c}"),
        }
    }
}

impl std::error::Error for Error {}

/// Iterator over options. After it returns `None`, [`Getopt::remaining`]
/// gives the operands.
pub struct Getopt {
    args: Vec<String>,
    optstring: Vec<(char, bool)>,
    index: usize,
    sub: usize,
}

impl Getopt {
    /// `args` excludes the program name. `optstring` uses getopt syntax
    /// (`"ab:c"` – `b` takes an argument).
    pub fn new(args: Vec<String>, optstring: &str) -> Self {
        let mut spec = Vec::new();
        let mut chars = optstring.chars().peekable();
        while let Some(c) = chars.next() {
            let takes_arg = chars.peek() == Some(&':');
            if takes_arg {
                chars.next();
            }
            spec.push((c, takes_arg));
        }
        Getopt { args, optstring: spec, index: 0, sub: 0 }
    }

    pub fn remaining(&self) -> &[String] {
        &self.args[self.index..]
    }

    pub fn into_remaining(mut self) -> Vec<String> {
        self.args.split_off(self.index)
    }
}

impl Iterator for Getopt {
    type Item = Result<Opt, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.sub == 0 {
            let arg = self.args.get(self.index)?;
            if arg == "--" {
                self.index += 1;
                return None;
            }
            if !arg.starts_with('-') || arg == "-" {
                return None;
            }
            self.sub = 1;
        }

        let arg = &self.args[self.index];
        let c = arg[self.sub..].chars().next().expect("sub always points at a char");
        self.sub += c.len_utf8();
        let at_end = self.sub >= arg.len();

        let Some(&(_, takes_arg)) = self.optstring.iter().find(|(o, _)| *o == c && *o != ':') else {
            if at_end {
                self.index += 1;
                self.sub = 0;
            }
            return Some(Err(Error::Unknown(c)));
        };

        if !takes_arg {
            if at_end {
                self.index += 1;
                self.sub = 0;
            }
            return Some(Ok(Opt::Flag(c)));
        }

        let value = if !at_end {
            arg[self.sub..].to_string()
        } else {
            self.index += 1;
            match self.args.get(self.index) {
                Some(v) => v.clone(),
                None => {
                    self.sub = 0;
                    return Some(Err(Error::MissingArgument(c)));
                }
            }
        };
        self.index += 1;
        self.sub = 0;
        Some(Ok(Opt::Arg(c, value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str], spec: &str) -> (Vec<Result<Opt, Error>>, Vec<String>) {
        let mut g = Getopt::new(args.iter().map(|s| s.to_string()).collect(), spec);
        let opts = g.by_ref().collect();
        (opts, g.into_remaining())
    }

    #[test]
    fn clustered_and_attached() {
        let (opts, rest) = parse(&["-lvfkey", "x"], "lvf:");
        assert_eq!(
            opts,
            vec![Ok(Opt::Flag('l')), Ok(Opt::Flag('v')), Ok(Opt::Arg('f', "key".into()))]
        );
        assert_eq!(rest, vec!["x"]);
    }

    #[test]
    fn detached_and_stop_at_operand() {
        let (opts, rest) = parse(&["-f", "key", "host", "-l"], "lf:");
        assert_eq!(opts, vec![Ok(Opt::Arg('f', "key".into()))]);
        assert_eq!(rest, vec!["host", "-l"]);
    }

    #[test]
    fn empty_argument_is_allowed() {
        let (opts, _) = parse(&["-N", "", "-q"], "N:q");
        assert_eq!(opts, vec![Ok(Opt::Arg('N', "".into())), Ok(Opt::Flag('q'))]);
    }

    #[test]
    fn double_dash_and_errors() {
        let (opts, rest) = parse(&["-x", "--", "-q"], "q");
        assert_eq!(opts, vec![Err(Error::Unknown('x'))]);
        assert_eq!(rest, vec!["-q"]);
        let (opts, _) = parse(&["-f"], "f:");
        assert_eq!(opts, vec![Err(Error::MissingArgument('f'))]);
    }
}
