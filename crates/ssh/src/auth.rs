//! User authentication, like OpenSSH's `ssh_userauth2`: a `none` request
//! first, then the methods in `PreferredAuthentications` order that the
//! server allows, until one succeeds or none is left.

use russh::client::AuthResult;
use sshutils_config::Options;

use crate::identity::Identities;
use crate::log;
use crate::pubkey::{Attempt, Pubkey};
use crate::transport::Transport;

/// The authentication methods OpenSSH knows, in the order of its table
/// (which is the default `PreferredAuthentications`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Method {
    GssapiWithMic,
    Hostbased,
    Publickey,
    KeyboardInteractive,
    Password,
    None,
}

const METHODS: [Method; 6] = [
    Method::GssapiWithMic,
    Method::Hostbased,
    Method::Publickey,
    Method::KeyboardInteractive,
    Method::Password,
    Method::None,
];

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::GssapiWithMic => "gssapi-with-mic",
            Method::Hostbased => "hostbased",
            Method::Publickey => "publickey",
            Method::KeyboardInteractive => "keyboard-interactive",
            Method::Password => "password",
            Method::None => "none",
        }
    }

    fn lookup(name: &str) -> Option<Method> {
        let method = METHODS.into_iter().find(|m| m.name() == name);
        if method.is_none() {
            log::debug2(&format!("Unrecognized authentication method name: {name}"));
        }
        method
    }
}

/// How authentication ended, if not by success.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// Every method failed; the message has been logged.
    Denied,
    /// The connection ended; nothing has been logged yet.
    Closed,
}

/// Which method to try next, like OpenSSH's `authmethod_get`.
struct Selection<'a> {
    options: &'a Options,
    /// Methods that had nothing (more) to send.
    disabled: Vec<Method>,
    /// `PreferredAuthentications`, or the enabled methods.
    preferences: String,
    /// The server's list the remaining preferences are for.
    supported: Option<String>,
    /// The preferences not tried yet against `supported`.
    remaining: usize,
    current: Option<Method>,
}

impl<'a> Selection<'a> {
    fn new(options: &'a Options) -> Selection<'a> {
        let mut selection = Selection {
            options,
            disabled: Vec::new(),
            preferences: String::new(),
            supported: None,
            remaining: 0,
            current: None,
        };
        selection.preferences = match &options.preferred_authentications {
            Some(list) => list.clone(),
            None => METHODS
                .into_iter()
                .filter(|m| selection.is_enabled(*m))
                .map(Method::name)
                .collect::<Vec<_>>()
                .join(","),
        };
        selection
    }

    /// OpenSSH's `authmethod_is_enabled`.
    fn is_enabled(&self, method: Method) -> bool {
        if self.disabled.contains(&method) {
            return false;
        }
        let options = self.options;
        let batch = options.batch_mode == Some(1);
        match method {
            Method::GssapiWithMic => options.gss_authentication == Some(1),
            Method::Hostbased => options.hostbased_authentication == Some(1),
            Method::Publickey => options.pubkey_authentication.is_some_and(|v| v != 0),
            Method::KeyboardInteractive => {
                options.kbd_interactive_authentication == Some(1) && !batch
            }
            Method::Password => options.password_authentication == Some(1) && !batch,
            Method::None => false,
        }
    }

    /// The next method to try for the server's `list`, if any.
    fn next(&mut self, list: &str) -> Option<Method> {
        let list = if list.is_empty() {
            self.preferences.clone()
        } else {
            list.to_string()
        };
        if self.supported.as_deref() != Some(list.as_str()) {
            log::debug3(&format!("start over, passed a different list {list}"));
            log::debug3(&format!("preferred {}", self.preferences));
            self.supported = Some(list.clone());
            self.remaining = 0;
            self.current = None;
        } else if let Some(current) = self.current
            && self.is_enabled(current)
        {
            return Some(current);
        }
        loop {
            let preferred = &self.preferences[self.remaining..];
            let Some((name, next)) = match_list(preferred, &list) else {
                log::debug("No more authentication methods to try.");
                self.current = None;
                return None;
            };
            self.remaining += next;
            log::debug3(&format!("authmethod_lookup {name}"));
            log::debug3(&format!(
                "remaining preferred: {}",
                &self.preferences[self.remaining..]
            ));
            self.current = Method::lookup(name);
            if let Some(method) = self.current
                && self.is_enabled(method)
            {
                log::debug3(&format!("authmethod_is_enabled {name}"));
                log::debug(&format!("Next authentication method: {name}"));
                return Some(method);
            }
        }
    }
}

/// The first name in `client` that is also in `server`, and the offset of
/// the name after it in `client`, like OpenSSH's `match_list`.
fn match_list<'c>(client: &'c str, server: &str) -> Option<(&'c str, usize)> {
    let mut start = 0;
    for name in client.split(',') {
        let end = start + name.len();
        if server.split(',').any(|s| s == name) {
            let next = if end < client.len() { end + 1 } else { end };
            return Some((name, next));
        }
        start = end + 1;
    }
    None
}

/// Authenticate as `user` to `host` (the name OpenSSH uses in messages,
/// lowercase since the configuration was resolved).
pub async fn authenticate(
    transport: &mut Transport,
    identities: &Identities,
    agent_socket: Option<&str>,
    user: &str,
    host: &str,
) -> Result<(), Failure> {
    let options = transport.options.clone();
    let mut selection = Selection::new(&options);
    let mut pubkey = Pubkey::new(&options, identities, agent_socket);
    log::debug("SSH2_MSG_SERVICE_ACCEPT received");
    let mut method = Method::None;
    let mut result = transport.handle.authenticate_none(user).await;
    loop {
        let (list, partial) = match result {
            Err(_) => return Err(Failure::Closed),
            Ok(AuthResult::Success) => {
                let peer = transport.peer;
                log::log(
                    log::VERBOSE,
                    &format!(
                        "Authenticated to {host} ([{}]:{}) using \"{}\".",
                        peer.ip(),
                        peer.port(),
                        method.name()
                    ),
                );
                return Ok(());
            }
            Ok(AuthResult::Failure {
                method_names,
                partial_success,
                ..
            }) => {
                if transport.handle.is_closed() {
                    return Err(Failure::Closed);
                }
                (method_names.join(","), partial_success)
            }
        };
        if partial {
            pubkey.reset();
            log::log(
                log::VERBOSE,
                &format!(
                    "Authenticated using \"{}\" with partial success.",
                    method.name()
                ),
            );
        }
        log::debug(&format!("Authentications that can continue: {list}"));
        loop {
            let Some(next) = selection.next(&list) else {
                log::fatal(&format!("{user}@{host}: Permission denied ({list})."));
                return Err(Failure::Denied);
            };
            method = next;
            let attempt = match method {
                Method::Publickey => pubkey.attempt(transport, user).await,
                // The other methods come in the next steps.
                _ => Attempt::Nothing,
            };
            match attempt {
                Attempt::Replied(reply) => {
                    log::debug2(&format!(
                        "we sent a {} packet, wait for reply",
                        method.name()
                    ));
                    result = Ok(reply);
                    break;
                }
                Attempt::Nothing => {
                    log::debug2("we did not send a packet, disable method");
                    selection.disabled.push(method);
                }
                Attempt::Closed => return Err(Failure::Closed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(preferred: Option<&str>, batch: bool) -> Options {
        let mut options = Options {
            preferred_authentications: preferred.map(str::to_string),
            batch_mode: batch.then_some(1),
            hostbased_authentication: Some(1),
            ..Options::default()
        };
        options.fill_defaults().unwrap();
        options
    }

    #[test]
    fn matching_lists() {
        assert_eq!(match_list("a,b,c", "c,b"), Some(("b", 4)));
        assert_eq!(match_list("a,b,c", "c"), Some(("c", 5)));
        assert_eq!(match_list("a,b", "x"), None);
        assert_eq!(match_list("", "a"), None);
        assert_eq!(match_list("a", "a"), Some(("a", 1)));
    }

    fn sequence(selection: &mut Selection, list: &str) -> Vec<&'static str> {
        let mut tried = Vec::new();
        while let Some(method) = selection.next(list) {
            tried.push(method.name());
            selection.disabled.push(method);
        }
        tried
    }

    #[test]
    fn default_preferences() {
        let options = make(None, false);
        let mut selection = Selection::new(&options);
        assert_eq!(
            selection.preferences,
            "hostbased,publickey,keyboard-interactive,password"
        );
        assert_eq!(
            sequence(&mut selection, "password,publickey,keyboard-interactive"),
            ["publickey", "keyboard-interactive", "password"]
        );

        let options = make(None, true);
        let selection = Selection::new(&options);
        assert_eq!(selection.preferences, "hostbased,publickey");
    }

    #[test]
    fn preferred_order() {
        let options = make(Some("password,none,bogus,publickey"), false);
        let mut selection = Selection::new(&options);
        assert_eq!(
            sequence(&mut selection, "publickey,password,none,bogus"),
            ["password", "publickey"]
        );
        // An empty list from the server means the preferences.
        let mut selection = Selection::new(&options);
        assert_eq!(sequence(&mut selection, ""), ["password", "publickey"]);
    }

    #[test]
    fn same_method_until_disabled() {
        let options = make(None, false);
        let mut selection = Selection::new(&options);
        assert_eq!(
            selection.next("password").map(Method::name),
            Some("password")
        );
        assert_eq!(
            selection.next("password").map(Method::name),
            Some("password")
        );
        selection.disabled.push(Method::Password);
        assert_eq!(selection.next("password"), None);
    }

    #[test]
    fn new_list_starts_over() {
        let options = make(None, false);
        let mut selection = Selection::new(&options);
        assert_eq!(
            selection.next("publickey,password").map(Method::name),
            Some("publickey")
        );
        // Not disabled: a new list after partial success starts at the
        // beginning of the preferences again.
        assert_eq!(
            selection.next("password,publickey").map(Method::name),
            Some("publickey")
        );
        selection.disabled.push(Method::Publickey);
        assert_eq!(
            selection.next("password,publickey").map(Method::name),
            Some("password")
        );
        // A method disabled earlier stays disabled.
        assert_eq!(selection.next("publickey"), None);
    }
}
