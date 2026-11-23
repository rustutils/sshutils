//! The `password` and `keyboard-interactive` methods, like OpenSSH's
//! `userauth_passwd` and `userauth_kbdint`: each is tried up to
//! `NumberOfPasswordPrompts` times, asking on the terminal (or through an
//! askpass program).

use russh::client::{AuthResult, KeyboardInteractiveAuthResponse, Prompt};
use sshutils_config::Options;
use sshutils_core::tty;

use crate::log;
use crate::pubkey::Attempt;
use crate::transport::Transport;

/// The state of both methods over one authentication.
pub struct Interactive<'a> {
    options: &'a Options,
    user: &'a str,
    /// The name prompts show: `HostKeyAlias`, or the host.
    host: &'a str,
    password_attempts: i32,
    kbdint_attempts: i32,
    /// The server sent an `SSH2_MSG_USERAUTH_INFO_REQUEST` at some point.
    info_request_seen: bool,
}

impl<'a> Interactive<'a> {
    pub fn new(options: &'a Options, user: &'a str, host: &'a str) -> Interactive<'a> {
        Interactive {
            options,
            user,
            host: options.host_key_alias.as_deref().unwrap_or(host),
            password_attempts: 0,
            kbdint_attempts: 0,
            info_request_seen: false,
        }
    }

    fn prompts(&self) -> i32 {
        self.options.number_of_password_prompts.unwrap_or(3)
    }

    /// Ask for the password and send it.
    pub async fn password(&mut self, transport: &mut Transport) -> Attempt {
        if self.password_attempts >= self.prompts() {
            return Attempt::Nothing;
        }
        self.password_attempts += 1;
        if self.password_attempts != 1 {
            log::error("Permission denied, please try again.");
        }
        let prompt = format!("{}@{}'s password: ", self.user, self.host);
        let password = tty::ask_terminal_secret(&prompt);
        match transport
            .handle
            .authenticate_password(self.user, password)
            .await
        {
            Ok(reply) => Attempt::Replied(reply),
            Err(_) => Attempt::Closed,
        }
    }

    /// Start a keyboard-interactive exchange and answer the server's
    /// prompts until it decides.
    pub async fn keyboard_interactive(&mut self, transport: &mut Transport) -> Attempt {
        if self.kbdint_attempts >= self.prompts() {
            return Attempt::Nothing;
        }
        self.kbdint_attempts += 1;
        if self.kbdint_attempts > 1 && !self.info_request_seen {
            log::debug3("userauth_kbdint: disable: no info_req_seen");
            return Attempt::Nothing;
        }
        log::debug2("userauth_kbdint");
        let devices = self
            .options
            .kbd_interactive_devices
            .clone()
            .unwrap_or_default();
        let mut reply = transport
            .handle
            .authenticate_keyboard_interactive_start(self.user, devices)
            .await;
        loop {
            match reply {
                Err(_) => return Attempt::Closed,
                Ok(KeyboardInteractiveAuthResponse::Success) => {
                    return Attempt::Replied(AuthResult::Success);
                }
                Ok(KeyboardInteractiveAuthResponse::Failure {
                    remaining_methods,
                    method_names,
                    partial_success,
                }) => {
                    return Attempt::Replied(AuthResult::Failure {
                        remaining_methods,
                        method_names,
                        partial_success,
                    });
                }
                Ok(KeyboardInteractiveAuthResponse::InfoRequest {
                    name,
                    instructions,
                    prompts,
                }) => {
                    let responses = self.info_request(&name, &instructions, &prompts);
                    reply = transport
                        .handle
                        .authenticate_keyboard_interactive_respond(responses)
                        .await;
                }
            }
        }
    }

    /// Show the request's name and instructions and ask its prompts, like
    /// OpenSSH's `input_userauth_info_req`.
    fn info_request(&mut self, name: &str, instructions: &str, prompts: &[Prompt]) -> Vec<String> {
        log::debug2("input_userauth_info_req: entering");
        self.info_request_seen = true;
        // OpenSSH means to add a newline only where there is none, but
        // checks the byte after the text, so it always adds one.
        for text in [name, instructions] {
            if !text.is_empty() {
                eprintln!("{}", log::untrusted(text));
            }
        }
        log::debug2(&format!(
            "input_userauth_info_req: num_prompts {}",
            prompts.len()
        ));
        prompts
            .iter()
            .map(|prompt| {
                let display =
                    log::untrusted(&format!("({}@{}) {}", self.user, self.host, prompt.prompt));
                if prompt.echo {
                    tty::ask_terminal(&display)
                } else {
                    tty::ask_terminal_secret(&display)
                }
            })
            .collect()
    }
}
