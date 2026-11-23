use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::Openssh;
use crate::agent::{AGENT_SOCKET, Agent};
use crate::process::{self, Outcome};

/// Runs our implementation of a tool and OpenSSH's side by side.
///
/// ```ignore
/// let openssh = require_openssh!();
/// let keygen = Differential::new(
///     env!("CARGO_BIN_EXE_ssh-keygen"),
///     openssh.require_tool("ssh-keygen"),
/// );
/// keygen
///     .case(["-l", "-f", "key.pub"])
///     .setup(|dir| std::fs::copy(FIXTURE, dir.join("key.pub")).map(drop).unwrap())
///     .run()
///     .assert_same_outcome();
/// ```
#[derive(Debug, Clone)]
pub struct Differential {
    ours: PathBuf,
    theirs: PathBuf,
}

impl Differential {
    pub fn new(ours: impl Into<PathBuf>, theirs: impl Into<PathBuf>) -> Self {
        Differential {
            ours: ours.into(),
            theirs: theirs.into(),
        }
    }

    /// Start describing an invocation with the given arguments.
    pub fn case<I, S>(&self, args: I) -> Case<'_>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Case {
            differential: self,
            args: args.into_iter().map(Into::into).collect(),
            setup: None,
            finish: None,
            stdin: Vec::new(),
            env: Vec::new(),
            agent: None,
            agent_program: None,
        }
    }
}

type Setup<'a> = Box<dyn Fn(&Path) + 'a>;

/// One invocation, run against both implementations.
pub struct Case<'a> {
    differential: &'a Differential,
    args: Vec<OsString>,
    setup: Option<Setup<'a>>,
    finish: Option<Setup<'a>>,
    stdin: Vec<u8>,
    env: Vec<(OsString, OsString)>,
    agent: Option<&'a Openssh>,
    agent_program: Option<PathBuf>,
}

impl<'a> Case<'a> {
    /// Prepare each scratch directory (e.g. copy fixtures) before running.
    /// Called once per implementation, each time with a fresh directory.
    pub fn setup(mut self, f: impl Fn(&Path) + 'a) -> Self {
        self.setup = Some(Box::new(f));
        self
    }

    /// Called with each scratch directory right after that implementation
    /// ran (to save state shared between the runs there, say).
    pub fn finish(mut self, f: impl Fn(&Path) + 'a) -> Self {
        self.finish = Some(Box::new(f));
        self
    }

    /// Data to feed on stdin (both implementations get the same bytes).
    pub fn stdin(mut self, input: impl Into<Vec<u8>>) -> Self {
        self.stdin = input.into();
        self
    }

    /// Set an environment variable for both implementations.
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Give each implementation its own fresh OpenSSH `ssh-agent`, with
    /// `SSH_AUTH_SOCK` pointing at it. The agent is started before
    /// [`setup`](Self::setup) runs, at [`AGENT_SOCKET`] in the scratch
    /// directory, so setup can load keys into it.
    pub fn agent(mut self, openssh: &'a Openssh) -> Self {
        self.agent = Some(openssh);
        self
    }

    /// Like [`agent`](Self::agent), with another agent program that takes
    /// OpenSSH's options (ours, say).
    pub fn agent_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.agent_program = Some(program.into());
        self
    }

    pub fn run(self) -> Comparison {
        let ours = self.run_one(&self.differential.ours);
        let theirs = self.run_one(&self.differential.theirs);
        Comparison {
            args: self.args,
            ours,
            theirs,
        }
    }

    fn run_one(&self, program: &Path) -> Run {
        let dir = tempfile::tempdir().expect("create scratch directory");
        let socket = dir.path().join(AGENT_SOCKET);
        let agent = match (&self.agent_program, self.agent) {
            (Some(program), _) => Some(Agent::start_program(program, &[], &socket)),
            (None, Some(openssh)) => Some(Agent::start(openssh, &socket)),
            (None, None) => None,
        };
        if let Some(setup) = &self.setup {
            setup(dir.path());
        }
        let mut command = process::command(program, dir.path());
        command.args(&self.args);
        for (key, value) in &self.env {
            command.env(key, value);
        }
        if let Some(agent) = &agent {
            command.env("SSH_AUTH_SOCK", agent.socket());
        }
        let outcome = process::run(&mut command, &self.stdin);
        if let Some(finish) = &self.finish {
            finish(dir.path());
        }
        Run {
            dir,
            outcome,
            agent,
        }
    }
}

/// One implementation's run: its scratch directory (kept until dropped, so
/// produced files can be inspected) and what happened.
#[derive(Debug)]
pub struct Run {
    pub dir: TempDir,
    pub outcome: Outcome,
    /// The run's agent, if the case asked for one.
    pub agent: Option<Agent>,
}

impl Run {
    /// Path of a file inside the scratch directory.
    pub fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.dir.path().join(relative)
    }
}

/// The results of running both implementations.
#[derive(Debug)]
pub struct Comparison {
    pub args: Vec<OsString>,
    pub ours: Run,
    pub theirs: Run,
}

impl Comparison {
    /// Assert both exited with the same status and printed the same stdout.
    /// Stderr is not compared (error wording may differ), but is shown on
    /// failure.
    pub fn assert_same_outcome(&self) -> &Self {
        let (ours, theirs) = (&self.ours.outcome, &self.theirs.outcome);
        if ours.status != theirs.status || ours.stdout != theirs.stdout {
            panic!(
                "outcomes differ for args {:?}\n\
                 --- ours: status {:?}\n[stdout]\n{}\n[stderr]\n{}\n\
                 --- OpenSSH: status {:?}\n[stdout]\n{}\n[stderr]\n{}",
                self.args,
                ours.status,
                ours.stdout,
                ours.stderr,
                theirs.status,
                theirs.stdout,
                theirs.stderr,
            );
        }
        self
    }

    /// Assert both runs' agents hold the same identities afterwards.
    pub fn assert_same_agent(&self, openssh: &Openssh) -> &Self {
        let identities = |run: &Run| {
            run.agent
                .as_ref()
                .expect("case was run with .agent()")
                .identities(openssh)
        };
        let (ours, theirs) = (identities(&self.ours), identities(&self.theirs));
        if ours != theirs {
            panic!(
                "agent contents differ for args {:?}\n--- ours:\n{ours}\n--- OpenSSH:\n{theirs}",
                self.args
            );
        }
        self
    }

    /// Assert a file has the same contents (or is missing) in both scratch
    /// directories.
    pub fn assert_same_file(&self, relative: impl AsRef<Path>) -> &Self {
        let relative = relative.as_ref();
        let ours = std::fs::read(self.ours.path(relative)).ok();
        let theirs = std::fs::read(self.theirs.path(relative)).ok();
        if ours != theirs {
            let show = |c: &Option<Vec<u8>>| match c {
                Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                None => "<missing>".to_string(),
            };
            panic!(
                "file {relative:?} differs for args {:?}\n--- ours:\n{}\n--- OpenSSH:\n{}",
                self.args,
                show(&ours),
                show(&theirs),
            );
        }
        self
    }
}
