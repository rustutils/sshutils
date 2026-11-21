use std::path::PathBuf;

use crate::process;

/// Directories searched for OpenSSH programs, in order. Covers Fedora/RHEL
/// (`/usr/libexec/openssh`), Debian/Ubuntu (`/usr/lib/openssh`, `/usr/sbin`)
/// and source installs (`/usr/local`).
const SEARCH_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/libexec/openssh",
    "/usr/lib/openssh",
    "/usr/libexec",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/local/libexec",
];

/// An OpenSSH installation to compare against.
#[derive(Debug, Clone)]
pub struct Openssh {
    dirs: Vec<PathBuf>,
    version: String,
    version_number: (u32, u32),
}

impl Openssh {
    /// Locate OpenSSH. `SSHUTILS_OPENSSH_BINDIR` (a `:`-separated list)
    /// replaces the default search directories.
    pub fn find() -> Option<Self> {
        let dirs: Vec<PathBuf> = match std::env::var_os("SSHUTILS_OPENSSH_BINDIR") {
            Some(dirs) => std::env::split_paths(&dirs).collect(),
            None => SEARCH_DIRS.iter().map(PathBuf::from).collect(),
        };
        let mut openssh = Openssh {
            dirs,
            version: String::new(),
            version_number: (0, 0),
        };
        let ssh = openssh.tool("ssh")?;
        let tmp = tempfile::tempdir().ok()?;
        let out = process::run(process::command(&ssh, tmp.path()).arg("-V"), b"");
        // "OpenSSH_10.5p1, OpenSSL 4.0.3 29 Sep 2026"
        let version = out.stderr.split([',', ' ']).next()?.to_string();
        let number = version.strip_prefix("OpenSSH_")?;
        let mut parts = number.split(|c: char| !c.is_ascii_digit());
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        openssh.version = version;
        openssh.version_number = (major, minor);
        Some(openssh)
    }

    /// Like [`find`](Self::find), but for use at the start of a test: if
    /// OpenSSH is missing, print a note and return `None` so the test can
    /// return early. Panics instead if `SSHUTILS_REQUIRE_OPENSSH` is set, so
    /// CI can't silently skip tests.
    pub fn find_or_skip() -> Option<Self> {
        let found = Self::find();
        if found.is_none() {
            if std::env::var_os("SSHUTILS_REQUIRE_OPENSSH").is_some() {
                panic!("OpenSSH not found, but SSHUTILS_REQUIRE_OPENSSH is set");
            }
            eprintln!("skipping: OpenSSH not found (set SSHUTILS_OPENSSH_BINDIR)");
        }
        found
    }

    /// Absolute path of an OpenSSH program (`ssh-keygen`, `sshd`,
    /// `sftp-server`, ...), if installed.
    pub fn tool(&self, name: &str) -> Option<PathBuf> {
        self.dirs
            .iter()
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
    }

    /// Like [`tool`](Self::tool), but panics with a clear message if missing.
    pub fn require_tool(&self, name: &str) -> PathBuf {
        self.tool(name)
            .unwrap_or_else(|| panic!("OpenSSH program {name:?} not found in {:?}", self.dirs))
    }

    /// Version string, e.g. `OpenSSH_10.5p1`.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// `(major, minor)`, e.g. `(10, 5)`.
    pub fn version_number(&self) -> (u32, u32) {
        self.version_number
    }

    /// Whether this OpenSSH is at least `major.minor`.
    pub fn at_least(&self, major: u32, minor: u32) -> bool {
        self.version_number >= (major, minor)
    }
}
