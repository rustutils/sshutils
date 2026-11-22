//! The `ssh_config` keywords of OpenSSH 10.5.
//!
//! The table keeps OpenSSH's order: `ssh -G` prints each option under the
//! first name listed for it. GSSAPI and PKCS#11 keywords are listed as
//! supported, as in distribution builds of OpenSSH.

/// What a keyword does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    Ignore,
    Deprecated,
    Unsupported,
    GssAuthentication,
    GssDelegateCreds,
    PKCS11Provider,
    ForwardAgent,
    ForwardX11,
    ForwardX11Trusted,
    ForwardX11Timeout,
    ExitOnForwardFailure,
    XAuthLocation,
    GatewayPorts,
    PasswordAuthentication,
    KbdInteractiveAuthentication,
    KbdInteractiveDevices,
    PubkeyAuthentication,
    HostbasedAuthentication,
    IdentityFile,
    IdentitiesOnly,
    CertificateFile,
    AddKeysToAgent,
    IdentityAgent,
    Hostname,
    HostKeyAlias,
    ProxyCommand,
    Port,
    Ciphers,
    Macs,
    RemoteForward,
    LocalForward,
    PermitRemoteOpen,
    User,
    Host,
    Match,
    Tag,
    EscapeChar,
    GlobalKnownHostsFile,
    UserKnownHostsFile,
    ConnectionAttempts,
    BatchMode,
    CheckHostIP,
    StrictHostKeyChecking,
    Compression,
    TCPKeepAlive,
    NumberOfPasswordPrompts,
    LogFacility,
    LogLevel,
    LogVerbose,
    DynamicForward,
    PreferredAuthentications,
    HostKeyAlgorithms,
    CASignatureAlgorithms,
    BindAddress,
    BindInterface,
    ClearAllForwardings,
    EnableSSHKeysign,
    VerifyHostKeyDNS,
    NoHostAuthenticationForLocalhost,
    RekeyLimit,
    ConnectTimeout,
    AddressFamily,
    ServerAliveInterval,
    ServerAliveCountMax,
    SendEnv,
    SetEnv,
    ControlPath,
    ControlMaster,
    ControlPersist,
    HashKnownHosts,
    Include,
    Tunnel,
    TunnelDevice,
    LocalCommand,
    PermitLocalCommand,
    RemoteCommand,
    VisualHostKey,
    KexAlgorithms,
    IPQoS,
    RequestTTY,
    SessionType,
    StdinNull,
    ForkAfterAuthentication,
    ProxyUseFdpass,
    CanonicalDomains,
    CanonicalizeFallbackLocal,
    CanonicalizeHostname,
    CanonicalizeMaxDots,
    CanonicalizePermittedCNAMEs,
    StreamLocalBindMask,
    StreamLocalBindUnlink,
    RevokedHostKeys,
    FingerprintHash,
    UpdateHostkeys,
    HostbasedAcceptedAlgorithms,
    PubkeyAcceptedAlgorithms,
    IgnoreUnknown,
    ProxyJump,
    SecurityKeyProvider,
    KnownHostsCommand,
    RequiredRSASize,
    EnableEscapeCommandline,
    ObscureKeystrokeTiming,
    ChannelTimeout,
    VersionAddendum,
    RefuseConnection,
    WarnWeakCrypto,
}

/// Keywords and their opcodes, in OpenSSH's order.
pub const KEYWORDS: &[(&str, Opcode)] = &[
    ("protocol", Opcode::Ignore),
    ("cipher", Opcode::Deprecated),
    ("fallbacktorsh", Opcode::Deprecated),
    ("globalknownhostsfile2", Opcode::Deprecated),
    ("rhostsauthentication", Opcode::Deprecated),
    ("userknownhostsfile2", Opcode::Deprecated),
    ("useroaming", Opcode::Deprecated),
    ("usersh", Opcode::Deprecated),
    ("useprivilegedport", Opcode::Deprecated),
    ("afstokenpassing", Opcode::Unsupported),
    ("kerberosauthentication", Opcode::Unsupported),
    ("kerberostgtpassing", Opcode::Unsupported),
    ("rsaauthentication", Opcode::Unsupported),
    ("rhostsrsaauthentication", Opcode::Unsupported),
    ("compressionlevel", Opcode::Unsupported),
    ("gssapiauthentication", Opcode::GssAuthentication),
    ("gssapidelegatecredentials", Opcode::GssDelegateCreds),
    ("pkcs11provider", Opcode::PKCS11Provider),
    ("smartcarddevice", Opcode::PKCS11Provider),
    ("forwardagent", Opcode::ForwardAgent),
    ("forwardx11", Opcode::ForwardX11),
    ("forwardx11trusted", Opcode::ForwardX11Trusted),
    ("forwardx11timeout", Opcode::ForwardX11Timeout),
    ("exitonforwardfailure", Opcode::ExitOnForwardFailure),
    ("xauthlocation", Opcode::XAuthLocation),
    ("gatewayports", Opcode::GatewayPorts),
    ("passwordauthentication", Opcode::PasswordAuthentication),
    (
        "kbdinteractiveauthentication",
        Opcode::KbdInteractiveAuthentication,
    ),
    ("kbdinteractivedevices", Opcode::KbdInteractiveDevices),
    (
        "challengeresponseauthentication",
        Opcode::KbdInteractiveAuthentication,
    ),
    ("skeyauthentication", Opcode::KbdInteractiveAuthentication),
    ("tisauthentication", Opcode::KbdInteractiveAuthentication),
    ("pubkeyauthentication", Opcode::PubkeyAuthentication),
    ("dsaauthentication", Opcode::PubkeyAuthentication),
    ("hostbasedauthentication", Opcode::HostbasedAuthentication),
    ("identityfile", Opcode::IdentityFile),
    ("identityfile2", Opcode::IdentityFile),
    ("identitiesonly", Opcode::IdentitiesOnly),
    ("certificatefile", Opcode::CertificateFile),
    ("addkeystoagent", Opcode::AddKeysToAgent),
    ("identityagent", Opcode::IdentityAgent),
    ("hostname", Opcode::Hostname),
    ("hostkeyalias", Opcode::HostKeyAlias),
    ("proxycommand", Opcode::ProxyCommand),
    ("port", Opcode::Port),
    ("ciphers", Opcode::Ciphers),
    ("macs", Opcode::Macs),
    ("remoteforward", Opcode::RemoteForward),
    ("localforward", Opcode::LocalForward),
    ("permitremoteopen", Opcode::PermitRemoteOpen),
    ("user", Opcode::User),
    ("host", Opcode::Host),
    ("match", Opcode::Match),
    ("tag", Opcode::Tag),
    ("escapechar", Opcode::EscapeChar),
    ("globalknownhostsfile", Opcode::GlobalKnownHostsFile),
    ("userknownhostsfile", Opcode::UserKnownHostsFile),
    ("connectionattempts", Opcode::ConnectionAttempts),
    ("batchmode", Opcode::BatchMode),
    ("checkhostip", Opcode::CheckHostIP),
    ("stricthostkeychecking", Opcode::StrictHostKeyChecking),
    ("compression", Opcode::Compression),
    ("tcpkeepalive", Opcode::TCPKeepAlive),
    ("keepalive", Opcode::TCPKeepAlive),
    ("numberofpasswordprompts", Opcode::NumberOfPasswordPrompts),
    ("syslogfacility", Opcode::LogFacility),
    ("loglevel", Opcode::LogLevel),
    ("logverbose", Opcode::LogVerbose),
    ("dynamicforward", Opcode::DynamicForward),
    ("preferredauthentications", Opcode::PreferredAuthentications),
    ("hostkeyalgorithms", Opcode::HostKeyAlgorithms),
    ("casignaturealgorithms", Opcode::CASignatureAlgorithms),
    ("bindaddress", Opcode::BindAddress),
    ("bindinterface", Opcode::BindInterface),
    ("clearallforwardings", Opcode::ClearAllForwardings),
    ("enablesshkeysign", Opcode::EnableSSHKeysign),
    ("verifyhostkeydns", Opcode::VerifyHostKeyDNS),
    (
        "nohostauthenticationforlocalhost",
        Opcode::NoHostAuthenticationForLocalhost,
    ),
    ("rekeylimit", Opcode::RekeyLimit),
    ("connecttimeout", Opcode::ConnectTimeout),
    ("addressfamily", Opcode::AddressFamily),
    ("serveraliveinterval", Opcode::ServerAliveInterval),
    ("serveralivecountmax", Opcode::ServerAliveCountMax),
    ("sendenv", Opcode::SendEnv),
    ("setenv", Opcode::SetEnv),
    ("controlpath", Opcode::ControlPath),
    ("controlmaster", Opcode::ControlMaster),
    ("controlpersist", Opcode::ControlPersist),
    ("hashknownhosts", Opcode::HashKnownHosts),
    ("include", Opcode::Include),
    ("tunnel", Opcode::Tunnel),
    ("tunneldevice", Opcode::TunnelDevice),
    ("localcommand", Opcode::LocalCommand),
    ("permitlocalcommand", Opcode::PermitLocalCommand),
    ("remotecommand", Opcode::RemoteCommand),
    ("visualhostkey", Opcode::VisualHostKey),
    ("kexalgorithms", Opcode::KexAlgorithms),
    ("ipqos", Opcode::IPQoS),
    ("requesttty", Opcode::RequestTTY),
    ("sessiontype", Opcode::SessionType),
    ("stdinnull", Opcode::StdinNull),
    ("forkafterauthentication", Opcode::ForkAfterAuthentication),
    ("proxyusefdpass", Opcode::ProxyUseFdpass),
    ("canonicaldomains", Opcode::CanonicalDomains),
    (
        "canonicalizefallbacklocal",
        Opcode::CanonicalizeFallbackLocal,
    ),
    ("canonicalizehostname", Opcode::CanonicalizeHostname),
    ("canonicalizemaxdots", Opcode::CanonicalizeMaxDots),
    (
        "canonicalizepermittedcnames",
        Opcode::CanonicalizePermittedCNAMEs,
    ),
    ("streamlocalbindmask", Opcode::StreamLocalBindMask),
    ("streamlocalbindunlink", Opcode::StreamLocalBindUnlink),
    ("revokedhostkeys", Opcode::RevokedHostKeys),
    ("fingerprinthash", Opcode::FingerprintHash),
    ("updatehostkeys", Opcode::UpdateHostkeys),
    (
        "hostbasedacceptedalgorithms",
        Opcode::HostbasedAcceptedAlgorithms,
    ),
    ("hostbasedkeytypes", Opcode::HostbasedAcceptedAlgorithms),
    ("pubkeyacceptedalgorithms", Opcode::PubkeyAcceptedAlgorithms),
    ("pubkeyacceptedkeytypes", Opcode::PubkeyAcceptedAlgorithms),
    ("ignoreunknown", Opcode::IgnoreUnknown),
    ("proxyjump", Opcode::ProxyJump),
    ("securitykeyprovider", Opcode::SecurityKeyProvider),
    ("knownhostscommand", Opcode::KnownHostsCommand),
    ("requiredrsasize", Opcode::RequiredRSASize),
    ("enableescapecommandline", Opcode::EnableEscapeCommandline),
    ("obscurekeystroketiming", Opcode::ObscureKeystrokeTiming),
    ("channeltimeout", Opcode::ChannelTimeout),
    ("versionaddendum", Opcode::VersionAddendum),
    ("refuseconnection", Opcode::RefuseConnection),
    ("warnweakcrypto", Opcode::WarnWeakCrypto),
];

/// Keywords added by distribution patches (Fedora, Debian) for GSSAPI key
/// exchange. Accepted and ignored, so distribution configuration files
/// don't fail.
pub const DISTRIBUTION_KEYWORDS: &[&str] = &[
    "gssapikeyexchange",
    "gssapiclientidentity",
    "gssapiserveridentity",
    "gssapirenewalforcesrekey",
    "gssapitrustdns",
    "gssapikexalgorithms",
];

/// The opcode for a (lowercase) keyword.
pub fn lookup(keyword: &str) -> Option<Opcode> {
    KEYWORDS
        .iter()
        .find(|(name, _)| *name == keyword)
        .map(|&(_, opcode)| opcode)
}

/// The name `ssh -G` uses for an opcode: the first one in the table.
pub fn name(opcode: Opcode) -> &'static str {
    KEYWORDS
        .iter()
        .find(|&&(_, op)| op == opcode)
        .map_or("UNKNOWN", |&(name, _)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_map_to_the_same_option() {
        assert_eq!(
            lookup("challengeresponseauthentication"),
            Some(Opcode::KbdInteractiveAuthentication)
        );
        assert_eq!(
            lookup("pubkeyacceptedkeytypes"),
            Some(Opcode::PubkeyAcceptedAlgorithms)
        );
        assert_eq!(
            name(Opcode::PubkeyAcceptedAlgorithms),
            "pubkeyacceptedalgorithms"
        );
        assert_eq!(name(Opcode::TCPKeepAlive), "tcpkeepalive");
        assert_eq!(
            lookup("gssapiauthentication"),
            Some(Opcode::GssAuthentication)
        );
        assert_eq!(lookup("pkcs11provider"), Some(Opcode::PKCS11Provider));
        assert_eq!(lookup("compressionlevel"), Some(Opcode::Unsupported));
        assert_eq!(lookup("Port"), None, "lookups are on lowercase names");
    }
}
