//! Key revocation lists (KRLs): OpenSSH's binary format for revoking keys
//! and certificates (`ssh-keygen -k`, `RevokedHostKeys`,
//! `RevokedKeys`), and the plain lists of public keys that may be used
//! instead.
//!
//! A KRL revokes keys explicitly or by SHA-1 or SHA-256 fingerprint, and
//! certificates by serial number (lists, ranges and bitmaps) or key ID,
//! for a given CA or for any CA. As in OpenSSH, the signature sections a
//! KRL may carry are skipped, not checked.

use std::collections::HashSet;

use russh::keys::ssh_key::public::KeyData;
use russh::keys::ssh_key::sha2::{Digest, Sha256};
use russh::keys::ssh_key::{Certificate, PublicKey};
use sha1::Sha1;

/// The magic string a KRL starts with.
pub const MAGIC: &[u8] = b"SSHKRL\n\0";
const FORMAT_VERSION: u32 = 1;

const SECTION_CERTIFICATES: u8 = 1;
const SECTION_EXPLICIT_KEY: u8 = 2;
const SECTION_FINGERPRINT_SHA1: u8 = 3;
const SECTION_SIGNATURE: u8 = 4;
const SECTION_FINGERPRINT_SHA256: u8 = 5;
const SECTION_EXTENSION: u8 = 255;

const CERT_SERIAL_LIST: u8 = 0x20;
const CERT_SERIAL_RANGE: u8 = 0x21;
const CERT_SERIAL_BITMAP: u8 = 0x22;
const CERT_KEY_ID: u8 = 0x23;
const CERT_EXTENSION: u8 = 0x39;

/// Why a KRL or key list couldn't be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// A message OpenSSH logs before giving the reason, if any.
    pub detail: Option<String>,
    /// OpenSSH's description of the failure (`ssh_err`).
    pub reason: String,
}

impl Error {
    fn new(reason: &str) -> Error {
        Error {
            detail: None,
            reason: reason.to_string(),
        }
    }

    fn with_detail(detail: impl Into<String>, reason: &str) -> Error {
        Error {
            detail: Some(detail.into()),
            reason: reason.to_string(),
        }
    }
}

const INVALID_FORMAT: &str = "invalid format";
const INCOMPLETE: &str = "message incomplete";

/// Certificates revoked for one CA (or, with no CA, for any).
#[derive(Debug, Clone, Default)]
struct RevokedCertificates {
    ca: Option<KeyData>,
    /// Inclusive serial number ranges.
    serials: Vec<(u64, u64)>,
    key_ids: HashSet<String>,
}

/// A parsed KRL.
#[derive(Debug, Clone, Default)]
pub struct Krl {
    pub version: u64,
    pub generated: u64,
    pub comment: String,
    keys: HashSet<Vec<u8>>,
    sha1: HashSet<Vec<u8>>,
    sha256: HashSet<Vec<u8>>,
    certificates: Vec<RevokedCertificates>,
}

/// A reader for the SSH wire encoding.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::new(INCOMPLETE));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().expect("four bytes")))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().expect("eight bytes")))
    }

    fn string(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// A string without embedded NULs (`sshbuf_get_cstring`).
    fn cstring(&mut self) -> Result<String, Error> {
        let bytes = self.string()?;
        if bytes.contains(&0) {
            return Err(Error::new(INVALID_FORMAT));
        }
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    /// An unsigned multiple-precision integer's magnitude, big-endian
    /// without leading zeros (`sshbuf_get_bignum2_bytes_direct`).
    fn mpint(&mut self) -> Result<&'a [u8], Error> {
        let mut bytes = self.string()?;
        if bytes.first().is_some_and(|b| b & 0x80 != 0) {
            return Err(Error::new("bignum is negative"));
        }
        while let [0, rest @ ..] = bytes {
            bytes = rest;
        }
        Ok(bytes)
    }
}

/// The wire encoding of a plain public key.
fn key_blob(key: &KeyData) -> Vec<u8> {
    PublicKey::from(key.clone())
        .to_bytes()
        .expect("encoding a public key into memory cannot fail")
}

/// Is this a KRL (does it start with the magic string)?
pub fn is_krl(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

impl Krl {
    /// Parse a KRL. Data that isn't a KRL at all is an error with the
    /// reason "KRL bad magic"; see [`is_krl`].
    pub fn parse(data: &[u8]) -> Result<Krl, Error> {
        if !is_krl(data) {
            return Err(Error::new("KRL bad magic"));
        }
        let mut r = Reader(&data[MAGIC.len()..]);
        let version = r.u32()?;
        if version != FORMAT_VERSION {
            return Err(Error::with_detail(
                format!("ssh_krl_from_blob: unsupported KRL format version {version}"),
                INVALID_FORMAT,
            ));
        }
        let mut krl = Krl {
            version: r.u64()?,
            generated: r.u64()?,
            ..Krl::default()
        };
        let _flags = r.u64()?;
        let _reserved = r.string()?;
        krl.comment = r.cstring()?;

        while !r.is_empty() {
            let section_type = r.u8()?;
            let mut section = Reader(r.string()?);
            match section_type {
                SECTION_CERTIFICATES => krl.parse_certificates(&mut section)?,
                SECTION_EXPLICIT_KEY => blobs(&mut section, &mut krl.keys, None)?,
                SECTION_FINGERPRINT_SHA1 => blobs(&mut section, &mut krl.sha1, Some(20))?,
                SECTION_FINGERPRINT_SHA256 => blobs(&mut section, &mut krl.sha256, Some(32))?,
                SECTION_EXTENSION => {
                    extension(&mut section, "KRL has invalid extension section", |name| {
                        format!("KRL contains unsupported critical section \"{name}\"")
                    })?
                }
                SECTION_SIGNATURE => {
                    // The section holds the signing key; the signature follows.
                    section = Reader(&[]);
                    r.string()?;
                }
                other => {
                    return Err(Error::with_detail(
                        format!("Unsupported KRL section {other}"),
                        INVALID_FORMAT,
                    ));
                }
            }
            if !section.is_empty() {
                return Err(Error::with_detail(
                    "KRL section contains unparsed data",
                    INVALID_FORMAT,
                ));
            }
        }
        Ok(krl)
    }

    fn parse_certificates(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let ca_blob = r.string()?;
        let _reserved = r.string()?;
        let ca = if ca_blob.is_empty() {
            None
        } else {
            Some(
                PublicKey::from_bytes(ca_blob)
                    .map_err(|_| Error::new(INVALID_FORMAT))?
                    .key_data()
                    .clone(),
            )
        };
        let index = match self.certificates.iter().position(|c| c.ca == ca) {
            Some(index) => index,
            None => {
                self.certificates.push(RevokedCertificates {
                    ca,
                    ..RevokedCertificates::default()
                });
                self.certificates.len() - 1
            }
        };
        let revoked = &mut self.certificates[index];
        let mut revoke = |lo: u64, hi: u64| {
            if lo > hi || lo == 0 {
                return Err(Error::new("invalid argument"));
            }
            revoked.serials.push((lo, hi));
            Ok(())
        };
        let mut key_ids = HashSet::new();
        while !r.is_empty() {
            let subsection_type = r.u8()?;
            let mut subsection = Reader(r.string()?);
            match subsection_type {
                CERT_SERIAL_LIST => {
                    while !subsection.is_empty() {
                        let serial = subsection.u64()?;
                        revoke(serial, serial)?;
                    }
                }
                CERT_SERIAL_RANGE => {
                    let lo = subsection.u64()?;
                    let hi = subsection.u64()?;
                    revoke(lo, hi)?;
                }
                CERT_SERIAL_BITMAP => {
                    let base = subsection.u64()?;
                    let bitmap = subsection.mpint()?;
                    let bits = bitmap.len() * 8;
                    for bit in 0..bits {
                        let byte = bitmap[bitmap.len() - 1 - bit / 8];
                        if byte & (1 << (bit % 8)) == 0 {
                            continue;
                        }
                        let serial = base.checked_add(bit as u64).ok_or_else(|| {
                            Error::with_detail(
                                "parse_revoked_certs: bitmap wraps u64",
                                INVALID_FORMAT,
                            )
                        })?;
                        revoke(serial, serial)?;
                    }
                }
                CERT_KEY_ID => {
                    while !subsection.is_empty() {
                        key_ids.insert(subsection.cstring()?);
                    }
                }
                CERT_EXTENSION => extension(
                    &mut subsection,
                    "KRL has invalid certificate extension subsection",
                    |name| {
                        format!(
                            "KRL contains unsupported critical certificate subsection \"{name}\""
                        )
                    },
                )?,
                other => {
                    return Err(Error::with_detail(
                        format!("Unsupported KRL certificate section {other}"),
                        INVALID_FORMAT,
                    ));
                }
            }
            if !subsection.is_empty() {
                return Err(Error::with_detail(
                    "KRL certificate section contains unparsed data",
                    INVALID_FORMAT,
                ));
            }
        }
        revoked.key_ids.extend(key_ids);
        Ok(())
    }

    /// Is the key revoked (`ssh_krl_check_key`)? A certificate is also
    /// revoked by its serial number or key ID, and if its CA's key is.
    pub fn is_revoked(&self, key: &KeyData, certificate: Option<&Certificate>) -> bool {
        if self.key_revoked(key) {
            return true;
        }
        let Some(certificate) = certificate else {
            return false;
        };
        let ca = certificate.signature_key();
        let by_ca = self.certificates.iter().find(|c| c.ca.as_ref() == Some(ca));
        let any_ca = self.certificates.iter().find(|c| c.ca.is_none());
        if [by_ca, any_ca]
            .into_iter()
            .flatten()
            .any(|revoked| certificate_revoked(revoked, certificate))
        {
            return true;
        }
        self.key_revoked(ca)
    }

    /// Is the plain key revoked, explicitly or by fingerprint?
    fn key_revoked(&self, key: &KeyData) -> bool {
        let blob = key_blob(key);
        self.sha1.contains(Sha1::digest(&blob).as_slice())
            || self.sha256.contains(Sha256::digest(&blob).as_slice())
            || self.keys.contains(&blob)
    }
}

/// Revoked by key ID, or (unless zero) by serial number.
fn certificate_revoked(revoked: &RevokedCertificates, certificate: &Certificate) -> bool {
    if revoked.key_ids.contains(certificate.key_id()) {
        return true;
    }
    let serial = certificate.serial();
    serial != 0
        && revoked
            .serials
            .iter()
            .any(|&(lo, hi)| lo <= serial && serial <= hi)
}

/// A section of strings, each `expected` bytes long if given.
fn blobs(
    r: &mut Reader<'_>,
    target: &mut HashSet<Vec<u8>>,
    expected: Option<usize>,
) -> Result<(), Error> {
    while !r.is_empty() {
        let blob = r.string()?;
        if expected.is_some_and(|len| blob.len() != len) {
            return Err(Error::with_detail(
                "blob_section: bad length",
                INVALID_FORMAT,
            ));
        }
        target.insert(blob.to_vec());
    }
    Ok(())
}

/// An extension (none are known): fine unless it is critical.
fn extension(
    r: &mut Reader<'_>,
    invalid: &str,
    critical: impl Fn(&str) -> String,
) -> Result<(), Error> {
    let parsed = (|| {
        let name = r.cstring()?;
        let is_critical = r.u8()?;
        r.string()?;
        Ok::<_, Error>((name, is_critical))
    })();
    let Ok((name, is_critical)) = parsed else {
        return Err(Error::with_detail(invalid, INVALID_FORMAT));
    };
    if !r.is_empty() {
        return Err(Error::with_detail(
            format!("{invalid}: trailing data"),
            INVALID_FORMAT,
        ));
    }
    if is_critical != 0 {
        return Err(Error::with_detail(critical(&name), "feature not supported"));
    }
    Ok(())
}

/// Whether `key` (or the CA of `certificate`) is in a plain list of
/// public keys, one per line (`sshkey_in_file`). Blank lines and `#`
/// comments are skipped; any other unreadable line is an error.
pub fn key_list_contains(
    text: &str,
    key: &KeyData,
    certificate: Option<&Certificate>,
) -> Result<bool, Error> {
    for line in text.lines() {
        let line = line.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split([' ', '\t']).filter(|f| !f.is_empty());
        let (Some(algorithm), Some(blob)) = (fields.next(), fields.next()) else {
            return Err(Error::new(INVALID_FORMAT));
        };
        let listed = match PublicKey::from_openssh(&format!("{algorithm} {blob}")) {
            Ok(listed) => listed.key_data().clone(),
            Err(_) => match Certificate::from_openssh(&format!("{algorithm} {blob}")) {
                Ok(listed) => listed.public_key().clone(),
                Err(_) => return Err(Error::new(INVALID_FORMAT)),
            },
        };
        if &listed == key || certificate.is_some_and(|c| c.signature_key() == &listed) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICzo7zTJEbePEgO0sq4yBF4spoOByo+Vd+uu/J4ZTzpX";
    const OTHER: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPcINqp0sLD2kaOJ3Vl21d61LH7dgfdOimuimh+4G7M6";

    fn key(text: &str) -> KeyData {
        PublicKey::from_openssh(text).unwrap().key_data().clone()
    }

    fn string(out: &mut Vec<u8>, data: &[u8]) {
        out.extend((data.len() as u32).to_be_bytes());
        out.extend(data);
    }

    /// A KRL with the given sections.
    fn krl(sections: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend(1u32.to_be_bytes());
        out.extend(7u64.to_be_bytes());
        out.extend(0u64.to_be_bytes());
        out.extend(0u64.to_be_bytes());
        string(&mut out, b"");
        string(&mut out, b"comment");
        for (section_type, data) in sections {
            out.push(*section_type);
            string(&mut out, data);
        }
        out
    }

    #[test]
    fn keys_and_fingerprints() {
        let blob = key_blob(&key(KEY));
        let mut explicit = Vec::new();
        string(&mut explicit, &blob);
        let mut sha256 = Vec::new();
        string(&mut sha256, &Sha256::digest(&blob));
        let mut sha1 = Vec::new();
        string(&mut sha1, &Sha1::digest(&blob));
        for section in [
            (SECTION_EXPLICIT_KEY, explicit),
            (SECTION_FINGERPRINT_SHA256, sha256),
            (SECTION_FINGERPRINT_SHA1, sha1),
        ] {
            let parsed = Krl::parse(&krl(&[section])).unwrap();
            assert_eq!(parsed.version, 7);
            assert_eq!(parsed.comment, "comment");
            assert!(parsed.is_revoked(&key(KEY), None));
            assert!(!parsed.is_revoked(&key(OTHER), None));
        }
    }

    #[test]
    fn invalid() {
        assert_eq!(
            Krl::parse(b"not a krl").unwrap_err().reason,
            "KRL bad magic"
        );
        let mut truncated = krl(&[]);
        truncated.truncate(truncated.len() - 3);
        assert_eq!(Krl::parse(&truncated).unwrap_err().reason, INCOMPLETE);
        let mut short = Vec::new();
        string(&mut short, &[0; 19]);
        assert!(Krl::parse(&krl(&[(SECTION_FINGERPRINT_SHA1, short)])).is_err());
        assert!(Krl::parse(&krl(&[(42, vec![])])).is_err());
        let mut critical = Vec::new();
        string(&mut critical, b"x@example.com");
        critical.push(1);
        string(&mut critical, b"");
        assert_eq!(
            Krl::parse(&krl(&[(SECTION_EXTENSION, critical.clone())]))
                .unwrap_err()
                .reason,
            "feature not supported"
        );
        critical[4 + 13] = 0;
        assert!(Krl::parse(&krl(&[(SECTION_EXTENSION, critical)])).is_ok());
    }

    #[test]
    fn bitmaps() {
        // Serials 10, 11 and 18 relative to base 10: bits 0, 1 and 8.
        let mut subsection = 10u64.to_be_bytes().to_vec();
        string(&mut subsection, &[0x01, 0x03]);
        let mut section = Vec::new();
        string(&mut section, b"");
        string(&mut section, b"");
        section.push(CERT_SERIAL_BITMAP);
        string(&mut section, &subsection);
        let parsed = Krl::parse(&krl(&[(SECTION_CERTIFICATES, section)])).unwrap();
        let serials = &parsed.certificates[0].serials;
        assert_eq!(serials, &[(10, 10), (11, 11), (18, 18)]);
    }

    #[test]
    fn serial_ranges() {
        let mut subsection = 3u64.to_be_bytes().to_vec();
        subsection.extend(9u64.to_be_bytes());
        let mut section = Vec::new();
        string(&mut section, b"");
        string(&mut section, b"");
        section.push(CERT_SERIAL_RANGE);
        string(&mut section, &subsection);
        let parsed = Krl::parse(&krl(&[(SECTION_CERTIFICATES, section)])).unwrap();
        let revoked = &parsed.certificates[0];
        assert!(revoked.ca.is_none());
        let in_range = |serial| {
            revoked
                .serials
                .iter()
                .any(|&(lo, hi)| lo <= serial && serial <= hi)
        };
        assert!(!in_range(2) && in_range(3) && in_range(9) && !in_range(10));
    }

    #[test]
    fn key_lists() {
        let list = format!("# revoked\n\n  {OTHER} comment\n{KEY}\n");
        assert!(key_list_contains(&list, &key(KEY), None).unwrap());
        assert!(!key_list_contains(&format!("{OTHER}\n"), &key(KEY), None).unwrap());
        assert!(key_list_contains("garbage\n", &key(KEY), None).is_err());
    }
}
