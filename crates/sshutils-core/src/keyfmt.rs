//! Human-readable key descriptions as printed by OpenSSH tools: type labels,
//! sizes, fingerprints and randomart.

use base64ct::{Base64Unpadded, Encoding};
use russh::keys::ssh_key::sha2::{Digest, Sha256, Sha512};
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, PublicKey, public::KeyData};
use sha1::Sha1;

/// Short uppercase type label: `ED25519`, `RSA`, `ECDSA`, `ED25519-SK`, ...
pub fn type_label(key: &KeyData) -> &'static str {
    match key.algorithm() {
        Algorithm::Dsa => "DSA",
        Algorithm::Ecdsa { .. } => "ECDSA",
        Algorithm::Ed25519 => "ED25519",
        Algorithm::Rsa { .. } => "RSA",
        Algorithm::SkEcdsaSha2NistP256 => "ECDSA-SK",
        Algorithm::SkEd25519 => "ED25519-SK",
        _ => "UNKNOWN",
    }
}

/// Key size in bits, as shown by `ssh-keygen -l`.
pub fn bits(key: &KeyData) -> u32 {
    match key {
        KeyData::Ecdsa(k) => curve_bits(k.curve()),
        KeyData::SkEcdsaSha2NistP256(_) => 256,
        KeyData::Ed25519(_) | KeyData::SkEd25519(_) => 256,
        KeyData::Rsa(k) => mpint_bits(k.n().as_positive_bytes().unwrap_or_default()),
        KeyData::Dsa(k) => mpint_bits(k.p().as_positive_bytes().unwrap_or_default()),
        _ => 0,
    }
}

pub fn curve_bits(curve: EcdsaCurve) -> u32 {
    match curve {
        EcdsaCurve::NistP256 => 256,
        EcdsaCurve::NistP384 => 384,
        EcdsaCurve::NistP521 => 521,
    }
}

fn mpint_bits(bytes: &[u8]) -> u32 {
    let bytes = match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        None => return 0,
    };
    (bytes.len() as u32 - 1) * 8 + (8 - bytes[0].leading_zeros())
}

/// Hash algorithms OpenSSH accepts for fingerprints (`-E`,
/// `FingerprintHash`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintHash {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl FingerprintHash {
    /// OpenSSH's name for the algorithm, as used in fingerprints.
    pub fn name(self) -> &'static str {
        match self {
            FingerprintHash::Md5 => "MD5",
            FingerprintHash::Sha1 => "SHA1",
            FingerprintHash::Sha256 => "SHA256",
            FingerprintHash::Sha512 => "SHA512",
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            FingerprintHash::Md5 => md5::compute(data).0.to_vec(),
            FingerprintHash::Sha1 => Sha1::digest(data).to_vec(),
            FingerprintHash::Sha256 => Sha256::digest(data).to_vec(),
            FingerprintHash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// Parse a fingerprint hash name (`md5`, `sha1`, `sha256`, `sha512`),
/// ignoring case.
pub fn parse_hash_alg(name: &str) -> Option<FingerprintHash> {
    match name.to_ascii_lowercase().as_str() {
        "md5" => Some(FingerprintHash::Md5),
        "sha1" => Some(FingerprintHash::Sha1),
        "sha256" => Some(FingerprintHash::Sha256),
        "sha512" => Some(FingerprintHash::Sha512),
        _ => None,
    }
}

/// Digest of the key's wire encoding.
fn key_digest(key: &KeyData, hash: FingerprintHash) -> Vec<u8> {
    let blob = PublicKey::from(key.clone())
        .to_bytes()
        .expect("encoding a public key into memory cannot fail");
    hash.digest(&blob)
}

/// `MD5:aa:bb:...` or `SHA256:<unpadded base64>` (likewise SHA1, SHA512).
pub fn fingerprint(key: &KeyData, hash: FingerprintHash) -> String {
    let digest = key_digest(key, hash);
    let encoded = match hash {
        FingerprintHash::Md5 => {
            let hex: Vec<String> = digest.iter().map(|b| format!("{b:02x}")).collect();
            hex.join(":")
        }
        _ => Base64Unpadded::encode_string(&digest),
    };
    format!("{}:{encoded}", hash.name())
}

/// Randomart ("visual host key") with OpenSSH's header and footer.
pub fn randomart(key: &KeyData, hash: FingerprintHash) -> String {
    let header = format!("[{} {}]", type_label(key), bits(key));
    let footer = format!("[{}]", hash.name());
    drunken_bishop(&key_digest(key, hash), &header, &footer)
}

/// The "drunken bishop" visualisation (Loss, Limmer, von Gernler, 2009).
fn drunken_bishop(digest: &[u8], header: &str, footer: &str) -> String {
    const W: usize = 17;
    const H: usize = 9;
    const SYMBOLS: &[u8] = b" .o+=*BOX@%&#/^SE";
    const START: u8 = SYMBOLS.len() as u8 - 2;
    const END: u8 = SYMBOLS.len() as u8 - 1;

    let mut field = [[0u8; H]; W];
    let (mut x, mut y) = (W / 2, H / 2);
    for &byte in digest {
        let mut bits = byte;
        for _ in 0..4 {
            x = if bits & 1 != 0 {
                (x + 1).min(W - 1)
            } else {
                x.saturating_sub(1)
            };
            y = if bits & 2 != 0 {
                (y + 1).min(H - 1)
            } else {
                y.saturating_sub(1)
            };
            if field[x][y] < START - 1 {
                field[x][y] += 1;
            }
            bits >>= 2;
        }
    }
    field[W / 2][H / 2] = START;
    field[x][y] = END;

    let border = |label: &str| {
        let pad = W.saturating_sub(label.len());
        format!(
            "+{}{}{}+",
            "-".repeat(pad / 2),
            label,
            "-".repeat(pad - pad / 2)
        )
    };
    let mut out = border(header);
    out.push('\n');
    for row in 0..H {
        out.push('|');
        for column in &field {
            out.push(SYMBOLS[column[row] as usize] as char);
        }
        out.push_str("|\n");
    }
    out.push_str(&border(footer));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures and expected output from OpenSSH 10.5 (`ssh-keygen -lv -E <hash>`).
    const ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAk7shWwUfM2IBq7V0QnZZSORfGadoAfaU8uT8ZHkMv6 fixture";
    const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC77DgoaxV9vMimAdVNkoopaftEXaGCqSCCNIhEe2vSkbK62eBSRzyalLTl0bLuEGjv2VWsk9+3MivPYoUoAvJi2lQeZkj8o3PiDi5dHrZ7BSFrdRLh0J34rfag1TnH4dO7dm1HihQ84GU4pAs2GuMaJFOrbbty14klRSgPMKCmLQ== fixture";

    fn key(line: &str) -> KeyData {
        PublicKey::from_openssh(line).unwrap().key_data().clone()
    }

    #[test]
    fn fingerprints_match_openssh() {
        let k = key(ED25519);
        assert_eq!(
            fingerprint(&k, FingerprintHash::Md5),
            "MD5:ac:0c:36:c4:49:b6:55:66:cb:0e:99:23:b2:ce:1c:a1"
        );
        assert_eq!(
            fingerprint(&k, FingerprintHash::Sha1),
            "SHA1:cy8qStz9cyujTPmfJARNjyrqmSQ"
        );
        assert_eq!(
            fingerprint(&k, FingerprintHash::Sha256),
            "SHA256:XyWqXluk1ylOE79eUbS7svWZeEYmTPZe8ygK46g8c70"
        );
        assert_eq!(
            fingerprint(&k, FingerprintHash::Sha512),
            "SHA512:NXPNXo99eC7+s5R2Gkd6uifN73vY6U++m8WK93+rVhBk2SDFds/Str2zPMV0VbRWTq/dRd6Q/ka/yqEvMK5kGw"
        );
    }

    #[test]
    fn randomart_matches_openssh() {
        let md5 = "\
+--[ED25519 256]--+
|    o ..+        |
|   + + * .       |
|  o * = o        |
| . = . =         |
|E o +   S        |
| + o + .         |
|  +   o          |
|                 |
|                 |
+------[MD5]------+";
        let sha512 = "\
+--[ED25519 256]--+
|           .+==oB|
|            oB.O*|
|          + o.==X|
|         . + o+B%|
|        S     *B&|
|         o     OX|
|       E. o  .=X&|
|      o o. .o+O^@|
|       o.  .=*X^^|
+----[SHA512]-----+";
        let rsa_sha256 = "\
+---[RSA 1024]----+
|E                |
|.                |
| . .. . .   .    |
|  . .o o * o     |
|o  .  = S * .    |
|*o. .o = * +     |
|+=o  .= . = .    |
|o+ =.o ooo .     |
|=o*++ oooo.      |
+----[SHA256]-----+";
        assert_eq!(randomart(&key(ED25519), FingerprintHash::Md5), md5);
        assert_eq!(randomart(&key(ED25519), FingerprintHash::Sha512), sha512);
        assert_eq!(randomart(&key(RSA), FingerprintHash::Sha256), rsa_sha256);
    }

    #[test]
    fn key_sizes() {
        assert_eq!(bits(&key(ED25519)), 256);
        assert_eq!(bits(&key(RSA)), 1024);
        assert_eq!(type_label(&key(RSA)), "RSA");
    }

    #[test]
    fn hash_names() {
        assert_eq!(parse_hash_alg("SHA1"), Some(FingerprintHash::Sha1));
        assert_eq!(parse_hash_alg("sha3"), None);
    }
}
