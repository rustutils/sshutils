//! Human-readable key descriptions as printed by OpenSSH tools.

use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg, PublicKey, public::KeyData};

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

/// Parse an `-E` fingerprint hash name.
pub fn parse_hash_alg(name: &str) -> Option<FingerprintHash> {
    match name.to_ascii_lowercase().as_str() {
        "sha256" => Some(FingerprintHash::Sha256),
        "md5" => Some(FingerprintHash::Md5),
        _ => None,
    }
}

/// Fingerprint hashes OpenSSH accepts. MD5 isn't in `ssh_key::HashAlg`, so we
/// compute it ourselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintHash {
    Sha256,
    Md5,
}

/// `SHA256:base64` or `MD5:aa:bb:...`
pub fn fingerprint(key: &KeyData, hash: FingerprintHash) -> String {
    match hash {
        FingerprintHash::Sha256 => key.fingerprint(HashAlg::Sha256).to_string(),
        FingerprintHash::Md5 => {
            let blob = PublicKey::from(key.clone()).to_bytes().unwrap_or_default();
            let digest = md5_digest(&blob);
            let hex: Vec<String> = digest.iter().map(|b| format!("{b:02x}")).collect();
            format!("MD5:{}", hex.join(":"))
        }
    }
}

/// Randomart ("visual host key") with OpenSSH's header/footer.
pub fn randomart(key: &KeyData, hash: FingerprintHash) -> String {
    let header = format!("[{} {}]", type_label(key), bits(key));
    match hash {
        FingerprintHash::Sha256 => key.fingerprint(HashAlg::Sha256).to_randomart(&header),
        FingerprintHash::Md5 => {
            let blob = PublicKey::from(key.clone()).to_bytes().unwrap_or_default();
            drunken_bishop(&md5_digest(&blob), &header, "[MD5]")
        }
    }
}

/// The "drunken bishop" visualisation (Loss, Limmer, von Gernler, 2009),
/// used for digests `ssh_key` can't render (MD5).
fn drunken_bishop(digest: &[u8], header: &str, footer: &str) -> String {
    const W: usize = 17;
    const H: usize = 9;
    const SYMBOLS: &[u8] = b" .o+=*BOX@%&#/^SE";
    let mut field = [[0u8; H]; W];
    let (mut x, mut y) = (W / 2, H / 2);
    for byte in digest {
        let mut b = *byte;
        for _ in 0..4 {
            x = if b & 1 != 0 {
                (x + 1).min(W - 1)
            } else {
                x.saturating_sub(1)
            };
            y = if b & 2 != 0 {
                (y + 1).min(H - 1)
            } else {
                y.saturating_sub(1)
            };
            let len = SYMBOLS.len() as u8 - 2;
            if field[x][y] < len - 1 {
                field[x][y] += 1;
            }
            b >>= 2;
        }
    }
    let start = (W / 2, H / 2);
    field[start.0][start.1] = SYMBOLS.len() as u8 - 2;
    field[x][y] = SYMBOLS.len() as u8 - 1;

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
        for col in field.iter() {
            out.push(SYMBOLS[col[row] as usize] as char);
        }
        out.push_str("|\n");
    }
    out.push_str(&border(footer));
    out
}

/// Minimal MD5 (RFC 1321). Only used for legacy `-E md5` fingerprints.
fn md5_digest(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32)
        .collect();
    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk
            .chunks(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, v) in [a0, b0, c0, d0].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_vectors() {
        let hex = |d: [u8; 16]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(md5_digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex(md5_digest(b"The quick brown fox jumps over the lazy dog")),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }
}
