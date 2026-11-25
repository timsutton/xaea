//! Archive keys for the encrypting (profile 1) AEAs Apple ships in restore
//! images, and how to obtain them.
//!
//! Each such archive carries its 32-byte symmetric key in its own auth
//! data, wrapped for a P-256 key that Apple publishes (unauthenticated) at
//! `com.apple.wkms.fcs-key-url`:
//!
//! * `com.apple.wkms.fcs-response` is JSON with base64 `enc-request` (the
//!   HPKE encapsulated key: an uncompressed P-256 point) and `wrapped-key`
//!   (the HPKE ciphertext: 32 key bytes + 16 GCM tag bytes).
//! * The wrap is RFC 9180 HPKE, base mode, DHKEM(P-256, HKDF-SHA256),
//!   HKDF-SHA256, AES-256-GCM, with empty `info` and empty AAD.
//! * The URL's last path component is `base64url(SHA-256(public point))`
//!   of that key pair, so a supplied PEM can be matched to the archive.
//!
//! xaea fetches the PEM itself (`net::fetch_key_pem`, only from Apple's
//! hosts) unless given `--key`, `--key-pem` or `--offline`.

use crate::kdf::Key;
use crate::sigverify::base64_decode;
use anyhow::{Context, Result, bail, ensure};
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};

const FCS_RESPONSE: &str = "com.apple.wkms.fcs-response";
const FCS_KEY_URL: &str = "com.apple.wkms.fcs-key-url";

fn auth_value<'a>(auth: &'a [(String, Vec<u8>)], key: &str) -> Option<&'a [u8]> {
    auth.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_slice())
}

/// Where the archive says its unwrapping key is published, if it does.
pub fn key_url(auth: &[(String, Vec<u8>)]) -> Option<&str> {
    auth_value(auth, FCS_KEY_URL).and_then(|v| std::str::from_utf8(v).ok())
}

/// Parse a symmetric key given on the command line: `base64:…` or `hex:…`
/// (Apple's `aea -key-value` spelling), or bare base64 / 64 hex digits.
pub fn parse_key(s: &str) -> Result<Key> {
    let s = s.trim();
    let bytes = if let Some(b) = s.strip_prefix("base64:") {
        base64_decode(b.as_bytes())?
    } else if let Some(h) = s.strip_prefix("hex:") {
        unhex(h)?
    } else if s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()) {
        unhex(s)?
    } else {
        base64_decode(s.as_bytes()).context("key is neither base64 nor 64 hex digits")?
    };
    bytes
        .as_slice()
        .try_into()
        .ok()
        .with_context(|| format!("key must be 32 bytes, got {}", bytes.len()))
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    ensure!(s.len().is_multiple_of(2), "odd-length hex key");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("bad hex digit in key"))
        .collect()
}

/// Unwrap the archive key from its `fcs-response` with the private key in
/// `pem` (PKCS#8, as served from the archive's key URL).
pub fn unwrap_key(auth: &[(String, Vec<u8>)], pem: &[u8]) -> Result<Key> {
    let resp = auth_value(auth, FCS_RESPONSE)
        .context("archive has no com.apple.wkms.fcs-response: its key is not wrapped for a PEM; pass --key instead")?;
    let resp: serde_json::Value =
        serde_json::from_slice(resp).context("fcs-response is not JSON")?;
    let field = |name: &str| -> Result<Vec<u8>> {
        let s = resp[name]
            .as_str()
            .with_context(|| format!("fcs-response has no `{name}`"))?;
        base64_decode(s.as_bytes()).with_context(|| format!("fcs-response `{name}`"))
    };
    let (enc, wrapped) = (field("enc-request")?, field("wrapped-key")?);

    let pem = std::str::from_utf8(pem).context("key PEM is not text")?;
    let sk = p256::SecretKey::from_pkcs8_pem(pem)
        .context("key PEM is not a PKCS#8 P-256 private key")?;
    let pk_r = sk.public_key().to_sec1_point(false);
    if let Some(url) = key_url(auth) {
        let id = url.rsplit('/').next().unwrap_or_default();
        ensure!(
            id == base64url(&Sha256::digest(pk_r.as_bytes())),
            "the key PEM is not the one this archive names ({url})"
        );
    }
    hpke_open(&sk, pk_r.as_bytes(), &enc, &wrapped)
}

fn base64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = c
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &x)| n | u32::from(x) << (16 - 8 * i));
        for i in 0..4 {
            s.push(if i <= c.len() {
                A[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    s
}

// ---- RFC 9180 HPKE, base mode, open only -------------------------------

const KEM_P256: u16 = 0x0010;
const KDF_SHA256: u16 = 0x0001;
const AEAD_AES256GCM: u16 = 0x0002;

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key size");
    for part in [b"HPKE-v1".as_slice(), suite, label, ikm] {
        m.update(part);
    }
    m.finalize().into_bytes().into()
}

fn labeled_expand<const N: usize>(suite: &[u8], prk: &[u8], label: &[u8], info: &[u8]) -> [u8; N] {
    let len = u16::try_from(N).expect("short output").to_be_bytes();
    let info = [&len[..], b"HPKE-v1", suite, label, info].concat();
    let mut out = [0u8; N];
    hkdf::Hkdf::<Sha256>::from_prk(prk)
        .expect("PRK is a full hash length")
        .expand(&info, &mut out)
        .expect("HKDF expand of fixed size cannot fail");
    out
}

fn hpke_open(sk: &p256::SecretKey, pk_r: &[u8], enc: &[u8], ct: &[u8]) -> Result<Key> {
    use aes_gcm::aead::{Aead, KeyInit as _};

    let pk_e = p256::PublicKey::from_sec1_bytes(enc).context("enc-request is not a P-256 point")?;
    let dh = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk_e.as_affine());

    // DHKEM(P-256): shared_secret = ExtractAndExpand(dh, enc || pkR).
    let kem = [b"KEM".as_slice(), &KEM_P256.to_be_bytes()].concat();
    let eae_prk = labeled_extract(&kem, b"", b"eae_prk", dh.raw_secret_bytes());
    let shared: [u8; 32] = labeled_expand(&kem, &eae_prk, b"shared_secret", &[enc, pk_r].concat());

    // KeySchedule, mode_base, empty psk / psk_id / info.
    let suite = [
        b"HPKE".as_slice(),
        &KEM_P256.to_be_bytes(),
        &KDF_SHA256.to_be_bytes(),
        &AEAD_AES256GCM.to_be_bytes(),
    ]
    .concat();
    let ctx = [
        &[0u8][..],
        &labeled_extract(&suite, b"", b"psk_id_hash", b""),
        &labeled_extract(&suite, b"", b"info_hash", b""),
    ]
    .concat();
    let secret = labeled_extract(&suite, &shared, b"secret", b"");
    let key: [u8; 32] = labeled_expand(&suite, &secret, b"key", &ctx);
    let nonce: [u8; 12] = labeled_expand(&suite, &secret, b"base_nonce", &ctx);

    let Ok(plain) = aes_gcm::Aes256Gcm::new(&key.into()).decrypt(&nonce.into(), ct) else {
        bail!("wrapped-key does not open with this PEM (GCM tag mismatch)");
    };
    plain
        .as_slice()
        .try_into()
        .ok()
        .with_context(|| format!("unwrapped key is {} bytes, not 32", plain.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_spellings() {
        let want = [0xABu8; 32];
        let hex = "ab".repeat(32);
        let b64 = "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=";
        for s in [
            hex.clone(),
            format!("hex:{hex}"),
            b64.into(),
            format!("base64:{b64}"),
        ] {
            assert_eq!(parse_key(&s).unwrap(), want, "{s}");
        }
        assert!(parse_key("base64:AAAA").is_err(), "short key");
    }

    #[test]
    fn base64url_matches_reference() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"\xfb\xff"), "-_8=");
        assert_eq!(base64url(b"foob"), "Zm9vYg==");
    }
}
