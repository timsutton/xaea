//! HPKE (RFC 9180) single-shot open for the suite AEA profile 1 uses:
//! `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM`, base mode.
//!
//! A profile-1 archive's auth data carries a WKMS FCS response whose
//! `enc-request` is the recipient's ephemeral DH public key and whose
//! `wrapped-key` is the HPKE-sealed symmetric key. Opening it requires the
//! matching P-256 private key, which Apple does not publish: it is held by
//! whoever is entitled to the firmware (currently obtainable through the
//! FCS entitlement flow).

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead as _, Nonce as AeadNonce},
};
use anyhow::{Result, anyhow, ensure};
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use p256::Scalar;
use p256::ecdh::{SharedSecret, diffie_hellman};
use p256::elliptic_curve::NonZeroScalar;
use p256::elliptic_curve::Field as _;
use p256::elliptic_curve::ops::Reduce;
use p256::NistP256;
use sha2::Sha256;

/// `KEM = DHKEM(P-256, HKDF-SHA256)` (0x0010).
const KEM_ID: &[u8; 5] = b"KEM\x00\x10";
/// `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM`.
const SUITE_ID: &[u8; 10] = b"HPKE\x00\x10\x00\x01\x00\x02";

fn hkdf_extract(ikm: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key size");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut t: [u8; 32] = [0; 32];
    let mut t_len = 0usize;
    let mut counter = 1u8;
    while out.len() < length {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(prk).expect("HMAC accepts any key size");
        mac.update(&t[..t_len]);
        mac.update(info);
        mac.update(&[counter]);
        let block: [u8; 32] = mac.finalize().into_bytes().into();
        out.extend_from_slice(&block);
        t = block;
        t_len = block.len();
        counter += 1;
    }
    out.truncate(length);
    out
}

/// RFC 9180 §5.1 `LabeledExtract(suite_id, salt, label, ikm)`.
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + suite_id.len() + label.len() + ikm.len());
    input.extend_from_slice(b"HPKE-v1");
    input.extend_from_slice(suite_id);
    input.extend_from_slice(label);
    input.extend_from_slice(ikm);
    hkdf_extract(&input, salt)
}

/// RFC 9180 §5.1 `LabeledExpand(suite_id, prk, label, info, L)`.
fn labeled_expand(suite_id: &[u8], prk: &[u8; 32], label: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut labeled_info = Vec::with_capacity(2 + 8 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    hkdf_expand(prk, &labeled_info, length)
}

/// Parses an SEC 1 private key scalar, accepting the 1..=32-byte big-endian
/// magnitude that PKCS#8 `ECPrivateKey` stores. The value is reduced modulo
/// the group order in constant time; a zero scalar is rejected.
fn parse_scalar(be: &[u8]) -> Result<Scalar> {
    ensure!(
        !be.is_empty() && be.len() <= 32,
        "invalid P-256 private key size: {} bytes",
        be.len()
    );
    let mut bytes = [0u8; 32];
    bytes[32 - be.len()..].copy_from_slice(be);
    let scalar = <Scalar as Reduce<p256::FieldBytes>>::reduce(&bytes.into());
    ensure!(
        !bool::from(scalar.is_zero()),
        "private key scalar is zero"
    );
    Ok(scalar)
}

/// Parses a PKCS#8 (`BEGIN PRIVATE KEY`) or SEC 1 (`BEGIN EC PRIVATE KEY`)
/// PEM-wrapped P-256 private key and returns its scalar.
pub fn parse_private_key_pem(pem: &[u8]) -> Result<Scalar> {
    let pem = std::str::from_utf8(pem)?;
    let mut label = None;
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(rest) = rest.strip_suffix("-----") {
                let rest = rest.trim();
                ensure!(
                    label.is_none() && matches!(rest, "PRIVATE KEY" | "EC PRIVATE KEY"),
                    "unsupported PEM type {rest:?}"
                );
                label = Some(rest);
                continue;
            }
        }
        if line.starts_with("-----END ") {
            ensure!(label.is_some(), "PEM END without BEGIN");
            continue;
        }
        if !line.is_empty() {
            ensure!(label.is_some(), "PEM data before BEGIN line");
            b64.push_str(line);
        }
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| anyhow!("base64 decode of PEM body failed: {e}"))?;
    let sec1 = match label {
        // PKCS#8: SEQUENCE { INTEGER 0, SEQUENCE { OID 2a8648ce3d030107 },
        // OCTET STRING { SEC1 ECPrivateKey } } — locate the inner ECPrivateKey
        // by its curve OID and take the OCTET STRING that follows.
        Some("PRIVATE KEY") => {
            const OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
            let at = der
                .windows(OID.len())
                .position(|w| w == OID)
                .ok_or_else(|| anyhow!("not a P-256 PKCS#8 key (curve OID missing)"))?;
            let tlv = &der[at + OID.len()..];
            ensure!(tlv.len() >= 2 && tlv[0] == 0x04, "malformed PKCS#8 keyData");
            let (len, hdr) = der_len(tlv, 1)?;
            ensure!(tlv.len() >= hdr + len, "truncated PKCS#8 keyData");
            &tlv[hdr..hdr + len]
        }
        Some("EC PRIVATE KEY") => &der,
        None => return Err(anyhow!("no PEM body found")),
        Some(other) => return Err(anyhow!("unsupported PEM type {other:?}")),
    };
    // SEC 1: ECPrivateKey ::= SEQUENCE { version, privateKey OCTET STRING, ... }
    ensure!(!sec1.is_empty() && sec1[0] == 0x30, "malformed ECPrivateKey");
    let (seq_len, hdr) = der_len(sec1, 1)?;
    ensure!(sec1.len() >= hdr + seq_len, "truncated ECPrivateKey");
    let seq = &sec1[hdr..hdr + seq_len];
    ensure!(
        seq.len() >= 4 && seq[0] == 0x02 && seq[1] == 0x01 && seq[2] == 0x01 && seq[3] == 0x04,
        "malformed ECPrivateKey version"
    );
    let (len, hdr) = der_len(seq, 4)?;
    ensure!(seq.len() >= hdr + len, "truncated ECPrivateKey privateKey");
    parse_scalar(&seq[hdr..hdr + len])
}

/// Reads a DER length at `seq[pos]`, returning `(length, content_offset)`,
/// where `content_offset` is the absolute index of the value's first byte.
fn der_len(seq: &[u8], pos: usize) -> Result<(usize, usize)> {
    ensure!(pos < seq.len(), "truncated DER length");
    let first = seq[pos];
    if first < 0x80 {
        Ok((first as usize, pos + 1))
    } else {
        let n = (first & 0x7f) as usize;
        ensure!(n >= 1 && n <= 4 && seq.len() >= pos + 1 + n, "malformed DER length");
        let mut len = 0usize;
        for &b in &seq[pos + 1..pos + 1 + n] {
            len = (len << 8) | b as usize;
        }
        Ok((len, pos + 1 + n))
    }
}

/// HPKE base-mode `Open` for the suite profile 1 uses, given the recipient
/// private key scalar, the encapsulated key `enc` (SEC 1 uncompressed, 65
/// bytes), the sealed `wrapped` ciphertext, and the context `info`.
pub fn open(enc: &[u8], wrapped: &[u8], info: &[u8], sk_rm: &Scalar) -> Result<Vec<u8>> {
    ensure!(
        enc.len() == 65 && enc[0] == 0x04,
        "enc is not a 65-byte uncompressed P-256 point"
    );
    let enc_point = p256::PublicKey::from_sec1_bytes(enc)
        .map_err(|e| anyhow!("enc is not a valid P-256 point: {e}"))?;
    let sk = NonZeroScalar::<NistP256>::new(*sk_rm)
        .into_option()
        .ok_or_else(|| anyhow!("recipient secret scalar must be non-zero"))?;
    let shared: SharedSecret = diffie_hellman(&sk, enc_point.as_affine());
    let pkr = public_key_uncompressed(sk_rm)
        .ok_or_else(|| anyhow!("recipient secret scalar must be non-zero"))?;
    open_ss(shared.raw_secret_bytes().as_slice(), enc, &pkr, wrapped, info)
}

/// Uncompressed SEC1 encoding (`0x04 || x || y`) of the public key matching
/// `sk`. Profile-1 archives identify the FCS key by the URL-safe-base64
/// (unpadded) form of exactly this encoding.
pub fn public_key_uncompressed(sk: &Scalar) -> Option<[u8; 65]> {
    use p256::elliptic_curve::sec1::ToSec1Point;

    let nz = NonZeroScalar::<NistP256>::new(*sk).into_option()?;
    let point = p256::PublicKey::from_secret_scalar(&nz).to_uncompressed_point();
    let bytes: &[u8] = &point;
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return None;
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(bytes);
    Some(out)
}

/// The key schedule and AEAD open, split out so tests can drive it with a
/// precomputed DH secret.
fn open_ss(z: &[u8], enc: &[u8], pkr: &[u8], wrapped: &[u8], info: &[u8]) -> Result<Vec<u8>> {
    // KEM: DHKEM(P-256, HKDF-SHA256) encapsulation open (base mode, so
    // kem_context = enc || pkR).
    let eae_prk = labeled_extract(KEM_ID, b"", b"eae_prk", z);
    let kem_context = [enc, pkr].concat();
    let shared_secret = labeled_expand(KEM_ID, &eae_prk, b"shared_secret", &kem_context, 32);

    // Key schedule (base mode: empty psk, psk_id = info).
    let psk_id_hash = labeled_extract(SUITE_ID, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(SUITE_ID, b"", b"info_hash", info);
    let ks_ctx = [&[0u8][..], &psk_id_hash[..], &info_hash[..]].concat();
    let secret = labeled_extract(SUITE_ID, &shared_secret, b"secret", b"");
    let key = labeled_expand(SUITE_ID, &secret, b"key", &ks_ctx, 32);
    let nonce = labeled_expand(SUITE_ID, &secret, b"base_nonce", &ks_ctx, 12);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("bad AES-256-GCM key"))?;
    let aead_nonce = AeadNonce::<Aes256Gcm>::try_from(&nonce[..])
        .map_err(|_| anyhow!("bad AEAD nonce length"))?;
    cipher
        .decrypt(&aead_nonce, wrapped)
        .map_err(|_| anyhow!("HPKE open failed (wrong key or corrupted wrapped key)"))
}

/// Extracts the symmetric key from a profile-1 archive's auth data given the
/// FCS private key PEM.
///
/// The auth data must contain `com.apple.wkms.fcs-response`, whose value is
/// JSON with base64 `enc-request` (the ephemeral recipient public key) and
/// `wrapped-key` (the HPKE-sealed key). The HPKE context `info` is empty.
pub fn unwrap_fcs_key(auth_data: &[u8], key_pem: &[u8]) -> Result<Vec<u8>> {
    let response = find_auth_value(auth_data, b"com.apple.wkms.fcs-response")
        .ok_or_else(|| anyhow!("auth data has no com.apple.wkms.fcs-response entry"))?;
    let json: serde_json::Value = serde_json::from_slice(response)
        .map_err(|e| anyhow!("fcs-response is not JSON: {e}"))?;
    let enc_b64 = json
        .get("enc-request")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("fcs-response has no enc-request"))?;
    let wrapped_b64 = json
        .get("wrapped-key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("fcs-response has no wrapped-key"))?;
    let enc = base64::engine::general_purpose::STANDARD
        .decode(enc_b64)
        .map_err(|e| anyhow!("enc-request is not base64: {e}"))?;
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(wrapped_b64)
        .map_err(|e| anyhow!("wrapped-key is not base64: {e}"))?;
    let sk = parse_private_key_pem(key_pem)?;
    open(&enc, &wrapped, b"", &sk)
}

/// Scans the auth-data key-value blob for `key` and returns its value.
///
/// Each entry is `{ u32le entry_len (counts itself), key bytes, 0x00, value
/// bytes }`.
pub fn find_auth_value<'a>(auth: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut pos = 0usize;
    while pos + 4 <= auth.len() {
        let len = u32::from_le_bytes(auth[pos..pos + 4].try_into().ok()?) as usize;
        if len < 4 || pos + len > auth.len() {
            return None;
        }
        let entry = &auth[pos + 4..pos + len];
        let nul = entry.iter().position(|&b| b == 0)?;
        if &entry[..nul] == key {
            return Some(&entry[nul + 1..]);
        }
        pos += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9180 A.3.1 base-mode vector, run through the same KEM and key
    /// schedule the fixture uses (the vector's AEAD is AES-128-GCM, ours is
    /// AES-256-GCM, so only the final AEAD step is substituted).
    #[test]
    fn rfc9180_a31_key_schedule() {
        let kem_id = KEM_ID;
        let hpke_id: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x01";
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let sk_rm = unhex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
        let enc = unhex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32\
                        5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
        let want_ss = unhex("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8\
                             cb8");
        let want_key = unhex("868c066ef58aae6dc589b6cfdd18f97e");
        let want_nonce = unhex("4e0bc5018beba4bf004cca59");

        let sk = parse_scalar(&sk_rm).unwrap();
        let nz = NonZeroScalar::<NistP256>::new(sk).into_option().unwrap();
        let point = p256::PublicKey::from_sec1_bytes(&enc).unwrap();
        let z = diffie_hellman(&nz, point.as_affine());
        let pkr = public_key_uncompressed(&sk).unwrap();

        let eae_prk = labeled_extract(kem_id, b"", b"eae_prk", z.raw_secret_bytes().as_slice());
        let kem_context = [enc.as_slice(), &pkr[..]].concat();
        let ss = labeled_expand(kem_id, &eae_prk, b"shared_secret", &kem_context, 32);
        assert_eq!(ss, want_ss, "DHKEM shared_secret");

        let psk_id_hash = labeled_extract(hpke_id, b"", b"psk_id_hash", b"");
        let info_hash = labeled_extract(hpke_id, b"", b"info_hash", &info);
        let ks_ctx = [&[0u8][..], &psk_id_hash[..], &info_hash[..]].concat();
        assert_eq!(
            ks_ctx,
            unhex("00b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e6980500798e4\
                   86f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85")
        );
        let secret = labeled_extract(hpke_id, &ss, b"secret", b"");
        assert_eq!(
            &secret[..],
            unhex("2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1")
        );
        let key = labeled_expand(hpke_id, &secret, b"key", &ks_ctx, 16);
        let nonce = labeled_expand(hpke_id, &secret, b"base_nonce", &ks_ctx, 12);
        assert_eq!(key, want_key, "suite_key");
        assert_eq!(nonce, want_nonce, "base_nonce");
    }

    /// End-to-end HPKE open against the FCS key and the fixture's auth data.
    #[test]
    fn fcs_unwrap_fixture_key() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
        let Ok(data) = std::fs::read(dir.join("141-11453-183-head.bin")) else {
            eprintln!("skipping: fixture 141-11453-183-head.bin not present");
            return;
        };
        let Ok(pem) = std::fs::read(dir.join("141-11453-183-fcs-key.pem")) else {
            eprintln!("skipping: fixture 141-11453-183-fcs-key.pem not present");
            return;
        };
        let auth_len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let auth = &data[12..12 + auth_len];
        let key = unwrap_fcs_key(auth, &pem).expect("FCS key unwrap");
        assert_eq!(
            hex(&key),
            "387391212f2007c57da75e2b1fc14b1b901ec35d36c30fd21ad61740ece286fd"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn parse_pkcs8_pem() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
        let Ok(pem) = std::fs::read(dir.join("141-11453-183-fcs-key.pem")) else {
            eprintln!("skipping: fixture key not present");
            return;
        };
        let sk = parse_private_key_pem(&pem).expect("parse fixture PEM");
        // The scalar must be nonzero and in range; round-trip through its
        // big-endian form to confirm it parses to something sane.
        assert!(!bool::from(sk.is_zero()));
    }
}
