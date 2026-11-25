//! ECDSA/RSA signature + certificate-chain verification for AEA profile 0.
//!
//! The file signature is an ECDSA P-256 signature over SHA-256 of the file
//! prefix through the first cluster header MAC, with the signature field
//! itself zeroed (kinnay FORMAT.md "Signature"). The signing certificate
//! chain arrives in the auth data as PEM.

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use std::fmt::Write;
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate};

/// Vendored trust anchors (Apple Root CA – G3) for `trusted_root`.
pub const APPLE_ROOTS: &[u8] = include_bytes!("../assets/AppleRootCA.pem");

const OID_ECDSA_SHA1: &[u8] = &[42, 134, 72, 206, 61, 4, 3, 1];
const OID_ECDSA_SHA256: &[u8] = &[42, 134, 72, 206, 61, 4, 3, 2];
const OID_ECDSA_SHA384: &[u8] = &[42, 134, 72, 206, 61, 4, 3, 3];
const OID_ECDSA_SHA512: &[u8] = &[42, 134, 72, 206, 61, 4, 3, 4];
const OID_RSA_SHA1: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 1, 5];
const OID_RSA_SHA256: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 1, 11];
const OID_RSA_SHA384: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 1, 12];
const OID_RSA_SHA512: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 1, 13];
const OID_EC_PUBLIC: &[u8] = &[42, 134, 72, 206, 61, 2, 1];
const OID_RSA_ENC: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 1, 1];

/// Split a (possibly multi-cert) PEM blob into DER certificates.
pub fn split_pem(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut acc: Vec<u8> = Vec::new();
    let mut in_block = false;
    for line in pem.split(|&c| c == b'\n') {
        let t = line.trim_ascii();
        if t.starts_with(b"-----BEGIN") {
            in_block = true;
            acc.clear();
        } else if t.starts_with(b"-----END") {
            ensure!(in_block, "PEM END without BEGIN");
            out.push(base64_decode(&acc)?);
            in_block = false;
        } else if in_block && !t.is_empty() {
            acc.extend_from_slice(t);
        }
    }
    ensure!(!out.is_empty(), "no PEM certificates found");
    Ok(out)
}

fn short_name(der: &[u8]) -> String {
    format!(
        "{} bytes: {}..{}",
        der.len(),
        hex(&der[..4.min(der.len())]),
        hex(&der[der.len().saturating_sub(4)..])
    )
}
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, c| {
            let _ = write!(s, "{c:02x}");
            s
        })
}

fn base64_decode(b: &[u8]) -> Result<Vec<u8>> {
    // minimal base64 decoder (standard alphabet)
    fn val(c: u8) -> Result<u32> {
        Ok(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => bail!("bad base64 byte"),
        })
    }
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    for chunk in b.chunks(4) {
        let mut acc: u32 = 0;
        let mut bits = 0;
        for &c in chunk {
            if c == b'=' {
                break;
            }
            acc = (acc << 6) | val(c)?;
            bits += 6;
        }
        // Emit whole bytes from the top of the accumulator; the leftover
        // <8 bits are the padding remainder and get dropped.
        for i in 0..bits / 8 {
            out.push((acc >> (bits - 8 * (i + 1))) as u8);
        }
    }
    Ok(out)
}

/// Minimal DER walker — enough to pull tbs/span, SPKI, signature, OIDs
/// out of an X.509 certificate without leaning on any parser's internals.
struct Der<'a> {
    b: &'a [u8],
    i: usize,
}

type Tlv = (u8, usize, usize); // tag, content_start, content_len

impl<'a> Der<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn tlv(&mut self) -> Result<Tlv> {
        let start = self.i;
        ensure!(start < self.b.len(), "der eof");
        let tag = self.b[start];
        let mut i = start + 1;
        if tag & 0x1f == 0x1f {
            // High-tag-number form: continuation octets, all bounds-checked
            // (hostile bytes must error, not panic).
            while self.b.get(i).is_some_and(|b| b & 0x80 != 0) {
                i += 1;
            }
            ensure!(i < self.b.len(), "der eof (high tag)");
            i += 1;
        }
        ensure!(i < self.b.len(), "der eof (len)");
        let l0 = self.b[i];
        let len = if l0 < 0x80 {
            i += 1;
            l0 as usize
        } else {
            let n = (l0 & 0x7f) as usize;
            ensure!((1..=3).contains(&n), "der length too long");
            ensure!(i + 1 + n <= self.b.len(), "der truncated (len bytes)");
            i += 1;
            let mut v = 0usize;
            for _ in 0..n {
                v = (v << 8) | self.b[i] as usize;
                i += 1;
            }
            v
        };
        ensure!(i + len <= self.b.len(), "der truncated");
        self.i = i + len;
        Ok((tag, i, len))
    }
}

#[derive(Debug, Clone)]
pub struct ParsedCert {
    pub subject: String,
    pub issuer: String,
    /// Validity window as unix seconds (for the `valid_now` policy check).
    pub not_before_ts: i64,
    pub not_after_ts: i64,
    /// basicConstraints.ca if the extension is present (trust policy: every
    /// non-leaf cert in the chain must be Some(true)).
    pub basic_ca: Option<bool>,
    pub sig_alg: String,
    pub key_kind: &'static str,
    /// Full DER of the TBSCertificate (span extracted with our own walker).
    tbs: Vec<u8>,
    spki_der: Vec<u8>,
    spki_alg: Vec<u8>,
    point: Vec<u8>,
    sig_alg_oid: Vec<u8>,
    sig: Vec<u8>,
    der: Vec<u8>,
}

fn oid_name(b: &[u8]) -> String {
    // base128 decode for display
    let Some((&first, rest)) = b.split_first() else {
        return String::new();
    };
    let mut out = format!("{}.{}", first / 40, first % 40);
    let mut v: u64 = 0;
    for &c in rest {
        v = (v << 7) | u64::from(c & 0x7f);
        if c & 0x80 == 0 {
            let _ = write!(out, ".{v}");
            v = 0;
        }
    }
    out
}

fn sig_alg_label(oid: &[u8]) -> &'static str {
    match oid {
        OID_ECDSA_SHA1 => "ecdsa-with-SHA1",
        OID_ECDSA_SHA256 => "ecdsa-with-SHA256",
        OID_ECDSA_SHA384 => "ecdsa-with-SHA384",
        OID_ECDSA_SHA512 => "ecdsa-with-SHA512",
        OID_RSA_SHA1 => "sha1WithRSAEncryption",
        OID_RSA_SHA256 => "sha256WithRSAEncryption",
        OID_RSA_SHA384 => "sha384WithRSAEncryption",
        OID_RSA_SHA512 => "sha512WithRSAEncryption",
        _ => "unknown",
    }
}

/// Children TLVs of a constructed value.
fn children(b: &[u8]) -> Result<Vec<Tlv>> {
    children_named(b, "")
}
fn children_named(b: &[u8], name: &str) -> Result<Vec<Tlv>> {
    let mut d = Der::new(b);
    let mut out = Vec::new();
    while d.i < b.len() {
        let n = out.len();
        out.push(
            d.tlv()
                .with_context(|| format!("{name} child #{n} of {}: {}", b.len(), hex(b)))?,
        );
    }
    Ok(out)
}

/// The content bytes of `tlv` within `b`.
fn content(b: &[u8], (_, start, len): Tlv) -> &[u8] {
    &b[start..start + len]
}

/// Child `n` of a constructed value's children, or an error naming `what`.
fn child(kids: &[Tlv], n: usize, what: &str) -> Result<Tlv> {
    kids.get(n)
        .copied()
        .with_context(|| format!("{what}: missing"))
}

/// The payload of a BIT STRING TLV: its content minus the unused-bits octet.
fn bit_string<'b>(b: &'b [u8], tlv: Tlv, what: &str) -> Result<&'b [u8]> {
    ensure!(tlv.0 == 0x03, "{what} not BIT STRING");
    content(b, tlv)
        .split_first()
        .map(|(_, bits)| bits)
        .with_context(|| format!("{what}: empty BIT STRING"))
}

pub fn parse_cert(der: &[u8]) -> Result<ParsedCert> {
    let (_rest, cert) = X509Certificate::from_der(der).context("x509 parse")?;
    // Own walker for exact TBS/SPKI spans.
    let mut d = Der::new(der);
    let outer = d
        .tlv()
        .with_context(|| format!("outer tlv (der {} bytes)", der.len()))?;
    ensure!(d.i == der.len(), "cert DER has trailing garbage");
    let inner = content(der, outer);
    let top = children_named(inner, "cert")?;
    ensure!(top.len() >= 3, "cert too short");
    let (t_tag, t_cs, t_cl) = top[0];
    ensure!(t_tag == 0x30, "tbs not SEQUENCE");
    // The signature covers the *full* DER TLV of TBSCertificate, tag + length
    // prefix included; tbs is the first TLV of the outer SEQUENCE's content.
    let tbs_full = &inner[..t_cs + t_cl];
    let tbs_body = &tbs_full[t_cs..];
    let sa_slice = content(inner, top[1]);
    let sig_alg_oid = content(
        sa_slice,
        child(&children(sa_slice)?, 0, "signature algorithm")?,
    )
    .to_vec();
    let sig = bit_string(inner, top[2], "cert signature")?.to_vec();

    // TBS fields: [0]version?, serial, sigalg, issuer, validity, subject, spki, ...
    let tc = children_named(tbs_body, "tbs")?;
    let k = usize::from(tc.first().is_some_and(|t| t.0 == 0xa0));
    // k: serial, +1 sigalg, +2 issuer, +3 validity, +4 subject, +5 spki
    let spki_tlv = child(&tc, k + 5, "spki")?;
    ensure!(spki_tlv.0 == 0x30, "spki not SEQUENCE");
    let spki = content(tbs_body, spki_tlv);
    let spki_children = children_named(spki, "spki")?;
    let alg_slice = content(spki, child(&spki_children, 0, "spki algorithm")?);
    let alg_children = children_named(alg_slice, "alg")?;
    let spki_alg = content(alg_slice, child(&alg_children, 0, "spki algorithm oid")?).to_vec();
    let point = bit_string(
        spki,
        child(&spki_children, 1, "spki pubkey")?,
        "spki pubkey",
    )?
    .to_vec();

    // basicConstraints, if present (the last one, should there be several).
    let basic_ca = cert
        .extensions()
        .iter()
        .rev()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => Some(bc.ca),
            _ => None,
        });
    Ok(ParsedCert {
        subject: cert.subject.to_string(),
        issuer: cert.issuer.to_string(),
        not_before_ts: cert.validity.not_before.timestamp(),
        not_after_ts: cert.validity.not_after.timestamp(),
        basic_ca,
        sig_alg: sig_alg_label(&sig_alg_oid).to_string(),
        key_kind: if spki_alg == OID_EC_PUBLIC {
            match point.len() {
                65 => "EC P-256",
                97 => "EC P-384",
                _ => "EC",
            }
        } else if spki_alg == OID_RSA_ENC {
            "RSA"
        } else {
            "other"
        },
        tbs: tbs_full.to_vec(),
        spki_der: spki.to_vec(),
        spki_alg,
        point,
        sig_alg_oid,
        sig,
        der: der.to_vec(),
    })
}

/// Decode a DER ECDSA signature (SEQUENCE{INTEGER r, INTEGER s}) into r||s.
/// `comp` is the byte length of one component (32 for P-256, 48 for P-384).
fn der_to_raw_ecdsa(der: &[u8], comp: usize) -> Result<Vec<u8>> {
    let (t, cs, cl) = Der::new(der).tlv()?;
    ensure!(t == 0x30, "ecdsa sig not SEQUENCE");
    let body = &der[cs..cs + cl];
    let kids = children(body)?;
    ensure!(kids.len() >= 2, "ecdsa sig missing r/s");
    let mut out = vec![0u8; comp * 2];
    for (i, k) in kids[..2].iter().enumerate() {
        ensure!(k.0 == 0x02, "ecdsa sig int expected");
        let v = &body[k.1..k.1 + k.2];
        let v = if v.len() > comp && v[0] == 0 {
            &v[1..]
        } else {
            v
        };
        ensure!(v.len() <= comp, "ecdsa component oversized");
        out[i * comp + (comp - v.len())..(i + 1) * comp].copy_from_slice(v);
    }
    Ok(out)
}

impl ParsedCert {
    /// Uncompressed X9.62 point of the subject public key (feeds the AEA main-key KDF).
    pub fn point(&self) -> &[u8] {
        &self.point
    }
}

fn hash(tag: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    // SHA-1 is deliberately unsupported: a chain that needs it is rejected
    // outright (review #12), labels for display still resolve.
    Ok(match tag {
        OID_ECDSA_SHA256 | OID_RSA_SHA256 => Sha256::digest(data).to_vec(),
        OID_ECDSA_SHA384 | OID_RSA_SHA384 => Sha384::digest(data).to_vec(),
        OID_ECDSA_SHA512 | OID_RSA_SHA512 => Sha512::digest(data).to_vec(),
        OID_ECDSA_SHA1 | OID_RSA_SHA1 => bail!("SHA-1 signatures are rejected"),
        _ => bail!("unsupported signature algorithm {}", oid_name(tag)),
    })
}

fn verify_with(issuer: &ParsedCert, signed: &ParsedCert) -> Result<bool> {
    let digest = hash(&signed.sig_alg_oid, &signed.tbs)?;
    if issuer.spki_alg == OID_EC_PUBLIC {
        match issuer.point.len() {
            65 => {
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&issuer.point)
                    .context("issuer p256 pubkey")?;
                if signed.sig_alg_oid.as_slice() != OID_ECDSA_SHA256 {
                    bail!("P-256 issuer with non-SHA256 digest");
                }
                let raw = der_to_raw_ecdsa(&signed.sig, 32).context("ecdsa sig der")?;
                let sig = p256::ecdsa::Signature::from_slice(&raw).context("ecdsa sig")?;
                Ok(vk.verify_prehash(&digest, &sig).is_ok())
            }
            97 => {
                let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&issuer.point)
                    .context("issuer p384 pubkey")?;
                if !matches!(signed.sig_alg_oid.as_slice(), OID_ECDSA_SHA384) {
                    bail!("P-384 issuer with non-SHA384 digest");
                }
                let raw = der_to_raw_ecdsa(&signed.sig, 48).context("ecdsa sig der")?;
                let sig = p384::ecdsa::Signature::from_slice(&raw).context("ecdsa sig")?;
                Ok(vk.verify_prehash(&digest, &sig).is_ok())
            }
            n => bail!("unsupported EC point length {n}"),
        }
    } else if issuer.spki_alg == OID_RSA_ENC {
        use rsa::PublicKey as RsaPublicKey;
        use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey};
        use rsa::pkcs8::DecodePublicKey;
        use rsa::signature::Verifier;
        let pubk =
            RsaPublicKey::from_public_key_der(&issuer.spki_der).context("issuer rsa pubkey")?;
        let sig = RsaSig::try_from(signed.sig.as_slice()).context("rsa sig der")?;
        Ok(match signed.sig_alg_oid.as_slice() {
            OID_RSA_SHA256 => VerifyingKey::<Sha256>::new(pubk)
                .verify(&signed.tbs, &sig)
                .is_ok(),
            OID_RSA_SHA384 => VerifyingKey::<Sha384>::new(pubk)
                .verify(&signed.tbs, &sig)
                .is_ok(),
            OID_RSA_SHA512 => VerifyingKey::<Sha512>::new(pubk)
                .verify(&signed.tbs, &sig)
                .is_ok(),
            other => bail!("unsupported RSA sig alg {}", oid_name(other)),
        })
    } else {
        bail!(
            "unsupported issuer key algorithm {}",
            oid_name(&issuer.spki_alg)
        )
    }
}

#[derive(Debug)]
pub struct AuthResult {
    pub certs: Vec<ParsedCert>,
    pub chain_ok: Vec<bool>, // chain_ok[i] = certs[i] verified by certs[i+1]
    /// Every chain link verified (trust policy requires this, not just a
    /// report — review #4).
    pub chain_all_ok: bool,
    /// All non-leaf certificates assert basicConstraints CA:true.
    pub ca_ok: bool,
    /// All certificates are within their validity window right now.
    pub valid_now: bool,
    pub trusted_root: bool,
    pub content_sig_ok: bool,
    pub sig_padded_ok: bool,
}

pub fn verify_all(
    chain_pem: &[u8],
    vendored_roots_pem: &[u8],
    sig_field: &[u8],
    signed_prefix: &[u8],
) -> Result<AuthResult> {
    let ders = split_pem(chain_pem)?;
    let certs: Vec<ParsedCert> = ders
        .iter()
        .enumerate()
        .map(|(i, d)| {
            parse_cert(d).with_context(|| format!("parsing cert #{i} ({})", short_name(d)))
        })
        .collect::<Result<_>>()?;

    // An unverifiable link (unsupported algorithm, bad key) is a failed one.
    let chain_ok: Vec<bool> = certs
        .windows(2)
        .map(|w| verify_with(&w[1], &w[0]).unwrap_or(false))
        .collect();
    let chain_all_ok = chain_ok.iter().all(|&b| b);
    // Trust policy (review #4): every issuer — intermediate and root — must
    // assert CA:true. A random leaf cert chained to a CA (e.g. some third-
    // party-held identity certs under Apple Root CA G3) must not verify.
    let ca_ok = certs.len() < 2 || certs[1..].iter().all(|c| c.basic_ca == Some(true));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let valid_now = certs
        .iter()
        .all(|c| c.not_before_ts <= now && now <= c.not_after_ts);

    let roots = split_pem(vendored_roots_pem).context("parsing vendored roots")?;
    let last = certs.last().unwrap();
    let trusted_root =
        roots.iter().any(|r| r == &last.der) && ca_ok && verify_with(last, last).unwrap_or(false);

    // Content signature: DER sig at the head of the 128-byte field, zero pad
    // after. A malformed length here is a failed signature, not a fatal
    // error — the check must stay reportable (review #7).
    let dl = der_sig_len(sig_field)
        .ok()
        .filter(|&d| d <= sig_field.len());
    let sig_padded_ok = dl.is_some_and(|d| sig_field[d..].iter().all(|&b| b == 0));
    let digest = Sha256::digest(signed_prefix).to_vec();
    let leaf = &certs[0];
    let content_sig_ok = match dl {
        Some(dl) if leaf.spki_alg == OID_EC_PUBLIC => {
            match (
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&leaf.point),
                der_to_raw_ecdsa(&sig_field[..dl], 32).ok(),
            ) {
                (Ok(vk), Some(raw)) => p256::ecdsa::Signature::from_slice(&raw)
                    .is_ok_and(|sig| vk.verify_prehash(&digest, &sig).is_ok()),
                _ => false,
            }
        }
        _ => false,
    };

    Ok(AuthResult {
        certs,
        chain_ok,
        chain_all_ok,
        ca_ok,
        valid_now,
        trusted_root,
        content_sig_ok,
        sig_padded_ok,
    })
}

/// Length of the DER SEQUENCE at the head of the 128-byte signature field.
fn der_sig_len(field: &[u8]) -> Result<usize> {
    let (_, cs, cl) = Der::new(field).tlv()?;
    ensure!(cs + cl <= field.len(), "signature DER past field");
    Ok(cs + cl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_decode(b"").unwrap(), Vec::<u8>::new());
        assert_eq!(base64_decode(b"Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode(b"YQ==").unwrap(), b"a");
        assert_eq!(base64_decode(b"YWI=").unwrap(), b"ab");
        assert_eq!(base64_decode(b"Zm9vCmJhcgo=").unwrap(), b"foo\nbar\n");
        // Regression: a partial trailing chunk must be emitted from the TOP
        // of the accumulator: "KA==" == 0b001010 -> 0x28 (not 0x80).
        assert_eq!(base64_decode(b"KA==").unwrap(), vec![0x28]);
        assert_eq!(base64_decode(b"TWFu").unwrap(), b"Man");
        assert!(base64_decode(b"Zm9!").is_err());
    }

    /// Certificate bytes come from the archive: malformed DER must be an
    /// error (exit 4/5), never a panic.
    #[test]
    fn malformed_der_is_an_error_not_a_panic() {
        // A BIT STRING needs at least its unused-bits octet.
        assert!(bit_string(b"\x03\x00", (0x03, 2, 0), "sig").is_err());
        assert!(bit_string(b"\x04\x01\x00", (0x04, 2, 1), "sig").is_err());
        assert_eq!(
            bit_string(b"\x03\x02\x00\xab", (0x03, 2, 2), "sig").unwrap(),
            b"\xab"
        );
        assert!(child(&[], 0, "spki").is_err());
        assert!(parse_cert(b"\x30\x00").is_err());
        assert!(der_sig_len(b"\x30\x05\x00").is_err());
    }

    #[test]
    fn pem_split_roundtrip() {
        // "MIIBAmR1bW15" is the base64 of 30 82 01 02 'dummy'.
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBAmR1bW15\n-----END CERTIFICATE-----\n";
        let out = split_pem(pem.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], b"\x30\x82\x01\x02dummy");
        assert!(split_pem(b"no pem here").is_err());
    }
}
