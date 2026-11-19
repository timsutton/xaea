//! ECDSA/RSA signature + certificate-chain verification for AEA profile 0.
//!
//! The file signature is an ECDSA P-256 signature over SHA-256 of the file
//! prefix through the first cluster header MAC, with the signature field
//! itself zeroed (kinnay FORMAT.md "Signature"). The signing certificate
//! chain arrives in the auth data as PEM.

use anyhow::{anyhow, bail, ensure, Context, Result};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use x509_parser::prelude::*;

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
const OID_SECP256R1: &[u8] = &[42, 134, 72, 206, 61, 3, 1, 7];

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
fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn base64_decode(b: &[u8]) -> Result<Vec<u8>> {
    // minimal base64 decoder (standard alphabet)
    fn val(c: u8) -> Result<u32> {
        Ok(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
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
    fn new_at(b: &'a [u8], i: usize) -> Self {
        Self { b, i }
    }
    fn tlv(&mut self) -> Result<Tlv> {
        let start = self.i;
        ensure!(start < self.b.len(), "der eof");
        let tag = self.b[start];
        let mut i = start + 1;
        if tag & 0x1f == 0x1f {
            while self.b[i] & 0x80 != 0 {
                i += 1;
            }
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
    fn done(&self) -> bool {
        self.i >= self.end()
    }
    fn end(&self) -> usize {
        self.b.len()
    }
}

#[derive(Debug, Clone)]
pub struct ParsedCert {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub sig_alg: String,
    pub key_kind: &'static str,
    /// Full DER of the TBSCertificate (span extracted with our own walker).
    tbs: Vec<u8>,
    spki_der: Vec<u8>,
    spki_alg: Vec<u8>,
    spki_params: Vec<u8>,
    point: Vec<u8>,
    sig_alg_oid: Vec<u8>,
    sig: Vec<u8>,
    der: Vec<u8>,
}

fn oid_name(b: &[u8]) -> String {
    // base128 decode for display
    let mut out = String::new();
    if b.is_empty() {
        return out;
    }
    let first = b[0];
    out.push_str(&(first / 40).to_string());
    out.push('.');
    out.push_str(&(first % 40).to_string());
    let mut v: u64 = 0;
    for &c in &b[1..] {
        v = (v << 7) | (c & 0x7f) as u64;
        if c & 0x80 == 0 {
            out.push('.');
            out.push_str(&v.to_string());
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
    let mut d = Der::new_at(b, 0);
    let mut out = Vec::new();
    while d.i < b.len() {
        let n = out.len();
        out.push(
            d.tlv()
                .map_err(|e| anyhow!("[{name} child #{n} of {}: {}]: {e:#}", b.len(), hex(b)))?,
        );
    }
    Ok(out)
}

pub fn parse_cert(der: &[u8]) -> Result<ParsedCert> {
    let (_rest, name) = X509Certificate::from_der(der).context("x509 parse")?;
    // Own walker for exact TBS/SPKI spans.
    let mut d = Der::new_at(der, 0);
    let (_, cs, cl) = d
        .tlv()
        .map_err(|e| anyhow!("outer tlv (der {} bytes): {e:#}", der.len()))?;
    ensure!(d.i == der.len(), "cert DER has trailing garbage");
    let inner = &der[cs..cs + cl];
    let top = children_named(inner, "cert")?;
    ensure!(top.len() >= 3, "cert too short");
    let (t_tag, t_cs, t_cl) = top[0];
    ensure!(t_tag == 0x30, "tbs not SEQUENCE");
    // The signature covers the *full* DER TLV of TBSCertificate, tag + length
    // prefix included; tbs is the first TLV of the outer SEQUENCE's content.
    let tbs_full = inner[..t_cs + t_cl].to_vec();
    let tbs_body = &tbs_full[t_cs..];
    let (_, sa_cs, sa_cl) = top[1];
    let sa_slice = &inner[sa_cs..sa_cs + sa_cl];
    let sigalg_children = children(sa_slice)?;
    let sig_alg_oid =
        sa_slice[sigalg_children[0].1..sigalg_children[0].1 + sigalg_children[0].2].to_vec();
    let (bs_tag, bs_cs, bs_cl) = top[2];
    ensure!(bs_tag == 0x03, "cert signature not BIT STRING");
    let sig = inner[bs_cs + 1..bs_cs + bs_cl].to_vec();

    // TBS fields: [0]version?, serial, sigalg, issuer, validity, subject, spki, ...
    let tc = children_named(tbs_body, "tbs")?;
    let mut k = 0usize;
    if tc[0].0 == 0xa0 {
        k = 1;
    }
    // k: serial, +1 sigalg, +2 issuer, +3 validity, +4 subject, +5 spki
    let spki_idx = k + 5;
    ensure!(
        tc.len() > spki_idx && tc[spki_idx].0 == 0x30,
        "spki not SEQUENCE"
    );
    let (s_cs, s_cl) = (tc[spki_idx].1, tc[spki_idx].2);
    let spki = &tbs_body[s_cs..s_cs + s_cl];
    let spki_der = spki.to_vec();
    let spki_children = children_named(spki, "spki")?;
    let alg_slice = &spki[spki_children[0].1..spki_children[0].1 + spki_children[0].2];
    let alg_children = children_named(alg_slice, "alg")?;
    let spki_alg = alg_slice[alg_children[0].1..alg_children[0].1 + alg_children[0].2].to_vec();
    let spki_params = if alg_children.len() > 1 {
        alg_slice[alg_children[1].1..alg_children[1].1 + alg_children[1].2].to_vec()
    } else {
        vec![]
    };
    let (pb_tag, pb_cs, pb_cl) = spki_children[1];
    ensure!(pb_tag == 0x03, "spki pubkey not BIT STRING");
    let point = spki[pb_cs + 1..pb_cs + pb_cl].to_vec();

    Ok(ParsedCert {
        subject: name.subject.to_string(),
        issuer: name.issuer.to_string(),
        serial: name.serial.to_str_radix(16),
        not_before: name.validity.not_before.to_string(),
        not_after: name.validity.not_after.to_string(),
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
        tbs: tbs_full,
        spki_der,
        spki_alg,
        spki_params,
        point,
        sig_alg_oid,
        sig,
        der: der.to_vec(),
    })
}

/// Decode a DER ECDSA signature (SEQUENCE{INTEGER r, INTEGER s}) into r||s.
fn der_to_p256_raw(der: &[u8], comp: usize) -> Result<Vec<u8>> {
    let (t, cs, cl) = Der::new_at(der, 0).tlv()?;
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
    Ok(match tag {
        OID_ECDSA_SHA256 | OID_RSA_SHA256 => Sha256::digest(data).to_vec(),
        OID_ECDSA_SHA384 | OID_RSA_SHA384 => Sha384::digest(data).to_vec(),
        OID_ECDSA_SHA512 | OID_RSA_SHA512 => Sha512::digest(data).to_vec(),
        OID_ECDSA_SHA1 | OID_RSA_SHA1 => Sha1::digest(data).to_vec(),
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
                if !matches!(
                    signed.sig_alg_oid.as_slice(),
                    OID_ECDSA_SHA256 | OID_ECDSA_SHA1
                ) {
                    bail!("P-256 issuer with non-SHA256 digest");
                }
                let raw = der_to_p256_raw(&signed.sig, 32).context("ecdsa sig der")?;
                let sig = p256::ecdsa::Signature::from_slice(&raw).context("ecdsa sig")?;
                Ok(vk.verify_prehash(&digest, &sig).is_ok())
            }
            97 => {
                let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&issuer.point)
                    .context("issuer p384 pubkey")?;
                if !matches!(signed.sig_alg_oid.as_slice(), OID_ECDSA_SHA384) {
                    bail!("P-384 issuer with non-SHA384 digest");
                }
                let raw = der_to_p256_raw(&signed.sig, 48).context("ecdsa sig der")?;
                let sig = p384::ecdsa::Signature::from_slice(&raw).context("ecdsa sig")?;
                Ok(vk.verify_prehash(&digest, &sig).is_ok())
            }
            n => bail!("unsupported EC point length {n}"),
        }
    } else if issuer.spki_alg == OID_RSA_ENC {
        use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey};
        use rsa::pkcs8::DecodePublicKey;
        use rsa::signature::Verifier;
        use rsa::RsaPublicKey;
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
            OID_RSA_SHA1 => VerifyingKey::<Sha1>::new(pubk)
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

    let mut chain_ok = Vec::new();
    for i in 0..certs.len() - 1 {
        match verify_with(&certs[i + 1], &certs[i]) {
            Ok(v) => chain_ok.push(v),
            Err(_) => chain_ok.push(false),
        }
    }

    let roots = split_pem(vendored_roots_pem).context("parsing vendored roots")?;
    let last = certs.last().unwrap();
    let trusted_root =
        roots.iter().any(|r| r == &last.der) && verify_with(last, last).unwrap_or(false);

    // Content signature: DER sig at the head of the 128-byte field, zero pad after.
    let dl = if sig_field[1] < 0x80 {
        2 + sig_field[1] as usize
    } else if sig_field[1] == 0x81 {
        3 + sig_field[2] as usize
    } else {
        bail!("unexpected DER length encoding in signature field")
    };
    ensure!(dl <= sig_field.len(), "signature field too small for DER");
    let sig_padded_ok = sig_field[dl..].iter().all(|&b| b == 0);
    let digest = Sha256::digest(signed_prefix).to_vec();
    let leaf = &certs[0];
    let content_sig_ok = if leaf.spki_alg == OID_EC_PUBLIC {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&leaf.point);
        let raw = der_to_p256_raw(&sig_field[..dl], 32).ok();
        match (vk, raw) {
            (Ok(vk), Some(raw)) => p256::ecdsa::Signature::from_slice(&raw)
                .map(|sig| vk.verify_prehash(&digest, &sig).is_ok())
                .unwrap_or(false),
            _ => false,
        }
    } else {
        false
    };

    Ok(AuthResult {
        certs,
        chain_ok,
        trusted_root,
        content_sig_ok,
        sig_padded_ok,
    })
}
