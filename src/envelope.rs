//! AEA envelope parsing per kinnay's FORMAT.md (github.com/kinnay/AEA),
//! with errata verified against Apple's real Xcode 27.3 beta 2 artifact
//! (see doc/FORMAT-NOTES.md).

use crate::kdf::{self, Key};
use crate::lzfse;
use crate::xz::{self, XzDecoder};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::fmt;

pub const ROOT_HEADER_LEN: usize = 0x30;
pub const SIGNATURE_LEN: usize = 128;
/// Every MAC in the envelope is an HMAC-SHA256.
const MAC_LEN: usize = 32;
/// Encrypted root header (profile 1): root MAC, AES-CTR-encrypted 48-byte
/// root header, next-cluster MAC.
const ENC_ROOT_HEADER_LEN: usize = 112;
/// Per-cluster and per-segment AES-256-CTR key material: 32-byte HMAC key,
/// 32-byte AES key, 16-byte IV.
const DATA_KEY_MATERIAL_LEN: usize = 80;

/// The FCS symmetric key of an encrypted archive, recovered out-of-band
/// (see [`crate::hpke::unwrap_fcs_key`]). It is the IKM of the main key,
/// derived during parsing; profile 0 derives its main key from the signing
/// public key instead, so it needs no key material.
pub struct MainKey(Key);

impl MainKey {
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        let key: Key = b.try_into().context("FCS symmetric key must be 32 bytes")?;
        Ok(MainKey(key))
    }

    /// The recovered symmetric key itself.
    pub fn as_slice(&self) -> &Key {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile(pub [u8; 3]);

impl Profile {
    pub const NO_ENC_SIGNED: Profile = Profile([0, 0, 0]);

    /// The profile id is a 24-bit little-endian number whose low byte encodes
    /// the signature scheme (even = signed, odd = unsigned).
    pub fn signed(self) -> bool {
        matches!(self.0[0], 0 | 2 | 4)
    }
    pub fn encrypted(self) -> bool {
        self != Self::NO_ENC_SIGNED
    }
    pub fn id(self) -> u32 {
        u32::from_le_bytes([self.0[0], self.0[1], self.0[2], 0])
    }
}

/// Segment compression algorithm, from the root header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Lz4,
    Lzbitmap,
    Lzfse,
    Lzvn,
    Lzma,
    Zlib,
}

impl TryFrom<u8> for Compression {
    type Error = anyhow::Error;

    fn try_from(c: u8) -> Result<Self> {
        Ok(match c {
            b'-' => Self::None,
            b'4' => Self::Lz4,
            b'b' => Self::Lzbitmap,
            b'e' => Self::Lzfse,
            b'f' => Self::Lzvn,
            b'x' => Self::Lzma,
            b'z' => Self::Zlib,
            _ => bail!("unknown compression algorithm {c:#x}"),
        })
    }
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Lz4 => "LZ4",
            Self::Lzbitmap => "LZBITMAP",
            Self::Lzfse => "LZFSE",
            Self::Lzvn => "LZVN",
            Self::Lzma => "LZMA",
            Self::Zlib => "ZLIB",
        })
    }
}

/// Per-segment checksum algorithm, from the root header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    None,
    Murmur64,
    Sha256,
}

impl Checksum {
    /// Bytes each segment header spends on its checksum.
    pub fn len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Murmur64 => 8,
            Self::Sha256 => 32,
        }
    }
}

impl TryFrom<u8> for Checksum {
    type Error = anyhow::Error;

    fn try_from(c: u8) -> Result<Self> {
        Ok(match c {
            0 => Self::None,
            1 => Self::Murmur64,
            2 => Self::Sha256,
            _ => bail!("unknown checksum algorithm {c}"),
        })
    }
}

impl fmt::Display for Checksum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Murmur64 => "MurmurHash64A",
            Self::Sha256 => "SHA-256",
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RootHeader {
    pub original_size: u64,
    pub encarchive_size: u64,
    pub segment_size: u32,
    pub segments_per_cluster: u32,
    pub compression: Compression,
    pub checksum: Checksum,
}

impl RootHeader {
    /// Length of one segment header: two u32 sizes plus the checksum.
    fn segment_header_len(&self) -> usize {
        8 + self.checksum.len()
    }
}

#[derive(Debug, Clone)]
pub struct Cluster {
    pub index: u32,
    pub segs: u32,
    pub seghdrs_off: usize,
    pub nextchmac_off: usize,
    pub seghmacs_off: usize,
    pub data_off: usize,
    /// Profile 1: the decrypted segment-header region. The file holds the
    /// AES-CTR-encrypted headers, so the decrypted copy is kept here for
    /// [`Envelope::segments`]. `None` for profile 0, whose headers are
    /// stored in plaintext at `seghdrs_off`.
    pub decrypted_headers: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct Segment<'a, 'b> {
    pub index: u32,
    pub cluster: u32,
    pub orig: u32,
    pub comp: u32,
    /// The stored checksum bytes. Profile 1 reads these from the decrypted
    /// cluster header (owned by the envelope), so it has a shorter lifetime
    /// than the file-slice fields.
    pub cksum: &'b [u8],
    pub mac: &'a [u8],
    pub data: &'a [u8],
    /// Absolute file offset of the segment's stored bytes (for pread-based
    /// parallel decoding without sharing the mmap).
    pub data_off: usize,
}

pub struct Envelope<'a> {
    pub file: &'a [u8],
    pub profile: Profile,
    pub scrypt_strength: u8,
    pub auth: Vec<(String, Vec<u8>)>,
    pub auth_start: usize,
    pub auth_end: usize,
    pub sig_off: usize,
    pub pubkey_off: usize,
    pub mainsalt_off: usize,
    pub rootmac_off: usize,
    pub root_off: usize,
    /// Offset of the first cluster header MAC (also: end of the signed prefix).
    pub chmac_off: usize,
    pub root: RootHeader,
    pub clusters: Vec<Cluster>,
    pub total_segments: u64,
    /// Profile 1 only: the derived main key (AEA_AMK), recovered during
    /// parsing. Profile 0 derives it on demand from the signing public key
    /// ([`Envelope::main_key`]).
    pub main: Option<Key>,
}

/// Root and cluster header MAC results.
#[derive(Debug)]
pub struct HeaderMacs {
    pub root_ok: bool,
    pub clusters_ok: bool,
    /// Which cluster-header-MAC salt layout matched (only layout 0 is
    /// known), or `None` if no cluster MAC matched at all.
    pub chmac_variant: Option<usize>,
}

#[derive(Debug)]
pub struct MacReport {
    pub root_mac_ok: bool,
    pub cluster_macs_ok: bool,
    pub chmac_variant: Option<usize>,
    pub segmac_failed: Vec<u32>,
}

fn u32le(b: &[u8], at: usize) -> Result<u32> {
    let n = b
        .get(at..)
        .and_then(<[u8]>::first_chunk)
        .context("short read")?;
    Ok(u32::from_le_bytes(*n))
}

fn u64le(b: &[u8], at: usize) -> Result<u64> {
    let n = b
        .get(at..)
        .and_then(<[u8]>::first_chunk)
        .context("short read")?;
    Ok(u64::from_le_bytes(*n))
}

/// The `MAC_LEN` bytes at `at`; offsets come from a parsed envelope.
fn mac_at(b: &[u8], at: usize) -> &[u8; MAC_LEN] {
    b[at..]
        .first_chunk()
        .expect("MAC offsets are validated by Envelope::parse")
}

/// Profile-1 (SymmetricEncryption) parsing: derive the main key from the
/// FCS symmetric key, verify and decrypt the root header, then walk the
/// clusters that are actually present in `file`. The walk is bounded by
/// the file size rather than the declared `original_size`, because an
/// encrypted archive may be truncated (e.g. a head-only fetch).
fn parse_profile1<'a>(
    file: &'a [u8],
    auth: Vec<(String, Vec<u8>)>,
    auth_start: usize,
    auth_end: usize,
    sig_off: usize,
    off: usize,
    key: &MainKey,
) -> Result<Envelope<'a>> {
    let profile = Profile([file[4], file[5], file[6]]);
    let scrypt_strength = file[7];
    let main_salt_off = off;
    let rootmac_off = off + 32;
    let root_off = off + 64;
    let chmac_off = off + 112;
    ensure!(
        rootmac_off + ENC_ROOT_HEADER_LEN <= file.len(),
        "truncated: no room for the encrypted root header"
    );

    let main = kdf::main_key_sym(
        key.as_slice(),
        &file[main_salt_off..main_salt_off + 32],
        &file[4..8],
    );

    // Root-header MAC: raw HMAC over clusterMAC || authData || encData ||
    // u64le(32 + authSize).
    let rh_mat = kdf::root_header_material(&main);
    ensure!(
        rh_mat.len() == DATA_KEY_MATERIAL_LEN,
        "bad root-header material length"
    );
    let stored_root_mac = mac_at(file, rootmac_off);
    let rh_enc = &file[root_off..root_off + ROOT_HEADER_LEN];
    let cluster_mac_stored = &file[chmac_off..chmac_off + MAC_LEN];
    let auth_data = &file[auth_start..auth_end];
    let mut rh_mac_data = Vec::with_capacity(32 + auth_data.len() + 48 + 8);
    rh_mac_data.extend_from_slice(cluster_mac_stored);
    rh_mac_data.extend_from_slice(auth_data);
    rh_mac_data.extend_from_slice(rh_enc);
    rh_mac_data.extend_from_slice(&(32usize + auth_data.len()).to_le_bytes());
    ensure!(
        kdf::mac_raw(&rh_mat[0..32], &rh_mac_data) == *stored_root_mac,
        "root header MAC mismatch"
    );

    let mut root_plain = rh_enc.to_vec();
    lzfse::aes_ctr_decrypt(&rh_mat, &mut root_plain)?;
    let root = RootHeader {
        original_size: u64le(&root_plain, 0x0)?,
        encarchive_size: u64le(&root_plain, 0x8)?,
        segment_size: u32le(&root_plain, 0x10)?,
        segments_per_cluster: u32le(&root_plain, 0x14)?,
        compression: root_plain[0x18].try_into()?,
        checksum: root_plain[0x19].try_into()?,
    };
    // Sanity floors only: same as profile 0, they reject garbage headers
    // without rejecting spec-legal small geometries.
    ensure!(root.segment_size >= 0x1000, "segment size too small");
    ensure!(root.segments_per_cluster >= 1, "no segments per cluster");

    // Walk clusters from the file size: each cluster header is padded to
    // the full segments-per-cluster capacity, so `cur` is the exact file
    // offset of the next cluster header.
    let entry_size = root.segment_header_len();
    let spc = root.segments_per_cluster as usize;
    let headers_size = entry_size * spc;
    let ch_size = headers_size + 32 + 32 * spc;
    let mut clusters: Vec<Cluster> = Vec::new();
    let mut total_segments = 0u64;
    let mut cur = chmac_off + MAC_LEN;
    let mut cidx = 0u32;
    loop {
        if cur + ch_size > file.len() {
            break; // cluster header not fully present (truncated archive)
        }
        let ck = kdf::cluster_key(&main, cidx);
        let ch_mat = kdf::cluster_header_material(&ck);
        ensure!(
            ch_mat.len() == DATA_KEY_MATERIAL_LEN,
            "bad cluster-header material length"
        );
        let headers_enc = &file[cur..cur + headers_size];
        let macs = &file[cur + headers_size..cur + ch_size];
        let stored = if cidx == 0 {
            mac_at(file, chmac_off)
        } else {
            mac_at(file, clusters[(cidx - 1) as usize].nextchmac_off)
        };
        let mut mac_data = Vec::with_capacity(macs.len() + headers_enc.len() + 8);
        mac_data.extend_from_slice(macs);
        mac_data.extend_from_slice(headers_enc);
        mac_data.extend_from_slice(&(macs.len() as u64).to_le_bytes());
        ensure!(
            kdf::mac_raw(&ch_mat[0..32], &mac_data) == *stored,
            "cluster {cidx} header MAC mismatch"
        );
        let mut headers = headers_enc.to_vec();
        lzfse::aes_ctr_decrypt(&ch_mat, &mut headers)?;
        let mut n_segs = 0u32;
        let mut doff = cur + ch_size;
        for s in 0..spc {
            let ho = s * entry_size;
            let orig = u32le(&headers, ho)?;
            let comp = u32le(&headers, ho + 4)? as usize;
            if comp == 0 {
                break; // unused trailing segments
            }
            ensure!(
                orig <= root.segment_size,
                "cluster {cidx} segment {s}: decoded size {orig} exceeds segment_size {}",
                root.segment_size
            );
            if doff + comp > file.len() {
                // Truncated archive (e.g. head-only fetch): the segment's
                // stored bytes are not fully present — stop at this segment.
                break;
            }
            n_segs += 1;
            doff += comp;
        }
        if n_segs == 0 {
            // No segment data is present: the archive is too truncated to
            // report anything.
            break;
        }
        clusters.push(Cluster {
            index: cidx,
            segs: n_segs,
            seghdrs_off: cur,
            nextchmac_off: cur + headers_size,
            seghmacs_off: cur + headers_size + 32,
            data_off: cur + ch_size,
            decrypted_headers: Some(headers),
        });
        total_segments += u64::from(n_segs);
        cur = doff;
        cidx += 1;
    }

    Ok(Envelope {
        file,
        profile,
        scrypt_strength,
        auth,
        auth_start,
        auth_end,
        sig_off,
        pubkey_off: sig_off,
        mainsalt_off: main_salt_off,
        rootmac_off,
        root_off,
        chmac_off,
        root,
        clusters,
        total_segments,
        main: Some(main),
    })
}

impl<'a> Envelope<'a> {
    pub fn parse(file: &'a [u8], key: Option<&MainKey>) -> Result<Self> {
        ensure!(
            file.len() > 12 && &file[0..4] == b"AEA1",
            "not an AEA file (bad magic)"
        );
        let profile = Profile([file[4], file[5], file[6]]);
        ensure!(
            profile == Profile::NO_ENC_SIGNED || profile.id() == 1,
            "profile {} not implemented yet; supported: 0 (no encryption, signed) \
             and 1 (symmetric encryption)",
            profile.id()
        );
        if profile.encrypted() && key.is_none() {
            bail!(
                "profile {} is encrypted: supply the FCS key file with --fcs-key",
                profile.id()
            );
        }
        let scrypt_strength = file[7];
        let authsize = u32le(file, 8)? as usize;
        let auth_start = 12usize;
        let auth_end = auth_start
            .checked_add(authsize)
            .context("auth size overflow")?;
        ensure!(auth_end < file.len(), "auth data runs past EOF");

        let auth = parse_auth_data(&file[auth_start..auth_end])?;

        // No-signature profiles have an empty signature section.
        let sig_off = auth_end;
        let mut off = auth_end;
        if profile.signed() {
            off += SIGNATURE_LEN;
        }

        if profile.encrypted() {
            return parse_profile1(
                file,
                auth,
                auth_start,
                auth_end,
                sig_off,
                off,
                key.expect("checked above"),
            );
        }

        // Profile 0: random 32-byte key from which the main key is derived.
        let pubkey_off = off;
        off += 32;
        let mainsalt_off = off;
        off += 32;
        let rootmac_off = off;
        off += MAC_LEN;
        let root_off = off;
        ensure!(
            root_off + ROOT_HEADER_LEN <= file.len(),
            "truncated: no room for root header"
        );

        // Profile 0 data keys are HMAC-only, so the root header is plaintext.
        let rh = &file[root_off..root_off + ROOT_HEADER_LEN];
        ensure!(
            rh[0x1a..0x30] == [0u8; 22],
            "root header reserved bytes are not zero — parse drift?"
        );
        let root = RootHeader {
            original_size: u64le(rh, 0x0)?,
            encarchive_size: u64le(rh, 0x8)?,
            segment_size: u32le(rh, 0x10)?,
            segments_per_cluster: u32le(rh, 0x14)?,
            compression: rh[0x18].try_into()?,
            checksum: rh[0x19].try_into()?,
        };
        // Sanity floors only: they reject garbage headers, while still
        // admitting spec-legal small geometries (our test archive uses
        // 64 KiB segments × 2 per cluster; Apple ships 16 MiB × 256).
        ensure!(root.segment_size >= 0x1000, "segment size too small");
        ensure!(root.segments_per_cluster >= 1, "no segments per cluster");
        if root.encarchive_size != file.len() as u64 {
            eprintln!(
                "warning: root header encarchive_size {} != file size {}",
                root.encarchive_size,
                file.len()
            );
        }

        let seg_hdr_len = root.segment_header_len();
        let chmac_off = root_off + ROOT_HEADER_LEN;

        // Walk clusters/segments purely from the segment headers.
        let total_segments = root
            .original_size
            .div_ceil(u64::from(root.segment_size))
            .max(1);
        let mut clusters = Vec::new();
        let mut sum_orig = 0u64;
        let mut idx = 0u64;
        let mut cur = chmac_off + MAC_LEN;
        let mut cidx = 0u32;
        // Empirical erratum (Xcode 27.3 b2): the segment-header and segment-MAC
        // lists of every cluster — including the last, partial one — are padded
        // to the full `segments_per_cluster` capacity.
        let spc = root.segments_per_cluster as usize;
        while idx < total_segments {
            let n = u64::from(root.segments_per_cluster).min(total_segments - idx) as u32;
            let seghdrs_off = cur;
            cur += spc * seg_hdr_len;
            let nextchmac_off = cur;
            cur += MAC_LEN;
            let seghmacs_off = cur;
            cur += spc * MAC_LEN;
            let data_off = cur;
            for s in 0..n as usize {
                let ho = seghdrs_off + s * seg_hdr_len;
                // Hostile-header limits (review #6): a decoded segment can
                // never exceed the declared segment size, and the decoded
                // sizes must sum to the declared payload size — otherwise a
                // crafted header could force multi-GiB allocations per
                // decoder thread.
                let orig = u32le(file, ho)?;
                ensure!(
                    orig <= root.segment_size,
                    "segment {idx} decoded size {orig} exceeds segment_size {}",
                    root.segment_size
                );
                let comp = u32le(file, ho + 4)? as usize;
                sum_orig += u64::from(orig);
                cur += comp;
            }
            ensure!(
                cur <= file.len(),
                "truncated: cluster {cidx} runs past EOF (would need {cur}, file is {})",
                file.len()
            );
            clusters.push(Cluster {
                index: cidx,
                segs: n,
                seghdrs_off,
                nextchmac_off,
                seghmacs_off,
                data_off,
                decrypted_headers: None,
            });
            idx += u64::from(n);
            cidx += 1;
        }
        ensure!(
            cur == file.len(),
            "geometry mismatch: segments end at {cur}, file size is {} (truncated download or spec drift?)",
            file.len()
        );
        ensure!(
            sum_orig == root.original_size,
            "segment decoded sizes sum to {sum_orig}, root header declares original_size {}",
            root.original_size
        );

        Ok(Self {
            file,
            profile,
            scrypt_strength,
            auth,
            auth_start,
            auth_end,
            sig_off,
            pubkey_off,
            mainsalt_off,
            rootmac_off,
            root_off,
            chmac_off,
            root,
            clusters,
            total_segments,
            main: None,
        })
    }

    /// Every segment, in payload order. The geometry was validated by
    /// [`Self::parse`], so this walk cannot fail.
    pub fn segments(&self) -> impl Iterator<Item = Segment<'a, '_>> + '_ {
        let file = self.file;
        let seg_hdr_len = self.root.segment_header_len();
        let spc = self.root.segments_per_cluster;
        self.clusters.iter().flat_map(move |c| {
            let mut doff = c.data_off;
            // Profile 1 stores its segment headers encrypted; parse()
            // decrypted them into the cluster. Profile 0 reads plaintext
            // headers straight from the file.
            let hdr_region: &[u8] = c
                .decrypted_headers
                .as_deref()
                .unwrap_or(&file[c.seghdrs_off..c.seghdrs_off + c.segs as usize * seg_hdr_len]);
            (0..c.segs).map(move |s| {
                let ho = s as usize * seg_hdr_len;
                let orig = u32le(hdr_region, ho).expect("validated by parse");
                let comp = u32le(hdr_region, ho + 4).expect("validated by parse");
                let data_off = doff;
                doff += comp as usize;
                Segment {
                    index: c.index * spc + s,
                    cluster: c.index,
                    orig,
                    comp,
                    cksum: &hdr_region[ho + 8..ho + seg_hdr_len],
                    mac: mac_at(file, c.seghmacs_off + s as usize * MAC_LEN),
                    data: &file[data_off..doff],
                    data_off,
                }
            })
        })
    }

    /// The PEM signing-certificate chain from the auth data, if present.
    pub fn certificate_chain(&self) -> Option<&[u8]> {
        self.auth
            .iter()
            .find(|(k, _)| k.ends_with(".signature.certificate-chain"))
            .map(|(_, v)| v.as_slice())
    }

    /// The fixed-size signature field (DER signature, zero padded).
    pub fn signature(&self) -> &'a [u8] {
        &self.file[self.sig_off..self.sig_off + SIGNATURE_LEN]
    }

    /// Bytes covered by the file signature (prefix through the first cluster
    /// MAC), with the 128-byte signature field nulled as the spec requires.
    pub fn signed_prefix(&self) -> Vec<u8> {
        let mut v = self.file[..self.chmac_off + MAC_LEN].to_vec();
        if self.profile.signed() {
            v[self.sig_off..self.sig_off + SIGNATURE_LEN].fill(0);
        }
        v
    }

    // ---- verification ---------------------------------------------------

    /// The archive's AES-master-key equivalent (AEA_AMK): the root of the
    /// HMAC key tree, bound to the signing certificate's public point.
    pub fn main_key(&self, signing_point: &[u8]) -> Key {
        kdf::main_key(
            &self.file[self.pubkey_off..self.pubkey_off + 32],
            &self.file[self.mainsalt_off..self.mainsalt_off + 32],
            &self.file[4..8],
            signing_point,
        )
    }

    pub fn verify_mac(&self, signing_point: &[u8]) -> MacReport {
        let main = self.main_key(signing_point);
        let headers = self.verify_header_macs(&main);
        MacReport {
            root_mac_ok: headers.root_ok,
            cluster_macs_ok: headers.clusters_ok,
            chmac_variant: headers.chmac_variant,
            segmac_failed: self.verify_segment_macs(&main),
        }
    }

    /// MAC verification for profile 1, where the main key comes from the FCS
    /// key rather than the signing public key. The root-header MAC is checked
    /// during parsing (it gates decryption), so here it is reported as ok.
    pub fn verify_mac_encrypted(&self, main: &Key) -> MacReport {
        let mut cluster_macs_ok = true;
        let mut segmac_failed = Vec::new();
        let entry_size = if self.root.checksum == Checksum::Sha256 {
            40
        } else {
            8
        };
        let spc = self.root.segments_per_cluster as usize;
        let headers_size = entry_size * spc;
        let ch_size = headers_size + 32 + 32 * spc;
        for cluster in &self.clusters {
            let ck = kdf::cluster_key(main, cluster.index);
            let ch_mat = kdf::cluster_header_material(&ck);
            let headers_enc = &self.file[cluster.seghdrs_off..cluster.seghdrs_off + headers_size];
            let macs =
                &self.file[cluster.seghdrs_off + headers_size..cluster.seghdrs_off + ch_size];
            let stored = if cluster.index == 0 {
                mac_at(self.file, self.chmac_off)
            } else {
                mac_at(self.file, cluster.nextchmac_off)
            };
            let mut mac_data = Vec::with_capacity(macs.len() + headers_enc.len() + 8);
            mac_data.extend_from_slice(macs);
            mac_data.extend_from_slice(headers_enc);
            mac_data.extend_from_slice(&(macs.len() as u64).to_le_bytes());
            if kdf::mac_raw(&ch_mat[0..32], &mac_data) != *stored {
                cluster_macs_ok = false;
            }
        }
        // Segment MACs: HMAC(key, ciphertext || u64le(0)) over the stored
        // (encrypted) segment bytes.
        let spc = self.root.segments_per_cluster;
        let ckeys: Vec<Key> = self
            .clusters
            .iter()
            .map(|c| kdf::cluster_key(main, c.index))
            .collect();
        for seg in self.segments() {
            let local = seg.index - seg.cluster * spc;
            let s_mat = kdf::segment_material(&ckeys[seg.cluster as usize], local);
            if kdf::mac(&s_mat[0..32], seg.data, b"").as_slice() != seg.mac {
                segmac_failed.push(seg.index);
            }
        }
        MacReport {
            root_mac_ok: true,
            cluster_macs_ok,
            chmac_variant: Some(0),
            segmac_failed,
        }
    }

    /// Root + cluster header MACs only — microseconds, no segment pass.
    /// Extraction runs these synchronously and folds the segment pass into
    /// the decode pipeline via [`Self::verify_segment_macs_with`].
    pub fn verify_header_macs(&self, main: &Key) -> HeaderMacs {
        let root_key = kdf::root_header_key(main);
        let first_chmac = mac_at(self.file, self.chmac_off);
        let mut salt = first_chmac.to_vec();
        salt.extend_from_slice(&self.file[self.auth_start..self.auth_end]);
        let root_ok = kdf::mac(
            &root_key,
            &self.file[self.root_off..self.root_off + ROOT_HEADER_LEN],
            &salt,
        ) == *mac_at(self.file, self.rootmac_off);

        // Cluster header MACs: salt is "the remaining part of the cluster header".
        // Empirically verified on Xcode 27.3 b2 (all three clusters):
        // chmac = mac(cluster_header_key, segment-header list padded to full
        // cluster capacity, next-chmac || segment-MAC list padded to capacity).
        let cap = self.root.segments_per_cluster as usize;
        let seg_hdr_len = self.root.segment_header_len();
        let mut any_matched = false;
        let mut clusters_ok = true;
        for (ci, c) in self.clusters.iter().enumerate() {
            let chek = kdf::cluster_header_key(&kdf::cluster_key(main, c.index));
            let stored = match ci.checked_sub(1) {
                None => first_chmac,
                Some(prev) => mac_at(self.file, self.clusters[prev].nextchmac_off),
            };
            let seghdrs = &self.file[c.seghdrs_off..c.seghdrs_off + cap * seg_hdr_len];
            let salt = &self.file[c.nextchmac_off..c.seghmacs_off + cap * MAC_LEN];
            if kdf::mac(&chek, seghdrs, salt) == *stored {
                any_matched = true;
            } else {
                clusters_ok = false;
            }
        }

        HeaderMacs {
            root_ok,
            clusters_ok,
            chmac_variant: any_matched.then_some(0),
        }
    }

    /// Segment MACs (profile 0): mac(segment_key(cluster-local index),
    /// stored segment bytes, empty salt). A full HMAC pass over the
    /// compressed data, run in parallel chunks; during extraction it runs
    /// concurrently with decoding (cheap on memory bandwidth, mostly not on
    /// the critical path).
    pub fn verify_segment_macs(&self, main: &Key) -> Vec<u32> {
        let nthreads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        self.verify_segment_macs_with(main, nthreads)
    }

    /// Segment-MAC pass with an explicit thread count (extraction uses a
    /// small one so it hides under the decode pipeline instead of racing
    /// the decoders for cores).
    pub fn verify_segment_macs_with(&self, main: &Key, nthreads: usize) -> Vec<u32> {
        let ckeys: Vec<Key> = (0..self.clusters.len() as u32)
            .map(|i| kdf::cluster_key(main, i))
            .collect();
        let spc = self.root.segments_per_cluster;
        let segs: Vec<Segment> = self.segments().collect();
        let encrypted = self.profile.encrypted();
        let mut failed: Vec<u32> = par_chunks(&segs, nthreads, |part| {
            part.iter()
                .filter(|sg| {
                    let local = sg.index - sg.cluster * spc;
                    let ck = &ckeys[sg.cluster as usize];
                    // Profile 0 stores 32-byte HMAC keys; profile 1 derives
                    // 80-byte material (HMAC key + AES key + IV).
                    let mat = kdf::segment_material(ck, local);
                    let segkey: &[u8] = if encrypted {
                        &mat[0..32]
                    } else {
                        &kdf::segment_key(ck, local)
                    };
                    kdf::mac(segkey, sg.data, b"").as_slice() != sg.mac
                })
                .map(|sg| sg.index)
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();
        failed.sort_unstable();
        failed
    }

    /// Verify per-segment checksums: returns how many passed, and the
    /// indices of those that failed. Empirically (Xcode 27.3 b2) the checksum
    /// is over the *decoded* (decompressed) segment data, not the stored bytes;
    /// segments stored uncompressed (orig == comp) trivially match either way.
    pub fn verify_checksums(&self, threads: usize, dec: XzDecoder) -> Result<(u64, Vec<u32>)> {
        ensure!(
            self.root.checksum == Checksum::Sha256,
            "checksum verification currently supports SHA-256 only"
        );
        let encrypted = self.profile.encrypted();
        if !encrypted {
            ensure!(
                self.root.compression == Compression::Lzma,
                "checksum verification implemented for LZMA segments only"
            );
        }
        // Profile 1: derive the cluster keys once, then hand the segment
        // material context to each checksum check.
        let ckeys: Vec<Key> = if encrypted {
            let main = self
                .main
                .as_ref()
                .expect("profile 1 parses with a main key");
            self.clusters
                .iter()
                .map(|c| kdf::cluster_key(main, c.index))
                .collect()
        } else {
            Vec::new()
        };
        let ctx = ChecksumCtx {
            ckeys: &ckeys,
            spc: self.root.segments_per_cluster,
        };
        let segs: Vec<Segment> = self.segments().collect();
        let failed: Vec<u32> = par_chunks(&segs, threads, |part| {
            part.iter()
                .filter(|sg| !checksum_ok(sg, encrypted.then_some(&ctx), dec))
                .map(|sg| sg.index)
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect();
        Ok(((segs.len() - failed.len()) as u64, failed))
    }
}

/// Per-cluster context for profile-1 checksum verification.
struct ChecksumCtx<'a> {
    ckeys: &'a [Key],
    spc: u32,
}

/// Whether `seg`'s decoded bytes match its SHA-256 checksum. A segment that
/// fails to decode fails its checksum.
fn checksum_ok(seg: &Segment<'_, '_>, ctx: Option<&ChecksumCtx<'_>>, dec: XzDecoder) -> bool {
    let digest = if let Some(ctx) = ctx {
        // Profile 1: the stored bytes are AES-CTR-encrypted. Decrypt, then
        // LZFSE-decode when the segment is compressed (comp != orig) — the
        // checksum covers the final plaintext.
        let ck = &ctx.ckeys[seg.cluster as usize];
        let local = seg.index - seg.cluster * ctx.spc;
        let s_mat = kdf::segment_material(ck, local);
        let mut plain = seg.data.to_vec();
        if lzfse::aes_ctr_decrypt(&s_mat, &mut plain).is_err() {
            return false;
        }
        if seg.comp == seg.orig {
            Sha256::digest(&plain)
        } else {
            let mut buf = vec![0u8; seg.orig as usize];
            if lzfse::decode(&plain, &mut buf, seg.orig as usize).is_err() {
                return false;
            }
            Sha256::digest(&buf)
        }
    } else if seg.data.len() == seg.orig as usize {
        Sha256::digest(seg.data)
    } else {
        match xz::decode(seg.data, seg.orig as usize, dec, true) {
            Ok(decoded) => Sha256::digest(&decoded),
            Err(_) => return false,
        }
    };
    digest.as_slice() == seg.cksum
}

/// Split `items` into at most `nthreads` (clamped to 1..=32) contiguous
/// chunks, run `f` on each on its own scoped thread, and return the
/// results in chunk order. A panic in `f` propagates.
fn par_chunks<T: Sync, R: Send>(
    items: &[T],
    nthreads: usize,
    f: impl Fn(&[T]) -> R + Sync,
) -> Vec<R> {
    let chunk = items.len().div_ceil(nthreads.clamp(1, 32)).max(1);
    let f = &f;
    std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|part| scope.spawn(move || f(part)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    })
}

/// Auth data key/value pairs. Empirically (Xcode 27.3 b2) the u32 length
/// prefix counts itself; kinnay's pseudocode reads as if it doesn't.
/// We accept either reading, preferring the inclusive one.
fn parse_auth_data(blob: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    [true, false]
        .into_iter()
        .find_map(|inclusive| try_parse_pairs(blob, inclusive))
        .context("could not parse auth data as key/value pairs")
}

fn try_parse_pairs(blob: &[u8], inclusive: bool) -> Option<Vec<(String, Vec<u8>)>> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < blob.len() {
        let n = u32::from_le_bytes(*blob[pos..].first_chunk()?) as usize;
        let (plen, body) = if inclusive {
            (n, blob.get(pos + 4..pos + n)?)
        } else {
            (n + 4, blob.get(pos + 4..pos + 4 + n)?)
        };
        if plen < 4 || pos + plen > blob.len() {
            return None;
        }
        let nul = body.iter().position(|&b| b == 0)?;
        let key = std::str::from_utf8(&body[..nul]).ok()?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b'.' || b == b'-')
        {
            return None;
        }
        out.push((key.to_string(), body[nul + 1..].to_vec()));
        pos += plen;
    }
    (pos == blob.len() && !out.is_empty() || blob.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end profile-1 parse + verification on the truncated fixture.
    /// The fixture is a head-only fetch of a real archive (cluster 0's
    /// header is fully present; only segment 0's data is), so geometry is
    /// bounded by what the file actually holds.
    #[test]
    fn profile1_fixture_parses_and_verifies() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
        let Ok(data) = std::fs::read(dir.join("141-11453-183-head.bin")) else {
            eprintln!("skipping: fixture 141-11453-183-head.bin not present");
            return;
        };
        let Ok(pem) = std::fs::read(dir.join("141-11453-183-fcs-key.pem")) else {
            eprintln!("skipping: fixture key not present");
            return;
        };
        let auth_len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let auth = &data[12..12 + auth_len];
        let symkey = crate::hpke::unwrap_fcs_key(auth, &pem).expect("FCS key unwrap");
        let key = MainKey::from_slice(&symkey).expect("main key slice");

        let env = Envelope::parse(&data, Some(&key)).expect("profile 1 parse");
        assert_eq!(env.profile.id(), 1);
        assert_eq!(env.root.original_size, 6813646848);
        assert_eq!(env.root.segment_size, 1048576);
        assert_eq!(env.root.segments_per_cluster, 256);
        assert_eq!(env.clusters.len(), 1);
        assert_eq!(env.total_segments, 1);

        // The root-header MAC is checked during parsing; the full report
        // covers the cluster and segment MACs.
        let main = env.main.as_ref().expect("profile 1 parses with a main key");
        let mac = env.verify_mac_encrypted(main);
        assert!(mac.root_mac_ok);
        assert!(mac.cluster_macs_ok, "cluster header MAC mismatch");
        assert!(
            mac.segmac_failed.is_empty(),
            "segment MAC failures: {:?}",
            mac.segmac_failed
        );

        let segs: Vec<Segment> = env.segments().collect();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].orig, 1048576);
        assert_eq!(segs[0].comp, 19318);
        assert_eq!(
            crate::sigverify::hex(segs[0].cksum),
            "d7615d202b3700ca7d56bd6aaffa6a92ecf92beb8caccbc40907f58a3819b457"
        );

        // Checksum pass: AES-CTR decrypt + LZFSE decode + SHA-256 of the
        // decompressed plaintext.
        let (passed, failed) = env
            .verify_checksums(1, crate::xz::XzDecoder::LzmaTurbo)
            .expect("checksum pass");
        assert!(failed.is_empty(), "checksum failures: {failed:?}");
        assert_eq!(passed, 1);
    }
}
