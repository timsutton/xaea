//! AEA envelope parsing per kinnay's FORMAT.md (github.com/kinnay/AEA),
//! with errata verified against Apple's real Xcode 27.3 beta 2 artifact
//! (see doc/FORMAT-NOTES.md).

use crate::kdf;
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Which LZMA (.xz) implementation decodes segments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum XzDecoder {
    /// liblzma (xz-utils), statically linked into xaea — portable default
    #[default]
    Liblzma,
    /// Apple's libcompression (COMPRESSION_LZMA), provided by the OS — macOS
    /// only; roughly 5% faster full extracts on M3 Max
    Libcompression,
}

impl XzDecoder {
    pub fn name(self) -> &'static str {
        match self {
            XzDecoder::Liblzma => "liblzma",
            XzDecoder::Libcompression => "libcompression",
        }
    }

    /// Fail early (before any work) if this decoder isn't available here.
    pub fn check_available(self) -> Result<()> {
        ensure!(
            self != XzDecoder::Libcompression || cfg!(target_os = "macos"),
            "--decoder libcompression is only available on macOS"
        );
        Ok(())
    }
}

/// A segment buffer: decoded bytes shared zero-copy between the parser and
/// the writers (see `aa::Piece`).
pub type SegBuf = Arc<[u8]>;

/// Allocate a `len`-byte [`SegBuf`] and let `fill` write it in place through
/// a raw pointer, so decoders write straight into the buffer the writers
/// will read. Going through `Vec` -> `Box<[u8]>` -> `Arc::from` instead
/// costs a second allocation and a full copy of every segment: `Arc` keeps
/// its refcounts in front of the data, so it cannot adopt a `Box`'s
/// allocation.
///
/// # Safety
/// When `fill` returns `Ok`, it must have initialized all `len` bytes at
/// the pointer it was given (and written nothing beyond them). On `Err` the
/// buffer is dropped without being read.
pub(crate) unsafe fn segbuf_filled(
    len: usize,
    fill: impl FnOnce(*mut u8) -> Result<()>,
) -> Result<SegBuf> {
    let mut buf = Arc::<[u8]>::new_uninit_slice(len);
    let dst = Arc::get_mut(&mut buf)
        .expect("freshly allocated Arc is unique")
        .as_mut_ptr()
        .cast::<u8>();
    fill(dst)?;
    // SAFETY: per this function's contract, `fill` initialized every byte.
    Ok(unsafe { buf.assume_init() })
}

/// Decompress one standalone .xz-stream segment whose decoded size `orig`
/// is known from the segment header; anything else is an error.
///
/// `sha256_follows`: the caller will SHA-256 the decoded bytes against the
/// segment checksum, which makes the .xz stream's own integrity check
/// (typically CRC64 over the same decoded bytes) redundant, so liblzma
/// skips it (`LZMA_IGNORE_CHECK`, ~12% of decode time in a benchmark).
/// Without verification the xz check stays on — it is then the only one.
pub fn decode_xz(data: &[u8], orig: usize, dec: XzDecoder, sha256_follows: bool) -> Result<SegBuf> {
    match dec {
        XzDecoder::Liblzma => liblzma_decode(data, orig, sha256_follows),
        #[cfg(target_os = "macos")]
        XzDecoder::Libcompression => libcompression::decode(data, orig),
        #[cfg(not(target_os = "macos"))]
        XzDecoder::Libcompression => bail!("libcompression is only available on macOS"),
    }
}

/// One-shot liblzma decode (`lzma_stream_buffer_decode`) straight into the
/// exact-size segment buffer: no `Read`/`BufReader` layer copying the input
/// through a small buffer, no zero-filling of the output before decoding
/// into it. Same acceptance as the streaming decoder it replaces: one .xz
/// stream, decoded size exactly `orig` (longer → LZMA_BUF_ERROR, shorter →
/// size mismatch), bytes after the end of the stream ignored.
fn liblzma_decode(data: &[u8], orig: usize, ignore_check: bool) -> Result<SegBuf> {
    use liblzma_sys as lz;
    let flags = if ignore_check {
        lz::LZMA_IGNORE_CHECK
    } else {
        0
    };
    let fill = |dst: *mut u8| -> Result<()> {
        let (mut memlimit, mut in_pos, mut out_pos) = (u64::MAX, 0usize, 0usize);
        // SAFETY: `data` is a valid input buffer of `data.len()` bytes and
        // `dst` points to `orig` writable bytes; liblzma writes at most
        // `orig` bytes there and reports how many in `out_pos`.
        let ret = unsafe {
            lz::lzma_stream_buffer_decode(
                &mut memlimit,
                flags,
                std::ptr::null(),
                data.as_ptr(),
                &mut in_pos,
                data.len(),
                dst,
                &mut out_pos,
                orig,
            )
        };
        let what = match ret {
            lz::LZMA_OK => None,
            lz::LZMA_FORMAT_ERROR => Some("not an .xz stream"),
            lz::LZMA_OPTIONS_ERROR => Some("unsupported .xz options"),
            lz::LZMA_DATA_ERROR => Some("corrupt data"),
            lz::LZMA_BUF_ERROR => Some("output exceeds the declared size, or input truncated"),
            lz::LZMA_MEMLIMIT_ERROR | lz::LZMA_MEM_ERROR => Some("out of memory"),
            _ => Some("liblzma error"),
        };
        if let Some(what) = what {
            bail!("xz decode: {what} (lzma_ret {ret})");
        }
        ensure!(
            out_pos == orig,
            "xz decoded size mismatch ({out_pos} vs {orig})"
        );
        Ok(())
    };
    // SAFETY: `fill` returns Ok only when liblzma wrote exactly `orig` bytes.
    unsafe { segbuf_filled(orig, fill) }
}

#[cfg(target_os = "macos")]
mod libcompression {
    use super::SegBuf;
    use anyhow::{Result, ensure};
    use std::cell::RefCell;

    /// COMPRESSION_LZMA: LZMA2 in an .xz container (<compression.h>).
    const COMPRESSION_LZMA: i32 = 0x306;

    #[link(name = "compression")]
    unsafe extern "C" {
        fn compression_decode_buffer(
            dst: *mut u8,
            dst_size: usize,
            src: *const u8,
            src_size: usize,
            scratch: *mut core::ffi::c_void,
            algorithm: i32,
        ) -> usize;
        fn compression_decode_scratch_buffer_size(algorithm: i32) -> usize;
    }

    thread_local! {
        // One scratch buffer per decoder thread instead of letting
        // libcompression allocate one per call.
        static SCRATCH: RefCell<Vec<u8>> = RefCell::new(vec![
            0u8;
            unsafe { compression_decode_scratch_buffer_size(COMPRESSION_LZMA) }
        ]);
    }

    /// The output buffer is exactly `orig` bytes: a spare byte (to detect an
    /// over-long stream, which decode_buffer silently truncates) once forced
    /// a realloc+copy and measured 5x peak RSS. Over-long streams are
    /// instead caught by the per-segment SHA-256 when verifying.
    pub fn decode(data: &[u8], orig: usize) -> Result<SegBuf> {
        let fill = |dst: *mut u8| -> Result<()> {
            // SAFETY: `dst` points to `orig` writable bytes; `data` and the
            // scratch buffer are valid for their lengths.
            let n = SCRATCH.with_borrow_mut(|scratch| unsafe {
                compression_decode_buffer(
                    dst,
                    orig,
                    data.as_ptr(),
                    data.len(),
                    scratch.as_mut_ptr().cast(),
                    COMPRESSION_LZMA,
                )
            });
            ensure!(
                n == orig,
                "libcompression xz decode failed or size mismatch ({n} vs {orig})"
            );
            Ok(())
        };
        // SAFETY: `fill` returns Ok only when all `orig` bytes were written.
        unsafe { super::segbuf_filled(orig, fill) }
    }
}

pub const ROOT_HEADER_LEN: usize = 0x30;
pub const SIGNATURE_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile(pub [u8; 3]);

impl Profile {
    pub const NO_ENC_SIGNED: Profile = Profile([0, 0, 0]);

    /// The profile id is a 24-bit little-endian number whose low byte encodes
    /// the signature scheme (even = signed, odd = unsigned).
    pub fn signed(&self) -> bool {
        matches!(self.0[0], 0 | 2 | 4)
    }
    pub fn encrypted(&self) -> bool {
        self.0 != [0, 0, 0]
    }
    pub fn id(&self) -> u32 {
        u32::from_le_bytes([self.0[0], self.0[1], self.0[2], 0])
    }
}

pub fn compression_name(c: u8) -> &'static str {
    match c {
        b'-' => "none",
        b'4' => "LZ4",
        b'b' => "LZBITMAP",
        b'e' => "LZFSE",
        b'f' => "LZVN",
        b'x' => "LZMA",
        b'z' => "ZLIB",
        _ => "unknown",
    }
}

pub fn checksum_name(c: u8) -> &'static str {
    match c {
        0 => "none",
        1 => "MurmurHash64A",
        2 => "SHA-256",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RootHeader {
    pub original_size: u64,
    pub encarchive_size: u64,
    pub segment_size: u32,
    pub segments_per_cluster: u32,
    pub compression: u8,
    pub checksum: u8,
}

#[derive(Debug, Clone)]
pub struct Cluster {
    pub index: u32,
    pub segs: u32,
    pub seghdrs_off: usize,
    pub nextchmac_off: usize,
    pub seghmacs_off: usize,
    pub data_off: usize,
}

#[derive(Debug)]
pub struct Segment<'a> {
    pub index: u32,
    pub cluster: u32,
    pub orig: u32,
    pub comp: u32,
    pub cksum: &'a [u8],
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
}

fn u32le(b: &[u8], at: usize) -> Result<u32> {
    let n: [u8; 4] = b.get(at..at + 4).context("short read")?.try_into().unwrap();
    Ok(u32::from_le_bytes(n))
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    let n: [u8; 8] = b.get(at..at + 8).context("short read")?.try_into().unwrap();
    Ok(u64::from_le_bytes(n))
}

impl<'a> Envelope<'a> {
    pub fn parse(file: &'a [u8]) -> Result<Self> {
        ensure!(
            file.len() > 12 && &file[0..4] == b"AEA1",
            "not an AEA file (bad magic)"
        );
        let profile = Profile([file[4], file[5], file[6]]);
        ensure!(
            profile == Profile::NO_ENC_SIGNED,
            "profile {} (encrypted variants) not implemented yet; only profile 0 (no encryption, signed)",
            profile.id()
        );
        let scrypt_strength = file[7];
        let authsize = u32le(file, 8)? as usize;
        let auth_start = 12usize;
        let auth_end = auth_start
            .checked_add(authsize)
            .context("auth size overflow")?;
        ensure!(auth_end < file.len(), "auth data runs past EOF");

        let auth = parse_auth_data(&file[auth_start..auth_end])?;

        let mut off = auth_end;
        let sig_off = if profile.signed() {
            let s = off;
            off += SIGNATURE_LEN;
            Some(s)
        } else {
            None
        };
        let sig_off = sig_off.unwrap_or(auth_end); // no-signature profiles: empty section
        // Profile 0: random 32-byte key from which the main key is derived.
        let pubkey_off = off;
        off += 32;
        let mainsalt_off = off;
        off += 32;
        let rootmac_off = off;
        off += 32;
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
            compression: rh[0x18],
            checksum: rh[0x19],
        };
        // Sanity floors only: they reject garbage headers, while still
        // admitting spec-legal small geometries (our test archive uses
        // 64 KiB segments × 2 per cluster; Apple ships 16 MiB × 256).
        ensure!(root.segment_size >= 0x1000, "segment size too small");
        ensure!(root.segments_per_cluster >= 1, "no segments per cluster");
        ensure!(
            checksum_name(root.checksum) != "unknown",
            "unknown checksum algorithm {}",
            root.checksum
        );
        ensure!(
            compression_name(root.compression) != "unknown",
            "unknown compression algorithm {:#x}",
            root.compression
        );
        if root.encarchive_size as usize != file.len() {
            eprintln!(
                "warning: root header encarchive_size {} != file size {}",
                root.encarchive_size,
                file.len()
            );
        }

        let ck_len = match root.checksum {
            0 => 0,
            1 => 8,
            2 => 32,
            _ => unreachable!(),
        };
        let seg_hdr_len = 8 + ck_len;
        let chmac_off = root_off + ROOT_HEADER_LEN;

        // Walk clusters/segments purely from the segment headers.
        let total_segments = root.original_size.div_ceil(root.segment_size as u64).max(1);
        let mut clusters = Vec::new();
        let mut sum_orig = 0u64;
        let mut idx = 0u64;
        let mut cur = chmac_off + 32;
        let mut cidx = 0u32;
        // Empirical erratum (Xcode 27.3 b2): the segment-header and segment-MAC
        // lists of every cluster — including the last, partial one — are padded
        // to the full `segments_per_cluster` capacity.
        let spc = root.segments_per_cluster as usize;
        while idx < total_segments {
            let n = std::cmp::min(root.segments_per_cluster as u64, total_segments - idx) as u32;
            let seghdrs_off = cur;
            cur += spc * seg_hdr_len;
            let nextchmac_off = cur;
            cur += 32;
            let seghmacs_off = cur;
            cur += spc * 32;
            let data_off = cur;
            for s in 0..n {
                let ho = seghdrs_off + (s as usize) * seg_hdr_len;
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
                sum_orig += orig as u64;
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
            });
            idx += n as u64;
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
        })
    }

    pub fn segments(&self) -> Vec<Segment<'a>> {
        let ck_len = match self.root.checksum {
            0 => 0,
            1 => 8,
            _ => 32,
        };
        let seg_hdr_len = 8 + ck_len;
        let file = self.file;
        let mut out = Vec::with_capacity(self.total_segments as usize);
        let mut index = 0u32;
        for c in &self.clusters {
            let mut doff = c.data_off;
            for s in 0..c.segs {
                let ho = c.seghdrs_off + (s as usize) * seg_hdr_len;
                let orig = u32::from_le_bytes(file[ho..ho + 4].try_into().unwrap());
                let comp = u32::from_le_bytes(file[ho + 4..ho + 8].try_into().unwrap()) as usize;
                out.push(Segment {
                    index,
                    cluster: c.index,
                    orig,
                    comp: comp as u32,
                    cksum: &file[ho + 8..ho + seg_hdr_len],
                    mac: &file[c.seghmacs_off + (s as usize) * 32..][..32],
                    data_off: doff,
                    data: &file[doff..doff + comp],
                });
                doff += comp;
                index += 1;
            }
        }
        out
    }

    /// Bytes covered by the file signature (prefix through the first cluster
    /// MAC), with the 128-byte signature field nulled as the spec requires.
    pub fn signed_prefix(&self) -> Vec<u8> {
        let end = self.chmac_off + 32;
        let mut v = self.file[..end].to_vec();
        if self.profile.signed() {
            for b in &mut v[self.sig_off..self.sig_off + SIGNATURE_LEN] {
                *b = 0;
            }
        }
        v
    }

    // ---- verification ---------------------------------------------------

    /// The archive's AES-master-key equivalent (AEA_AMK): the root of the
    /// HMAC key tree, bound to the signing certificate's public point.
    pub fn main_key(&self, signing_point: &[u8]) -> Vec<u8> {
        kdf::main_key(
            &self.file[self.pubkey_off..self.pubkey_off + 32],
            &self.file[self.mainsalt_off..self.mainsalt_off + 32],
            &self.file[4..8],
            signing_point,
        )
    }

    pub fn verify_mac(&self, signing_point: &[u8]) -> Result<MacReport> {
        ensure!(
            !self.profile.encrypted(),
            "MAC verification for encrypted profiles not implemented"
        );
        let main = self.main_key(signing_point);
        self.verify_mac_keyed(&main)
    }

    /// Root + cluster + segment MACs, given the main key (so the expensive
    /// segment pass can run concurrently with extraction).
    pub fn verify_mac_keyed(&self, main: &[u8]) -> Result<MacReport> {
        let (root_mac_ok, cluster_macs_ok, chmac_variant) = self.verify_header_macs(main)?;
        Ok(MacReport {
            root_mac_ok,
            cluster_macs_ok,
            chmac_variant,
            segmac_failed: self.verify_segment_macs(main),
        })
    }

    /// Root + cluster header MACs only — microseconds, no segment pass.
    /// Extraction runs these synchronously and folds the segment pass into
    /// the decode pipeline via [`Self::verify_segment_macs`].
    pub fn verify_header_macs(&self, main: &[u8]) -> Result<(bool, bool, Option<usize>)> {
        let root_key = kdf::root_header_key(main);
        let first_chmac = &self.file[self.chmac_off..self.chmac_off + 32];
        let mut salt = first_chmac.to_vec();
        salt.extend_from_slice(&self.file[self.auth_start..self.auth_end]);
        let stored_root_mac: [u8; 32] = self.file[self.rootmac_off..self.rootmac_off + 32]
            .try_into()
            .unwrap();
        let root_mac_ok = kdf::mac(
            &root_key,
            &self.file[self.root_off..self.root_off + ROOT_HEADER_LEN],
            &salt,
        ) == stored_root_mac;

        // Cluster header MACs: salt is "the remaining part of the cluster header".
        let mut chmac_variant = None;
        let mut cluster_macs_ok = true;
        for (ci, c) in self.clusters.iter().enumerate() {
            let ck = kdf::cluster_key(main, c.index);
            let chek = kdf::cluster_header_key(&ck);
            let stored: [u8; 32] = if ci == 0 {
                first_chmac
            } else {
                &self.file
                    [self.clusters[ci - 1].nextchmac_off..self.clusters[ci - 1].nextchmac_off + 32]
            }
            .try_into()
            .unwrap();
            // Empirically verified on Xcode 27.3 b2 (all three clusters):
            // chmac = mac(cluster_header_key, segment-header list padded to full
            // cluster capacity, next-chmac || segment-MAC list padded to capacity).
            let seg_hdr_len = 8 + match self.root.checksum {
                0 => 0,
                1 => 8,
                _ => 32,
            };
            let cap = self.root.segments_per_cluster as usize;
            let seghdrs = &self.file[c.seghdrs_off..c.seghdrs_off + cap * seg_hdr_len];
            let salt = &self.file[c.nextchmac_off..c.seghmacs_off + cap * 32];
            let matched = if kdf::mac(&chek, seghdrs, salt) == stored {
                Some(0)
            } else {
                None
            };
            match matched {
                Some(v) => {
                    if chmac_variant.is_none() {
                        chmac_variant = Some(v);
                    }
                }
                None => cluster_macs_ok = false,
            }
        }

        Ok((root_mac_ok, cluster_macs_ok, chmac_variant))
    }

    /// Segment MACs (profile 0): mac(segment_key(cluster-local index),
    /// stored segment bytes, empty salt). A full HMAC pass over the
    /// compressed data, run in parallel chunks; during extraction it runs
    /// concurrently with decoding (cheap on memory bandwidth, mostly not on
    /// the critical path).
    pub fn verify_segment_macs(&self, main: &[u8]) -> Vec<u32> {
        let nthreads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 32);
        self.verify_segment_macs_with(main, nthreads)
    }

    /// Segment-MAC pass with an explicit thread count (extraction uses a
    /// small one so it hides under the decode pipeline instead of racing
    /// the decoders for cores).
    pub fn verify_segment_macs_with(&self, main: &[u8], nthreads: usize) -> Vec<u32> {
        let ckeys: Vec<Vec<u8>> = (0..self.clusters.len() as u32)
            .map(|i| kdf::cluster_key(main, i))
            .collect();
        let spc = self.root.segments_per_cluster;
        let segs = self.segments();
        let nthreads = nthreads.clamp(1, 32);
        let chunk = segs.len().div_ceil(nthreads);
        let mut segmac_failed: Vec<u32> = Vec::new();
        std::thread::scope(|scope| {
            let results: Vec<_> = (0..nthreads)
                .map(|t| {
                    let part =
                        &segs[(t * chunk).min(segs.len())..((t + 1) * chunk).min(segs.len())];
                    let ckeys = &ckeys;
                    scope.spawn(move || {
                        let mut failed = Vec::new();
                        for sg in part {
                            let local = sg.index - sg.cluster * spc;
                            let segkey = kdf::segment_key(&ckeys[sg.cluster as usize], local);
                            if kdf::mac(&segkey, sg.data, b"") != *sg.mac {
                                failed.push(sg.index);
                            }
                        }
                        failed
                    })
                })
                .collect();
            for r in results {
                segmac_failed.extend(r.join().unwrap());
            }
        });
        segmac_failed.sort_unstable();
        segmac_failed
    }

    /// Verify per-segment checksums. Empirically (Xcode 27.3 b2) the checksum
    /// is over the *decoded* (decompressed) segment data, not the stored bytes;
    /// segments stored uncompressed (orig == comp) trivially match either way.
    pub fn verify_checksums(&self, threads: usize, dec: XzDecoder) -> Result<(u64, Vec<u32>)> {
        ensure!(
            self.root.checksum == 2,
            "checksum verification currently supports SHA-256 only"
        );
        ensure!(
            self.root.compression == b'x',
            "checksum verification implemented for LZMA segments only"
        );
        let segs: Vec<(u32, &[u8], &[u8], u32)> = self
            .segments()
            .into_iter()
            .map(|s| (s.index, s.data, s.cksum, s.orig))
            .collect();
        let nthreads = threads.clamp(1, 32);
        let chunk = segs.len().div_ceil(nthreads);
        let mut ok = 0u64;
        let mut failed = Vec::new();
        std::thread::scope(|scope| {
            let results: Vec<_> = (0..nthreads)
                .map(|t| {
                    let part =
                        &segs[(t * chunk).min(segs.len())..((t + 1) * chunk).min(segs.len())];
                    scope.spawn(move || {
                        let mut ok = 0u64;
                        let mut failed = Vec::new();
                        for (idx, data, cksum, orig) in part {
                            let owned;
                            let decoded: &[u8] = if data.len() as u32 == *orig {
                                data
                            } else {
                                match decode_xz(data, *orig as usize, dec, true) {
                                    Ok(d) => {
                                        owned = d;
                                        &owned
                                    }
                                    Err(_) => {
                                        failed.push(*idx);
                                        continue;
                                    }
                                }
                            };
                            if decoded.len() as u32 != *orig {
                                failed.push(*idx);
                                continue;
                            }
                            let h: [u8; 32] = Sha256::digest(decoded).into();
                            if h.as_slice() == *cksum {
                                ok += 1;
                            } else {
                                failed.push(*idx);
                            }
                        }
                        (ok, failed)
                    })
                })
                .collect();
            for r in results {
                let (o, f) = r.join().unwrap();
                ok += o;
                failed.extend(f);
            }
        });
        Ok((ok, failed))
    }
}

#[derive(Debug)]
pub struct MacReport {
    pub root_mac_ok: bool,
    pub cluster_macs_ok: bool,
    pub chmac_variant: Option<usize>,
    pub segmac_failed: Vec<u32>,
}

/// Auth data key/value pairs. Empirically (Xcode 27.3 b2) the u32 length
/// prefix counts itself; kinnay's pseudocode reads as if it doesn't.
/// We accept either reading, preferring the inclusive one.
fn parse_auth_data(blob: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    for inclusive in [true, false] {
        if let Some(pairs) = try_parse_pairs(blob, inclusive) {
            return Ok(pairs);
        }
    }
    bail!("could not parse auth data as key/value pairs")
}

fn try_parse_pairs(blob: &[u8], inclusive: bool) -> Option<Vec<(String, Vec<u8>)>> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < blob.len() {
        if pos + 4 > blob.len() {
            return None;
        }
        let n = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
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

    fn xz(data: &[u8]) -> Vec<u8> {
        use std::io::Read;
        let mut v = Vec::new();
        // Default check for this encoder: CRC64.
        liblzma::read::XzEncoder::new(data, 6)
            .read_to_end(&mut v)
            .unwrap();
        v
    }

    #[test]
    fn liblzma_one_shot_decode() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let n = data.len();
        let enc = xz(&data);
        let dec = |b: &[u8], orig, ignore| decode_xz(b, orig, XzDecoder::Liblzma, ignore);
        for ignore in [false, true] {
            assert_eq!(&*dec(&enc, n, ignore).unwrap(), &data[..]);
        }
        // Declared size must match exactly, in both directions.
        assert!(dec(&enc, n - 1, true).is_err(), "over-long stream");
        assert!(dec(&enc, n + 1, true).is_err(), "short stream");
        assert!(dec(&enc[..enc.len() / 2], n, true).is_err(), "truncated");

        // Flip a bit of the stored CRC64: caught when the xz check is the
        // only one, skipped when the caller's SHA-256 will cover the bytes.
        let crc = unsafe { liblzma_sys::lzma_crc64(data.as_ptr(), data.len(), 0) }.to_le_bytes();
        let at = enc
            .windows(8)
            .position(|w| w == crc)
            .expect("CRC64 stored in stream");
        let mut bad = enc.clone();
        bad[at] ^= 1;
        assert!(dec(&bad, n, false).is_err(), "check enforced");
        assert_eq!(&*dec(&bad, n, true).unwrap(), &data[..], "check skipped");
    }
}
