//! Turning one segment's stored bytes back into payload bytes, for any
//! supported profile and compression: decrypt (encrypting profiles), then
//! decompress. The profile-0 extract pipeline has its own zero-copy path
//! (`extract::decode`); this one serves `decrypt` and checksum checks.

use crate::envelope::Compression;
use crate::kdf::CipherKeys;
use crate::xz::{self, XzDecoder};
use anyhow::{Result, bail, ensure};

/// Decode `stored` (one segment's bytes as stored in the archive) into its
/// `orig` payload bytes. `keys` decrypts first when the profile encrypts.
/// A segment whose stored size equals `orig` is stored uncompressed.
pub fn decode(
    stored: &[u8],
    orig: usize,
    keys: Option<&CipherKeys>,
    compression: Compression,
    dec: XzDecoder,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    decode_into(
        stored,
        orig,
        keys,
        compression,
        dec,
        &mut Vec::new(),
        &mut out,
    )?;
    Ok(out)
}

/// [`decode`] into caller-owned buffers, so a worker can reuse them across
/// segments (fresh 1 MiB buffers per segment cost a page fault per page).
/// `scratch` holds the decrypted bytes of a compressed segment; `out`
/// receives the payload.
pub fn decode_into(
    stored: &[u8],
    orig: usize,
    keys: Option<&CipherKeys>,
    compression: Compression,
    dec: XzDecoder,
    scratch: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<()> {
    // Decrypting copies out of the (read-only) archive map anyway, so it
    // goes straight to where the bytes are needed next. `resize` of a
    // reused buffer to the same length touches nothing.
    let plain_stored: &[u8] = match keys {
        Some(k) if stored.len() == orig => {
            out.resize(orig, 0);
            k.apply_ctr_b2b(stored, out);
            return Ok(());
        }
        Some(k) => {
            scratch.resize(stored.len(), 0);
            k.apply_ctr_b2b(stored, scratch);
            scratch
        }
        None if stored.len() == orig => {
            out.clear();
            out.extend_from_slice(stored);
            return Ok(());
        }
        None => stored,
    };
    match compression {
        Compression::Lzma => {
            let buf = xz::decode(plain_stored, orig, dec, true)?;
            out.clear();
            out.extend_from_slice(&buf);
        }
        Compression::Lzfse => lzfse(plain_stored, orig, out)?,
        Compression::None => bail!(
            "segment stores {} bytes for {orig} payload bytes, but the archive is uncompressed",
            stored.len()
        ),
        other => bail!("{other} segment compression is not supported yet"),
    }
    ensure!(
        out.len() == orig,
        "segment decoded to {} bytes, header declares {orig}",
        out.len()
    );
    Ok(())
}

/// LZFSE through Apple's libcompression, which decodes ~20% faster than
/// the pure-Rust port.
#[cfg(target_os = "macos")]
fn lzfse(data: &[u8], orig: usize, out: &mut Vec<u8>) -> Result<()> {
    const COMPRESSION_LZFSE: i32 = 0x801;
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
    }
    // One spare byte: decode_buffer silently truncates an over-long
    // stream, and a full buffer is how that shows.
    out.clear();
    out.reserve(orig + 1);
    // SAFETY: `out` has `orig + 1` bytes of capacity and `data` is valid
    // for its length; a null scratch makes libcompression allocate its own.
    // The decoder initializes the `n` bytes it reports.
    let n = unsafe {
        let n = compression_decode_buffer(
            out.as_mut_ptr(),
            orig + 1,
            data.as_ptr(),
            data.len(),
            std::ptr::null_mut(),
            COMPRESSION_LZFSE,
        );
        out.set_len(n);
        n
    };
    ensure!(n != 0, "LZFSE decode failed");
    Ok(())
}

/// LZFSE through the pure-Rust port.
#[cfg(not(target_os = "macos"))]
fn lzfse(data: &[u8], orig: usize, out: &mut Vec<u8>) -> Result<()> {
    out.clear();
    out.reserve(orig);
    lzfse_rust::decode_bytes(data, out).map_err(|e| anyhow::anyhow!("LZFSE decode failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lzfse_and_stored_segments() {
        let plain: Vec<u8> = (0..50_000u32)
            .flat_map(|i| (i % 251).to_le_bytes())
            .collect();
        let mut comp = Vec::new();
        lzfse_rust::encode_bytes(&plain, &mut comp).unwrap();
        assert!(comp.len() < plain.len());
        let d = |v: Vec<u8>| {
            decode(
                &v,
                plain.len(),
                None,
                Compression::Lzfse,
                XzDecoder::LzmaTurbo,
            )
        };
        assert_eq!(d(comp.clone()).unwrap(), plain);
        assert_eq!(d(plain.clone()).unwrap(), plain, "stored as-is");
        assert!(d(comp[..comp.len() / 2].to_vec()).is_err(), "truncated");
    }

    #[test]
    fn decrypts_before_decoding() {
        let keys = crate::kdf::segment_cipher(&[1u8; 32], 0);
        let plain = b"restore image bytes".to_vec();
        let mut stored = plain.clone();
        keys.apply_ctr(&mut stored);
        let got = decode(
            &stored,
            plain.len(),
            Some(&keys),
            Compression::Lzfse,
            XzDecoder::LzmaTurbo,
        );
        assert_eq!(got.unwrap(), plain);
    }

    #[test]
    fn reused_buffers_hold_only_the_latest_segment() {
        let keys = crate::kdf::segment_cipher(&[2u8; 32], 0);
        let (mut scratch, mut out) = (Vec::new(), Vec::new());
        let big: Vec<u8> = b"compressible ".repeat(5000);
        let mut comp = Vec::new();
        lzfse_rust::encode_bytes(&big, &mut comp).unwrap();
        keys.apply_ctr(&mut comp);
        let mut short = b"short".to_vec();
        keys.apply_ctr(&mut short);
        for (stored, plain) in [(&comp, &big), (&short, &b"short".to_vec()), (&comp, &big)] {
            let (k, c, x) = (Some(&keys), Compression::Lzfse, XzDecoder::LzmaTurbo);
            decode_into(stored, plain.len(), k, c, x, &mut scratch, &mut out).unwrap();
            assert_eq!(&out, plain);
        }
    }
}
