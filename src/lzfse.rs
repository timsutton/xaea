//! LZFSE segment decoding and the AES-256-CTR stream used by encrypted
//! profiles.
//!
//! Profile 1 stores its segments compressed with Apple's LZFSE codec, which
//! is not published as a portable reference implementation. macOS ships it in
//! `libcompression`, the same system library used for LZMA in [`crate::xz`],
//! so decoding goes through it via FFI.

use aes::Aes256;
use anyhow::{Result, bail};
use ctr::cipher::{KeyIvInit, StreamCipher};

/// `COMPRESSION_LZFSE` in `<compression.h>`.
const COMPRESSION_LZFSE: i32 = 0x801;

/// Decrypts `data` in place with AES-256-CTR using the 32-byte key and
/// 16-byte IV from an 80-byte derived key material (the layout profile 1
/// derives: 32-byte MAC key, 32-byte AES key, 16-byte IV).
pub fn aes_ctr_decrypt(mat: &[u8], data: &mut [u8]) -> Result<()> {
    if mat.len() != 80 {
        bail!("expected 80 bytes of key material, got {}", mat.len());
    }
    let mut cipher = ctr::Ctr128BE::<Aes256>::new_from_slices(&mat[32..64], &mat[64..80])
        .map_err(|_| anyhow::anyhow!("invalid AES-CTR key/IV size"))?;
    cipher.apply_keystream(data);
    Ok(())
}

/// Decodes an LZFSE stream into `dst`, which must be exactly
/// `expected` bytes long.
pub fn decode(src: &[u8], dst: &mut [u8], expected: usize) -> Result<()> {
    if dst.len() != expected {
        bail!(
            "LZFSE output buffer is {} bytes, expected {expected}",
            dst.len()
        );
    }
    if expected == 0 {
        return Ok(());
    }
    lz_decode(src, dst)
}

#[cfg(target_os = "macos")]
mod lz {
    use super::COMPRESSION_LZFSE;
    use anyhow::{Result, bail};
    use std::cell::RefCell;
    use std::ffi::c_void;

    #[link(name = "compression")]
    unsafe extern "C" {
        fn compression_decode_buffer(
            dst_ptr: *mut u8,
            dst_size: usize,
            src_ptr: *const u8,
            src_size: usize,
            scratch_ptr: *mut c_void,
            algorithm: i32,
        ) -> usize;
        fn compression_decode_scratch_buffer_size(algorithm: i32) -> usize;
    }

    thread_local! {
        static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    pub fn lz_decode(src: &[u8], dst: &mut [u8]) -> Result<()> {
        let written = SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            // SAFETY: the FFI reads only the algorithm id; no pointers are involved.
            let needed = unsafe { compression_decode_scratch_buffer_size(COMPRESSION_LZFSE) };
            if scratch.len() < needed {
                scratch.resize(needed.max(1), 0);
            }
            // SAFETY: dst and src are contiguous Rust slices and scratch holds at
            // least the advertised scratch size, matching the contract of
            // compression_decode_buffer.
            unsafe {
                compression_decode_buffer(
                    dst.as_mut_ptr(),
                    dst.len(),
                    src.as_ptr(),
                    src.len(),
                    scratch.as_mut_ptr().cast(),
                    COMPRESSION_LZFSE,
                )
            }
        });
        if written != dst.len() {
            bail!(
                "LZFSE decode produced {written} bytes, expected {}",
                dst.len()
            );
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
mod lz {
    use anyhow::{Result, bail};

    pub fn lz_decode(_src: &[u8], _dst: &mut [u8]) -> Result<()> {
        bail!("LZFSE decoding is only supported on macOS")
    }
}

use lz::lz_decode;
