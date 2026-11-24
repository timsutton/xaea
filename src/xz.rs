//! Segment decompression: one standalone .xz stream per segment, decoded
//! straight into the buffer the writers will read.

use anyhow::{Result, bail, ensure};
use std::sync::Arc;

/// Which LZMA (.xz) implementation decodes segments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum XzDecoder {
    /// liblzma (xz-utils), statically linked into xaea — portable default
    #[default]
    Liblzma,
    /// Apple's libcompression (COMPRESSION_LZMA), provided by the OS — macOS
    /// only; full-extract speed is indistinguishable from liblzma
    Libcompression,
    /// xz-native: a pure-Rust port of liblzma 5.8.4 (no C)
    XzNative,
}

impl XzDecoder {
    pub fn name(self) -> &'static str {
        match self {
            XzDecoder::Liblzma => "liblzma",
            XzDecoder::Libcompression => "libcompression",
            XzDecoder::XzNative => "xz-native",
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
pub unsafe fn segbuf_filled(
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
/// (e.g. CRC64 over the same decoded bytes) redundant, so liblzma skips it
/// (`LZMA_IGNORE_CHECK`; ~9% of decode time for CRC64 streams). Apple's own
/// segments declare check type "none", so for them this flag changes nothing.
/// Without verification the xz check stays on, if the stream has one.
pub fn decode(data: &[u8], orig: usize, dec: XzDecoder, sha256_follows: bool) -> Result<SegBuf> {
    match dec {
        XzDecoder::Liblzma => liblzma_decode(data, orig, sha256_follows),
        XzDecoder::XzNative => xz_native_decode(data, orig, sha256_follows),
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
                &raw mut memlimit,
                flags,
                std::ptr::null(),
                data.as_ptr(),
                &raw mut in_pos,
                data.len(),
                dst,
                &raw mut out_pos,
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

/// One-shot xz-native decode (`decompress_with_options_to_slice`, the
/// counterpart of `lzma_stream_buffer_decode`) into the exact-size segment
/// buffer. Same acceptance as [`liblzma_decode`]: one .xz stream, decoded
/// size exactly `orig`, bytes after the end of the stream ignored
/// (`concatenated(false)`).
fn xz_native_decode(data: &[u8], orig: usize, ignore_check: bool) -> Result<SegBuf> {
    let opts = xz_native::DecoderOptions::new()
        .concatenated(false)
        .ignore_check(ignore_check);
    // xz-native takes a `&mut [u8]`, so unlike the raw-pointer decoders the
    // buffer must be initialized first (`Arc::new_zeroed_slice` would avoid
    // the memset but is stable only since 1.92).
    let mut buf = Arc::<[u8]>::new_uninit_slice(orig);
    let ptr = Arc::get_mut(&mut buf)
        .expect("freshly allocated Arc is unique")
        .as_mut_ptr()
        .cast::<u8>();
    // SAFETY: `ptr` is valid for `orig` bytes; zeroing initializes them, and
    // the buffer is uniquely borrowed for as long as `out` lives.
    let out = unsafe {
        ptr.write_bytes(0, orig);
        std::slice::from_raw_parts_mut(ptr, orig)
    };
    let n = xz_native::decompress_with_options_to_slice(data, opts, out)
        .map_err(|e| anyhow::anyhow!("xz decode: {e}"))?;
    ensure!(n == orig, "xz decoded size mismatch ({n} vs {orig})");
    // SAFETY: zero-initialized above, then overwritten by the decoder.
    Ok(unsafe { buf.assume_init() })
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
            // SAFETY: no preconditions.
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
    fn xz_native_one_shot_decode() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let n = data.len();
        let enc = xz(&data);
        let dec = |b: &[u8], orig, ignore| decode(b, orig, XzDecoder::XzNative, ignore);
        for ignore in [false, true] {
            assert_eq!(&*dec(&enc, n, ignore).unwrap(), &data[..]);
        }
        assert!(dec(&enc, n - 1, true).is_err(), "over-long stream");
        assert!(dec(&enc, n + 1, true).is_err(), "short stream");
        assert!(dec(&enc[..enc.len() / 2], n, true).is_err(), "truncated");
        // Trailing bytes after the stream are ignored, like liblzma.
        let mut trailing = enc.clone();
        trailing.extend_from_slice(b"garbage after the stream");
        assert_eq!(&*dec(&trailing, n, true).unwrap(), &data[..]);

        // Flip a bit of the stored CRC64: enforced unless skipped.
        // SAFETY: `data` is valid for `data.len()` bytes.
        let crc = unsafe { liblzma_sys::lzma_crc64(data.as_ptr(), data.len(), 0) }.to_le_bytes();
        let at = enc.windows(8).position(|w| w == crc).unwrap();
        let mut bad = enc.clone();
        bad[at] ^= 1;
        assert!(dec(&bad, n, false).is_err(), "check enforced");
        assert_eq!(&*dec(&bad, n, true).unwrap(), &data[..], "check skipped");
    }

    #[test]
    fn liblzma_one_shot_decode() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let n = data.len();
        let enc = xz(&data);
        let dec = |b: &[u8], orig, ignore| decode(b, orig, XzDecoder::Liblzma, ignore);
        for ignore in [false, true] {
            assert_eq!(&*dec(&enc, n, ignore).unwrap(), &data[..]);
        }
        // Declared size must match exactly, in both directions.
        assert!(dec(&enc, n - 1, true).is_err(), "over-long stream");
        assert!(dec(&enc, n + 1, true).is_err(), "short stream");
        assert!(dec(&enc[..enc.len() / 2], n, true).is_err(), "truncated");

        // Flip a bit of the stored CRC64: caught when the xz check is the
        // only one, skipped when the caller's SHA-256 will cover the bytes.
        // SAFETY: `data` is valid for `data.len()` bytes.
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
