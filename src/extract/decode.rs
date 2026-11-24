//! Decoder threads' work: read one segment and decode it.

use crate::envelope::Segment;
use crate::prof::{self, C};
use crate::xz::{self, SegBuf, XzDecoder};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::unix::fs::FileExt;

fn read_pread(f: &File, off: u64, len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    read_pread_into(f, off, &mut v)?;
    Ok(v)
}

fn read_pread_into(f: &File, off: u64, buf: &mut [u8]) -> Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let n = f.read_at(&mut buf[done..], off + done as u64)?;
        ensure!(n > 0, "unexpected EOF at offset {}", off + done as u64);
        done += n;
    }
    Ok(())
}

/// Decoder-side view of a segment (owned/Copy so threads can own it).
#[derive(Clone, Copy)]
pub(crate) struct SegInfo {
    off: u64,
    comp: u32,
    orig: u32,
    /// The SHA-256 to check the decoded bytes against, when verifying.
    cksum: Option<[u8; 32]>,
}

impl SegInfo {
    pub(crate) fn new(seg: &Segment, verify: bool) -> Self {
        SegInfo {
            off: seg.data_off as u64,
            comp: seg.comp,
            orig: seg.orig,
            cksum: if verify {
                seg.cksum.try_into().ok()
            } else {
                None
            },
        }
    }
}

/// Decode one segment (pread stored bytes; LZMA-decode to `orig`) and, when
/// it carries a checksum, check the SHA-256 of the *decoded* bytes (the AEA
/// checksum covers decompressed data — erratum 3). SHA-256 runs while the
/// other decoders are busy; it is cheap next to LZMA.
pub(crate) fn decode_segment(
    fh: &File,
    sg: &SegInfo,
    index: usize,
    dec: XzDecoder,
) -> Result<SegBuf> {
    // Both arms produce the shared segment buffer directly (no Vec -> Arc
    // copy; see xz::segbuf_filled).
    let buf = if sg.comp == sg.orig {
        let len = sg.orig as usize;
        let fill = |dst: *mut u8| -> Result<()> {
            // SAFETY: `dst` points to `len` writable bytes. Zeroing them
            // first makes the `&mut [u8]` handed to pread fully initialized.
            let s = unsafe {
                std::ptr::write_bytes(dst, 0, len);
                std::slice::from_raw_parts_mut(dst, len)
            };
            read_pread_into(fh, sg.off, s)
        };
        // SAFETY: `fill` initialized all `len` bytes (zeroed, then read).
        unsafe { xz::segbuf_filled(len, fill)? }
    } else {
        let raw = prof::time(C::DPread, || read_pread(fh, sg.off, sg.comp as usize))?;
        prof::time(C::DDecode, || {
            xz::decode(&raw, sg.orig as usize, dec, sg.cksum.is_some())
        })?
    };
    if let Some(want) = sg.cksum {
        let got: [u8; 32] = prof::time(C::DSha, || Sha256::digest(&buf[..]).into());
        ensure!(
            got == want,
            "checksum mismatch for segment {index} (corrupt or tampered archive)"
        );
    }
    Ok(buf)
}
