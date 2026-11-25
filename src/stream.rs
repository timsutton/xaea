//! Reading an encrypted archive front to back, in one pass, as its bytes
//! arrive from the network: the head, then each cluster's header block
//! and segments, then the padding. Every MAC is checked as soon as its
//! bytes are in (the same checks `Envelope` makes with the whole file in
//! hand), and segments go to the decrypt workers as they are read.

use crate::cmd::decrypt::{Job, Sink};
use crate::envelope::{Head, cluster_header_len, cluster_headers, cluster_mac, segment_header};
use crate::kdf;
use anyhow::{Context, Result, ensure};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::borrow::Cow;

/// A source of the archive's bytes, in order.
pub trait Take {
    /// Exactly the next `n` bytes, into `out` (replacing its contents).
    fn take_into(&mut self, n: usize, out: &mut Vec<u8>) -> Result<()>;

    fn take(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        self.take_into(n, &mut v)?;
        Ok(v)
    }
}

/// The archive's head bytes (see [`Head::len`]).
pub fn read_head(src: &mut impl Take) -> Result<Vec<u8>> {
    let mut head = src.take(12)?;
    let n = Head::len(&head)?;
    ensure!(n <= 16 << 20, "implausibly large archive head ({n} bytes)");
    head.extend(src.take(n - 12)?);
    Ok(head)
}

/// Read the rest of an encrypted archive of `total` bytes whose head has
/// been read and parsed, sending each segment to `sink` in payload order.
/// `progress` hears the archive offset read so far.
pub fn feed(
    src: &mut impl Take,
    head: &Head,
    head_bytes: &[u8],
    total: u64,
    verify: bool,
    sink: &Sink<'_, '_>,
    progress: &mut dyn FnMut(u64),
) -> Result<()> {
    let main = head
        .sym_main
        .context("only encrypted archives (restore images) can be read from the network")?;
    let root = &head.root;
    ensure!(
        root.encarchive_size == total,
        "root header says the archive is {} bytes, but it is {total}",
        root.encarchive_size
    );
    let spc = u64::from(root.segments_per_cluster);
    let total_segments = root
        .original_size
        .div_ceil(u64::from(root.segment_size))
        .max(1);
    let block_len = cluster_header_len(root);
    let list_len = block_len - 32 * (spc as usize + 1);
    // A segment stored larger than this is a hostile header, not data.
    let max_stored = u64::from(root.segment_size) * 2;

    let mut pos = head_bytes.len() as u64;
    let mut chmac: [u8; 32] = *head.first_chmac(head_bytes);
    let (mut idx, mut cidx, mut sum_orig) = (0u64, 0u32, 0u64);
    while idx < total_segments {
        let n = spc.min(total_segments - idx) as usize;
        ensure!(
            pos + block_len as u64 <= total,
            "truncated: cluster {cidx} headers run past EOF"
        );
        let block = src.take(block_len)?;
        pos += block_len as u64;
        ensure!(
            !verify || cluster_mac(&main, cidx, &block, root) == chmac,
            "cluster {cidx} header MAC mismatch (corrupt or tampered archive)"
        );
        let headers = cluster_headers(Some(&main), cidx, &block[..list_len]);
        chmac = block[list_len..list_len + 32].try_into().expect("32 bytes");
        let macs = &block[list_len + 32..];
        for s in 0..n {
            let (orig, comp, cksum) =
                segment_header(&headers, root, s).with_context(|| format!("segment {idx}"))?;
            ensure!(
                u64::from(comp) <= max_stored && pos + u64::from(comp) <= total,
                "segment {idx} stores {comp} bytes: corrupt header or truncated archive"
            );
            let data = src.take(comp as usize)?;
            pos += u64::from(comp);
            sum_orig += u64::from(orig);
            sink.send(Job {
                index: idx as u32,
                cluster: cidx,
                orig,
                cksum: Cow::Owned(cksum.to_vec()),
                mac: macs[s * 32..s * 32 + 32].try_into().expect("32 bytes"),
                data: Cow::Owned(data),
            })?;
            progress(pos);
            idx += 1;
        }
        cidx += 1;
    }
    ensure!(
        sum_orig == root.original_size,
        "segment decoded sizes sum to {sum_orig}, root header declares original_size {}",
        root.original_size
    );
    // Random padding up to encarchive_size, authenticated by the last
    // cluster's next-chmac slot. It can be large (~1% of a simulator
    // runtime asset), so it is MACed in pieces as it streams in.
    let pad = total - pos;
    let mut mac = Hmac::<Sha256>::new_from_slice(&kdf::padding_key(&main))
        .expect("HMAC accepts any key size");
    let mut buf = Vec::new();
    while pos < total {
        let n = (total - pos).min(8 << 20);
        src.take_into(n as usize, &mut buf)?;
        mac.update(&buf);
        pos += n;
        progress(pos);
    }
    let padding_mac: [u8; 32] = mac.finalize().into_bytes().into();
    ensure!(
        !verify || pad == 0 || padding_mac == chmac,
        "padding MAC mismatch (corrupt or tampered archive)"
    );
    progress(total);
    Ok(())
}
