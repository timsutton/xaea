//! `xaea cat`: stream one regular file out of an archive to a writer.
//!
//! The AA01 payload has no index, so locating a member means walking the
//! record stream in order. Segments are still decoded in parallel (same
//! decoder-pool shape as `extract`), reordered, and fed to the record
//! parser; every blob byte before the target is discarded, the target's
//! bytes are written as they arrive, and decoding stops as soon as the
//! target's last byte has been emitted.
//!
//! Verification (on by default) runs the cheap whole-archive checks up
//! front (signature, certificate chain policy, root/cluster header MACs)
//! and then, per segment actually decoded, checks the segment MAC over the
//! stored bytes and the SHA-256 of the decoded bytes *before* that segment's
//! data is parsed — so no byte reaches the writer unauthenticated. What it
//! does not do is the full-file segment-MAC pass over segments it never
//! reads; use `inspect --verify` for a whole-archive audit.

use crate::aa::{Piece, Record, Sink, Stream};
use crate::envelope::{decode_xz, Envelope, Segment, XzDecoder};
use crate::extract::{sanitize, verify_upfront};
use crate::kdf;
use anyhow::{bail, ensure, Context, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::thread;

pub struct Opts {
    pub verify: bool,
    pub decoders: usize,
    pub decoder: XzDecoder,
}

enum State {
    Searching,
    Emitting { expect: u64, written: u64 },
    Done { written: u64 },
}

struct CatSink<'a, W: Write> {
    want: PathBuf,
    member: &'a str,
    out: &'a mut W,
    state: State,
    done: Arc<AtomicBool>,
}

impl<W: Write> Sink for CatSink<'_, W> {
    fn record(&mut self, rec: &Record) -> Result<()> {
        if !matches!(self.state, State::Searching) {
            return Ok(());
        }
        // Compare the way extraction would place the path (`./x`, `a/../x`
        // clamp identically); records whose path cannot be sanitized can
        // never match, and since nothing is written to disk they are skipped
        // rather than fatal.
        if sanitize(&rec.path).ok().as_deref() != Some(self.want.as_path()) {
            return Ok(());
        }
        match rec.typ {
            b'F' => {
                if rec.dat == 0 {
                    self.state = State::Done { written: 0 };
                    self.done.store(true, Relaxed);
                } else {
                    self.state = State::Emitting {
                        expect: rec.dat,
                        written: 0,
                    };
                }
                Ok(())
            }
            b'D' => bail!("{:?} is a directory", self.member),
            b'L' => bail!(
                "{:?} is a symlink to {:?}; ask for the target path instead",
                self.member,
                rec.link
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default()
            ),
            t => bail!("{:?} has unknown object type {:?}", self.member, t as char),
        }
    }

    fn blob(&mut self, piece: Piece) -> Result<()> {
        if let State::Emitting { expect, written } = &mut self.state {
            self.out
                .write_all(piece.bytes())
                .context("write to output")?;
            *written += piece.len() as u64;
            if *written == *expect {
                self.state = State::Done { written: *expect };
                self.done.store(true, Relaxed);
            }
        }
        Ok(())
    }
}

/// Decode (and, with a main key, authenticate) one segment.
fn decode_one(
    sg: &Segment<'_>,
    keys: Option<(&[Vec<u8>], u32)>,
    verify: bool,
    dec: XzDecoder,
) -> Result<Arc<[u8]>> {
    if let Some((ckeys, spc)) = keys {
        let local = sg.index - sg.cluster * spc;
        let key = kdf::segment_key(&ckeys[sg.cluster as usize], local);
        ensure!(
            kdf::mac(&key, sg.data, b"") == *sg.mac,
            "segment {} MAC mismatch (corrupt or tampered archive)",
            sg.index
        );
    }
    let buf: Arc<[u8]> = if sg.comp == sg.orig {
        Arc::from(sg.data)
    } else {
        Arc::from(decode_xz(sg.data, sg.orig as usize, dec)?.into_boxed_slice())
    };
    if verify {
        use sha2::{Digest, Sha256};
        let got: [u8; 32] = Sha256::digest(&buf[..]).into();
        ensure!(
            got.as_slice() == sg.cksum,
            "checksum mismatch for segment {} (corrupt or tampered archive)",
            sg.index
        );
    }
    Ok(buf)
}

/// Write the contents of regular file `member` to `out`; returns its size.
/// Errors (member missing, not a regular file, verification failure) leave
/// whatever was already written in place — callers streaming to a pipe must
/// treat a non-zero exit as "output is not trustworthy".
pub fn cat<W: Write>(env: &Envelope, member: &str, out: &mut W, opts: &Opts) -> Result<u64> {
    ensure!(
        !env.profile.encrypted(),
        "profile {} is encrypted: cat supports profile 0 only",
        env.profile.id()
    );
    let want = sanitize(member.as_bytes()).with_context(|| format!("member path {member:?}"))?;
    let main = if opts.verify {
        ensure!(
            env.root.checksum == 2,
            "verification enforces SHA-256 segment checksums; this archive declares {} — \
             use --no-verify to read anyway",
            crate::envelope::checksum_name(env.root.checksum)
        );
        Some(verify_upfront(env)?)
    } else {
        None
    };
    let ckeys: Vec<Vec<u8>> = match &main {
        Some(m) => (0..env.clusters.len() as u32)
            .map(|i| kdf::cluster_key(m, i))
            .collect(),
        None => Vec::new(),
    };
    let spc = env.root.segments_per_cluster;
    let keys = main.is_some().then_some((ckeys.as_slice(), spc));
    let segs = env.segments();
    let nseg = segs.len();
    let (verify, dec) = (opts.verify, opts.decoder);
    let nd = opts.decoders.max(1);

    let done = Arc::new(AtomicBool::new(false));
    let mut sink = CatSink {
        want,
        member,
        out,
        state: State::Searching,
        done: done.clone(),
    };

    let next = AtomicUsize::new(0);
    thread::scope(|scope| -> Result<()> {
        let (dtx, drx) = sync_channel::<Result<(usize, Arc<[u8]>)>>(nd + 4);
        let (segs, next_ref) = (&segs, &next);
        for _ in 0..nd {
            let dtx = dtx.clone();
            scope.spawn(move || loop {
                let i = next_ref.fetch_add(1, Relaxed);
                if i >= nseg {
                    break;
                }
                let r = decode_one(&segs[i], keys, verify, dec)
                    .map(|b| (i, b))
                    .with_context(|| format!("decode segment {i}"));
                if dtx.send(r).is_err() {
                    break; // consumer is gone (done or error)
                }
            });
        }
        drop(dtx);

        let mut stream = Stream::new(&mut sink);
        let mut pending: HashMap<usize, Arc<[u8]>> = HashMap::new();
        let mut expect = 0usize;
        let result = (|| -> Result<()> {
            'outer: while expect < nseg {
                let (i, buf) = drx.recv().context("decoder thread died")??;
                pending.insert(i, buf);
                while let Some(b) = pending.remove(&expect) {
                    stream.feed(b)?;
                    expect += 1;
                    if done.load(Relaxed) {
                        break 'outer;
                    }
                }
            }
            if !done.load(Relaxed) {
                stream.finish()?;
            }
            Ok(())
        })();
        // Whatever happened, stop the decoders so the scope can join them.
        next.store(nseg, Relaxed);
        drop(drx);
        result
    })?;

    match sink.state {
        State::Done { written } => {
            sink.out.flush().context("flush output")?;
            Ok(written)
        }
        State::Searching => bail!("{member:?} not found in archive"),
        State::Emitting { .. } => bail!("archive ended inside {member:?}"),
    }
}
