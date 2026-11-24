//! `xaea cat`: stream one regular file out of an archive to stdout.

use super::open_archive;
use crate::aa::{Piece, Record, Sink, Stream};
use crate::cli::CatArgs;
use crate::envelope::{Checksum, Envelope};
use crate::exit::{Exit, WithExit, bail_exit};
use crate::extract::decode::{SegInfo, decode_segment};
use crate::extract::paths::sanitize;
use crate::extract::verify_upfront;
use anyhow::{Context, Result, bail, ensure};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::sync_channel;
use std::thread;

pub fn run(args: &CatArgs) -> Result<()> {
    args.decoder.check_available().with_exit(Exit::Usage)?;
    // The member path is normalized exactly the way extraction places
    // files relative to an output root, so `./x` and `a/../x` match the
    // same member.
    let want = sanitize(args.member.as_bytes()).with_exit(Exit::Usage)?;
    let archive = open_archive(&args.file)?;
    let env = Envelope::parse(&archive.map).with_exit(Exit::Rejected)?;
    if env.profile.encrypted() {
        bail_exit!(
            Exit::Rejected,
            "profile {} is encrypted: cat supports profile 0 only \
             (encrypted profiles are inspect-only)",
            env.profile.id()
        );
    }
    // The pipeline (up-front authenticity gates, decode, parse, print) is
    // tagged with the extraction exit class, same as `extract`.
    pipeline(&env, &archive.src.path, &want, args).with_exit(Exit::Extraction)
}

/// Run the decode/parse/print pipeline. Everything in here is treated as
/// an extraction-domain failure by the caller.
fn pipeline(env: &Envelope, src: &Path, want: &Path, args: &CatArgs) -> Result<()> {
    if !args.no_verify {
        // Enforce the same up-front authenticity gates as extract: signature
        // and chain policy, then the root/cluster header MACs. Cheap
        // relative to decoding.
        ensure!(
            env.root.checksum == Checksum::Sha256,
            "cat verification enforces SHA-256 segment checksums; this archive \
             declares {} — use --no-verify to print anyway",
            env.root.checksum
        );
        let _main = verify_upfront(env)?;
    }
    stream_member(env, src, want, args)
}

/// Stream the requested member from the payload to stdout, then stop.
///
/// Decoders run ahead in parallel; the consumer reorders into strict
/// payload order and feeds the AA01 record parser. Non-matching blobs are
/// dropped as they arrive, so the memory footprint stays small; decoding
/// stops as soon as the target's last byte is out.
fn stream_member(env: &Envelope, src: &Path, want: &Path, args: &CatArgs) -> Result<()> {
    let segs: Arc<[SegInfo]> = env
        .segments()
        .map(|s| SegInfo::new(&s, !args.no_verify))
        .collect();
    let nseg = segs.len();
    let fh = Arc::new(File::open(src).with_context(|| format!("open {}", src.display()))?);

    let cores = std::thread::available_parallelism()?.get();
    let decoders = args
        .jobs
        .unwrap_or_else(|| cores.saturating_sub(1).max(2))
        .max(1);

    // Bounded send queue, like extract: a few segments in flight keeps
    // memory flat.
    let (dtx, drx) = sync_channel::<Result<(usize, Arc<[u8]>)>>(decoders + 4);
    let next = Arc::new(AtomicUsize::new(0));
    let decoder = args.decoder;
    let mut workers = Vec::new();
    for _ in 0..decoders {
        let (next, fh, segs, dtx) = (next.clone(), fh.clone(), segs.clone(), dtx.clone());
        workers.push(thread::spawn(move || {
            loop {
                let i = next.fetch_add(1, Relaxed);
                if i >= nseg {
                    break;
                }
                let sg = &segs[i];
                let r = decode_segment(&fh, sg, i, decoder)
                    .map(|b| (i, b))
                    .with_context(|| format!("decode segment {i}"));
                if dtx.send(r).is_err() {
                    break; // consumer is gone (error path or early stop)
                }
            }
        }));
    }
    drop(dtx);

    // The sink writes only the target's bytes; progress flags are shared
    // through atomics so the reorder loop can stop early.
    let done = Arc::new(AtomicBool::new(false));
    let found = Arc::new(AtomicBool::new(false));
    let mut dest = Dest::new(want.to_path_buf(), done.clone(), found.clone());
    let mut stream = Stream::new(&mut dest);

    let mut pending: HashMap<usize, Arc<[u8]>> = HashMap::new();
    let mut expect = 0usize;
    while !done.load(Relaxed) && expect < nseg {
        let item = drx.recv().context("decoder thread died")?;
        let (i, buf) = item?;
        if i == expect {
            stream.feed(&buf)?;
            expect += 1;
            while !done.load(Relaxed) {
                let Some(b) = pending.remove(&expect) else {
                    break;
                };
                stream.feed(&b)?;
                expect += 1;
            }
        } else {
            pending.insert(i, buf);
        }
    }

    // A clean end of the stream is a finish-record-by-record invariant;
    // skipping it is only safe when we walked away mid-blob.
    if !done.load(Relaxed) {
        stream.finish()?;
    }
    drop(stream);

    // Release the workers: a send failure unblocks each blocked sender.
    drop(drx);
    for t in workers {
        let _ = t.join();
    }

    if done.load(Relaxed) {
        return Ok(());
    }

    if found.load(Relaxed) {
        // The record was found but its bytes never arrived — a truncated
        // archive. finish() above would have caught this, but be explicit.
        bail!(
            "member {}: archive ended before the file was fully read",
            want.display()
        );
    }
    bail!("no member named {} in this archive", want.display())
}

/// The stdout destination for the target member.
struct Dest {
    /// Sanitized member path to match.
    want: PathBuf,
    out: io::BufWriter<io::Stdout>,
    /// Remaining bytes of the target file's blob.
    remaining: u64,
    /// Whether the current record is the target.
    in_target: bool,
    /// Set once the target's last byte (or an empty file) is out.
    done: Arc<AtomicBool>,
    /// Set once a matching record was seen.
    found: Arc<AtomicBool>,
}

impl Dest {
    fn new(want: PathBuf, done: Arc<AtomicBool>, found: Arc<AtomicBool>) -> Self {
        Self {
            want,
            out: io::BufWriter::with_capacity(1 << 20, io::stdout()),
            remaining: 0,
            in_target: false,
            done,
            found,
        }
    }
}

impl Sink for Dest {
    fn record(&mut self, rec: &Record) -> Result<()> {
        self.in_target = false;
        let rel = sanitize(&rec.path)?;
        if rel != self.want {
            return Ok(()); // not our member; its blob is dropped below
        }
        self.found.store(true, Relaxed);
        match rec.typ {
            b'F' => {
                self.remaining = rec.dat;
                if rec.dat == 0 {
                    self.done.store(true, Relaxed);
                }
                self.in_target = true;
                Ok(())
            }
            b'D' => bail!(
                "member {} is a directory, not a regular file",
                self.want.display()
            ),
            b'L' => {
                let target = rec
                    .link
                    .as_deref()
                    .map(|t| String::from_utf8_lossy(t).into_owned());
                match target {
                    Some(t) => bail!(
                        "member {} is a symlink (-> {}), not a regular file",
                        self.want.display(),
                        t
                    ),
                    None => bail!(
                        "member {} is a symlink, not a regular file",
                        self.want.display()
                    ),
                }
            }
            t => bail!(
                "member {} has unknown record type {:#x}, not a regular file",
                self.want.display(),
                t
            ),
        }
    }

    fn blob(&mut self, piece: Piece) -> Result<()> {
        if self.done.load(Relaxed) || !self.in_target {
            return Ok(());
        }
        let bytes = piece.bytes();
        match self.out.write_all(bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                // The reader closed the pipe (e.g. `| head`): stop quietly.
                self.done.store(true, Relaxed);
                return Ok(());
            }
            Err(e) => return Err(e).context("write stdout"),
        }
        self.remaining -= bytes.len() as u64;
        if self.remaining == 0 {
            match self.out.flush() {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    self.done.store(true, Relaxed);
                    return Ok(());
                }
                Err(e) => return Err(e).context("write stdout"),
            }
            self.done.store(true, Relaxed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanity: normalization used for matching is the same one extraction
    // uses, and the pure-escape case clamps.
    #[test]
    fn member_matching_uses_extract_normalization() {
        assert_eq!(
            sanitize(b"T/../../esc/../escaped/inside.bin").unwrap(),
            PathBuf::from("escaped/inside.bin")
        );
    }
}
