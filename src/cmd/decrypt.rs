//! `xaea decrypt`: write an archive's whole payload to one file — for a
//! restore image's `.dmg.aea`, its disk image.
//!
//! Segments are independent once the headers are known: workers take the
//! next segment, check its MAC, decrypt and decompress it into a pooled
//! buffer, and check its checksum; one writer thread writes the buffers
//! out in payload order. On an M4 Max this writes a 5.9 GiB image as fast
//! as Apple's `aea decrypt` (~1 s), which is about the speed of writing
//! the bytes at all.
//!
//! What the write side measured on APFS (details in doc/PERFORMANCE-NOTES.md):
//! * Writes to one file serialize in the kernel; more writer threads do
//!   not help.
//! * Writing segments slightly out of order (as parallel workers finish
//!   them) is ~45% slower than in order.
//! * A sparse output (skipping all-zero segments, or letting APFS detect
//!   them) costs ~0.7 s more, paid when the file is closed, to save ~5% of
//!   the disk space. So every byte is written.

use super::{human, open_archive, parse_envelope};
use crate::cli::DecryptArgs;
use crate::envelope::{Checksum, Envelope};
use crate::exit::{Exit, WithExit, bail_exit};
use crate::extract::verify_upfront;
use crate::kdf::{self, Key};
use crate::payload;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::Instant;

pub fn run(args: &DecryptArgs) -> Result<()> {
    args.decoder.check_available().with_exit(Exit::Usage)?;
    let out = output_path(args).with_exit(Exit::Usage)?;
    if out.exists() {
        bail_exit!(
            Exit::Extraction,
            "{} already exists; not overwriting it",
            out.display()
        );
    }
    let t0 = Instant::now();
    let archive = open_archive(&args.file)?;
    let env = parse_envelope(&archive.map, &args.key)?;
    let jobs = args
        .jobs
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, std::num::NonZero::get))
        .max(1);
    decrypt(&env, &out, jobs, args).with_exit(Exit::Extraction)?;
    let secs = t0.elapsed().as_secs_f64();
    let bytes = env.root.original_size;
    let rate = bytes as f64 / secs / (1u64 << 20) as f64;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "out": out.display().to_string(),
                "profile": env.profile.id(),
                "verified": !args.no_verify,
                "bytes": bytes,
                "segments": env.total_segments,
                "jobs": jobs,
                "seconds": secs, "mib_per_s": rate,
            })
        );
    } else {
        println!(
            "{} {} ({}) in {secs:.1}s ({rate:.0} MiB/s, {jobs} threads)",
            if args.no_verify {
                "wrote"
            } else {
                "verified and wrote"
            },
            out.display(),
            human(bytes),
        );
    }
    Ok(())
}

/// The explicit output path, else the archive's name minus `.aea` in the
/// current directory.
fn output_path(args: &DecryptArgs) -> Result<PathBuf> {
    if let Some(out) = &args.out {
        ensure!(
            out != Path::new("-"),
            "writing the payload to standard output is not supported; name an output file"
        );
        return Ok(out.clone());
    }
    let name = args
        .file
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".aea"))
        .filter(|n| !n.is_empty());
    name.map(PathBuf::from)
        .context("cannot name the output after the archive (no `.aea` suffix): give an output path")
}

fn decrypt(env: &Envelope, out: &Path, jobs: usize, args: &DecryptArgs) -> Result<()> {
    let verify = !args.no_verify;
    // Up-front: the signature chain (profile 0) and the root/cluster
    // header MACs. Segment MACs and checksums are checked per segment.
    let main: Key = if !verify {
        env.main_key(&[])
    } else if env.profile.encrypted() {
        let main = env.main_key(&[]);
        let macs = env.verify_header_macs(&main);
        ensure!(macs.root_ok, "root header MAC mismatch");
        ensure!(macs.clusters_ok, "cluster header MAC mismatch");
        ensure!(macs.padding_ok != Some(false), "padding MAC mismatch");
        main
    } else {
        verify_upfront(env)?
    };
    let check_sums = verify && env.root.checksum == Checksum::Sha256;

    // Write to a temporary file beside the output and rename it into place
    // at the end, so a failure never leaves a partial image behind.
    let dir = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = tempfile::Builder::new()
        .prefix(".xaea-decrypt-")
        .tempfile_in(dir)
        .with_context(|| format!("create a temporary file in {}", dir.display()))?;
    let fh: &File = tmp.as_file();
    fh.set_len(env.root.original_size)
        .context("size the output file")?;

    // Payload offset of every segment.
    let segs: Vec<_> = env
        .segments()
        .scan(0u64, |off, s| {
            let at = *off;
            *off += u64::from(s.orig);
            Some((at, s))
        })
        .collect();
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let first_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    let fail = |e: anyhow::Error| {
        stop.store(true, Relaxed);
        first_err
            .lock()
            .expect("no panics hold it")
            .get_or_insert(e);
    };
    let spc = env.root.segments_per_cluster;

    // A single writer thread, writing in payload order (see the module
    // docs). Payload buffers cycle back to the workers through `pool`
    // instead of being reallocated.
    let workers = jobs.min(segs.len()).max(1);
    let (tx, rx) = sync_channel::<(usize, Vec<u8>)>(workers * 2);
    let pool: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

    let work = |tx: SyncSender<(usize, Vec<u8>)>| -> Result<()> {
        let mut scratch = Vec::new();
        while !stop.load(Relaxed) {
            let i = next.fetch_add(1, Relaxed);
            let Some((_, sg)) = segs.get(i) else {
                return Ok(());
            };
            let ck = kdf::cluster_key(&main, sg.cluster);
            let local = sg.index - sg.cluster * spc;
            if verify {
                ensure!(
                    kdf::mac(&kdf::segment_key(&ck, local), sg.data, b"") == *sg.mac,
                    "segment {} MAC mismatch (corrupt or tampered archive)",
                    sg.index
                );
            }
            let keys = env
                .profile
                .encrypted()
                .then(|| kdf::segment_cipher(&ck, local));
            let mut plain = pool
                .lock()
                .expect("no panics hold it")
                .pop()
                .unwrap_or_default();
            payload::decode_into(
                sg.data,
                sg.orig as usize,
                keys.as_ref(),
                env.root.compression,
                args.decoder,
                &mut scratch,
                &mut plain,
            )
            .with_context(|| format!("segment {}", sg.index))?;
            if check_sums {
                ensure!(
                    Sha256::digest(&plain).as_slice() == sg.cksum,
                    "checksum mismatch for segment {} (corrupt or tampered archive)",
                    sg.index
                );
            }
            if tx.send((i, plain)).is_err() {
                return Ok(()); // the writer failed and reported it
            }
        }
        Ok(())
    };
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let tx = tx.clone();
            scope.spawn(|| work(tx).unwrap_or_else(fail));
        }
        drop(tx);
        // The writer, on this thread. Workers claim segments in order, so
        // the reorder window stays around one segment per worker.
        let mut pending = BTreeMap::new();
        let mut due = 0usize;
        'recv: for (i, buf) in rx {
            pending.insert(i, buf);
            while let Some(buf) = pending.remove(&due) {
                if let Err(e) = fh.write_all_at(&buf, segs[due].0) {
                    fail(anyhow::Error::new(e).context(format!("write {}", out.display())));
                    break 'recv; // dropping rx unblocks the workers
                }
                pool.lock().expect("no panics hold it").push(buf);
                due += 1;
            }
        }
    });
    if let Some(e) = first_err.into_inner().expect("no panics hold it") {
        return Err(e);
    }
    tmp.persist_noclobber(out)
        .map_err(|e| e.error)
        .with_context(|| format!("move the output into place at {}", out.display()))?;
    Ok(())
}
