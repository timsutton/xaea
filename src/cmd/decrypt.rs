//! `xaea decrypt`: write an archive's whole payload to one file — for a
//! restore image's `.dmg.aea`, its disk image.
//!
//! Segments are independent once the headers are known, and each has a
//! fixed place in the output, so this is a flat parallel loop: every
//! worker takes the next segment, checks its MAC, decrypts and
//! decompresses it, checks its checksum, and `pwrite`s it at its offset.
//! All-zero segments are not written at all, leaving holes in a sparse
//! output (disk images are full of them).

use super::{human, open_archive, parse_envelope};
use crate::cli::DecryptArgs;
use crate::envelope::{Checksum, Envelope};
use crate::exit::{Exit, WithExit, bail_exit};
use crate::extract::verify_upfront;
use crate::kdf::{self, Key};
use crate::payload;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
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
    let st = decrypt(&env, &out, jobs, args).with_exit(Exit::Extraction)?;
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
                "sparse_segments": st.holes,
                "jobs": jobs,
                "seconds": secs, "mib_per_s": rate,
            })
        );
    } else {
        println!(
            "{} {} ({}) in {secs:.1}s ({rate:.0} MiB/s, {jobs} threads{})",
            if args.no_verify {
                "wrote"
            } else {
                "verified and wrote"
            },
            out.display(),
            human(bytes),
            if st.holes > 0 {
                format!(", {} empty segments left sparse", st.holes)
            } else {
                String::new()
            },
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

struct Stats {
    /// Segments skipped because they decoded to all zeroes.
    holes: u64,
}

fn decrypt(env: &Envelope, out: &Path, jobs: usize, args: &DecryptArgs) -> Result<Stats> {
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
    let holes = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let first_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    let spc = env.root.segments_per_cluster;

    let work = || -> Result<()> {
        while !stop.load(Relaxed) {
            let i = next.fetch_add(1, Relaxed);
            let Some((at, sg)) = segs.get(i) else {
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
            let plain = payload::decode(
                sg.data.to_vec(),
                sg.orig as usize,
                keys.as_ref(),
                env.root.compression,
                args.decoder,
            )
            .with_context(|| format!("segment {}", sg.index))?;
            if check_sums {
                ensure!(
                    Sha256::digest(&plain).as_slice() == sg.cksum,
                    "checksum mismatch for segment {} (corrupt or tampered archive)",
                    sg.index
                );
            }
            if plain.iter().all(|&b| b == 0) {
                holes.fetch_add(1, Relaxed);
            } else {
                fh.write_all_at(&plain, *at)
                    .with_context(|| format!("write {}", out.display()))?;
            }
        }
        Ok(())
    };
    std::thread::scope(|scope| {
        for _ in 0..jobs.min(segs.len().max(1)) {
            scope.spawn(|| {
                if let Err(e) = work() {
                    stop.store(true, Relaxed);
                    first_err
                        .lock()
                        .expect("no panics hold it")
                        .get_or_insert(e);
                }
            });
        }
    });
    if let Some(e) = first_err.into_inner().expect("no panics hold it") {
        return Err(e);
    }
    tmp.persist_noclobber(out)
        .map_err(|e| e.error)
        .with_context(|| format!("move the output into place at {}", out.display()))?;
    Ok(Stats {
        holes: holes.into_inner() as u64,
    })
}
