//! `xaea decrypt`: write an archive's whole payload to one file — for a
//! restore image's `.dmg.aea`, its disk image. The archive can be a local
//! file, a member of a local or remote IPSW, or a URL.
//!
//! Segments are independent once the headers are known: a feeder hands
//! them out in payload order (borrowed from the map for a local archive,
//! read off the network for a remote one); workers check each one's MAC,
//! decrypt and decompress it into a pooled buffer, and check its checksum;
//! one writer thread writes the buffers out in payload order. On an M4
//! Max this writes a 5.9 GiB image from a local archive as fast as
//! Apple's `aea decrypt` (~1 s), about the speed of writing the bytes at
//! all; from the network, it keeps up with the download.
//!
//! What the write side measured on APFS (details in doc/PERFORMANCE-NOTES.md):
//! * Writes to one file serialize in the kernel; more writer threads do
//!   not help.
//! * Writing segments slightly out of order (as parallel workers finish
//!   them) is ~45% slower than in order.
//! * A sparse output (skipping all-zero segments, or letting APFS detect
//!   them) costs ~0.7 s more, paid when the file is closed, to save ~5% of
//!   the disk space. So every byte is written.

use super::{
    Input, archive_key, classify_key_error, human, image_listing, input_exit, parse_envelope,
};
use crate::cli::DecryptArgs;
use crate::envelope::{Checksum, Compression, Envelope, Head, Prelude};
use crate::exit::{Exit, WithExit, bail_exit, classify};
use crate::extract::verify_upfront;
use crate::ipsw;
use crate::kdf::{self, Key};
use crate::net::{NetError, RangeStream};
use crate::payload;
use crate::stream;
use crate::xz::XzDecoder;
use crate::zip;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Range requests in flight when reading from the network.
const DEFAULT_CONNECTIONS: usize = 4;

pub fn run(args: &DecryptArgs) -> Result<()> {
    args.decoder.check_available().with_exit(Exit::Usage)?;
    let t0 = Instant::now();
    let input = Input::open(&args.input, args.key.offline)?;
    let jobs = args
        .jobs
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, std::num::NonZero::get))
        .max(1);

    // The archive: the input itself, or the IPSW member asked for.
    let (name, range) = if input.is_zip()? {
        let entries = zip::entries(input.read_at()).map_err(input_exit)?;
        let listing = ipsw::list(input.read_at(), &entries).map_err(input_exit)?;
        let Some(want) = &args.member else {
            eprint!("{}", image_listing(&input.label(), &listing));
            bail_exit!(
                Exit::Usage,
                "{} is an IPSW: name the disk image to decrypt, by role or member name",
                input.label()
            );
        };
        let image = ipsw::select(&listing, want).with_exit(Exit::Usage)?;
        let e = &image.entry;
        if !image.encrypted() || e.method != zip::STORED {
            bail_exit!(
                Exit::Rejected,
                "{} is not an encrypted disk image (an AEA stored in the IPSW); unzip it instead",
                e.name
            );
        }
        let off = zip::data_offset(input.read_at(), e).map_err(input_exit)?;
        (e.name.clone(), off..off + e.compressed)
    } else {
        if let Some(m) = &args.member {
            bail_exit!(
                Exit::Usage,
                "{} is an archive, not an IPSW: there is no member `{m}` to pick",
                input.label()
            );
        }
        (input.label(), 0..input.len())
    };
    let out = output_path(args, &name).with_exit(Exit::Usage)?;
    if out.exists() {
        bail_exit!(
            Exit::Extraction,
            "{} already exists; not overwriting it",
            out.display()
        );
    }

    let (bytes, profile, segments) = match &input {
        Input::Local(archive) => {
            let file = &archive.map[range.start as usize..range.end as usize];
            let env = parse_envelope(file, &args.key)?;
            // Profile 0's main key comes from its verified signing
            // certificate; unverified, the key is not used.
            let main = if !args.no_verify && !env.profile.encrypted() {
                verify_upfront(&env).map_err(pipeline_exit)?
            } else {
                env.main_key(&[])
            };
            let plan = Plan::new(main, &env.root, env.profile.encrypted(), jobs, args);
            decrypt_local(&env, &out, &plan).map_err(pipeline_exit)?;
            (env.root.original_size, env.profile.id(), env.total_segments)
        }
        Input::Remote(remote) => {
            let conns = args.connections.unwrap_or(DEFAULT_CONNECTIONS);
            let total = range.end - range.start;
            let mut src = RangeStream::new(Arc::clone(remote), range.start, range.end, conns);
            let head_bytes = stream::read_head(&mut src).map_err(input_exit)?;
            let prelude = Prelude::parse(&head_bytes).with_exit(Exit::Rejected)?;
            let key = archive_key(&args.key, &prelude)?;
            let head = Head::parse(&head_bytes, key.as_ref()).map_err(classify_key_error)?;
            if !head.profile.encrypted() {
                bail_exit!(
                    Exit::Rejected,
                    "only encrypted archives (restore images) are read from the network; download this one first"
                );
            }
            let main = head.sym_main.expect("encrypted heads carry their main key");
            let plan = Plan::new(main, &head.root, true, jobs, args);
            let mut meter = Meter::new(total);
            write_image(&out, &plan, |sink| {
                stream::feed(
                    &mut src,
                    &head,
                    &head_bytes,
                    total,
                    plan.verify,
                    sink,
                    &mut |at| {
                        meter.update(at);
                    },
                )
            })
            .map_err(pipeline_exit)?;
            meter.finish();
            let segs = head
                .root
                .original_size
                .div_ceil(u64::from(head.root.segment_size))
                .max(1);
            (head.root.original_size, head.profile.id(), segs)
        }
    };

    let secs = t0.elapsed().as_secs_f64();
    let rate = bytes as f64 / secs / (1u64 << 20) as f64;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "out": out.display().to_string(),
                "archive": name,
                "profile": profile,
                "verified": !args.no_verify,
                "bytes": bytes,
                "segments": segments,
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

/// Errors of the decode pipeline: a failed download is an unreadable
/// input; anything else (verification, decode, output I/O) an extraction
/// failure.
fn pipeline_exit(e: anyhow::Error) -> anyhow::Error {
    if e.chain().any(<dyn std::error::Error>::is::<NetError>) {
        classify(Exit::Unreadable, e)
    } else {
        classify(Exit::Extraction, e)
    }
}

/// The explicit output path, else the archive's name minus `.aea` in the
/// current directory.
fn output_path(args: &DecryptArgs, archive: &str) -> Result<PathBuf> {
    if let Some(out) = &args.output {
        ensure!(
            out != Path::new("-"),
            "writing the payload to standard output is not supported; name an output file"
        );
        return Ok(out.clone());
    }
    let base = archive.rsplit('/').next().unwrap_or(archive);
    let name = base.strip_suffix(".aea").filter(|n| !n.is_empty());
    name.map(PathBuf::from)
        .context("cannot name the output after the archive (no `.aea` suffix): pass -o")
}

/// One segment, for the workers.
pub struct Job<'a> {
    /// Segment index in the payload; also the order they are written in.
    pub index: u32,
    pub cluster: u32,
    pub orig: u32,
    pub cksum: Cow<'a, [u8]>,
    pub mac: [u8; 32],
    pub data: Cow<'a, [u8]>,
}

/// Where a feeder sends segments.
pub struct Sink<'s, 'a> {
    tx: SyncSender<Job<'a>>,
    stop: &'s AtomicBool,
}

impl<'a> Sink<'_, 'a> {
    /// Send `job` on; fails once the pipeline has failed elsewhere (that
    /// failure is the one reported).
    pub fn send(&self, job: Job<'a>) -> Result<()> {
        ensure!(!self.stop.load(Relaxed), "stopped");
        self.tx.send(job).ok().context("stopped")
    }
}

/// What the workers need to know about the archive.
pub struct Plan {
    main: Key,
    original_size: u64,
    spc: u32,
    compression: Compression,
    encrypted: bool,
    verify: bool,
    check_sums: bool,
    decoder: XzDecoder,
    jobs: usize,
}

impl Plan {
    fn new(
        main: Key,
        root: &crate::envelope::RootHeader,
        encrypted: bool,
        jobs: usize,
        args: &DecryptArgs,
    ) -> Self {
        let verify = !args.no_verify;
        Plan {
            main,
            original_size: root.original_size,
            spc: root.segments_per_cluster,
            compression: root.compression,
            encrypted,
            verify,
            check_sums: verify && root.checksum == Checksum::Sha256,
            decoder: args.decoder,
            jobs,
        }
    }
}

/// A local archive: header checks up front (profile 0's signature chain
/// already passed), then every segment straight off the map.
fn decrypt_local(env: &Envelope, out: &Path, plan: &Plan) -> Result<()> {
    if plan.verify && env.profile.encrypted() {
        // Segment MACs and checksums are checked per segment.
        let macs = env.verify_header_macs(&plan.main);
        ensure!(macs.root_ok, "root header MAC mismatch");
        ensure!(macs.clusters_ok, "cluster header MAC mismatch");
        ensure!(macs.padding_ok != Some(false), "padding MAC mismatch");
    }
    write_image(out, plan, |sink| {
        for sg in env.segments() {
            sink.send(Job {
                index: sg.index,
                cluster: sg.cluster,
                orig: sg.orig,
                cksum: Cow::Borrowed(sg.cksum),
                mac: *sg.mac.first_chunk().expect("32-byte MAC"),
                data: Cow::Borrowed(sg.data),
            })?;
        }
        Ok(())
    })
}

/// Run the pipeline: `feed` sends every segment in payload order, and the
/// payload lands at `out` only if everything succeeds.
fn write_image<'a>(
    out: &Path,
    plan: &Plan,
    feed: impl FnOnce(&Sink<'_, 'a>) -> Result<()> + Send,
) -> Result<()> {
    // Write to a temporary file beside the output and rename it into place
    // at the end, so a failure never leaves a partial image behind.
    let dir = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = tempfile::Builder::new()
        .prefix(".xaea-decrypt-")
        // An ordinary new file's mode (the umask applies), not tempfile's 0600.
        .permissions(std::fs::Permissions::from_mode(0o666))
        .tempfile_in(dir)
        .with_context(|| format!("create a temporary file in {}", dir.display()))?;
    let fh: &File = tmp.as_file();
    fh.set_len(plan.original_size)
        .context("size the output file")?;

    let stop = AtomicBool::new(false);
    let first_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    // Record the error before raising `stop`, so whoever sees `stop`
    // knows the real error is already in.
    let fail = |e: anyhow::Error| {
        first_err
            .lock()
            .expect("no panics hold it")
            .get_or_insert(e);
        stop.store(true, Relaxed);
    };
    let stop = &stop;

    let workers = plan.jobs;
    let (job_tx, job_rx) = sync_channel::<Job<'a>>(workers * 2);
    let job_rx = Mutex::new(job_rx);
    let (tx, rx) = sync_channel::<(u32, Vec<u8>)>(workers * 2);
    // Payload buffers cycle back to the workers instead of being
    // reallocated.
    let pool: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

    let written = std::thread::scope(|scope| {
        let sink = Sink { tx: job_tx, stop };
        scope.spawn(move || {
            if let Err(e) = feed(&sink) {
                fail(e);
            }
        });
        for _ in 0..workers {
            let tx = tx.clone();
            let (job_rx, pool) = (&job_rx, &pool);
            scope.spawn(move || {
                if let Err(e) = work(plan, job_rx, pool, &tx, stop) {
                    fail(e);
                }
                // Drain, so a feeder blocked on a full queue can finish.
                while job_rx.lock().expect("no panics hold it").recv().is_ok() {}
            });
        }
        drop(tx);
        // The writer, on this thread. Segments are fed in order, so the
        // reorder window stays around one segment per worker.
        let mut pending = BTreeMap::new();
        let (mut due, mut at) = (0u32, 0u64);
        'recv: for (i, buf) in rx {
            pending.insert(i, buf);
            while let Some(buf) = pending.remove(&due) {
                if let Err(e) = fh.write_all_at(&buf, at) {
                    fail(anyhow::Error::new(e).context(format!("write {}", out.display())));
                    break 'recv; // dropping rx unblocks the workers
                }
                at += buf.len() as u64;
                pool.lock().expect("no panics hold it").push(buf);
                due += 1;
            }
        }
        at
    });
    if let Some(e) = first_err.into_inner().expect("no panics hold it") {
        return Err(e);
    }
    ensure!(
        written == plan.original_size,
        "wrote {written} bytes, the archive declares {}",
        plan.original_size
    );
    tmp.persist_noclobber(out)
        .map_err(|e| e.error)
        .with_context(|| format!("move the output into place at {}", out.display()))?;
    Ok(())
}

/// One worker: take segments until the feeder is done, check, decode and
/// check them, and pass them to the writer.
fn work(
    plan: &Plan,
    jobs: &Mutex<Receiver<Job>>,
    pool: &Mutex<Vec<Vec<u8>>>,
    tx: &SyncSender<(u32, Vec<u8>)>,
    stop: &AtomicBool,
) -> Result<()> {
    let mut scratch = Vec::new();
    loop {
        if stop.load(Relaxed) {
            return Ok(());
        }
        let Ok(sg) = jobs.lock().expect("no panics hold it").recv() else {
            return Ok(()); // the feeder is done
        };
        let ck = kdf::cluster_key(&plan.main, sg.cluster);
        let local = sg.index - sg.cluster * plan.spc;
        if plan.verify {
            ensure!(
                kdf::mac(&kdf::segment_key(&ck, local), &sg.data, b"") == sg.mac,
                "segment {} MAC mismatch (corrupt or tampered archive)",
                sg.index
            );
        }
        let keys = plan.encrypted.then(|| kdf::segment_cipher(&ck, local));
        let mut plain = pool
            .lock()
            .expect("no panics hold it")
            .pop()
            .unwrap_or_default();
        payload::decode_into(
            &sg.data,
            sg.orig as usize,
            keys.as_ref(),
            plan.compression,
            plan.decoder,
            &mut scratch,
            &mut plain,
        )
        .with_context(|| format!("segment {}", sg.index))?;
        if plan.check_sums {
            ensure!(
                Sha256::digest(&plain).as_slice() == &sg.cksum[..],
                "checksum mismatch for segment {} (corrupt or tampered archive)",
                sg.index
            );
        }
        if tx.send((sg.index, plain)).is_err() {
            return Ok(()); // the writer failed and reported it
        }
    }
}

/// Download progress on a terminal's stderr.
struct Meter {
    total: u64,
    t0: Instant,
    last: Instant,
    on: bool,
}

impl Meter {
    fn new(total: u64) -> Self {
        let now = Instant::now();
        Meter {
            total,
            t0: now,
            last: now,
            on: std::io::stderr().is_terminal(),
        }
    }

    fn update(&mut self, at: u64) {
        if !self.on || self.last.elapsed().as_millis() < 250 {
            return;
        }
        self.last = Instant::now();
        let rate = at as f64 / self.t0.elapsed().as_secs_f64() / (1u64 << 20) as f64;
        let mut e = std::io::stderr().lock();
        let _ = write!(
            e,
            "\r\x1b[2K{} of {} ({:.0}%), {rate:.1} MiB/s",
            human(at),
            human(self.total),
            at as f64 * 100.0 / self.total.max(1) as f64
        );
        let _ = e.flush();
    }

    fn finish(&self) {
        if self.on {
            eprint!("\r\x1b[2K");
        }
    }
}
