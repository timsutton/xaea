//! Parallel extraction of the AA01 payload.
//!
//! Pipeline: `D` decoder threads pread + LZMA-decode segments (out of
//! order) → bounded channel → this thread reorders to strict payload order
//! and runs the AA01 record parser → work items (mkdir / symlink / open /
//! blob slices) are dispatched to `W` writer threads via per-writer
//! channels. ALL filesystem syscalls execute on writers — or, for the final
//! symlink pass only, on scoped helpers owned by one writer: the parser is
//! pure CPU + dispatch (instrumentation showed parser-issued syscalls were
//! the wall-clock bottleneck, not write throughput). Ordering rules:
//!
//! * files pick a writer by round-robin sequence — their Open and all blob
//!   slices share that one FIFO channel;
//! * directories hash-route by path, and file parents are additionally
//!   created on demand (only when the file's open fails with ENOENT), so
//!   no cross-channel ordering assumption is ever made;
//! * blob pieces are zero-copy Arc<[u8]> views of decoded segment buffers,
//!   `pwrite`d at explicit offsets;
//! * **symlinks and non-default directory modes run as a final pass** on
//!   one writer after the stream ends (bsdtar/unxip policy): while records
//!   stream, no archive-created symlink exists yet, so no file write can be
//!   redirected through one; within the final pass, a symlink whose path
//!   traverses an earlier archive symlink is refused (classic tar link
//!   attack, review #1), and directory modes are applied last so a hostile
//!   0555 dir cannot block its own subtree (review #8). That guard reads
//!   only the record list, never the tree, so on a list with no link nested
//!   under another link it is evaluated for every record up front, on one
//!   thread, before the first link exists, and the `symlink(2)` calls then
//!   fan out over `--writers` scoped helpers (link creation is APFS-serialised
//!   metadata work and stops scaling past ~8 threads).
//!
//! With `--verify` (the default) extraction refuses archives whose root/
//! cluster/segment MACs, content signature, certificate chain policy, or
//! per-segment SHA-256 checksums fail; checksums are checked inline in the
//! decoder threads (SHA-256 is cheap next to LZMA) so no segment reaches a
//! writer before its own check, and the full-file segment-MAC pass runs
//! concurrently with the pipeline, joined before the final pass.
//! `--no-verify` skips all of it.
//!
//! Memory: decoded buffers are bounded by the decoder channel (≈2× the
//! decoder count in flight); writer queues add at most writers × queue(32)
//! × segment_size — on a 15-decoder/6-writer machine with 16 MiB segments
//! that is a ~3 GiB pinned *worst* case (every queue full of whole-segment
//! slices simultaneously), far less in practice since most files hold only
//! a slice or two and writers drain continuously.
//!
//! Status: on BSDs/macOS the tool answers `SIGINFO` (Ctrl-T) by printing a
//! one-line progress report, like `dd` and friends; on Linux, which has no
//! SIGINFO, the same report is available via `SIGUSR1`.

pub(crate) mod decode;
mod links;
pub(crate) mod paths;
mod sink;
mod status;
mod writer;

use crate::aa::Stream;
use crate::decmpfs;
use crate::envelope::{Checksum, Envelope};
use crate::kdf::Key;
use crate::prof::{self, C, K};
use crate::xz::XzDecoder;
use anyhow::{Context, Result, ensure};
use decode::{SegInfo, decode_segment};
use sink::DispatchSink;
use status::Progress;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;
use writer::{Load, Work, Writer};

#[derive(Debug, Default)]
pub struct Stats {
    pub dirs: u64,
    pub files: u64,
    pub links: u64,
    pub bytes: u64,
    /// Files were written with transparent compression (`--compress` and a
    /// volume that supports it).
    pub compressed: bool,
}

/// Upper bound for the default `--readahead` (decoded segments buffered
/// between the decoders and the parser). The old default was `decoders + 4`,
/// which kept decoders from running ahead during the file-heavy,
/// writer-bound first half of an Xcode archive; a deeper window lets them
/// bank the large-file tail instead. Full extract, Xcode 27.3 b2: at 160, M3
/// Max 9.0 → 8.2 s (−9%, peak RSS 3.2 → 5.3 GiB); M4 Max 6.55 → 6.10 s (−7%,
/// 3.2 → 4.8 GiB). Beyond ~160 the M4 gains nothing and the M3 only slowly
/// (640: 7.9 s, 6.3 GiB) at a steep memory price.
pub const MAX_READAHEAD: usize = 160;

/// Default `--readahead`: as deep as [`MAX_READAHEAD`], but never more than
/// 1/8 of physical RAM worth of segments, and never below the old
/// `decoders + 4`. With unknown RAM, stay at that floor. On a 16 GB Mac this
/// is 128 segments (2 GiB of buffers); from 32 GB up it is the full 160.
pub fn default_readahead(ram: Option<u64>, seg_bytes: usize, decoders: usize) -> usize {
    let floor = decoders + 4;
    let Some(ram) = ram else { return floor };
    let fit = ((ram / 8) / seg_bytes.max(1) as u64) as usize;
    fit.min(MAX_READAHEAD).max(floor)
}

/// Physical memory in bytes, if the platform tells us.
pub fn physical_ram() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let mut v: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        // SAFETY: `v`/`len` describe a valid u64 out-buffer for hw.memsize.
        let rc = unsafe {
            libc::sysctlbyname(
                c"hw.memsize".as_ptr(),
                (&raw mut v).cast(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (rc == 0 && v > 0).then_some(v)
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: sysconf has no preconditions.
        let (pages, size) = unsafe {
            (
                libc::sysconf(libc::_SC_PHYS_PAGES),
                libc::sysconf(libc::_SC_PAGESIZE),
            )
        };
        (pages > 0 && size > 0).then(|| pages as u64 * size as u64)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

pub struct Opts {
    pub out: PathBuf,
    pub dry: bool,
    pub decoders: usize,
    pub writers: usize,
    /// Capacity of the decoder→parser result channel, in segments.
    pub readahead: usize,
    /// Reserve each file's full length (fcntl/posix_fallocate) before the
    /// first write so APFS doesn't grow extents mid-blob.
    pub prealloc: bool,
    /// Enforce MACs, signature/chain policy and per-segment checksums
    /// (default on; `--no-verify` clears).
    pub verify: bool,
    /// LZMA implementation for segment decoding.
    pub decoder: XzDecoder,
    /// Store files with transparent APFS compression (decmpfs, LZBITMAP),
    /// as Apple's extractor does. Already resolved against the output
    /// volume by [`resolve_compress`].
    pub compress: bool,
    /// Which compression policy to use when storing compressed. Ignored
    /// when `compress` is false.
    pub compress_mode: CompressMode,
}

/// Which compression policy to use when storing compressed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum CompressMode {
    /// Apple's extractor's policy: compress everything that clearly pays
    /// (the default).
    #[default]
    Balanced,
    /// xaea-only: skip small files entirely, give up after 1 MiB, and keep
    /// only files that save at least 10% — less CPU on the writer threads,
    /// more disk.
    Fast,
}

impl CompressMode {
    /// The policy this mode resolves to.
    pub fn policy(self) -> decmpfs::Policy {
        match self {
            CompressMode::Balanced => decmpfs::Policy::balanced(),
            CompressMode::Fast => decmpfs::Policy::fast(),
        }
    }

    /// Machine-readable name for `--json` output.
    pub fn name(self) -> &'static str {
        match self {
            CompressMode::Balanced => "balanced",
            CompressMode::Fast => "fast",
        }
    }
}

/// Whether to store files compressed. Either way, a volume that can't hold
/// compressed files (see [`decmpfs::probe`]) gets plain files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compress {
    Off,
    /// The macOS default: fall back silently.
    Auto,
    /// Asked for explicitly (`--compress`): warn when falling back.
    On,
}

/// Decide whether this run compresses. One probe up front decides for the
/// whole run: a volume either stores compressed files or it doesn't
/// (FAT/exFAT, most network shares, Linux). Creates `out` when it has to
/// probe it. Called before the writer count is chosen, since compressing
/// wants more writers.
pub fn resolve_compress(out: &Path, want: Compress, dry: bool) -> Result<bool> {
    if want == Compress::Off || dry {
        return Ok(false);
    }
    std::fs::create_dir_all(out).with_context(|| format!("mkdir {}", out.display()))?;
    Ok(match decmpfs::probe(out) {
        Ok(()) => true,
        Err(e) => {
            if want == Compress::On {
                eprintln!(
                    "warning: writing uncompressed files: {} can't hold compressed files ({e:#})",
                    out.display()
                );
            }
            false
        }
    })
}

/// Enforce every structural guarantee that does not need a full file pass,
/// before touching the filesystem (review #2): signature + chain policy,
/// then the root/cluster header MACs — microseconds next to decoding.
/// Returns the main key so the caller can run the expensive segment-MAC
/// pass concurrently with the pipeline (joined before the final pass).
pub(crate) fn verify_upfront(env: &Envelope) -> Result<Key> {
    let chain = env
        .certificate_chain()
        .context("no certificate-chain auth pair")?;
    let auth = crate::sigverify::verify_all(
        chain,
        crate::sigverify::APPLE_ROOTS,
        env.signature(),
        &env.signed_prefix(),
    )
    .context("signature/chain verification")?;
    ensure!(auth.content_sig_ok, "content signature does not verify");
    ensure!(auth.sig_padded_ok, "signature field has non-zero padding");
    ensure!(auth.chain_all_ok, "certificate chain link failed to verify");
    ensure!(auth.ca_ok, "chain contains an issuer without CA:true");
    ensure!(
        auth.valid_now,
        "chain contains an out-of-validity certificate"
    );
    if !auth.trusted_root {
        eprintln!(
            "warning: signer does not chain to the vendored Apple root — content \
             integrity is verified, but Apple distribution trust is NOT established"
        );
    }
    let main = env.main_key(auth.certs[0].point());
    let macs = env.verify_header_macs(&main);
    ensure!(macs.root_ok, "root header MAC mismatch");
    ensure!(macs.clusters_ok, "cluster header MAC mismatch");
    Ok(main)
}

pub fn extract(env: &Envelope, src: &Path, opts: &Opts) -> Result<Stats> {
    // Cheap upfront checks (signature, chain policy, header MACs); the one
    // full-file check — segment MACs over the compressed bytes — then runs
    // concurrently with the pipeline instead of serializing ~1.5 s of HMAC
    // in front of it, and is joined before the final pass. Per-segment
    // checksums still gate every write inline in the decoder threads.
    let main = if opts.verify {
        anyhow::ensure!(
            env.root.checksum == Checksum::Sha256,
            "extract verification enforces SHA-256 segment checksums; this archive \
             declares {} — use --no-verify to extract anyway",
            env.root.checksum
        );
        Some(verify_upfront(env)?)
    } else {
        None
    };
    std::thread::scope(|scope| {
        let segmac = main.map(|k| {
            // Few threads on purpose: this path should hide underneath the
            // decode pipeline, not compete with it for cores.
            let n = std::thread::available_parallelism()
                .map_or(2, |n| n.get().min(4))
                .max(1);
            scope.spawn(move || env.verify_segment_macs_with(&k, n))
        });
        extract_body(env, src, opts, segmac)
    })
}

fn extract_body(
    env: &Envelope,
    src: &Path,
    opts: &Opts,
    segmac: Option<std::thread::ScopedJoinHandle<'_, Vec<u32>>>,
) -> Result<Stats> {
    if !opts.dry {
        std::fs::create_dir_all(&opts.out)
            .with_context(|| format!("mkdir {}", opts.out.display()))?;
    }
    let compress = opts.compress && !opts.dry;
    let policy = compress.then(|| opts.compress_mode.policy());
    let segs: Arc<[SegInfo]> = env
        .segments()
        .map(|s| SegInfo::new(&s, opts.verify))
        .collect();
    let nseg = segs.len();
    let fh = Arc::new(File::open(src).with_context(|| format!("open {}", src.display()))?);
    let prog = Arc::new(Progress::new());
    status::install_signal();

    // Writers: per-writer ordered channels.
    let (file_default, dir_default) = writer::create_defaults();
    let nw = opts.writers.max(1);
    let (wtx, wrx): (Vec<SyncSender<Work>>, Vec<Receiver<Work>>) = (0..nw)
        .map(|_| sync_channel::<Work>(prof::depth("XAEA_WQ", 32)))
        .unzip();
    let load: Option<Load> = (compress || std::env::var_os("XAEA_BALANCE").is_some())
        .then(|| (0..nw).map(|_| AtomicU64::new(0)).collect());
    let writers: Vec<_> = wrx
        .into_iter()
        .enumerate()
        .map(|(i, rx)| {
            let root = opts.out.clone();
            let load = load.clone().map(|l| (l, i));
            let writer = Writer::new(root, file_default, policy, nw, load);
            thread::spawn(move || writer.run(&rx))
        })
        .collect();

    // Decoders: pull segment indices, pread + decode, hand results over a
    // bounded channel (results carry errors so the parser can surface them).
    let nd = opts.decoders.max(1);
    let decoder = opts.decoder;
    let (dtx, drx) = sync_channel::<Result<(usize, Arc<[u8]>)>>(opts.readahead.max(1));
    let next = Arc::new(AtomicUsize::new(0));
    let mut decoders = Vec::new();
    for _ in 0..nd {
        let (next, fh, segs, dtx) = (next.clone(), fh.clone(), segs.clone(), dtx.clone());
        decoders.push(thread::spawn(move || {
            loop {
                let i = next.fetch_add(1, Relaxed);
                if i >= nseg {
                    break;
                }
                let sg = &segs[i];
                let r = decode_segment(&fh, sg, i, decoder)
                    .map(|b| (i, b))
                    .with_context(|| format!("decode segment {i}"));
                prof::count(K::Segs, 1);
                if prof::time(C::DSend, || dtx.send(r)).is_err() {
                    break; // parser is gone (error path)
                }
            }
        }));
    }
    drop(dtx);

    let _timeline = {
        let p = prog.clone();
        prof::timeline(prog.started, move || p.seg_done.load(Relaxed))
    };
    let mut sink = DispatchSink::new(opts, compress, wtx, load, prog.clone());
    let mut stream = Stream::new(&mut sink);

    // Reorder decoded segments into strict payload order and parse.
    let mut pending: HashMap<usize, Arc<[u8]>> = HashMap::new();
    let mut expect = 0usize;
    while expect < nseg {
        let (i, buf) = prof::time(C::PRecv, || drx.recv()).context("decoder thread died")??;
        if i == expect {
            prof::time(C::PFeed, || stream.feed(&buf))?;
            expect += 1;
            while let Some(b) = pending.remove(&expect) {
                prof::time(C::PFeed, || stream.feed(&b))?;
                expect += 1;
            }
            prog.seg_done.store(expect, Relaxed);
            status::maybe_print(&prog, nseg);
        } else {
            pending.insert(i, buf);
        }
    }
    stream.finish()?;
    drop(stream);
    let parser_done = prog.started.elapsed().as_secs_f64();
    sink.close_cur()?;
    // Join the concurrent segment-MAC pass: by now every blob byte on disk
    // has also passed its inline checksum, but nothing symlink- or
    // chmod-shaped should land in the tree of an archive whose compressed
    // bytes fail their MACs.
    let segmac_failed = match segmac {
        Some(h) => h
            .join()
            .map_err(|_| anyhow::anyhow!("segment MAC thread panicked"))?,
        None => Vec::new(),
    };
    ensure!(
        segmac_failed.is_empty(),
        "segment MAC failures: {segmac_failed:?}"
    );
    // A failed send here means a writer already exited with its own error
    // (e.g. the link pass refusing a traversal), so hold it until the
    // writers are joined and report theirs first.
    let tail = sink.final_pass(dir_default);
    let st = sink.into_stats(); // closes writer channels; writers flush and exit

    let mut first_err: Option<anyhow::Error> = None;
    let mut refused = 0;
    for h in writers {
        let r = h
            .join()
            .map_err(|_| anyhow::anyhow!("writer thread panicked"))?;
        match r {
            Ok(n) => refused += n,
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    for h in decoders {
        let _ = h.join();
    }
    if std::env::var_os("XAEA_STATS").is_some() {
        let total = prog.started.elapsed().as_secs_f64();
        eprintln!(
            "[stats] parse+dispatch done at {parser_done:.1}s; writer drain +{:.1}s; total {total:.1}s",
            total - parser_done
        );
        prof::report();
    }
    status::maybe_print(&prog, nseg);
    status::end_line();
    if compress && refused > 0 {
        eprintln!(
            "warning: the volume refused compression for {refused} files; they were written uncompressed"
        );
    }
    match first_err {
        Some(e) => Err(e),
        None => tail.map(|()| st),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readahead_scales_with_ram() {
        const GIB: u64 = 1 << 30;
        let seg = 16 << 20;
        // 8 GB -> 64, 16 GB -> 128, 32 GB and up -> the 160 cap.
        assert_eq!(default_readahead(Some(8 * GIB), seg, 15), 64);
        assert_eq!(default_readahead(Some(16 * GIB), seg, 15), 128);
        assert_eq!(default_readahead(Some(32 * GIB), seg, 15), 160);
        assert_eq!(default_readahead(Some(128 * GIB), seg, 15), 160);
        // Never below the old decoders + 4, whatever the RAM says.
        assert_eq!(default_readahead(Some(GIB), seg, 15), 19);
        assert_eq!(default_readahead(None, seg, 15), 19);
        // Absurdly many decoders must not panic the clamp.
        assert_eq!(default_readahead(Some(128 * GIB), seg, 400), 404);
        assert_eq!(default_readahead(Some(8 * GIB), 0, 2), 160);
    }
}
