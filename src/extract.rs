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

use crate::aa::{Piece, Record, Sink, Stream};
use crate::decmpfs;
use crate::envelope::{Envelope, XzDecoder};
use crate::prof::{self, C, K};
use anyhow::{Context, Result, bail, ensure};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;
use std::time::Instant;

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
                &mut len,
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

/// Effective create defaults under the current umask; matching modes skip a
/// chmod/fchmod syscall (~137k of them across a full Xcode tree otherwise).
fn create_defaults() -> (u32, u32) {
    let mask = unsafe {
        let m = libc::umask(0);
        libc::umask(m);
        m
    } as u32;
    (0o666 & !mask, 0o777 & !mask)
}

#[cfg(target_os = "macos")]
fn preallocate(f: &File, size: u64) -> std::io::Result<()> {
    let st = libc::fstore_t {
        fst_flags: libc::F_ALLOCATEALL | libc::F_PEOFPOSMODE as u32,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: size as libc::c_longlong,
        fst_bytesalloc: 0,
    };
    let r = unsafe {
        libc::fcntl(
            std::os::fd::AsRawFd::as_raw_fd(f),
            libc::F_PREALLOCATE,
            &st as *const libc::fstore_t,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn preallocate(f: &File, size: u64) -> std::io::Result<()> {
    let r = unsafe {
        libc::posix_fallocate(std::os::fd::AsRawFd::as_raw_fd(f), 0, size as libc::off_t)
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(r))
    }
}

// ------------------------------------------------------------ status (^T)

/// Live counters mirrored from the parser sink; read only when the user
/// asks for status.
pub struct Progress {
    seg_done: AtomicUsize,
    bytes_out: AtomicU64,
    files: AtomicU64,
    started: Instant,
}

impl Progress {
    fn new() -> Self {
        Progress {
            seg_done: AtomicUsize::new(0),
            bytes_out: AtomicU64::new(0),
            files: AtomicU64::new(0),
            started: Instant::now(),
        }
    }
}

static STATUS_WANTED: AtomicBool = AtomicBool::new(false);
static STATUS_SHOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_status(_sig: libc::c_int) {
    // Async-signal-safe: only flips a flag; the parser prints.
    STATUS_WANTED.store(true, Relaxed);
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const STATUS_SIG: libc::c_int = libc::SIGINFO;
#[cfg(target_os = "linux")]
const STATUS_SIG: libc::c_int = libc::SIGUSR1;

fn install_status_signal() {
    unsafe {
        libc::signal(STATUS_SIG, on_status as *const () as libc::sighandler_t);
    }
}

fn gib(n: u64) -> f64 {
    n as f64 / (1u64 << 30) as f64
}

fn maybe_print_status(p: &Progress, nseg: usize) {
    if !STATUS_WANTED.swap(false, Relaxed) {
        return;
    }
    STATUS_SHOWN.store(true, Relaxed);
    let secs = p.started.elapsed().as_secs_f64().max(1e-6);
    let seg = p.seg_done.load(Relaxed);
    let bytes = p.bytes_out.load(Relaxed);
    eprint!(
        "\r\x1b[K ^T  seg {seg}/{nseg} ({:.0}%)  {:.2} GiB payload  {:.0} MiB/s  files {}  {secs:.1}s",
        100.0 * seg as f64 / nseg as f64,
        gib(bytes),
        bytes as f64 / secs / (1u64 << 20) as f64,
        p.files.load(Relaxed),
    );
}

/// Terminate a dangling status line so normal output starts fresh.
pub fn end_status_line() {
    if STATUS_SHOWN.swap(false, Relaxed) {
        eprintln!();
    }
}

// ---------------------------------------------------------------- writers

/// Messages to a writer thread. All filesystem *syscalls* (mkdir, open,
/// chmod, symlink, pwrite) happen on writer threads so the
/// parser stays pure CPU + dispatch; per-writer channels are FIFO, so any
/// ordering a path needs is guaranteed by routing that path's messages to
/// one channel (files/links by round-robin sequence, directories by
/// content-hash of their path).
enum Work {
    Mkdir {
        path: Box<Path>,
    },
    Open {
        seq: u64,
        path: Box<Path>,
        mode: u32,
        /// Declared length (decides whether and how to compress).
        size: u64,
    },
    Slice {
        seq: u64,
        off: u64,
        piece: Piece,
        prealloc: u64,
    },
    /// Drain barrier: acknowledge once everything queued before it has
    /// been executed (per-writer channels are FIFO).
    Flush(std::sync::mpsc::SyncSender<()>),
    /// Final pass, in stream order, single writer (see module docs). The
    /// writer may fan the creations out to scoped helpers; the ordering
    /// guarantee that matters is that the pass completes before the writer
    /// takes the `DirModes` message queued behind it.
    LinkPass(Vec<(Box<Path>, Box<str>)>),
    /// Final pass: directory modes, applied after every object exists.
    DirModes(Vec<(Box<Path>, u32)>),
}

/// Below this many links the final pass stays on one thread. A `symlink(2)`
/// on APFS costs tens of microseconds, so on a short pass thread spawn and
/// queue handoff cost more than they save.
const LINK_PAR_MIN: usize = 256;

/// Ceiling on final-pass workers. APFS serialises metadata updates well
/// before the core count: creating 12k links over a deep tree measured
/// 40.2 us/link on one thread, 12.6 us/link at 6 (3.2x), 18.5 at 8 (2.2x),
/// and back to ~serial at 12 and 16 — contention, not parallelism. The
/// default `--writers` is 6, which is where that curve peaks.
const LINK_PAR_MAX: usize = 8;

/// Lowercase a clamped record path for guard comparison, component by
/// component, so the result is byte-identical to the ancestor accumulator the
/// guard walk builds. Case-insensitivity matters on case-insensitive volumes,
/// where a link at `Payload/up` and a record at `payload/up/under` collide.
fn lower_path(path: &Path) -> Vec<u8> {
    let mut acc: Vec<u8> = Vec::new();
    for comp in path.components() {
        if !acc.is_empty() {
            acc.push(b'/');
        }
        acc.extend_from_slice(comp.as_os_str().to_string_lossy().to_lowercase().as_bytes());
    }
    acc
}

/// Final-pass symlink creation with the tar-attack guard: a symlink whose
/// path traverses a symlink created earlier in the same pass is refused —
/// during the stream phase no archive symlink exists at all, so this closes
/// the "link `x -> ..` then write `x/PWNED`" class entirely. Comparison is
/// case-insensitive to match case-insensitive volumes.
///
/// `workers` > 1 lets the *creations* run concurrently, but only for a link
/// list that is pairwise independent (see [`links_are_independent`]); any
/// other list — and any list shorter than [`LINK_PAR_MIN`] — runs the
/// sequential pass below, unchanged.
fn link_pass(root: &Path, links: &[(Box<Path>, Box<str>)], workers: usize) -> Result<()> {
    if links.len() >= LINK_PAR_MIN && workers > 1 && links_are_independent(links) {
        link_pass_par(root, links, workers)
    } else {
        link_pass_seq(root, links)
    }
}

/// True when no link path is a strict component-boundary ancestor of another
/// and no two paths name the same link case-insensitively.
///
/// This is the guard, hoisted. The guard below only ever consults `created`,
/// which is built from the record list itself and never from the filesystem,
/// so whether a link traverses an archive symlink is a property of the list,
/// not of the tree — it can be decided for every link, single-threaded,
/// before a single link exists. Under independence no link can be created
/// *through* another one (the only way two `symlink(2)` calls in this pass
/// can interact), so the creations are free to race each other harmlessly.
///
/// The test is deliberately stronger than the guard it replaces (it rejects
/// an ancestor pair in either stream order, the guard only if the ancestor
/// comes first) and it is *not* a verdict on the archive: false means "run
/// the sequential pass", which still applies the guard exactly as written.
fn links_are_independent(links: &[(Box<Path>, Box<str>)]) -> bool {
    let mut all: std::collections::HashSet<Vec<u8>> =
        std::collections::HashSet::with_capacity(links.len());
    for (path, _) in links {
        if !all.insert(lower_path(path)) {
            return false; // two records name the same link: last-writer-wins today
        }
    }
    for (path, _) in links {
        // Strict ancestors of `path`, at component boundaries — same walk as
        // the guard's, but matched against every link rather than earlier ones.
        let mut acc: Vec<u8> = Vec::new();
        for comp in path.components() {
            if !acc.is_empty() && all.contains(&acc) {
                return false;
            }
            if !acc.is_empty() {
                acc.push(b'/');
            }
            acc.extend_from_slice(comp.as_os_str().to_string_lossy().to_lowercase().as_bytes());
        }
    }
    true
}

/// Create one link record. `symlink(2)` first: in the common case the parent
/// exists and the name is free, so this is the only syscall, and each extra
/// syscall here (it used to be mkdir + stat + unlink + symlink) is pure wall
/// time. Shared by both passes so their occupant and missing-parent
/// behaviour cannot drift apart.
fn create_link(root: &Path, path: &Path, target: &str) -> Result<()> {
    let full = root.join(path);
    let mut r = symlink(target, &full);
    if matches!(&r, Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        if let Some(p) = full.parent() {
            std::fs::create_dir_all(p).with_context(|| format!("mkdir -p {}", p.display()))?;
        }
        r = symlink(target, &full);
    }
    if matches!(&r, Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists) {
        match std::fs::remove_file(&full) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // EISDIR etc.: a real directory (or file) we cannot replace
            // lives here — in a well-formed archive this cannot happen;
            // bail loudly rather than silently keep the occupant (a
            // planted `x/` dir against a link record is itself
            // suspicious).
            Err(e) => Err(e).with_context(|| format!("replace {} with symlink", full.display()))?,
        }
        r = symlink(target, &full);
    }
    r.with_context(|| format!("symlink {} -> {}", full.display(), target))
}

/// The original pass: guard each link against the links created before it,
/// then create it, in stream order, on this thread.
fn link_pass_seq(root: &Path, links: &[(Box<Path>, Box<str>)]) -> Result<()> {
    let mut created: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for (path, target) in links {
        // Strict ancestors of `path`, at component boundaries.
        let mut acc: Vec<u8> = Vec::new();
        for comp in path.components() {
            let name = comp.as_os_str().to_string_lossy();
            if created.contains(&acc) && !acc.is_empty() {
                bail!(
                    "refusing symlink {}: traverses archive-created symlink {}",
                    path.display(),
                    String::from_utf8_lossy(&acc)
                );
            }
            if !acc.is_empty() {
                acc.push(b'/');
            }
            acc.extend_from_slice(name.to_lowercase().as_bytes());
        }
        create_link(root, path, target)?;
        // `acc` is now the whole lowercased path: record it with the same
        // walk that produced the ancestors compared above, so a link can
        // never be recorded under one spelling and matched under another.
        created.insert(acc);
    }
    Ok(())
}

/// Concurrent variant, valid only for an independent link list (checked by
/// the caller, before anything was created, so there is no check-then-create
/// window between workers). Workers pull record indices off one shared
/// counter — a flat split would strand the tail on whichever thread drew the
/// deep subtrees.
///
/// On the error path this can create a handful of links that the sequential
/// pass would not have reached (the ones already in flight when the first
/// failure lands); the extraction aborts either way, and every link created
/// here is inside the tree and traverses no other link.
fn link_pass_par(root: &Path, links: &[(Box<Path>, Box<str>)], workers: usize) -> Result<()> {
    let workers = workers.min(LINK_PAR_MAX).min(links.len()).max(1);
    if workers == 1 {
        return link_pass_seq(root, links);
    }
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let err: std::sync::Mutex<Option<anyhow::Error>> = std::sync::Mutex::new(None);
    // Scoped, not spawned: the pass must not outlive the message that
    // carried the link list, and `DirModes` may not start until it has.
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    if failed.load(Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Relaxed);
                    if i >= links.len() {
                        break;
                    }
                    let (path, target) = &links[i];
                    if let Err(e) = create_link(root, path, target) {
                        if !failed.swap(true, Relaxed) {
                            *err.lock().unwrap_or_else(|p| p.into_inner()) = Some(e);
                        }
                        break;
                    }
                }
            });
        }
    });
    match err.lock().unwrap_or_else(|p| p.into_inner()).take() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Subtracts a message's cost from its writer's [`Load`] when dropped.
struct Credit<'a>(&'a AtomicU64, u64);

impl Drop for Credit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(self.1, Relaxed);
    }
}

/// The file a writer is filling.
struct OpenFile {
    seq: u64,
    f: File,
    /// Data goes through the writer's encoder rather than straight to disk.
    compressing: bool,
    /// Mode still to apply at close. Compressed files get theirs only after
    /// the xattrs are stored: the kernel checks xattr writes against the
    /// file's mode, not the fd, so a 0444 file would refuse them.
    chmod: Option<u32>,
    path: PathBuf,
}

/// Close the writer's current file, storing it compressed first if that is
/// how it was being written.
fn close_file(cur: &mut Option<OpenFile>, enc: &mut Option<decmpfs::Encoder>) -> Result<()> {
    if let Some(o) = cur.take() {
        if o.compressing {
            let e = enc.as_mut().context("compressing without an encoder")?;
            prof::time(C::WStore, || e.finish(&o.f))
                .with_context(|| format!("store compressed {}", o.path.display()))?;
        }
        if let Some(mode) = o.chmod {
            prof::time(C::WFchmod, || {
                o.f.set_permissions(std::fs::Permissions::from_mode(mode))
            })
            .with_context(|| format!("fchmod {}", o.path.display()))?;
        }
        prof::time(C::WClose, || drop(o));
    }
    Ok(())
}

/// Queued work per writer, in bytes still to write plus [`OPEN_COST`] per
/// pending open. Lets the parser hand each new file to the least-loaded
/// writer instead of round-robin, which matters when writers also compress:
/// a writer encoding a large file would otherwise sit on a queue full of
/// small files while the parser blocks on it and the other writers idle.
type Load = Arc<[AtomicU64]>;
/// What one open + close costs a writer, in bytes-of-work terms.
const OPEN_COST: u64 = 32 << 10;

fn work_cost(w: &Work) -> u64 {
    match w {
        Work::Open { .. } => OPEN_COST,
        Work::Slice { piece, .. } => piece.len() as u64,
        _ => 0,
    }
}

/// Least-loaded writer, scanning from `start` so ties rotate.
fn least_loaded(load: &[AtomicU64], start: usize) -> usize {
    let n = load.len();
    (0..n)
        .map(|k| (start + k) % n)
        .min_by_key(|&w| load[w].load(Relaxed))
        .unwrap_or(0)
}

fn writer_loop(
    rx: Receiver<Work>,
    root: PathBuf,
    file_default: u32,
    compress: bool,
    load: Option<(Load, usize)>,
    link_workers: usize,
) -> Result<()> {
    // Open file being written; closed when the next Open, a Flush, or the
    // channel end arrives.
    let mut cur: Option<OpenFile> = None;
    let mut enc = compress.then(decmpfs::Encoder::new);
    while let Ok(w) = prof::time(C::WRecv, || rx.recv()) {
        // Credited back once the message is handled (on error the whole
        // extraction is failing anyway).
        let _done = load.as_ref().map(|(l, i)| Credit(&l[*i], work_cost(&w)));
        match w {
            Work::Mkdir { path } => {
                let full = root.join(path);
                // One mkdir(2) in the common case. create_dir_all would also
                // do just that when it succeeds, but it is the fallback for
                // the rare cases (parent not created yet, or a file writer
                // already made this dir on demand: EEXIST + stat).
                prof::time(C::WMkdir, || -> Result<()> {
                    if std::fs::create_dir(&full).is_err() {
                        std::fs::create_dir_all(&full)
                            .with_context(|| format!("mkdir {}", full.display()))?;
                    }
                    Ok(())
                })?;
            }
            Work::Flush(ack) => {
                close_file(&mut cur, &mut enc)?; // finish the open file before acknowledging
                let _ = ack.send(());
            }
            Work::LinkPass(links) => {
                prof::time(C::WLink, || link_pass(&root, &links, link_workers))?
            }
            Work::DirModes(modes) => {
                prof::time(C::WDirmode, || -> Result<()> {
                    for (path, mode) in modes {
                        let full = root.join(path);
                        std::fs::set_permissions(&full, std::fs::Permissions::from_mode(mode))
                            .with_context(|| format!("chmod {}", full.display()))?;
                    }
                    Ok(())
                })?;
            }
            Work::Open {
                seq,
                path,
                mode,
                size,
            } => {
                close_file(&mut cur, &mut enc)?;
                prof::count(K::Opens, 1);
                let full = root.join(path);
                let open = |p: &Path| {
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(p)
                };
                // Open first; create the parent only if it is missing. The
                // parent normally exists already (its Mkdir precedes this
                // record in the stream), but it may be owned by a sibling
                // writer that hasn't run it yet. An unconditional
                // create_dir_all here cost two syscalls per file — mkdir
                // (EEXIST) + stat — about 250k across an Xcode tree.
                let f = match prof::time(C::WOpen, || open(&full)) {
                    Ok(f) => Ok(f),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if let Some(p) = full.parent() {
                            prof::time(C::WMkp, || std::fs::create_dir_all(p))
                                .with_context(|| format!("mkdir -p {}", p.display()))?;
                        }
                        prof::time(C::WOpen, || open(&full))
                    }
                    Err(e) => Err(e),
                }
                .with_context(|| format!("create {}", full.display()))?;
                // Empty files stay plain, as Apple's extractor leaves them.
                let compressing = size > 0 && enc.is_some();
                // Skip fchmod when open(2) already produced the mode via the
                // umask default — see create_defaults() for the rationale.
                let chmod = (mode != file_default).then_some(mode);
                if !compressing && let Some(mode) = chmod {
                    prof::time(C::WFchmod, || {
                        f.set_permissions(std::fs::Permissions::from_mode(mode))
                    })
                    .with_context(|| format!("fchmod {}", full.display()))?;
                }
                if compressing && let Some(e) = enc.as_mut() {
                    e.begin(size);
                }
                cur = Some(OpenFile {
                    seq,
                    f,
                    compressing,
                    chmod: chmod.filter(|_| compressing),
                    path: full,
                });
            }
            Work::Slice {
                seq,
                mut off,
                piece,
                prealloc,
            } => {
                let o = cur.as_mut().context("slice for file not opened")?;
                ensure!(
                    o.seq == seq,
                    "slice seq {seq} but writer is on file {}",
                    o.seq
                );
                let f = &o.f;
                if o.compressing {
                    let e = enc.as_mut().context("compressing without an encoder")?;
                    let keep = prof::time(C::WCompress, || e.push(piece.bytes()))
                        .with_context(|| format!("compress {}", o.path.display()))?;
                    if !keep {
                        // Not worth it: write what was encoded so far back
                        // out plainly and send the rest straight to disk.
                        prof::time(C::WStore, || e.spill(f))
                            .with_context(|| format!("write {}", o.path.display()))?;
                        o.compressing = false;
                    }
                    continue;
                }
                if prealloc > 0 {
                    // Allocation failure isn't fatal — writes still work.
                    let _ = preallocate(f, prealloc);
                }
                let mut b = piece.bytes();
                while !b.is_empty() {
                    let n = prof::time(C::WPwrite, || f.write_at(b, off)).context("pwrite")?;
                    prof::count(K::Pwrites, 1);
                    prof::count(K::PwriteBytes, n as u64);
                    ensure!(n > 0, "pwrite made no progress");
                    off += n as u64;
                    b = &b[n..];
                }
            }
        }
    }
    close_file(&mut cur, &mut enc)
}

// ------------------------------------------------------------ parser sink

/// Bookkeeping for the file record currently being streamed; the actual fd
/// lives on its writer thread.
struct Cur {
    seq: u64,
    expect: u64,
    written: u64,
    path: Vec<u8>,
    writer: usize,
    prealloc: u64,
}

struct DispatchSink {
    dry: bool,
    /// Output root, used to refuse top-level collisions with existing paths.
    root: PathBuf,
    /// Top-level names already checked (each is checked once, on first sight).
    seen_top: std::collections::HashSet<std::ffi::OsString>,
    txs: Vec<SyncSender<Work>>,
    cur: Option<Cur>,
    st: Stats,
    prog: Arc<Progress>,
    /// Files + links share this round-robin counter for writer selection.
    obj_seq: u64,
    /// Per-writer queued work; when set, files go to the least-loaded
    /// writer instead of round-robin.
    load: Option<Load>,
    prealloc: bool,
    /// Held back for the final pass (see module docs).
    links: Vec<(Box<Path>, Box<str>)>,
    dir_modes: Vec<(Box<Path>, u32)>,
}

/// FNV-1a over the path so all messages *about one directory* (its own
/// mkdir) land on one channel; children get their own channel but create
/// their parent on demand, so no cross-channel ordering is required.
fn route_hash(path: &[u8], nw: usize) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h as usize % nw
}

impl DispatchSink {
    fn close_cur(&mut self) -> Result<()> {
        if let Some(c) = self.cur.take() {
            ensure!(
                c.written == c.expect,
                "short blob for {}: wrote {} of {} bytes",
                String::from_utf8_lossy(&c.path),
                c.written,
                c.expect
            );
        }
        Ok(())
    }

    /// Refuse to extract over an existing path. Checked once per distinct
    /// top-level name, *before* any work for it is dispatched, so a
    /// collision (typically `Xcode.app` already present) aborts at the
    /// archive's first record with nothing written — and never trips over
    /// entries this extraction created itself. `symlink_metadata`: a
    /// dangling symlink at that name is a collision too.
    fn check_top_level(&mut self, rel: &Path) -> Result<()> {
        let Some(Component::Normal(top)) = rel.components().next() else {
            return Ok(());
        };
        if !self.seen_top.insert(top.to_os_string()) {
            return Ok(());
        }
        let dest = self.root.join(top);
        match std::fs::symlink_metadata(&dest) {
            Ok(_) => bail!(
                "{} already exists; remove it or choose another output directory",
                dest.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("stat {}", dest.display())),
        }
    }

    fn send(&self, w: usize, work: Work) -> Result<()> {
        if let Some(l) = &self.load {
            l[w].fetch_add(work_cost(&work), Relaxed);
        }
        prof::time(C::PSend, || self.txs[w].send(work))
            .context("writer channel closed (writer died?)")
    }
}

impl Sink for DispatchSink {
    fn record(&mut self, rec: &Record) -> Result<()> {
        self.close_cur()?;
        let rel = sanitize(&rec.path)
            .with_context(|| format!("record path {:?}", String::from_utf8_lossy(&rec.path)))?
            .into_boxed_path();
        // Strip setuid/setgid/sticky: an unprivileged extraction must never
        // plant privilege bits (review #9; Apple's own tree needs none).
        let mode = rec.mode & 0o0777;
        self.check_top_level(&rel)?;
        let nw = self.txs.len();
        match rec.typ {
            b'D' => {
                if !self.dry {
                    self.send(route_hash(&rec.path, nw), Work::Mkdir { path: rel.clone() })?;
                    self.dir_modes.push((rel, mode));
                }
                self.st.dirs += 1;
            }
            b'L' => {
                let target = rec
                    .link
                    .as_ref()
                    .map(|l| link_target(l))
                    .context("link record without LNK")??;
                self.obj_seq += 1;
                if !self.dry {
                    self.links.push((rel, target.into_boxed_str()));
                }
                self.st.links += 1;
            }
            b'F' => {
                self.obj_seq += 1;
                let seq = self.obj_seq;
                let w = match &self.load {
                    Some(l) => least_loaded(l, seq as usize % nw),
                    None => seq as usize % nw,
                };
                if !self.dry {
                    self.send(
                        w,
                        Work::Open {
                            seq,
                            path: rel,
                            mode,
                            size: rec.dat,
                        },
                    )?;
                }
                self.cur = Some(Cur {
                    seq,
                    expect: rec.dat,
                    written: 0,
                    path: rec.path.clone(),
                    writer: w,
                    prealloc: if self.prealloc && rec.dat > 0 {
                        rec.dat
                    } else {
                        0
                    },
                });
                self.st.files += 1;
                self.prog.files.fetch_add(1, Relaxed);
            }
            t => bail!("unknown object type {:?} at {rel:?}", t as char),
        }
        Ok(())
    }

    fn blob(&mut self, piece: Piece) -> Result<()> {
        let c = self.cur.as_mut().context("blob outside file record")?;
        let len = piece.len() as u64;
        let off = c.written;
        c.written += len;
        self.st.bytes += len;
        self.prog.bytes_out.fetch_add(len, Relaxed);
        if !self.dry {
            let writer = c.writer;
            let work = Work::Slice {
                seq: c.seq,
                off,
                piece,
                prealloc: std::mem::take(&mut c.prealloc),
            };
            self.send(writer, work)?;
        }
        Ok(())
    }
}

// ------------------------------------------------------------ path safety

/// Map a record path to a path under the output root. Absolute paths are
/// rejected; `..` components are clamped to the root (Apple's archives
/// contain intentional top-level escapes such as
/// `Xcode-beta.app/…/SharedFrameworks -> ../../../SystemFrameworks`, whose
/// target never lands in the archive; symlinks keep the *original* target so
/// in-root links resolve exactly as Apple's tool produces).
fn clamp(rel: &str) -> Result<PathBuf> {
    ensure!(!rel.is_empty(), "empty path");
    ensure!(!rel.starts_with('/'), "absolute path");
    let mut out = PathBuf::new();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(_) => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop(); // clamps at root
            }
            Component::RootDir | Component::Prefix(_) => bail!("absolute path"),
        }
    }
    ensure!(
        !out.as_os_str().is_empty(),
        "path escapes to nothing: {rel:?}"
    );
    Ok(out)
}

fn sanitize(p: &[u8]) -> Result<PathBuf> {
    let s = std::str::from_utf8(p).context("non-UTF8 path")?;
    clamp(s)
}

fn link_target(s: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(s).context("non-UTF8 link target")?;
    ensure!(!s.starts_with('/'), "absolute link target");
    Ok(s.to_string())
}

// ---------------------------------------------------------------- driver

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

/// Decode one segment (pread stored bytes; LZMA-decode to `orig`) and, when
/// `expect` is Some, check the SHA-256 of the *decoded* bytes (the AEA
/// checksum covers decompressed data — erratum 3). SHA-256 runs while the
/// other decoders are busy; it is cheap next to LZMA.
fn decode_segment(
    fh: &File,
    data_off: u64,
    comp: u32,
    orig: u32,
    expect: Option<[u8; 32]>,
    index: usize,
    dec: XzDecoder,
) -> Result<Arc<[u8]>> {
    // Both arms produce the shared segment buffer directly (no Vec -> Arc
    // copy; see envelope::segbuf_filled).
    let buf: Arc<[u8]> = if comp == orig {
        let len = orig as usize;
        let fill = |dst: *mut u8| -> Result<()> {
            // SAFETY: `dst` points to `len` writable bytes. Zeroing them
            // first makes the `&mut [u8]` handed to pread fully initialized.
            let s = unsafe {
                std::ptr::write_bytes(dst, 0, len);
                std::slice::from_raw_parts_mut(dst, len)
            };
            read_pread_into(fh, data_off, s)
        };
        // SAFETY: `fill` initialized all `len` bytes (zeroed, then read).
        unsafe { crate::envelope::segbuf_filled(len, fill)? }
    } else {
        let raw = prof::time(C::DPread, || read_pread(fh, data_off, comp as usize))?;
        prof::time(C::DDecode, || {
            crate::envelope::decode_xz(&raw, orig as usize, dec, expect.is_some())
        })?
    };
    if let Some(want) = expect {
        use sha2::{Digest, Sha256};
        let got: [u8; 32] = prof::time(C::DSha, || Sha256::digest(&buf[..]).into());
        ensure!(
            got == want,
            "checksum mismatch for segment {index} (corrupt or tampered archive)"
        );
    }
    Ok(buf)
}

/// Decoder-side view of a segment (owned/Copy so threads can own it).
#[derive(Clone, Copy)]
struct SegInfo {
    off: u64,
    comp: u32,
    orig: u32,
    cksum: Option<[u8; 32]>,
}

/// Enforce every structural guarantee that does not need a full file pass,
/// before touching the filesystem (review #2): signature + chain policy,
/// then the root/cluster header MACs — microseconds next to decoding.
/// Returns the main key so the caller can run the expensive segment-MAC
/// pass concurrently with the pipeline (joined before the final pass).
fn verify_upfront(env: &Envelope) -> Result<Vec<u8>> {
    let chain = env
        .auth
        .iter()
        .find(|(k, _)| k.ends_with(".signature.certificate-chain"))
        .map(|(_, v)| v.clone())
        .context("no certificate-chain auth pair")?;
    let auth = crate::sigverify::verify_all(
        &chain,
        crate::sigverify::APPLE_ROOTS,
        &env.file[env.sig_off..env.sig_off + crate::envelope::SIGNATURE_LEN],
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
    let (root_mac_ok, cluster_macs_ok, _) =
        env.verify_header_macs(&main).context("MAC verification")?;
    ensure!(root_mac_ok, "root header MAC mismatch");
    ensure!(cluster_macs_ok, "cluster header MAC mismatch");
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
            env.root.checksum == 2,
            "extract verification enforces SHA-256 segment checksums; this archive \
             declares {} — use --no-verify to extract anyway",
            crate::envelope::checksum_name(env.root.checksum)
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
                .map(|n| n.get().min(4))
                .unwrap_or(2)
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
        std::fs::create_dir_all(&opts.out)?;
    }
    let compress = opts.compress && !opts.dry;
    let ck = opts.verify.then_some(());
    let segs: Arc<Vec<SegInfo>> = Arc::new(
        env.segments()
            .iter()
            .map(|s| SegInfo {
                off: s.data_off as u64,
                comp: s.comp,
                orig: s.orig,
                cksum: ck.and_then(|()| <[u8; 32]>::try_from(s.cksum).ok()),
            })
            .collect(),
    );
    let nseg = segs.len();
    let fh = Arc::new(File::open(src).with_context(|| format!("open {}", src.display()))?);
    let prog = Arc::new(Progress::new());
    install_status_signal();

    // Writers: per-writer ordered channels.
    let (file_default, dir_default) = create_defaults();
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
            thread::spawn(move || writer_loop(rx, root, file_default, compress, load, nw))
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
                let r = decode_segment(&fh, sg.off, sg.comp, sg.orig, sg.cksum, i, decoder)
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
    let mut sink = DispatchSink {
        dry: opts.dry,
        root: opts.out.clone(),
        seen_top: Default::default(),
        txs: wtx,
        cur: None,
        st: Stats {
            dirs: 0,
            files: 0,
            links: 0,
            bytes: 0,
            compressed: compress,
        },
        prog: prog.clone(),
        obj_seq: 0,
        load,
        prealloc: opts.prealloc,
        links: Vec::new(),
        dir_modes: Vec::new(),
    };
    let mut stream = Stream::new(&mut sink);

    // Reorder decoded segments into strict payload order and parse.
    let mut pending: HashMap<usize, Arc<[u8]>> = HashMap::new();
    let mut expect = 0usize;
    while expect < nseg {
        let (i, buf) = prof::time(C::PRecv, || drx.recv()).context("decoder thread died")??;
        if i == expect {
            prof::time(C::PFeed, || stream.feed(buf))?;
            expect += 1;
            while let Some(b) = pending.remove(&expect) {
                prof::time(C::PFeed, || stream.feed(b))?;
                expect += 1;
            }
            prog.seg_done.store(expect, Relaxed);
            maybe_print_status(&prog, nseg);
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
    // Final pass, on one writer, strictly after every stream-phase write
    // has executed: a per-writer Flush barrier first (writer 0's queue
    // alone proves nothing about the others), then symlinks (before any
    // restrictive dir modes), then deferred directory modes.
    if !opts.dry {
        let t_flush = Instant::now();
        for w in 0..sink.txs.len() {
            let (atx, arx) = sync_channel::<()>(1);
            sink.send(w, Work::Flush(atx))?;
            arx.recv()
                .map_err(|_| anyhow::anyhow!("writer {w} died mid-flush"))?;
        }
        prof::add_since(C::WFlush, t_flush);
        let links = std::mem::take(&mut sink.links);
        sink.send(0, Work::LinkPass(links))?;
        let modes: Vec<(Box<Path>, u32)> = sink
            .dir_modes
            .drain(..)
            .filter(|(_, m)| *m != dir_default)
            .collect();
        sink.send(0, Work::DirModes(modes))?;
    }
    let st = Stats {
        dirs: sink.st.dirs,
        files: sink.st.files,
        links: sink.st.links,
        bytes: sink.st.bytes,
        compressed: sink.st.compressed,
    };
    drop(sink); // closes writer channels; writers flush and exit

    let mut first_err: Option<anyhow::Error> = None;
    for h in writers {
        let r = h
            .join()
            .map_err(|_| anyhow::anyhow!("writer thread panicked"))?;
        if r.is_err() && first_err.is_none() {
            first_err = r.err();
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
    maybe_print_status(&prog, nseg);
    end_status_line();
    let refused = decmpfs::REFUSED.load(Relaxed);
    if compress && refused > 0 {
        eprintln!(
            "warning: the volume refused compression for {refused} files; they were written uncompressed"
        );
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(st),
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

    #[test]
    fn clamp_policy() {
        assert_eq!(clamp("a/b/c").unwrap(), PathBuf::from("a/b/c"));
        assert_eq!(clamp("a/./b").unwrap(), PathBuf::from("a/b"));
        assert_eq!(clamp("a/b/../c").unwrap(), PathBuf::from("a/c"));
        assert_eq!(clamp("../../x").unwrap(), PathBuf::from("x"));
        assert_eq!(clamp("a/../../x").unwrap(), PathBuf::from("x"));
        assert_eq!(clamp("./x").unwrap(), PathBuf::from("x"));
        assert!(clamp("/abs").is_err(), "absolute paths rejected");
        assert!(clamp("").is_err());
        assert!(clamp("..").is_err(), "pure escape clamps to nothing");
        // The exact synthetic-fixture case:
        assert_eq!(
            sanitize(b"T/../../esc/../escaped/inside.bin").unwrap(),
            PathBuf::from("escaped/inside.bin")
        );
        assert!(sanitize(&[b'x', 0xff, b'y']).is_err(), "non-UTF8 rejected");
        // Link targets stay verbatim, but absolute ones are rejected.
        assert_eq!(link_target(b"a/../../b").unwrap(), "a/../../b");
        assert!(link_target(b"/etc/passwd").is_err());
    }

    #[test]
    fn link_pass_fallbacks() {
        let root = std::env::temp_dir().join(format!("xaea-linkpass-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("d")).unwrap();
        std::fs::write(root.join("d/occupied"), b"x").unwrap();
        std::fs::create_dir(root.join("d/isdir")).unwrap();
        let l = |p: &str, t: &str| (PathBuf::from(p).into_boxed_path(), Box::<str>::from(t));

        // Fast path, missing parent, and a file occupying the name.
        link_pass(
            &root,
            &[
                l("d/plain", "t1"),
                l("new/deeper/link", "t2"),
                l("d/occupied", "t3"),
            ],
            6,
        )
        .unwrap();
        for (p, t) in [
            ("d/plain", "t1"),
            ("new/deeper/link", "t2"),
            ("d/occupied", "t3"),
        ] {
            assert_eq!(std::fs::read_link(root.join(p)).unwrap(), Path::new(t));
        }

        // A real directory in the way is refused, not replaced.
        assert!(link_pass(&root, &[l("d/isdir", "t4")], 6).is_err());
        assert!(root.join("d/isdir").is_dir());

        // Traversing a symlink created earlier in the same pass is refused.
        assert!(link_pass(&root, &[l("x", "."), l("x/y", "t5")], 6).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Directory the parallel-path specs spread their links over.
    const SPEC_DIRS: usize = 400;

    /// A link list big enough for the parallel path, mixing every shape the
    /// pass has to handle: an existing parent (the common case, and what a
    /// real archive looks like), a missing parent (the `mkdir -p` fallback),
    /// a plain file occupying the link's name, unicode and space names.
    fn big_link_spec(n: usize) -> Vec<(PathBuf, String)> {
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            let dir = format!(
                "Payload/F/{:04}/N.framework/Versions/Current",
                i % SPEC_DIRS
            );
            let path = match i % 7 {
                0 | 1 | 5 | 6 => format!("{dir}/l{i}"),
                // parent never created: exercises the mkdir -p fallback
                2 => format!("deep/{:03}/missing/parent/l{i}", i % 50),
                3 => format!("{dir}/ünïcode l{i}"),
                _ => format!("{dir}/sp ace/l{i}"),
            };
            v.push((PathBuf::from(path), format!("../../tgt/{i}")));
        }
        // A regular file already sitting on this name: replaced, not refused.
        v.push((PathBuf::from("Payload/F/0000/occupied"), "t".into()));
        v
    }

    /// Snapshot a tree as sorted (relpath, kind, link-target) triples.
    fn snapshot(root: &Path) -> Vec<(String, char, String)> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, char, String)>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                let rel = p.strip_prefix(root).unwrap().display().to_string();
                let md = std::fs::symlink_metadata(&p).unwrap();
                if md.is_dir() {
                    out.push((rel.clone(), 'D', String::new()));
                    walk(root, &p, out);
                } else if md.is_symlink() {
                    let t = std::fs::read_link(&p).unwrap().display().to_string();
                    out.push((rel, 'L', t));
                } else {
                    out.push((rel, 'F', String::new()));
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    fn fresh_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "xaea-linkpass-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn spec_to_records(spec: &[(PathBuf, String)]) -> Vec<(Box<Path>, Box<str>)> {
        spec.iter()
            .map(|(p, t)| (p.clone().into_boxed_path(), Box::<str>::from(t.as_str())))
            .collect()
    }

    /// Pre-populate a root the way the data phase would: the framework dirs
    /// the links live in already exist (as they do in a real archive, where
    /// the pass is pure `symlink(2)` work), and one plain file occupies a
    /// name a later link record wants.
    fn seed_data_phase(root: &Path) {
        for d in 0..SPEC_DIRS {
            std::fs::create_dir_all(root.join(format!("Payload/F/{d:04}/N.framework/Versions")))
                .unwrap();
        }
        std::fs::write(root.join("Payload/F/0000/occupied"), b"occupant").unwrap();
    }

    #[test]
    fn parallel_link_pass_matches_sequential() {
        let spec = big_link_spec(LINK_PAR_MIN * 4);
        let recs = spec_to_records(&spec);
        assert!(
            links_are_independent(&recs),
            "the synthetic spec must exercise the parallel path"
        );
        let a = fresh_root("seq");
        let b = fresh_root("par");
        seed_data_phase(&a);
        seed_data_phase(&b);
        link_pass_seq(&a, &recs).unwrap();
        link_pass(&b, &recs, 8).unwrap();
        let (sa, sb) = (snapshot(&a), snapshot(&b));
        assert_eq!(sa.len(), sb.len());
        let diff: Vec<_> = sa.iter().zip(&sb).filter(|(x, y)| x != y).collect();
        assert!(diff.is_empty(), "trees differ: {diff:?}");
        assert_eq!(sb.iter().filter(|(_, k, _)| *k == 'L').count(), spec.len());
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn nested_links_fall_back_and_still_bail() {
        // Well over the parallel threshold, but one link is nested under
        // another: the guard must still fire, with the same message.
        let mut spec = big_link_spec(LINK_PAR_MIN * 2);
        spec.push((PathBuf::from("Payload/up"), ".".into()));
        spec.push((PathBuf::from("Payload/up/under"), "t".into()));
        let recs = spec_to_records(&spec);
        assert!(!links_are_independent(&recs));
        let root = fresh_root("nested");
        seed_data_phase(&root);
        let err = link_pass(&root, &recs, 8).unwrap_err().to_string();
        assert!(
            err.contains("traverses archive-created symlink"),
            "unexpected error: {err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn independence_test_details() {
        let l = |p: &str| (PathBuf::from(p).into_boxed_path(), Box::<str>::from("t"));
        let recs = |v: &[&str]| -> Vec<(Box<Path>, Box<str>)> { v.iter().map(|p| l(p)).collect() };
        // `a` is an ancestor of `a/b2`, so this list is *not* independent.
        assert!(!links_are_independent(&recs(&["a", "b", "a/b2"])));
        assert!(links_are_independent(&recs(&["a", "b", "c/d"])));
        // Siblings sharing a prefix string are not ancestors.
        assert!(links_are_independent(&recs(&["ab", "a"])));
        // Ancestor in either stream order disqualifies.
        assert!(!links_are_independent(&recs(&["a", "a/b"])));
        assert!(!links_are_independent(&recs(&["a/b", "a"])));
        // Case-insensitive volumes: `A` and `a/b` are the same directory.
        assert!(!links_are_independent(&recs(&["A", "a/b"])));
        assert!(!links_are_independent(&recs(&[
            "Payload/up",
            "payload/up/under"
        ])));
        // Duplicate names (last-writer-wins today) stay sequential.
        assert!(!links_are_independent(&recs(&["a", "A"])));
    }

    /// Regression: the guard compared a lowercased ancestor against a set of
    /// paths inserted *un*-lowercased, so a nested pair spelled with capitals
    /// (`Payload/up`, `Payload/up/under`) slipped through and the second link
    /// was created straight through the first.
    #[test]
    fn guard_is_case_insensitive() {
        for (parent, child) in [
            ("Payload/up", "Payload/up/under"),
            ("Payload/up", "payload/up/under"),
            ("payload/up", "Payload/up/under"),
        ] {
            let root = fresh_root("caseguard");
            let recs: Vec<(Box<Path>, Box<str>)> = [parent, child]
                .iter()
                .map(|p| (PathBuf::from(p).into_boxed_path(), Box::<str>::from("..")))
                .collect();
            let err = link_pass_seq(&root, &recs).unwrap_err().to_string();
            assert!(
                err.contains("traverses archive-created symlink"),
                "{parent} + {child}: {err}"
            );
            assert!(
                std::fs::symlink_metadata(root.join(child)).is_err(),
                "{child} must not exist"
            );
            std::fs::remove_dir_all(&root).unwrap();
        }
    }

    /// Repeatable scaling signal for the final pass. Ignored by default
    /// because it is a benchmark, not an assertion:
    /// `cargo test --release -- --ignored --nocapture link_pass_scaling`
    #[test]
    #[ignore]
    fn link_pass_scaling() {
        let spec = big_link_spec(12_000);
        let recs = spec_to_records(&spec);
        for workers in [1usize, 2, 4, 6, 8, 12, 16] {
            let root = fresh_root("scale");
            seed_data_phase(&root);
            let t = Instant::now();
            if workers == 1 {
                link_pass_seq(&root, &recs).unwrap();
            } else {
                link_pass(&root, &recs, workers).unwrap();
            }
            let dt = t.elapsed().as_secs_f64();
            println!(
                "  workers={workers:2}  {:7.1} ms  {:6.2} us/link",
                dt * 1000.0,
                dt / recs.len() as f64 * 1e6
            );
            std::fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn route_hash_deterministic_and_in_range() {
        let h = route_hash(b"some/dir", 6);
        assert!(h < 6);
        assert_eq!(h, route_hash(b"some/dir", 6));
        let mut spread = std::collections::HashSet::new();
        for i in 0..60 {
            spread.insert(route_hash(format!("dir/{i}").as_bytes(), 6));
        }
        assert!(spread.len() >= 5, "hash should spread across writers");
    }
}
