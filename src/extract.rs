//! Parallel extraction of the AA01 payload.
//!
//! Pipeline (M3): `D` decoder threads pread + LZMA-decode segments (out of
//! order) → bounded channel → this thread reorders to strict payload order
//! and runs the AA01 record parser → file-blob pieces are dispatched
//! zero-copy (Arc<[u8]> views) to `W` writer threads via per-writer
//! channels. Slices of one file always go to the same writer, preserving
//! per-file order; the parser holds each file's fd in an Arc so slices
//! `pwrite` at explicit offsets while the parser has already moved on.
//!
//! Memory is bounded by the two channel capacities: at most
//! (seg_queue + D) decoded buffers plus the pieces still queued by writers
//! (pieces share buffers with in-flight decoded segments) — a few hundred
//! MiB worst case.
//!
//! Status: on BSDs/macOS the tool answers `SIGINFO` (Ctrl-T) by printing a
//! one-line progress report, like `dd` and friends; on Linux, which has no
//! SIGINFO, the same report is available via `SIGUSR1`.

use crate::aa::{Piece, Record, Sink, Stream};
use crate::envelope::Envelope;
use anyhow::{Context, Result, bail, ensure};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
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
}

pub struct Opts {
    pub out: PathBuf,
    pub dry: bool,
    pub decoders: usize,
    pub writers: usize,
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

enum Work {
    Slice {
        f: Arc<File>,
        off: u64,
        piece: Piece,
    },
}

fn writer_loop(rx: Receiver<Work>) -> Result<()> {
    while let Ok(w) = rx.recv() {
        match w {
            Work::Slice { f, mut off, piece } => {
                let mut b = piece.bytes();
                while !b.is_empty() {
                    let n = f.write_at(b, off).context("pwrite")?;
                    ensure!(n > 0, "pwrite made no progress");
                    off += n as u64;
                    b = &b[n..];
                }
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------ parser sink

struct CurFile {
    f: Arc<File>,
    off: u64,
    expect: u64,
    written: u64,
    path: Vec<u8>,
    writer: usize,
}

struct DispatchSink {
    root: PathBuf,
    dry: bool,
    txs: Vec<SyncSender<Work>>,
    cur: Option<CurFile>,
    st: Stats,
    prog: Arc<Progress>,
    mkdir_parents_seen: HashSet<PathBuf>,
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
            // Arc<File> drops here; the fd actually closes once the last
            // queued slice referencing it has been written.
        }
        Ok(())
    }

    /// create_dir_all, skipping parents we already ensured this run.
    fn ensure_parent(&mut self, p: &Path) -> Result<()> {
        if self.mkdir_parents_seen.insert(p.to_path_buf()) {
            std::fs::create_dir_all(p)
                .with_context(|| format!("mkdir -p {}", p.display()))?;
        }
        Ok(())
    }
}

impl Sink for DispatchSink {
    fn record(&mut self, rec: &Record) -> Result<()> {
        self.close_cur()?;
        let rel = sanitize(&rec.path)
            .with_context(|| format!("record path {:?}", String::from_utf8_lossy(&rec.path)))?;
        let full = self.root.join(&rel);
        let mode = rec.mode & 0o7777;
        match rec.typ {
            b'D' => {
                if !self.dry {
                    std::fs::create_dir_all(&full)
                        .with_context(|| format!("mkdir {}", full.display()))?;
                    std::fs::set_permissions(&full, std::fs::Permissions::from_mode(mode))
                        .with_context(|| format!("chmod {}", full.display()))?;
                    self.mkdir_parents_seen.insert(full.clone());
                }
                self.st.dirs += 1;
            }
            b'L' => {
                let target = rec
                    .link
                    .as_ref()
                    .map(|l| link_target(l))
                    .context("link record without LNK")??;
                if !self.dry {
                    if let Some(p) = full.parent() {
                        self.ensure_parent(p)?;
                    }
                    match std::fs::remove_file(&full) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => Err(e).with_context(|| format!("replace {}", full.display()))?,
                    }
                    symlink(&target, &full)
                        .with_context(|| format!("symlink {} -> {}", full.display(), target))?;
                }
                self.st.links += 1;
            }
            b'F' => {
                let mut fd = None;
                if !self.dry {
                    if let Some(p) = full.parent() {
                        self.ensure_parent(p)?;
                    }
                    let f = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&full)
                        .with_context(|| format!("create {}", full.display()))?;
                    f.set_permissions(std::fs::Permissions::from_mode(mode))
                        .with_context(|| format!("fchmod {}", full.display()))?;
                    fd = Some(Arc::new(f));
                }
                let writer = self.st.files as usize % self.txs.len();
                self.cur = Some(CurFile {
                    f: fd.unwrap_or_else(|| Arc::clone(empty_marker())),
                    off: 0,
                    expect: rec.dat,
                    written: 0,
                    path: rec.path.clone(),
                    writer,
                });
                self.st.files += 1;
                self.prog.files.fetch_add(1, Relaxed);
            }
            t => bail!("unknown object type {:?} at {}", t as char, full.display()),
        }
        Ok(())
    }

    fn blob(&mut self, piece: Piece) -> Result<()> {
        let c = self.cur.as_mut().context("blob outside file record")?;
        let len = piece.len() as u64;
        c.off += len;
        c.written += len;
        self.st.bytes += len;
        self.prog.bytes_out.fetch_add(len, Relaxed);
        if !self.dry {
            let work = Work::Slice {
                f: c.f.clone(),
                off: c.off - len,
                piece,
            };
            self.txs[c.writer]
                .send(work)
                .context("writer channel closed (writer died?)")?;
        }
        Ok(())
    }
}

/// Placeholder fd used in dry runs (never written to).
fn empty_marker() -> &'static Arc<File> {
    use std::sync::OnceLock;
    static M: OnceLock<Arc<File>> = OnceLock::new();
    M.get_or_init(|| Arc::new(File::open("/dev/null").expect("/dev/null")))
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

fn read_pread(f: &File, off: u64, len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    let mut done = 0usize;
    while done < len {
        let n = f.read_at(&mut v[done..], off + done as u64)?;
        ensure!(n > 0, "unexpected EOF at offset {}", off + done as u64);
        done += n;
    }
    Ok(v)
}

/// Decode one segment (pread stored bytes; LZMA-decode to `orig`).
fn decode_segment(fh: &File, data_off: u64, comp: u32, orig: u32) -> Result<Arc<[u8]>> {
    if comp == orig {
        return Ok(Arc::from(
            read_pread(fh, data_off, comp as usize)?.into_boxed_slice(),
        ));
    }
    let raw = read_pread(fh, data_off, comp as usize)?;
    let mut out: Vec<u8> = Vec::with_capacity(orig as usize);
    xz2::read::XzDecoder::new(&raw[..])
        .read_to_end(&mut out)
        .context("xz decode")?;
    ensure!(
        out.len() as u32 == orig,
        "xz decoded size mismatch ({} vs {orig})",
        out.len()
    );
    Ok(Arc::from(out.into_boxed_slice()))
}

/// Decoder-side view of a segment (owned/Copy so threads can own it).
#[derive(Clone, Copy)]
struct SegInfo {
    off: u64,
    comp: u32,
    orig: u32,
}

pub fn extract(env: &Envelope, src: &Path, opts: &Opts) -> Result<Stats> {
    if !opts.dry {
        std::fs::create_dir_all(&opts.out)?;
    }
    let segs: Arc<Vec<SegInfo>> = Arc::new(
        env.segments()
            .iter()
            .map(|s| SegInfo { off: s.data_off as u64, comp: s.comp, orig: s.orig })
            .collect(),
    );
    let nseg = segs.len();
    let fh = Arc::new(File::open(src).with_context(|| format!("open {}", src.display()))?);
    let prog = Arc::new(Progress::new());
    install_status_signal();

    // Writers: per-writer ordered channels.
    let nw = opts.writers.max(1);
    let (wtx, wrx): (Vec<SyncSender<Work>>, Vec<Receiver<Work>>) =
        (0..nw).map(|_| sync_channel::<Work>(32)).unzip();
    let writers: Vec<_> = wrx
        .into_iter()
        .map(|rx| thread::spawn(move || writer_loop(rx)))
        .collect();

    // Decoders: pull segment indices, pread + decode, hand results over a
    // bounded channel (results carry errors so the parser can surface them).
    let nd = opts.decoders.max(1);
    let (dtx, drx) = sync_channel::<Result<(usize, Arc<[u8]>)>>(nd + 4);
    let next = Arc::new(AtomicUsize::new(0));
    let mut decoders = Vec::new();
    for _ in 0..nd {
        let (next, fh, segs, dtx) = (next.clone(), fh.clone(), segs.clone(), dtx.clone());
        decoders.push(thread::spawn(move || loop {
            let i = next.fetch_add(1, Relaxed);
            if i >= nseg {
                break;
            }
            let sg = &segs[i];
            let r = decode_segment(&fh, sg.off, sg.comp, sg.orig)
                .map(|b| (i, b))
                .with_context(|| format!("decode segment {i}"));
            if dtx.send(r).is_err() {
                break; // parser is gone (error path)
            }
        }));
    }
    drop(dtx);

    let mut sink = DispatchSink {
        root: opts.out.clone(),
        dry: opts.dry,
        txs: wtx,
        cur: None,
        st: Stats { dirs: 0, files: 0, links: 0, bytes: 0 },
        prog: prog.clone(),
        mkdir_parents_seen: HashSet::new(),
    };
    let mut stream = Stream::new(&mut sink);

    // Reorder decoded segments into strict payload order and parse.
    let mut pending: HashMap<usize, Arc<[u8]>> = HashMap::new();
    let mut expect = 0usize;
    while expect < nseg {
        let (i, buf) = drx.recv().context("decoder thread died")??;
        if i == expect {
            stream.feed(buf)?;
            expect += 1;
            while let Some(b) = pending.remove(&expect) {
                stream.feed(b)?;
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
    sink.close_cur()?;
    let st = Stats {
        dirs: sink.st.dirs,
        files: sink.st.files,
        links: sink.st.links,
        bytes: sink.st.bytes,
    };
    drop(sink); // closes writer channels; writers flush and exit

    let mut first_err: Option<anyhow::Error> = None;
    for h in writers {
        let r = h.join().map_err(|_| anyhow::anyhow!("writer thread panicked"))?;
        if r.is_err() && first_err.is_none() {
            first_err = r.err();
        }
    }
    for h in decoders {
        let _ = h.join();
    }
    maybe_print_status(&prog, nseg);
    end_status_line();
    match first_err {
        Some(e) => Err(e),
        None => Ok(st),
    }
}
