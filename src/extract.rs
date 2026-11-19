//! Parallel extraction of the AA01 payload.
//!
//! Pipeline: `D` decoder threads pread + LZMA-decode segments (out of
//! order) → bounded channel → this thread reorders to strict payload order
//! and runs the AA01 record parser → work items (mkdir / symlink / open /
//! blob slices) are dispatched to `W` writer threads via per-writer
//! channels. ALL filesystem syscalls execute on writers: the parser is pure
//! CPU + dispatch (instrumentation showed parser-issued syscalls were the
//! wall-clock bottleneck, not write throughput). Ordering rules:
//!
//! * files/links pick a writer by round-robin sequence — their Open/Mklnk
//!   and all blob slices share that one FIFO channel;
//! * directories hash-route by path, and file/link parents are additionally
//!   created on demand (`create_dir_all`, stat-fast when present), so no
//!   cross-channel ordering assumption is ever made;
//! * blob pieces are zero-copy Arc<[u8]> views of decoded segment buffers,
//!   `pwrite`d at explicit offsets.
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
use anyhow::{bail, ensure, Context, Result};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{symlink, FileExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
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
    /// Reserve each file's full length (fcntl/posix_fallocate) before the
    /// first write so APFS doesn't grow extents mid-blob.
    pub prealloc: bool,
    /// Tag created objects with com.apple.quarantine (macOS only).
    pub quarantine: bool,
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

/// macOS Gatekeeper quarantine tag; no-op elsewhere (callers gate the flag).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn set_quarantine(path: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let v = format!("{:04X};{:08X};unaea;", 0x0001, t);
    let r = unsafe {
        libc::setxattr(
            path.as_os_str().as_bytes().as_ptr() as *const libc::c_char,
            c"com.apple.quarantine".as_ptr(),
            v.as_ptr() as *const libc::c_void,
            v.len(),
            0,
            0,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn set_quarantine(_path: &Path) -> std::io::Result<()> {
    Ok(())
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
/// chmod, symlink, quarantine, pwrite) happen on writer threads so the
/// parser stays pure CPU + dispatch; per-writer channels are FIFO, so any
/// ordering a path needs is guaranteed by routing that path's messages to
/// one channel (files/links by round-robin sequence, directories by
/// content-hash of their path).
enum Work {
    Mkdir {
        path: Box<Path>,
        mode: u32,
    },
    Mklnk {
        path: Box<Path>,
        target: Box<str>,
    },
    Open {
        seq: u64,
        path: Box<Path>,
        mode: u32,
    },
    Slice {
        seq: u64,
        off: u64,
        piece: Piece,
        prealloc: u64,
    },
}

fn writer_loop(
    rx: Receiver<Work>,
    root: PathBuf,
    file_default: u32,
    dir_default: u32,
    quarantine: bool,
) -> Result<()> {
    // Open file being written; closed implicitly when the next Open (or the
    // channel end) replaces/drops it.
    let mut cur: Option<(u64, File)> = None;
    while let Ok(w) = rx.recv() {
        match w {
            Work::Mkdir { path, mode } => {
                let full = root.join(path);
                std::fs::create_dir_all(&full)
                    .with_context(|| format!("mkdir {}", full.display()))?;
                if mode != dir_default {
                    std::fs::set_permissions(&full, std::fs::Permissions::from_mode(mode))
                        .with_context(|| format!("chmod {}", full.display()))?;
                }
                if quarantine {
                    let _ = set_quarantine(&full);
                }
            }
            Work::Mklnk { path, target } => {
                let full = root.join(path);
                if let Some(p) = full.parent() {
                    std::fs::create_dir_all(p)?;
                }
                match std::fs::remove_file(&full) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => Err(e).with_context(|| format!("replace {}", full.display()))?,
                }
                symlink(target.as_ref(), &full)
                    .with_context(|| format!("symlink {} -> {}", full.display(), target))?;
                if quarantine {
                    let _ = set_quarantine(&full);
                }
            }
            Work::Open { seq, path, mode } => {
                let full = root.join(path);
                // Always ensure the parent: a sibling writer may own its
                // mkdir and not have run it yet; create_dir_all is a cheap
                // stat when the dir exists, and EEXIST races are tolerated.
                if let Some(p) = full.parent() {
                    std::fs::create_dir_all(p)
                        .with_context(|| format!("mkdir -p {}", p.display()))?;
                }
                let f = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&full)
                    .with_context(|| format!("create {}", full.display()))?;
                // Skip fchmod when open(2) already produced the mode via the
                // umask default — see create_defaults() for the rationale.
                if mode != file_default {
                    f.set_permissions(std::fs::Permissions::from_mode(mode))
                        .with_context(|| format!("fchmod {}", full.display()))?;
                }
                if quarantine {
                    let _ = set_quarantine(&full);
                }
                cur = Some((seq, f));
            }
            Work::Slice {
                seq,
                mut off,
                piece,
                prealloc,
            } => {
                let (cseq, f) = cur.as_mut().context("slice for file not opened")?;
                ensure!(*cseq == seq, "slice seq {seq} but writer is on file {cseq}");
                if prealloc > 0 {
                    // Allocation failure isn't fatal — writes still work.
                    let _ = preallocate(f, prealloc);
                }
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
    txs: Vec<SyncSender<Work>>,
    cur: Option<Cur>,
    st: Stats,
    prog: Arc<Progress>,
    /// Files + links share this round-robin counter for writer selection.
    obj_seq: u64,
    prealloc: bool,
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

    fn send(&self, w: usize, work: Work) -> Result<()> {
        self.txs[w]
            .send(work)
            .context("writer channel closed (writer died?)")
    }
}

impl Sink for DispatchSink {
    fn record(&mut self, rec: &Record) -> Result<()> {
        self.close_cur()?;
        let rel = sanitize(&rec.path)
            .with_context(|| format!("record path {:?}", String::from_utf8_lossy(&rec.path)))?
            .into_boxed_path();
        let mode = rec.mode & 0o7777;
        let nw = self.txs.len();
        match rec.typ {
            b'D' => {
                if !self.dry {
                    self.send(route_hash(&rec.path, nw), Work::Mkdir { path: rel, mode })?;
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
                    let w = self.obj_seq as usize % nw;
                    self.send(
                        w,
                        Work::Mklnk {
                            path: rel,
                            target: target.into_boxed_str(),
                        },
                    )?;
                }
                self.st.links += 1;
            }
            b'F' => {
                self.obj_seq += 1;
                let seq = self.obj_seq;
                let w = seq as usize % nw;
                if !self.dry {
                    self.send(
                        w,
                        Work::Open {
                            seq,
                            path: rel,
                            mode,
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
            .map(|s| SegInfo {
                off: s.data_off as u64,
                comp: s.comp,
                orig: s.orig,
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
    let (wtx, wrx): (Vec<SyncSender<Work>>, Vec<Receiver<Work>>) =
        (0..nw).map(|_| sync_channel::<Work>(32)).unzip();
    let writers: Vec<_> = wrx
        .into_iter()
        .map(|rx| {
            let (root, q) = (opts.out.clone(), opts.quarantine);
            thread::spawn(move || writer_loop(rx, root, file_default, dir_default, q))
        })
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
        dry: opts.dry,
        txs: wtx,
        cur: None,
        st: Stats {
            dirs: 0,
            files: 0,
            links: 0,
            bytes: 0,
        },
        prog: prog.clone(),
        obj_seq: 0,
        prealloc: opts.prealloc,
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
    let parser_done = prog.started.elapsed().as_secs_f64();
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
    if std::env::var_os("UNAEA_STATS").is_some() {
        let total = prog.started.elapsed().as_secs_f64();
        eprintln!(
            "[stats] parse+dispatch done at {parser_done:.1}s; writer drain +{:.1}s; total {total:.1}s",
            total - parser_done
        );
    }
    maybe_print_status(&prog, nseg);
    end_status_line();
    match first_err {
        Some(e) => Err(e),
        None => Ok(st),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
