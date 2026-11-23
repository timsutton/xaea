//! Writer threads: they execute every filesystem syscall of the stream
//! phase, and the final link and directory-mode passes.

use super::links::{Link, link_pass};
use crate::aa::Piece;
use crate::decmpfs;
use crate::prof::{self, C, K};
use anyhow::{Context, Result, ensure};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, SyncSender};

/// Messages to a writer thread. All filesystem *syscalls* (mkdir, open,
/// chmod, symlink, pwrite) happen on writer threads so the
/// parser stays pure CPU + dispatch; per-writer channels are FIFO, so any
/// ordering a path needs is guaranteed by routing that path's messages to
/// one channel (files/links by round-robin sequence, directories by
/// content-hash of their path).
pub(super) enum Work {
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
    Flush(SyncSender<()>),
    /// Final pass, in stream order, single writer (see module docs). The
    /// writer may fan the creations out to scoped helpers; the ordering
    /// guarantee that matters is that the pass completes before the writer
    /// takes the `DirModes` message queued behind it.
    LinkPass(Vec<Link>),
    /// Final pass: directory modes, applied after every object exists.
    DirModes(Vec<(Box<Path>, u32)>),
}

/// Effective create defaults under the current umask; matching modes skip a
/// chmod/fchmod syscall (~137k of them across a full Xcode tree otherwise).
pub(super) fn create_defaults() -> (u32, u32) {
    // SAFETY: umask(2) cannot fail. Reading it means setting it, so it is
    // restored at once; nothing else in the process creates files yet.
    let mask = unsafe {
        let m = libc::umask(0);
        libc::umask(m);
        m
    };
    #[allow(
        clippy::useless_conversion,
        reason = "mode_t is u16 on macOS but already u32 on Linux"
    )]
    let mask = u32::from(mask);
    (0o666 & !mask, 0o777 & !mask)
}

#[cfg(target_os = "macos")]
fn preallocate(f: &File, size: u64) -> std::io::Result<()> {
    let st = libc::fstore_t {
        fst_flags: libc::F_ALLOCATEALL | libc::F_PEOFPOSMODE as u32,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: i64::try_from(size).unwrap_or(i64::MAX),
        fst_bytesalloc: 0,
    };
    // SAFETY: F_PREALLOCATE takes a pointer to an fstore_t, valid for the
    // duration of the call; `f` is an open fd.
    let r = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_PREALLOCATE, &raw const st) };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn preallocate(f: &File, size: u64) -> std::io::Result<()> {
    let len = libc::off_t::try_from(size).unwrap_or(libc::off_t::MAX);
    // SAFETY: plain syscall on an open fd.
    let r = unsafe { libc::posix_fallocate(f.as_raw_fd(), 0, len) };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(r))
    }
}

/// Subtracts a message's cost from its writer's [`Load`] when dropped.
struct Credit<'a>(&'a AtomicU64, u64);

impl Drop for Credit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(self.1, Relaxed);
    }
}

/// Queued work per writer, in bytes still to write plus [`OPEN_COST`] per
/// pending open. Lets the parser hand each new file to the least-loaded
/// writer instead of round-robin, which matters when writers also compress:
/// a writer encoding a large file would otherwise sit on a queue full of
/// small files while the parser blocks on it and the other writers idle.
pub(super) type Load = Arc<[AtomicU64]>;
/// What one open + close costs a writer, in bytes-of-work terms.
const OPEN_COST: u64 = 32 << 10;

pub(super) fn work_cost(w: &Work) -> u64 {
    match w {
        Work::Open { .. } => OPEN_COST,
        Work::Slice { piece, .. } => piece.len() as u64,
        _ => 0,
    }
}

/// Least-loaded writer, scanning from `start` so ties rotate.
pub(super) fn least_loaded(load: &[AtomicU64], start: usize) -> usize {
    let n = load.len();
    (0..n)
        .map(|k| (start + k) % n)
        .min_by_key(|&w| load[w].load(Relaxed))
        .unwrap_or(0)
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

/// One writer thread's state.
pub(super) struct Writer {
    root: PathBuf,
    /// Mode a new file gets from open(2) under the umask.
    file_default: u32,
    /// Scoped helpers the final link pass may fan out to.
    link_workers: usize,
    /// Open file being written; closed when the next Open, a Flush, or the
    /// channel end arrives.
    cur: Option<OpenFile>,
    /// Set when this run stores files compressed.
    enc: Option<decmpfs::Encoder>,
    /// Files the volume refused to store compressed (written plain).
    refused: u64,
    /// The shared load table and this writer's slot in it, when the
    /// parser balances by load.
    load: Option<(Load, usize)>,
}

impl Writer {
    pub(super) fn new(
        root: PathBuf,
        file_default: u32,
        compress: bool,
        link_workers: usize,
        load: Option<(Load, usize)>,
    ) -> Self {
        Writer {
            root,
            file_default,
            link_workers,
            cur: None,
            enc: compress.then(decmpfs::Encoder::new),
            refused: 0,
            load,
        }
    }

    /// Execute work until the channel closes. Returns how many files the
    /// volume refused to store compressed.
    pub(super) fn run(mut self, rx: &Receiver<Work>) -> Result<u64> {
        let load = self.load.take();
        while let Ok(w) = prof::time(C::WRecv, || rx.recv()) {
            // Credited back once the message is handled (on error the whole
            // extraction is failing anyway).
            let _done = load.as_ref().map(|(l, i)| Credit(&l[*i], work_cost(&w)));
            self.handle(w)?;
        }
        self.close_file()?;
        Ok(self.refused)
    }

    fn handle(&mut self, w: Work) -> Result<()> {
        match w {
            Work::Mkdir { path } => {
                let full = self.root.join(path);
                // One mkdir(2) in the common case. create_dir_all would also
                // do just that when it succeeds, but it is the fallback for
                // the rare cases (parent not created yet, or a file writer
                // already made this dir on demand: EEXIST + stat).
                prof::time(C::WMkdir, || {
                    if std::fs::create_dir(&full).is_err() {
                        std::fs::create_dir_all(&full)
                            .with_context(|| format!("mkdir {}", full.display()))?;
                    }
                    Ok(())
                })
            }
            Work::Flush(ack) => {
                self.close_file()?; // finish the open file before acknowledging
                let _ = ack.send(());
                Ok(())
            }
            Work::LinkPass(links) => prof::time(C::WLink, || {
                link_pass(&self.root, &links, self.link_workers)
            }),
            Work::DirModes(modes) => prof::time(C::WDirmode, || {
                for (path, mode) in modes {
                    let full = self.root.join(path);
                    std::fs::set_permissions(&full, std::fs::Permissions::from_mode(mode))
                        .with_context(|| format!("chmod {}", full.display()))?;
                }
                Ok(())
            }),
            Work::Open {
                seq,
                path,
                mode,
                size,
            } => self.open(seq, &path, mode, size),
            Work::Slice {
                seq,
                off,
                piece,
                prealloc,
            } => self.slice(seq, off, &piece, prealloc),
        }
    }

    fn open(&mut self, seq: u64, path: &Path, mode: u32, size: u64) -> Result<()> {
        self.close_file()?;
        prof::count(K::Opens, 1);
        let full = self.root.join(path);
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(p) = full.parent() {
                    prof::time(C::WMkp, || std::fs::create_dir_all(p))
                        .with_context(|| format!("mkdir -p {}", p.display()))?;
                }
                prof::time(C::WOpen, || open(&full))
            }
            r => r,
        }
        .with_context(|| format!("create {}", full.display()))?;
        // Empty files stay plain, as Apple's extractor leaves them.
        let compressing = size > 0 && self.enc.is_some();
        // Skip fchmod when open(2) already produced the mode via the
        // umask default — see create_defaults() for the rationale.
        let chmod = (mode != self.file_default).then_some(mode);
        if !compressing && let Some(mode) = chmod {
            prof::time(C::WFchmod, || {
                f.set_permissions(std::fs::Permissions::from_mode(mode))
            })
            .with_context(|| format!("fchmod {}", full.display()))?;
        }
        if compressing && let Some(e) = self.enc.as_mut() {
            e.begin(size);
        }
        self.cur = Some(OpenFile {
            seq,
            f,
            compressing,
            chmod: chmod.filter(|_| compressing),
            path: full,
        });
        Ok(())
    }

    fn slice(&mut self, seq: u64, mut off: u64, piece: &Piece, prealloc: u64) -> Result<()> {
        let o = self.cur.as_mut().context("slice for file not opened")?;
        ensure!(
            o.seq == seq,
            "slice seq {seq} but writer is on file {}",
            o.seq
        );
        let f = &o.f;
        if o.compressing {
            let e = self
                .enc
                .as_mut()
                .context("compressing without an encoder")?;
            let keep = prof::time(C::WCompress, || e.push(piece.bytes()))
                .with_context(|| format!("compress {}", o.path.display()))?;
            if !keep {
                // Not worth it: write what was encoded so far back
                // out plainly and send the rest straight to disk.
                prof::time(C::WStore, || e.spill(f))
                    .with_context(|| format!("write {}", o.path.display()))?;
                o.compressing = false;
            }
            return Ok(());
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
        Ok(())
    }

    /// Close the current file, storing it compressed first if that is how
    /// it was being written.
    fn close_file(&mut self) -> Result<()> {
        let Some(o) = self.cur.take() else {
            return Ok(());
        };
        if o.compressing {
            let e = self
                .enc
                .as_mut()
                .context("compressing without an encoder")?;
            let outcome = prof::time(C::WStore, || e.finish(&o.f))
                .with_context(|| format!("store compressed {}", o.path.display()))?;
            if outcome == decmpfs::Outcome::Refused {
                self.refused += 1;
            }
        }
        if let Some(mode) = o.chmod {
            prof::time(C::WFchmod, || {
                o.f.set_permissions(std::fs::Permissions::from_mode(mode))
            })
            .with_context(|| format!("fchmod {}", o.path.display()))?;
        }
        prof::time(C::WClose, || drop(o));
        Ok(())
    }
}
