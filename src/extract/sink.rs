//! The parser's sink: turns AA01 records into writer work.

use super::links::Link;
use super::paths::{link_target, sanitize};
use super::status::Progress;
use super::writer::{Load, Work, least_loaded, work_cost};
use super::{Opts, Stats};
use crate::aa::{Piece, Record, Sink};
use crate::prof::{self, C};
use anyhow::{Context, Result, bail, ensure};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::Instant;

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

pub(super) struct DispatchSink {
    dry: bool,
    /// Output root, used to refuse top-level collisions with existing paths.
    root: PathBuf,
    /// Top-level names already checked (each is checked once, on first sight).
    seen_top: HashSet<OsString>,
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
    links: Vec<Link>,
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
    pub(super) fn new(
        opts: &Opts,
        compressed: bool,
        txs: Vec<SyncSender<Work>>,
        load: Option<Load>,
        prog: Arc<Progress>,
    ) -> Self {
        DispatchSink {
            dry: opts.dry,
            root: opts.out.clone(),
            seen_top: HashSet::new(),
            txs,
            cur: None,
            st: Stats {
                compressed,
                ..Stats::default()
            },
            prog,
            obj_seq: 0,
            load,
            prealloc: opts.prealloc,
            links: Vec::new(),
            dir_modes: Vec::new(),
        }
    }

    /// Final pass, on one writer, strictly after every stream-phase write
    /// has executed: a per-writer Flush barrier first (writer 0's queue
    /// alone proves nothing about the others), then symlinks (before any
    /// restrictive dir modes), then deferred directory modes other than
    /// `dir_default`.
    pub(super) fn final_pass(&mut self, dir_default: u32) -> Result<()> {
        if self.dry {
            return Ok(());
        }
        let t_flush = Instant::now();
        for w in 0..self.txs.len() {
            let (atx, arx) = sync_channel::<()>(1);
            self.send(w, Work::Flush(atx))?;
            arx.recv()
                .map_err(|_| anyhow::anyhow!("writer {w} died mid-flush"))?;
        }
        prof::add_since(C::WFlush, t_flush);
        let links = std::mem::take(&mut self.links);
        self.send(0, Work::LinkPass(links))?;
        let mut modes = std::mem::take(&mut self.dir_modes);
        modes.retain(|(_, m)| *m != dir_default);
        self.send(0, Work::DirModes(modes))
    }

    /// The totals; dropping the sink closes the writer channels.
    pub(super) fn into_stats(self) -> Stats {
        self.st
    }

    /// End the current file record, checking it got all its bytes.
    pub(super) fn close_cur(&mut self) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
