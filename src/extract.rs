//! Single-threaded extraction of the AA01 payload (M2: correctness first;
//! parallel decode/decode-pipelined writers land in M3).

use crate::aa::{Record, Sink, Stream};
use crate::envelope::{decode_xz, Envelope};
use anyhow::{bail, ensure, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub struct Stats {
    pub dirs: u64,
    pub files: u64,
    pub links: u64,
    pub bytes: u64,
}

struct ExtractSink {
    root: PathBuf,
    cur: Option<(File, u64, Vec<u8>)>, // open file, expected len, path (for errors)
    written: u64,
    st: Stats,
}

impl ExtractSink {
    fn close_cur(&mut self) -> Result<()> {
        if let Some((mut f, expect, path)) = self.cur.take() {
            f.flush()?;
            let got = f.metadata()?.len();
            ensure!(
                got == expect,
                "short blob for {}: wrote {got} of {expect} bytes",
                String::from_utf8_lossy(&path)
            );
        }
        Ok(())
    }
}

impl Sink for ExtractSink {
    fn record(&mut self, rec: &Record) -> Result<()> {
        self.close_cur()?;
        let rel = sanitize(&rec.path)
            .with_context(|| format!("record path {:?}", String::from_utf8_lossy(&rec.path)))?;
        let full = self.root.join(&rel);
        let mode = rec.mode & 0o7777;
        match rec.typ {
            b'D' => {
                std::fs::create_dir_all(&full)
                    .with_context(|| format!("mkdir {}", full.display()))?;
                std::fs::set_permissions(&full, std::fs::Permissions::from_mode(mode))
                    .with_context(|| format!("chmod {}", full.display()))?;
                self.st.dirs += 1;
            }
            b'L' => {
                let target = rec
                    .link
                    .as_ref()
                    .map(|l| link_target(l))
                    .context("link record without LNK")??;
                if let Some(p) = full.parent() {
                    std::fs::create_dir_all(p)?;
                }
                match std::fs::remove_file(&full) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => Err(e).with_context(|| format!("replace {}", full.display()))?,
                }
                symlink(&target, &full)
                    .with_context(|| format!("symlink {} -> {}", full.display(), target))?;
                self.st.links += 1;
            }
            b'F' => {
                if let Some(p) = full.parent() {
                    std::fs::create_dir_all(p)?;
                }
                let f = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&full)
                    .with_context(|| format!("create {}", full.display()))?;
                f.set_permissions(std::fs::Permissions::from_mode(mode))
                    .with_context(|| format!("fchmod {}", full.display()))?;
                self.cur = Some((f, rec.dat, rec.path.clone()));
                self.st.files += 1;
            }
            t => bail!("unknown object type {:?} at {}", t as char, full.display()),
        }
        Ok(())
    }

    fn blob(&mut self, bytes: &[u8]) -> Result<()> {
        let (f, _, path) = self.cur.as_mut().context("blob outside file record")?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", String::from_utf8_lossy(path)))?;
        self.written += bytes.len() as u64;
        self.st.bytes += bytes.len() as u64;
        Ok(())
    }
}

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
                if !out.pop() {
                    // already at root; clamp
                }
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

pub fn extract(env: &Envelope, out: &Path) -> Result<Stats> {
    std::fs::create_dir_all(out)?;
    let mut sink = ExtractSink {
        root: out.to_path_buf(),
        cur: None,
        written: 0,
        st: Stats {
            dirs: 0,
            files: 0,
            links: 0,
            bytes: 0,
        },
    };
    let mut decoded = Vec::new();
    {
        let mut stream = Stream::new(&mut sink);
        for seg in env.segments() {
            if seg.comp == seg.orig {
                stream.feed(seg.data)?; // stored uncompressed
            } else {
                decoded.clear();
                decoded.extend_from_slice(
                    &decode_xz(seg.data)
                        .with_context(|| format!("segment {} xz decode", seg.index))?,
                );
                ensure!(
                    decoded.len() as u32 == seg.orig,
                    "segment {} decoded to {} bytes, header says {}",
                    seg.index,
                    decoded.len(),
                    seg.orig
                );
                stream.feed(&decoded)?;
            }
        }
        stream.finish()?;
    }
    sink.close_cur()?;
    Ok(sink.st)
}
