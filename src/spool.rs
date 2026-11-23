//! Archive input resolution: a real path passes straight through; the
//! conventional `-` means standard input.
//!
//! Stdin is spooled to a private temporary file and the existing
//! file-backed path then runs unchanged. That keeps every guarantee the
//! file path has: the archive is mmap'd (mmap needs a real fd and a known
//! length, neither of which a pipe offers), the root header's declared
//! `encarchive_size` is compared against the actual byte count (as a
//! warning), and — the hard one — the segment walk must land exactly on
//! end-of-file, which catches truncated or padded streams. A streaming
//! reader would have to defer that last check to end-of-stream and rework
//! the pread-based parallel segment reads; deliberately out of scope here.
//!
//! The spool holds untrusted bytes. `tempfile::NamedTempFile` creates it
//! with `O_CREAT|O_EXCL` and mode `0600` under a random name in
//! `std::env::temp_dir()` (which honours `TMPDIR`), and unlinks it on
//! drop — every exit path that runs destructors, including errors and
//! panic unwinding. A hard kill (SIGKILL) can leave one behind; nothing
//! in userspace can prevent that.

use anyhow::{Context, Result, bail};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// The resolved archive input: a path to open (real file, or the spool),
/// plus a short label for reports and error context.
pub struct Input {
    pub path: PathBuf,
    pub label: String,
    // Kept alive (and unlinked on drop) for as long as the archive work
    // runs: the extractor re-opens this path for its pread segment reads.
    _spool: Option<NamedTempFile>,
}

/// Resolve the archive path the user gave. `-` reads standard input into a
/// private spool file first; anything else is returned untouched.
pub fn resolve(path: &Path) -> Result<Input> {
    if path != Path::new("-") {
        return Ok(Input {
            path: path.to_path_buf(),
            label: path.display().to_string(),
            _spool: None,
        });
    }
    if std::io::stdin().is_terminal() {
        bail!("`-` reads the archive from standard input, but standard input is a terminal");
    }
    // A *named* temp file, not `tempfile()`: the extractor re-opens the
    // archive by path, so the spool needs a real path that outlives the
    // write. The prefix/suffix make it recognisable in lsof/df output
    // when debugging a spool that outlived a SIGKILL.
    let mut spool = tempfile::Builder::new()
        .prefix("xaea-")
        .suffix(".aea")
        .tempfile()
        .context("create private spool file in $TMPDIR (is TMPDIR writable?)")?;
    let path = spool.path().to_path_buf();
    let dir = path
        .parent()
        .map_or_else(std::env::temp_dir, Path::to_path_buf);
    let mut stdin = std::io::stdin().lock();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let k = stdin
            .read(&mut buf)
            .with_context(|| format!("read standard input (spooled {} so far)", human_k(total)))?;
        if k == 0 {
            break;
        }
        spool.write_all(&buf[..k]).map_err(|e| spool_err(e, &dir))?;
        total += k as u64;
    }
    if total == 0 {
        bail!("standard input is empty (pipe the archive in, e.g. `curl ... | xaea extract -`)");
    }
    Ok(Input {
        path,
        label: "stdin".into(),
        _spool: Some(spool),
    })
}

fn spool_err(e: std::io::Error, dir: &Path) -> anyhow::Error {
    if e.raw_os_error() == Some(libc::ENOSPC) {
        anyhow::Error::new(e).context(format!(
            "no space left on the volume holding {} while spooling stdin",
            dir.display()
        ))
    } else {
        anyhow::Error::new(e).context("spool standard input")
    }
}

fn human_k(n: u64) -> String {
    if n >= 1 << 30 {
        format!("{:.1} GiB", n as f64 / (1u64 << 30) as f64)
    } else if n >= 1 << 20 {
        format!("{:.1} MiB", n as f64 / (1u64 << 20) as f64)
    } else {
        format!("{n} B")
    }
}
