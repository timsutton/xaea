//! Subcommand implementations, and what they share.

pub mod cat;
pub mod decrypt;
pub mod extract;
pub mod inspect;

use crate::exit::{Exit, WithExit};
use crate::spool;
use anyhow::{Context, Result};
use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

/// An archive opened for parsing: the resolved input and its mapping.
pub struct OpenArchive {
    /// Must outlive every use of the archive: for `-` it owns the spool
    /// file (unlinked on drop), which the extractor re-opens by path.
    pub src: spool::Input,
    pub map: Mmap,
}

/// Resolve `path` (spooling stdin for `-`) and map it read-only. Every
/// failure here is [`Exit::Unreadable`].
pub fn open_archive(path: &Path) -> Result<OpenArchive> {
    let src = spool::resolve(path).with_exit(Exit::Unreadable)?;
    let file = File::open(&src.path)
        .with_context(|| format!("open {}", src.label))
        .with_exit(Exit::Unreadable)?;
    // SAFETY: the mapping is only ever read. Another process truncating
    // or rewriting the archive while we read it is outside our model, as
    // for any mmap-based reader; at worst that raises SIGBUS.
    let map = unsafe { Mmap::map(&file) }
        .context("mmap")
        .with_exit(Exit::Unreadable)?;
    Ok(OpenArchive { src, map })
}

/// `n` bytes in binary units with two decimals, e.g. `9.71 GiB`.
pub fn human(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.2} {}", UNITS[i])
}
