//! Subcommand implementations, and what they share.

pub mod cat;
pub mod decrypt;
pub mod extract;
pub mod inspect;

use crate::cli::KeyArgs;
use crate::envelope::{Envelope, NeedsKey, Prelude, WrongKey};
use crate::exit::{Exit, WithExit, bail_exit};
use crate::kdf::Key;
use crate::{spool, wkms};
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

/// The symmetric key `key` asks for, if any; every failure is [`Exit::Key`].
pub fn archive_key(key: &KeyArgs, prelude: &Prelude) -> Result<Option<Key>> {
    if let Some(k) = &key.key {
        return wkms::parse_key(k)
            .context("--key")
            .with_exit(Exit::Key)
            .map(Some);
    }
    let Some(pem) = &key.key_pem else {
        return Ok(None);
    };
    let pem = std::fs::read(pem)
        .with_context(|| format!("read --key-pem {}", pem.display()))
        .with_exit(Exit::Key)?;
    wkms::unwrap_key(&prelude.auth, &pem)
        .context("unwrap the archive key with --key-pem")
        .with_exit(Exit::Key)
        .map(Some)
}

/// Parse `file`'s envelope with the key `key` asks for. A missing or wrong
/// key is [`Exit::Key`]; any other parse failure is [`Exit::Rejected`].
pub fn parse_envelope<'a>(file: &'a [u8], key: &KeyArgs) -> Result<Envelope<'a>> {
    let prelude = Prelude::parse(file).with_exit(Exit::Rejected)?;
    let sym = archive_key(key, &prelude)?;
    if sym.is_some() && !prelude.profile.encrypted() {
        eprintln!("warning: archive is not encrypted; ignoring the key");
    }
    Envelope::parse(file, sym.as_ref()).map_err(|e| {
        let exit = if e.is::<NeedsKey>() || e.is::<WrongKey>() {
            Exit::Key
        } else {
            Exit::Rejected
        };
        crate::exit::classify(exit, e)
    })
}

/// Refuse an encrypted archive in the commands that read the payload as a
/// file archive: what restore images encrypt is a disk image.
pub fn refuse_disk_image(file: &[u8], cmd: &str) -> Result<()> {
    let prelude = Prelude::parse(file).with_exit(Exit::Rejected)?;
    if prelude.profile.encrypted() {
        bail_exit!(
            Exit::Rejected,
            "profile {} is encrypted: such archives (restore images) hold a disk image, not \
             a file tree, so `{cmd}` does not apply — use `xaea decrypt` to write the image",
            prelude.profile.id()
        );
    }
    Ok(())
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
