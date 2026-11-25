//! Subcommand implementations, and what they share.

pub mod cat;
pub mod decrypt;
pub mod extract;
pub mod inspect;

use crate::cli::KeyArgs;
use crate::envelope::{Envelope, NeedsKey, Prelude, WrongKey};
use crate::exit::{Exit, WithExit, bail_exit, classify};
use crate::ipsw::Listing;
use crate::kdf::Key;
use crate::net::{self, NetError, Remote};
use crate::zip::{self, ReadAt};
use crate::{spool, wkms};
use anyhow::{Context, Result};
use memmap2::Mmap;
use std::fmt::Write as _;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

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

/// What a command reads: a local archive or IPSW (mapped), or a remote one.
pub enum Input {
    Local(OpenArchive),
    Remote(Arc<Remote>),
}

impl Input {
    /// Open `path`, a local path (or `-`) or an `http(s)` URL. Every
    /// failure here is [`Exit::Unreadable`] (or [`Exit::Usage`] for a URL
    /// with `--offline`).
    pub fn open(path: &str, offline: bool) -> Result<Self> {
        if !net::is_url(path) {
            return open_archive(Path::new(path)).map(Input::Local);
        }
        if offline {
            bail_exit!(
                Exit::Usage,
                "--offline: not reading {path} from the network"
            );
        }
        Remote::open(path)
            .with_exit(Exit::Unreadable)
            .map(|r| Input::Remote(Arc::new(r)))
    }

    pub fn label(&self) -> String {
        match self {
            Input::Local(a) => a.src.label.clone(),
            Input::Remote(r) => {
                let path = r.url.split(['?', '#']).next().unwrap_or(&r.url);
                path.rsplit('/').next().unwrap_or(path).to_owned()
            }
        }
    }

    pub fn len(&self) -> u64 {
        self.read_at().len()
    }

    pub fn read_at(&self) -> &dyn ReadAt {
        match self {
            Input::Local(a) => &a.map,
            Input::Remote(r) => &**r,
        }
    }

    /// Whether the input is a zip (an IPSW) rather than an archive.
    pub fn is_zip(&self) -> Result<bool> {
        if self.len() < 4 {
            return Ok(false);
        }
        let magic = self.read_at().read_at(0, 4).with_exit(Exit::Unreadable)?;
        Ok(zip::is_zip(&magic))
    }
}

/// Classify a failure reading an input's structure: a failed download is
/// [`Exit::Unreadable`], anything else [`Exit::Rejected`].
pub fn input_exit(e: anyhow::Error) -> anyhow::Error {
    if e.chain().any(<dyn std::error::Error>::is::<NetError>) {
        classify(Exit::Unreadable, e)
    } else {
        classify(Exit::Rejected, e)
    }
}

/// An IPSW's disk images, one per line, for people.
pub fn image_listing(label: &str, l: &Listing) -> String {
    let mut s = format!("{label}  —  IPSW");
    if let (Some(v), Some(b)) = (&l.product_version, &l.build) {
        let _ = write!(s, ", {v} ({b})");
    }
    if !l.devices.is_empty() {
        let _ = write!(s, " for {}", l.devices.join(", "));
    }
    s.push('\n');
    let w = l
        .images
        .iter()
        .map(|i| i.roles.join(", ").len())
        .chain([4])
        .max()
        .unwrap_or(4);
    let _ = writeln!(s, "  {:w$}  {:<24} {:>10}", "ROLE", "MEMBER", "SIZE");
    for i in &l.images {
        let roles = if i.roles.is_empty() {
            "-".to_owned()
        } else {
            i.roles.join(", ")
        };
        let _ = writeln!(
            s,
            "  {roles:w$}  {:<24} {:>10}  {}",
            i.entry.name,
            human(i.entry.size),
            if i.encrypted() { "encrypted" } else { "plain" }
        );
    }
    s
}

/// The symmetric key `key` asks for, if any: `--key`, `--key-pem`, or by
/// default for an encrypted archive, the PEM fetched from the URL the
/// archive names. Every failure is [`Exit::Key`].
pub fn archive_key(key: &KeyArgs, prelude: &Prelude) -> Result<Option<Key>> {
    if let Some(k) = &key.key {
        return wkms::parse_key(k)
            .context("--key")
            .with_exit(Exit::Key)
            .map(Some);
    }
    if let Some(pem) = &key.key_pem {
        let pem = std::fs::read(pem)
            .with_context(|| format!("read --key-pem {}", pem.display()))
            .with_exit(Exit::Key)?;
        return wkms::unwrap_key(&prelude.auth, &pem)
            .context("unwrap the archive key with --key-pem")
            .with_exit(Exit::Key)
            .map(Some);
    }
    if !prelude.profile.encrypted() || key.offline {
        return Ok(None);
    }
    let Some(url) = wkms::key_url(&prelude.auth) else {
        return Ok(None);
    };
    eprintln!("fetching the archive key from {url}");
    let pem = net::fetch_key_pem(url)
        .context("fetch the archive's key (pass --key or --key-pem to supply it instead)")
        .with_exit(Exit::Key)?;
    wkms::unwrap_key(&prelude.auth, &pem)
        .context("unwrap the archive key with the PEM from its key URL")
        .with_exit(Exit::Key)
        .map(Some)
}

/// A missing or wrong key is [`Exit::Key`]; any other failure to parse an
/// envelope [`Exit::Rejected`].
pub fn classify_key_error(e: anyhow::Error) -> anyhow::Error {
    let exit = if e.is::<NeedsKey>() || e.is::<WrongKey>() {
        Exit::Key
    } else {
        Exit::Rejected
    };
    classify(exit, e)
}

/// Parse `file`'s envelope with the key `key` asks for. A missing or wrong
/// key is [`Exit::Key`]; any other parse failure is [`Exit::Rejected`].
pub fn parse_envelope<'a>(file: &'a [u8], key: &KeyArgs) -> Result<Envelope<'a>> {
    let prelude = Prelude::parse(file).with_exit(Exit::Rejected)?;
    let sym = archive_key(key, &prelude)?;
    if sym.is_some() && !prelude.profile.encrypted() {
        eprintln!("warning: archive is not encrypted; ignoring the key");
    }
    Envelope::parse(file, sym.as_ref()).map_err(classify_key_error)
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
