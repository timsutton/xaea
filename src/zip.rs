//! Just enough of the zip format to find an IPSW's members and read them
//! in place: the central directory (with zip64), stored and DEFLATE
//! members. IPSWs store their `.dmg.aea` members uncompressed, so an
//! archive inside one is a plain byte range of the IPSW.

use anyhow::{Context, Result, bail, ensure};
use std::borrow::Cow;
use std::io::Read;

/// Random access to a file, local or remote.
pub trait ReadAt {
    fn len(&self) -> u64;
    fn read_at(&self, off: u64, len: usize) -> Result<Cow<'_, [u8]>>;
}

impl ReadAt for [u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }
    fn read_at(&self, off: u64, len: usize) -> Result<Cow<'_, [u8]>> {
        let a = usize::try_from(off)
            .ok()
            .filter(|&a| a <= <[u8]>::len(self));
        a.and_then(|a| self.get(a..a.checked_add(len)?))
            .map(Cow::Borrowed)
            .context("zip: read past the end of the file")
    }
}

impl ReadAt for memmap2::Mmap {
    fn len(&self) -> u64 {
        self[..].len() as u64
    }
    fn read_at(&self, off: u64, len: usize) -> Result<Cow<'_, [u8]>> {
        self[..].read_at(off, len)
    }
}

impl ReadAt for crate::net::Remote {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_at(&self, off: u64, len: usize) -> Result<Cow<'_, [u8]>> {
        crate::net::Remote::read_at(self, off, len).map(Cow::Owned)
    }
}

pub const STORED: u16 = 0;
pub const DEFLATE: u16 = 8;

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub method: u16,
    pub compressed: u64,
    pub size: u64,
    local_off: u64,
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// Whether `b` starts like a zip file.
pub fn is_zip(b: &[u8]) -> bool {
    b.starts_with(b"PK\x03\x04")
}

/// The central directory's entries.
pub fn entries(src: &(impl ReadAt + ?Sized)) -> Result<Vec<Entry>> {
    const EOCD: &[u8] = b"PK\x05\x06";
    let len = src.len();
    let tail_len = len.min(22 + 0xFFFF);
    let tail = src.read_at(len - tail_len, tail_len as usize)?;
    let at = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| &tail[i..i + 4] == EOCD)
        .context("not a zip file (no end of central directory)")?;
    let e = &tail[at..];
    let (mut count, mut cd_len, mut cd_off) = (
        u64::from(u16le(e, 10)),
        u64::from(u32le(e, 12)),
        u64::from(u32le(e, 16)),
    );
    if count == 0xFFFF || cd_len == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF {
        // zip64: a locator just before the EOCD points at the zip64 EOCD.
        ensure!(
            at >= 20 && &tail[at - 20..at - 16] == b"PK\x06\x07",
            "zip64 locator missing"
        );
        let e64_off = u64le(&tail, at - 20 + 8);
        let e64 = src.read_at(e64_off, 56)?;
        ensure!(
            &e64[..4] == b"PK\x06\x06",
            "bad zip64 end of central directory"
        );
        (count, cd_len, cd_off) = (u64le(&e64, 32), u64le(&e64, 40), u64le(&e64, 48));
    }
    ensure!(
        cd_off.checked_add(cd_len).is_some_and(|end| end <= len) && cd_len < 1 << 30,
        "zip central directory out of bounds"
    );
    let cd = src.read_at(cd_off, cd_len as usize)?;
    let mut out = Vec::with_capacity(count.min(1 << 16) as usize);
    let mut p = 0usize;
    for _ in 0..count {
        ensure!(
            p + 46 <= cd.len() && &cd[p..p + 4] == b"PK\x01\x02",
            "bad zip central directory entry"
        );
        let method = u16le(&cd, p + 10);
        let mut compressed = u64::from(u32le(&cd, p + 20));
        let mut size = u64::from(u32le(&cd, p + 24));
        let (nlen, xlen, clen) = (
            usize::from(u16le(&cd, p + 28)),
            usize::from(u16le(&cd, p + 30)),
            usize::from(u16le(&cd, p + 32)),
        );
        let mut local_off = u64::from(u32le(&cd, p + 42));
        let end = p + 46 + nlen + xlen + clen;
        ensure!(
            end <= cd.len(),
            "zip central directory entry runs past its end"
        );
        let name = String::from_utf8_lossy(&cd[p + 46..p + 46 + nlen]).into_owned();
        // zip64 extra field: the 0xFFFFFFFF fields, in this order.
        let mut x = &cd[p + 46 + nlen..p + 46 + nlen + xlen];
        while x.len() >= 4 {
            let (id, n) = (u16le(x, 0), usize::from(u16le(x, 2)));
            let body = x.get(4..4 + n).context("bad zip extra field")?;
            if id == 1 {
                let mut f = body
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|c| u64::from_le_bytes(*c));
                for v in [&mut size, &mut compressed, &mut local_off] {
                    if *v == 0xFFFF_FFFF {
                        *v = f.next().context("short zip64 extra field")?;
                    }
                }
            }
            x = &x[4 + n..];
        }
        out.push(Entry {
            name,
            method,
            compressed,
            size,
            local_off,
        });
        p = end;
    }
    Ok(out)
}

/// Where `e`'s stored bytes start (past its local header).
pub fn data_offset(src: &(impl ReadAt + ?Sized), e: &Entry) -> Result<u64> {
    let h = src.read_at(e.local_off, 30)?;
    ensure!(
        &h[..4] == b"PK\x03\x04",
        "bad zip local header for {}",
        e.name
    );
    let off = e.local_off + 30 + u64::from(u16le(&h, 26)) + u64::from(u16le(&h, 28));
    ensure!(
        off.checked_add(e.compressed)
            .is_some_and(|end| end <= src.len()),
        "zip member {} runs past the end of the file",
        e.name
    );
    Ok(off)
}

/// A small member's contents (stored or DEFLATE), at most `limit` bytes.
pub fn read(src: &(impl ReadAt + ?Sized), e: &Entry, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        e.size <= limit,
        "zip member {} is too large to read ({} bytes)",
        e.name,
        e.size
    );
    let raw = src.read_at(data_offset(src, e)?, e.compressed as usize)?;
    let out = match e.method {
        STORED => raw.into_owned(),
        DEFLATE => {
            let mut out = Vec::with_capacity(e.size as usize);
            flate2::read::DeflateDecoder::new(&raw[..])
                .take(limit + 1)
                .read_to_end(&mut out)
                .with_context(|| format!("inflate {}", e.name))?;
            out
        }
        m => bail!("zip member {} uses compression method {m}", e.name),
    };
    ensure!(
        out.len() as u64 == e.size,
        "zip member {} has the wrong size",
        e.name
    );
    Ok(out)
}
