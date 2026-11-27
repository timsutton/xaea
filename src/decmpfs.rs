//! Transparent filesystem compression (decmpfs) for extracted files, written
//! the way Apple's `archiveutil extractXcodeAEA` writes them.
//!
//! On APFS/HFS+ a file can keep its contents compressed on disk and have the
//! kernel decompress them on read. Such a file has an empty data fork, the
//! `UF_COMPRESSED` flag, a `com.apple.decmpfs` xattr holding a 16-byte header
//! (`"fpmc"`, compression type, uncompressed size: all little-endian), and the
//! compressed bytes either inline after that header or in the resource fork.
//! None of this is documented API, but the layout has been stable for over a
//! decade (`ditto --hfsCompression`, `afsctool` and `unxip` write it too).
//!
//! Apple's extractor uses LZBITMAP, which encodes about twice as fast as LZFSE
//! for a slightly worse ratio. We do the same, and match the policy measured on
//! its Xcode 27.3 b2 output (see doc/FORMAT-NOTES.md):
//!
//! * **type 13** (LZBITMAP, inline): files that fit in one 64 KiB chunk whose
//!   encoded chunk plus the header is ≤ 3584 bytes. The chunk lives in the
//!   xattr, so the file takes no data blocks at all;
//! * **type 14** (LZBITMAP, resource fork): everything else. The fork is a
//!   table of `n + 1` little-endian u32 offsets followed by the `n` chunks,
//!   each the encoding of 64 KiB of the file (the last one shorter);
//! * a chunk that doesn't shrink is stored as `0xFF` followed by the raw bytes;
//! * a file whose fork would not save at least one 4 KiB block stays a plain
//!   file (mostly `.pkg`, `.car` and PNG payloads).

use anyhow::{Context, Result, bail, ensure};
use std::fs::File;
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// Uncompressed bytes per chunk (the decmpfs chunk size).
pub const CHUNK: usize = 64 * 1024;
/// Largest `com.apple.decmpfs` xattr Apple's extractor writes inline.
const MAX_INLINE_XATTR: usize = 3584;
const HEADER_LEN: usize = 16;
/// Allocation unit used to decide whether compressing saved anything.
const BLOCK: u64 = 4096;
/// Chunk prefix for "stored, not compressed".
const RAW_MARK: u8 = 0xFF;
const TYPE_INLINE: u32 = 13;
const TYPE_RSRC: u32 = 14;
/// How aggressively to compress. The writer consults this at open time
/// (`min_file_bytes`) and the encoder consults it at every chunk
/// (`give_up_after` / `floor_pct`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Files smaller than this are never compressed; the writer stores them
    /// plainly. Fixed per-file overhead (encoder, xattrs, flag) is a large
    /// share of the work on small files and the absolute savings are tiny.
    pub min_file_bytes: u64,
    /// After this many fed bytes, a file that has saved less than
    /// `floor_pct` percent is written plain. Archives, images and the
    /// large `.pkg` payloads never get better, and encoding them only to
    /// decode them again is wasted CPU.
    pub give_up_after: u64,
    /// The savings floor, in percent. A file must have saved at least this
    /// much of the bytes fed so far, else it is written plain.
    pub floor_pct: u64,
}

impl Policy {
    /// Apple's extractor's policy (the default): give up after 2 MiB on a
    /// file saving less than 2%.
    pub fn balanced() -> Self {
        Policy {
            min_file_bytes: 0,
            give_up_after: 2 << 20,
            floor_pct: 2,
        }
    }
    /// Faster, less disk-saving: skip small files entirely, give up after
    /// 1 MiB, and only keep files that clearly save at least 10%.
    pub fn fast() -> Self {
        Policy {
            min_file_bytes: 1 << 20,
            give_up_after: 1 << 20,
            floor_pct: 10,
        }
    }
}

/// Whether a file worth keeping, given `done` bytes fed and `stored` bytes
/// of resource fork so far.
fn worth_keeping(done: u64, stored: u64, policy: &Policy) -> bool {
    !(done >= policy.give_up_after && stored * 100 >= done * (100 - policy.floor_pct))
}

#[cfg(target_os = "macos")]
mod ffi {
    /// COMPRESSION_LZBITMAP (<compression.h>, macOS 12+).
    pub const LZBITMAP: i32 = 0x702;

    #[link(name = "compression")]
    unsafe extern "C" {
        pub fn compression_encode_buffer(
            dst: *mut u8,
            dst_size: usize,
            src: *const u8,
            src_size: usize,
            scratch: *mut core::ffi::c_void,
            algorithm: i32,
        ) -> usize;
        pub fn compression_encode_scratch_buffer_size(algorithm: i32) -> usize;
        pub fn compression_decode_buffer(
            dst: *mut u8,
            dst_size: usize,
            src: *const u8,
            src_size: usize,
            scratch: *mut core::ffi::c_void,
            algorithm: i32,
        ) -> usize;
    }
}

/// Encode `src` into `dst`; 0 when it does not fit (or the OS lacks LZBITMAP).
#[cfg(target_os = "macos")]
fn lzbitmap_encode(dst: &mut [u8], src: &[u8], scratch: &mut [u8]) -> usize {
    // SAFETY: every pointer is valid for the length passed with it, and the
    // scratch buffer is the size libcompression asked for.
    unsafe {
        ffi::compression_encode_buffer(
            dst.as_mut_ptr(),
            dst.len(),
            src.as_ptr(),
            src.len(),
            scratch.as_mut_ptr().cast(),
            ffi::LZBITMAP,
        )
    }
}

#[cfg(target_os = "macos")]
fn lzbitmap_decode(dst: &mut [u8], src: &[u8]) -> usize {
    // SAFETY: both pointers are valid for the lengths passed; a null scratch
    // makes libcompression allocate its own.
    unsafe {
        ffi::compression_decode_buffer(
            dst.as_mut_ptr(),
            dst.len(),
            src.as_ptr(),
            src.len(),
            std::ptr::null_mut(),
            ffi::LZBITMAP,
        )
    }
}

#[cfg(target_os = "macos")]
fn scratch_size() -> usize {
    // SAFETY: no preconditions.
    unsafe { ffi::compression_encode_scratch_buffer_size(ffi::LZBITMAP) }
}

#[cfg(not(target_os = "macos"))]
fn lzbitmap_encode(_: &mut [u8], _: &[u8], _: &mut [u8]) -> usize {
    0
}
#[cfg(not(target_os = "macos"))]
fn lzbitmap_decode(_: &mut [u8], _: &[u8]) -> usize {
    0
}
#[cfg(not(target_os = "macos"))]
fn scratch_size() -> usize {
    0
}

#[cfg(target_os = "macos")]
fn fsetxattr(f: &File, name: &std::ffi::CStr, val: &[u8]) -> std::io::Result<()> {
    // SAFETY: `val` is valid for its length; `name` is NUL-terminated.
    let r = unsafe {
        libc::fsetxattr(
            f.as_raw_fd(),
            name.as_ptr(),
            val.as_ptr().cast(),
            val.len(),
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

#[cfg(target_os = "macos")]
fn set_compressed_flag(f: &File) -> std::io::Result<()> {
    // fchflags *replaces* the flag word: a fresh file has none set, but keep
    // whatever is there anyway.
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is a valid out-buffer for fstat.
    if unsafe { libc::fstat(f.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded, so it filled `st`.
    let st = unsafe { st.assume_init() };
    // SAFETY: plain syscall on an fd we own.
    if unsafe { libc::fchflags(f.as_raw_fd(), st.st_flags | libc::UF_COMPRESSED) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
fn fsetxattr(_: &File, _: &std::ffi::CStr, _: &[u8]) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}
#[cfg(not(target_os = "macos"))]
fn set_compressed_flag(_: &File) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// Best-effort removal of a half-applied compression.
#[cfg(target_os = "macos")]
fn undo(f: &File) {
    for name in [c"com.apple.ResourceFork", c"com.apple.decmpfs"] {
        // SAFETY: plain syscall on an open fd with a NUL-terminated name.
        unsafe { libc::fremovexattr(f.as_raw_fd(), name.as_ptr(), libc::XATTR_SHOWCOMPRESSION) };
    }
}
#[cfg(not(target_os = "macos"))]
fn undo(_: &File) {}

/// What [`Encoder::finish`] did with the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Stored compressed; the data fork stays empty.
    Compressed,
    /// Written as a plain file: compression didn't pay.
    Plain,
    /// Written as a plain file because the volume refused the xattrs or
    /// the flag. The up-front [`probe`] makes this rare; the extractor
    /// warns when it happens.
    Refused,
}

/// Streaming per-file encoder. One per writer thread, reused across files:
/// `begin`, any number of `push`es in file order, then `finish` (or
/// `abandon` part-way). Holds one file's compressed bytes in memory, which
/// for an Xcode tree is at most a few tens of MiB.
pub struct Encoder {
    policy: Policy,
    scratch: Vec<u8>,
    /// Bytes of the current chunk not yet encoded (only when a chunk spans
    /// two pushes).
    stage: Vec<u8>,
    /// Resource fork under construction: offset table, then chunks.
    rsrc: Vec<u8>,
    nchunks: usize,
    next_chunk: usize,
    size: u64,
    fed: u64,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new(Policy::balanced())
    }
}

impl Encoder {
    pub fn new(policy: Policy) -> Self {
        Encoder {
            policy,
            scratch: vec![0u8; scratch_size().max(1)],
            stage: Vec::with_capacity(CHUNK),
            rsrc: Vec::new(),
            nchunks: 0,
            next_chunk: 0,
            size: 0,
            fed: 0,
        }
    }

    /// Start a file of `size` bytes.
    pub fn begin(&mut self, size: u64) {
        self.nchunks = size.div_ceil(CHUNK as u64) as usize;
        self.next_chunk = 0;
        self.size = size;
        self.fed = 0;
        self.stage.clear();
        self.rsrc.clear();
        // Don't let one huge file pin its buffer for the rest of the run.
        if self.rsrc.capacity() > 64 << 20 {
            self.rsrc = Vec::new();
        }
        self.rsrc.resize((self.nchunks + 1) * 4, 0);
    }

    /// Feed the next bytes of the file. Returns `false` once the file has
    /// proven not worth compressing; the caller should then [`spill`] and
    /// write the rest plainly.
    ///
    /// [`spill`]: Encoder::spill
    pub fn push(&mut self, mut data: &[u8]) -> Result<bool> {
        ensure!(
            self.fed + data.len() as u64 <= self.size,
            "file data overruns its declared size {}",
            self.size
        );
        self.fed += data.len() as u64;
        // Finish a chunk started by an earlier push.
        if !self.stage.is_empty() {
            let want = self.chunk_len(self.next_chunk) - self.stage.len();
            let take = want.min(data.len());
            self.stage.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.stage.len() == self.chunk_len(self.next_chunk) {
                let stage = std::mem::take(&mut self.stage);
                self.encode_chunk(&stage);
                self.stage = stage;
                self.stage.clear();
            }
        }
        // Whole chunks straight from the caller's buffer (the common case:
        // decoded segments are far larger than a chunk).
        while self.next_chunk < self.nchunks && data.len() >= self.chunk_len(self.next_chunk) {
            let n = self.chunk_len(self.next_chunk);
            self.encode_chunk(&data[..n]);
            data = &data[n..];
        }
        self.stage.extend_from_slice(data);
        let done = (self.next_chunk * CHUNK) as u64;
        let stored = (self.rsrc.len() - (self.nchunks + 1) * 4) as u64;
        Ok(worth_keeping(done, stored, &self.policy))
    }

    fn chunk_len(&self, i: usize) -> usize {
        (self.size - (i * CHUNK) as u64).min(CHUNK as u64) as usize
    }

    fn encode_chunk(&mut self, src: &[u8]) {
        let i = self.next_chunk;
        let start = self.rsrc.len();
        self.rsrc[i * 4..i * 4 + 4].copy_from_slice(&(start as u32).to_le_bytes());
        // Only an encoding shorter than the input is worth keeping, so
        // offer exactly `src.len()` bytes of room: libcompression returns 0
        // when the stream doesn't fit, and the raw form (1 + len) wins.
        self.rsrc.resize(start + src.len(), 0);
        let n = lzbitmap_encode(&mut self.rsrc[start..], src, &mut self.scratch);
        if n == 0 {
            self.rsrc.truncate(start);
            self.rsrc.push(RAW_MARK);
            self.rsrc.extend_from_slice(src);
        } else {
            self.rsrc.truncate(start + n);
        }
        self.next_chunk += 1;
    }

    /// Store the file. `f` must be the freshly created (empty) file.
    pub fn finish(&mut self, f: &File) -> Result<Outcome> {
        ensure!(
            self.fed == self.size && self.stage.is_empty() && self.next_chunk == self.nchunks,
            "compressed file incomplete: {} of {} bytes",
            self.fed,
            self.size
        );
        let table = (self.nchunks + 1) * 4;
        let end = self.rsrc.len();
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(b"fpmc");
        header[8..].copy_from_slice(&self.size.to_le_bytes());
        if self.nchunks == 1 && HEADER_LEN + (end - table) <= MAX_INLINE_XATTR {
            header[4..8].copy_from_slice(&TYPE_INLINE.to_le_bytes());
            let mut x = Vec::with_capacity(HEADER_LEN + end - table);
            x.extend_from_slice(&header);
            x.extend_from_slice(&self.rsrc[table..]);
            if fsetxattr(f, c"com.apple.decmpfs", &x).is_ok() && set_compressed_flag(f).is_ok() {
                return Ok(Outcome::Compressed);
            }
            undo(f);
            return self.spill(f).map(|()| Outcome::Refused);
        }
        let worth = (end as u64).div_ceil(BLOCK) < self.size.div_ceil(BLOCK);
        if !worth {
            return self.spill(f).map(|()| Outcome::Plain);
        }
        ensure!(
            end <= u32::MAX as usize,
            "resource fork too large ({end} bytes)"
        );
        self.rsrc[self.nchunks * 4..table].copy_from_slice(&(end as u32).to_le_bytes());
        header[4..8].copy_from_slice(&TYPE_RSRC.to_le_bytes());
        // Fork first, then the header, then the flag: until the flag is set
        // the file reads as empty, never as half-built.
        if fsetxattr(f, c"com.apple.ResourceFork", &self.rsrc).is_ok()
            && fsetxattr(f, c"com.apple.decmpfs", &header).is_ok()
            && set_compressed_flag(f).is_ok()
        {
            return Ok(Outcome::Compressed);
        }
        undo(f);
        self.spill(f).map(|()| Outcome::Refused)
    }

    /// Write everything fed so far as plain bytes at offset 0 (decoding the
    /// encoded chunks back), for a file that is going to stay uncompressed.
    pub fn spill(&mut self, f: &File) -> Result<()> {
        let mut buf = vec![0u8; CHUNK];
        let table = (self.nchunks + 1) * 4;
        for i in 0..self.next_chunk {
            let start = self.table_entry(i);
            let end = if i + 1 < self.next_chunk {
                self.table_entry(i + 1)
            } else {
                self.rsrc.len()
            };
            debug_assert!(start >= table);
            let want = self.chunk_len(i);
            let enc = &self.rsrc[start..end];
            let plain: &[u8] = if enc.first() == Some(&RAW_MARK) {
                &enc[1..]
            } else {
                let n = lzbitmap_decode(&mut buf[..want], enc);
                ensure!(n == want, "LZBITMAP round trip failed in chunk {i}");
                &buf[..want]
            };
            ensure!(plain.len() == want, "chunk {i} has the wrong length");
            f.write_all_at(plain, (i * CHUNK) as u64)
                .context("pwrite")?;
        }
        if !self.stage.is_empty() {
            f.write_all_at(&self.stage, (self.next_chunk * CHUNK) as u64)
                .context("pwrite")?;
        }
        self.stage.clear();
        self.rsrc.clear();
        Ok(())
    }

    /// Entry `i` of the resource fork's offset table.
    fn table_entry(&self, i: usize) -> usize {
        let at = &self.rsrc[i * 4..];
        u32::from_le_bytes(*at.first_chunk().expect("offset table entry")) as usize
    }
}

/// Check, once per extraction, that `dir`'s volume stores and reads back an
/// LZBITMAP-compressed file (both layouts). Fails on non-APFS/HFS+ volumes,
/// on network shares that drop the flag, and on macOS releases without
/// LZBITMAP. Leaves nothing behind.
pub fn probe(dir: &Path) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("transparent compression is only available on macOS");
    }
    // Compressible, and two chunks long so it exercises the resource fork.
    let data: Vec<u8> = (0..CHUNK + 4000)
        .map(|i| b"xaea decmpfs probe "[i % 19])
        .collect();
    let mut enc = Encoder::new(Policy::balanced());
    for (k, body) in [&data[..], &data[..100]].into_iter().enumerate() {
        let p = dir.join(format!(
            ".xaea-compression-probe-{}-{k}",
            std::process::id()
        ));
        let r = (|| -> Result<()> {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&p)
                .with_context(|| format!("create {}", p.display()))?;
            enc.begin(body.len() as u64);
            enc.push(body)?;
            ensure!(
                k > 0 || enc.rsrc.len() < body.len() / 2,
                "LZBITMAP is unavailable (macOS 12 or later is required)"
            );
            ensure!(
                enc.finish(&f)? == Outcome::Compressed,
                "the volume does not accept compressed files"
            );
            drop(f);
            ensure!(
                std::fs::read(&p)? == body,
                "the volume does not read compressed files back correctly"
            );
            Ok(())
        })();
        let _ = std::fs::remove_file(&p);
        r?;
    }
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::macos::fs::MetadataExt;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("xaea-decmpfs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Pseudo-random bytes (incompressible) without a rand dependency.
    fn noise(n: usize, mut s: u64) -> Vec<u8> {
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s as u8
            })
            .collect()
    }

    fn text(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| b"the quick brown fox "[i % 20] ^ (i / 997) as u8)
            .collect()
    }

    fn roundtrip(dir: &Path, name: &str, body: &[u8], pieces: usize) -> Outcome {
        let p = dir.join(name);
        let f = File::create(&p).unwrap();
        let mut enc = Encoder::new(Policy::balanced());
        enc.begin(body.len() as u64);
        let step = body.len().div_ceil(pieces.max(1)).max(1);
        let mut plain = false;
        let mut off = 0;
        for c in body.chunks(step) {
            if plain {
                f.write_all_at(c, off as u64).unwrap();
            } else if !enc.push(c).unwrap() {
                enc.spill(&f).unwrap();
                plain = true;
            }
            off += c.len();
        }
        let out = if plain {
            Outcome::Plain
        } else {
            enc.finish(&f).unwrap()
        };
        drop(f);
        assert_eq!(std::fs::read(&p).unwrap(), body, "{name} reads back");
        let compressed = std::fs::metadata(&p).unwrap().st_flags() & libc::UF_COMPRESSED != 0;
        assert_eq!(compressed, out == Outcome::Compressed, "{name} flag");
        out
    }

    #[test]
    fn layouts_round_trip() {
        if let Err(e) = probe(&std::env::temp_dir()) {
            eprintln!("skipping: temp volume does not support compression: {e:#}");
            return;
        }
        let d = tmpdir("rt");
        // Inline: tiny, small-and-raw, and one-chunk-but-compressible.
        assert_eq!(roundtrip(&d, "tiny", b"hi\n", 1), Outcome::Compressed);
        assert_eq!(
            roundtrip(&d, "raw3k", &noise(3000, 1), 1),
            Outcome::Compressed
        );
        assert_eq!(
            roundtrip(&d, "text40k", &text(40_000), 3),
            Outcome::Compressed
        );
        // Resource fork, chunk boundaries split across odd-sized pushes.
        assert_eq!(
            roundtrip(&d, "text1m", &text(1_000_003), 7),
            Outcome::Compressed
        );
        assert_eq!(
            roundtrip(&d, "exact", &text(CHUNK * 3), 5),
            Outcome::Compressed
        );
        // Mostly-noise file with a compressible tail: raw chunks + encoded.
        let mut mixed = noise(200_000, 2);
        mixed.extend(text(300_000));
        assert_eq!(roundtrip(&d, "mixed", &mixed, 9), Outcome::Compressed);
        // Incompressible: kept plain, both via finish() and via give-up.
        assert_eq!(
            roundtrip(&d, "noise100k", &noise(100_000, 3), 2),
            Outcome::Plain
        );
        assert_eq!(
            roundtrip(&d, "noise5m", &noise(5 << 20, 4), 13),
            Outcome::Plain
        );
        std::fs::remove_dir_all(&d).unwrap();
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn balanced_matches_apples_policy() {
        // Apple's extractor: give up after 2 MiB on a file saving < 2%.
        let b = Policy::balanced();
        assert_eq!(b.min_file_bytes, 0);
        assert_eq!(b.give_up_after, 2 << 20);
        assert_eq!(b.floor_pct, 2);
        // <2% saved: not worth keeping. More than 2% saved: keep.
        let done = b.give_up_after;
        assert!(!worth_keeping(done, done * 99 / 100, &b));
        assert!(worth_keeping(done, done * 97 / 100, &b));
    }

    #[test]
    fn fast_is_stricter_and_skips_small_files() {
        // Fast: skip small files, give up after 1 MiB, keep only >=10% saved.
        let f = Policy::fast();
        assert_eq!(f.min_file_bytes, 1 << 20);
        assert_eq!(f.give_up_after, 1 << 20);
        assert_eq!(f.floor_pct, 10);
        // 5% saved: not worth keeping. More than 10% saved: keep.
        let done = f.give_up_after;
        assert!(!worth_keeping(done, done * 95 / 100, &f));
        assert!(worth_keeping(done, done * 89 / 100, &f));
    }

    #[test]
    fn give_up_only_after_the_threshold() {
        // Under the give-up threshold, any savings keep the file.
        let f = Policy::fast();
        assert!(worth_keeping(f.give_up_after - 1, 99_999, &f));
        // Above the threshold, a barely-saving file is dropped.
        assert!(!worth_keeping(f.give_up_after, f.give_up_after - 1, &f));
    }
}
