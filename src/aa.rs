//! Incremental parser for the `AA01` Apple Archive object stream that an AEA
//! payload decodes to.
//!
//! Empirically established on Xcode 27.3 b2 (see FORMAT-NOTES.md): a record
//! is `"AA01" + u16le size` (size covers the header) followed by a body of
//! 4-byte tagged fields `TAG<F>` where `<F>` encodes the payload kind:
//!
//! * `'1' | '2' | '4' | '8'` — little-endian int of that width
//! * `'A' | 'B' | 'C'`       — little-endian int of width 2, 4, 8 (length tiers)
//! * `'P'`                   — u16le length + bytes
//! * `'p'`                   — u32le length + bytes
//!
//! Records seen: `TYP{1}` ('D' dir / 'F' file / 'L' link), `PAT{P}` path,
//! `LNK{P}` link target, `UID{1}`, `GID{1}`, `MOD{2}` (full st_mode incl.
//! S_IF* bits), `DAT{A|B}` inline data length, `FLG{1}`, `AFT{1}`. A file
//! record is immediately followed by its `DAT` bytes in the stream; the bytes
//! are *not* part of the record size.

use anyhow::{bail, ensure, Result};
use std::sync::Arc;

/// A zero-copy slice of a decoded segment buffer.
#[derive(Clone)]
pub struct Piece {
    pub buf: Arc<[u8]>,
    pub start: usize,
    pub end: usize,
}

impl Piece {
    pub fn bytes(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    pub typ: u8, // b'D', b'F', b'L'
    pub path: Vec<u8>,
    pub link: Option<Vec<u8>>,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub dat: u64,
}

pub trait Sink {
    /// A record was fully parsed. For files, `record.dat` bytes follow and
    /// will be delivered via [`Sink::blob`] (possibly in several pieces).
    fn record(&mut self, rec: &Record) -> Result<()>;
    /// Streaming piece of the current file's data blob (zero-copy view of a
    /// decoded segment buffer).
    fn blob(&mut self, piece: Piece) -> Result<()>;
}

/// Blanket: mutable references to sinks are sinks (lets Stream borrow).
impl<P: Sink + ?Sized> Sink for &mut P {
    fn record(&mut self, rec: &Record) -> Result<()> {
        (*self).record(rec)
    }
    fn blob(&mut self, piece: Piece) -> Result<()> {
        (*self).blob(piece)
    }
}

pub struct Stream<P: Sink> {
    sink: P,
    state: State,
    buf: Vec<u8>,
}

enum State {
    Header,
    Body(u16),
    Blob(u64),
}

impl<P: Sink> Stream<P> {
    pub fn new(sink: P) -> Self {
        Stream {
            sink,
            state: State::Header,
            buf: Vec::with_capacity(4096),
        }
    }

    pub fn feed(&mut self, chunk: Arc<[u8]>) -> Result<()> {
        let mut p = 0usize;
        while p < chunk.len() {
            match self.state {
                State::Header => {
                    let need = 6 - self.buf.len();
                    let take = need.min(chunk.len() - p);
                    self.buf.extend_from_slice(&chunk[p..p + take]);
                    p += take;
                    if self.buf.len() == 6 {
                        ensure!(
                            &self.buf[..4] == b"AA01",
                            "AA01 stream desync (bad record magic)"
                        );
                        let size = u16::from_le_bytes([self.buf[4], self.buf[5]]);
                        ensure!(size >= 8, "record size {size} too small");
                        self.buf.clear();
                        self.state = State::Body(size);
                    }
                }
                State::Body(size) => {
                    let need = size as usize - 6 - self.buf.len();
                    let take = need.min(chunk.len() - p);
                    self.buf.extend_from_slice(&chunk[p..p + take]);
                    p += take;
                    if self.buf.len() == size as usize - 6 {
                        let body = std::mem::take(&mut self.buf);
                        let rec = parse_record(&body)?;
                        self.buf.clear();
                        self.sink.record(&rec)?;
                        if rec.dat > 0 {
                            self.state = State::Blob(rec.dat);
                        } else {
                            self.state = State::Header;
                        }
                    }
                }
                State::Blob(rem) => {
                    let take = (rem as usize).min(chunk.len() - p);
                    self.sink.blob(Piece { buf: chunk.clone(), start: p, end: p + take })?;
                    p += take;
                    let rem = rem - take as u64;
                    self.state = if rem == 0 { State::Header } else { State::Blob(rem) };
                }
            }
        }
        Ok(())
    }

    pub fn finish(&self) -> Result<()> {
        match self.state {
            State::Header if self.buf.is_empty() => Ok(()),
            State::Blob(0) if self.buf.is_empty() => Ok(()),
            _ => anyhow::bail!("AA01 stream ended mid-record/mid-blob"),
        }
    }
}

/// Parse a record body (everything after the 6-byte header).
fn parse_record(body: &[u8]) -> Result<Record> {
    let (mut typ, mut path, mut link) = (None, None, None);
    let (mut uid, mut gid, mut mode, mut dat) = (0u32, 0u32, 0u32, 0u64);
    let mut q = 0usize;
    while q < body.len() {
        ensure!(q + 4 <= body.len(), "truncated tag at {q}");
        let tag = &body[q..q + 4];
        let fmt = tag[3];
        let key = &tag[..3];
        q += 4;
        let put_int = |q: &mut usize, body: &[u8], fmt: u8| -> Result<u64> {
            let w: usize = match fmt {
                b'1' => 1,
                b'2' => 2,
                b'4' => 4,
                b'8' => 8,
                b'A' => 2,
                b'B' => 4,
                b'C' => 8,
                c => bail!("unknown int format {:?} in record", c as char),
            };
            ensure!(*q + w <= body.len(), "truncated int field");
            let mut v = [0u8; 8];
            v[..w].copy_from_slice(&body[*q..*q + w]);
            *q += w;
            Ok(u64::from_le_bytes(v))
        };
        let put_bytes = |q: &mut usize, body: &[u8], fmt: u8| -> Result<Vec<u8>> {
            let ln: usize = match fmt {
                b'P' => {
                    ensure!(*q + 2 <= body.len(), "truncated len");
                    u16::from_le_bytes([body[*q], body[*q + 1]]) as usize
                }
                b'p' => {
                    ensure!(*q + 4 <= body.len(), "truncated len");
                    u32::from_le_bytes(body[*q..*q + 4].try_into()?) as usize
                }
                c => bail!("unknown bytes format {:?} in record", c as char),
            };
            *q += if fmt == b'P' { 2 } else { 4 };
            ensure!(*q + ln <= body.len(), "truncated bytes field");
            let v = body[*q..*q + ln].to_vec();
            *q += ln;
            Ok(v)
        };
        match key {
            b"TYP" => typ = Some(put_int(&mut q, body, fmt)? as u8),
            b"PAT" => path = Some(put_bytes(&mut q, body, fmt)?),
            b"LNK" => link = Some(put_bytes(&mut q, body, fmt)?),
            b"UID" => uid = put_int(&mut q, body, fmt)? as u32,
            b"GID" => gid = put_int(&mut q, body, fmt)? as u32,
            b"MOD" => mode = put_int(&mut q, body, fmt)? as u32,
            b"DAT" => dat = put_int(&mut q, body, fmt)?,
            // Observed on file records with constant values so far; keep the
            // stream parseable whatever they hold.
            b"FLG" | b"AFT" => {
                put_int(&mut q, body, fmt)?;
            }
            _ => bail!(
                "unknown AA01 tag {:?}",
                std::str::from_utf8(tag).unwrap_or("?")
            ),
        }
    }
    let typ = typ.context_any("record without TYP")?;
    let path = path.context_any("record without PAT")?;
    Ok(Record {
        typ,
        path,
        link,
        uid,
        gid,
        mode,
        dat,
    })
}

// Small helper so we don't pull anyhow::Context for Option here.
trait ContextAny<T> {
    fn context_any(self, msg: &'static str) -> Result<T>;
}
impl<T> ContextAny<T> for Option<T> {
    fn context_any(self, msg: &'static str) -> Result<T> {
        self.ok_or_else(|| anyhow::anyhow!(msg))
    }
}
