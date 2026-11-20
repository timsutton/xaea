//! Incremental parser for the `AA01` Apple Archive object stream that an AEA
//! payload decodes to.
//!
//! Empirically established on Xcode 27.3 b2 (see doc/FORMAT-NOTES.md): a record
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

use anyhow::{Result, bail, ensure};
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
}

#[derive(Debug, Clone)]
pub struct Record {
    pub typ: u8, // b'D', b'F', b'L'
    pub path: Vec<u8>,
    pub link: Option<Vec<u8>>,
    // Parsed but not applied: chown requires root (Apple's own CLI refuses
    // too when run unprivileged); kept for a future `--Owners` option.
    #[allow(dead_code)]
    pub uid: u32,
    #[allow(dead_code)]
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
                    self.sink.blob(Piece {
                        buf: chunk.clone(),
                        start: p,
                        end: p + take,
                    })?;
                    p += take;
                    let rem = rem - take as u64;
                    self.state = if rem == 0 {
                        State::Header
                    } else {
                        State::Blob(rem)
                    };
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

    /// Recover the sink (used by tests; the extractor drives to completion).
    #[cfg(test)]
    pub fn into_sink(self) -> P {
        self.sink
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Ev {
        recs: Vec<Record>,
        blob: Vec<u8>,
    }
    impl Sink for Ev {
        fn record(&mut self, r: &Record) -> Result<()> {
            self.recs.push(r.clone());
            Ok(())
        }
        fn blob(&mut self, p: Piece) -> Result<()> {
            self.blob.extend_from_slice(p.bytes());
            Ok(())
        }
    }

    fn t(key: &str, fmt: char, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + payload.len());
        v.extend_from_slice(key.as_bytes());
        v.push(fmt as u8);
        v.extend_from_slice(payload);
        v
    }
    fn rec(body: &[u8]) -> Vec<u8> {
        let mut v = b"AA01".to_vec();
        v.extend_from_slice(&(6u16 + body.len() as u16).to_le_bytes());
        v.extend_from_slice(body);
        v
    }
    fn bytes16(n: u16, tail: &[u8]) -> Vec<u8> {
        let mut v = n.to_le_bytes().to_vec();
        v.extend_from_slice(tail);
        v
    }
    fn pat(s: &str) -> Vec<u8> {
        t("PAT", 'P', &bytes16(s.len() as u16, s.as_bytes()))
    }
    fn dir_rec(path: &str) -> Vec<u8> {
        let mut body = t("TYP", '1', b"D");
        body.extend(pat(path));
        body.extend(t("MOD", '2', &0o40_755u16.to_le_bytes()));
        rec(&body)
    }
    fn file_rec(path: &str, dat: u16) -> Vec<u8> {
        let mut body = t("TYP", '1', b"F");
        body.extend(pat(path));
        body.extend(t("MOD", '2', &0o100_644u16.to_le_bytes()));
        if dat > 0 {
            body.extend(t("DAT", 'A', &dat.to_le_bytes()));
        }
        body.extend(t("FLG", '1', &[0x20]));
        body.extend(t("AFT", '1', &[0x14]));
        rec(&body)
    }
    fn link_rec(path: &str, target: &str) -> Vec<u8> {
        let mut body = t("TYP", '1', b"L");
        body.extend(pat(path));
        body.extend(t(
            "LNK",
            'P',
            &bytes16(target.len() as u16, target.as_bytes()),
        ));
        body.extend(t("MOD", '2', &0o120_777u16.to_le_bytes()));
        rec(&body)
    }

    #[test]
    fn parser_survives_every_chunking() {
        let blob: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let blob2: Vec<u8> = vec![0xAA, 0xBB];
        let mut s = Vec::new();
        s.extend(dir_rec("d"));
        s.extend(file_rec("d/f.bin", 300));
        s.extend(&blob);
        s.extend(link_rec("d/l", "f.bin"));
        s.extend(file_rec("d/empty", 0));
        s.extend(file_rec("d/tiny", 2));
        s.extend(&blob2);

        for &chunk in &[1usize, 2, 3, 5, 7, 64, 1000, s.len()] {
            let mut st = Stream::new(Ev {
                recs: vec![],
                blob: vec![],
            });
            for c in s.chunks(chunk) {
                st.feed(Arc::from(c.to_vec().into_boxed_slice())).unwrap();
            }
            st.finish().unwrap();
            let Ev { recs, blob: got } = st.into_sink();
            assert_eq!(recs.len(), 5, "chunk={chunk}");
            assert_eq!(recs[0].typ, b'D');
            assert_eq!(recs[1].typ, b'F');
            assert_eq!(recs[1].dat, 300);
            assert_eq!(recs[2].typ, b'L');
            assert_eq!(recs[2].link.as_deref(), Some("f.bin".as_bytes()));
            assert_eq!(recs[3].dat, 0);
            assert_eq!(recs[4].dat, 2);
            let mut want = blob.clone();
            want.extend_from_slice(&blob2);
            assert_eq!(got, want, "blob bytes, chunk={chunk}");
        }
    }

    #[test]
    fn parser_rejects_garbage_and_truncation() {
        // Bad magic -> error naming desync.
        let mut st = Stream::new(Ev {
            recs: vec![],
            blob: vec![],
        });
        let e = st
            .feed(Arc::from(b"XXXX\x08\x00".to_vec().into_boxed_slice()))
            .unwrap_err();
        assert!(e.to_string().contains("desync"), "{e}");

        // Trailing partial record -> finish() errors.
        let mut st = Stream::new(Ev {
            recs: vec![],
            blob: vec![],
        });
        st.feed(Arc::from(dir_rec("a")[..4].to_vec().into_boxed_slice()))
            .unwrap();
        assert!(st.finish().is_err());

        // Blob promised but never delivered -> finish() errors.
        let mut st = Stream::new(Ev {
            recs: vec![],
            blob: vec![],
        });
        st.feed(Arc::from(file_rec("f", 300))).unwrap();
        assert!(st.finish().is_err());
    }

    #[test]
    fn unknown_tag_is_rejected() {
        let mut body = t("TYP", '1', b"D");
        body.extend(pat("x"));
        body.extend(t("ZZZ", '1', &[0]));
        let mut st = Stream::new(Ev {
            recs: vec![],
            blob: vec![],
        });
        let e = st.feed(Arc::from(rec(&body))).unwrap_err();
        assert!(e.to_string().contains("unknown AA01 tag"), "{e}");
    }
}
