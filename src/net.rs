//! HTTP(S) reads: an archive's key PEM from its key URL, and byte ranges
//! of a remote IPSW or `.aea` (restore images are gigabytes; only the
//! wanted member is fetched, and decrypted as it arrives).
//!
//! Redirects are followed by hand, once, when a remote file is opened, so
//! every later range request goes straight to the final URL with its
//! `Range` header intact.

use anyhow::{Context, Result, bail, ensure};
use std::collections::VecDeque;
use std::fmt;
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use ureq::http::{StatusCode, Uri, header};

/// Bytes per range request when streaming a member.
const CHUNK: u64 = 8 << 20;
const MAX_REDIRECTS: usize = 10;
const ATTEMPTS: u32 = 4;

/// Marks an error as a failed network read, so the command can report it
/// as an unreadable input rather than as a damaged archive.
#[derive(Debug)]
pub struct NetError(pub String);

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NetError {}

fn net_err(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(NetError(msg.into()))
}

/// Whether `s` names a remote file rather than a local path.
pub fn is_url(s: &str) -> bool {
    s.starts_with("https://") || s.starts_with("http://")
}

fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .user_agent(concat!("xaea/", env!("CARGO_PKG_VERSION")))
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(20)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            // A stalled transfer, not a slow one: per read, not per body.
            .timeout_per_read(Some(Duration::from_secs(60)))
            .build()
            .into()
    })
}

/// One GET, following redirects, with an optional `Range`. Returns the
/// final URL and the response. Only `https` may be redirected to, unless
/// the request started on plain `http`.
fn get(url: &str, range: Option<(u64, u64)>) -> Result<(String, ureq::http::Response<ureq::Body>)> {
    let mut url = url.to_owned();
    for _ in 0..=MAX_REDIRECTS {
        let mut req = agent().get(&url);
        if let Some((a, b)) = range {
            req = req.header(header::RANGE, format!("bytes={a}-{}", b - 1));
        }
        let resp = req.call().map_err(|e| net_err(format!("GET {url}: {e}")))?;
        if !resp.status().is_redirection() {
            return Ok((url, resp));
        }
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .with_context(|| format!("GET {url}: redirect without a Location"))?;
        let next = resolve(&url, loc)?;
        ensure!(
            next.starts_with("https://") || url.starts_with("http://"),
            "GET {url}: refusing a redirect from https to {next}"
        );
        url = next;
    }
    Err(net_err(format!("GET {url}: too many redirects")))
}

/// A `Location` value made absolute against the URL it came from.
fn resolve(base: &str, loc: &str) -> Result<String> {
    if is_url(loc) {
        return Ok(loc.to_owned());
    }
    let uri: Uri = base.parse().context("bad URL")?;
    let origin = format!(
        "{}://{}",
        uri.scheme_str().unwrap_or("https"),
        uri.authority().map_or("", |a| a.as_str())
    );
    Ok(if loc.starts_with('/') {
        format!("{origin}{loc}")
    } else {
        let path = uri.path();
        format!("{origin}{}{loc}", &path[..=path.rfind('/').unwrap_or(0)])
    })
}

/// The host of `url`, lowercased.
pub fn host(url: &str) -> Option<String> {
    let uri: Uri = url.parse().ok()?;
    uri.host().map(str::to_ascii_lowercase)
}

/// Apple's own hosts: the only ones an archive's key URL may send us to.
fn apple_host(url: &str) -> bool {
    url.starts_with("https://")
        && host(url).is_some_and(|h| {
            ["apple.com", "cdn-apple.com"]
                .iter()
                .any(|d| h == *d || h.ends_with(&format!(".{d}")))
        })
}

/// Fetch the key PEM an archive names. The URL comes from the archive's
/// unauthenticated auth data, so it must be `https` on an Apple host,
/// before and after redirects, and the body small.
pub fn fetch_key_pem(url: &str) -> Result<Vec<u8>> {
    ensure!(
        apple_host(url),
        "the archive's key URL {url} is not an https URL on an Apple host; not fetching it"
    );
    let (fin, resp) = with_retries(|| get(url, None))?;
    ensure!(
        apple_host(&fin),
        "the key URL redirected to {fin}, not an https URL on an Apple host"
    );
    let status = resp.status();
    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        return Err(net_err(format!("GET {fin}: HTTP {status}")));
    }
    ensure!(status.is_success(), "GET {fin}: HTTP {status}");
    resp.into_body()
        .with_config()
        .limit(64 << 10)
        .read_to_vec()
        .map_err(|e| net_err(format!("GET {fin}: {e}")))
}

/// Retry transient failures (network errors, 5xx, 429) with backoff.
fn with_retries<T>(mut f: impl FnMut() -> Result<T>) -> Result<T> {
    let mut wait = Duration::from_millis(500);
    for attempt in 1.. {
        match f() {
            Err(e) if attempt < ATTEMPTS && e.is::<NetError>() => {
                std::thread::sleep(wait);
                wait *= 2;
            }
            r => return r,
        }
    }
    unreachable!()
}

/// A remote file read by byte ranges.
#[derive(Debug)]
pub struct Remote {
    /// The URL after redirects.
    pub url: String,
    pub len: u64,
}

impl Remote {
    /// Resolve redirects and learn the size with a one-byte range read,
    /// which also checks that the server honors ranges.
    pub fn open(url: &str) -> Result<Self> {
        let (fin, resp) = with_retries(|| get(url, Some((0, 1))))?;
        match resp.status() {
            StatusCode::PARTIAL_CONTENT => {}
            StatusCode::OK => bail!(
                "{url}: the server does not support range requests; download the file and pass its path"
            ),
            s => return Err(net_err(format!("GET {url}: HTTP {s}"))),
        }
        let (_, _, len) = content_range(&resp)?;
        Ok(Remote { url: fin, len })
    }

    /// Bytes `[off, off + len)`.
    pub fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>> {
        let end = off + len as u64;
        ensure!(end <= self.len, "read past the end of {}", self.url);
        if len == 0 {
            return Ok(Vec::new());
        }
        with_retries(|| {
            let (_, resp) = get(&self.url, Some((off, end)))?;
            if resp.status() != StatusCode::PARTIAL_CONTENT {
                return Err(
                    if resp.status().is_server_error()
                        || resp.status() == StatusCode::TOO_MANY_REQUESTS
                    {
                        net_err(format!("GET {}: HTTP {}", self.url, resp.status()))
                    } else {
                        anyhow::anyhow!(
                            "GET {}: HTTP {} for a range request",
                            self.url,
                            resp.status()
                        )
                    },
                );
            }
            let (a, b, total) = content_range(&resp)?;
            ensure!(
                a == off && b == end && total == self.len,
                "{}: the server sent bytes {a}-{b}/{total} for {off}-{end}/{} (did the file change?)",
                self.url,
                self.len
            );
            let body = resp
                .into_body()
                .with_config()
                .limit(len as u64)
                .read_to_vec()
                .map_err(|e| net_err(format!("GET {}: {e}", self.url)))?;
            if body.len() != len {
                return Err(net_err(format!(
                    "GET {}: short body ({} of {len} bytes)",
                    self.url,
                    body.len()
                )));
            }
            Ok(body)
        })
    }
}

/// `Content-Range: bytes a-b/total` as `(a, b + 1, total)`.
fn content_range(resp: &ureq::http::Response<ureq::Body>) -> Result<(u64, u64, u64)> {
    let v = resp
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .context("range response without a Content-Range")?;
    let parse = || -> Option<(u64, u64, u64)> {
        let (range, total) = v.strip_prefix("bytes ")?.split_once('/')?;
        let (a, b) = range.split_once('-')?;
        Some((
            a.parse().ok()?,
            b.parse::<u64>().ok()? + 1,
            total.parse().ok()?,
        ))
    };
    parse().with_context(|| format!("unparseable Content-Range {v:?}"))
}

/// Sequential reads over `[start, end)` of a remote file, with up to
/// `window` chunk requests in flight ahead of the reader.
pub struct RangeStream {
    remote: Arc<Remote>,
    next: u64,
    end: u64,
    window: usize,
    inflight: VecDeque<Receiver<Result<Vec<u8>>>>,
    cur: Vec<u8>,
    pos: usize,
}

impl RangeStream {
    pub fn new(remote: Arc<Remote>, start: u64, end: u64, window: usize) -> Self {
        RangeStream {
            remote,
            next: start,
            end,
            window: window.max(1),
            inflight: VecDeque::new(),
            cur: Vec::new(),
            pos: 0,
        }
    }

    fn top_up(&mut self) {
        while self.inflight.len() < self.window && self.next < self.end {
            let (off, len) = (self.next, CHUNK.min(self.end - self.next));
            self.next += len;
            let (tx, rx) = sync_channel(1);
            let remote = Arc::clone(&self.remote);
            // A reader that stops early just drops the receivers; the
            // fetches in flight finish and their sends fail quietly.
            std::thread::spawn(move || {
                let _ = tx.send(remote.read_at(off, len as usize));
            });
            self.inflight.push_back(rx);
        }
    }
}

impl crate::stream::Take for RangeStream {
    fn take_into(&mut self, mut n: usize, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        out.reserve(n);
        while n > 0 {
            if self.pos == self.cur.len() {
                self.top_up();
                let rx = self
                    .inflight
                    .pop_front()
                    .context("read past the end of the archive")?;
                self.cur = rx.recv().context("download thread died")??;
                self.pos = 0;
            }
            let k = n.min(self.cur.len() - self.pos);
            out.extend_from_slice(&self.cur[self.pos..self.pos + k]);
            self.pos += k;
            n -= k;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_urls_must_be_apple_https() {
        assert!(apple_host("https://wkms-public.apple.com/fcs-keys/x="));
        assert!(apple_host("https://fcs-keys-pub-prod.cdn-apple.com/x"));
        assert!(!apple_host("http://wkms-public.apple.com/x"));
        assert!(!apple_host("https://apple.com.evil.example/x"));
        assert!(!apple_host("https://evilapple.com/x"));
    }

    #[test]
    fn relative_redirects() {
        let b = "https://h.example/a/b/c.ipsw";
        assert_eq!(resolve(b, "/x").unwrap(), "https://h.example/x");
        assert_eq!(resolve(b, "d").unwrap(), "https://h.example/a/b/d");
        assert_eq!(
            resolve(b, "https://o.example/y").unwrap(),
            "https://o.example/y"
        );
    }
}
