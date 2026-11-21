//! Opt-in pipeline profiling probes (`--features profile`).
//!
//! Without the feature every function here is an empty `#[inline(always)]`
//! shim, so default builds carry no timing calls, no atomics and no env
//! lookups. With it, each pipeline stage accumulates wall time (summed over
//! its threads) into global counters, printed after `XAEA_STATS=1`, and
//! `XAEA_TL=1` streams a 250 ms timeline to stderr. `XAEA_WQ` overrides
//! the per-writer queue depth. See
//! doc/PERFORMANCE-NOTES.md ("Profiling build") for how to read the output.

/// Time-accounting categories.
#[derive(Clone, Copy)]
pub enum C {
    /// Decoder: `pread` of the compressed segment.
    DPread,
    /// Decoder: LZMA decode.
    DDecode,
    /// Decoder: SHA-256 of the decoded segment.
    DSha,
    /// Decoder: blocked handing the result to the parser.
    DSend,
    /// Parser: waiting for the next decoded segment.
    PRecv,
    /// Parser: AA01 parse + dispatch (includes `PSend`).
    PFeed,
    /// Parser: blocked sending to a writer queue.
    PSend,
    /// Writer: idle, waiting for work.
    WRecv,
    WMkdir,
    WOpen,
    /// Writer: `create_dir_all` fallback when an open's parent was missing.
    WMkp,
    WClose,
    WFchmod,
    WPwrite,
    /// Writer: LZBITMAP-encoding file data (`--compress`).
    WCompress,
    /// Writer: storing a compressed file (xattrs + flag), or writing back
    /// one that didn't compress.
    WStore,
    /// Parser: waiting on the per-writer drain barrier.
    WFlush,
    WLink,
    WDirmode,
}

/// Event counters.
#[derive(Clone, Copy)]
pub enum K {
    Segs,
    Opens,
    Pwrites,
    PwriteBytes,
}

#[cfg(feature = "profile")]
mod on {
    use super::{C, K};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
    use std::time::{Duration, Instant};

    const NC: usize = C::WDirmode as usize + 1;
    const NK: usize = K::PwriteBytes as usize + 1;
    static TIME_NS: [AtomicU64; NC] = [const { AtomicU64::new(0) }; NC];
    static COUNT: [AtomicU64; NK] = [const { AtomicU64::new(0) }; NK];

    #[inline]
    pub fn time<R>(c: C, f: impl FnOnce() -> R) -> R {
        let t0 = Instant::now();
        let r = f();
        TIME_NS[c as usize].fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
        r
    }

    /// Account time measured by the caller (for spans a closure can't wrap).
    #[inline]
    pub fn add_since(c: C, t0: Instant) {
        TIME_NS[c as usize].fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
    }

    #[inline]
    pub fn count(k: K, n: u64) {
        COUNT[k as usize].fetch_add(n, Relaxed);
    }

    pub fn depth(var: &str, default: usize) -> usize {
        std::env::var(var)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    fn secs(c: C) -> f64 {
        TIME_NS[c as usize].load(Relaxed) as f64 / 1e9
    }
    fn n(k: K) -> u64 {
        COUNT[k as usize].load(Relaxed)
    }

    pub fn report() {
        use C::*;
        eprintln!(
            "[prof] decoders (s, summed over threads): pread {:.2}  lzma {:.2}  sha256 {:.2}  \
             send-blocked {:.2}  segs {}",
            secs(DPread),
            secs(DDecode),
            secs(DSha),
            secs(DSend),
            n(K::Segs)
        );
        eprintln!(
            "[prof] parser (s): recv-wait {:.2}  feed {:.2} (of which send-blocked {:.2})",
            secs(PRecv),
            secs(PFeed),
            secs(PSend)
        );
        eprintln!(
            "[prof] writers (s, summed over threads): idle {:.2}  mkdir {:.2}  open {:.2} ({} opens, \
             mkdir-p fallback {:.2})  close {:.2}  fchmod {:.2}  pwrite {:.2} ({} calls, {:.2} GiB)  \
             compress {:.2}  store {:.2}  linkpass {:.2}  dirmodes {:.2}; drain barrier {:.2}",
            secs(WRecv),
            secs(WMkdir),
            secs(WOpen),
            n(K::Opens),
            secs(WMkp),
            secs(WClose),
            secs(WFchmod),
            secs(WPwrite),
            n(K::Pwrites),
            n(K::PwriteBytes) as f64 / (1u64 << 30) as f64,
            secs(WCompress),
            secs(WStore),
            secs(WLink),
            secs(WDirmode),
            secs(WFlush)
        );
    }

    /// Stops the timeline thread when dropped.
    pub struct Timeline(Option<Arc<AtomicBool>>);

    impl Drop for Timeline {
        fn drop(&mut self) {
            if let Some(stop) = &self.0 {
                stop.store(true, Relaxed);
            }
        }
    }

    /// Start the `XAEA_TL=1` timeline: every 250 ms, one row of segments
    /// decoded / parsed, opens/s, MiB/s written, and how many threads' worth
    /// of time decoders spent send-blocked, writers spent in filesystem
    /// calls, and the parser spent blocked on a writer queue.
    pub fn timeline(started: Instant, parsed: impl Fn() -> usize + Send + 'static) -> Timeline {
        if std::env::var_os("XAEA_TL").is_none() {
            return Timeline(None);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        std::thread::spawn(move || {
            const STEP: u64 = 250;
            let fs_busy = || {
                [
                    C::WMkdir,
                    C::WOpen,
                    C::WClose,
                    C::WFchmod,
                    C::WPwrite,
                    C::WStore,
                ]
                .iter()
                .map(|&c| TIME_NS[c as usize].load(Relaxed))
                .sum::<u64>()
            };
            let snap = || {
                (
                    n(K::Opens),
                    n(K::PwriteBytes),
                    TIME_NS[C::DSend as usize].load(Relaxed),
                    fs_busy(),
                    TIME_NS[C::PSend as usize].load(Relaxed),
                )
            };
            eprintln!(
                "[tl]  t(s) decoded parsed opens/s MiB/s  dec-blocked(thr) writer-fs-busy(thr) parser-blocked"
            );
            let mut prev = snap();
            while !st.load(Relaxed) {
                std::thread::sleep(Duration::from_millis(STEP));
                let cur = snap();
                let s = STEP as f64 / 1000.0;
                let d = |a: u64, b: u64| a.saturating_sub(b) as f64;
                eprintln!(
                    "[tl] {:6.2} {:7} {:6} {:7.0} {:5.0} {:16.1} {:19.1} {:14.2}",
                    started.elapsed().as_secs_f64(),
                    n(K::Segs),
                    parsed(),
                    d(cur.0, prev.0) / s,
                    d(cur.1, prev.1) / s / 1048576.0,
                    d(cur.2, prev.2) / 1e9 / s,
                    d(cur.3, prev.3) / 1e9 / s,
                    d(cur.4, prev.4) / 1e9 / s,
                );
                prev = cur;
            }
        });
        Timeline(Some(stop))
    }
}

#[cfg(feature = "profile")]
pub use on::*;

#[cfg(not(feature = "profile"))]
mod off {
    use super::{C, K};
    use std::time::Instant;

    #[inline(always)]
    pub fn time<R>(_: C, f: impl FnOnce() -> R) -> R {
        f()
    }
    #[inline(always)]
    pub fn add_since(_: C, _: Instant) {}
    #[inline(always)]
    pub fn count(_: K, _: u64) {}
    #[inline(always)]
    pub fn depth(_: &str, default: usize) -> usize {
        default
    }
    #[inline(always)]
    pub fn report() {}

    pub struct Timeline;
    #[inline(always)]
    pub fn timeline(_: Instant, _: impl Fn() -> usize + Send + 'static) -> Timeline {
        Timeline
    }
}

#[cfg(not(feature = "profile"))]
pub use off::*;
