//! Progress report on demand: on BSDs/macOS the tool answers `SIGINFO`
//! (Ctrl-T) with a one-line status, like `dd` and friends; on Linux, which
//! has no SIGINFO, the same report is available via `SIGUSR1`.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

/// Live counters mirrored from the parser sink; read only when the user
/// asks for status.
pub(super) struct Progress {
    pub(super) seg_done: AtomicUsize,
    pub(super) bytes_out: AtomicU64,
    pub(super) files: AtomicU64,
    pub(super) started: Instant,
}

impl Progress {
    pub(super) fn new() -> Self {
        Progress {
            seg_done: AtomicUsize::new(0),
            bytes_out: AtomicU64::new(0),
            files: AtomicU64::new(0),
            started: Instant::now(),
        }
    }
}

static STATUS_WANTED: AtomicBool = AtomicBool::new(false);
static STATUS_SHOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_status(_sig: libc::c_int) {
    // Async-signal-safe: only flips a flag; the parser prints.
    STATUS_WANTED.store(true, Relaxed);
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const STATUS_SIG: libc::c_int = libc::SIGINFO;
#[cfg(target_os = "linux")]
const STATUS_SIG: libc::c_int = libc::SIGUSR1;

pub(super) fn install_signal() {
    // SAFETY: `on_status` is an `extern "C" fn(c_int)` that only stores to
    // an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(STATUS_SIG, on_status as *const () as libc::sighandler_t);
    }
}

fn gib(n: u64) -> f64 {
    n as f64 / (1u64 << 30) as f64
}

pub(super) fn maybe_print(p: &Progress, nseg: usize) {
    if !STATUS_WANTED.swap(false, Relaxed) {
        return;
    }
    STATUS_SHOWN.store(true, Relaxed);
    let secs = p.started.elapsed().as_secs_f64().max(1e-6);
    let seg = p.seg_done.load(Relaxed);
    let bytes = p.bytes_out.load(Relaxed);
    eprint!(
        "\r\x1b[K ^T  seg {seg}/{nseg} ({:.0}%)  {:.2} GiB payload  {:.0} MiB/s  files {}  {secs:.1}s",
        100.0 * seg as f64 / nseg as f64,
        gib(bytes),
        bytes as f64 / secs / (1u64 << 20) as f64,
        p.files.load(Relaxed),
    );
}

/// Terminate a dangling status line so normal output starts fresh.
pub(super) fn end_line() {
    if STATUS_SHOWN.swap(false, Relaxed) {
        eprintln!();
    }
}
