//! Process exit codes and how errors are tagged with them.

use std::fmt;
use std::process::ExitCode;

/// Process exit codes. These are part of the CLI stability contract:
/// scripts may branch on them, so existing codes are never renumbered or
/// repurposed. See doc/ERROR-CODES.md for the full table, the reserved
/// ranges (126–128 and ≥128 stay off-limits: shell exec failures and
/// signal deaths), and what adding a new code requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Exit {
    /// 1 — unclassified failure: environment or internal errors not tied
    /// to the archive (thread spawn/panic, `available_parallelism`, JSON
    /// serialization).
    Generic = 1,
    /// 2 — usage error. clap exits 2 itself on argument errors; this
    /// variant covers option values rejected after parsing (e.g.
    /// `--decoder libcompression` off macOS).
    Usage = 2,
    /// 3 — the input archive could not be read: missing path, permission
    /// denied, input is a directory, mmap/IO failure.
    Unreadable = 3,
    /// 4 — the archive was read but rejected: bad magic, truncated or
    /// malformed envelope, bad geometry, or a valid archive this command
    /// cannot process (encrypted profile with `extract`).
    Rejected = 4,
    /// 5 — integrity/authenticity verification failed (`inspect --verify`:
    /// content signature, certificate chain, MACs, checksums).
    Verification = 5,
    /// 6 — extraction failed: output I/O, entry collisions, decode errors,
    /// and verification failures detected mid-extract (the streaming
    /// extractor folds those together; use `inspect --verify` for code 5).
    Extraction = 6,
}

impl Exit {
    /// SCREAMING_SNAKE_CASE name used in the `--json` error envelope.
    pub fn code_name(self) -> &'static str {
        match self {
            Exit::Generic => "GENERIC",
            Exit::Usage => "USAGE",
            Exit::Unreadable => "UNREADABLE",
            Exit::Rejected => "REJECTED",
            Exit::Verification => "VERIFICATION",
            Exit::Extraction => "EXTRACTION",
        }
    }
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        ExitCode::from(exit as u8)
    }
}

/// Attaches an [`Exit`] class to an anyhow error at the `main` boundary.
/// Display/source forward to the inner error, so stderr stays byte-identical
/// to a plain `fn main() -> Result<()>`; classification downcasts the error
/// chain and never inspects message text.
#[derive(Debug)]
struct Classified {
    exit: Exit,
    inner: anyhow::Error,
}

impl fmt::Display for Classified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl std::error::Error for Classified {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

/// Tag an error with its exit class.
pub fn classify(exit: Exit, inner: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(Classified { exit, inner })
}

/// `.with_exit(Exit::X)`: tag a failing result with its exit class.
pub trait WithExit<T> {
    fn with_exit(self, exit: Exit) -> anyhow::Result<T>;
}

impl<T, E: Into<anyhow::Error>> WithExit<T> for Result<T, E> {
    fn with_exit(self, exit: Exit) -> anyhow::Result<T> {
        self.map_err(|e| classify(exit, e.into()))
    }
}

/// Classified equivalent of `anyhow::bail!`.
macro_rules! bail_exit {
    ($exit:expr, $($arg:tt)+) => {
        return Err($crate::exit::classify($exit, anyhow::anyhow!($($arg)+)))
    };
}
pub(crate) use bail_exit;

/// Print a failed command's error, and map the result to the process exit
/// code. With `--json` the error goes to stderr as a machine-readable
/// object (`{"error":{"code","exit_code","message"}}`); stdout stays empty.
pub fn report(result: anyhow::Result<()>, json: bool) -> ExitCode {
    let Err(err) = result else {
        return ExitCode::SUCCESS;
    };
    let exit = err
        .chain()
        .find_map(|e| e.downcast_ref::<Classified>())
        .map_or(Exit::Generic, |c| c.exit);
    let full = match err.downcast_ref::<Classified>() {
        Some(c) => format!("{:?}", c.inner),
        None => format!("{err:?}"),
    };
    if json {
        let message = full.lines().next().unwrap_or("unknown error").to_string();
        eprintln!(
            "{}",
            serde_json::json!({
                "error": {
                    "code": exit.code_name(),
                    "exit_code": exit as u8,
                    "message": message,
                }
            })
        );
    } else {
        eprintln!("Error: {full}");
    }
    exit.into()
}
