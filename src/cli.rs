//! Command-line interface definition.

use crate::extract::Compress;
use crate::xz::XzDecoder;
use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

/// xaea — fast extractor for Apple Encrypted Archives (Xcode edition)
#[derive(Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Parse and (optionally) verify an AEA file
    #[command(visible_alias = "i")]
    Inspect(InspectArgs),
    /// Extract an AEA's payload (e.g. `Xcode.app`) into a directory
    #[command(visible_alias = "x")]
    Extract(ExtractArgs),
    /// Print a shell-completion script to stdout (e.g. `xaea completions zsh`)
    Completions(CompletionsArgs),
    /// Write one regular file from an archive to stdout (e.g. `xaea cat Xcode.aea Xcode.app/Contents/Info.plist | plutil -p -`)
    #[command(visible_alias = "c")]
    Cat(CatArgs),
}

// Plain comments, not doc comments, on the argument structs: clap would
// otherwise take them as the subcommands' help text.

#[derive(Args)]
pub struct InspectArgs {
    /// Archive path; `-` reads the archive from standard input
    pub file: PathBuf,
    /// Machine-readable output
    #[arg(long)]
    pub json: bool,
    /// Verify MACs, signatures and all segment checksums
    #[arg(long)]
    pub verify: bool,
    /// Skip the full checksum pass when used with --verify
    #[arg(long)]
    pub no_checksums: bool,
    /// LZMA decoder: `liblzma` (vendored xz-utils, the default),
    /// `libcompression` (Apple's OS-provided library; macOS only; the
    /// two measure the same on full extracts) or `lzma-turbo` (pure Rust,
    /// ported from 7-Zip's decoder)
    #[arg(long, value_enum, default_value_t = XzDecoder::Liblzma)]
    pub decoder: XzDecoder,
}

#[derive(Args)]
pub struct ExtractArgs {
    /// Archive path; `-` reads the archive from standard input
    pub file: PathBuf,
    /// Directory to extract into (created if missing; default: the
    /// current directory). Aborts before writing anything if the
    /// archive's top-level entry (e.g. `Xcode.app`) already exists there.
    #[arg(default_value = ".")]
    pub out_dir: PathBuf,
    /// Machine-readable summary
    #[arg(long)]
    pub json: bool,
    /// Parse and decode everything, but write no files
    #[arg(long)]
    pub dry_run: bool,
    /// Skip all integrity and authenticity checks (signature, cert chain,
    /// MAC, checksums). Only for trusted or damaged archives: a tampered
    /// or corrupt archive extracts silently. You can still validate the
    /// extracted app afterwards with `codesign --verify --deep --strict`.
    /// Verification is on by default.
    #[arg(long)]
    pub no_verify: bool,
    /// Decoder threads (default: cores-1, min 2)
    #[arg(short, long)]
    pub jobs: Option<usize>,
    /// Writer threads; execute all filesystem syscalls (default: 6, or
    /// 10 when compressing, the macOS default)
    #[arg(short = 'w', long)]
    pub writers: Option<usize>,
    /// Decoded segments (~16 MiB each) buffered ahead of the parser
    /// (default: 1/8 of RAM worth, at most 160, at least decoders+4).
    /// The start of an Xcode archive is file-heavy and filesystem-bound;
    /// a deep buffer lets decoders run ahead meanwhile so the large-file
    /// tail is not decode-bound afterwards. Costs memory (up to ~+2 GiB
    /// peak vs 19); lower it on small machines.
    #[arg(long)]
    pub readahead: Option<usize>,
    /// Pre-reserve each file's extents before writing (helps on some
    /// volumes; measured neutral-to-worse on APFS/NVMe, so off by default)
    #[arg(long)]
    pub prealloc: bool,
    /// LZMA decoder: `liblzma` (vendored xz-utils, the default),
    /// `libcompression` (Apple's OS-provided library; macOS only; the
    /// two measure the same on full extracts) or `lzma-turbo` (pure Rust,
    /// ported from 7-Zip's decoder)
    #[arg(long, value_enum, default_value_t = XzDecoder::Liblzma)]
    pub decoder: XzDecoder,
    /// Store files with transparent APFS compression, as Apple's
    /// `archiveutil` does (an Xcode tree takes ~3.9 GiB on disk instead
    /// of ~10 GiB). The default on macOS; on a volume that can't hold
    /// compressed files, extraction quietly writes plain files instead
    /// (with this flag given explicitly, it warns).
    #[arg(long, overrides_with = "no_compress")]
    pub compress: bool,
    /// Write plain, uncompressed files (faster: ~8 s instead of ~12 s
    /// for an Xcode archive on M3 Max, at 2.6× the disk space)
    #[arg(long, overrides_with = "compress")]
    pub no_compress: bool,
}

#[derive(Args)]
pub struct CatArgs {
    /// Archive path; `-` reads the archive from standard input
    pub file: PathBuf,
    /// Path of the regular file within the archive, as extraction would
    /// place it (`./x` and `a/../x` normalize the same way). Directories
    /// and symlinks are refused: `cat` prints file contents, not link text.
    pub member: String,
    /// Skip all integrity and authenticity checks (signature, cert chain,
    /// MAC, checksums). Only for trusted or damaged archives. Verification
    /// is on by default.
    #[arg(long)]
    pub no_verify: bool,
    /// Decoder threads (default: cores-1, min 2)
    #[arg(short, long)]
    pub jobs: Option<usize>,
    /// LZMA decoder: `liblzma` (vendored xz-utils, the default),
    /// `libcompression` (Apple's OS-provided library; macOS only) or
    /// `lzma-turbo` (pure Rust, ported from 7-Zip's decoder)
    #[arg(long, value_enum, default_value_t = XzDecoder::Liblzma)]
    pub decoder: XzDecoder,
}

#[derive(Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: Shell,
}

impl ExtractArgs {
    /// The compression policy the `--compress`/`--no-compress` pair asks
    /// for: explicit flags win, otherwise compress on macOS only.
    pub fn compress_policy(&self) -> Compress {
        if self.no_compress {
            Compress::Off
        } else if self.compress {
            Compress::On
        } else if cfg!(target_os = "macos") {
            Compress::Auto
        } else {
            Compress::Off
        }
    }
}
