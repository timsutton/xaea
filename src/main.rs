mod aa;
mod decmpfs;
mod envelope;
mod extract;
mod kdf;
mod prof;
mod sigverify;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use envelope::XzDecoder;
use std::path::PathBuf;
use std::process::ExitCode;

/// xaea — fast extractor for Apple Encrypted Archives (Xcode edition)
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse and (optionally) verify an AEA file
    #[command(visible_alias = "i")]
    Inspect {
        file: PathBuf,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
        /// Verify MACs, signatures and all segment checksums
        #[arg(long)]
        verify: bool,
        /// Skip the full checksum pass when used with --verify
        #[arg(long)]
        no_checksums: bool,
        /// LZMA decoder: `liblzma` (vendored xz-utils, the default) or
        /// `libcompression` (Apple's OS-provided library; macOS only;
        /// roughly 5% faster full extracts measured on M3 Max)
        #[arg(long, value_enum, default_value_t = XzDecoder::Liblzma)]
        decoder: XzDecoder,
    },
    /// Extract an AEA's payload (e.g. `Xcode.app`) into a directory
    #[command(visible_alias = "x")]
    Extract {
        file: PathBuf,
        /// Directory to extract into (created if missing; default: the
        /// current directory). Aborts before writing anything if the
        /// archive's top-level entry (e.g. `Xcode.app`) already exists there.
        #[arg(default_value = ".")]
        out_dir: PathBuf,
        /// Machine-readable summary
        #[arg(long)]
        json: bool,
        /// Parse and decode everything, but write no files
        #[arg(long)]
        dry_run: bool,
        /// Skip all integrity and authenticity checks (signature, cert chain,
        /// MAC, checksums). Only for trusted or damaged archives: a tampered
        /// or corrupt archive extracts silently. You can still validate the
        /// extracted app afterwards with `codesign --verify --deep --strict`.
        /// Verification is on by default.
        #[arg(long)]
        no_verify: bool,
        /// Decoder threads (default: cores-1, min 2)
        #[arg(short, long)]
        jobs: Option<usize>,
        /// Writer threads; execute all filesystem syscalls (default: 6, or
        /// 10 when compressing, the macOS default)
        #[arg(short = 'w', long)]
        writers: Option<usize>,
        /// Decoded segments (~16 MiB each) buffered ahead of the parser
        /// (default: 1/8 of RAM worth, at most 160, at least decoders+4).
        /// The start of an Xcode archive is file-heavy and filesystem-bound;
        /// a deep buffer lets decoders run ahead meanwhile so the large-file
        /// tail is not decode-bound afterwards. Costs memory (up to ~+2 GiB
        /// peak vs 19); lower it on small machines.
        #[arg(long)]
        readahead: Option<usize>,
        /// Pre-reserve each file's extents before writing (helps on some
        /// volumes; measured neutral-to-worse on APFS/NVMe, so off by default)
        #[arg(long)]
        prealloc: bool,
        /// LZMA decoder: `liblzma` (vendored xz-utils, the default) or
        /// `libcompression` (Apple's OS-provided library; macOS only;
        /// roughly 5% faster full extracts measured on M3 Max)
        #[arg(long, value_enum, default_value_t = XzDecoder::Liblzma)]
        decoder: XzDecoder,
        /// Store files with transparent APFS compression, as Apple's
        /// `archiveutil` does (an Xcode tree takes ~3.9 GiB on disk instead
        /// of ~10 GiB). The default on macOS; on a volume that can't hold
        /// compressed files, extraction quietly writes plain files instead
        /// (with this flag given explicitly, it warns).
        #[arg(long, overrides_with = "no_compress")]
        compress: bool,
        /// Write plain, uncompressed files (faster: ~8 s instead of ~12 s
        /// for an Xcode archive on M3 Max, at 2.6× the disk space)
        #[arg(long, overrides_with = "compress")]
        no_compress: bool,
    },
}

/// Process exit codes. These are part of the CLI stability contract:
/// scripts may branch on them, so existing codes are never renumbered or
/// repurposed. See doc/ERROR-CODES.md for the full table, the reserved
/// ranges (126–128 and ≥128 stay off-limits: shell exec failures and
/// signal deaths), and what adding a new code requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
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

/// Attaches an [`Exit`] class to an anyhow error at the `main` boundary.
/// Display/source forward to the inner error, so stderr stays byte-identical
/// to a plain `fn main() -> Result<()>`; classification downcasts the error
/// chain and never inspects message text.
#[derive(Debug)]
struct Classified {
    exit: Exit,
    inner: anyhow::Error,
}

impl std::fmt::Display for Classified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

impl std::error::Error for Classified {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

/// `map_err(classified(Exit::X))`: tag an error with its exit class.
fn classified(exit: Exit) -> impl FnOnce(anyhow::Error) -> anyhow::Error {
    move |inner| anyhow::Error::new(Classified { exit, inner })
}

/// Classified equivalent of `anyhow::bail!`.
macro_rules! bail_exit {
    ($exit:expr, $($arg:tt)+) => {
        return Err(classified($exit)(anyhow::anyhow!($($arg)+)))
    };
}

fn main() -> ExitCode {
    // clap handles --help/--version (exit 0) and usage errors (exit 2) itself.
    let cli = Cli::parse();
    let result = match cli.cmd {
        Commands::Inspect {
            file,
            json,
            verify,
            no_checksums,
            decoder,
        } => inspect(&file, json, verify, no_checksums, decoder),
        Commands::Extract {
            file,
            out_dir,
            json,
            dry_run,
            no_verify,
            jobs,
            writers,
            readahead,
            prealloc,
            decoder,
            compress,
            no_compress,
        } => extract_cmd(
            &file,
            &out_dir,
            json,
            dry_run,
            no_verify,
            jobs,
            writers,
            readahead,
            prealloc,
            decoder,
            if no_compress {
                extract::Compress::Off
            } else if compress {
                extract::Compress::On
            } else if cfg!(target_os = "macos") {
                extract::Compress::Auto
            } else {
                extract::Compress::Off
            },
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let exit = err
                .chain()
                .find_map(|e| e.downcast_ref::<Classified>())
                .map_or(Exit::Generic, |c| c.exit);
            // Print exactly what `fn main() -> Result<()>` would have.
            match err.downcast_ref::<Classified>() {
                Some(c) => eprintln!("Error: {:?}", c.inner),
                None => eprintln!("Error: {err:?}"),
            }
            ExitCode::from(exit as u8)
        }
    }
}

fn human(n: u64) -> String {
    const U: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < 3 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.2} {}", U[i])
}

fn inspect(
    path: &std::path::Path,
    json: bool,
    verify: bool,
    no_checksums: bool,
    decoder: XzDecoder,
) -> Result<()> {
    decoder.check_available().map_err(classified(Exit::Usage))?;
    let fstd = std::fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))
        .map_err(classified(Exit::Unreadable))?;
    let file = unsafe { memmap2::Mmap::map(&fstd) }
        .context("mmap")
        .map_err(classified(Exit::Unreadable))?;
    let env = envelope::Envelope::parse(&file).map_err(classified(Exit::Rejected))?;

    let mut report_checks = Vec::new();
    let mut certs_summary = serde_json::json!(null);
    // Every integrity check folded in (any false ⇒ non-zero exit, review
    // #3). trusted_root is *reported* but does not fail: re-signed or
    // private-CA archives stay inspectable.
    let mut integrity_ok = true;

    if verify {
        // Signature & chain first: the leaf signing key feeds the main-key KDF.
        let chain = env
            .auth
            .iter()
            .find(|(k, _)| k.ends_with(".signature.certificate-chain"))
            .map(|(_, v)| v.clone())
            .context("no certificate-chain auth pair")
            .map_err(classified(Exit::Rejected))?;
        let auth = sigverify::verify_all(
            &chain,
            sigverify::APPLE_ROOTS,
            &env.file[env.sig_off..env.sig_off + envelope::SIGNATURE_LEN],
            &env.signed_prefix(),
        )
        .map_err(classified(Exit::Verification))?;
        let mac = env
            .verify_mac(auth.certs[0].point())
            .context("MAC verification")
            .map_err(classified(Exit::Verification))?;
        integrity_ok &= mac.root_mac_ok && mac.cluster_macs_ok && mac.segmac_failed.is_empty();
        report_checks.push(serde_json::json!({
            "root_mac_ok": mac.root_mac_ok,
            "cluster_macs_ok": mac.cluster_macs_ok,
            "chmac_salt_variant": mac.chmac_variant,
            "segment_macs_ok": mac.segmac_failed.is_empty(),
            "segment_macs_failed": mac.segmac_failed,
        }));
        if !no_checksums {
            let t0 = std::time::Instant::now();
            let (ok, failed) = env
                .verify_checksums(std::thread::available_parallelism()?.get(), decoder)
                .map_err(classified(Exit::Verification))?;
            integrity_ok &= failed.is_empty();
            report_checks.push(serde_json::json!({
                "checksums_ok": ok, "checksums_failed": failed,
                "checksum_seconds": t0.elapsed().as_secs_f64(),
            }));
        }
        certs_summary = serde_json::json!(
            &auth
                .certs
                .iter()
                .map(|c| serde_json::json!({
                    "subject": c.subject, "issuer": c.issuer, "sig_alg": c.sig_alg,
                    "key": c.key_kind, "serial": c.serial,
                    "valid": [c.not_before, c.not_after],
                }))
                .collect::<Vec<_>>()
        );
        integrity_ok &= auth.content_sig_ok
            && auth.sig_padded_ok
            && auth.chain_all_ok
            && auth.ca_ok
            && auth.valid_now;
        report_checks.push(serde_json::json!({
            "content_signature_ok": auth.content_sig_ok,
            "signature_padded_ok": auth.sig_padded_ok,
            "chain_ok": auth.chain_ok,
            "chain_all_ok": auth.chain_all_ok,
            "ca_ok": auth.ca_ok,
            "valid_now": auth.valid_now,
            "trusted_root": auth.trusted_root,
        }));
    }

    let summary = serde_json::json!({
        "file": path.file_name().map(|s| s.to_string_lossy().to_string()),
        "format": "AEA1",
        "profile": env.profile.id(),
        "profile_name": "hkdf_sha256_hmac__none__ecdsa_p256",
        "scrypt_strength": env.scrypt_strength,
        "file_size": file.len(),
        "auth": env.auth.iter().map(|(k, v)| serde_json::json!({"key": k, "bytes": v.len()})).collect::<Vec<_>>(),
        "root": {
            "original_size": env.root.original_size,
            "encarchive_size": env.root.encarchive_size,
            "segment_size": env.root.segment_size,
            "segments_per_cluster": env.root.segments_per_cluster,
            "compression": envelope::compression_name(env.root.compression),
            "checksum": envelope::checksum_name(env.root.checksum),
        },
        "clusters": env.clusters.len(),
        "segments": env.total_segments,
        "geometry_ok": true,
        "checks": report_checks,
    });

    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        if verify && !integrity_ok {
            bail_exit!(
                Exit::Verification,
                "verification FAILED (see checks in the JSON report)"
            );
        }
        return Ok(());
    }

    println!(
        "{}  —  AEA1, profile {} (no encryption, signed)",
        path.display(),
        env.profile.id()
    );
    println!(
        "  compressed {:.2} GiB → original {} (ratio {:.2}×)",
        file.len() as f64 / (1u64 << 30) as f64,
        human(env.root.original_size),
        env.root.original_size as f64 / file.len() as f64
    );
    println!(
        "  segments: {} × ≤{} in {} clusters of {}, checksum={}, compression={}",
        env.total_segments,
        human(env.root.segment_size as u64),
        env.clusters.len(),
        env.root.segments_per_cluster,
        envelope::checksum_name(env.root.checksum),
        envelope::compression_name(env.root.compression),
    );
    println!("  geometry: segment walk lands exactly on EOF ✓");
    for (k, v) in &env.auth {
        println!("  auth: {k} ({} bytes)", v.len());
    }

    if verify {
        for check in &report_checks {
            println!("  check: {check}");
        }
        if let serde_json::Value::Array(cs) = &certs_summary {
            for c in cs {
                println!(
                    "  cert: {}  ← {}  [{} {}]",
                    c["subject"].as_str().unwrap_or("?"),
                    c["issuer"].as_str().unwrap_or("?"),
                    c["key"].as_str().unwrap_or("?"),
                    c["sig_alg"].as_str().unwrap_or("?"),
                );
            }
        }
    }
    if verify && !integrity_ok {
        bail_exit!(Exit::Verification, "verification FAILED (see checks above)");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn extract_cmd(
    path: &std::path::Path,
    out: &std::path::Path,
    json: bool,
    dry_run: bool,
    no_verify: bool,
    jobs: Option<usize>,
    writers: Option<usize>,
    readahead: Option<usize>,
    prealloc: bool,
    decoder: XzDecoder,
    compress: extract::Compress,
) -> Result<()> {
    decoder.check_available().map_err(classified(Exit::Usage))?;
    let t0 = std::time::Instant::now();
    let fstd = std::fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))
        .map_err(classified(Exit::Unreadable))?;
    let file = unsafe { memmap2::Mmap::map(&fstd) }
        .context("mmap")
        .map_err(classified(Exit::Unreadable))?;
    let env = envelope::Envelope::parse(&file).map_err(classified(Exit::Rejected))?;
    if env.profile.encrypted() {
        bail_exit!(
            Exit::Rejected,
            "profile {} is encrypted: extraction supports profile 0 only \
             (encrypted profiles are inspect-only; supply a passphrase/KEM key in a future version)",
            env.profile.id()
        );
    }
    // No up-front "dir must be empty" check any more: extracting into a
    // populated directory (the cwd, by default) is fine. Collisions with
    // the archive's own top-level entries are caught by the extractor
    // before it writes the first byte of the colliding entry.
    // Tuned on M3 Max (16c): writers spend most of their time blocked on
    // fs syscalls, so decoders can safely oversubscribe the CPU — cores-1
    // beat every lower count in A/B runs (8.4s vs 9.1s).
    let cores = std::thread::available_parallelism()?.get();
    let decoders = jobs.unwrap_or_else(|| cores.saturating_sub(1).max(2));
    // Output I/O (it may create `out` to probe it), so it joins the other
    // output-side failures under code 6.
    let compress =
        extract::resolve_compress(out, compress, dry_run).map_err(classified(Exit::Extraction))?;
    let opts = extract::Opts {
        out: out.to_path_buf(),
        dry: dry_run,
        decoders,
        // Compressing makes writers CPU-bound (LZBITMAP runs ~350 MB/s per
        // core), so they want more threads: on M3 Max, 6 → 13.7 s, 8 → 12.7 s,
        // 10 → 12.6 s, 14 → 12.4 s for the Xcode 27.3 b2 archive.
        writers: writers.unwrap_or(if compress { 10 } else { 6 }),
        readahead: readahead.unwrap_or(extract::default_readahead(
            extract::physical_ram(),
            env.segments()
                .iter()
                .map(|s| s.orig as usize)
                .max()
                .unwrap_or(0),
            decoders,
        )),
        prealloc,
        verify: !no_verify,
        decoder,
        compress,
    };
    let st = extract::extract(&env, path, &opts).map_err(classified(Exit::Extraction))?;
    let secs = t0.elapsed().as_secs_f64();
    let rate = st.bytes as f64 / secs / (1u64 << 20) as f64;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "out": out.display().to_string(),
                "dry_run": dry_run,
                "verified": !no_verify,
                "decoder": decoder.name(),
                "decoders": opts.decoders, "writers": opts.writers, "readahead": opts.readahead,
                "dirs": st.dirs, "files": st.files, "links": st.links,
                "bytes": st.bytes, "compressed": st.compressed,
                "seconds": secs, "mib_per_s": rate,
            })
        );
    } else {
        println!(
            "{} {} dirs, {} files, {} links ({}) in {secs:.1}s ({rate:.0} MiB/s payload, {} decoders, {} writers)",
            if dry_run { "verified" } else { "extracted" },
            st.dirs,
            st.files,
            st.links,
            human(st.bytes),
            opts.decoders,
            opts.writers,
        );
    }
    Ok(())
}
