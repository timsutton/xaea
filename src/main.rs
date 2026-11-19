mod aa;
mod envelope;
mod extract;
mod kdf;
mod sigverify;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use envelope::XzDecoder;
use std::path::PathBuf;

/// unaea — fast extractor for Apple Encrypted Archives (Xcode edition)
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse and (optionally) verify an AEA file
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
    /// Extract an AEA's payload to a directory
    Extract {
        file: PathBuf,
        /// Output directory (created; must not be an existing non-empty dir)
        #[arg(short, long)]
        out: PathBuf,
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
        /// Writer threads; execute all filesystem syscalls (default: 6)
        #[arg(short = 'w', long)]
        writers: Option<usize>,
        /// Pre-reserve each file's extents before writing (helps on some
        /// volumes; measured neutral-to-worse on APFS/NVMe, so off by default)
        #[arg(long)]
        prealloc: bool,
        /// Tag extracted objects with com.apple.quarantine (macOS only)
        #[arg(long)]
        quarantine: bool,
        /// LZMA decoder: `liblzma` (vendored xz-utils, the default) or
        /// `libcompression` (Apple's OS-provided library; macOS only;
        /// roughly 5% faster full extracts measured on M3 Max)
        #[arg(long, value_enum, default_value_t = XzDecoder::Liblzma)]
        decoder: XzDecoder,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Inspect {
            file,
            json,
            verify,
            no_checksums,
            decoder,
        } => inspect(&file, json, verify, no_checksums, decoder),
        Commands::Extract {
            file,
            out,
            json,
            dry_run,
            no_verify,
            jobs,
            writers,
            prealloc,
            quarantine,
            decoder,
        } => extract_cmd(
            &file, &out, json, dry_run, no_verify, jobs, writers, prealloc, quarantine, decoder,
        ),
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
    decoder.check_available()?;
    let fstd = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let file = unsafe { memmap2::Mmap::map(&fstd).context("mmap")? };
    let env = envelope::Envelope::parse(&file)?;

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
            .context("no certificate-chain auth pair")?;
        let auth = sigverify::verify_all(
            &chain,
            sigverify::APPLE_ROOTS,
            &env.file[env.sig_off..env.sig_off + envelope::SIGNATURE_LEN],
            &env.signed_prefix(),
        )?;
        let mac = env
            .verify_mac(auth.certs[0].point())
            .context("MAC verification")?;
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
            let (ok, failed) =
                env.verify_checksums(std::thread::available_parallelism()?.get(), decoder)?;
            integrity_ok &= failed.is_empty();
            report_checks.push(serde_json::json!({
                "checksums_ok": ok, "checksums_failed": failed,
                "checksum_seconds": t0.elapsed().as_secs_f64(),
            }));
        }
        certs_summary = serde_json::json!(&auth
            .certs
            .iter()
            .map(|c| serde_json::json!({
                "subject": c.subject, "issuer": c.issuer, "sig_alg": c.sig_alg,
                "key": c.key_kind, "serial": c.serial,
                "valid": [c.not_before, c.not_after],
            }))
            .collect::<Vec<_>>());
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
            anyhow::bail!("verification FAILED (see checks in the JSON report)");
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
        anyhow::bail!("verification FAILED (see checks above)");
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
    prealloc: bool,
    quarantine: bool,
    decoder: XzDecoder,
) -> Result<()> {
    decoder.check_available()?;
    if quarantine && !cfg!(target_os = "macos") {
        anyhow::bail!("--quarantine is only meaningful on macOS");
    }
    let t0 = std::time::Instant::now();
    let fstd = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let file = unsafe { memmap2::Mmap::map(&fstd).context("mmap")? };
    let env = envelope::Envelope::parse(&file)?;
    anyhow::ensure!(
        !env.profile.encrypted(),
        "profile {} is encrypted: extraction supports profile 0 only \
         (encrypted profiles are inspect-only; supply a passphrase/KEM key in a future version)",
        env.profile.id()
    );
    if !dry_run && out.exists() {
        anyhow::ensure!(
            out.read_dir()?.next().is_none(),
            "output dir {} is not empty",
            out.display()
        );
    }
    // Tuned on M3 Max (16c): writers spend most of their time blocked on
    // fs syscalls, so decoders can safely oversubscribe the CPU — cores-1
    // beat every lower count in A/B runs (8.4s vs 9.1s).
    let cores = std::thread::available_parallelism()?.get();
    let opts = extract::Opts {
        out: out.to_path_buf(),
        dry: dry_run,
        decoders: jobs.unwrap_or_else(|| cores.saturating_sub(1).max(2)),
        writers: writers.unwrap_or(6),
        prealloc,
        quarantine,
        verify: !no_verify,
        decoder,
    };
    let st = extract::extract(&env, path, &opts)?;
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
                "decoders": opts.decoders, "writers": opts.writers,
                "dirs": st.dirs, "files": st.files, "links": st.links,
                "bytes": st.bytes, "seconds": secs, "mib_per_s": rate,
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
