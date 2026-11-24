//! `xaea inspect`: describe an archive and, with `--verify`, check it.

use super::{human, open_archive};
use crate::cli::InspectArgs;
use crate::envelope::Envelope;
use crate::exit::{Exit, WithExit, bail_exit};
use crate::sigverify::{self, ParsedCert};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::time::Instant;

/// The outcome of `--verify`, kept as typed values so the human report and
/// the `--json` report are rendered from the same data.
struct Verification {
    certs: Vec<ParsedCert>,
    root_mac_ok: bool,
    cluster_macs_ok: bool,
    chmac_variant: Option<usize>,
    segment_macs_failed: Vec<u32>,
    /// `None` when the checksum pass was skipped (`--no-checksums`).
    checksums: Option<Checksums>,
    content_sig_ok: bool,
    sig_padded_ok: bool,
    chain_ok: Vec<bool>,
    chain_all_ok: bool,
    ca_ok: bool,
    valid_now: bool,
    trusted_root: bool,
    /// Every integrity check passed (any false ⇒ non-zero exit, review
    /// #3). `trusted_root` is *reported* but does not count: re-signed or
    /// private-CA archives stay inspectable.
    ok: bool,
}

/// The per-segment checksum pass (skipped with `--no-checksums`).
struct Checksums {
    passed: u64,
    failed: Vec<u32>,
    total: u64,
    seconds: f64,
}

impl Verification {
    /// One JSON object per group of checks, in report order.
    fn checks_json(&self) -> Vec<Value> {
        let mut checks = vec![json!({
            "root_mac_ok": self.root_mac_ok,
            "cluster_macs_ok": self.cluster_macs_ok,
            "chmac_salt_variant": self.chmac_variant,
            "segment_macs_ok": self.segment_macs_failed.is_empty(),
            "segment_macs_failed": self.segment_macs_failed,
        })];
        if let Some(c) = &self.checksums {
            checks.push(json!({
                "checksums_ok": c.passed,
                "checksums_failed": c.failed,
                "checksum_seconds": c.seconds,
            }));
        }
        checks.push(json!({
            "content_signature_ok": self.content_sig_ok,
            "signature_padded_ok": self.sig_padded_ok,
            "chain_ok": self.chain_ok,
            "chain_all_ok": self.chain_all_ok,
            "ca_ok": self.ca_ok,
            "valid_now": self.valid_now,
            "trusted_root": self.trusted_root,
        }));
        checks
    }
}

pub fn run(args: &InspectArgs) -> Result<()> {
    args.decoder.check_available().with_exit(Exit::Usage)?;
    let archive = open_archive(&args.file)?;
    let file = &archive.map[..];
    let env = Envelope::parse(file).with_exit(Exit::Rejected)?;
    let verification = args.verify.then(|| verify(&env, args)).transpose()?;

    if args.json {
        let summary = json!({
            "file": args.file.file_name().map(|s| s.to_string_lossy().to_string()),
            "format": "AEA1",
            "profile": env.profile.id(),
            "profile_name": "hkdf_sha256_hmac__none__ecdsa_p256",
            "scrypt_strength": env.scrypt_strength,
            "file_size": file.len(),
            "auth": env.auth.iter().map(|(k, v)| json!({"key": k, "bytes": v.len()})).collect::<Vec<_>>(),
            "root": {
                "original_size": env.root.original_size,
                "encarchive_size": env.root.encarchive_size,
                "segment_size": env.root.segment_size,
                "segments_per_cluster": env.root.segments_per_cluster,
                "compression": env.root.compression.to_string(),
                "checksum": env.root.checksum.to_string(),
            },
            "clusters": env.clusters.len(),
            "segments": env.total_segments,
            "geometry_ok": true,
            "checks": verification.as_ref().map_or(Vec::new(), Verification::checks_json),
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
        if verification.is_some_and(|v| !v.ok) {
            bail_exit!(
                Exit::Verification,
                "verification FAILED (see checks in the JSON report)"
            );
        }
        return Ok(());
    }

    println!(
        "{}  —  AEA1, profile {} (no encryption, signed)",
        archive.src.label,
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
        human(u64::from(env.root.segment_size)),
        env.clusters.len(),
        env.root.segments_per_cluster,
        env.root.checksum,
        env.root.compression,
    );
    println!("  geometry: segment walk lands exactly on EOF ✓");
    for (k, v) in &env.auth {
        println!("  auth: {k} ({} bytes)", v.len());
    }

    if let Some(v) = verification {
        print_checks(&v);
        for c in &v.certs {
            println!(
                "  cert: {}  ← {}  [{} {}]",
                c.subject, c.issuer, c.key_kind, c.sig_alg
            );
        }
        if !v.ok {
            bail_exit!(Exit::Verification, "verification FAILED (see checks above)");
        }
    }
    Ok(())
}

fn print_checks(v: &Verification) {
    let sym = |ok: bool| if ok { "✓" } else { "✗" };
    println!("  {} root MACs", sym(v.root_mac_ok));
    let salt = v
        .chmac_variant
        .map(|n| format!(" (salt layout {n})"))
        .unwrap_or_default();
    println!("  {} cluster MACs{salt}", sym(v.cluster_macs_ok));
    if v.segment_macs_failed.is_empty() {
        println!("  ✓ segment MACs");
    } else {
        println!(
            "  ✗ segment MACs — failed segments: {}",
            v.segment_macs_failed
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(c) = &v.checksums {
        if c.failed.is_empty() {
            println!(
                "  ✓ segment checksums ({}/{} in {:.2}s)",
                c.passed, c.total, c.seconds
            );
        } else {
            println!(
                "  ✗ segment checksums — {} of {} failed",
                c.failed.len(),
                c.total
            );
        }
    }
    println!("  {} content signature", sym(v.content_sig_ok));
    println!("  {} signature padding", sym(v.sig_padded_ok));
    println!(
        "  {} certificate chain ({} links)",
        sym(v.chain_all_ok),
        v.chain_ok.len()
    );
    println!("  {} issuers are CA:true", sym(v.ca_ok));
    println!("  {} certificates within validity window", sym(v.valid_now));
    println!(
        "  {} trusted Apple root (reported, not a gate)",
        sym(v.trusted_root)
    );
}

/// Run every check `--verify` asks for. Checks that run and fail are
/// reported, not raised; errors are archives too malformed to check.
fn verify(env: &Envelope, args: &InspectArgs) -> Result<Verification> {
    // Signature & chain first: the leaf signing key feeds the main-key KDF.
    let chain = env
        .certificate_chain()
        .context("no certificate-chain auth pair")
        .with_exit(Exit::Rejected)?;
    let auth = sigverify::verify_all(
        chain,
        sigverify::APPLE_ROOTS,
        env.signature(),
        &env.signed_prefix(),
    )
    .with_exit(Exit::Verification)?;
    let mac = env
        .verify_mac(auth.certs[0].point())
        .context("MAC verification")
        .with_exit(Exit::Verification)?;
    let mut ok = mac.root_mac_ok && mac.cluster_macs_ok && mac.segmac_failed.is_empty();
    let mut checksums = None;
    if !args.no_checksums {
        let t0 = Instant::now();
        let (passed, failed) = env
            .verify_checksums(std::thread::available_parallelism()?.get(), args.decoder)
            .with_exit(Exit::Verification)?;
        ok &= failed.is_empty();
        checksums = Some(Checksums {
            passed,
            total: passed + failed.len() as u64,
            failed,
            seconds: t0.elapsed().as_secs_f64(),
        });
    }
    ok &= auth.content_sig_ok
        && auth.sig_padded_ok
        && auth.chain_all_ok
        && auth.ca_ok
        && auth.valid_now;
    Ok(Verification {
        certs: auth.certs,
        root_mac_ok: mac.root_mac_ok,
        cluster_macs_ok: mac.cluster_macs_ok,
        chmac_variant: mac.chmac_variant,
        segment_macs_failed: mac.segmac_failed,
        checksums,
        content_sig_ok: auth.content_sig_ok,
        sig_padded_ok: auth.sig_padded_ok,
        chain_ok: auth.chain_ok,
        chain_all_ok: auth.chain_all_ok,
        ca_ok: auth.ca_ok,
        valid_now: auth.valid_now,
        trusted_root: auth.trusted_root,
        ok,
    })
}
