//! `xaea inspect`: describe an archive and, with `--verify`, check it.

use super::{archive_key, human, open_archive, parse_envelope};
use crate::cli::InspectArgs;
use crate::envelope::{Envelope, Prelude};
use crate::exit::{Exit, WithExit, bail_exit};
use crate::sigverify::{self, ParsedCert};
use crate::wkms;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::time::Instant;

/// The outcome of `--verify`.
struct Verification {
    /// One JSON object per group of checks, in report order.
    checks: Vec<Value>,
    certs: Vec<ParsedCert>,
    /// Every integrity check passed (any false ⇒ non-zero exit, review
    /// #3). `trusted_root` is *reported* but does not count: re-signed or
    /// private-CA archives stay inspectable.
    ok: bool,
}

pub fn run(args: &InspectArgs) -> Result<()> {
    args.decoder.check_available().with_exit(Exit::Usage)?;
    let archive = open_archive(&args.file)?;
    let file = &archive.map[..];
    let prelude = Prelude::parse(file).with_exit(Exit::Rejected)?;
    if prelude.profile.encrypted() && !args.verify && archive_key(&args.key, &prelude)?.is_none() {
        // Everything after the auth data is encrypted: describe what the
        // archive says about itself and where its key comes from.
        return describe_locked(args, &archive.src.label, file.len(), &prelude);
    }
    let env = parse_envelope(file, &args.key)?;
    let verification = args.verify.then(|| verify(&env, args)).transpose()?;
    let checks = verification.as_ref().map_or(&[][..], |v| &v.checks[..]);

    if args.json {
        let summary = json!({
            "file": args.file.file_name().map(|s| s.to_string_lossy().to_string()),
            "format": "AEA1",
            "profile": env.profile.id(),
            "profile_name": env.profile.name(),
            "encrypted": env.profile.encrypted(),
            "scrypt_strength": env.scrypt_strength,
            "file_size": file.len(),
            "auth": env.auth.iter().map(|(k, v)| json!({"key": k, "bytes": v.len()})).collect::<Vec<_>>(),
            "key_url": wkms::key_url(&env.auth),
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
            "padding": env.padding,
            "geometry_ok": true,
            "checks": checks,
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
        "{}  —  AEA1, profile {} ({})",
        archive.src.label,
        env.profile.id(),
        env.profile.describe()
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
    if env.padding == 0 {
        println!("  geometry: segment walk lands exactly on EOF ✓");
    } else {
        println!(
            "  geometry: segment walk ends {} before EOF, in random padding up to encarchive_size ✓",
            human(env.padding as u64)
        );
    }
    print_auth(&env.auth);

    if let Some(v) = verification {
        for check in &v.checks {
            println!("  check: {check}");
        }
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

fn print_auth(auth: &[(String, Vec<u8>)]) {
    for (k, v) in auth {
        println!("  auth: {k} ({} bytes)", v.len());
    }
    if let Some(url) = wkms::key_url(auth) {
        println!("  key: unwrapped by the PEM at {url}");
    }
}

/// `inspect` of an encrypted archive without its key: only the prelude is
/// readable.
fn describe_locked(args: &InspectArgs, label: &str, size: usize, p: &Prelude) -> Result<()> {
    if args.json {
        let summary = json!({
            "file": args.file.file_name().map(|s| s.to_string_lossy().to_string()),
            "format": "AEA1",
            "profile": p.profile.id(),
            "profile_name": p.profile.name(),
            "encrypted": true,
            "scrypt_strength": p.scrypt_strength,
            "file_size": size,
            "auth": p.auth.iter().map(|(k, v)| json!({"key": k, "bytes": v.len()})).collect::<Vec<_>>(),
            "key_url": wkms::key_url(&p.auth),
            "root": null,
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }
    println!(
        "{label}  —  AEA1, profile {} ({})",
        p.profile.id(),
        p.profile.describe()
    );
    println!("  {}; headers are encrypted", human(size as u64));
    print_auth(&p.auth);
    println!("  pass --key or --key-pem to read the geometry and --verify it");
    Ok(())
}

/// Run every check `--verify` asks for. Checks that run and fail are
/// reported, not raised; errors are archives too malformed to check.
fn verify(env: &Envelope, args: &InspectArgs) -> Result<Verification> {
    if env.profile.encrypted() {
        return verify_encrypted(env, args);
    }
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
    let mac = env.verify_mac(auth.certs[0].point());
    let mut ok = mac.root_mac_ok && mac.cluster_macs_ok && mac.segmac_failed.is_empty();
    let mut checks = vec![json!({
        "root_mac_ok": mac.root_mac_ok,
        "cluster_macs_ok": mac.cluster_macs_ok,
        "chmac_salt_variant": mac.chmac_variant,
        "segment_macs_ok": mac.segmac_failed.is_empty(),
        "segment_macs_failed": mac.segmac_failed,
    })];
    if !args.no_checksums {
        let t0 = Instant::now();
        let (passed, failed) = env
            .verify_checksums(std::thread::available_parallelism()?.get(), args.decoder)
            .with_exit(Exit::Verification)?;
        ok &= failed.is_empty();
        checks.push(json!({
            "checksums_ok": passed, "checksums_failed": failed,
            "checksum_seconds": t0.elapsed().as_secs_f64(),
        }));
    }
    ok &= auth.content_sig_ok
        && auth.sig_padded_ok
        && auth.chain_all_ok
        && auth.ca_ok
        && auth.valid_now;
    checks.push(json!({
        "content_signature_ok": auth.content_sig_ok,
        "signature_padded_ok": auth.sig_padded_ok,
        "chain_ok": auth.chain_ok,
        "chain_all_ok": auth.chain_all_ok,
        "ca_ok": auth.ca_ok,
        "valid_now": auth.valid_now,
        "trusted_root": auth.trusted_root,
    }));
    Ok(Verification {
        checks,
        certs: auth.certs,
        ok,
    })
}

/// `--verify` for an encrypting profile: no signature to check, and the
/// root MAC already held when the key opened the envelope.
fn verify_encrypted(env: &Envelope, args: &InspectArgs) -> Result<Verification> {
    let mac = env.verify_mac(&[]);
    let mut ok = mac.root_mac_ok
        && mac.cluster_macs_ok
        && mac.padding_mac_ok != Some(false)
        && mac.segmac_failed.is_empty();
    let mut checks = vec![json!({
        "root_mac_ok": mac.root_mac_ok,
        "cluster_macs_ok": mac.cluster_macs_ok,
        "padding_mac_ok": mac.padding_mac_ok,
        "segment_macs_ok": mac.segmac_failed.is_empty(),
        "segment_macs_failed": mac.segmac_failed,
    })];
    if !args.no_checksums {
        let t0 = Instant::now();
        let (passed, failed) = env
            .verify_checksums(std::thread::available_parallelism()?.get(), args.decoder)
            .with_exit(Exit::Verification)?;
        ok &= failed.is_empty();
        checks.push(json!({
            "checksums_ok": passed, "checksums_failed": failed,
            "checksum_seconds": t0.elapsed().as_secs_f64(),
        }));
    }
    Ok(Verification {
        checks,
        certs: Vec::new(),
        ok,
    })
}
