//! `xaea extract`: unpack an archive's payload into a directory.

use super::{human, open_archive};
use crate::cli::ExtractArgs;
use crate::envelope::Envelope;
use crate::exit::{Exit, WithExit, bail_exit};
use crate::extract;
use anyhow::Result;
use std::path::Path;
use std::time::Instant;

pub fn run(args: &ExtractArgs) -> Result<()> {
    args.decoder.check_available().with_exit(Exit::Usage)?;
    let out = args.out_dir.as_path();
    if out == Path::new("-") {
        bail_exit!(
            Exit::Usage,
            "`-` names standard input, which is not an output directory"
        );
    }
    let t0 = Instant::now();
    // `archive.src` (for `-`, the spool) must outlive extract(), which
    // re-opens the path for its pread segment reads.
    let archive = open_archive(&args.file)?;
    let env = Envelope::parse(&archive.map, None).with_exit(Exit::Rejected)?;
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
    let decoders = args.jobs.unwrap_or_else(|| cores.saturating_sub(1).max(2));
    // Output I/O (it may create `out` to probe it), so it joins the other
    // output-side failures under code 6.
    let compress = extract::resolve_compress(out, args.compress_policy(), args.dry_run)
        .with_exit(Exit::Extraction)?;
    let opts = extract::Opts {
        out: out.to_path_buf(),
        dry: args.dry_run,
        decoders,
        // Compressing makes writers CPU-bound (LZBITMAP runs ~350 MB/s per
        // core), so they want more threads: on M3 Max, 6 → 13.7 s, 8 → 12.7 s,
        // 10 → 12.6 s, 14 → 12.4 s for the Xcode 27.3 b2 archive.
        writers: args.writers.unwrap_or(if compress { 10 } else { 6 }),
        readahead: args.readahead.unwrap_or_else(|| {
            let largest = env.segments().map(|s| s.orig as usize).max().unwrap_or(0);
            extract::default_readahead(extract::physical_ram(), largest, decoders)
        }),
        prealloc: args.prealloc,
        verify: !args.no_verify,
        decoder: args.decoder,
        compress,
    };
    let st = extract::extract(&env, &archive.src.path, &opts).with_exit(Exit::Extraction)?;
    let secs = t0.elapsed().as_secs_f64();
    let rate = st.bytes as f64 / secs / (1u64 << 20) as f64;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "out": out.display().to_string(),
                "dry_run": args.dry_run,
                "verified": opts.verify,
                "decoder": args.decoder.name(),
                "decoders": opts.decoders, "writers": opts.writers, "readahead": opts.readahead,
                "dirs": st.dirs, "files": st.files, "links": st.links,
                "bytes": st.bytes, "compressed": st.compressed,
                "seconds": secs, "mib_per_s": rate,
            })
        );
    } else {
        println!(
            "{} {} dirs, {} files, {} links ({}) in {secs:.1}s ({rate:.0} MiB/s payload, {} decoders, {} writers)",
            if args.dry_run {
                "verified"
            } else {
                "extracted"
            },
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
