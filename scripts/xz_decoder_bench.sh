#!/usr/bin/env bash
# Single-thread microbenchmark of the segment decoders: xz 5.2.5
# (lzma-sys 0.1.20, what xaea used before) vs xz 5.8.4 (liblzma-sys 0.4.9,
# what it uses now), with and without LZMA_IGNORE_CHECK, and the same
# streams through lzma-turbo (pure Rust). The liblzma crates link the same
# native library name, so they are built as tiny projects alongside the
# lzma-turbo one.
#
#   scripts/xz_decoder_bench.sh [INPUT]   # default: a 16 MiB slice of the
#                                         # largest file in the Xcode in /Applications
#
# Needs: cargo, xz(1) (only to make the test .xz), and network for crates.io
# on the first run. Output: best/mean ms and MiB/s per variant.
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
size=$((16 * 1024 * 1024))

if [ $# -ge 1 ]; then
    src=$1
else
    src=$(find /Applications/Xcode*.app/Contents/SharedFrameworks -type f -size +60M 2>/dev/null | head -1)
    [ -n "$src" ] || { echo "no input found; pass a large binary as INPUT" >&2; exit 1; }
fi
dd if="$src" of="$work/seg.bin" bs=1048576 skip=20 count=16 2>/dev/null
[ "$(wc -c <"$work/seg.bin")" -eq "$size" ] || { echo "input too small (need > 36 MiB)" >&2; exit 1; }
xz -6 --check=none  -c "$work/seg.bin" >"$work/seg-none.xz"   # what Apple's segments use
xz -6 --check=crc64 -c "$work/seg.bin" >"$work/seg.xz"

# The liblzma variants link a native library; the lzma-turbo variant is pure
# Rust. Each is built as a tiny project so the native-library name clash
# between old and new does not matter.
for v in old new turbo; do
    mkdir -p "$work/$v/src"
    if [ $v = old ]; then
        dep='lzma-sys = { version = "=0.1.20", features = ["static"] }'
    elif [ $v = new ]; then
        dep='liblzma-sys = { version = "=0.4.9", features = ["static"] }'
    else
        dep='lzma-turbo = { version = "0.11", default-features = false, features = ["asm", "std", "xz", "native-crypto"] }'
    fi
    printf '[package]\nname = "xzb"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\n%s\n[profile.release]\nopt-level = 3\n' "$dep" >"$work/$v/Cargo.toml"
    if [ $v = turbo ]; then
        cat >"$work/$v/src/main.rs" <<'RSEOF'
use std::io::Read;
use std::time::Instant;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let xz = std::fs::read(&a[1]).unwrap();
    let orig: usize = a[2].parse().unwrap();
    let ignore = a.get(3).map(|s| s == "ignore").unwrap_or(false);
    let mut out = vec![0u8; orig];
    let (mut best, mut sum, runs) = (f64::MAX, 0.0, 15);
    for _ in 0..runs {
        let t = Instant::now();
        let mut opts = lzma_turbo::xz::XzOptions::default();
        opts.verify_checks = !ignore;
        let mut r = lzma_turbo::xz::XzReader::with_options(std::io::Cursor::new(&xz), opts).single_stream();
        r.read_exact(&mut out).unwrap();
        let e = t.elapsed().as_secs_f64();
        best = best.min(e); sum += e;
    }
    println!("{:<34} best {:6.1} ms  mean {:6.1} ms  ({:.0} MiB/s)", a[4], best * 1e3, sum / runs as f64 * 1e3, orig as f64 / 1048576.0 / best);
}
RSEOF
    else
        ext=lzma_sys
        [ $v = new ] && ext=liblzma_sys
        cat >"$work/$v/src/main.rs" <<RSEOF
extern crate $ext as lz;
use std::time::Instant;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let xz = std::fs::read(&a[1]).unwrap();
    let orig: usize = a[2].parse().unwrap();
    let flags: u32 = if a.get(3).map(|s| s == "ignore").unwrap_or(false) { 0x10 } else { 0 }; // LZMA_IGNORE_CHECK
    let mut out = vec![0u8; orig];
    let (mut best, mut sum, runs) = (f64::MAX, 0.0, 15);
    for _ in 0..runs {
        let (mut limit, mut ip, mut op) = (u64::MAX, 0usize, 0usize);
        let t = Instant::now();
        let r = unsafe { lz::lzma_stream_buffer_decode(&mut limit, flags, std::ptr::null(), xz.as_ptr(), &mut ip, xz.len(), out.as_mut_ptr(), &mut op, orig) };
        let e = t.elapsed().as_secs_f64();
        assert!(r == 0 && op == orig, "decode failed: {r}");
        best = best.min(e); sum += e;
    }
    println!("{:<34} best {:6.1} ms  mean {:6.1} ms  ({:.0} MiB/s)", a[4], best * 1e3, sum / runs as f64 * 1e3, orig as f64 / 1048576.0 / best);
}
RSEOF
    fi
    (cd "$work/$v" && cargo build --release -q)
done

label_for() {
    if [ $1 = old ]; then
        echo "xz 5.2.5"
    elif [ $1 = new ]; then
        echo "xz 5.8.4"
    else
        echo "lzma-turbo"
    fi
}

echo "input: $src (16 MiB slice, xz -6 --check=crc64)  host: $(uname -m)"
for r in 1 2; do
    for v in old new turbo; do
        label=$(label_for "$v")
        "$work/$v/target/release/xzb" "$work/seg-none.xz" $size check "$label, no check (Apple)"
        "$work/$v/target/release/xzb" "$work/seg.xz" $size check "$label, CRC64 checked"
        "$work/$v/target/release/xzb" "$work/seg.xz" $size ignore "$label, CRC64, IGNORE_CHECK"
    done
done
