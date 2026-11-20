#!/usr/bin/env bash
# Single-thread microbenchmark of liblzma's one-shot decoder: xz 5.2.5
# (lzma-sys 0.1.20, what xaea used before) vs xz 5.8.4 (liblzma-sys 0.4.9,
# what it uses now), with and without LZMA_IGNORE_CHECK. The two crates link
# the same native library name, so they are built as two tiny projects.
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

for v in old new; do
    mkdir -p "$work/$v/src"
    if [ $v = old ]; then
        dep='lzma-sys = { version = "=0.1.20", features = ["static"] }'; ext=lzma_sys; label="xz 5.2.5"
    else
        dep='liblzma-sys = { version = "=0.4.9", features = ["static"] }'; ext=liblzma_sys; label="xz 5.8.4"
    fi
    printf '[package]\nname = "xzb"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\n%s\n[profile.release]\nopt-level = 3\n' "$dep" >"$work/$v/Cargo.toml"
    cat >"$work/$v/src/main.rs" <<EOF
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
EOF
    (cd "$work/$v" && cargo build --release -q)
    eval "${v}_label='$label'"
done

echo "input: $src (16 MiB slice, xz -6 --check=crc64)  host: $(uname -m)"
for r in 1 2; do
    for v in old new; do
        label=$([ $v = old ] && echo "xz 5.2.5" || echo "xz 5.8.4")
        "$work/$v/target/release/xzb" "$work/seg-none.xz" $size check "$label, no check (Apple)"
        "$work/$v/target/release/xzb" "$work/seg.xz" $size check "$label, CRC64 checked"
        "$work/$v/target/release/xzb" "$work/seg.xz" $size ignore "$label, CRC64, IGNORE_CHECK"
    done
done
