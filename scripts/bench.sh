#!/bin/bash
# End-to-end timing harness: hyperfine over `unaea extract` on a real
# archive, one or more variants side by side, warm cache.
#
# Usage: scripts/bench.sh [options] [VARIANT...]
#   VARIANT        name=extra unaea args, e.g. 'lzma=--decoder liblzma'
#                  (default: one variant, "default", with no extra args)
#   -f FILE        archive (default: fixtures/Xcode_27.3_beta_2.aea)
#   -b BIN         unaea binary (default: build + use target/release/unaea)
#   -o DIR         scratch output dir, wiped before every run; must be on
#                  the volume you want to measure (default: target/bench-out)
#   -r N           timed runs per variant (default: 5)
#   -w N           warmup runs per variant (default: 1)
#   -d             --dry-run: decode+parse only, no filesystem writes
#   -j FILE        also write hyperfine's JSON export here
#
# Examples:
#   scripts/bench.sh                                      # full extract, defaults
#   scripts/bench.sh 'liblzma=--decoder liblzma' 'libcompression=--decoder libcompression'
#   scripts/bench.sh -d -r 10 'j8=-j 8' 'j15=-j 15'
#
# Prints the machine, git revision, and per-variant mean/σ/min plus
# throughput (decoded stream bytes / mean wall). Relative speeds are the
# point; absolute seconds only compare on the same machine.
set -euo pipefail
cd "$(dirname "$0")/.."

fixture=fixtures/Xcode_27.3_beta_2.aea
bin=
out=target/bench-out
runs=5
warmup=1
dry=
json=
while getopts "f:b:o:r:w:dj:h" opt; do
    case $opt in
        f) fixture=$OPTARG ;;
        b) bin=$OPTARG ;;
        o) out=$OPTARG ;;
        r) runs=$OPTARG ;;
        w) warmup=$OPTARG ;;
        d) dry=--dry-run ;;
        j) json=$OPTARG ;;
        *) sed -n '2,25p' "$0"; exit 2 ;;
    esac
done
shift $((OPTIND - 1))
[ $# -gt 0 ] || set -- "default="

command -v hyperfine >/dev/null || { echo "bench: needs hyperfine (brew install hyperfine)" >&2; exit 1; }
[ -f "$fixture" ] || { echo "bench: no archive at $fixture (-f)" >&2; exit 1; }
if [ -z "$bin" ]; then
    cargo build --release --quiet
    bin=target/release/unaea
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp" "$out"' EXIT
export_json=${json:-$tmp/bench.json}

args=()
for v in "$@"; do
    name=${v%%=*}
    extra=${v#*=}
    [ "$name" != "$v" ] || { echo "bench: variant must be name=args, got '$v'" >&2; exit 2; }
    # $extra is intentionally unquoted: it is a list of unaea flags.
    args+=(-n "$name" "$(printf '%q ' "$bin" extract "$fixture" -o "$out") $dry $extra")
done

if [ "$(uname)" = Darwin ]; then
    cpu="$(sysctl -n machdep.cpu.brand_string) ($(sysctl -n hw.ncpu) cpus, $(( $(sysctl -n hw.memsize) >> 30 )) GiB)"
else
    cpu="$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //') ($(nproc) cpus)"
fi
echo "machine: $cpu"
echo "rev:     $(git rev-parse --short HEAD)$(git diff --quiet HEAD -- src Cargo.toml Cargo.lock || echo '+dirty')"
echo "archive: $fixture"
echo "mode:    ${dry:-extract to $out}, $warmup warmup + $runs runs/variant"
echo

stream_bytes=$("$bin" inspect "$fixture" --json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["root"]["original_size"])')

hyperfine --style basic -w "$warmup" -r "$runs" \
    --prepare "rm -rf $(printf '%q' "$out")" \
    --export-json "$export_json" "${args[@]}"

python3 - "$export_json" "$stream_bytes" <<'EOF'
import json, sys
mib = int(sys.argv[2]) / (1 << 20)

def stats(r):
    """(wall mean, σ, min, cpu mean or None, peak RSS GiB or None) across
    hyperfine 1.x (flat keys) and 2.x (results[].summary) exports."""
    s = r.get("summary")
    if s is None:
        cpu = r["user"] + r["system"]
        return r["mean"], r["stddev"], r["min"], cpu, None
    w = s["time_wall_clock"]
    cpu = s.get("time_cpu", {}).get("mean")
    rss = s.get("memory_peak_resident", {}).get("mean")
    return w["mean"], w["stddev"], w["min"], cpu, rss and rss / (1 << 30)

results = json.load(open(sys.argv[1]))["results"]
base = stats(results[0])[0]
fmt = lambda v, f: format(v, f) if v is not None else "-"
print(f"\n{'variant':<20} {'mean':>8} {'σ':>7} {'min':>8} {'cpu':>8} "
      f"{'peakGiB':>7} {'MiB/s':>7} {'vs first':>9}")
for i, r in enumerate(results):
    mean, sd, mn, cpu, rss = stats(r)
    rel = f"{(mean / base - 1) * 100:+.1f}%" if i else ""
    # 2.x keeps -n in "name"; 1.x replaces "command" with it.
    print(f"{r.get('name', r['command']):<20} {mean:>7.2f}s {sd:>6.2f}s {mn:>7.2f}s "
          f"{fmt(cpu, '>7.1f')}s {fmt(rss, '>7.2f')} {mib / mean:>7.0f} {rel:>9}")
EOF
