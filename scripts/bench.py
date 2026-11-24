#!/usr/bin/env python3
"""End-to-end timing harness: hyperfine over `xaea extract` on a real
archive, one or more variants side by side, warm cache.

Prints the machine, git revision, and per-variant mean/σ/min plus
throughput (decoded stream bytes / mean wall). Relative speeds are the
point; absolute seconds only compare on the same machine. "vs first" is
relative to the first variant, so archiveutil (-a, always last) reads as
how much slower Apple's tool is than your first variant.

Needs hyperfine >= 2.0 (brew install hyperfine).
"""
import argparse
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARCHIVEUTIL = "/usr/bin/archiveutil"

EXAMPLES = """\
examples:
  scripts/bench.py Xcode.aea                            # full extract, defaults
  scripts/bench.py -d Xcode.aea 'lzma-turbo=--decoder lzma-turbo' 'liblzma=--decoder liblzma'
  scripts/bench.py -d -r 10 Xcode.aea 'j8=-j 8' 'j15=-j 15'
  scripts/bench.py -a Xcode.aea                         # xaea vs archiveutil
"""


def machine() -> str:
    if platform.system() == "Darwin":
        def sysctl(key):
            return subprocess.check_output(["sysctl", "-n", key], text=True).strip()
        return (f"{sysctl('machdep.cpu.brand_string')} ({sysctl('hw.ncpu')} cpus, "
                f"{int(sysctl('hw.memsize')) >> 30} GiB)")
    with open("/proc/cpuinfo") as f:
        model = next((l.split(":", 1)[1].strip() for l in f if l.startswith("model name")), "?")
    return f"{model} ({os.cpu_count()} cpus)"


def revision() -> str:
    rev = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
    clean = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--", "src", "Cargo.toml", "Cargo.lock"]
    ).returncode == 0
    return rev if clean else rev + "+dirty"


def sh_c(script: str) -> str:
    """One hyperfine command (run with -N) that needs shell syntax."""
    return shlex.join(["/bin/sh", "-c", script])


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("archive", type=Path, help="the .aea archive to extract")
    p.add_argument("variants", nargs="*", metavar="VARIANT",
                   help="name=extra xaea args, e.g. 'lzma=--decoder liblzma' "
                        "(default: one variant, \"default\", with no extra args)")
    p.add_argument("-b", dest="bin", type=Path,
                   help="xaea binary (default: build + use target/release/xaea)")
    p.add_argument("-o", dest="out", type=Path, default=ROOT / "target/bench-out",
                   help="scratch output dir, wiped before every run; must be on the "
                        "volume you want to measure (default: target/bench-out)")
    p.add_argument("-r", dest="runs", type=int, default=5, help="timed runs per variant (default: 5)")
    p.add_argument("-w", dest="warmup", type=int, default=1, help="warmup runs per variant (default: 1)")
    p.add_argument("-d", dest="dry", action="store_true",
                   help="--dry-run: decode+parse only, no filesystem writes")
    p.add_argument("-a", dest="apple", action="store_true",
                   help="also time Apple's `archiveutil extractXcodeAEA` (macOS only, "
                        "full extraction only, so not with -d), appended as the last variant")
    p.add_argument("-j", dest="json", type=Path, help="also write hyperfine's JSON export here")
    args = p.parse_intermixed_args()
    if args.apple and args.dry:
        p.error("archiveutil has no dry-run mode; drop -d or -a")
    args.variants = args.variants or ["default="]
    for v in args.variants:
        if "=" not in v:
            p.error(f"variant must be name=args, got '{v}'")
    # Resolve against the caller's cwd now: we chdir to the repo root below,
    # and archiveutil cds into the output dir.
    for name in ("archive", "bin", "out", "json"):
        if getattr(args, name):
            setattr(args, name, getattr(args, name).resolve())
    return args


def keep_wall_only(result: dict) -> dict:
    """hyperfine's JSON export carries every metric whatever --metrics says."""
    wall = "time_wall_clock"
    result["summary"] = {wall: result["summary"][wall]}
    result["measurements"] = [{wall: m[wall]} for m in result["measurements"]]
    return result


def print_table(results: list, stream_bytes: int) -> None:
    if "summary" not in results[0]:
        sys.exit("bench: needs hyperfine >= 2.0 (the --export-json schema changed)")
    mib = stream_bytes / (1 << 20)

    def fmt(v, spec, unit=""):
        return f"{v:{spec}}{unit}" if v is not None else "-"

    base = results[0]["summary"]["time_wall_clock"]["mean"]
    print(f"\n{'variant':<20} {'mean':>8} {'σ':>7} {'min':>8} {'cpu':>8} "
          f"{'peakGiB':>7} {'MiB/s':>7} {'vs first':>9}")
    for i, r in enumerate(results):
        s = r["summary"]
        wall = s["time_wall_clock"]
        cpu = s.get("time_cpu", {}).get("mean")
        rss = s.get("memory_peak_resident", {}).get("mean")
        rel = f"{(wall['mean'] / base - 1) * 100:+.1f}%" if i else ""
        # stddev is null for a single run
        print(f"{r['name']:<20} {wall['mean']:>7.2f}s {wall['stddev'] or 0:>6.2f}s "
              f"{wall['min']:>7.2f}s {fmt(cpu, '.1f', 's'):>8} "
              f"{fmt(rss and rss / (1 << 30), '.2f'):>7} {mib / wall['mean']:>7.0f} {rel:>9}")


def main() -> None:
    args = parse_args()
    os.chdir(ROOT)

    if not shutil.which("hyperfine"):
        sys.exit("bench: needs hyperfine (brew install hyperfine)")
    if not args.archive.is_file():
        sys.exit(f"bench: no archive at {args.archive}")
    if args.apple and not os.access(ARCHIVEUTIL, os.X_OK):
        sys.exit(f"bench: -a needs {ARCHIVEUTIL} (macOS)")
    bin = args.bin
    if bin is None:
        subprocess.run(["cargo", "build", "--release", "--quiet"], check=True)
        bin = ROOT / "target/release/xaea"

    q = shlex.quote
    commands = []
    for v in args.variants:
        name, _, extra = v.partition("=")
        cmd = [str(bin), "extract", str(args.archive), str(args.out),
               *(["--dry-run"] if args.dry else []), *shlex.split(extra)]
        commands += ["-n", name, shlex.join(cmd)]
    # (wall time only?, hyperfine commands) per invocation. archiveutil gets its
    # own, wall time only: hyperfine sees just the launcher process, so its CPU
    # and peak RSS would be meaningless next to xaea's. --metrics is per invocation.
    groups = [(False, commands)]
    if args.apple:
        # archiveutil takes no output dir and extracts into its cwd.
        groups.append((True, ["-n", "archiveutil", sh_c(
            f"mkdir -p {q(str(args.out))} && cd {q(str(args.out))} && "
            f"exec {ARCHIVEUTIL} extractXcodeAEA {q(str(args.archive))}")]))
    # The one-shot retry covers rm -rf racing with something else touching
    # a freshly written 100k-file tree.
    prepare = sh_c(f"rm -rf {q(str(args.out))} || {{ sleep 2; rm -rf {q(str(args.out))}; }}")

    print(f"machine: {machine()}")
    print(f"rev:     {revision()}")
    print(f"archive: {args.archive}")
    mode = "--dry-run" if args.dry else f"extract to {args.out}"
    print(f"mode:    {mode}, {args.warmup} warmup + {args.runs} runs/variant\n", flush=True)

    inspect = subprocess.check_output([str(bin), "inspect", str(args.archive), "--json"])
    stream_bytes = json.loads(inspect)["root"]["original_size"]

    results = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            for i, (wall_only, cmds) in enumerate(groups):
                export = Path(tmp) / f"{i}.json"
                # -N: no intermediate shell, so only the sh_c commands pay for one.
                rc = subprocess.run(
                    ["hyperfine", "--style", "basic", "-N", "-w", str(args.warmup),
                     "-r", str(args.runs), "--prepare", prepare,
                     *(["--metrics", "time_wall_clock"] if wall_only else []),
                     "--export-json", str(export), *cmds]).returncode
                if rc:
                    sys.exit(rc)
                group = json.loads(export.read_text())["results"]
                results += map(keep_wall_only, group) if wall_only else group
        if args.json:
            args.json.write_text(json.dumps({"results": results}, indent=2))
        print_table(results, stream_bytes)
    finally:
        shutil.rmtree(args.out, ignore_errors=True)


if __name__ == "__main__":
    main()
