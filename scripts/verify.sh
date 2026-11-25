#!/usr/bin/env bash
# Compare two extracted trees hash-for-hash.
#
# One tree must come from xaea and the other from an independent reference
# extractor (the "oracle"): Apple's `archiveutil extractXcodeAEA` or unxip,
# both driven by scripts/extract-oracle.sh. A mismatch means xaea's output
# diverges from the reference at the byte level.
#
# Usage:
#   verify.sh <mine> <oracle> [top-dir-to-strip]   compare two trees directly
#   verify.sh --hash <tree> <manifest>             write a tree's manifest
#   verify.sh --compare <a.sha> <b.sha> [top-dir-to-strip]
#
# Manifest mode exists for disk-constrained environments (CI runners): hash
# the oracle tree, delete it, extract with xaea, hash that, then compare the
# two manifests. Manifests hash paths relative to the tree root, so they are
# comparable across trees. The optional strip argument removes a differing
# top-level directory (e.g. Xcode-beta.app) from both sides before comparing.
set -euo pipefail

# Regular files are hashed by content; symlinks are hashed by their target
# string. Hashing a symlink's *content* would follow the link, which fails on
# links to directories (most of a framework's are) and would compare
# destinations rather than the recorded link itself.
hash_tree() { # <dir> <manifest>
  local dir=$1 out=$2
  ( cd "$dir" && find . -type f -print0 \
      | xargs -0 -P"$(sysctl -n hw.ncpu)" shasum -a 256 ) > "$out"
  # One perl process hashes every link target; spawning shasum per link
  # (there are ~11k in an Xcode AEA) would dominate the runtime.
  ( cd "$dir" && find . -type l -print0 \
      | perl -MDigest::SHA=sha256_hex -e \
          'local $/; for my $l (grep { length } split /\0/, <STDIN>) {
             my $t = readlink($l) or die "readlink $l: $!\n";
             print sha256_hex($t), "  $l\n";
           }' ) >> "$out"
  LC_ALL=C sort -k2 -o "$out" "$out"
}

compare_manifests() { # <a.sha> <b.sha> [strip]
  python3 - "$1" "$2" "${3:-}" <<'EOF'
import sys
a_f, b_f, strip = sys.argv[1], sys.argv[2], sys.argv[3]
def load(fn):
    d = {}
    for line in open(fn):
        h, p = line[:64], line[66:].rstrip("\n")
        if strip:
            pre = "./" + strip.strip("/") + "/"
            if p.startswith(pre):
                p = "./" + p[len(pre):]
        d[p] = h
    return d
m, o = load(a_f), load(b_f)
common = set(m) & set(o)
diff = [p for p in common if m[p] != o[p]]
print(f"mine={len(m)} oracle={len(o)} common={len(common)} "
      f"only-mine={len(set(m)-set(o))} only-oracle={len(set(o)-set(m))} hash-differs={len(diff)}")
for p in sorted(diff)[:20]:
    print("D:", p)
sys.exit(1 if diff or set(m) != set(o) else 0)
EOF
}

case "${1:-}" in
  --hash)
    [[ $# -eq 3 ]] || { echo "usage: verify.sh --hash <tree> <manifest>" >&2; exit 2; }
    hash_tree "$2" "$3"
    ;;
  --compare)
    [[ $# -ge 3 && $# -le 4 ]] || { echo "usage: verify.sh --compare <a.sha> <b.sha> [strip]" >&2; exit 2; }
    compare_manifests "$2" "$3" "${4:-}"
    ;;
  *)
    [[ $# -ge 2 && $# -le 3 ]] || { echo "usage: verify.sh <mine> <oracle> [strip]" >&2; exit 2; }
    mine=$1 oracle=$2 strip=${3:-}
    a=$(mktemp); b=$(mktemp); trap 'rm -f "$a" "$b"' EXIT
    hash_tree "$mine" "$a"
    hash_tree "$oracle" "$b"
    compare_manifests "$a" "$b" "$strip"
    ;;
esac
