#!/bin/bash
# Fidelity check: hash-compare two extracted trees.
#   files    -> sha256 of contents
#   symlinks -> sha256 of the literal target string (LINK: prefix)
# Usage: scripts/verify.sh <mine-root> <oracle-root> [path-strip-for-mine]
set -euo pipefail
mine=${1:?mine root}; oracle=${2:?oracle root}; strip=${3:-}
man() {
    ( cd "$1"
      find . -type l -print0 | xargs -0 -P 10 -n 512 sh -c \
          'for l do printf "%s  %s\n" "$(printf %s "$l" >/dev/null; printf %s "$(readlink "$l")" | shasum -a 256 | cut -d" " -f1)" "$l"; done' sh
      find . -type f -print0 | xargs -P 10 -0 shasum -a 256
    ) | sort -k2
}
man "$mine" > /tmp/verify_mine.sha
man "$oracle" > /tmp/verify_oracle.sha
python3 - "$strip" <<'EOF'
import sys
strip = sys.argv[1]
def load(fn):
    d = {}
    for line in open(fn):
        h, p = line[:64], line[66:].rstrip("\n")
        if strip and p.startswith(strip):
            p = "./" + p[len(strip):]
        d[p] = h
    return d
m, o = load("/tmp/verify_mine.sha"), load("/tmp/verify_oracle.sha")
common = set(m) & set(o)
diff = [p for p in common if m[p] != o[p]]
print(f"mine={len(m)} oracle={len(o)} common={len(common)} "
      f"only-mine={len(set(m)-set(o))} only-oracle={len(set(o)-set(m))} hash-differs={len(diff)}")
for p in sorted(diff)[:20]:
    print("D:", p)
sys.exit(1 if diff or set(m) != set(o) else 0)
EOF
