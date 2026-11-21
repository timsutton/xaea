#!/bin/bash
# Fidelity check: compare an extracted tree against an oracle tree produced
# by Apple's own tooling (`archiveutil extractXcodeAEA`), or two trees
# against each other. See doc/ORACLE-VERIFY.md for the full procedure.
#
# Compared, for every path in either tree:
#   presence (including empty directories), entry type (dir/file/symlink),
#   permission bits, symlink targets (the literal target string, not the
#   file it resolves to), and file contents (SHA-256, unless --fast).
#
# Deliberately NOT compared: uid/gid, timestamps, xattrs and APFS
# compression attributes — see doc/ORACLE-VERIFY.md for why.
#
# Usage:
#   scripts/verify.sh [options] <mine-root> [<oracle-root>] [path-strip-for-mine]
#   scripts/verify.sh --manifest <root>
#
# Options:
#   --fast          skip file-content hashes (structure, modes, targets only)
#   --manifest      print <root>'s manifest to stdout; no comparison
#   --golden FILE   compare <mine-root> against a committed manifest (the
#                   oracle tree itself is then not needed)
#   -h, --help      usage
#
# Manifest format — one tab-separated line per path, sorted by path:
#   <path>\t<type>\t<mode>\t<digest-or-target>
#     type              d=dir  f=file  l=symlink
#     mode              octal permission bits; '-' for symlinks, whose
#                       bits are not meaningful and cannot be set
#     digest-or-target  sha256 for files, literal target for links, '-' for dirs
# Paths containing tabs or newlines are not supported; Apple archives
# contain none.
#
# Exit status: 0 identical, 1 differences found, 2 usage/environment error
# (a missing or empty oracle is an error, never a silent pass).
set -euo pipefail

die() { echo "verify.sh: $*" >&2; exit 2; }

usage() {
  echo "usage: scripts/verify.sh [options] <mine-root> [<oracle-root>] [strip]"
  echo "       scripts/verify.sh --manifest <root>"
  echo "options: --fast, --manifest, --golden FILE, -h/--help"
  echo "see the script header and doc/ORACLE-VERIFY.md for details"
}

fast=0 mode=compare golden= mine= oracle= strip=
while [ $# -gt 0 ]; do
  case "$1" in
    --fast) fast=1 ;;
    --manifest) mode=manifest ;;
    --golden) [ $# -ge 2 ] || die "--golden needs a file"; golden=$2; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *)
      if [ -z "$mine" ]; then mine=$1
      elif [ -z "$oracle" ]; then oracle=$1
      elif [ -z "$strip" ]; then strip=$1
      else die "too many arguments"; fi ;;
  esac
  shift
done

[ -n "$mine" ] || { usage >&2; exit 2; }
# --fast skips content hashes, so a --fast manifest could only ever make a
# blind golden (every file would compare "-" to "-"). Hashing is mandatory
# wherever a manifest is written or read.
if [ "$fast" = 1 ] && { [ "$mode" = manifest ] || [ -n "$golden" ]; }; then
  die "--fast applies only to tree-vs-tree comparison, not --manifest/--golden"
fi
case $mode in
  manifest)
    [ -z "$oracle" ] && [ -z "$golden" ] && [ -z "$strip" ] \
      || die "--manifest takes exactly one root"
    ;;
  compare)
    if [ -n "$golden" ]; then
      [ -z "$oracle" ] || die "give either an oracle root or --golden, not both"
      [ -f "$golden" ] || die "golden manifest not found: $golden"
    else
      [ -n "$oracle" ] || { usage >&2; die "missing oracle root (or --golden FILE)"; }
    fi
    ;;
esac

# A root that doesn't exist, or exists but is empty, must fail loudly: an
# empty manifest compared against another empty manifest would otherwise
# "pass" vacuously.
check_root() {
  [ -d "$2" ] || die "$1 root is not a directory: $2"
  [ -n "$(find "$2" -mindepth 1 -maxdepth 1 -print -quit)" ] \
    || die "$1 root is empty: $2 — refusing to compare nothing"
}
check_root mine "$mine"
if [ -n "$oracle" ]; then check_root oracle "$oracle"; fi

# stat(1) format dialects (BSD/macOS vs GNU/coreutils). The format strings
# below contain literal tabs.
if stat -c '' . >/dev/null 2>&1; then
  STATF=(stat -c "%n	%a")
else
  STATF=(stat -f "%N	%Lp")
fi
if command -v shasum >/dev/null 2>&1; then
  SHA=(shasum -a 256)
else
  SHA=(sha256sum)
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# build_tree <root> <out-prefix>: writes <prefix>.dirs/.files/.links/.hashes
# (NUL-separated staging files are removed afterwards).
build_tree() {
  ( cd "$1"
    find . -type d -print0 | xargs -0 "${STATF[@]}" > "$2.dirs"
    find . -type f -print0 > "$2.files0"
    find . -type l -print0 > "$2.links0"
    if [ -s "$2.files0" ]; then
      xargs -0 "${STATF[@]}" < "$2.files0" > "$2.files"
      if [ "$fast" = 0 ]; then
        xargs -P 10 -0 -n 512 "${SHA[@]}" < "$2.files0" > "$2.hashes"
      else
        : > "$2.hashes"
      fi
    else
      : > "$2.files"; : > "$2.hashes"
    fi
    if [ -s "$2.links0" ]; then
      # trailing "sh" is the sh -c init-arg: without it the first path
      # would land in $0 and the loop would skip it.
      xargs -0 -n 256 sh -c 'for l do printf "%s\t%s\n" "$l" "$(readlink "$l")"; done' sh \
        < "$2.links0" > "$2.links"
    else
      : > "$2.links"
    fi
    rm -f "$2.files0" "$2.links0"
  )
}

cat > "$tmp/cmp.py" <<'EOF'
import sys

def read_lines(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        return [ln.rstrip("\n") for ln in f]

def load_tree(dirs, files, links, hashes, fast):
    d = {}
    for ln in read_lines(dirs):
        p, m = ln.split("\t")
        d[p] = ("d", m, "-")
    hs = {}
    for ln in read_lines(hashes):
        if len(ln) >= 66:                      # "<64 hex>  <path>"
            hs[ln[66:]] = ln[:64]
    nodigest = "-" if fast else "?"            # "?" = hash expected but absent
    for ln in read_lines(files):
        p, m = ln.split("\t")
        d[p] = ("f", m, hs.get(p, nodigest))
    for ln in read_lines(links):
        p, t = ln.split("\t", 1)
        d[p] = ("l", "-", t)
    return d

def load_manifest(path):
    d = {}
    for ln in read_lines(path):
        p, ty, m, x = ln.split("\t", 3)
        d[p] = (ty, m, x)
    return d

def strip_paths(d, strip):
    if not strip:
        return d
    out = {}
    for p, v in d.items():
        if p.startswith(strip):
            rest = p[len(strip):].lstrip("/")  # strip may or may not end in /
            p = "./" + rest if rest else "."
        out[p] = v
    return out

def report(mine, oracle):
    missing = [p for p, v in list(mine.items()) + list(oracle.items()) if v[2] == "?"]
    if missing:
        print(f"verify.sh: {len(missing)} file(s) with no content hash "
              f"(paths with tabs/newlines are unsupported), e.g. {missing[0]!r}",
              file=sys.stderr)
        sys.exit(2)
    only_mine = sorted(set(mine) - set(oracle))
    only_oracle = sorted(set(oracle) - set(mine))
    cats = {"type": [], "mode": [], "target": [], "hash": []}
    for p in set(mine) & set(oracle):
        a, b = mine[p], oracle[p]
        if a[0] != b[0]:
            cats["type"].append(p)
        else:
            if a[0] in "df" and a[1] != b[1]:
                cats["mode"].append(p)
            if a[0] == "l" and a[2] != b[2]:
                cats["target"].append(p)
            if a[0] == "f" and a[2] != b[2]:
                cats["hash"].append(p)
    common = set(mine) & set(oracle)
    print(f"mine={len(mine)} oracle={len(oracle)} common={len(common)} "
          f"only-mine={len(only_mine)} only-oracle={len(only_oracle)} "
          + " ".join(f"{k}-differs={len(v)}" for k, v in cats.items()))
    for name, lst in [("only-mine", only_mine), ("only-oracle", only_oracle)] \
            + [(k + "-differs", v) for k, v in cats.items()]:
        for p in sorted(lst)[:20]:
            print(f"{name}: {p}")
    sys.exit(1 if (only_mine or only_oracle or any(cats.values())) else 0)

mode = sys.argv[1]
fast = sys.argv[-1] == "fast"
if mode == "manifest":
    d = load_tree(*sys.argv[2:6], fast)
    for p in sorted(d):
        t, m, x = d[p]
        print(f"{p}\t{t}\t{m}\t{x}")
elif mode == "golden":
    report(strip_paths(load_tree(*sys.argv[3:7], fast), sys.argv[2]),
           load_manifest(sys.argv[7]))
else:
    report(strip_paths(load_tree(*sys.argv[3:7], fast), sys.argv[2]),
           load_tree(*sys.argv[7:11], fast))
EOF

if [ "$fast" = 1 ]; then fastarg=fast; else fastarg=full; fi

if [ "$mode" = manifest ]; then
  build_tree "$mine" "$tmp/m"
  python3 -I - manifest "$tmp/m.dirs" "$tmp/m.files" "$tmp/m.links" "$tmp/m.hashes" \
    "$fastarg" < "$tmp/cmp.py"
elif [ -n "$golden" ]; then
  build_tree "$mine" "$tmp/m"
  python3 -I - golden "$strip" "$tmp/m.dirs" "$tmp/m.files" "$tmp/m.links" \
    "$tmp/m.hashes" "$golden" "$fastarg" < "$tmp/cmp.py"
else
  build_tree "$mine" "$tmp/m"
  build_tree "$oracle" "$tmp/o"
  python3 -I - compare "$strip" "$tmp/m.dirs" "$tmp/m.files" "$tmp/m.links" \
    "$tmp/m.hashes" "$tmp/o.dirs" "$tmp/o.files" "$tmp/o.links" "$tmp/o.hashes" \
    "$fastarg" < "$tmp/cmp.py"
fi
