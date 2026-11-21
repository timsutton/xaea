#!/bin/bash
# Self-test for scripts/verify.sh: builds small synthetic trees and asserts
# the exit code for each kind of difference — and, critically, that a missing
# or empty oracle root FAILS (exit 2) rather than passing vacuously, which is
# the regression this hardening exists to prevent.
#
# Needs no fixture and no Apple tooling; CI runs it on every PR
# (.github/workflows/oracle-verify.yml). Exit 0 = all checks passed.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
verify=$here/verify.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0

# Base tree: a 0755 dir with an executable, a 0700 dir (dir modes), an empty
# dir, a 0600 file, a 0644 file, and a symlink.
base=$tmp/base
mkdir -p "$base/app/bin" "$base/app/empty" "$base/app/conf"
printf 'tool\n'   >| "$base/app/bin/tool";    chmod 0755 "$base/app/bin/tool"
printf 'sekrit\n' >| "$base/app/conf/secret"; chmod 0600 "$base/app/conf/secret"
printf 'hello\n'  >| "$base/file.txt"
chmod 0700 "$base/app/conf"
chmod 0755 "$base/app/empty"
ln -s bin/tool "$base/app/link"

copy() { cp -Rp "$base" "$1"; }

# run <desc> <expected-exit> <verify.sh args...>
run() {
  local desc=$1 exp=$2 rc out
  shift 2
  set +e; out=$("$verify" "$@" 2>&1); rc=$?; set -e
  if [ "$rc" -eq "$exp" ]; then
    echo "ok   [$exp] $desc"
  else
    echo "FAIL [$rc, want $exp] $desc"
    printf '%s\n' "$out" | sed 's/^/       /'
    fails=$((fails + 1))
  fi
}

copy "$tmp/same"
run "identical trees"                    0 "$tmp/same" "$base"

copy "$tmp/mode";  chmod 0644 "$tmp/mode/app/conf/secret"
run "file mode differs"                  1 "$tmp/mode" "$base"

copy "$tmp/dirmode"; chmod 0755 "$tmp/dirmode/app/conf"
run "dir mode differs"                   1 "$tmp/dirmode" "$base"

copy "$tmp/emptydir"; rmdir "$tmp/emptydir/app/empty"
run "empty dir missing"                  1 "$tmp/emptydir" "$base"

copy "$tmp/link"; rm "$tmp/link/app/link"; ln -s /etc/passwd "$tmp/link/app/link"
run "symlink target differs"             1 "$tmp/link" "$base"

copy "$tmp/content"; printf 'hello!\n' >| "$tmp/content/file.txt"
run "file content differs"               1 "$tmp/content" "$base"
run "content differs, --fast ignores it" 0 --fast "$tmp/content" "$base"

copy "$tmp/type"; rm "$tmp/type/app/link"; printf 'now a file\n' >| "$tmp/type/app/link"
run "type differs (link -> file)"        1 "$tmp/type" "$base"

mkdir -p "$tmp/emptyroot"
run "missing oracle root"                2 "$tmp/same" "$tmp/nope"
run "empty oracle root"                  2 "$tmp/same" "$tmp/emptyroot"
run "missing mine root"                  2 "$tmp/nope" "$base"

mkdir -p "$tmp/wrapped"; copy "$tmp/wrapped/wrapper"
run "wrapped mine root via strip"        0 "$tmp/wrapped" "$base" "./wrapper"

# Manifest / golden round-trip.
"$verify" --manifest "$base" > "$tmp/golden.tsv"
run "golden matches its own tree"        0 --golden "$tmp/golden.tsv" "$tmp/same"
run "golden catches content drift"       1 --golden "$tmp/golden.tsv" "$tmp/content"
run "missing golden file"                2 --golden "$tmp/nope.tsv" "$tmp/same"
# --fast must never write or read a manifest: a content-blind golden is a
# silent pass, the exact failure mode this script exists to prevent.
run "--fast refused with --manifest"     2 --fast --manifest "$base"
run "--fast refused with --golden"       2 --fast --golden "$tmp/golden.tsv" "$tmp/same"

check() { # check <desc> <cmd...>
  local desc=$1; shift
  if "$@"; then echo "ok        $desc"; else echo "FAIL      $desc"; fails=$((fails + 1)); fi
}
check "manifest lists the empty dir"     grep -q "^./app/empty	d	755	-$" "$tmp/golden.tsv"
check "manifest lists the 0600 file"     grep -q "^./app/conf/secret	f	600	[0-9a-f]\{64\}$" "$tmp/golden.tsv"
check "manifest lists the symlink"       grep -q "^./app/link	l	-	bin/tool$" "$tmp/golden.tsv"
check "manifest is path-sorted"          env LC_ALL=C sort -c "$tmp/golden.tsv"
check "every line has 4 tab fields"      awk -F'\t' 'NF != 4 { exit 1 }' "$tmp/golden.tsv"

echo
if [ "$fails" -gt 0 ]; then
  echo "verify-selftest: $fails failure(s)" >&2
  exit 1
fi
echo "verify-selftest: all checks passed"
