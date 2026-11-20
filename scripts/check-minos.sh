#!/usr/bin/env bash
# Assert every given Mach-O binary declares exactly the expected minimum macOS
# (LC_BUILD_VERSION minos), so a toolchain/SDK bump can't silently raise the
# floor. Usage: scripts/check-minos.sh <expected e.g. 11.0> <binary>...
set -euo pipefail
expected=$1; shift
status=0
for bin in "$@"; do
  # LC_BUILD_VERSION reports `minos`; the older LC_VERSION_MIN_MACOSX (what
  # rustc emits for x86_64 below macOS 10.14-era floors) reports `version`.
  minos=$(otool -l "$bin" | awk '
    /LC_BUILD_VERSION|LC_VERSION_MIN_MACOSX/ {f=1}
    f && ($1=="minos" || $1=="version") {print $2; exit}')
  if [ "$minos" = "$expected" ]; then
    echo "ok   $bin: minos $minos"
  else
    echo "FAIL $bin: minos ${minos:-<none>}, expected $expected" >&2
    status=1
  fi
done
exit $status
