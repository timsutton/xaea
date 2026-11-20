#!/usr/bin/env bash
# Verify the macOS binaries inside GoReleaser's darwin archives are signed
# with a Developer ID and the hardened runtime. Run as a GoReleaser `after`
# hook; a no-op when signing wasn't enabled (MACOS_SIGN_P12 unset) or we're
# not on macOS (codesign needs it). Usage: verify-macos-signature.sh [dist-dir]
set -euo pipefail

dist="${1:-dist}"
[ -n "${MACOS_SIGN_P12:-}" ] || { echo "signing not enabled; skipping signature check"; exit 0; }
[ "$(uname -s)" = Darwin ] || { echo "not macOS; skipping signature check"; exit 0; }

shopt -s nullglob
archives=("$dist"/xaea_*_darwin_*.tar.gz)
[ ${#archives[@]} -gt 0 ] || { echo "error: no darwin archives in $dist" >&2; exit 1; }

for a in "${archives[@]}"; do
  d=$(mktemp -d)
  tar -xzf "$a" -C "$d" xaea
  codesign --verify --strict --verbose=2 "$d/xaea"
  info=$(codesign -dvv "$d/xaea" 2>&1)
  echo "$info"
  grep -q 'Authority=Developer ID Application' <<<"$info" \
    || { echo "error: $a is not Developer ID-signed" >&2; exit 1; }
  grep -Eq 'flags=0x[0-9a-f]+\(.*runtime' <<<"$info" \
    || { echo "error: $a lacks the hardened runtime" >&2; exit 1; }
  rm -rf "$d"
  echo "ok: $a"
done
