#!/usr/bin/env bash
# Extract an AEA with a reference implementation (the "oracle") and print the
# path of the resulting tree, for use with scripts/verify.sh.
#
# The AEA format is proprietary, so byte-level fidelity needs an independent
# extractor: verify.sh compares xaea's extraction against this tree
# hash-for-hash. Apple's own `archiveutil extractXcodeAEA` (built into the
# macOS Archive Utility) is the authoritative oracle; unxip is the only
# third-party implementation and is used as a fallback on macOS versions
# without the subcommand. Note unxip 3.3 cannot read every AEA variant, so
# prefer archiveutil whenever it is available.
#
# Usage: extract-oracle.sh <input.aea> [path-file]
#
# The oracle tree path is printed on stdout. When path-file is given, the path
# is also written there, so callers can recover it even when stdout is a
# command substitution that also captures the extraction log.
#
# Both extractors validate the archive's own checksums while extracting, so a
# failure here means the fixture itself is suspect, not the comparison.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <input.aea> [path-file]" >&2
  exit 2
fi
INPUT=$1
OUTFILE=${2:-}

if [[ ! -f "$INPUT" ]]; then
  echo "error: no such file: $INPUT" >&2
  exit 2
fi
if ! command -v archiveutil >/dev/null 2>&1 && ! command -v unxip >/dev/null 2>&1; then
  echo "error: neither archiveutil (macOS 26+) nor unxip (brew install unxip) found on PATH" >&2
  exit 3
fi

# Both tools refuse to overwrite an existing output path, so start from a
# unique fresh directory under the system temp dir. archiveutil extracts into
# its working directory; unxip takes the output path as an argument.
OUTPUT=$(mktemp -d "${TMPDIR:-/tmp}/xaea-oracle-$(basename "$INPUT" .aea)-XXXXXX")

if command -v archiveutil >/dev/null 2>&1; then
  echo "Extracting $INPUT with archiveutil (oracle) into $OUTPUT ..." >&2
  ( cd "$OUTPUT" && archiveutil extractXcodeAEA "$INPUT" )
else
  echo "Extracting $INPUT with unxip (oracle) into $OUTPUT ..." >&2
  unxip "$INPUT" "$OUTPUT"
fi

# The tools write the app bundle at the output root; report the first entry so
# the path works with verify.sh regardless of the bundle name.
TREE=$(find "$OUTPUT" -mindepth 1 -maxdepth 1 -print -quit)
if [[ -z "$TREE" ]]; then
  echo "error: oracle extraction produced no output in $OUTPUT" >&2
  exit 1
fi

if [[ -n "$OUTFILE" ]]; then
  printf '%s\n' "$TREE" > "$OUTFILE"
fi
printf '%s\n' "$TREE"
