#!/usr/bin/env bash
# Print the CHANGELOG.md section for one version (heading excluded), for use as
# the GitHub release body via `goreleaser --release-notes`. Fails if the version
# has no section or the section is empty, so a release can't go out without
# notes. Usage: release-notes.sh VERSION [changelog]
set -euo pipefail

version="${1:?usage: release-notes.sh VERSION [changelog]}"
changelog="${2:-CHANGELOG.md}"

# Headings read "## 0.2.0 - date" (older ones use an em dash), so match on the
# second field rather than the whole line.
notes=$(awk -v v="$version" '
  /^## / { if (found) exit; found = ($2 == v); next }
  found
' "$changelog")

# Drop the blank line(s) after the heading; $(...) already trimmed the tail.
notes=$(printf '%s\n' "$notes" | sed '/./,$!d')

[ -n "$notes" ] || { echo "error: no CHANGELOG.md entry for $version" >&2; exit 1; }
printf '%s\n' "$notes"
