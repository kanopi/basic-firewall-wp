#!/usr/bin/env bash
#
# Prints the CHANGELOG section for one version, to use as release notes.
#
#     bash build/release-notes.sh 1.0.0
#
# Everything under `## [1.0.0]` up to the next `## [` heading or the link
# reference definitions at the foot of the file, with the heading itself
# dropped (the release is already titled) and surrounding blank lines trimmed.
# Exits non-zero when the section is missing or empty, because a release
# published with no notes is a release nobody can evaluate.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

version=${1:-}
version=${version#v}

if [ -z "$version" ]; then
	echo "usage: $0 <version>" >&2
	exit 2
fi

notes=$(awk -v want="$version" '
	/^## \[/ {
		if (found) exit
		v = $0
		sub(/^## \[/, "", v)
		sub(/\].*/, "", v)
		if (v == want) { found = 1; next }
	}
	/^\[[^]]+\]: / { if (found) exit }
	found { print }
' "$ROOT/CHANGELOG.md" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')

if [ -z "$notes" ]; then
	echo "release-notes: CHANGELOG.md has no '## [$version]' section, or it is empty." >&2
	exit 1
fi

printf '%s\n' "$notes"
