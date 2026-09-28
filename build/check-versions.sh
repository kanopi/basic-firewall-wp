#!/usr/bin/env bash
#
# Every place the plugin states its version must state the same one.
#
# WordPress reads the header, the updater compares against readme.txt's Stable
# tag, the code reports BASIC_FIREWALL_VERSION, the release is named after the
# tag, and the changelog is what the release notes are cut from. Any two of
# those disagreeing ships a release that describes itself wrongly -- the most
# likely form being a tag pushed before the bump, which would publish last
# release's code under this release's name.
#
# Two modes:
#
#   bash build/check-versions.sh
#       The header, the constant and the Stable tag agree with each other.
#       Cheap, and run on every branch so drift is caught when it is made
#       rather than on release day.
#
#   bash build/check-versions.sh --release [TAG]
#       All of the above, and the newest released CHANGELOG heading -- the
#       first `## [x.y.z]` that is not `[Unreleased]` -- agrees too. With a TAG
#       (or CIRCLE_TAG set, which is how CI runs it) the tag must match as
#       well; a leading `v` is ignored, so `v1.0.0` and `1.0.0` are the same.
#
# A pre-release is not special-cased: to tag 1.1.0-rc.1, every one of these says
# 1.1.0-rc.1 and the changelog has a `## [1.1.0-rc.1]` section to use as notes.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

release=0
tag=${CIRCLE_TAG:-}

while [ $# -gt 0 ]; do
	case "$1" in
		--release) release=1 ;;
		-h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		-*) echo "check-versions: unknown option $1" >&2; exit 2 ;;
		*) tag=$1; release=1 ;;
	esac
	shift
done

# A tag always means a release check, however the script was invoked.
[ -n "$tag" ] && release=1

# ` * Version:           1.0.0` in the plugin file's header block.
header=$(sed -n 's/^[[:space:]]*\*[[:space:]]*Version:[[:space:]]*\([^[:space:]]*\).*/\1/p' \
	"$ROOT/basic-firewall.php" | head -1)

# define( 'BASIC_FIREWALL_VERSION', '1.0.0' ); -- optional, checked when present.
constant=$(sed -n "s/.*define([[:space:]]*'BASIC_FIREWALL_VERSION',[[:space:]]*'\([^']*\)'.*/\1/p" \
	"$ROOT/basic-firewall.php" | head -1)

stable=$(sed -n 's/^Stable tag:[[:space:]]*\([^[:space:]]*\).*/\1/p' "$ROOT/readme.txt" | head -1)

problems=0

fail() {
	echo "  FAIL  $*" >&2
	problems=$(( problems + 1 ))
}

if [ -z "$header" ]; then
	fail "basic-firewall.php has no 'Version:' header"
fi

printf '  plugin header   %s\n' "${header:-<none>}"

if [ -n "$constant" ]; then
	printf '  constant        %s\n' "$constant"
	[ "$constant" = "$header" ] || fail "BASIC_FIREWALL_VERSION is $constant, the header says $header"
else
	printf '  constant        <not defined, skipped>\n'
fi

printf '  readme.txt      %s\n' "${stable:-<none>}"

if [ -z "$stable" ]; then
	fail "readme.txt has no 'Stable tag:'"
elif [ "$stable" != "$header" ]; then
	fail "readme.txt Stable tag is $stable, the header says $header"
fi

if [ "$release" = 1 ]; then
	# The first `## [...]` heading that is not Unreleased, with any trailing
	# date (`## [1.0.0] - 2026-10-01`) ignored.
	changelog=$(awk '
		/^## \[/ {
			v = $0
			sub(/^## \[/, "", v)
			sub(/\].*/, "", v)
			if (tolower(v) != "unreleased") { print v; exit }
		}
	' "$ROOT/CHANGELOG.md")

	printf '  CHANGELOG.md    %s\n' "${changelog:-<none>}"

	if [ -z "$changelog" ]; then
		fail "CHANGELOG.md has no released section (a '## [x.y.z]' heading other than Unreleased)"
	elif [ "$changelog" != "$header" ]; then
		fail "the newest released CHANGELOG section is $changelog, the header says $header"
	fi

	if [ -n "$tag" ]; then
		tag_version=${tag#v}
		printf '  tag             %s\n' "$tag"
		[ "$tag_version" = "$header" ] || fail "the tag is $tag, the header says $header"
	fi
fi

if [ "$problems" -gt 0 ]; then
	echo "check-versions: $problems disagreement(s). Bump every one of them together; see README, Releasing." >&2
	exit 1
fi

echo "check-versions: all agree on ${header}."
