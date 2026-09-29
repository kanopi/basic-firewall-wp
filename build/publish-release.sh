#!/usr/bin/env bash
#
# Publishes a GitHub Release for a tag, with the zip attached twice: as
# basic-firewall-<version>.zip, and as basic-firewall.zip for the stable
# releases/latest/download URL that `wp plugin install` is pointed at.
#
#     GITHUB_TOKEN=... bash build/publish-release.sh v1.0.0 build/dist/basic-firewall-1.0.0.zip
#
# Run by the CircleCI `release` job, which only exists on tag builds and only
# after every other job -- the whole matrix, the version check and the package
# smoke test -- has passed. It is not meant to be run by hand, but nothing stops
# it, and it does the same thing either way.
#
#   - Refuses unless every version the plugin states agrees with the tag
#     (build/check-versions.sh).
#   - Notes are the matching CHANGELOG section (build/release-notes.sh).
#   - A version with a pre-release suffix (1.1.0-rc.1) is published as a GitHub
#     pre-release, so it is never offered as "Latest".
#   - Re-running for a tag that already has a release replaces the zip and the
#     notes rather than failing, so a job re-run after a flaky upload finishes
#     the job instead of needing the release deleted by hand.
#
# Needs `gh` on PATH and GITHUB_TOKEN (or GH_TOKEN) with write access to the
# repository's contents. The repository is taken from GITHUB_REPOSITORY, else
# CircleCI's CIRCLE_PROJECT_USERNAME/CIRCLE_PROJECT_REPONAME, else
# kanopi/basic-firewall-wp.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tag=${1:-${CIRCLE_TAG:-}}
zip=${2:-}

if [ -z "$tag" ] || [ -z "$zip" ]; then
	echo "usage: $0 <tag> <zip>" >&2
	exit 2
fi

if [ ! -f "$zip" ]; then
	echo "publish-release: $zip does not exist." >&2
	exit 1
fi

if [ -z "${GITHUB_TOKEN:-}${GH_TOKEN:-}" ]; then
	cat >&2 <<'EOF'
publish-release: neither GITHUB_TOKEN nor GH_TOKEN is set.

In CI the release job gets one from ci-tools/github-app-token, which exchanges
the Kanopi GitHub App's credentials in the kanopi-code context for an
installation token. If you are reading this there, that exchange failed: check
its step output, that the App is installed on this repository with Contents:
Read and write, and that the job runs with the kanopi-code context.
See README, "Releasing".
EOF
	exit 1
fi

if [ -n "${GITHUB_REPOSITORY:-}" ]; then
	repo=$GITHUB_REPOSITORY
elif [ -n "${CIRCLE_PROJECT_USERNAME:-}" ] && [ -n "${CIRCLE_PROJECT_REPONAME:-}" ]; then
	repo="$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME"
else
	repo=kanopi/basic-firewall-wp
fi

version=${tag#v}

echo "==> Checking every stated version agrees with ${tag}"
bash "$ROOT/build/check-versions.sh" --release "$tag"

# The zip is named after the header version by build/build-zip.sh. Checking the
# name as well catches a workspace carrying a stale build.
case "$(basename "$zip")" in
	"basic-firewall-${version}.zip") ;;
	*)
		echo "publish-release: $zip is not basic-firewall-${version}.zip." >&2
		exit 1
		;;
esac

notes=$(mktemp)
stable_dir=$(mktemp -d)
trap 'rm -rf "$notes" "$stable_dir"' EXIT

# The same zip again under a name with no version in it. GitHub serves
# releases/latest/download/<asset> from whichever release is marked Latest, so a
# fixed name is what gives `wp plugin install <url>` one URL that always means
# the current release -- on a site with no Composer, that URL is the whole
# install. Pre-releases are never Latest, so an -rc tag cannot be picked up by
# it. The versioned asset stays for anyone pinning a release.
stable_zip="$stable_dir/basic-firewall.zip"
cp "$zip" "$stable_zip"

echo "==> Cutting release notes from CHANGELOG.md"
bash "$ROOT/build/release-notes.sh" "$version" > "$notes"

prerelease=false
case "$version" in
	*-*) prerelease=true ; echo "==> ${version} is a pre-release" ;;
esac

title="Basic Firewall ${version}"

if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
	echo "==> ${tag} already has a release on ${repo}; replacing its zip and notes"
	gh release upload "$tag" "$zip" "$stable_zip" --repo "$repo" --clobber
	gh release edit "$tag" --repo "$repo" --title "$title" --notes-file "$notes" --prerelease="$prerelease"
else
	echo "==> Creating the ${tag} release on ${repo}"
	# --verify-tag: the tag must already exist on GitHub. Without it gh would
	# create one from the default branch, which is exactly the release this
	# pipeline exists to prevent.
	gh release create "$tag" "$zip" "$stable_zip" \
		--repo "$repo" \
		--verify-tag \
		--title "$title" \
		--notes-file "$notes" \
		--prerelease="$prerelease"
fi

gh release view "$tag" --repo "$repo" --json url,isPrerelease,assets \
	--jq '"==> Published \(.url) (pre-release: \(.isPrerelease)) with \([.assets[].name] | join(", "))"'
