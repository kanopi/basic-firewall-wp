#!/usr/bin/env bash
#
# The release zip, installed and made to refuse a real request.
#
# build/build-zip.sh proves the scoped build resolves its classes. It cannot
# prove the zip works as a plugin, because nothing in it runs WordPress: a zip
# that fatals on activation, or that activates and then never enforces, passes
# every check the build makes. This is the check that it does not.
#
# Against a clean, served WordPress with nothing of this plugin on it:
#
#   1. install the zip through `wp plugin install`, the same code path an
#      upload through Plugins -> Add New takes, and activate it
#   2. confirm it loaded scoped and installed its mu-plugin
#   3. prove a request to the smoke path is NOT refused before the rule exists,
#      so the 403 later is the rule's doing and not the site's
#   4. import a single block rule through `wp basic-firewall import`
#   5. an unmatched request is allowed, and the matched one is refused with the
#      configured message -- in that order, because refusing a request records
#      the client in the block list and every later request from it is refused
#      by that instead of by the rule
#   6. deactivate and uninstall, both exiting 0, and leave nothing behind
#
# Usage:
#
#     BFW_WP="wp --path=/tmp/clean --allow-root" \
#     BFW_SMOKE_URL=http://127.0.0.1:8081 \
#       bash tests/package/smoke.sh build/dist/basic-firewall-1.0.0.zip
#
# The site must be one you are willing to throw away, with no copy of this
# plugin on it: the install is refused if one is already there, so the zip is
# never tested on top of leftovers, and the script ends by uninstalling, which
# deletes the plugin's settings. CI runs it on a site that exists for one job.
#
# Paths are as the `wp` process sees them. The zip argument and BFW_FIXTURE are
# handed to `wp`, not opened here, so under a container they must name the
# file inside the container.
#
# Keeping Composer off PATH is the caller's job, because only the caller knows
# which PATH the web server and `wp` run under. CI hides the binary before this
# runs and asserts it is gone.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

WP=${BFW_WP:-wp}
URL=${BFW_SMOKE_URL:-http://127.0.0.1:8081}
URL=${URL%/}
FIXTURE=${BFW_FIXTURE:-$ROOT/tests/package/block-rule.yml}

ZIP=${1:-}

if [ -z "$ZIP" ]; then
	# The newest build, if the caller did not say. A glob that matches nothing
	# stays literal, which the install then reports as a missing file.
	ZIP=$(ls -t "$ROOT"/build/dist/basic-firewall-*.zip 2>/dev/null | head -1)
fi

readonly SLUG=basic-firewall
readonly BLOCKED_PATH=/bfw-package-smoke-blocked
readonly BLOCK_MESSAGE='Blocked by the package smoke test.'

passed=0
failed=0

summary() {
	printf '\n%s\n' "----------------------------------------------------------------"

	if [ "$failed" -gt 0 ]; then
		printf 'package: %d passed, %d FAILED\n' "$passed" "$failed"
		exit 1
	fi

	printf 'package: %d passed\n' "$passed"
}
trap summary EXIT

report() {
	local outcome=$1 description=$2 detail=${3:-}

	if [ "$outcome" = pass ]; then
		passed=$(( passed + 1 ))
		printf '  ok    %s\n' "$description"

		return
	fi

	failed=$(( failed + 1 ))
	printf '  FAIL  %s\n' "$description"
	[ -n "$detail" ] && printf '%s\n' "$detail" | sed 's/^/        /'
}

# Stop at the first failure from here on. Every later step depends on the one
# before it -- nothing is refused by a plugin that did not activate -- so
# carrying on only buries the real failure under the ones it caused.
bail() {
	printf '\npackage: stopping; every later check depends on this one.\n'
	exit 1
}

# Run a `wp` command, asserting its exit status and optionally what it printed.
#
# Arguments: <ok|fail> <description> <substring or ''> <wp arguments...>
expect_wp() {
	local want=$1 description=$2 needle=$3
	shift 3

	local output status
	output=$($WP "$@" </dev/null 2>&1)
	status=$?

	if [ "$want" = ok ] && [ "$status" -ne 0 ]; then
		report fail "$description" "expected exit 0, got $status:
$output"

		return 1
	fi

	if [ "$want" = fail ] && [ "$status" -eq 0 ]; then
		report fail "$description" "expected a non-zero exit, got 0:
$output"

		return 1
	fi

	if [ -n "$needle" ] && ! printf '%s' "$output" | grep -qF -- "$needle"; then
		report fail "$description" "output did not contain '$needle':
$output"

		return 1
	fi

	# A PHP warning is not an exit status, and a zip that activates noisily is
	# a zip that will fill a customer's error log.
	if printf '%s' "$output" | grep -qE 'PHP (Fatal error|Warning|Deprecated|Notice)'; then
		report fail "$description" "PHP complained:
$output"

		return 1
	fi

	report pass "$description"
}

# Request a path, asserting the status and optionally the body.
#
# Arguments: <status or !status> <description> <path> [body substring]
expect_http() {
	local want=$1 description=$2 path=$3 needle=${4:-}
	local body status

	body=$(mktemp)
	status=$(curl -s -o "$body" -w '%{http_code}' --max-time 30 \
		-A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36' \
		"$URL$path")

	local ok=1

	case "$want" in
		!*) [ "$status" != "${want#!}" ] || ok=0 ;;
		*) [ "$status" = "$want" ] || ok=0 ;;
	esac

	if [ "$ok" = 1 ] && [ -n "$needle" ] && ! grep -qF -- "$needle" "$body"; then
		report fail "$description" "status $status as expected, but the body did not contain '$needle':
$(head -c 400 "$body")"
		rm -f "$body"

		return 1
	fi

	rm -f "$body"

	if [ "$ok" = 0 ]; then
		report fail "$description" "wanted $want from $URL$path, got $status"

		return 1
	fi

	report pass "$description"
}

printf 'package: %s\n' "$ZIP"
printf '         against %s\n\n' "$URL"

printf 'package: install and activate\n'

expect_wp ok 'the site is reachable through wp' '' core is-installed || bail
expect_http 200 'the site answers over HTTP before the plugin is installed' / || bail

expect_wp fail 'the site has no copy of the plugin yet' '' plugin is-installed "$SLUG" || bail
expect_wp ok 'the zip installs and activates' "Plugin 'basic-firewall' activated" \
	plugin install "$ZIP" --activate || bail
expect_wp ok 'WordPress reports it active' '' plugin is-active "$SLUG" || bail

# The claim the zip exists to make. An unscoped zip would still pass everything
# below, and then collide with the first other plugin that bundles the library.
expect_wp ok 'it loaded the scoped library' 'yes (scoped)' basic-firewall status || bail
expect_wp ok 'activation installed the mu-plugin loader' 'present' \
	eval 'echo file_exists( WPMU_PLUGIN_DIR . "/basic-firewall-loader.php" ) ? "present" : "missing";' || bail

printf '\npackage: a rule, and a request it refuses\n'

# Without this the 403 below could be anything that refuses the path -- a web
# server rule, a missing file handler -- and the test would pass with the
# firewall doing nothing.
expect_http '!403' 'the smoke path is not refused before the rule exists' "$BLOCKED_PATH" || bail

expect_wp ok 'a block rule imports and compiles' 'Imported and recompiled' \
	basic-firewall import "$FIXTURE" --yes || bail
expect_wp ok 'the rule is in the rule set' 'package_smoke_block_path' basic-firewall rules || bail

# Control first. See the header: after the block, this address is on the block
# list and everything it asks for is refused.
expect_http 200 'an unmatched request is allowed' / || bail
expect_http 403 'the matched request is refused with the configured message' \
	"$BLOCKED_PATH" "$BLOCK_MESSAGE" || bail

printf '\npackage: deactivate and uninstall\n'

expect_wp ok 'deactivate exits 0' 'deactivated' plugin deactivate "$SLUG" || bail
expect_wp ok 'deactivation removed the mu-plugin loader' 'gone' \
	eval 'echo file_exists( WPMU_PLUGIN_DIR . "/basic-firewall-loader.php" ) ? "present" : "gone";'

# The firewall is off now, so the block list recorded above no longer answers.
expect_http 200 'the site serves again once the plugin is deactivated' /

expect_wp ok 'uninstall exits 0' 'Uninstalled' plugin uninstall "$SLUG"
expect_wp fail 'the plugin files are gone' '' plugin is-installed "$SLUG"
expect_wp fail 'the settings are gone' '' option get basic_firewall_settings
