#!/usr/bin/env bash
#
# Every WP-CLI subcommand, exercised against a real site.
#
# The integration suite calls PHP; this calls `wp`. Between the two sits
# everything WP-CLI itself owns and PHPUnit cannot reach: whether a method is
# registered as a subcommand at all, whether its `## OPTIONS` block parses,
# whether a flag the docblock advertises is accepted, and what the process
# exits with. A command can be perfectly correct PHP and still be unreachable
# from a shell, which is the only place anybody actually runs it.
#
# Exit status is the point of several of these. `check` exits 0 whether or not
# the address was blocked, because the status reports whether the query ran --
# a deploy script that reads a non-zero exit as "blocked" would be wrong. And
# anything destructive must exit NON-zero when it refuses, because the failure
# this guards against is a command that prints a prompt nobody answers and then
# exits 0 having changed nothing.
#
# Usage:
#
#     BFW_WP="ddev wp" bash tests/cli/commands.sh
#     BFW_WP="wp --path=/tmp/wp --allow-root" bash tests/cli/commands.sh
#
# Nothing here reads a file back from the script's own filesystem, and that is
# deliberate rather than tidy: `ddev wp` runs inside a container, so a path this
# script can see is not a path the command can write to. Assertions are made on
# what the command printed, and the one file involved is named in BFW_TMP as the
# *command* sees it.
#
# Destructive coverage -- `clear-blocked --yes` and `import --mode=replace
# --yes` -- is opt-in through BFW_CLI_DESTRUCTIVE=1, and CI opts in because its
# site is thrown away afterwards. Without it the refusals are still asserted,
# which is the half that has actually broken before; what is skipped is only
# the confirmation that agreeing works. Running this against a site you care
# about therefore does not empty its block list.

set -uo pipefail

WP=${BFW_WP:-wp}
DESTRUCTIVE=${BFW_CLI_DESTRUCTIVE:-0}

# A writable directory as the `wp` process sees it, which under ddev is inside
# the container and not this shell's /tmp.
TMP=${BFW_TMP:-/tmp}
readonly EXPORT_FILE="$TMP/bfw-cli-commands.yml"

# RFC 5737 reserves this range for documentation, so it can never be an address
# this site legitimately has an opinion about.
readonly ADDRESS=203.0.113.242

passed=0
failed=0

cleanup() {
	# Best effort, and quiet: the address is ours, and leaving it blocked would
	# make a second run of this script start from a different place than the
	# first.
	$WP basic-firewall unblock "$ADDRESS" >/dev/null 2>&1

	printf '\n%s\n' "----------------------------------------------------------------"

	if [ "$failed" -gt 0 ]; then
		printf 'wp-cli: %d passed, %d FAILED\n' "$passed" "$failed"
		exit 1
	fi

	printf 'wp-cli: %d passed\n' "$passed"
}
trap cleanup EXIT

# Record a result. Keeps the reason next to the assertion rather than leaving a
# bare "failed" for somebody to go and reproduce.
report() {
	local outcome=$1 description=$2 detail=${3:-}

	if [ "$outcome" = pass ]; then
		passed=$(( passed + 1 ))
		printf '  ok    %s\n' "$description"

		return
	fi

	failed=$(( failed + 1 ))
	printf '  FAIL  %s\n' "$description"
	[ -n "$detail" ] && printf '        %s\n' "$detail"
}

# Run a subcommand, asserting the exit status and optionally what it printed.
#
# Arguments: <expected status> <description> <substring or ''> <command...>
# Stdin is closed, because a command that waits for an answer nobody is there
# to give must fail rather than hang the run.
expect() {
	local want=$1 description=$2 needle=$3
	shift 3

	local output status
	output=$($WP basic-firewall "$@" </dev/null 2>&1)
	status=$?

	if [ "$want" = ok ] && [ "$status" -ne 0 ]; then
		report fail "$description" "expected exit 0, got $status: $(printf '%s' "$output" | head -1)"

		return
	fi

	if [ "$want" = fail ] && [ "$status" -eq 0 ]; then
		report fail "$description" 'expected a non-zero exit, got 0'

		return
	fi

	if [ -n "$needle" ] && ! printf '%s' "$output" | grep -qF "$needle"; then
		report fail "$description" "output did not contain '$needle': $(printf '%s' "$output" | head -1)"

		return
	fi

	report pass "$description"
}

printf 'wp-cli: reporting commands\n'

expect ok 'status reports the library version' 'Library' status
expect ok 'status renders as json' '"Enabled"' status --format=json
expect ok 'rules lists in evaluation order' '' rules
expect ok 'sources lists the presets' '' sources
expect ok 'blocked lists the block list' '' blocked
expect ok 'rebuild recompiles' 'Compiled to' rebuild

printf '\nwp-cli: the block list\n'

expect ok 'check answers for an address that is not blocked' 'false' check "$ADDRESS"
expect ok 'block takes a duration and a reason' 'is blocked' \
	block "$ADDRESS" --duration=600 --reason='CLI coverage'
expect ok 'check sees the block it just made' 'true' check "$ADDRESS"
expect ok 'check reports the reason back' 'CLI coverage' check "$ADDRESS"
expect ok 'blocked lists the blocked address' "$ADDRESS" blocked
expect ok 'unblock releases it' 'unblocked' unblock "$ADDRESS"
expect ok 'check sees it released' 'false' check "$ADDRESS"

# The exit status reports whether the query ran, not what the answer was. A
# deploy script reading non-zero as "this address is blocked" would be wrong on
# every run, so this is pinned rather than left to read like an accident.
expect ok 'check exits 0 for an address that is not blocked' '' check 198.51.100.7

printf '\nwp-cli: references and lists\n'

expect fail 'find-reference refuses a reference that does not exist' 'was not found' \
	find-reference BFW-NO-SUCH-REFERENCE
expect ok 'refresh-sources previews without fetching' '' refresh-sources --dry-run

printf '\nwp-cli: export and import\n'

expect ok 'export writes to standard output' 'Basic Firewall configuration export' export

# The invariant the whole export path exists to hold, asserted on the document
# itself rather than on a unit test's idea of it: a credential is removed, and
# the document says which, so a receiving site knows what it has to supply.
expect ok 'the export names the credentials it stripped' 'REMOVED from this export' export

expect ok 'export writes a document to a file' 'Written to' export --file="$EXPORT_FILE"
expect fail 'export refuses a rule that does not exist' 'no rule with the identifier' \
	export --rule=bfw-no-such-rule

expect ok 'import previews without changing anything' 'nothing was changed' \
	import "$EXPORT_FILE" --dry-run

printf '\nwp-cli: destructive commands refuse without --yes\n'

# The one that has actually gone wrong. WP_CLI::confirm() calls halt(0) when it
# reads EOF, so with stdin closed the old behaviour was a prompt nobody answered
# and an exit 0 that a deploy script reads as success.
expect fail 'import --mode=replace refuses without --yes' 'Nothing was changed' \
	import "$EXPORT_FILE" --mode=replace
expect fail 'clear-blocked refuses without --yes' 'Nothing was changed' clear-blocked

if [ "$DESTRUCTIVE" != 1 ]; then
	printf '  skip  agreeing to a destructive command (set BFW_CLI_DESTRUCTIVE=1)\n'

	exit 0
fi

printf '\nwp-cli: destructive commands proceed with --yes\n'

expect ok 'import --mode=replace proceeds with --yes' 'Imported and recompiled' \
	import "$EXPORT_FILE" --mode=replace --yes
expect ok 'clear-blocked proceeds with --yes' 'Released' clear-blocked --yes
