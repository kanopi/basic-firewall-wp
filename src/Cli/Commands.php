<?php
/**
 * WP-CLI commands.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Cli;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Library_Loader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Runtime\Trusted_Proxies;
use Kanopi\BasicFirewall\Sources\Refresher;
use Kanopi\BasicFirewall\Transfer\Exporter;
use Kanopi\BasicFirewall\Transfer\Importer;
use WP_CLI;
use WP_CLI\Utils;

/**
 * Manage the Basic Firewall.
 *
 * The same twelve verbs as the Drush commands, so a runbook written for one
 * site works on the other.
 */
final class Commands {

	/**
	 * Register the command.
	 */
	public static function register(): void {
		WP_CLI::add_command( 'basic-firewall', self::class );
	}

	/**
	 * Require explicit agreement before doing something destructive.
	 *
	 * Not WP_CLI::confirm(). That helper calls WP_CLI::halt(0) when the answer
	 * is anything but "y" -- and reaching EOF on a closed stdin counts, which is
	 * what every CI job and every `wp ... < /dev/null` does. The result is a
	 * command that prints a prompt nobody answers and then **exits 0 having
	 * changed nothing**, which a deploy script reads as "the import succeeded".
	 *
	 * Measured before this existed: `wp basic-firewall import file --mode=replace`
	 * with stdin closed printed the prompt and returned 0.
	 *
	 * So: --yes proceeds, an interactive "y" proceeds, and everything else is an
	 * error with a non-zero status.
	 *
	 * @param string                $question   What is about to happen.
	 * @param array<string, string> $assoc_args Flags, checked for --yes.
	 */
	private function confirm_or_fail( string $question, array $assoc_args ): void {
		if ( (bool) Utils\get_flag_value( $assoc_args, 'yes', false ) ) {
			return;
		}

		$interactive = function_exists( 'posix_isatty' ) && @posix_isatty( STDIN ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( ! $interactive ) {
			WP_CLI::error(
				sprintf(
					'%s Nothing was changed. Re-run with --yes to agree to this in a non-interactive context.',
					$question
				)
			);
		}

		WP_CLI::out( $question . ' [y/n] ' );

		$answer = fgets( STDIN );

		if ( ! is_string( $answer ) || 'y' !== strtolower( trim( $answer ) ) ) {
			WP_CLI::error( 'Cancelled. Nothing was changed.' );
		}
	}

	/**
	 * Refresh the rule lists referenced by rules.
	 *
	 * A rule can name a published list by URL instead of carrying a copy of it.
	 * The request path never fetches one -- it reads a cache and nothing else,
	 * so a provider's outage cannot become this site's latency -- which makes
	 * this command, and the schedule behind it, what keeps that cache current.
	 *
	 * Runs on a WP-Cron schedule by default. Use this after adding a rule that
	 * references a list, on a host where WP-Cron is disabled, or from a deploy.
	 *
	 * ## OPTIONS
	 *
	 * [--force]
	 * : Revalidate every list, even one the cache still considers fresh.
	 *
	 * [--dry-run]
	 * : List what is referenced and what the cache holds. Fetches nothing.
	 *
	 * ## EXAMPLES
	 *
	 *     wp basic-firewall refresh-sources
	 *     wp basic-firewall refresh-sources --force
	 *     wp basic-firewall refresh-sources --dry-run
	 *
	 * @subcommand refresh-sources
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function refresh_sources( array $args, array $assoc_args ): void {
		$declarations = Refresher::declarations();

		if ( array() === $declarations ) {
			WP_CLI::success( 'No rule references a list, so there was nothing to refresh.' );

			return;
		}

		if ( isset( $assoc_args['dry-run'] ) ) {
			$rows = array();

			foreach ( $declarations as $declaration ) {
				$rows[] = array(
					'name'     => (string) ( $declaration['name'] ?? 'unnamed' ),
					'upstream' => is_array( $declaration['upstream'] ?? null )
						? (string) ( $declaration['upstream']['url'] ?? '' )
						: (string) ( $declaration['upstream'] ?? '' ),
					'ttl'      => (string) ( $declaration['ttl'] ?? '' ),
					'on_error' => (string) ( $declaration['onError'] ?? 'last_known_good' ),
				);
			}

			Utils\format_items( 'table', $rows, array( 'name', 'upstream', 'ttl', 'on_error' ) );

			return;
		}

		$result = Refresher::refresh( isset( $assoc_args['force'] ) );

		foreach ( $result['refreshed'] as $name => $count ) {
			WP_CLI::log( sprintf( '  %-28s %d entries', $name, $count ) );
		}

		foreach ( $result['failed'] as $name => $message ) {
			WP_CLI::warning( sprintf( '%s: %s', $name, $message ) );
		}

		if ( ! $result['ran'] ) {
			WP_CLI::error( $result['message'] );
		}

		/*
		 * A failure exits non-zero even though traffic is unaffected, because
		 * the caller is a deploy or a cron wrapper and the whole value of the
		 * arrangement is that somebody finds out a list has gone stale before
		 * it starts mattering.
		 */
		if ( array() !== $result['failed'] ) {
			WP_CLI::error( $result['message'] );
		}

		WP_CLI::success( $result['message'] );
	}

	/**
	 * Recompile the configuration.
	 *
	 * ## EXAMPLES
	 *
	 *     wp basic-firewall rebuild
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function rebuild( array $args, array $assoc_args ): void {
		$result = Plugin::instance()->compiled()->rebuild();

		foreach ( $result['problems'] as $problem ) {
			WP_CLI::warning( $problem );
		}

		if ( ! $result['written'] ) {
			// Never exit 0 having failed.
			WP_CLI::error( 'The configuration could not be compiled. The firewall is running on whatever was compiled before, or on nothing.' );
		}

		/*
		 * Problems are a warning, not a success. A rebuild that skipped a rule
		 * because its type is unavailable has produced a firewall enforcing less
		 * than the administrator configured, and a green "Success" over the top
		 * of that is how it goes unnoticed.
		 */
		if ( array() !== $result['problems'] ) {
			WP_CLI::error(
				sprintf(
					'Compiled with %d problem(s). The firewall is enforcing less than is configured.',
					count( $result['problems'] )
				)
			);
		}

		WP_CLI::success( sprintf( 'Compiled to %s', $result['path'] ) );
	}

	/**
	 * Report what the firewall is doing right now.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp basic-firewall status
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function status( array $args, array $assoc_args ): void {
		$plugin   = Plugin::instance();
		$settings = $plugin->settings();
		$compiled = $plugin->compiled();
		$paths    = $plugin->paths();

		$mode = (string) $settings->get( 'global.mode', 'log' );

		$forced = defined( 'BASIC_FIREWALL_MODE' ) ? (string) constant( 'BASIC_FIREWALL_MODE' ) : null;

		$rows = array(
			array(
				'setting' => 'Enabled',
				'value'   => $plugin->runner()->is_enabled() ? 'yes' : 'no',
			),
			array(
				'setting' => 'Mode',
				'value'   => null !== $forced
					? sprintf( '%s (forced by BASIC_FIREWALL_MODE, configured as %s)', $forced, $mode )
					: $mode,
			),
			array(
				'setting' => 'Library',
				'value'   => sprintf( '%s (%s)', Library_Loader::version() ?? 'unknown', Library_Loader::mode() ?? 'not loaded' ),
			),
			array(
				'setting' => 'Collision safe',
				'value'   => Library_Loader::is_collision_safe() ? 'yes (scoped)' : 'no (unscoped vendor tree)',
			),
			array(
				'setting' => 'Compiled configuration',
				'value'   => $compiled->exists() ? $paths->compiled_file() : 'MISSING — run `wp basic-firewall rebuild`',
			),
			array(
				'setting' => 'Rules configured',
				'value'   => (string) count( (array) $settings->get( 'rules', array() ) ),
			),
			array(
				'setting' => 'Presets enabled',
				'value'   => (string) count( (array) $settings->get( 'presets', array() ) ),
			),
			array(
				'setting' => 'Block list storage',
				'value'   => (string) $settings->get( 'storage.backend', 'file' ),
			),
			array(
				'setting' => 'Evaluation point',
				'value'   => $this->evaluation_summary(),
			),
			array(
				'setting' => 'Proxy posture',
				'value'   => $this->proxy_summary(),
			),
			array(
				'setting' => 'Private directory',
				'value'   => $paths->base(),
			),
		);

		Utils\format_items(
			(string) ( $assoc_args['format'] ?? 'table' ),
			$rows,
			array( 'setting', 'value' )
		);

		foreach ( ( new Library_Capabilities() )->unavailable() as $missing ) {
			WP_CLI::warning( sprintf( '%s: %s', $missing['feature'], $missing['reason'] ) );
		}

		if ( 'log' === $mode ) {
			WP_CLI::log( '' );
			WP_CLI::log( 'Mode is "log": rules are evaluated and matches recorded, but nothing is blocked.' );
		}
	}

	/**
	 * Where the firewall runs, and whether its fallback is in place.
	 *
	 * Reported because `status` is what a runbook calls after a deployment,
	 * and a deployment is exactly what silently removes either piece: an
	 * overwritten wp-config.php takes the early path, and a wp-content sync
	 * takes the mu-plugin loader. Both leave a firewall that still works and
	 * evaluates later than it should, which is the kind of regression nothing
	 * reports unless it is asked to.
	 */
	private function evaluation_summary(): string {
		$mu    = is_readable( WPMU_PLUGIN_DIR . '/basic-firewall-loader.php' );
		$early = Site_Health::early_report();

		if ( $early['called'] && ! $early['evaluated'] && 'disabled' !== $early['reason'] ) {
			return sprintf(
				'wp-config.php snippet present but NOT evaluating (%s) — running from the mu-plugin instead',
				(string) $early['reason']
			);
		}

		if ( $early['called'] ) {
			return $mu
				? 'wp-config.php, before WordPress (mu-plugin fallback installed)'
				: 'wp-config.php, before WordPress (mu-plugin fallback MISSING)';
		}

		return $mu
			? 'mu-plugin, before plugins and the theme'
			: 'plugins_loaded — LATE. The mu-plugin loader is missing; reactivate the plugin';
	}

	/**
	 * Summarise the proxy posture.
	 */
	private function proxy_summary(): string {
		$answer     = (string) Plugin::instance()->settings()->get( 'global.behind_proxy', 'unknown' );
		$configured = Trusted_Proxies::are_configured();

		if ( $configured ) {
			return sprintf( 'trusted proxies configured (answer: %s)', $answer );
		}

		return match ( $answer ) {
			'yes' => 'ERROR — declared behind a proxy, but no trusted proxies are configured. Every address rule is forgeable.',
			'no'  => 'asserted: not behind a proxy',
			default => 'UNKNOWN — nobody has answered whether this site is behind a proxy.',
		};
	}

	/**
	 * List the rules in evaluation order.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - yaml
	 *   - csv
	 * ---
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function rules( array $args, array $assoc_args ): void {
		$registry = Plugin::instance()->rule_types();
		$rules    = (array) Plugin::instance()->settings()->get( 'rules', array() );

		if ( array() === $rules ) {
			WP_CLI::log( 'No rules are configured.' );

			return;
		}

		usort(
			$rules,
			static fn ( array $a, array $b ): int => ( (int) ( $a['weight'] ?? 0 ) ) <=> ( (int) ( $b['weight'] ?? 0 ) )
		);

		$rows = array();

		foreach ( $rules as $rule ) {
			$type = $registry->get( (string) ( $rule['type'] ?? '' ) );

			$rows[] = array(
				'id'       => (string) ( $rule['id'] ?? '' ),
				'type'     => (string) ( $rule['type'] ?? '' ),
				'response' => (string) ( $rule['response'] ?? '' ),
				'weight'   => (int) ( $rule['weight'] ?? 0 ),
				'enabled'  => empty( $rule['enabled'] ) ? 'no' : 'yes',
				'status'   => null === $type
					? 'UNKNOWN TYPE'
					: ( $type->is_available() ? 'ok' : 'UNAVAILABLE' ),
			);
		}

		Utils\format_items(
			(string) ( $assoc_args['format'] ?? 'table' ),
			$rows,
			array( 'id', 'type', 'response', 'weight', 'enabled', 'status' )
		);
	}

	/**
	 * List every blocked client.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - yaml
	 *   - csv
	 * ---
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function blocked( array $args, array $assoc_args ): void {
		$listing = Plugin::instance()->blocked()->all();

		if ( ! $listing['supported'] ) {
			// Says so rather than printing an empty table, which would read as
			// "nobody is blocked".
			WP_CLI::error( 'The configured storage backend cannot list what it holds. Use `wp basic-firewall check <ip>` to ask about one address.' );
		}

		if ( array() === $listing['clients'] ) {
			WP_CLI::log( 'No clients are currently blocked.' );

			return;
		}

		$rows = array();

		foreach ( $listing['clients'] as $client ) {
			$rows[] = array(
				'ip'       => (string) $client['ip'],
				'expires'  => $client['permanent'] ? 'never' : gmdate( 'Y-m-d H:i:s', (int) $client['expires'] ) . ' UTC',
				'offenses' => (int) $client['offenses'],
				'rule'     => (string) ( $client['record']['plugin'] ?? '' ),
				'reason'   => (string) ( $client['record']['reason'] ?? '' ),
			);
		}

		Utils\format_items(
			(string) ( $assoc_args['format'] ?? 'table' ),
			$rows,
			array( 'ip', 'expires', 'offenses', 'rule', 'reason' )
		);
	}

	/**
	 * Ask whether an address is blocked.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The client address.
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp basic-firewall check 203.0.113.10
	 *     wp basic-firewall check 203.0.113.10 --format=json
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function check( array $args, array $assoc_args ): void {
		$ip = (string) ( $args[0] ?? '' );

		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			WP_CLI::error( sprintf( '"%s" is not an IP address.', $ip ) );
		}

		$answer = Plugin::instance()->blocked()->check( $ip );
		$record = $answer['record'] ?? array();

		$row = array(
			array(
				'ip'         => $ip,
				'blocked'    => $answer['blocked'] ? 'true' : 'false',
				'backend'    => $answer['backend'],
				'blocked_by' => (string) ( $record['plugin'] ?? '' ),
				'blocked_at' => (string) ( $record['timestamp'] ?? '' ),
				'reference'  => (string) ( $record['event_id'] ?? '' ),
				'reason'     => (string) ( $record['reason'] ?? '' ),
			),
		);

		Utils\format_items(
			(string) ( $assoc_args['format'] ?? 'table' ),
			$row,
			array( 'ip', 'blocked', 'backend', 'blocked_by', 'blocked_at', 'reference', 'reason' )
		);

		/*
		 * Deliberately exits 0 whether or not the address turned out to be
		 * blocked. The exit status reports whether the *query* ran; read the
		 * `blocked` field for the answer. A non-zero exit for "not blocked"
		 * would make every `set -e` script treat a clean address as a failure.
		 */
	}

	/**
	 * Find which rule would match a request.
	 *
	 * ## OPTIONS
	 *
	 * <reference>
	 * : A block reference from a log line or a blocked response.
	 *
	 * ## EXAMPLES
	 *
	 *     wp basic-firewall find-reference 0173FC1BC09BA522
	 *
	 * @subcommand find-reference
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function find_reference( array $args, array $assoc_args ): void {
		$reference = strtoupper( trim( (string) ( $args[0] ?? '' ) ) );

		if ( '' === $reference ) {
			WP_CLI::error( 'Give the reference from the blocked response or the log line.' );
		}

		$listing = Plugin::instance()->blocked()->all();

		if ( $listing['supported'] ) {
			foreach ( $listing['clients'] as $client ) {
				if ( strtoupper( (string) ( $client['record']['event_id'] ?? '' ) ) === $reference ) {
					WP_CLI::success(
						sprintf(
							'%s — blocked by rule "%s" at %s.',
							(string) $client['ip'],
							(string) ( $client['record']['plugin'] ?? 'unknown' ),
							(string) ( $client['record']['timestamp'] ?? 'unknown' )
						)
					);

					return;
				}
			}
		}

		WP_CLI::error( sprintf( 'Reference %s was not found in the block list. It may have expired, or the block may predate the current storage backend.', $reference ) );
	}

	/**
	 * Block an address by hand.
	 *
	 * This adds an entry to the block list, which the firewall consults before
	 * evaluating rules. It does not create a rule: the entry expires like any
	 * other and is not part of an exported document.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The client address.
	 *
	 * [--duration=<seconds>]
	 * : How long to block for. 0 blocks permanently, until cleared by hand.
	 * ---
	 * default: 3600
	 * ---
	 *
	 * [--reason=<reason>]
	 * : Recorded alongside the block.
	 *
	 * ## EXAMPLES
	 *
	 *     wp basic-firewall block 203.0.113.10
	 *     wp basic-firewall block 203.0.113.10 --duration=0 --reason="Scraping"
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function block( array $args, array $assoc_args ): void {
		$ip = (string) ( $args[0] ?? '' );

		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			WP_CLI::error( sprintf( '"%s" is not an IP address.', $ip ) );
		}

		$blocked = Plugin::instance()->blocked();

		if ( ! $blocked->is_durable() ) {
			// Says so rather than reporting success on a block that will not
			// outlive the command.
			WP_CLI::error( 'Storage is set to in-memory, so this block would be discarded the moment the command exits. Nothing was written.' );
		}

		$duration = (int) ( $assoc_args['duration'] ?? 3600 );
		$reason   = (string) ( $assoc_args['reason'] ?? '' );

		if ( ! $blocked->block( $ip, $duration, $reason ) ) {
			WP_CLI::error( sprintf( '%s could not be blocked.', $ip ) );
		}

		WP_CLI::success(
			0 === $duration
				? sprintf( '%s is blocked permanently, until cleared by hand.', $ip )
				: sprintf( '%s is blocked for %d seconds.', $ip, $duration )
		);
	}

	/**
	 * Release an address.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The client address.
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function unblock( array $args, array $assoc_args ): void {
		$ip = (string) ( $args[0] ?? '' );

		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			WP_CLI::error( sprintf( '"%s" is not an IP address.', $ip ) );
		}

		if ( ! Plugin::instance()->blocked()->unblock( $ip ) ) {
			WP_CLI::error( sprintf( '%s was not in the block list, or could not be removed.', $ip ) );
		}

		WP_CLI::success( sprintf( '%s has been unblocked, and its offense history cleared.', $ip ) );
	}

	/**
	 * Empty the block list.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Do not prompt for confirmation.
	 *
	 * ## EXAMPLES
	 *
	 *     wp basic-firewall clear-blocked --yes
	 *
	 * @subcommand clear-blocked
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function clear_blocked( array $args, array $assoc_args ): void {
		$this->confirm_or_fail( 'This releases every currently blocked client, including any blocked permanently.', $assoc_args );

		$cleared = Plugin::instance()->blocked()->clear();

		if ( -1 === $cleared ) {
			WP_CLI::error( 'The block list could not be cleared.' );
		}

		WP_CLI::success( sprintf( 'Released %d client(s).', $cleared ) );
	}

	/**
	 * List the available presets.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - yaml
	 *   - csv
	 * ---
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function sources( array $args, array $assoc_args ): void {
		$plugin  = Plugin::instance();
		$enabled = (array) $plugin->settings()->get( 'presets', array() );

		$rows = array();

		foreach ( $plugin->presets()->applicable() as $name => $preset ) {
			$rows[] = array(
				'name'    => (string) $name,
				'label'   => (string) ( $preset['label'] ?? $name ),
				'enabled' => in_array( $name, $enabled, true ) ? 'yes' : 'no',
				'source'  => ! empty( $preset['shipped'] ) ? 'library' : 'contributed',
			);
		}

		if ( array() === $rows ) {
			WP_CLI::log( 'No presets are available.' );

			return;
		}

		Utils\format_items(
			(string) ( $assoc_args['format'] ?? 'table' ),
			$rows,
			array( 'name', 'label', 'enabled', 'source' )
		);
	}

	/**
	 * Export the configuration as a portable document.
	 *
	 * Credentials are stripped and the document says which were removed. An
	 * %env() or %file() token is a reference rather than a secret and survives.
	 *
	 * ## OPTIONS
	 *
	 * [--file=<path>]
	 * : Write to a file instead of standard output.
	 *
	 * [--rule=<id>]
	 * : Export one rule rather than the whole configuration.
	 *
	 * ## EXAMPLES
	 *
	 *     wp basic-firewall export --file=firewall.yml
	 *     wp basic-firewall export --rule=block_scanners
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function export( array $args, array $assoc_args ): void {
		$exporter = new Exporter();

		if ( isset( $assoc_args['rule'] ) ) {
			$yaml = $exporter->rule_to_yaml( (string) $assoc_args['rule'] );

			if ( null === $yaml ) {
				WP_CLI::error( sprintf( 'There is no rule with the identifier "%s".', (string) $assoc_args['rule'] ) );
			}
		} else {
			$yaml = $exporter->to_yaml();
		}

		if ( ! isset( $assoc_args['file'] ) ) {
			WP_CLI::line( (string) $yaml );

			return;
		}

		$path = (string) $assoc_args['file'];

		if ( false === file_put_contents( $path, (string) $yaml ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			WP_CLI::error( sprintf( 'Could not write to %s.', $path ) );
		}

		WP_CLI::success( sprintf( 'Written to %s.', $path ) );
	}

	/**
	 * Import a configuration document.
	 *
	 * ## OPTIONS
	 *
	 * <file>
	 * : The document to read.
	 *
	 * [--mode=<mode>]
	 * : Whether to merge into the current configuration or replace the rule set.
	 * ---
	 * default: merge
	 * options:
	 *   - merge
	 *   - replace
	 * ---
	 *
	 * [--dry-run]
	 * : Print what would change and apply nothing.
	 *
	 * [--yes]
	 * : Do not prompt for confirmation.
	 *
	 * ## EXAMPLES
	 *
	 *     wp basic-firewall import firewall.yml --dry-run
	 *     wp basic-firewall import firewall.yml --mode=replace --yes
	 *
	 * @param array<int, string>    $args       Positional arguments.
	 * @param array<string, string> $assoc_args Flags.
	 */
	public function import( array $args, array $assoc_args ): void {
		$path = (string) ( $args[0] ?? '' );

		if ( ! is_readable( $path ) ) {
			WP_CLI::error( sprintf( 'Cannot read %s.', $path ) );
		}

		$yaml = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file, not a remote URL; WP_Filesystem is not loaded this early.
		$mode = (string) ( $assoc_args['mode'] ?? 'merge' );

		$importer = new Importer();
		$preview  = $importer->preview( $yaml, $mode );

		if ( ! $preview['ok'] ) {
			WP_CLI::error( (string) $preview['error'] );
		}

		$this->print_summary( $preview['summary'] );

		if ( Utils\get_flag_value( $assoc_args, 'dry-run', false ) ) {
			WP_CLI::success( 'Dry run: nothing was changed.' );

			return;
		}

		// A destructive import must not run unless it was explicitly agreed to,
		// and must not report success when it was not. See confirm_or_fail().
		$this->confirm_or_fail(
			'replace' === $mode
				? 'This replaces the current rule set.'
				: 'This merges the document into the current configuration.',
			$assoc_args
		);

		$result = $importer->import( $yaml, $mode );

		if ( ! $result['ok'] ) {
			WP_CLI::error( (string) $result['error'] );
		}

		foreach ( $result['problems'] as $problem ) {
			WP_CLI::warning( sprintf( '%s: %s', $problem['path'], $problem['message'] ) );
		}

		$rebuild = Plugin::instance()->compiled()->rebuild();

		if ( ! $rebuild['written'] ) {
			WP_CLI::error( 'The configuration was imported but could not be compiled, so the firewall is still running the previous rule set.' );
		}

		WP_CLI::success( 'Imported and recompiled.' );
	}

	/**
	 * Print an import summary.
	 *
	 * @param array<string, mixed> $summary Summary from the importer.
	 */
	private function print_summary( array $summary ): void {
		WP_CLI::log( sprintf( 'Mode: %s', (string) ( $summary['mode'] ?? 'merge' ) ) );

		foreach ( array(
			'rules_new'         => 'New rules',
			'rules_overwritten' => 'Rules overwritten',
			'rules_removed'     => 'Rules removed',
			'sections_changed'  => 'Sections changed',
		) as $key => $label ) {
			$values = (array) ( $summary[ $key ] ?? array() );

			WP_CLI::log(
				sprintf(
					'%s: %s',
					$label,
					array() === $values ? 'none' : implode( ', ', array_map( 'strval', $values ) )
				)
			);
		}
	}
}
