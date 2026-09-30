<?php
/**
 * What the last web request looked like to both evaluation paths.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

use Kanopi\BasicFirewall\Cache\Cache_Backend;
use Kanopi\BasicFirewall\Library_Loader;
use Kanopi\BasicFirewall\Plugin;

/**
 * Keeps the last web request's early-path report where WP-CLI can read it.
 *
 * **Why.** The wp-config.php bootstrap reports on itself in a global, and
 * every status screen reads that global -- from *its own* request. An admin
 * screen is one request; `wp basic-firewall status` is another process, and
 * on a host that runs WP-CLI in its own container, another machine. None of
 * them can see what the bootstrap did on a visitor's request to a web
 * container, which is the only request that matters when a rule is not
 * firing there (#34). So the runner, which runs on every request that
 * reaches WordPress, saves a compact report for the others to read.
 *
 * **Two slots.** The last request, and the last *anomalous* one -- a
 * fail-open, an early path that did not evaluate for a reason that is not
 * the configuration working as meant, or a verdict the early path handed on
 * instead of answering -- kept apart so a stream of ordinary requests does
 * not overwrite the one somebody needs to see.
 *
 * **Cheap.** Transients, because the reader may be in another container and
 * the object cache or the database is what they share. Written at most once
 * every few seconds per slot, which is decided by the modification time of a
 * marker file in the private directory -- one stat per request, where
 * reading a transient back to compare would be a query on every request of a
 * site with no object cache. Never from WP-CLI or cron, which are not web
 * requests.
 *
 * **Nothing sensitive.** The URL path without its query string, the request
 * method, and facts about the firewall. No cookies, no headers, no client
 * address, no credentials; exception messages are masked the way the
 * bootstrap masks them.
 */
final class Diagnostics {

	/**
	 * Transient holding the last web request's report.
	 */
	public const LAST = 'basic_firewall_last_request';

	/**
	 * Transient holding the last anomalous web request's report.
	 */
	public const ANOMALY = 'basic_firewall_last_anomaly';

	/**
	 * How long either report is kept, in seconds.
	 */
	public const TTL = DAY_IN_SECONDS;

	/**
	 * The shortest gap between two writes of one slot, in seconds.
	 */
	public const THROTTLE = 5;

	/**
	 * How recent an anomaly has to be for Site Health to raise it, in seconds.
	 */
	public const RECENT = 6 * HOUR_IN_SECONDS;

	/**
	 * The response header BASIC_FIREWALL_DEBUG adds.
	 */
	public const HEADER = 'X-Basic-Firewall-Early';

	/**
	 * Reasons the early path does not evaluate that are the configuration
	 * working as meant. basic_firewall_benign_reasons() in bootstrap.php must
	 * agree.
	 */
	public const BENIGN_REASONS = array( 'disabled', 'switched-off', 'deferred-login' );

	/**
	 * Whether the shutdown save is registered for this request.
	 *
	 * @var bool
	 */
	private static bool $watching = false;

	/**
	 * Save this request's report when it ends, if it is a web request.
	 *
	 * At shutdown rather than now, because the runner is not finished with
	 * the request when it returns: a request deferred at `muplugins_loaded`
	 * is evaluated at `plugins_loaded`. A shutdown function also runs after
	 * a refusal's exit(), so a request the runner refused is reported too.
	 */
	public static function watch(): void {
		if ( self::$watching || ! self::is_web_request() ) {
			return;
		}

		self::$watching = true;

		register_shutdown_function( array( self::class, 'persist' ) );
	}

	/**
	 * Whether this is a request from a visitor, as opposed to WP-CLI or cron.
	 */
	public static function is_web_request(): bool {
		if ( 'cli' === PHP_SAPI || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return false;
		}

		return ! ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() );
	}

	/**
	 * Save this request's report: always the last one, and the anomaly slot too.
	 *
	 * Never throws: a diagnostic must not be the reason a request fails.
	 */
	public static function persist(): void {
		try {
			$report = self::build();

			if ( null !== $report['anomaly'] && self::may_write( 'anomaly' ) ) {
				set_transient( self::ANOMALY, $report, self::TTL );
			}

			if ( self::may_write( 'last' ) ) {
				set_transient( self::LAST, $report, self::TTL );
			}
		} catch ( \Throwable $e ) {
			return;
		}
	}

	/**
	 * Whether a slot may be written now, claiming it if so.
	 *
	 * @param string $slot `last` or `anomaly`.
	 */
	private static function may_write( string $slot ): bool {
		$marker = self::marker( $slot );

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- no marker yet is the ordinary answer.
		$written = @filemtime( $marker );

		if ( false !== $written && time() - $written < self::THROTTLE ) {
			return false;
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_touch -- best effort: an unwritable marker only means no throttle.
		@touch( $marker );

		return true;
	}

	/**
	 * The marker file whose modification time throttles a slot.
	 *
	 * @param string $slot `last` or `anomaly`.
	 */
	private static function marker( string $slot ): string {
		return Plugin::instance()->paths()->base() . '/.report-' . $slot;
	}

	/**
	 * Forget the throttle, so the next save writes. Test seam.
	 *
	 * @internal
	 */
	public static function reset_throttle(): void {
		foreach ( array( 'last', 'anomaly' ) as $slot ) {
			clearstatcache( true, self::marker( $slot ) );
			wp_delete_file( self::marker( $slot ) );
		}

		self::$watching = false;
	}

	/**
	 * The last web request's report, or null when there is none.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function last(): ?array {
		$report = get_transient( self::LAST );

		return is_array( $report ) ? $report : null;
	}

	/**
	 * The last anomalous web request's report, or null when there is none.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function last_anomaly(): ?array {
		$report = get_transient( self::ANOMALY );

		return is_array( $report ) ? $report : null;
	}

	/**
	 * The last anomaly, when it happened within RECENT seconds.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function recent_anomaly(): ?array {
		$report = self::last_anomaly();

		return null !== $report && time() - (int) ( $report['time'] ?? 0 ) <= self::RECENT ? $report : null;
	}

	/**
	 * This request's report.
	 *
	 * @return array{time: int, method: string, path: string, anomaly: string|null, early: array<string, mixed>, runner: array<string, mixed>, library: array<string, mixed>, compiled: array<string, mixed>, cache: array<string, mixed>, mode: array<string, mixed>}
	 */
	public static function build(): array {
		$early  = self::early();
		$runner = self::runner();
		$file   = Plugin::instance()->paths()->compiled_file();

		$report = array(
			'time'     => time(),
			'method'   => self::method(),
			'path'     => self::path(),
			'anomaly'  => null,
			'early'    => $early,
			'runner'   => $runner,
			'mode'     => array(
				'configured' => self::configured_mode(),
				'early'      => $early['mode'],
				'runner'     => $runner['mode'],
			),
			'library'  => array(
				'copy'    => Library_Loader::is_scoped_build() ? 'scoped' : 'unscoped',
				'loader'  => Library_Loader::mode(),
				'version' => Library_Loader::version(),
				'early'   => $early['library'],
			),
			'compiled' => array(
				'path'  => $file,
				'mtime' => is_readable( $file ) ? (int) filemtime( $file ) : null,
				'hash'  => is_readable( $file ) ? substr( (string) hash_file( 'sha256', $file ), 0, 12 ) : null,
				'early' => $early['compiled'],
			),
			'cache'    => array(
				'early'  => null === $early['cache_dir'] ? null : 'files in ' . $early['cache_dir'],
				'runner' => self::runner_cache(),
			),
		);

		$report['anomaly'] = self::anomaly( $report );

		return $report;
	}

	/**
	 * What made a report worth keeping apart, or null for an ordinary one.
	 *
	 * `fail-open` -- either path failed and let the request through.
	 * `early-verdict-deferred` -- the early path reached a refusal and handed
	 * it on instead of answering it (a solved challenge is handed on by
	 * design, and is not one). `not-evaluated` -- the snippet ran and did not
	 * evaluate, for a reason that is not the configuration working as meant.
	 *
	 * @param array<string, mixed> $report A report from build().
	 */
	public static function anomaly( array $report ): ?string {
		$early  = (array) ( $report['early'] ?? array() );
		$runner = (array) ( $report['runner'] ?? array() );

		if ( null !== ( $early['failure'] ?? null ) || in_array( $runner['failure'] ?? null, array( 'evaluation-failed', 'could-not-start' ), true ) ) {
			return 'fail-open';
		}

		if ( in_array( $runner['early_verdict'] ?? null, array( 'challenge', 'redirect', 'blocked' ), true ) || ! empty( $early['refused'] ) ) {
			return 'early-verdict-deferred';
		}

		if ( ! empty( $early['called'] ) && empty( $early['evaluated'] ) && ! in_array( $early['reason'] ?? null, self::BENIGN_REASONS, true ) ) {
			return 'not-evaluated';
		}

		return null;
	}

	/**
	 * The bootstrap's report on this request, normalised.
	 *
	 * @return array{called: bool, evaluated: bool, reason: string|null, credentials: bool, responder: bool, autoloader: array{source: string|null, file: string|null, named: string|null}, library: string|null, mode: string|null, compiled: array{path: string, mtime: int}|null, cache_dir: string|null, outcome: string|null, deferred: bool, failure: string|null, failure_origin: string|null, refused: string|null}
	 */
	public static function early(): array {
		$early = isset( $GLOBALS['basic_firewall_early'] ) && is_array( $GLOBALS['basic_firewall_early'] ) ? $GLOBALS['basic_firewall_early'] : array();

		$string = static fn ( string $key ): ?string => isset( $early[ $key ] ) && is_scalar( $early[ $key ] ) && '' !== (string) $early[ $key ] ? (string) $early[ $key ] : null;

		$autoloader = is_array( $early['autoloader'] ?? null ) ? $early['autoloader'] : array();
		$compiled   = is_array( $early['compiled'] ?? null ) ? $early['compiled'] : null;
		$failure    = $string( 'failure' );

		return array(
			'called'         => ! empty( $early['called'] ),
			'evaluated'      => ! empty( $early['evaluated'] ),
			'reason'         => $string( 'reason' ),
			'credentials'    => ! empty( $early['credentials'] ),
			'responder'      => ! isset( $early['responder'] ) || ! empty( $early['responder'] ),
			'autoloader'     => array(
				'source' => isset( $autoloader['source'] ) ? (string) $autoloader['source'] : null,
				'file'   => isset( $autoloader['file'] ) ? (string) $autoloader['file'] : null,
				'named'  => isset( $autoloader['named'] ) ? (string) $autoloader['named'] : null,
			),
			'library'        => $string( 'library' ),
			'mode'           => $string( 'mode' ),
			'compiled'       => null === $compiled ? null : array(
				'path'  => (string) ( $compiled['path'] ?? '' ),
				'mtime' => (int) ( $compiled['mtime'] ?? 0 ),
			),
			'cache_dir'      => $string( 'cache_dir' ),
			'outcome'        => $string( 'outcome' ),
			'deferred'       => null !== Runner::early_outcome() || null !== Runner::state()['early_verdict'],
			'failure'        => null === $failure ? null : self::mask( $failure ),
			'failure_origin' => $string( 'failure_origin' ),
			'refused'        => $string( 'refused' ),
		);
	}

	/**
	 * The runner's own report on this request.
	 *
	 * @return array{evaluated: bool, outcome: string|null, mode: string|null, early_verdict: string|null, failure: string|null, failure_detail: string|null, exempt: bool}
	 */
	public static function runner(): array {
		$state = Runner::state();

		return array(
			'evaluated'      => $state['evaluated'],
			'outcome'        => $state['outcome'],
			'mode'           => $state['mode'],
			'early_verdict'  => $state['early_verdict'],
			'failure'        => $state['failure'],
			'failure_detail' => '' === $state['failure_detail'] ? null : self::mask( $state['failure_detail'] ),
			'exempt'         => $state['exempt'],
		);
	}

	/**
	 * Add the X-Basic-Firewall-Early header, when BASIC_FIREWALL_DEBUG asks.
	 *
	 * For troubleshooting only: anybody who can make a request learns how the
	 * firewall is deployed and whether it evaluated them. Off unless the
	 * constant is defined truthy. Carries the compact report and nothing
	 * sensitive: no paths beyond a file name, no message text.
	 */
	public static function send_header(): void {
		if ( ! self::debug_enabled() || headers_sent() ) {
			return;
		}

		$json = wp_json_encode( self::compact(), JSON_UNESCAPED_SLASHES );

		if ( is_string( $json ) ) {
			header( self::HEADER . ': ' . $json, true );
		}
	}

	/**
	 * Whether BASIC_FIREWALL_DEBUG is defined truthy.
	 */
	public static function debug_enabled(): bool {
		return defined( 'BASIC_FIREWALL_DEBUG' ) && (bool) constant( 'BASIC_FIREWALL_DEBUG' );
	}

	/**
	 * The report, compact, for the debug header.
	 *
	 * The `early` half is the shape basic_firewall_debug_report() writes on
	 * the wp-config.php path, so the header reads the same from either.
	 *
	 * @return array{early: array<string, mixed>, runner: array<string, mixed>}
	 */
	public static function compact(): array {
		$early  = self::early();
		$runner = self::runner();

		return array(
			'early'  => array(
				'called'     => $early['called'],
				'evaluated'  => $early['evaluated'],
				'reason'     => $early['reason'],
				'autoloader' => $early['autoloader']['source'],
				'library'    => $early['library'],
				'mode'       => $early['mode'],
				'outcome'    => $early['outcome'],
				'failure'    => self::short_failure( $early['failure'], $early['failure_origin'] ),
				'refused'    => null !== $early['refused'],
				'responder'  => $early['responder'],
			),
			'runner' => array(
				'evaluated'     => $runner['evaluated'],
				'outcome'       => $runner['outcome'],
				'mode'          => $runner['mode'],
				'early_verdict' => $runner['early_verdict'],
				'failure'       => $runner['failure'],
			),
		);
	}

	/**
	 * Write a fail-open to the PHP error log.
	 *
	 * The same shape as the bootstrap's line, so one search finds both:
	 * `Basic Firewall [warning]: fail-open (<where>)`.
	 *
	 * @param string     $where `early` or `runner`.
	 * @param \Throwable $e     What was thrown.
	 * @param string     $what  What failed, in a few words.
	 */
	public static function warn_fail_open( string $where, \Throwable $e, string $what ): void {
		$described = self::describe( $e );

		self::warn(
			sprintf(
				'fail-open (%s): %s -- %s "%s" at %s -- so the request was let through unfiltered.',
				$where,
				$what,
				$described['class'],
				$described['message'],
				$described['origin']
			)
		);
	}

	/**
	 * Write a warning to the PHP error log.
	 *
	 * Not the firewall's own logger: it is configured by the compiled file
	 * that may be what failed, and on the runner path it is not built until
	 * the firewall is.
	 *
	 * @param string $message What happened.
	 */
	public static function warn( string $message ): void {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- the one log a host always keeps, and the firewall's own may be what failed.
		error_log( 'Basic Firewall [warning]: ' . $message );
	}

	/**
	 * What a throwable was: class, masked message, and where it was thrown.
	 *
	 * Mirrors basic_firewall_describe_throwable() in bootstrap.php, which
	 * cannot depend on this class being loadable.
	 *
	 * @param \Throwable $e What was thrown.
	 *
	 * @return array{class: string, message: string, origin: string}
	 */
	public static function describe( \Throwable $e ): array {
		return array(
			'class'   => get_class( $e ),
			'message' => self::mask( $e->getMessage() ),
			'origin'  => $e->getFile() . ':' . $e->getLine(),
		);
	}

	/**
	 * Mask credentials in a URL, flatten whitespace, and cap the length.
	 *
	 * @param string $message A message that may name a DSN.
	 */
	public static function mask( string $message ): string {
		$message = (string) preg_replace( '#(://[^/\s:@]*):[^@\s/]*@#', '$1:***@', $message );
		$message = trim( (string) preg_replace( '/\s+/', ' ', $message ) );

		return strlen( $message ) > 300 ? substr( $message, 0, 300 ) . '...' : $message;
	}

	/**
	 * One line about a report, for `wp basic-firewall status`.
	 *
	 * @param array<string, mixed>|null $report A saved report, or null.
	 */
	public static function summary( ?array $report ): string {
		if ( null === $report ) {
			return 'none recorded';
		}

		$early  = (array) ( $report['early'] ?? array() );
		$runner = (array) ( $report['runner'] ?? array() );

		if ( empty( $early['called'] ) ) {
			$where = 'early path not called';
		} elseif ( ! empty( $early['evaluated'] ) ) {
			$where = 'early: evaluated' . ( isset( $early['outcome'] ) ? ', ' . $early['outcome'] : '' );
		} else {
			$where = 'early: NOT evaluated (' . (string) ( $early['reason'] ?? 'no reason' ) . ')';
		}

		$parts = array(
			sprintf( '%s ago', human_time_diff( (int) ( $report['time'] ?? 0 ) ) ),
			trim( (string) ( $report['method'] ?? '' ) . ' ' . (string) ( $report['path'] ?? '' ) ),
			$where,
			'runner: ' . ( ! empty( $runner['evaluated'] ) ? 'evaluated' . ( isset( $runner['outcome'] ) ? ', ' . $runner['outcome'] : '' ) : 'did not evaluate' ),
		);

		if ( null !== ( $early['failure'] ?? null ) ) {
			$parts[] = 'early failure: ' . (string) $early['failure'] . ( isset( $early['failure_origin'] ) ? ' at ' . (string) $early['failure_origin'] : '' );
		}

		if ( null !== ( $runner['failure'] ?? null ) ) {
			$parts[] = 'runner failure: ' . (string) $runner['failure'] . ( isset( $runner['failure_detail'] ) ? ' (' . (string) $runner['failure_detail'] . ')' : '' );
		}

		if ( null !== ( $report['anomaly'] ?? null ) ) {
			array_unshift( $parts, strtoupper( (string) $report['anomaly'] ) );
		}

		return implode( '; ', $parts );
	}

	/**
	 * A failure as the header carries it: the class, and file:line by name.
	 *
	 * @param string|null $failure `Class: message`.
	 * @param string|null $origin  `file:line`.
	 */
	private static function short_failure( ?string $failure, ?string $origin ): ?string {
		if ( null === $failure ) {
			return null;
		}

		$class = strstr( $failure, ':', true );

		return ( false === $class ? $failure : $class ) . ( null === $origin ? '' : ' @ ' . basename( $origin ) );
	}

	/**
	 * The mode the settings ask for, BASIC_FIREWALL_MODE first.
	 */
	private static function configured_mode(): string {
		if ( defined( 'BASIC_FIREWALL_MODE' ) && is_string( constant( 'BASIC_FIREWALL_MODE' ) ) ) {
			return (string) constant( 'BASIC_FIREWALL_MODE' );
		}

		return (string) Plugin::instance()->settings()->get( 'global.mode', 'log' );
	}

	/**
	 * The cache backend the runner hands the library, in a few words.
	 */
	private static function runner_cache(): string {
		$backend = Cache_Backend::configured();

		if ( 'object_cache' === $backend ) {
			return Cache_Backend::has_persistent_object_cache() ? 'object_cache (persistent, handed over live)' : 'object_cache (not persistent, so files)';
		}

		return $backend;
	}

	/**
	 * The request method, when it is one of the ordinary ones.
	 */
	private static function method(): string {
		$method = strtoupper( sanitize_key( wp_unslash( (string) ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) ) );

		return in_array( $method, array( 'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS' ), true ) ? $method : 'OTHER';
	}

	/**
	 * The URL path of the request, without its query string, capped.
	 *
	 * The query string is left out because it is where tokens and personal
	 * data travel; the path is enough to say which rule should have matched.
	 */
	private static function path(): string {
		$uri  = wp_unslash( (string) ( $_SERVER['REQUEST_URI'] ?? '' ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized below, once the query string is gone.
		$path = wp_parse_url( $uri, PHP_URL_PATH );
		$path = is_string( $path ) ? sanitize_text_field( $path ) : '';

		return strlen( $path ) > 200 ? substr( $path, 0, 200 ) . '...' : $path;
	}
}
