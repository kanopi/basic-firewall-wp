<?php
/**
 * Refreshes referenced rule lists, out of band.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Sources;

use Kanopi\BasicFirewall\Library_Loader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceLoader;
use Kanopi\Firewall\Source\SourceManager;
use Symfony\Component\Yaml\Yaml;

/**
 * Fetches the lists a rule references, on a schedule and never during a request.
 *
 * The library can fetch a source the moment a rule needs it. This plugin does
 * not let it, and the reason is the one that governs everything on the request
 * path: a firewall that makes an outbound HTTP call while a visitor waits is a
 * firewall that fails when the network does -- and it fails by adding the
 * provider's latency to every page, then timing out into whatever the error
 * policy says.
 *
 * So `KANOPI_FIREWALL_SOURCES_OFFLINE` is on for evaluation, which makes the
 * request path read the cache and nothing else, and this class is what puts
 * something in the cache. That is the split the library documents for
 * `bin/firewall-sources`; this is the same job, driven by WP-Cron and WP-CLI so
 * a WordPress site does not need a system crontab entry to stay current.
 *
 * A refresh that fails is not an emergency. The error policy on each source
 * decides what happens to traffic, and the default keeps the last copy that
 * worked -- so a provider having an outage does not become this site having one.
 */
final class Refresher {

	/**
	 * The scheduled event.
	 */
	public const HOOK = 'basic_firewall_refresh_sources';

	/**
	 * Option holding the result of the last run.
	 */
	public const RESULT_OPTION = 'basic_firewall_sources_last_run';

	/**
	 * Register the schedule and its handler.
	 */
	public static function register(): void {
		add_filter( 'cron_schedules', array( self::class, 'add_schedule' ) ); // phpcs:ignore WordPress.WP.CronInterval.ChangeDetected -- administrator-configured, and a day by default.
		add_action( self::HOOK, array( self::class, 'run_scheduled' ) );
		add_action( 'basic_firewall_settings_saved', array( self::class, 'reschedule' ) );
	}

	/**
	 * Add the configurable interval WordPress has no name for.
	 *
	 * @param array<string, mixed> $schedules Registered schedules.
	 *
	 * @return array<string, mixed>
	 */
	public static function add_schedule( array $schedules ): array {
		$interval = self::interval();

		if ( $interval > 0 ) {
			$schedules['basic_firewall_sources'] = array(
				'interval' => $interval,
				'display'  => __( 'Basic Firewall list refresh', 'basic-firewall' ),
			);
		}

		return $schedules;
	}

	/**
	 * How often to check, in seconds. Zero disables the schedule entirely.
	 */
	public static function interval(): int {
		return max( 0, (int) Plugin::instance()->settings()->get( 'sources.cron_interval', DAY_IN_SECONDS ) );
	}

	/**
	 * Put the schedule in place, or take it away.
	 */
	public static function reschedule(): void {
		self::unschedule();

		if ( 0 === self::interval() ) {
			return;
		}

		/*
		 * Offset rather than scheduled for now. Every site running this plugin
		 * would otherwise ask the same published lists for the same file at the
		 * same moment after a release, which is a thundering herd pointed at
		 * somebody else's CDN.
		 */
		wp_schedule_event( time() + wp_rand( 60, 600 ), 'basic_firewall_sources', self::HOOK );
	}

	/**
	 * Remove the schedule. Called on deactivation.
	 */
	public static function unschedule(): void {
		$next = wp_next_scheduled( self::HOOK );

		while ( false !== $next ) {
			wp_unschedule_event( $next, self::HOOK );

			$next = wp_next_scheduled( self::HOOK );
		}
	}

	/**
	 * The scheduled run: refresh only what the cache considers stale.
	 */
	public static function run_scheduled(): void {
		self::refresh( false );
	}

	/**
	 * Refresh every list the compiled configuration references.
	 *
	 * @param bool $force Revalidate even a copy the cache still considers fresh.
	 *
	 * @return array{ran: bool, refreshed: array<string, int>, failed: array<string, string>, message: string}
	 */
	public static function refresh( bool $force = false ): array {
		if ( ! Library_Loader::is_usable() ) {
			return array(
				'ran'       => false,
				'refreshed' => array(),
				'failed'    => array(),
				'message'   => __( 'The firewall library is not available, so no list could be refreshed.', 'basic-firewall' ),
			);
		}

		$declarations = self::declarations();

		if ( array() === $declarations ) {
			$result = array(
				'ran'       => true,
				'refreshed' => array(),
				'failed'    => array(),
				'message'   => __( 'No rule references a list, so there was nothing to refresh.', 'basic-firewall' ),
			);

			self::record( $result );

			return $result;
		}

		self::define_cache_dir();

		/*
		 * The cache directory is left to the library to derive from
		 * KANOPI_FIREWALL_CACHE_DIR rather than passed in.
		 *
		 * This has to agree with the request path exactly or the whole
		 * arrangement is pointless: the runtime builds its own SourceCache with
		 * no directory, so naming one here would fill a cache nothing reads,
		 * and every request would find an empty one and apply the error policy
		 * to a list that had just been fetched successfully.
		 *
		 * `false` for offline is passed explicitly, because the constant that
		 * keeps the request path off the network is defined by the time this
		 * runs and would otherwise make this method a no-op reporting success.
		 */
		$loader  = new SourceLoader( new SourceCache(), null, null, null, null, null, false );
		$manager = new SourceManager( $loader );

		$refreshed = array();
		$failed    = array();

		foreach ( $declarations as $declaration ) {
			$name = (string) ( $declaration['name'] ?? 'unnamed' );

			try {
				$entries            = $manager->load( array( $declaration ), $force );
				$refreshed[ $name ] = count( $entries );
			} catch ( \Throwable $e ) {
				$failed[ $name ] = $e->getMessage();
			}
		}

		$result = array(
			'ran'       => true,
			'refreshed' => $refreshed,
			'failed'    => $failed,
			'message'   => array() === $failed
				? sprintf(
					/* translators: %d: number of lists. */
					_n( '%d list refreshed.', '%d lists refreshed.', count( $refreshed ), 'basic-firewall' ),
					count( $refreshed )
				)
				: sprintf(
					/* translators: 1: number refreshed, 2: number that failed. */
					__( '%1$d list(s) refreshed, %2$d could not be fetched.', 'basic-firewall' ),
					count( $refreshed ),
					count( $failed )
				),
		);

		self::record( $result );

		return $result;
	}

	/**
	 * Point the library's caches at the private directory.
	 *
	 * The runner does this before evaluating; a cron or CLI run may reach here
	 * without having evaluated anything, and a refresh that wrote to the system
	 * temporary directory would be discarded by the next clear-out.
	 */
	private static function define_cache_dir(): void {
		if ( ! defined( 'KANOPI_FIREWALL_CACHE_DIR' ) ) {
			define( 'KANOPI_FIREWALL_CACHE_DIR', Plugin::instance()->paths()->base() . '/cache' );
		}
	}

	/**
	 * Every `metadata.sources` declaration in the compiled configuration.
	 *
	 * Read from the compiled file rather than from the settings option, because
	 * the compiled file is what the runtime reads: a list referenced by a rule
	 * that failed to compile is not one the firewall will ever consult, and
	 * fetching it would report a health this site does not have.
	 *
	 * @return list<array<string, mixed>>
	 */
	public static function declarations(): array {
		$path = Plugin::instance()->paths()->compiled_file();

		if ( ! is_readable( $path ) ) {
			return array();
		}

		try {
			$config = Yaml::parseFile( $path );
		} catch ( \Throwable $e ) {
			return array();
		}

		if ( ! is_array( $config ) || ! is_array( $config['plugins'] ?? null ) ) {
			return array();
		}

		$declarations = array();
		$seen         = array();

		foreach ( $config['plugins'] as $plugin ) {
			if ( ! is_array( $plugin ) || ! is_array( $plugin['metadata']['sources'] ?? null ) ) {
				continue;
			}

			foreach ( $plugin['metadata']['sources'] as $source ) {
				if ( ! is_array( $source ) ) {
					continue;
				}

				/*
				 * Deduplicated on the whole declaration, as the library's own
				 * sync command does: the same upstream is often referenced by
				 * two rules -- one to allow, one to challenge -- and should be
				 * fetched once per run rather than once per rule.
				 */
				$fingerprint = md5( (string) wp_json_encode( $source ) );

				if ( isset( $seen[ $fingerprint ] ) ) {
					continue;
				}

				$seen[ $fingerprint ] = true;
				$declarations[]       = $source;
			}
		}

		return $declarations;
	}

	/**
	 * What the last run did, for the screens and the CLI.
	 *
	 * @return array<string, mixed>
	 */
	public static function last_run(): array {
		$result = get_option( self::RESULT_OPTION, array() );

		return is_array( $result ) ? $result : array();
	}

	/**
	 * Record a run.
	 *
	 * @param array<string, mixed> $result What happened.
	 */
	private static function record( array $result ): void {
		$result['at'] = time();

		update_option( self::RESULT_OPTION, $result, false );
	}
}
