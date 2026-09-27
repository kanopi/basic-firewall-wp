<?php
/**
 * Where the firewall caches what it works out.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Cache;

use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\Plugin;

/**
 * One answer to "where does this cache go", for everything that builds a firewall.
 *
 * Three backends, reaching the library two different ways:
 *
 * - **Files and APCu are written into the compiled file**, as a pool class and
 *   scalar arguments the library builds for itself. That is what lets them
 *   reach the wp-config.php path, where nothing but the compiled file exists.
 * - **The object cache is handed over live**, as an object, at the paths the
 *   compiler recorded. YAML cannot carry an object, and on the wp-config.php
 *   path there is no object cache to hand over -- so a site using that path
 *   keeps files there, and only there.
 *
 * It lives in one place because three things build a firewall -- the runner
 * serving a request, the firewall built to answer Site Health, and the request
 * tester -- and a cache aimed in one and forgotten in another writes a second
 * copy of the corpus to disk on a site that moved its caches off disk to avoid
 * exactly that. The Drupal module found that out by having it happen.
 */
final class Cache_Backend {

	/**
	 * Namespace the agent detection corpus is kept under.
	 *
	 * Separate from the verdicts below so that clearing one can never quietly
	 * discard the other -- and discarded reverse-DNS verdicts widen nothing,
	 * but they do put every crawler back on a cold, fail-closed cache at once.
	 */
	public const AGENTS = 'basic_firewall_agents';

	/**
	 * Namespace reverse-DNS verdicts are kept under.
	 */
	public const VERDICTS = 'basic_firewall_rdns';

	/**
	 * The backend the settings name.
	 */
	public static function configured(): string {
		return (string) Plugin::instance()->settings()->get( 'cache.backend', 'filesystem' );
	}

	/**
	 * Whether the site has an object cache that outlives the request.
	 *
	 * Without a drop-in, WordPress's object cache is an array that forgets
	 * everything when the request ends. Handing that to the library would mean
	 * parsing the agent corpus afresh on every request -- roughly 600 ms, which
	 * is far worse than the slow filesystem this option exists to avoid.
	 */
	public static function has_persistent_object_cache(): bool {
		return (bool) wp_using_ext_object_cache();
	}

	/**
	 * Whether APCu is usable in this PHP.
	 *
	 * Only this SAPI's. APCu is commonly disabled under the command line
	 * (`apc.enable_cli`), so WP-CLI answering no says nothing about the web
	 * server -- which is why the compiler writes an APCu pool regardless, and
	 * this is asked where the answer is about the web server: the Storage
	 * screen and Site Health.
	 */
	public static function has_apcu(): bool {
		return function_exists( 'apcu_enabled' ) && apcu_enabled();
	}

	/**
	 * The directory the files backend was told to use, resolved, or null.
	 *
	 * A relative path resolves inside the private directory, like every other
	 * stored path.
	 */
	public static function directory(): ?string {
		$directory = trim( (string) Plugin::instance()->settings()->get( 'cache.directory', '' ) );

		return '' === $directory ? null : rtrim( Plugin::instance()->paths()->resolve( $directory ), '/' );
	}

	/**
	 * The pool to write into the compiled file, or null to write none.
	 *
	 * Null for the files backend with no directory named, which is what every
	 * release before this did: the library's own filesystem pool under
	 * KANOPI_FIREWALL_CACHE_DIR. Null for the object cache too, because that
	 * one is not written down at all.
	 *
	 * @param string $name_space Which cache this pool is for.
	 *
	 * @return array{adaptor: class-string, args: list<mixed>}|null
	 */
	public static function compiled_pool( string $name_space ): ?array {
		$backend = self::configured();

		if ( 'apcu' === $backend ) {
			return array(
				'adaptor' => Library_Map::CACHE_POOLS['apcu'],
				'args'    => array( $name_space, (int) Plugin::instance()->settings()->get( 'cache.apcu_ttl', 86400 ) ),
			);
		}

		$directory = self::directory();

		if ( 'filesystem' !== $backend || null === $directory ) {
			return null;
		}

		return array(
			'adaptor' => Library_Map::CACHE_POOLS['filesystem'],

			// No default lifetime: the agent corpus is keyed by the detector's
			// own version, and a verdict carries the expiry the rule gave it.
			'args'    => array( $name_space, 0, $directory ),
		);
	}

	/**
	 * Overrides that hand the object cache to the library, or none.
	 *
	 * Empty for every backend but the object cache, whose pools the compiled
	 * file already names, and empty for the object cache too when it is not
	 * persistent -- the library then uses its filesystem default, which is a
	 * slower cache rather than none. Site Health says so.
	 *
	 * @return array<string, Object_Cache_Adapter>
	 */
	public static function overrides(): array {
		if ( 'object_cache' !== self::configured() || ! self::has_persistent_object_cache() ) {
			return array();
		}

		$compiled  = Plugin::instance()->compiled();
		$overrides = array();

		if ( array() !== $compiled->cache_pool_paths() ) {
			$agents = self::agent_pool();

			foreach ( $compiled->cache_pool_paths() as $path ) {
				$overrides[ $path ] = $agents;
			}
		}

		if ( array() !== $compiled->verify_cache_paths() ) {
			$verdicts = new Object_Cache_Adapter( self::VERDICTS );

			foreach ( $compiled->verify_cache_paths() as $path ) {
				$overrides[ $path ] = $verdicts;
			}
		}

		return $overrides;
	}

	/**
	 * The object cache pool for the agent corpus, or null to leave the rule alone.
	 *
	 * Null is the ordinary answer and does not mean "no cache": every other
	 * backend is already named in the compiled file, which the library builds
	 * for itself. Only the object cache has to be handed over live.
	 */
	public static function agent_pool(): ?Object_Cache_Adapter {
		if ( 'object_cache' !== self::configured() || ! self::has_persistent_object_cache() ) {
			return null;
		}

		return new Object_Cache_Adapter( self::AGENTS );
	}

	/**
	 * What the configured backend actually resolves to here, for people.
	 */
	public static function describe(): string {
		switch ( self::configured() ) {
			case 'object_cache':
				return self::has_persistent_object_cache()
					? __( 'the WordPress object cache', 'basic-firewall' )
					: __( 'files, because this site has no persistent object cache', 'basic-firewall' );

			case 'apcu':
				return __( 'APCu', 'basic-firewall' );

			default:
				$directory = self::directory() ?? Plugin::instance()->paths()->library_cache_dir();

				/* translators: %s: directory path. */
				return sprintf( __( 'files, in %s', 'basic-firewall' ), $directory );
		}
	}
}
