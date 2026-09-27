<?php
/**
 * Discards whatever the firewall has cached, wherever it put it.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Cache;

use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\Plugin;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Empties every cache backend, not only the one currently chosen.
 *
 * Switching backends leaves the previous one warm, and a stale corpus left on
 * a network filesystem is the thing the setting exists to avoid. The clears are
 * cheap and do nothing where a backend was never used.
 *
 * WordPress has no "clear all caches" moment to hook -- `wp cache flush` fires
 * nothing, and an object cache flush does not reach files or APCu -- so this is
 * reached from the Storage screen and from `wp basic-firewall clear-cache`.
 *
 * Two things in the cache directory are deliberately left alone: the parsed
 * configuration and the downloaded bodies of imported rule lists. Neither is
 * free to lose. The first is what the firewall reads to know its rules; without
 * the second every rule built on a list matches nothing until cron fetches it
 * again, and a clear that re-downloaded every list is how a site gets rate
 * limited by the list it depends on. Each has its own way back -- a rebuild,
 * and the next refresh. So files are cleared by pool namespace, never by
 * sweeping the directory.
 */
final class Cache_Clearer {

	/**
	 * Namespaces the library's own filesystem pools use when none is named.
	 *
	 * Which is what the files backend with no directory amounts to: the
	 * compiled file names no pool, and the library builds these under
	 * KANOPI_FIREWALL_CACHE_DIR.
	 */
	private const LIBRARY_NAMESPACES = array( 'device-detector', 'kanopi_firewall_rdns' );

	/**
	 * Clear every cache the firewall may have written.
	 *
	 * APCu is the exception worth knowing about: its memory belongs to the
	 * process pool that filled it, so a clear from WP-CLI empties the command
	 * line's own APCu -- usually disabled, always a different one -- and leaves
	 * the web server's untouched. The Storage screen's button runs in a web
	 * request, which is the only place that clear can reach.
	 *
	 * @return list<string> The backends cleared: `object_cache`, `apcu`, `filesystem`.
	 */
	public function clear(): array {
		$cleared = array();

		if ( $this->clear_pools( fn ( string $name_space ): CacheItemPoolInterface => new Object_Cache_Adapter( $name_space ), array( Cache_Backend::AGENTS, Cache_Backend::VERDICTS ) ) ) {
			$cleared[] = 'object_cache';
		}

		if ( Cache_Backend::has_apcu() ) {
			$class = Library_Map::CACHE_POOLS['apcu'];
			$ttl   = (int) Plugin::instance()->settings()->get( 'cache.apcu_ttl', 86400 );

			if ( $this->clear_pools( fn ( string $name_space ): CacheItemPoolInterface => new $class( $name_space, $ttl ), array( Cache_Backend::AGENTS, Cache_Backend::VERDICTS ) ) ) {
				$cleared[] = 'apcu';
			}
		}

		if ( $this->clear_files() ) {
			$cleared[] = 'filesystem';
		}

		return $cleared;
	}

	/**
	 * The filesystem pools: the library's defaults, and a named directory's.
	 */
	private function clear_files(): bool {
		$class   = Library_Map::CACHE_POOLS['filesystem'];
		$library = Plugin::instance()->paths()->library_cache_dir();

		$cleared = is_dir( $library ) && $this->clear_pools(
			fn ( string $name_space ): CacheItemPoolInterface => new $class( $name_space, 0, $library ),
			self::LIBRARY_NAMESPACES
		);

		$directory = Cache_Backend::directory();

		if ( null !== $directory && is_dir( $directory ) ) {
			$cleared = $this->clear_pools(
				fn ( string $name_space ): CacheItemPoolInterface => new $class( $name_space, 0, $directory ),
				array( Cache_Backend::AGENTS, Cache_Backend::VERDICTS )
			) || $cleared;
		}

		return $cleared;
	}

	/**
	 * Clear one pool per namespace.
	 *
	 * Never throws. A cache that cannot be cleared is a cache that stays warm,
	 * which is the state it was in before somebody pressed the button.
	 *
	 * @param callable(string): CacheItemPoolInterface $build       Builds a pool for a namespace.
	 * @param list<string>                             $name_spaces Namespaces to clear.
	 *
	 * @return bool Whether any pool reported a clear.
	 */
	private function clear_pools( callable $build, array $name_spaces ): bool {
		$cleared = false;

		foreach ( $name_spaces as $name_space ) {
			try {
				$cleared = $build( $name_space )->clear() || $cleared;
			} catch ( \Throwable $e ) {
				continue;
			}
		}

		return $cleared;
	}
}
