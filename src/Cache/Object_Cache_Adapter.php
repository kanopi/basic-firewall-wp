<?php
/**
 * A PSR-6 pool over the WordPress object cache.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Cache;

use Symfony\Component\Cache\Adapter\AbstractAdapter;

/**
 * Hands the library whatever persistent object cache the site already runs.
 *
 * The library caches parsed user agents and reverse-DNS verdicts, and left
 * alone each lands on the filesystem -- the wrong place where uploads is a
 * network mount, because the cost is not one slow read but many small ones
 * spread through the request. Rather than a second cache configuration to get
 * right, this borrows the one a site already has: Redis or Memcached through
 * an `object-cache.php` drop-in arrives here with nothing to configure.
 *
 * Built on Symfony's AbstractAdapter rather than written against PSR-6 from
 * scratch, because the adapter already does the parts that are easy to get
 * subtly wrong -- key validation, expiry arithmetic, deferred saves -- and the
 * library's own pools are built the same way. What is left to say is how to
 * reach `wp_cache_*()`.
 *
 * **Clearing is versioned**, not flushed. `wp_cache_flush()` would empty the
 * whole site's cache to discard the firewall's, and even a group flush -- where
 * a drop-in offers one -- would empty every namespace in the group, so clearing
 * the reverse-DNS verdicts would throw away the agent corpus with them. Every
 * key carries a namespace version instead, and clearing writes a new one: the
 * old entries become unreachable at once and are left to the backend's own
 * eviction.
 *
 * **Only meaningful with a persistent object cache.** WordPress's default is an
 * array that forgets everything when the request ends, which here would mean
 * rebuilding the agent corpus -- the better part of a second -- on every
 * request. Cache_Backend refuses to hand this over in that case.
 */
final class Object_Cache_Adapter extends AbstractAdapter {

	/**
	 * The object cache group every firewall entry lives in.
	 *
	 * A group of its own, so no other plugin's keys can collide with these and
	 * a drop-in that flushes by group can empty the firewall alone. Not a
	 * global group: on a network each site keeps its own, as it keeps its own
	 * block list.
	 */
	public const GROUP = 'basic_firewall';

	/**
	 * Build a pool.
	 *
	 * @param string $name_space      Keeps two consumers of the group apart.
	 * @param int    $default_lifetime Seconds an item lives when saved without an expiry.
	 */
	public function __construct( string $name_space = '', int $default_lifetime = 0 ) {
		parent::__construct( $name_space, $default_lifetime );

		$this->enableVersioning();
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<int, string> $ids Keys to read.
	 *
	 * @return iterable<string, mixed>
	 */
	protected function doFetch( array $ids ): iterable {
		$found = array();

		foreach ( $ids as $id ) {
			$hit   = false;
			$value = wp_cache_get( $id, self::GROUP, false, $hit );

			if ( $hit ) {
				$found[ $id ] = $value;
			}
		}

		return $found;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param string $id Key.
	 */
	protected function doHave( string $id ): bool {
		$hit = false;

		wp_cache_get( $id, self::GROUP, false, $hit );

		return $hit;
	}

	/**
	 * {@inheritDoc}
	 *
	 * The namespace version has already moved on by the time this runs, so
	 * there is nothing left that has to be deleted for the clear to be true.
	 *
	 * @param string $name_space The namespace being cleared.
	 */
	protected function doClear( string $name_space ): bool {
		return true;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<int, string> $ids Keys to delete.
	 */
	protected function doDelete( array $ids ): bool {
		foreach ( $ids as $id ) {
			wp_cache_delete( $id, self::GROUP );
		}

		return true;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $values   Keys to values.
	 * @param int                  $lifetime Seconds, 0 for no expiry.
	 *
	 * @return array<int, string>|bool The keys that failed, or true.
	 */
	protected function doSave( array $values, int $lifetime ): array|bool {
		$failed = array();

		foreach ( $values as $id => $value ) {
			if ( ! wp_cache_set( (string) $id, $value, self::GROUP, max( 0, $lifetime ) ) ) {
				$failed[] = (string) $id;
			}
		}

		return array() === $failed ? true : $failed;
	}
}
