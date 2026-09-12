<?php
/**
 * Reads WordPress's database credentials at request time.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall;

/**
 * Supplies the library with WordPress's own connection, freshly, every request.
 *
 * **These credentials are never written into the compiled file.** The compiled
 * storage section carries the two table names and nothing else; the connection
 * is handed to the library as a runtime override by the runner. That is a
 * security invariant with a test behind it, and it is not tidiness -- it buys
 * three things:
 *
 * 1. **An export cannot leak them**, because they were never in the document
 *    that gets exported.
 * 2. **A plaintext password never reaches disk.** The compiled file lives under
 *    uploads, which on nginx this plugin has measured to be web-readable.
 * 3. **A rotated password takes effect on the next request** rather than at the
 *    next rebuild. This is the one that turns a nicety into a requirement.
 *    Pantheon binds credentials from the environment and rotates them per
 *    environment and on container operations, and a baked snapshot goes stale
 *    between rebuilds. The failure is silent from the outside:
 *
 *        block()  -> false      the client is not recorded
 *        request  -> allowed    the firewall fails open
 *
 *    with nothing but a line in the firewall's own log to say why.
 *
 * The values are read from the `DB_*` constants rather than from `$wpdb`'s
 * properties, because `$wpdb->dbpassword` and friends are protected and a site
 * may have replaced `$wpdb` with a drop-in (HyperDB, LudicrousDB) that does not
 * keep them where core does. The constants are what `wp-config.php` defines and
 * what every drop-in still reads.
 */
final class Database_Credentials {

	/**
	 * Doctrine driver names, keyed by how the host is likely to be configured.
	 */
	private const DRIVER = 'pdo_mysql';

	/**
	 * Connection parameters for the library, or an empty array if unavailable.
	 *
	 * @return array<string, mixed>
	 */
	public function get_connection_parameters(): array {
		if ( ! defined( 'DB_NAME' ) || ! defined( 'DB_USER' ) || ! defined( 'DB_HOST' ) ) {
			return array();
		}

		$host = (string) constant( 'DB_HOST' );

		$parameters = array(
			'driver'   => self::DRIVER,
			'dbname'   => (string) constant( 'DB_NAME' ),
			'user'     => (string) constant( 'DB_USER' ),
			'password' => defined( 'DB_PASSWORD' ) ? (string) constant( 'DB_PASSWORD' ) : '',
		);

		$parameters += $this->parse_host( $host );

		if ( defined( 'DB_CHARSET' ) && '' !== (string) constant( 'DB_CHARSET' ) ) {
			$parameters['charset'] = (string) constant( 'DB_CHARSET' );
		}

		return $parameters;
	}

	/**
	 * Split WordPress's DB_HOST into what Doctrine expects.
	 *
	 * `DB_HOST` is not a hostname. WordPress accepts four shapes in that one
	 * constant and its own `wpdb::parse_db_host()` exists to pull them apart:
	 *
	 * | DB_HOST                  | Means                                  |
	 * |--------------------------|----------------------------------------|
	 * | `db.internal`            | host                                   |
	 * | `db.internal:3306`       | host and port                          |
	 * | `[::1]:3306`             | IPv6 literal and port                  |
	 * | `localhost:/tmp/sock`    | unix socket                            |
	 *
	 * Handing any of the last three to Doctrine as a hostname produces a
	 * connection failure whose message names a host nobody configured. The
	 * socket form matters most in practice -- it is what a local stack and
	 * several managed hosts use, and it is the one whose failure looks least
	 * like its cause.
	 *
	 * @param string $host The DB_HOST constant.
	 *
	 * @return array<string, mixed>
	 */
	private function parse_host( string $host ): array {
		$host = trim( $host );

		if ( '' === $host ) {
			return array( 'host' => 'localhost' );
		}

		// A unix socket: anything after a colon that looks like a path.
		if ( preg_match( '#^(.*?):(/.+)$#', $host, $matches ) === 1 ) {
			return array(
				'host'        => '' !== $matches[1] ? $matches[1] : 'localhost',
				'unix_socket' => $matches[2],
			);
		}

		// An IPv6 literal in brackets, optionally with a port.
		if ( preg_match( '#^\[(.+)\](?::(\d+))?$#', $host, $matches ) === 1 ) {
			$parsed = array( 'host' => $matches[1] );

			// The capture group is \d+, so its presence is the only question.
			if ( isset( $matches[2] ) ) {
				$parsed['port'] = (int) $matches[2];
			}

			return $parsed;
		}

		// host:port, but only when what follows the colon is entirely digits --
		// a bare IPv6 address contains colons and no port.
		if ( preg_match( '#^(.+):(\d+)$#', $host, $matches ) === 1 ) {
			return array(
				'host' => $matches[1],
				'port' => (int) $matches[2],
			);
		}

		return array( 'host' => $host );
	}

	/**
	 * Whether WordPress's credentials can be read at all.
	 */
	public function is_available(): bool {
		return array() !== $this->get_connection_parameters();
	}

	/**
	 * Apply this site's table prefix to a firewall table name.
	 *
	 * The library reaches the database through Doctrine DBAL rather than
	 * `$wpdb`, so nothing applies the prefix on the way through and this plugin
	 * has to. Without it, every site in a network writes to
	 * `basic_firewall_blocked`: blocking a client on one site blocks them
	 * everywhere, offense counts merge so escalation triggers sooner than
	 * configured, and one site's block list is readable from another.
	 *
	 * A prefix the administrator already typed is not doubled -- the field on
	 * the storage screen shows the resulting name, and somebody who has read it
	 * and typed it back must not end up with `wp_wp_basic_firewall_blocked`.
	 *
	 * @param string $table Unprefixed table name.
	 */
	public function prefix_table( string $table ): string {
		global $wpdb;

		$prefix = isset( $wpdb->prefix ) ? (string) $wpdb->prefix : '';

		if ( '' === $prefix || 0 === strpos( $table, $prefix ) ) {
			return $table;
		}

		return $prefix . $table;
	}

	/**
	 * This site's table prefix.
	 */
	public function prefix(): string {
		global $wpdb;

		return isset( $wpdb->prefix ) ? (string) $wpdb->prefix : '';
	}

	/**
	 * A discriminator that separates this site's Redis keys from its siblings'.
	 *
	 * The library defaults its rate-limit keys to a bare `ratelimit:`, so
	 * sibling sites sharing one Redis instance would count each other's
	 * requests. A single site keeps the plain prefix so keys stay recognisable
	 * in `redis-cli`; a network site gets its prefix mixed in.
	 */
	public function rate_limit_key_prefix(): string {
		if ( ! is_multisite() ) {
			return 'ratelimit:';
		}

		$discriminator = trim( $this->prefix(), '_' );

		if ( '' === $discriminator ) {
			$discriminator = 'site' . get_current_blog_id();
		}

		return 'ratelimit:' . $discriminator . ':';
	}
}
