<?php
/**
 * Where the Redis password comes from.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall;

use Kanopi\BasicFirewall\Transfer\Secret_Paths;
use Kanopi\Firewall\Utility\TokenSubstitute;

/**
 * The password for every Redis connection the plugin configures.
 *
 * The block list on Redis and a rate limit's counters on Redis both need one,
 * and until #48 both were written into the compiled file as typed. That file
 * lives under uploads, which on nginx this plugin has measured to be
 * web-readable, and the wp-config.php path reads nothing else -- it runs before
 * there are options -- so a password only in the settings did not reach it.
 * Moving it to a sidecar beside the compiled file would be the same plaintext
 * on the same disk (#17).
 *
 * So there are three sources, best first:
 *
 * 1. **The `BASIC_FIREWALL_REDIS_PASSWORD` constant**, defined in
 *    wp-config.php above the bootstrap snippet. Both paths can read a
 *    constant, so the password is handed to the library as a runtime override
 *    at request time, exactly as the `DB_*` credentials are (see
 *    Database_Credentials), and never written to any file this plugin owns.
 *    The compiler records only *where* it belongs, in the options and in a
 *    sidecar of paths -- `redis-auth-paths.json`, paths and usernames, never a
 *    password. It applies to every Redis connection, block list and counters
 *    alike: one server is the ordinary case, and a site with several gives
 *    each field a token of its own instead.
 * 2. **A `%env(NAME)%` token in the field.** Written into the compiled file as
 *    the token, and resolved by the library each time it loads the file. The
 *    resolved value does reach the library's parse cache, a PHP file readable
 *    only by the owner, which is the same place every other token lands.
 * 3. **The password typed literally.** Still works, and is still written into
 *    the compiled file, because that is the only way the wp-config.php path
 *    can have it: it cannot read the settings, and a sidecar would be the same
 *    plaintext on the same disk. Site Health recommends one of the others.
 *
 * Not in bootstrap.php, which must not need this plugin's classes; that file
 * reads the constant for itself, through its `redis_password` option.
 */
final class Redis_Password {

	/**
	 * The wp-config.php constant.
	 */
	public const CONSTANT = 'BASIC_FIREWALL_REDIS_PASSWORD';

	/**
	 * What tests use in place of the constant, which cannot be undefined.
	 *
	 * @var array{0: string|null}|null
	 */
	private static ?array $simulated = null;

	/**
	 * The constant's value, if it is set to something usable.
	 *
	 * Not trimmed: a password is whatever was issued. An empty string counts as
	 * not set, so `define( ..., getenv( 'X' ) ?: '' )` on an environment without
	 * the variable falls back to the settings rather than to no password.
	 */
	public static function from_constant(): ?string {
		if ( null !== self::$simulated ) {
			return self::$simulated[0];
		}

		if ( ! defined( self::CONSTANT ) ) {
			return null;
		}

		$value = constant( self::CONSTANT );

		return is_string( $value ) && '' !== $value ? $value : null;
	}

	/**
	 * Whether the constant supplies the password.
	 */
	public static function is_overridden(): bool {
		return null !== self::from_constant();
	}

	/**
	 * The password to connect with now, from whichever source applies.
	 *
	 * For code that opens a connection itself rather than through the
	 * compiled file -- the block list screen and WP-CLI. A token is resolved
	 * here as the library would resolve it; one that cannot be resolved is no
	 * password, and the connection then reports why it failed.
	 *
	 * @param string $stored The stored password, literal or a token.
	 */
	public static function live( string $stored ): string {
		$constant = self::from_constant();

		if ( null !== $constant ) {
			return $constant;
		}

		if ( ! Secret_Paths::is_token( $stored ) ) {
			return $stored;
		}

		try {
			$resolved = TokenSubstitute::substitute( trim( $stored ) );
		} catch ( \Throwable $e ) {
			return '';
		}

		return is_scalar( $resolved ) ? (string) $resolved : '';
	}

	/**
	 * Whether a stored password is typed literally rather than a token.
	 *
	 * @param mixed $stored The stored password.
	 */
	public static function is_plaintext( $stored ): bool {
		return is_string( $stored ) && '' !== $stored && ! Secret_Paths::is_token( $stored );
	}

	/**
	 * The `auth` option `ext-redis` takes: a password, or a username and password.
	 *
	 * @param string $username The ACL username, or empty.
	 * @param string $password The password.
	 *
	 * @return string|list<string>
	 */
	public static function auth( string $username, string $password ) {
		return '' === $username ? $password : array( $username, $password );
	}

	/**
	 * Stand in for the constant, for tests.
	 *
	 * A constant cannot be undefined, so a test that defined it would change
	 * every test after it. Null restores the real lookup.
	 *
	 * @internal
	 *
	 * @param string|null $value   The value to act as the constant's.
	 * @param bool        $restore Whether to go back to reading the constant.
	 */
	public static function simulate( ?string $value, bool $restore = false ): void {
		self::$simulated = $restore ? null : array( null === $value || '' === $value ? null : $value );
	}
}
