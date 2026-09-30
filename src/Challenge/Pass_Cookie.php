<?php
/**
 * Which cookie carries a solved challenge's pass token.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Challenge;

/**
 * The pass cookie's name: the one the admin set, and the marker beside it.
 *
 * The name comes from the Challenge screen (`challenge.cookie_name`) and is
 * used exactly as stored, trimmed. The compiler writes it into the compiled
 * file and the runner issues the cookie under the compiled name, so the
 * cookie a solved challenge sets is always the one the library looks for.
 *
 * Some hosts and edge caches forward only cookies whose names match their own
 * rules. Nothing here guesses at those: an admin whose host drops the default
 * sets a name the host forwards, and the marker follows it (marker_name()).
 *
 * WordPress-free, so the compiler, the runner and a unit test all read the
 * same answer.
 */
final class Pass_Cookie {

	/**
	 * The name used when none is stored, or the stored one is unusable.
	 */
	public const DEFAULT_NAME = 'bfw_pass';

	/**
	 * Appended to the pass cookie's name to name the solved marker.
	 */
	public const MARKER_SUFFIX = '_solved';

	/**
	 * Is this usable as a cookie name?
	 *
	 * An RFC 6265 token: printable ASCII, no separators, no whitespace. PHP's
	 * setcookie() refuses `=,; \t\r\n\013\014` outright; the rest of the
	 * separators are refused too, because a browser or proxy may split on
	 * them.
	 *
	 * @param string $name Cookie name.
	 */
	public static function is_valid( string $name ): bool {
		return 1 === preg_match( '/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/', $name );
	}

	/**
	 * The cookie name the firewall issues and reads.
	 *
	 * The stored name, trimmed. Empty or unusable -- only possible through an
	 * import or WP-CLI, since the screen refuses both -- falls back to the
	 * default rather than compiling a name no browser would send back.
	 *
	 * @param string $stored The stored `challenge.cookie_name`.
	 */
	public static function name( string $stored ): string {
		$stored = trim( $stored );

		return self::is_valid( $stored ) ? $stored : self::DEFAULT_NAME;
	}

	/**
	 * The short-lived marker a solved challenge sets beside the pass.
	 *
	 * Derived from the pass cookie's name, so whatever prefix an admin chose
	 * to get the pass past their host's edge applies to the marker too.
	 *
	 * @param string $pass_cookie The pass cookie's name.
	 */
	public static function marker_name( string $pass_cookie ): string {
		return $pass_cookie . self::MARKER_SUFFIX;
	}
}
