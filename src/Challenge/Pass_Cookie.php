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
 * WordPress-free, so the compiler, the runner, the decision dispatcher on
 * the wp-config.php path and a unit test all read the same answer.
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
	 * How long the solved marker lives, in seconds.
	 *
	 * Long enough to cover the redirect and a slow page, short enough that a
	 * visitor who clears their cookies later is not told a stale story.
	 */
	public const MARKER_TTL = 120;

	/**
	 * What a visitor whose pass went missing is told, in English.
	 *
	 * The source string of missing_notice(), kept here so a path without
	 * WordPress's translations says exactly what the translated one would.
	 */
	public const MISSING_NOTICE = 'You completed this check a moment ago, but the verification cookie did not come back with this request. Your browser may be blocking cookies for this site, or the site\'s host may not be passing the cookie on. If this keeps happening, allow cookies for this site or contact the site owner.';

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

	/**
	 * The marker cookie a solve sets beside the pass: when it was solved.
	 *
	 * Set by the runner beside the pass it issues in `exception` mode, and by
	 * Decision_Dispatcher when the library issues the pass itself in `block`
	 * mode (#46), so a re-challenge moments later can say the pass went
	 * missing instead of silently asking again.
	 *
	 * @param string   $pass_cookie The pass cookie's name.
	 * @param bool     $secure      Whether the request arrived over HTTPS.
	 * @param int|null $now         The time of the solve; now when null.
	 *
	 * @return array{name: string, value: string, options: array<string, mixed>}
	 */
	public static function marker_cookie( string $pass_cookie, bool $secure, ?int $now = null ): array {
		$now = $now ?? time();

		return array(
			'name'    => self::marker_name( $pass_cookie ),
			'value'   => (string) $now,
			'options' => array(
				'expires'  => $now + self::MARKER_TTL,
				'path'     => '/',
				'httponly' => true,
				'secure'   => $secure,
				'samesite' => 'Lax',
			),
		);
	}

	/**
	 * Is this visitor being challenged again right after solving a challenge?
	 *
	 * A solved challenge sets the pass cookie and, beside it, a short-lived
	 * marker holding the time it was solved. A challenge that arrives carrying
	 * the marker but no pass cookie at all means the pass was issued and then
	 * did not come back: a host or edge cache that forwards only cookies
	 * matching its own rules (#35), or a browser refusing it. Left alone, that
	 * visitor solves the same challenge again and again with nothing on the
	 * page to say why.
	 *
	 * Only when the pass cookie is absent. A pass that arrived and was refused
	 * -- expired, revoked, earned against a different provider -- is a
	 * different story, and the ordinary interstitial is the right answer.
	 *
	 * The marker is not signed, and does not need to be: it only adds a line
	 * to a page the visitor is already being refused with, and a visitor who
	 * forges it misleads nobody but themselves.
	 *
	 * @param string               $pass_cookie The pass cookie's name.
	 * @param array<string, mixed> $cookies     The request's cookies.
	 * @param int|null             $now         The time to judge the marker's age by; now when null.
	 */
	public static function went_missing( string $pass_cookie, array $cookies, ?int $now = null ): bool {
		if ( '' === $pass_cookie || array_key_exists( $pass_cookie, $cookies ) ) {
			return false;
		}

		$marker = $cookies[ self::marker_name( $pass_cookie ) ] ?? null;

		if ( ! is_string( $marker ) || ! ctype_digit( $marker ) ) {
			return false;
		}

		// The marker's own lifetime, checked again: a browser that ignores
		// Max-Age must not see the notice on every challenge for ever after.
		$age = ( $now ?? time() ) - (int) $marker;

		return $age >= 0 && $age <= self::MARKER_TTL;
	}

	/**
	 * The line shown on the challenge page when the pass went missing.
	 *
	 * Plain text: the library escapes a notice when it writes the page.
	 * Translated once WordPress has loaded its translations; before that --
	 * the wp-config.php path, or `muplugins_loaded` -- in English, since
	 * calling __() there would be a fatal error or load nothing.
	 */
	public static function missing_notice(): string {
		if ( function_exists( '__' ) && function_exists( 'did_action' ) && did_action( 'init' ) > 0 ) {
			return __( 'You completed this check a moment ago, but the verification cookie did not come back with this request. Your browser may be blocking cookies for this site, or the site\'s host may not be passing the cookie on. If this keeps happening, allow cookies for this site or contact the site owner.', 'basic-firewall' );
		}

		return self::MISSING_NOTICE;
	}
}
