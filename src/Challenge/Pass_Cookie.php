<?php
/**
 * Which cookie carries a solved challenge's pass token.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Challenge;

/**
 * Chooses the pass cookie's name, and knows which names Pantheon forwards.
 *
 * **Why a host matters here (#35).** Pantheon's Global CDN does not forward
 * every request cookie to PHP. It passes on the names that match its own
 * patterns -- `STYXKEY*`, `SESS*`, `wordpress*`, `wp-*`, `NO_CACHE` and a few
 * more -- and strips the rest before the request reaches WordPress. The
 * default name, `bfw_pass`, matches none of them. So a visitor solves the
 * challenge, is handed a valid pass, and arrives back without it: the firewall
 * never sees the pass and challenges them again, forever, with nothing on the
 * page to say why.
 *
 * On Pantheon the default is therefore `STYXKEY_bfw_pass`. The prefix is
 * forwarded, and it also makes the edge keep a separate cache variant per
 * cookie value, so a visitor holding a pass is never handed a cached copy of
 * somebody else's interstitial.
 *
 * **Never over an admin's choice.** Only a name nobody chose is replaced:
 * empty, or `bfw_pass` itself. The second is the schema default, and every
 * save of the Challenge screen writes whatever the field showed back, so a
 * stored `bfw_pass` is indistinguishable from "never set". Treating it as a
 * choice would leave every existing Pantheon install broken, for a name that
 * cannot work there anyway. Any other name is used exactly as typed, and Site
 * Health says so if Pantheon will strip it.
 *
 * Other managed hosts are deliberately not guessed at. WP Engine, Kinsta and
 * Flywheel vary or bypass their cache on particular cookies rather than
 * stripping the rest, so the same failure does not follow from the same name,
 * and a rename made on a guess would cost every visitor a challenge for
 * nothing. The README says what to check instead.
 *
 * WordPress-free, so the compiler, the runner and a unit test all read the
 * same answer.
 */
final class Pass_Cookie {

	/**
	 * The name used when nothing else applies.
	 */
	public const DEFAULT_NAME = 'bfw_pass';

	/**
	 * The name used on Pantheon when the admin has not chosen one.
	 */
	public const PANTHEON_NAME = 'STYXKEY_bfw_pass';

	/**
	 * Cookie names Pantheon's edge forwards to PHP.
	 *
	 * From Pantheon's "Working with Cookies on Pantheon" and "Caching: Advanced
	 * Topics": the cache-varying `STYXKEY` form, whose documented shape is
	 * `STYXKEY[a-zA-Z0-9_-]+`, and the cache-busting names -- `NO_CACHE`,
	 * `SESS`/`SSESS` session cookies ("followed by numbers and lowercase
	 * characters"), `wordpress*`, `wp-*`, `comment_author*` and
	 * `woocommerce*`. Anchored, and case-sensitive as Pantheon's own patterns
	 * are: `styxkey_x` is stripped.
	 *
	 * @var list<string>
	 */
	public const PANTHEON_FORWARDED = array(
		'/^STYXKEY[a-zA-Z0-9_-]+$/',
		'/^NO_CACHE$/',
		'/^S+ESS[a-z0-9]+$/',
		'/^wordpress/',
		'/^wp-/',
		'/^comment_author/',
		'/^woocommerce/',
	);

	/**
	 * Why the effective name is what it is.
	 */
	public const REASON_CHOSEN   = 'chosen';
	public const REASON_PANTHEON = 'pantheon';
	public const REASON_DEFAULT  = 'default';

	/**
	 * Is this site running on Pantheon?
	 *
	 * Pantheon sets `PANTHEON_ENVIRONMENT` (dev, test, live or a multidev name)
	 * in the process environment of every web and CLI container, and PHP-FPM
	 * copies it into `$_ENV` and `$_SERVER` as well. All three are read,
	 * because `variables_order` decides whether `$_ENV` is populated and a
	 * pool can be configured not to pass the environment through at all.
	 */
	public static function on_pantheon(): bool {
		$value = getenv( 'PANTHEON_ENVIRONMENT' );

		if ( is_string( $value ) && '' !== $value ) {
			return true;
		}

		foreach ( array( $_ENV, $_SERVER ) as $source ) {
			if ( isset( $source['PANTHEON_ENVIRONMENT'] ) && is_string( $source['PANTHEON_ENVIRONMENT'] ) && '' !== $source['PANTHEON_ENVIRONMENT'] ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a stored name means "whatever the default is".
	 *
	 * @param string $stored The stored `challenge.cookie_name`.
	 */
	public static function is_automatic( string $stored ): bool {
		$stored = trim( $stored );

		return '' === $stored || self::DEFAULT_NAME === $stored;
	}

	/**
	 * The cookie name the firewall issues and reads.
	 *
	 * @param string    $stored   The stored `challenge.cookie_name`.
	 * @param bool|null $pantheon Whether the site is on Pantheon; detected when null.
	 */
	public static function effective_name( string $stored, ?bool $pantheon = null ): string {
		if ( ! self::is_automatic( $stored ) ) {
			return trim( $stored );
		}

		return ( $pantheon ?? self::on_pantheon() ) ? self::PANTHEON_NAME : self::DEFAULT_NAME;
	}

	/**
	 * Why effective_name() gave what it gave: one of the REASON_ constants.
	 *
	 * @param string    $stored   The stored `challenge.cookie_name`.
	 * @param bool|null $pantheon Whether the site is on Pantheon; detected when null.
	 */
	public static function reason( string $stored, ?bool $pantheon = null ): string {
		if ( ! self::is_automatic( $stored ) ) {
			return self::REASON_CHOSEN;
		}

		return ( $pantheon ?? self::on_pantheon() ) ? self::REASON_PANTHEON : self::REASON_DEFAULT;
	}

	/**
	 * Does Pantheon's edge pass a cookie of this name on to PHP?
	 *
	 * @param string $name Cookie name.
	 */
	public static function forwarded_by_pantheon( string $name ): bool {
		foreach ( self::PANTHEON_FORWARDED as $pattern ) {
			if ( 1 === preg_match( $pattern, $name ) ) {
				return true;
			}
		}

		return false;
	}
}
