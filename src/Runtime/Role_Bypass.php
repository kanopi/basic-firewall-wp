<?php
/**
 * Exempts members of chosen roles from evaluation.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

/**
 * The General screen's "Roles exempt from evaluation".
 *
 * **Roles do not exist where the firewall runs.** It evaluates before
 * WordPress has authenticated anybody -- from wp-config.php, before WordPress
 * exists at all, or from the mu-plugin at `muplugins_loaded`, before the
 * pluggable functions that check a login cookie are loaded. That is what
 * makes refusing a request cheap, and it is why this setting was stored,
 * shown, reported by Site Health and honoured by nothing.
 *
 * So it splits on the one question both points *can* answer: does this
 * request carry a WordPress login cookie? The Drupal module splits the same
 * way, on a session cookie.
 *
 * | Request                | Where it is evaluated                                   |
 * |------------------------|---------------------------------------------------------|
 * | No login cookie        | Where it always was. Cannot belong to anyone.           |
 * | Login cookie present   | At `plugins_loaded`, once the cookie can be validated.  |
 *
 * Nearly all hostile traffic is in the first row and is untouched. A request
 * in the second is evaluated as usual unless its cookie validates, for a user
 * holding an exempt role on this site -- a forged, expired or logged-out
 * cookie authenticates as nobody, and nobody holds a role. Naming a cookie
 * buys an attacker a later evaluation, never a skipped one.
 *
 * **Only while a role is exempt.** With the setting empty -- the default --
 * nothing here runs and both paths are exactly what they were.
 *
 * **Runs without WordPress**, in part. The wp-config.php bootstrap loads this
 * class by hand for carries_login_cookie(), which touches nothing but its
 * argument; exempts() needs WordPress and is called only by the runner.
 */
final class Role_Bypass {

	/**
	 * The prefix WordPress names its login cookie with.
	 *
	 * The full name carries a hash of the site URL, which the wp-config.php
	 * path has no way to compute, so the prefix is matched. LOGGED_IN_COOKIE
	 * is honoured too, for a site that renames it.
	 */
	public const COOKIE_PREFIX = 'wordpress_logged_in_';

	/**
	 * Whether a request carries something named like a WordPress login cookie.
	 *
	 * The name only, never the value: this decides where a request is
	 * evaluated, not whether it is exempt, so it can afford to be generous.
	 *
	 * @param array<mixed> $cookies The request's cookies, usually `$_COOKIE`.
	 */
	public static function carries_login_cookie( array $cookies ): bool {
		$custom = defined( 'LOGGED_IN_COOKIE' ) ? (string) constant( 'LOGGED_IN_COOKIE' ) : '';

		foreach ( array_keys( $cookies ) as $name ) {
			$name = (string) $name;

			if ( 0 === strpos( $name, self::COOKIE_PREFIX ) || ( '' !== $custom && $custom === $name ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The configured roles worth checking: non-empty strings, once each.
	 *
	 * @param array<mixed> $roles What was stored.
	 *
	 * @return list<string>
	 */
	public static function clean( array $roles ): array {
		$clean = array();

		foreach ( $roles as $role ) {
			$role = is_string( $role ) ? trim( $role ) : '';

			if ( '' !== $role && ! in_array( $role, $clean, true ) ) {
				$clean[] = $role;
			}
		}

		return $clean;
	}

	/**
	 * Whether the current request can be checked for a role yet.
	 *
	 * The login cookie is validated by wp_validate_auth_cookie(), a pluggable
	 * function, which WordPress loads after the regular plugins and before
	 * `plugins_loaded`; the cookie name it reads is defined just before those
	 * plugins. So from `plugins_loaded` on -- and not at `muplugins_loaded`,
	 * even if an mu-plugin has declared its own copy of the function.
	 */
	public static function can_authenticate(): bool {
		return function_exists( 'did_action' )
			&& ( did_action( 'plugins_loaded' ) > 0 || doing_action( 'plugins_loaded' ) )
			&& function_exists( 'wp_validate_auth_cookie' );
	}

	/**
	 * Whether the request's login cookie belongs to a member of an exempt role.
	 *
	 * The cookie is validated, not just read, and without making anybody the
	 * current user: calling wp_get_current_user() this early would settle the
	 * current user before plugins that authenticate some other way -- an
	 * application password, a token -- have had their say, and they would
	 * find it already decided.
	 *
	 * @param list<string> $roles Exempt roles.
	 */
	public static function exempts( array $roles ): bool {
		if ( array() === $roles || ! self::can_authenticate() ) {
			return false;
		}

		$user_id = wp_validate_auth_cookie( '', 'logged_in' );

		if ( ! is_int( $user_id ) || $user_id <= 0 ) {
			return false;
		}

		$user = get_userdata( $user_id );

		if ( false === $user ) {
			return false;
		}

		return array() !== array_intersect( $roles, (array) $user->roles );
	}
}
