<?php
/**
 * The challenge signing secret.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Install;

use Kanopi\BasicFirewall\Plugin;

/**
 * Guarantees a signing secret exists, and resolves which one is in force.
 *
 * The secret signs the pass tokens a solved challenge issues, so a token cannot
 * be forged. The library refuses to start rather than sign with nothing, and
 * this plugin catches that refusal and fails open -- which means a missing
 * secret does not break challenges, it switches **the entire firewall** off
 * while the interface goes on reporting that it is enabled.
 *
 * That consequence is why this is written as an invariant rather than as a
 * one-time step at activation. Generating it once on install leaves every route
 * that can produce a site without one: an import that carried an empty secret,
 * a database restored from before the field existed, an option edited by hand,
 * a site cloned with the option dropped. ensure() is therefore cheap, idempotent
 * and called from activation, from the upgrade routines, and before every
 * compile.
 */
final class Challenge_Secret {

	/**
	 * The wp-config.php constant that overrides the stored value.
	 */
	public const CONSTANT = 'BASIC_FIREWALL_CHALLENGE_SECRET';

	/**
	 * Length of a generated secret, in bytes before hex encoding.
	 */
	private const BYTES = 32;

	/**
	 * Write a secret if there is not one already.
	 *
	 * Returns true when it had to generate one, which the caller may want to
	 * report -- a secret appearing where there was none invalidates nothing,
	 * but a rotation would, and the two are worth telling apart.
	 */
	public static function ensure(): bool {
		$settings = Plugin::instance()->settings();
		$stored   = (string) $settings->get( 'challenge.secret', '' );

		if ( '' !== trim( $stored ) ) {
			return false;
		}

		// A secret supplied out of band is a secret. Do not overwrite it with a
		// generated one just because the stored field is empty -- that is the
		// documented way to keep it out of configuration.
		if ( self::from_constant() !== null ) {
			return false;
		}

		$settings->set( 'challenge.secret', self::generate() );

		return true;
	}

	/**
	 * A new random secret.
	 *
	 * `wp_generate_password()` is not used here. It is seeded from
	 * `wp_rand()`, which is documented as suitable for passwords rather than
	 * for keys, and this value is an HMAC key. `random_bytes()` is the
	 * cryptographically secure source and has been in core PHP since 7.0.
	 */
	public static function generate(): string {
		return bin2hex( random_bytes( self::BYTES ) );
	}

	/**
	 * The secret in force for this request, or null if there is none.
	 *
	 * Precedence, highest first:
	 *
	 * 1. The `BASIC_FIREWALL_CHALLENGE_SECRET` constant in wp-config.php. This
	 *    is the wp-config.php equivalent of the module's `$settings[...]` entry,
	 *    and the admin field is disabled while it is set so the interface never
	 *    shows a value that is not the one being used.
	 * 2. The stored value, which may itself be a `%env(NAME)%` or `%file(/path)%`
	 *    token -- those are resolved by the library when it reads the compiled
	 *    file, not here, which is what lets a rotated value take effect without
	 *    a rebuild.
	 */
	public static function resolve(): ?string {
		$constant = self::from_constant();

		if ( null !== $constant ) {
			return $constant;
		}

		$stored = trim( (string) Plugin::instance()->settings()->get( 'challenge.secret', '' ) );

		return '' === $stored ? null : $stored;
	}

	/**
	 * The constant's value, if it is set to something usable.
	 */
	private static function from_constant(): ?string {
		if ( ! defined( self::CONSTANT ) ) {
			return null;
		}

		$value = constant( self::CONSTANT );

		if ( ! is_string( $value ) || '' === trim( $value ) ) {
			return null;
		}

		return trim( $value );
	}

	/**
	 * Whether the secret is being supplied by the wp-config.php constant.
	 */
	public static function is_overridden(): bool {
		return null !== self::from_constant();
	}
}
