<?php
/**
 * Versioned upgrade routines.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Install;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Paths;
use Kanopi\BasicFirewall\Support\Schema;

/**
 * Runs upgrade routines against a stored schema version.
 *
 * The translation of `hook_post_update_NAME()`. Drupal gets an update system
 * with a registry, an ordering guarantee and a `drush updatedb` that a
 * deployment can be made to fail on. WordPress has none of that: a plugin's
 * files are replaced and the next request runs the new code against the old
 * data, whether or not anybody is watching.
 *
 * So the contract here is narrower and has to be stricter:
 *
 * - **Routines are numbered and run in order**, from the stored version to the
 *   current one.
 * - **Every routine is idempotent.** There is no transaction around a WordPress
 *   request and no guarantee one finishes -- a timeout halfway through leaves
 *   the version unadvanced and the routine re-runs from the start next request.
 *   A routine that cannot survive that is a routine that corrupts data.
 * - **The version advances per routine, not at the end.** A later routine
 *   failing must not make an earlier one run twice.
 * - **A failure is reported, never fatal.** The firewall keeps serving.
 */
final class Upgrader {

	/**
	 * Option recording an upgrade that did not complete.
	 */
	public const FAILURE_OPTION = 'basic_firewall_upgrade_error';

	/**
	 * Run any routines this site has not run yet.
	 *
	 * Hooked to `plugins_loaded` at priority 1, so it is ahead of anything that
	 * reads settings.
	 */
	public static function maybe_upgrade(): void {
		$stored = (int) get_option( Schema::VERSION_OPTION, 0 );

		if ( $stored >= Schema::VERSION ) {
			return;
		}

		/*
		 * A site that has the plugin's files but has never written the option is
		 * not an upgrade -- it is an install that has not been activated, or one
		 * whose activation hook never ran (a copied wp-content, a plugin
		 * activated by dropping it into mu-plugins). Bring it to current
		 * without running migrations over data that was never written.
		 */
		if ( 0 === $stored && ! Plugin::instance()->settings()->is_installed() ) {
			update_option( Schema::VERSION_OPTION, Schema::VERSION, false );
			return;
		}

		foreach ( self::routines() as $version => $routine ) {
			if ( $version <= $stored ) {
				continue;
			}

			try {
				$routine();
			} catch ( \Throwable $e ) {
				update_option(
					self::FAILURE_OPTION,
					sprintf(
						/* translators: 1: schema version number, 2: error message. */
						__( 'Upgrade routine %1$d did not complete: %2$s. The firewall is still running on the previous configuration.', 'basic-firewall' ),
						$version,
						$e->getMessage()
					),
					false
				);

				// Stop rather than skip. A later routine may assume this one ran.
				return;
			}

			// Advance one at a time. See the class docblock.
			update_option( Schema::VERSION_OPTION, $version, false );
		}

		delete_option( self::FAILURE_OPTION );

		/**
		 * Fires after upgrade routines have brought the site to the current
		 * schema version.
		 *
		 * The compiler listens: a settings shape that changed has to be
		 * recompiled before it is next read, and the compiled file may also
		 * carry class names that a scoped build has just renamed.
		 */
		do_action( 'basic_firewall_upgraded' );
	}

	/**
	 * The routines, keyed by the schema version they bring the site to.
	 *
	 * @return array<int, callable(): void>
	 */
	private static function routines(): array {
		return array(

			/*
			 * 1: the first shipped schema. Present so that the machinery has a
			 * routine to run and is exercised by the test suite from the first
			 * release rather than from the first time it matters.
			 *
			 * It re-grants capabilities and re-asserts the invariants that later
			 * releases may add to, all of which are idempotent by construction.
			 */
			1 => static function (): void {
				Capabilities::grant();
				Plugin::instance()->paths()->ensure();
				Challenge_Secret::ensure();
			},

			/*
			 * 2: drop the Drupal `private://` scheme from stored paths.
			 *
			 * The scheme was carried over from the module, where it is a real
			 * registered stream wrapper. WordPress has no such thing, so it was
			 * a Drupal-ism in front of every WordPress developer for a string
			 * their platform cannot resolve. Paths are now plain: relative to
			 * the private directory, or absolute.
			 *
			 * Paths::resolve() still accepts the old spelling, so a site that
			 * skipped this routine keeps working. This is what stops the old
			 * spelling being shown back to somebody on the storage screen.
			 */
			2 => static function (): void {
				$settings = Plugin::instance()->settings();
				$values   = $settings->all();

				self::strip_legacy_scheme( $values );

				$settings->replace( $values );
			},
		);
	}

	/**
	 * Remove the legacy `private://` prefix from every stored path.
	 *
	 * Walks the whole document rather than naming the keys that hold a path.
	 * Naming them is how uninstall.php came to leave two options behind: a list
	 * that has to be maintained alongside the thing it describes rots, and a
	 * rule type contributed by another plugin can store a path this file has
	 * never heard of.
	 *
	 * @param array<string, mixed> $values Settings document, by reference.
	 */
	private static function strip_legacy_scheme( array &$values ): void {
		foreach ( $values as $key => $value ) {
			if ( is_array( $value ) ) {
				self::strip_legacy_scheme( $values[ $key ] );

				continue;
			}

			if ( is_string( $value ) && 0 === strpos( $value, Paths::LEGACY_SCHEME ) ) {
				$values[ $key ] = substr( $value, strlen( Paths::LEGACY_SCHEME ) );
			}
		}
	}

	/**
	 * The message from an upgrade that did not complete, or null.
	 */
	public static function failure(): ?string {
		$stored = get_option( self::FAILURE_OPTION, '' );

		return is_string( $stored ) && '' !== $stored ? $stored : null;
	}
}
