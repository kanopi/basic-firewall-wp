<?php
/**
 * Versioned upgrade routines.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Install;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Settings;
use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Types\Vulnerability_Score;
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
	 * Hooked to `plugins_loaded` at priority 1, where the check costs one
	 * autoloaded option on every request. The routines themselves wait for
	 * `init` at priority 0, still ahead of the admin, WP-CLI commands and
	 * cron, which are what read settings after that.
	 *
	 * They wait because of what they set off. A routine saves settings, a
	 * save rebuilds the compiled file, and the compiler and the rule types
	 * translate every problem they report -- and translating before `init`
	 * makes WordPress 6.7 and later report "translation loading was triggered
	 * too early" on whichever visitor's request happened to follow an update.
	 * The runner has already evaluated that request by then, from the
	 * compiled file on disk, so waiting costs it nothing.
	 */
	public static function maybe_upgrade(): void {
		$stored = (int) get_option( Schema::VERSION_OPTION, 0 );

		if ( $stored >= Schema::VERSION ) {
			return;
		}

		if ( ! did_action( 'init' ) && ! doing_action( 'init' ) ) {
			if ( ! has_action( 'init', array( self::class, 'maybe_upgrade' ) ) ) {
				add_action( 'init', array( self::class, 'maybe_upgrade' ), 0 );
			}

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

		/*
		 * And then to current, which is not the same thing.
		 *
		 * The loop above only advances as far as the highest routine, so a
		 * release that raises the schema version without needing a migration --
		 * a settings key added with a harmless default, which is most of them --
		 * left the stored version behind the constant permanently. Nothing
		 * broke, and `maybe_upgrade()` ran its whole loop on every single
		 * request forever, re-running the last routine each time.
		 */
		update_option( Schema::VERSION_OPTION, Schema::VERSION, false );

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
			1  => static function (): void {
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
			2  => static function (): void {
				$settings = Plugin::instance()->settings();
				$values   = $settings->all();

				/*
				 * Routine 3's rewrite, first. replace() re-validates every
				 * rule, and validation takes a pasted pattern's delimiters off
				 * while leaving its case to the checkbox -- which is right for
				 * somebody typing `#foo#i` into the form, and wrong here: a
				 * schema 1 document carries its case in the flag and has no
				 * checkbox value at all. Run in this order, routine 3 found
				 * every pattern already unwrapped and had no flag left to read,
				 * so `#Bot#` stored before 1.0.0 came out case-insensitive.
				 * Idempotent, so routine 3 running after it changes nothing.
				 */
				self::unwrap_regex_conditions( $values );
				self::strip_legacy_scheme( $values );

				$settings->replace( $values );
			},

			/*
			 * 3: store a regular expression as its body, not as `#body#i`.
			 *
			 * The delimiters and the case flag are now added at compile time
			 * from the condition's own case-sensitivity box, which makes that
			 * box behave here as it does on every other operator and removes a
			 * requirement nobody should have had to know about -- an
			 * undelimited pattern used to save, report itself active, and match
			 * nothing.
			 *
			 * The flag is read back out rather than discarded: a pattern stored
			 * as `#bot#i` was case-insensitive, so the condition it becomes has
			 * to be too, or this upgrade would quietly narrow what every such
			 * rule matches.
			 *
			 * The legacy reading is used: before this, the stored value was
			 * the whole pattern, so `/wp-admin/` was delimited even without
			 * flags. Anywhere else a bare slash pair is a path, not delimiters
			 * -- see Condition_Rule_Type_Base::regex_body().
			 *
			 * Little depends on the routine having run. `regex_body()` unwraps
			 * a pattern delimited any other way wherever one turns up, so a
			 * site that skips this keeps working; the routine is what stops the
			 * old spelling being shown back to somebody on the rule screen, and
			 * what reads a slash-delimited pattern the way it was meant.
			 */
			3  => static function (): void {
				$settings = Plugin::instance()->settings();
				$values   = $settings->all();

				self::unwrap_regex_conditions( $values );

				$settings->replace( $values );
			},

			/*
			 * 6: seed `storage.record_request`, new in library 2.31.0.
			 *
			 * Writing the document back through the validator fills in every key
			 * the schema has gained since it was last saved, which is what this
			 * is for -- the compiler defaults an absent bucket too, but only the
			 * stored document is what the storage screen shows, and a screen
			 * whose fields are blank while the compiled file has the defaults is
			 * a screen that lies.
			 */
			6  => static function (): void {
				$settings = Plugin::instance()->settings();

				$settings->replace( $settings->all() );
			},

			/*
			 * 7: store condition variables under the names the library reads.
			 *
			 * The geolocation type offered `country_name`, `timezone`,
			 * `latitude` and `longitude`, and the ASN type `organization`. The
			 * library knows them as `country.name`, `location.timeZone`,
			 * `location.latitude`, `location.longitude` and `asn_org`, and
			 * resolves any other name to nothing -- so every rule on one saved,
			 * reported itself healthy, and matched nobody.
			 *
			 * Each rule type's own rename map is used, so a type contributed by
			 * another plugin that renames a variable is migrated the same way.
			 * Nothing depends on the routine having run: the compiler translates
			 * an old name wherever it finds one. This is what stops the old name
			 * being shown back on the rule screen.
			 */
			7  => static function (): void {
				$settings = Plugin::instance()->settings();
				$values   = $settings->all();

				self::rename_condition_variables( $values );

				$settings->replace( $values );
			},

			/*
			 * 8: drop the "send events to WordPress" settings.
			 *
			 * `logging.to_wordpress` and `logging.wp_level` were stored and
			 * shown on the Logging screen, and nothing forwarded anything:
			 * WordPress has no log to forward to, and decisions already reach
			 * it as the `basic_firewall_decision` actions. Settings drops
			 * retired keys whenever it reads or writes the document; this
			 * writes the option once, so they leave the database as well.
			 * Read from the option itself, because all() has already dropped
			 * them from what it returns.
			 */
			8  => static function (): void {
				$stored = get_option( Schema::OPTION, array() );

				if ( ! is_array( $stored ) || Settings::drop_retired( $stored ) === $stored ) {
					return;
				}

				Plugin::instance()->settings()->replace( Plugin::instance()->settings()->all() );
			},

			/*
			 * 9: the Request / URL type's `referer` and `content_type`.
			 *
			 * Both are headers to the library, which reads them as
			 * `header.referer` and `header.content-type` and resolves the old
			 * names to nothing -- so "referer does not contain example.com"
			 * blocked every request. The same rewrite as routine 7, run again
			 * because the rename map has grown; it is idempotent, so a name
			 * already rewritten is left alone.
			 *
			 * `uri`, `body` and `server.*` are not renamed, because the library
			 * reads nothing equivalent. They are kept as they are and reported
			 * -- on the rule, and by the compiler -- rather than dropped: out of
			 * an "all" rule, dropping a negated condition would widen what the
			 * rule matches.
			 */
			9  => static function (): void {
				$settings = Plugin::instance()->settings();
				$values   = $settings->all();

				self::rename_condition_variables( $values );

				$settings->replace( $values );
			},

			/*
			 * 10: recompile, so the compiled file carries `path_source`.
			 *
			 * Nothing stored changes. The compiled file now says
			 * `global.path_source: script_name`, and `base_path` on a
			 * subdirectory install, and until it is rebuilt a direct request
			 * for wp-login.php or an admin screen is matched as `/` again --
			 * the request rewrite that used to paper over that is gone. Every
			 * upgrade is followed by a rebuild, so an empty routine is what
			 * makes one happen on the first request after the update rather
			 * than on the next settings save. Site Health's request path check
			 * is critical on a compiled file that is missing the key.
			 */
			10 => static function (): void {
				// Deliberately empty: the rebuild that follows every upgrade is the point.
			},

			/*
			 * 11: recompile, so the compiled file names the pass cookie
			 * explicitly and the compile record carries it.
			 *
			 * Nothing stored changes. The runner now sets the pass under the
			 * name the compiled file gives the library, read from the compile
			 * record (#35); without a rebuild an existing site has no record
			 * until the next settings save.
			 */
			11 => static function (): void {
				// Deliberately empty: the rebuild that follows every upgrade is the point.
			},

			/*
			 * 12: translate vulnerability score rules the withdrawn type saved.
			 *
			 * That type stored `{threshold, weights}`, the library reads
			 * `risk_levels` and `scoring.*`, and so every such rule matched
			 * nothing; 1.0 skipped them and named them in Site Health. The
			 * rebuilt type stores the library's own shape, and this carries
			 * each old rule into it where the mapping is sound -- see
			 * Vulnerability_Score::translate_legacy(): the threshold becomes a
			 * single level that matches at it, with the default scores.
			 *
			 * A rule with weights is not translated, because a weight was one
			 * number for a whole signal and the library scores each value of a
			 * signal on its own; there is nothing to map it to that would not
			 * be a guess about what somebody meant. It is kept in its old shape
			 * and switched off, and the compiler names it on the Status screen
			 * and in Site Health until somebody sets its scores or deletes it.
			 *
			 * Idempotent: a translated rule is no longer in the old shape, and
			 * one switched off stays off.
			 */
			12 => static function (): void {
				$settings = Plugin::instance()->settings();
				$values   = $settings->all();

				if ( self::translate_vulnerability_scores( $values ) ) {
					$settings->replace( $values );
				}
			},

			/*
			 * 13: delete the geolocation and ASN license key (#54).
			 *
			 * The field is gone because nothing ever read it: the library
			 * opens a local database and never downloads one, and the only
			 * thing it would use a key for is the MaxMind web-service client,
			 * which this plugin does not configure. A stored credential that
			 * nothing reads is only a liability -- it sits in the options
			 * table and in every backup of it -- so the stored value is
			 * deleted rather than merely no longer shown.
			 *
			 * Idempotent: a rule without the key is left alone, and the
			 * settings are written only when one was removed.
			 */
			13 => static function (): void {
				$settings = Plugin::instance()->settings();
				$values   = $settings->all();

				if ( self::remove_reader_license_keys( $values ) ) {
					$settings->replace( $values );
				}
			},
		);
	}

	/**
	 * Remove the license key from every geolocation and ASN rule's reader.
	 *
	 * See routine 13.
	 *
	 * @param array<string, mixed> $values Settings, modified in place.
	 *
	 * @return bool Whether anything changed.
	 */
	private static function remove_reader_license_keys( array &$values ): bool {
		if ( ! isset( $values['rules'] ) || ! is_array( $values['rules'] ) ) {
			return false;
		}

		$changed = false;

		foreach ( $values['rules'] as $index => $rule ) {
			if ( ! is_array( $rule ) || ! in_array( (string) ( $rule['type'] ?? '' ), array( 'geolocation', 'asn' ), true ) ) {
				continue;
			}

			if ( ! is_array( $rule['settings']['reader'] ?? null ) || ! array_key_exists( 'license_key', $rule['settings']['reader'] ) ) {
				continue;
			}

			unset( $values['rules'][ $index ]['settings']['reader']['license_key'] );
			$changed = true;
		}

		return $changed;
	}

	/**
	 * Carry every withdrawn-shape vulnerability score rule into the new shape.
	 *
	 * See routine 12.
	 *
	 * @param array<string, mixed> $values Settings, modified in place.
	 *
	 * @return bool Whether anything changed.
	 */
	private static function translate_vulnerability_scores( array &$values ): bool {
		if ( ! isset( $values['rules'] ) || ! is_array( $values['rules'] ) ) {
			return false;
		}

		$type    = new Vulnerability_Score();
		$changed = false;

		foreach ( $values['rules'] as $index => $rule ) {
			if ( ! is_array( $rule ) || 'vulnerability_score' !== ( $rule['type'] ?? '' ) ) {
				continue;
			}

			$stored = is_array( $rule['settings'] ?? null ) ? $rule['settings'] : array();

			if ( ! Vulnerability_Score::is_legacy( $stored ) ) {
				continue;
			}

			$translated = $type->translate_legacy( $stored );

			if ( null !== $translated ) {
				$values['rules'][ $index ]['settings'] = $translated;
				$changed                               = true;

				continue;
			}

			if ( ! empty( $rule['enabled'] ) ) {
				$values['rules'][ $index ]['enabled'] = false;
				$changed                              = true;
			}
		}

		return $changed;
	}

	/**
	 * Rewrite every stored condition and list variable to the library's name.
	 *
	 * @param array<string, mixed> $values Settings, modified in place.
	 */
	private static function rename_condition_variables( array &$values ): void {
		if ( ! isset( $values['rules'] ) || ! is_array( $values['rules'] ) ) {
			return;
		}

		$registry = Plugin::instance()->rule_types();

		foreach ( $values['rules'] as $rule_index => $rule ) {
			if ( ! is_array( $rule ) || ! is_array( $rule['settings'] ?? null ) ) {
				continue;
			}

			$type = $registry->get( (string) ( $rule['type'] ?? '' ) );

			if ( ! $type instanceof Condition_Rule_Type_Base ) {
				continue;
			}

			foreach ( array( 'conditions', 'sources' ) as $list ) {
				if ( ! is_array( $rule['settings'][ $list ] ?? null ) ) {
					continue;
				}

				foreach ( $rule['settings'][ $list ] as $index => $row ) {
					if ( ! is_array( $row ) || ! is_string( $row['variable'] ?? null ) ) {
						continue;
					}

					$values['rules'][ $rule_index ]['settings'][ $list ][ $index ]['variable'] = $type->library_variable( $row['variable'] );
				}
			}
		}
	}

	/**
	 * Take the delimiters off every stored regular expression.
	 *
	 * @param array<string, mixed> $values Settings, modified in place.
	 */
	private static function unwrap_regex_conditions( array &$values ): void {
		if ( ! isset( $values['rules'] ) || ! is_array( $values['rules'] ) ) {
			return;
		}

		foreach ( $values['rules'] as $rule_index => $rule ) {
			if ( ! is_array( $rule ) || ! is_array( $rule['settings']['conditions'] ?? null ) ) {
				continue;
			}

			foreach ( $rule['settings']['conditions'] as $index => $condition ) {
				if ( ! is_array( $condition ) || 'regex' !== ( $condition['operator'] ?? '' ) ) {
					continue;
				}

				$stored = trim( (string) ( $condition['value'] ?? '' ) );
				$body   = Condition_Rule_Type_Base::legacy_regex_body( $stored );

				if ( $body === $stored ) {
					continue;
				}

				$values['rules'][ $rule_index ]['settings']['conditions'][ $index ]['value'] = $body;

				/*
				 * An `i` flag meant case-insensitive, which is now the
				 * unchecked box. Read from the tail of the stored pattern,
				 * because that is where the answer was.
				 */
				$flags = substr( $stored, strrpos( $stored, $stored[0] ) + 1 );

				$values['rules'][ $rule_index ]['settings']['conditions'][ $index ]['case_sensitive'] =
					false === stripos( $flags, 'i' );
			}
		}
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
