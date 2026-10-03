<?php
/**
 * The wording and styling of the pages the firewall serves.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Support;

use Kanopi\Firewall\Challenge\ChallengePage;
use Kanopi\Firewall\Page\BlockPage;

/**
 * Turns the stored page settings into `challenge.page`, `global.block_page` and
 * `global.lockdown_page` (kanopi/firewall 2.37.0, #451, #452).
 *
 * The library refuses to start on a page value it cannot use -- an unknown
 * key, a malformed `lang`, CSS containing a closing style tag, a stylesheet
 * that is not a site path or an `https:` URL -- and this plugin fails open when
 * the library refuses to start. So a typo in a colour would switch every rule
 * off. Two things stand between the two:
 *
 * - the settings validator asks the library about each value as it is saved
 *   (the `check` callbacks below), so the screen reports the problem in the
 *   library's own words and the value is not stored;
 * - the compiler writes only values the library accepts, so a document that
 *   arrives some other way loses the one bad value, not the firewall.
 *
 * Asking the library rather than repeating its rules keeps the two from
 * drifting: a release that loosens or tightens a rule is honoured here
 * without a change.
 *
 * `lang`, `styles` and `stylesheet` are stored once, under `global.pages`, and
 * written into all three pages. The library's pages share one card and one
 * stylesheet, so one set of colours is what an administrator means, and three
 * copies of the same CSS would only drift apart.
 */
final class Page_Settings {

	/**
	 * The appearance keys shared by every page.
	 */
	public const APPEARANCE_KEYS = array( 'lang', 'styles', 'stylesheet' );

	/**
	 * The challenge page's text keys, as the library names them.
	 */
	public const CHALLENGE_TEXT_KEYS = array( 'title', 'heading', 'intro', 'button', 'error_message' );

	/**
	 * What is wrong with a `lang` value, if anything.
	 *
	 * @param string $value The value, trimmed.
	 */
	public static function lang_problem( string $value ): ?string {
		return self::problem( 'lang', $value );
	}

	/**
	 * What is wrong with a `styles` value, if anything.
	 *
	 * @param string $value The value, trimmed.
	 */
	public static function styles_problem( string $value ): ?string {
		return self::problem( 'styles', $value );
	}

	/**
	 * What is wrong with a `stylesheet` value, if anything.
	 *
	 * @param string $value The value, trimmed.
	 */
	public static function stylesheet_problem( string $value ): ?string {
		return self::problem( 'stylesheet', $value );
	}

	/**
	 * The compiled `challenge.page`, empty when nothing is set.
	 *
	 * @param array<string, mixed> $page  Stored `challenge.page`.
	 * @param array<string, mixed> $pages Stored `global.pages`.
	 *
	 * @return array<string, string>
	 */
	public static function challenge( array $page, array $pages ): array {
		return self::usable( $page, self::CHALLENGE_TEXT_KEYS ) + self::usable( $pages, self::APPEARANCE_KEYS );
	}

	/**
	 * The compiled `global.block_page` or `global.lockdown_page`.
	 *
	 * Null when the page is off, which leaves the key out and the refusal the
	 * plain text it has always been. `true`, the built-in page as it comes, when
	 * it is on and nothing about it is set.
	 *
	 * @param array<string, mixed> $page      Stored `global.block_page` or `global.lockdown_page`.
	 * @param array<string, mixed> $pages     Stored `global.pages`.
	 * @param list<string>         $text_keys The text keys this page stores.
	 *
	 * @return array<string, string>|true|null
	 */
	public static function refusal( array $page, array $pages, array $text_keys ) {
		if ( true !== ( $page['enabled'] ?? false ) ) {
			return null;
		}

		$compiled = self::usable( $page, $text_keys ) + self::usable( $pages, self::APPEARANCE_KEYS );

		return array() === $compiled ? true : $compiled;
	}

	/**
	 * The set values of some keys that the library accepts.
	 *
	 * @param array<string, mixed> $values Stored values.
	 * @param list<string>         $keys   The keys to take.
	 *
	 * @return array<string, string>
	 */
	private static function usable( array $values, array $keys ): array {
		$usable = array();

		foreach ( $keys as $key ) {
			$value = $values[ $key ] ?? null;

			if ( ! is_string( $value ) ) {
				continue;
			}

			$value = trim( $value );

			if ( '' !== $value && null === self::problem( $key, $value ) ) {
				$usable[ $key ] = $value;
			}
		}

		return $usable;
	}

	/**
	 * What the library says is wrong with one value, if anything.
	 *
	 * Asked of both page validators: every key here means the same on all
	 * three pages, so a value either accepts is one the other accepts.
	 *
	 * @param string $key   A page key.
	 * @param string $value Its value.
	 */
	private static function problem( string $key, string $value ): ?string {
		$problems = 'message' === $key
			? BlockPage::problems( array( $key => $value ) )
			: ChallengePage::problems( array( $key => $value ) );

		return $problems[0] ?? null;
	}
}
