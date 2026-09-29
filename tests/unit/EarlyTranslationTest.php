<?php
/**
 * Nothing on the request path translates before `init`.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use PHPUnit\Framework\TestCase;

/**
 * The runner fails at `muplugins_loaded`, and the responder refuses there.
 *
 * Translating at that point makes WordPress 6.7 and later report
 * "translation loading was triggered too early" -- on every request the
 * firewall could not start for, and on every refused one. So the runner
 * records a key and translates when the message is read, and the responder
 * translates only once `init` has run.
 *
 * Read from the source, because the runner cannot be driven before `init`
 * in a suite that loads WordPress, and cannot be constructed without it here.
 *
 * @coversNothing
 */
final class EarlyTranslationTest extends TestCase {

	/**
	 * Functions that load translations.
	 */
	private const TRANSLATING = array( '__', '_e', '_x', '_n', 'esc_html__', 'esc_attr__', 'esc_html_e', 'esc_attr_e' );

	/**
	 * Runner::evaluate() translates nothing.
	 */
	public function test_the_runner_translates_nothing_while_evaluating(): void {
		$this->assertSame(
			array(),
			$this->translations_in( dirname( __DIR__, 2 ) . '/src/Runtime/Runner.php', 'evaluate' ),
			'Runner::evaluate() runs at muplugins_loaded, before init; translate when the failure is read.'
		);
	}

	/**
	 * Every translation in the responder is behind the check for `init`.
	 */
	public function test_the_responder_translates_only_after_init(): void {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/src/Runtime/Outcome_Responder.php' ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reading the plugin's own source.

		$this->assertSame( 0, preg_match( '/function_exists\(\s*\'__\'\s*\)\s*\?/', $source ), 'A translation in the responder is guarded only by __() existing, which it does before init on the mu-plugin path.' );
		$this->assertMatchesRegularExpression( '/did_action\(\s*\'init\'\s*\)/', $source );
	}

	/**
	 * The translating calls inside one method of a file.
	 *
	 * @param string $file   Source file.
	 * @param string $method Method name.
	 *
	 * @return list<string>
	 */
	private function translations_in( string $file, string $method ): array {
		$tokens = token_get_all( (string) file_get_contents( $file ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reading the plugin's own source.
		$found  = array();
		$inside = false;
		$depth  = 0;
		$count  = count( $tokens );

		for ( $i = 0; $i < $count; $i++ ) {
			$token = $tokens[ $i ];

			if ( ! $inside ) {
				if ( is_array( $token ) && T_FUNCTION === $token[0] ) {
					$j = $i + 1;

					while ( $j < $count && is_array( $tokens[ $j ] ) && T_WHITESPACE === $tokens[ $j ][0] ) {
						++$j;
					}

					if ( isset( $tokens[ $j ] ) && is_array( $tokens[ $j ] ) && $method === $tokens[ $j ][1] ) {
						$inside = true;
					}
				}

				continue;
			}

			if ( '{' === $token || ( is_array( $token ) && in_array( $token[0], array( T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES ), true ) ) ) {
				++$depth;
			} elseif ( '}' === $token ) {
				--$depth;

				if ( 0 === $depth ) {
					break;
				}
			} elseif ( is_array( $token ) && T_STRING === $token[0] && in_array( $token[1], self::TRANSLATING, true ) ) {
				$found[] = $token[1];
			}
		}

		$this->assertTrue( $inside, "$method() was not found in $file." );

		return $found;
	}
}
