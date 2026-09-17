<?php
/**
 * Regular expressions reach the library as they were written.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Types\Url;
use PHPUnit\Framework\TestCase;

/**
 * The case-sensitivity setting must never reach a regex condition.
 *
 * The library implements case-insensitivity by lowercasing both sides of the
 * comparison before running it, and for this operator one of those sides is the
 * pattern. Lowercasing a pattern does not make it case-insensitive: it rewrites
 * it, and for the uppercase metacharacter escapes it rewrites it into its own
 * opposite.
 *
 * `#\D+#` — written to match anything that is not a number — ran as `#\d+#` and
 * matched only numbers, in a rule that saved, validated and reported itself
 * active. Nothing could have caught it downstream either: this plugin validates
 * the pattern as written, and the library ran a different one.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base
 */
final class RegexCaseTest extends TestCase {

	/**
	 * A rule with one condition.
	 *
	 * @param array<string, mixed> $condition Condition overrides.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( array $condition ): array {
		return array(
			'id'       => 'r',
			'type'     => 'url',
			'response' => 'block',
			'settings' => array(
				'match_type' => 'any',
				'conditions' => array(
					array_merge(
						array(
							'variable'       => 'path',
							'operator'       => 'regex',
							'value'          => '#\D+#',
							'negate'         => false,
							'case_sensitive' => false,
						),
						$condition
					),
				),
				'sources'    => array(),
			),
		);
	}

	/**
	 * A regex always reaches the library as case sensitive.
	 *
	 * Not because case does not matter, but because the library's way of
	 * honouring it would rewrite the pattern. The administrator's choice is
	 * carried in the `i` flag instead — see the next test.
	 */
	public function test_a_regex_is_always_compiled_case_sensitive(): void {
		foreach ( array( false, true ) as $checkbox ) {
			$entry = ( new Url() )->compile( $this->rule( array( 'case_sensitive' => $checkbox ) ) );

			$this->assertTrue(
				$entry['config'][0]['case_sensitive'],
				'A regex compiled case-insensitive, so the library will lowercase the pattern and run something else.'
			);
		}
	}

	/**
	 * The checkbox is honoured, as the pattern's flag.
	 */
	public function test_the_checkbox_becomes_the_i_flag(): void {
		$insensitive = ( new Url() )->compile(
			$this->rule(
				array(
					'value'          => '^/admin',
					'case_sensitive' => false,
				)
			)
		);
		$sensitive   = ( new Url() )->compile(
			$this->rule(
				array(
					'value'          => '^/admin',
					'case_sensitive' => true,
				)
			)
		);

		$this->assertSame( '#^/admin#i', $insensitive['config'][0]['value'] );
		$this->assertSame( '#^/admin#', $sensitive['config'][0]['value'] );
	}

	/**
	 * The stored value is the body; the delimiters are the plugin's business.
	 *
	 * An undelimited pattern used to be accepted by the field and rejected by
	 * the library, so the rule saved, reported itself active, and matched
	 * nothing. Owning the delimiters removes the requirement rather than
	 * warning about it.
	 *
	 * @dataProvider bodies
	 *
	 * @param string $body     What is typed.
	 * @param bool   $sensitive Whether case matters.
	 * @param string $expected The pattern the library receives.
	 */
	public function test_a_body_is_wrapped( string $body, bool $sensitive, string $expected ): void {
		$this->assertSame( $expected, Condition_Rule_Type_Base::assemble_regex( $body, $sensitive ) );
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an invalid pattern warns, and the warning is the thing being asserted about.
		$this->assertNotFalse( @preg_match( $expected, '' ), 'The assembled pattern does not compile.' );
	}

	/**
	 * Bodies, and what they become.
	 *
	 * @return array<string, array{0: string, 1: bool, 2: string}>
	 */
	public static function bodies(): array {
		return array(
			'plain, insensitive'       => array( '^/wp-admin', false, '#^/wp-admin#i' ),
			'plain, sensitive'         => array( '^/wp-admin', true, '#^/wp-admin#' ),
			'the escape that inverted' => array( '\\D+', false, '#\\D+#i' ),
			'an uppercase class'       => array( '[A-Z]{3}', true, '#[A-Z]{3}#' ),
			'a body holding a hash'    => array( 'colour#[0-9a-f]+', false, '~colour#[0-9a-f]+~i' ),
			'a body holding them all'  => array( 'a#b~c%d!e@f', false, '#a\\#b~c%d!e@f#i' ),
			'pasted with delimiters'   => array( '#already#i', false, '#already#i' ),
			'pasted with slashes'      => array( '/slashes/', false, '#slashes#i' ),
			'a literal leading hash'   => array( '#tag', false, '~#tag~i' ),
		);
	}

	/**
	 * An existing delimited value still loads.
	 *
	 * The upgrade routine rewrites stored patterns, but nothing may depend on
	 * it having run: a document imported from a site that skipped it, or a
	 * settings option restored from a backup, still has to work.
	 */
	public function test_a_delimited_value_is_unwrapped(): void {
		$entry = ( new Url() )->compile(
			$this->rule(
				array(
					'value'          => '#^/legacy#i',
					'case_sensitive' => false,
				)
			)
		);

		$this->assertSame( '#^/legacy#i', $entry['config'][0]['value'], 'A stored pattern was double-wrapped.' );
	}

	/**
	 * Every other operator still honours the setting.
	 *
	 * The fix has to be narrow. Case-insensitive `contains` is the common case
	 * and lowercasing both sides is exactly right for it.
	 */
	public function test_other_operators_still_honour_the_setting(): void {
		foreach ( array( 'contains', 'equals', 'starts_with', 'ends_with' ) as $operator ) {
			$entry = ( new Url() )->compile(
				$this->rule(
					array(
						'operator'       => $operator,
						'value'          => 'Admin',
						'case_sensitive' => false,
					)
				)
			);

			$this->assertFalse(
				$entry['config'][0]['case_sensitive'],
				sprintf( 'The %s operator stopped honouring case sensitivity.', $operator )
			);
		}
	}

	/**
	 * What lowercasing actually did, pinned so the reason stays legible.
	 *
	 * Asserted against PCRE rather than against the library, because the point
	 * is a property of regular expressions and not of anybody's code.
	 *
	 * @dataProvider corrupted_patterns
	 *
	 * @param string $pattern The pattern as written.
	 * @param string $subject Something it was written to match.
	 */
	public function test_lowercasing_a_pattern_changes_what_it_matches( string $pattern, string $subject ): void {
		$this->assertSame( 1, preg_match( $pattern, $subject ), 'The fixture pattern does not match its own subject.' );

		$this->assertNotSame(
			1,
			preg_match( strtolower( $pattern ), $subject ),
			'This pattern survives lowercasing, so it is not evidence of anything and should not be in this list.'
		);
	}

	/**
	 * Patterns whose meaning lowercasing destroys.
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function corrupted_patterns(): array {
		return array(
			'non-digit becomes digit'          => array( '#\D+#', 'abc' ),
			'non-word becomes word'            => array( '#\W#', '!' ),
			'non-whitespace becomes space'     => array( '#\S+#', 'x' ),
			'an uppercase class becomes lower' => array( '#^[A-Z]{3}$#', 'ABC' ),
		);
	}
}
