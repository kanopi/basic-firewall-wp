<?php
/**
 * Tests for the redirect and mark checks.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\RuleType\Response_Settings;
use PHPUnit\Framework\TestCase;

/**
 * The rule screen and the compiler both ask these questions, so the answers are
 * pinned here once.
 *
 * The redirect destination is the one with teeth. The library does not reject
 * a redirect rule naming nowhere when it loads; it throws when the rule
 * matches, so an empty destination is not a rule that does nothing -- it is a
 * firewall failure on every request the rule was written for.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Response_Settings
 */
final class ResponseSettingsTest extends TestCase {

	/**
	 * Destinations the library can send a visitor to.
	 *
	 * @return array<string, array{string}>
	 */
	public static function usable_destinations(): array {
		return array(
			'a path'            => array( '/too-many-requests' ),
			'the front page'    => array( '/' ),
			'an https URL'      => array( 'https://example.com/notice' ),
			'an http URL'       => array( 'http://example.com/notice' ),
			'upper-case scheme' => array( 'HTTPS://example.com/' ),
			'padded'            => array( '  /notice  ' ),
		);
	}

	/**
	 * A path or an http(s) URL is accepted.
	 *
	 * @dataProvider usable_destinations
	 *
	 * @param string $location Destination.
	 */
	public function test_a_path_or_url_is_accepted( string $location ): void {
		$this->assertNull( Response_Settings::redirect_problem( $location ) );
	}

	/**
	 * Nowhere is refused, including whitespace that trims to nowhere.
	 */
	public function test_an_empty_destination_is_refused(): void {
		$this->assertSame( Response_Settings::REDIRECT_EMPTY, Response_Settings::redirect_problem( '' ) );
		$this->assertSame( Response_Settings::REDIRECT_EMPTY, Response_Settings::redirect_problem( '   ' ) );
	}

	/**
	 * A scheme-relative destination is named, because it reads like a path.
	 */
	public function test_a_scheme_relative_destination_is_named_as_off_site(): void {
		$this->assertSame( Response_Settings::REDIRECT_OFF_SITE, Response_Settings::redirect_problem( '//evil.example/x' ) );
	}

	/**
	 * Anything else is refused.
	 */
	public function test_anything_else_is_refused(): void {
		foreach ( array( 'notice', 'javascript:alert(1)', 'ftp://example.com/', 'example.com/notice' ) as $location ) {
			$this->assertSame(
				Response_Settings::REDIRECT_UNSUPPORTED,
				Response_Settings::redirect_problem( $location ),
				$location
			);
		}
	}

	/**
	 * A URL rule whose own path condition matches its destination is caught.
	 */
	public function test_a_redirect_into_its_own_conditions_is_caught(): void {
		$this->assertTrue( Response_Settings::redirect_loops( '/old-api/gone', array( self::path( 'starts_with', '/old-api' ) ) ) );
		$this->assertTrue( Response_Settings::redirect_loops( '/Notice', array( self::path( 'equals', '/notice' ) ) ), 'Case does not hide it.' );
		$this->assertTrue( Response_Settings::redirect_loops( '/a/notice/b', array( self::path( 'contains', 'notice' ) ) ) );
	}

	/**
	 * A negated condition, another variable, or a miss is not a loop.
	 */
	public function test_what_is_not_a_loop(): void {
		$negated           = self::path( 'starts_with', '/old-api' );
		$negated['negate'] = true;

		$this->assertFalse( Response_Settings::redirect_loops( '/old-api/gone', array( $negated ) ) );
		$this->assertFalse(
			Response_Settings::redirect_loops(
				'/old-api/gone',
				array(
					array(
						'variable' => 'query.page',
						'operator' => 'contains',
						'value'    => 'old-api',
					),
				)
			)
		);
		$this->assertFalse( Response_Settings::redirect_loops( '/notice', array( self::path( 'starts_with', '/old-api' ) ) ) );
		$this->assertFalse( Response_Settings::redirect_loops( '/notice', array( self::path( 'regex', 'notice' ) ) ), 'Only the obvious shapes are checked.' );
		$this->assertFalse( Response_Settings::redirect_loops( '', array( self::path( 'contains', '' ) ) ) );
	}

	/**
	 * A mark name has to be addressable as part of an attribute key.
	 */
	public function test_mark_names(): void {
		$this->assertTrue( Response_Settings::is_mark_name( '' ), 'Blank means the rule identifier.' );
		$this->assertTrue( Response_Settings::is_mark_name( 'probe_2-x' ) );
		$this->assertFalse( Response_Settings::is_mark_name( 'has space' ) );
		$this->assertFalse( Response_Settings::is_mark_name( 'has.dot' ) );
	}

	/**
	 * A header name is letters, numbers and hyphens.
	 */
	public function test_header_names(): void {
		$this->assertTrue( Response_Settings::is_header_name( '' ), 'Blank means no header.' );
		$this->assertTrue( Response_Settings::is_header_name( 'X-Firewall-Flagged' ) );
		$this->assertFalse( Response_Settings::is_header_name( 'X Firewall' ) );
		$this->assertFalse( Response_Settings::is_header_name( 'X-Firewall:' ) );
		$this->assertFalse( Response_Settings::is_header_name( 'X_Firewall' ) );
	}

	/**
	 * A path condition.
	 *
	 * @param string $operator Operator.
	 * @param string $value    Value.
	 *
	 * @return array<string, mixed>
	 */
	private static function path( string $operator, string $value ): array {
		return array(
			'variable' => 'path',
			'operator' => $operator,
			'value'    => $value,
			'negate'   => false,
		);
	}
}
