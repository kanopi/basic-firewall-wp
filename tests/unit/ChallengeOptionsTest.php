<?php
/**
 * Tests for the translation between the Challenge screen and the providers.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Compiler\Config_Compiler;
use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use PHPUnit\Framework\TestCase;

/**
 * What the screen stores is not always what a provider reads.
 *
 * The screen offers "reject the visitor" and "let them through" as `fail` and
 * `pass`. Turnstile and reCAPTCHA read `block` and `allow`, and treat anything
 * they do not recognise as `block` -- so "let them through" silently rejected
 * everybody during a vendor outage. The integration suite proves the value
 * reaches a constructed provider; this pins the translation itself.
 *
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler::provider_options
 */
final class ChallengeOptionsTest extends TestCase {

	/**
	 * Every spelling of the error policy, and what the provider should get.
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function policies(): array {
		return array(
			'screen: reject'        => array( 'fail', 'block' ),
			'screen: let through'   => array( 'pass', 'allow' ),
			'library: block'        => array( 'block', 'block' ),
			'library: allow'        => array( 'allow', 'allow' ),
			'anything else rejects' => array( 'maybe', 'block' ),
		);
	}

	/**
	 * The error policy is written in the provider's vocabulary.
	 *
	 * @dataProvider policies
	 *
	 * @param string $stored   What the screen stored.
	 * @param string $compiled What the provider reads.
	 */
	public function test_the_error_policy_is_translated( string $stored, string $compiled ): void {
		$this->assertSame( $compiled, Config_Compiler::provider_options( array( 'on_error' => $stored ) )['on_error'] );
	}

	/**
	 * A timeout is written as the one the provider will actually use.
	 */
	public function test_the_timeout_is_what_the_provider_allows(): void {
		$this->assertSame( Library_Map::CHALLENGE_TIMEOUT_MAX, Config_Compiler::provider_options( array( 'timeout' => 120 ) )['timeout'] );
		$this->assertSame( 1, Config_Compiler::provider_options( array( 'timeout' => 0 ) )['timeout'] );
		$this->assertSame( 4, Config_Compiler::provider_options( array( 'timeout' => '4' ) )['timeout'] );
	}

	/**
	 * The ceiling is the providers' own, not a guess at it.
	 */
	public function test_the_ceiling_matches_the_providers(): void {
		foreach ( array( TurnstileChallengeProvider::class, RecaptchaChallengeProvider::class ) as $provider ) {
			$this->assertSame( Library_Map::CHALLENGE_TIMEOUT_MAX, ( new \ReflectionClassConstant( $provider, 'MAX_TIMEOUT' ) )->getValue(), $provider );
		}
	}

	/**
	 * Blank values are left for the provider's default; a false flag is kept.
	 */
	public function test_blanks_are_dropped_and_flags_kept(): void {
		$this->assertSame(
			array(
				'site_key'      => 'key',
				'send_remoteip' => false,
			),
			Config_Compiler::provider_options(
				array(
					'site_key'      => 'key',
					'widget_src'    => '',
					'theme'         => null,
					'send_remoteip' => false,
				)
			)
		);
	}
}
