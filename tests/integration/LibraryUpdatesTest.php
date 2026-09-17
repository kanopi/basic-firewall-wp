<?php
/**
 * What arrived with the library, and what this plugin does with it.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Library_Loader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Types\Ip_Address;
use Kanopi\BasicFirewall\RuleType\Types\Rate_Limit;
use Kanopi\BasicFirewall\RuleType\Types\Url;
use Kanopi\Firewall\Utility\Schedule;
use PHPUnit\Framework\TestCase;

/**
 * Library 2.27.0 to 2.29.0, absorbed.
 *
 * Three releases widened what a rule can say about itself. A rule can be given
 * a window; a rate limit can count something other than the address; a
 * referenced list can be XML. None of it changes an existing configuration —
 * every one of these is absent by default and absent means what it always
 * meant — which is exactly why each needs a test: a feature that changes
 * nothing when unused changes nothing when broken, either.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Rule_Type_Base
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Rate_Limit
 */
final class LibraryUpdatesTest extends TestCase {

	/**
	 * The plugin ships a library new enough for all of this.
	 */
	public function test_the_library_is_current_enough(): void {
		$version = Library_Loader::version();

		$this->assertIsString( $version );
		$this->assertTrue(
			version_compare( ltrim( $version, 'v' ), '2.30.0', '>=' ),
			sprintf( 'The challenge TTL ceiling and source verification need 2.30.0; this is %s.', $version )
		);
	}

	/**
	 * A rule with no schedule writes no schedule.
	 *
	 * An empty `active` block is not "a schedule that never applies" — the
	 * library reads an absent key as always, and an empty one has to be
	 * interpreted. A value in an exported document that nothing acts on is
	 * something the next reader has to go and disprove.
	 */
	public function test_an_unscheduled_rule_says_nothing(): void {
		$entry = ( new Url() )->compile( $this->rule() );

		$this->assertArrayNotHasKey( 'active', $entry['metadata'] ?? array() );
	}

	/**
	 * A schedule compiles to what the library reads.
	 */
	public function test_a_schedule_compiles(): void {
		$entry = ( new Url() )->compile(
			$this->rule(
				array(
					'timezone' => 'America/Los_Angeles',
					'days'     => array( 'mon', 'tue' ),
					'hours'    => '18:00-06:00',
				)
			)
		);

		$active = $entry['metadata']['active'];

		$this->assertSame( 'America/Los_Angeles', $active['timezone'] );
		$this->assertSame( array( 'mon', 'tue' ), $active['days'] );
		$this->assertSame( '18:00-06:00', $active['hours'] );

		// And the library agrees it is a schedule.
		$this->assertInstanceOf( Schedule::class, Schedule::fromMetadata( $active ) );
	}

	/**
	 * A schedule with no timezone gets the site's, not UTC.
	 *
	 * The library reads an absent timezone as UTC, which is right for a library
	 * and wrong here: somebody typing business hours into a WordPress admin
	 * means the hours this site keeps. Left to the default, 09:00-17:00 would
	 * be out by up to twelve hours and look correct while it was.
	 */
	public function test_a_schedule_without_a_timezone_uses_the_site(): void {
		$declaration = Rule_Type_Base::schedule_declaration( array( 'hours' => '09:00-17:00' ) );

		$this->assertSame( wp_timezone_string(), $declaration['timezone'] );
	}

	/**
	 * A rate limit that names no key writes none.
	 *
	 * The library's default is byte-identical to what it counted before
	 * 2.27.0, so no counter resets on upgrade — but only if nothing is written.
	 */
	public function test_a_rate_limit_without_a_key_says_nothing(): void {
		$entry = $this->rate_limit( '/wp-login.php 5 300' );

		$this->assertArrayNotHasKey( 'key', $entry['config'][0] );
	}

	/**
	 * A fourth field names what to count.
	 *
	 * @dataProvider keys
	 *
	 * @param string       $line     The limit as typed.
	 * @param list<string> $expected The key components.
	 */
	public function test_a_rate_limit_key_compiles( string $line, array $expected ): void {
		$entry = $this->rate_limit( $line );

		$this->assertSame( $expected, $entry['config'][0]['key'] );
	}

	/**
	 * Limits, and what they count.
	 *
	 * @return array<string, array{0: string, 1: list<string>}>
	 */
	public static function keys(): array {
		return array(
			'the account being tried' => array( '/login 5 300 post.log', array( 'post.log' ) ),
			'each endpoint apart'     => array( '/api/* 100 60 client_ip,path', array( 'client_ip', 'path' ) ),
			'spacing is forgiving'    => array( '/x 1 1 client_ip, path', array( 'client_ip', 'path' ) ),
		);
	}

	/**
	 * XML is offered as a referenced-list format.
	 */
	public function test_xml_is_an_offered_format(): void {
		$this->assertArrayHasKey( 'xml', Url::formats() );
	}

	/**
	 * A rule, with an optional schedule.
	 *
	 * @param array<string, mixed> $schedule The schedule.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( array $schedule = array() ): array {
		return array(
			'id'       => 'r',
			'type'     => 'url',
			'response' => 'block',
			'schedule' => $schedule,
			'settings' => array(
				'match_type' => 'any',
				'sources'    => array(),
				'conditions' => array(
					array(
						'variable' => 'path',
						'operator' => 'equals',
						'value'    => '/x',
					),
				),
			),
		);
	}

	/**
	 * Compile a rate limit from one typed line.
	 *
	 * @param string $line The limit.
	 *
	 * @return array<string, mixed>
	 */
	private function rate_limit( string $line ): array {
		$type   = new Rate_Limit();
		$errors = array();

		$settings = $type->validate_settings(
			array(
				'paths'                => array( $line ),
				'default_limit'        => 60,
				'default_window'       => 60,
				'limit_unlisted_paths' => false,
				'storage'              => array( 'backend' => 'file' ),
			),
			$errors
		);

		return $type->compile(
			array(
				'id'       => 'r',
				'response' => 'block',
				'settings' => $settings,
			)
		);
	}

	/**
	 * The challenge lifetime ceiling is written, not left to the default.
	 *
	 * Library 2.30.0 made `challenge.ttl` a ceiling as well as a default,
	 * because the lifetime that signs a pass token used to arrive in the
	 * interstitial's own POST body -- solve one arithmetic puzzle, ask for
	 * thirty-one years, and hold a signed exemption from every challenge rule
	 * for three decades. The signature was valid; it covered the number the
	 * client chose.
	 *
	 * Written out rather than inherited so the value is visible in the compiled
	 * file and on the screen that sets it, since a rule asking for longer is
	 * quietly granted this instead.
	 */
	public function test_the_challenge_ttl_ceiling_is_compiled(): void {
		$settings = Plugin::instance()->settings();
		$snapshot = $settings->all();

		try {
			$values                     = $settings->all();
			$values['challenge']['ttl'] = 900;
			$settings->replace( $values );

			Plugin::instance()->compiled()->rebuild();

			$this->assertStringContainsString(
				'ttl: 900',
				(string) Plugin::instance()->compiled()->contents(),
				'The ceiling never reached the library, so a rule asking for longer would get an hour without anyone having chosen that.'
			);
		} finally {
			$settings->replace( $snapshot );
			Plugin::instance()->compiled()->rebuild();
		}
	}

	/**
	 * A referenced list can say what its bytes should be, and how many.
	 */
	public function test_a_list_can_be_verified_and_bounded(): void {
		$entry = ( new Ip_Address() )->compile(
			array(
				'id'       => 'r',
				'response' => 'allow',
				'settings' => array(
					'addresses' => array(),
					'sources'   => array(
						array_merge(
							Ip_Address::source_defaults(),
							array(
								'url'      => 'https://example.test/ips.txt',
								'checksum' => 'sha256',
								'max_size' => '8M',
							)
						),
					),
				),
			)
		);

		$source = $entry['metadata']['sources'][0];

		$this->assertSame( 'sha256', $source['checksum'] );
		$this->assertIsArray( $source['upstream'], 'max_size belongs on the upstream, which has to become a map to carry it.' );
		$this->assertSame( '8M', $source['upstream']['max_size'] );
		$this->assertSame( 'https://example.test/ips.txt', $source['upstream']['url'], 'The URL has to survive the upstream becoming a map.' );
	}

	/**
	 * Declaring both a checksum and a signature is refused here, not there.
	 *
	 * The library throws on that combination rather than guessing which half
	 * was meant. Left to it, the rule saves and the throw arrives when the
	 * firewall next loads -- which is either a list that silently stops
	 * contributing or a firewall that does not start, depending on the error
	 * policy.
	 */
	public function test_a_checksum_and_a_signature_together_are_refused(): void {
		$errors = array();

		$clean = ( new Ip_Address() )->validate_settings(
			array(
				'addresses' => array(),
				'sources'   => array(
					array_merge(
						Ip_Address::source_defaults(),
						array(
							'url'      => 'https://example.test/ips.txt',
							'checksum' => 'sha256',
							'advanced' => array(
								'signature' => array(
									'algorithm'  => 'ed25519',
									'public_key' => '%env(FEED_KEY)%',
								),
							),
						)
					),
				),
			),
			$errors
		);

		$this->assertSame( array(), $clean['sources'] );
		$this->assertArrayHasKey( 'sources.0.checksum', $errors );
	}
}
