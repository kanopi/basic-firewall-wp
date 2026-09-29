<?php
/**
 * A crawler rule that asks to verify and has nothing to verify against.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Transfer\Importer;
use Symfony\Component\Yaml\Yaml;

/**
 * An allow rule for crawlers whose domains were all dropped must not compile.
 *
 * The rule screen refuses `verify` with no domain, but every other writer
 * stores what the validator leaves: `*.googlebot.com` is not a domain, so it is
 * dropped, the verify flag is kept, and the rule is left verifying against
 * nothing. It used to compile without its verification -- a plain `bot equals
 * true` allow rule, which ends evaluation for anybody sending `Googlebot/2.1`.
 *
 * Each case here puts a block-everything rule behind the crawler rule, so a
 * crawler rule that compiled is visible as a request that was let through.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\User_Agent
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Transfer\Importer
 * @covers \Kanopi\BasicFirewall\Settings
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class UnverifiableCrawlerRuleTest extends Honoured_Settings {

	/**
	 * Skip where the library cannot verify: the compiler skips every verifying rule there.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! ( new Library_Capabilities() )->has_identity_verification() ) {
			$this->markTestSkipped( 'The installed library cannot verify crawlers.' );
		}
	}

	/**
	 * Stored through Settings::replace(), the way WP-CLI and a seed script write.
	 */
	public function test_written_through_settings_it_lets_no_claimed_crawler_through(): void {
		$firewall = $this->build( array( 'rules' => $this->rules() ) );

		$this->assert_skipped_and_reported();
		$this->assertSame( 'block', $this->outcome( $firewall, self::request( '/', '203.0.113.200', array( 'User-Agent' => 'Googlebot/2.1 (+http://www.google.com/bot.html)' ) ) )['verdict'] );
	}

	/**
	 * Stored through an import, which reports the dropped domain as well.
	 */
	public function test_imported_it_lets_no_claimed_crawler_through(): void {
		$this->build( array( 'rules' => array() ) );

		$result = ( new Importer() )->import( Yaml::dump( array( 'rules' => $this->rules() ), 10, 2 ), 'merge' );

		$this->assertTrue( $result['ok'], 'The document did not import.' );
		$this->assertContains( 'rules.crawlers.settings.verify_suffixes', array_column( $result['problems'], 'path' ), 'The import did not say the domain was dropped.' );

		$firewall = $this->start();

		$this->assert_skipped_and_reported();
		$this->assertSame( 'block', $this->outcome( $firewall, self::request( '/', '203.0.113.200', array( 'User-Agent' => 'Googlebot/2.1 (+http://www.google.com/bot.html)' ) ) )['verdict'] );
	}

	/**
	 * The control: with a domain listed the rule compiles, verifying.
	 *
	 * Without it, a compiler that skipped every crawler rule would satisfy the
	 * cases above.
	 */
	public function test_with_a_domain_the_rule_compiles_verifying(): void {
		$rules                                   = $this->rules();
		$rules[0]['settings']['verify_suffixes'] = array( 'googlebot.com' );

		$this->build( array( 'rules' => $rules ) );

		$names = array_column( (array) ( $this->compiled['plugins'] ?? array() ), 'metadata' );
		$entry = array_values( array_filter( $names, static fn ( $metadata ): bool => 'crawlers' === ( $metadata['name'] ?? '' ) ) );

		$this->assertCount( 1, $entry, 'The crawler rule was not compiled.' );
		$this->assertSame( 'reverse-dns', $entry[0]['verify'] ?? null );
		$this->assertSame( array( 'googlebot.com' ), $entry[0]['verify_suffixes'] ?? null );
	}

	/**
	 * The crawler rule is absent from the compiled file, and named everywhere it should be.
	 */
	private function assert_skipped_and_reported(): void {
		foreach ( (array) ( $this->compiled['plugins'] ?? array() ) as $entry ) {
			$this->assertNotSame( 'crawlers', $entry['metadata']['name'] ?? null, 'The crawler rule was compiled with nothing to verify against.' );
		}

		$this->assertNotSame( array(), array_filter( $this->problems, static fn ( string $problem ): bool => false !== strpos( $problem, '"crawlers"' ) ), 'The compiler did not report the skipped rule.' );

		$stored = array_values( (array) Plugin::instance()->settings()->get( 'rules', array() ) );
		$type   = Plugin::instance()->rule_types()->get( 'user_agent' );

		$this->assertNotNull( $type );
		$this->assertTrue( $stored[0]['settings']['verify'], 'The verify flag was turned off behind the operator\'s back.' );
		$this->assertStringContainsString( 'skipped', implode( ' ', $type->check_requirements( $stored[0]['settings'] ) ) );

		$health = Site_Health::check( 'verification' );

		$this->assertSame( 'critical', $health['status'] );
		$this->assertStringContainsString( 'no domain', $health['label'] );
	}

	/**
	 * An allow rule for crawlers verifying against a wildcard, then a rule refusing everybody.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function rules(): array {
		return array(
			$this->rule(
				'crawlers',
				'user_agent',
				array(
					'match_type'      => 'any',
					'conditions'      => array( self::condition( 'bot', 'equals', 'true' ) ),
					'verify'          => true,
					'verify_suffixes' => array( '*.googlebot.com' ),
				),
				array(
					'response' => 'allow',
					'weight'   => -10,
				)
			),
			$this->rule(
				'everybody',
				'url',
				array(
					'match_type' => 'any',
					'conditions' => array( self::condition( 'path', 'starts_with', '/' ) ),
				),
				array( 'weight' => 10 )
			),
		);
	}
}
