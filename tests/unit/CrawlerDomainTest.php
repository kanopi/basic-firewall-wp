<?php
/**
 * Tests for the domains a verified crawler may reverse-resolve into.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\RuleType\Types\User_Agent;
use PHPUnit\Framework\TestCase;

/**
 * What is stored, and what is refused, as an accepted crawler domain.
 *
 * The library matches on a label boundary, so `googlebot.com` accepts
 * `crawl-1.googlebot.com` and not `evilgooglebot.com`. Everything refused here
 * is a value that would never have matched anything -- a URL, a wildcard, an
 * address, a bare top-level domain -- so refusing it on the screen is the
 * difference between a typo and an allow rule that silently never fires.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\User_Agent
 */
final class CrawlerDomainTest extends TestCase {

	/**
	 * Typed input, and what is stored.
	 *
	 * @return array<string, array{mixed, list<string>}>
	 */
	public static function typed(): array {
		return array(
			'one per line'            => array( "googlebot.com\nsearch.msn.com", array( 'googlebot.com', 'search.msn.com' ) ),
			'leading dot is dropped'  => array( '.googlebot.com', array( 'googlebot.com' ) ),
			'trailing dot is dropped' => array( 'googlebot.com.', array( 'googlebot.com' ) ),
			'case is folded'          => array( 'GoogleBot.COM', array( 'googlebot.com' ) ),
			'blank lines are ignored' => array( "googlebot.com\n\n  \n", array( 'googlebot.com' ) ),
			'duplicates collapse'     => array( "googlebot.com\n.GOOGLEBOT.com", array( 'googlebot.com' ) ),
			'nothing typed'           => array( '', array() ),
			'an already-split list'   => array( array( 'googlebot.com', ' applebot.apple.com ' ), array( 'googlebot.com', 'applebot.apple.com' ) ),
		);
	}

	/**
	 * Domains are stored normalised, whichever shape they arrive in.
	 *
	 * Both shapes, because the rule screen posts a textarea and everything else
	 * that writes settings -- an import, WP-CLI, the settings normaliser --
	 * hands back the list this produced last time.
	 *
	 * @dataProvider typed
	 *
	 * @param mixed        $value    What arrived.
	 * @param list<string> $expected What is stored.
	 */
	public function test_domains_are_normalised( $value, array $expected ): void {
		$this->assertSame( $expected, User_Agent::normalise_suffixes( $value ) );
	}

	/**
	 * Normalising is idempotent.
	 */
	public function test_normalising_twice_changes_nothing(): void {
		$once = User_Agent::normalise_suffixes( "GoogleBot.com.\n.search.msn.com" );

		$this->assertSame( $once, User_Agent::normalise_suffixes( $once ) );
	}

	/**
	 * Crawler domains that are accepted.
	 *
	 * @return array<string, array{string}>
	 */
	public static function plausible(): array {
		return array(
			'google'     => array( 'googlebot.com' ),
			'bing'       => array( 'search.msn.com' ),
			'apple'      => array( 'applebot.apple.com' ),
			'duckduckgo' => array( 'duckduckgo.com' ),
			'hyphenated' => array( 'crawl-host.example.org' ),
		);
	}

	/**
	 * A crawler domain passes.
	 *
	 * @dataProvider plausible
	 *
	 * @param string $suffix The domain.
	 */
	public function test_a_crawler_domain_is_plausible( string $suffix ): void {
		$this->assertTrue( User_Agent::is_plausible_suffix( $suffix ) );
	}

	/**
	 * Values that are not a domain.
	 *
	 * @return array<string, array{string}>
	 */
	public static function implausible(): array {
		return array(
			'a URL'                           => array( 'https://googlebot.com' ),
			'a wildcard'                      => array( '*.googlebot.com' ),
			'a path'                          => array( 'googlebot.com/bot' ),
			'a port'                          => array( 'googlebot.com:443' ),
			'an address'                      => array( '66.249.66.1:80' ),
			'a bare TLD'                      => array( 'com' ),
			'a single label'                  => array( 'localhost' ),
			'a leading hyphen'                => array( '-googlebot.com' ),
			'an empty label'                  => array( 'googlebot..com' ),
			'whitespace inside'               => array( 'google bot.com' ),
			'upper case (not yet normalised)' => array( 'Googlebot.com' ),
		);
	}

	/**
	 * Something that is not a domain is refused.
	 *
	 * @dataProvider implausible
	 *
	 * @param string $suffix The candidate.
	 */
	public function test_something_else_is_not_plausible( string $suffix ): void {
		$this->assertFalse( User_Agent::is_plausible_suffix( $suffix ) );
	}
}
