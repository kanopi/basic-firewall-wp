<?php
/**
 * Tests for what a rate limit counts by, and what it has to be paired with.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\RuleType\Types\Rate_Limit;
use PHPUnit\Framework\TestCase;

/**
 * The two key shapes catch opposite attacks.
 *
 * | Keyed by | Catches                            | Misses                                  |
 * |----------|------------------------------------|-----------------------------------------|
 * | address  | one client hammering many accounts | a botnet against one account            |
 * | identity | many clients against one account   | one client walking a list of usernames  |
 *
 * And an identity-keyed limit records no offense, so on its own it leaves brute
 * force unprotected and the block list empty. What is pinned here is how the
 * plugin tells the two apart, and what it counts as a companion.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Rate_Limit
 */
final class RateLimitKeyTest extends TestCase {

	/**
	 * No key, or one with the address in it, is address-keyed.
	 */
	public function test_the_default_and_anything_with_the_address_count_the_address(): void {
		$this->assertFalse( Rate_Limit::counts_an_identity( array() ), 'The default key counts the address.' );
		$this->assertFalse( Rate_Limit::counts_an_identity( array( 'client_ip', 'post.log' ) ), 'A combined key still bans by address.' );
		$this->assertFalse( Rate_Limit::counts_an_identity( array( 'client_ip', 'path' ) ) );
	}

	/**
	 * A key without the address counts an identity.
	 */
	public function test_a_key_without_the_address_counts_an_identity(): void {
		$this->assertTrue( Rate_Limit::counts_an_identity( array( 'post.log' ) ) );
		$this->assertTrue( Rate_Limit::counts_an_identity( array( 'header.authorization' ) ) );
		$this->assertTrue( Rate_Limit::counts_an_identity( array( 'rule_pattern', 'path' ) ), 'Even a key naming no identity at all withholds the ban.' );
	}

	/**
	 * Every component the library resolves is accepted.
	 */
	public function test_every_component_the_library_resolves_is_known(): void {
		$this->assertSame(
			array(),
			Rate_Limit::unknown_key_components(
				array( 'client_ip', 'rule_pattern', 'path', 'method', 'host', 'scheme', 'port', 'query', 'header.x-api-key', 'post.log', 'cookie.session', 'query.q' )
			)
		);
	}

	/**
	 * A component the library cannot resolve is named.
	 *
	 * It would resolve to an empty string on every request, so every request
	 * would share one count -- one visitor spending the allowance for the site.
	 */
	public function test_an_unresolvable_component_is_named(): void {
		$this->assertSame(
			array( 'pots.log', 'post', 'header.', 'ip' ),
			Rate_Limit::unknown_key_components( array( 'post.log', 'pots.log', 'post', 'header.', 'ip' ) )
		);
	}

	/**
	 * A form field, cookie or query name keeps its case; a prefix and a header do not.
	 *
	 * Those three names are case-sensitive everywhere that reads them, so
	 * `post.userName` lower-cased is a field that is never there. A header name
	 * is case-insensitive, and the prefix is forgiven its case.
	 */
	public function test_a_case_sensitive_name_keeps_its_case(): void {
		$this->assertSame(
			array( 'post.userName', 'cookie.Session', 'query.Q', 'header.x-api-key', 'post.log', 'post.x', 'client_ip', 'query' ),
			Rate_Limit::parse_key( ' post.userName, cookie.Session ,query.Q, header.X-Api-Key, POST.log, Post.x, CLIENT_IP, Query, ' )
		);
	}

	/**
	 * The plugin spells every component exactly as the library reads it.
	 *
	 * Checked against the library's own normalisation rather than a copy of
	 * it, so a library that changes its mind fails here. A key that already
	 * worked -- lower case, or a capitalised header or prefix -- is spelled as
	 * it always was, which is why no stored key moves to a different counter.
	 */
	public function test_components_match_the_library(): void {
		$typed = array( 'post.userName', 'cookie.Session', 'query.Q', 'header.User-Agent', 'POST.x', 'Cookie.sid', 'CLIENT_IP', 'rule_pattern', 'Path', 'post.log', 'header.x-api-key' );

		$library = ( new \ReflectionClass( \Kanopi\Firewall\Plugins\RateLimit::class ) )->newInstanceWithoutConstructor();
		$method  = new \ReflectionMethod( $library, 'keyComponents' );
		$method->setAccessible( true );

		$this->assertSame( $method->invoke( $library, array( 'key' => $typed ) ), Rate_Limit::parse_key( implode( ',', $typed ) ) );
		$this->assertSame( array( 'header.user-agent', 'post.x' ), Rate_Limit::parse_key( 'header.User-Agent, POST.x' ) );
	}

	/**
	 * An identity-keyed limit alone is unpaired.
	 */
	public function test_an_identity_keyed_limit_alone_is_unpaired(): void {
		$this->assertSame(
			array( 'accounts' => array( '/wp-login.php' ) ),
			Rate_Limit::unpaired_identity_limits( array( $this->rule( 'accounts', array( '/wp-login.php 5 300 post.log' ) ) ) )
		);
	}

	/**
	 * An address-keyed limit on the same pattern, in another rule, pairs it.
	 */
	public function test_an_address_keyed_limit_in_another_rule_pairs_it(): void {
		$this->assertSame(
			array(),
			Rate_Limit::unpaired_identity_limits(
				array(
					$this->rule( 'accounts', array( '/wp-login.php 5 300 post.log' ) ),
					$this->rule( 'addresses', array( '/wp-login.php 50 300' ) ),
				)
			)
		);
	}

	/**
	 * A companion in the same rule is no companion.
	 *
	 * Within one rule the library uses the first line whose pattern matches,
	 * so the second line for a pattern is never reached. The library's own
	 * documentation pairs the two this way, and it is the pairing that does
	 * nothing.
	 */
	public function test_a_companion_in_the_same_rule_does_not_count(): void {
		$this->assertSame(
			array( 'both' => array( '/wp-login.php' ) ),
			Rate_Limit::unpaired_identity_limits(
				array( $this->rule( 'both', array( '/wp-login.php 5 300 post.log', '/wp-login.php 50 300' ) ) )
			)
		);
	}

	/**
	 * A disabled companion is no companion either.
	 */
	public function test_a_disabled_companion_does_not_count(): void {
		$companion            = $this->rule( 'addresses', array( '/wp-login.php 50 300' ) );
		$companion['enabled'] = false;

		$this->assertArrayHasKey(
			'accounts',
			Rate_Limit::unpaired_identity_limits( array( $this->rule( 'accounts', array( '/wp-login.php 5 300 post.log' ) ), $companion ) )
		);
	}

	/**
	 * A companion on a different pattern does not pair it.
	 */
	public function test_a_companion_on_another_pattern_does_not_count(): void {
		$this->assertArrayHasKey(
			'accounts',
			Rate_Limit::unpaired_identity_limits(
				array(
					$this->rule( 'accounts', array( '/wp-login.php 5 300 post.log' ) ),
					$this->rule( 'addresses', array( '/xmlrpc.php 50 300' ) ),
				)
			)
		);
	}

	/**
	 * A key with the address in it needs no companion.
	 */
	public function test_a_combined_key_needs_no_companion(): void {
		$this->assertSame(
			array(),
			Rate_Limit::unpaired_identity_limits( array( $this->rule( 'combined', array( '/wp-login.php 5 300 client_ip, post.log' ) ) ) )
		);
	}

	/**
	 * Validated maps are read the same as the lines they came from.
	 */
	public function test_validated_limits_are_read_like_typed_ones(): void {
		$rule                      = $this->rule( 'accounts', array() );
		$rule['settings']['paths'] = array(
			array(
				'pattern' => '/wp-login.php',
				'limit'   => 5,
				'window'  => 300,
				'key'     => array( 'post.log' ),
			),
		);

		$this->assertSame( array( 'accounts' => array( '/wp-login.php' ) ), Rate_Limit::unpaired_identity_limits( array( $rule ) ) );
	}

	/**
	 * A rate limit rule.
	 *
	 * @param string       $id    Identifier.
	 * @param list<string> $lines Limit lines, as typed.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( string $id, array $lines ): array {
		return array(
			'id'       => $id,
			'type'     => 'rate_limit',
			'enabled'  => true,
			'settings' => array( 'paths' => $lines ),
		);
	}
}
