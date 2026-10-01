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
				array( 'client_ip', 'rule_pattern', 'path', 'method', 'host', 'scheme', 'port', 'query', 'header.x-api-key', 'post.log', 'cookie.session', 'query.q', 'query_count', 'query_count.f', 'query_count.Facet' )
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
			array( 'pots.log', 'post', 'header.', 'ip', 'query_count.', 'querycount.f' ),
			Rate_Limit::unknown_key_components( array( 'post.log', 'pots.log', 'post', 'header.', 'ip', 'query_count', 'query_count.', 'querycount.f' ) )
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
			array( 'post.userName', 'cookie.Session', 'query.Q', 'header.x-api-key', 'post.log', 'post.x', 'client_ip', 'query', 'query_count.Facet', 'query_count' ),
			Rate_Limit::parse_key( ' post.userName, cookie.Session ,query.Q, header.X-Api-Key, POST.log, Post.x, CLIENT_IP, Query, Query_Count.Facet, QUERY_COUNT, ' )
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
		$typed = array( 'post.userName', 'cookie.Session', 'query.Q', 'header.User-Agent', 'POST.x', 'Cookie.sid', 'CLIENT_IP', 'rule_pattern', 'Path', 'post.log', 'header.x-api-key', 'query_count.f', 'Query_Count.Facet', 'QUERY_COUNT' );

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
	 * A line an earlier line covers is named with the line that takes its requests.
	 *
	 * @dataProvider shadows
	 *
	 * @param list<string> $patterns The rule's patterns, in order.
	 * @param string|null  $shadow   What covers the last one, or null.
	 */
	public function test_an_earlier_line_that_covers_a_later_one( array $patterns, ?string $shadow ): void {
		$last = (string) array_pop( $patterns );

		$this->assertSame( $shadow, Rate_Limit::shadowed_by( $last, $patterns ) );
	}

	/**
	 * Patterns in order, and what covers the last one.
	 *
	 * @return array<string, array{0: list<string>, 1: string|null}>
	 */
	public static function shadows(): array {
		return array(
			'a wildcard before an exact path' => array( array( '/log*', '/login' ), '/log*' ),
			'the same path in capitals'       => array( array( '/login', '/LOGIN' ), '/login' ),
			'the same path'                   => array( array( '/login', '/login' ), '/login' ),
			'a prefix before a longer prefix' => array( array( '/api*', '/api/v1/*' ), '/api*' ),
			'a catch-all'                     => array( array( '*', '/api/v1/*' ), '*' ),
			'the same wildcard, other case'   => array( array( '/API/*', '/api/*' ), '/API/*' ),
			'a later exact path it misses'    => array( array( '/login', '/login2' ), null ),
			'a narrower pattern first'        => array( array( '/api/v1/*', '/api*' ), null ),
			'a wildcard in the middle'        => array( array( '/a*b*', '/a/x/*' ), null ),
			'a regex earlier is left alone'   => array( array( '#^/log#', '/login' ), null ),
			'a regex later is left alone'     => array( array( '/log*', '#^/login$#' ), null ),
			'nothing before it'               => array( array( '/login' ), null ),
		);
	}

	/**
	 * Unreachable lines are listed in order, each with what takes its requests.
	 */
	public function test_unreachable_lines_are_listed(): void {
		$this->assertSame(
			array(
				array(
					'pattern' => '/login',
					'shadow'  => '/log*',
				),
				array(
					'pattern' => '/LOG-OUT',
					'shadow'  => '/log*',
				),
			),
			Rate_Limit::unreachable_limits( array( 'paths' => array( '/log* 50 300', '/login 5 300 post.log', '/contact 5 60', '/LOG-OUT 5 60' ) ) )
		);
	}

	/**
	 * A line that never runs needs no companion; the reverse warning 2.35.0 gave is gone.
	 */
	public function test_an_unreachable_identity_line_is_not_unpaired(): void {
		$this->assertSame(
			array(),
			Rate_Limit::unpaired_identity_limits( array( $this->rule( 'shadowed', array( '/log* 50 300', '/login 5 300 post.log' ) ) ) )
		);
	}

	/**
	 * Across rules, a companion is the same path in any case.
	 */
	public function test_a_companion_in_another_case_pairs_it(): void {
		$this->assertSame(
			array(),
			Rate_Limit::unpaired_identity_limits(
				array(
					$this->rule( 'accounts', array( '/login 5 300 post.log' ) ),
					$this->rule( 'addresses', array( '/LOGIN 50 300' ) ),
				)
			)
		);
	}

	/**
	 * A companion is the line of the other rule that actually takes the request.
	 */
	public function test_a_companion_is_the_line_that_runs(): void {
		$this->assertSame(
			array(),
			Rate_Limit::unpaired_identity_limits(
				array(
					$this->rule( 'accounts', array( '/wp-login.php 5 300 post.log' ) ),
					$this->rule( 'addresses', array( '/wp-* 100 300' ) ),
				)
			),
			'An address-keyed wildcard in another rule takes the login requests, and was not counted.'
		);

		$this->assertArrayHasKey(
			'accounts',
			Rate_Limit::unpaired_identity_limits(
				array(
					$this->rule( 'accounts', array( '/wp-login.php 5 300 post.log' ) ),
					$this->rule( 'others', array( '/wp-* 100 300 header.x-api-key', '/wp-login.php 50 300' ) ),
				)
			),
			'The address line in the other rule never runs, behind a wildcard that counts something else, and was counted.'
		);
	}

	/**
	 * Where the library's lint and this check can both answer, they give the same answer.
	 *
	 * Each scenario is compiled to the library's shape and run through
	 * `ConfigLinter`, and the paths it calls "rate limited by identity, but not
	 * by address", and the entries it says never run, are compared with this
	 * check's. The one place this check is deliberately kinder -- a companion
	 * that covers the path with a wildcard, which the lint does not look for --
	 * is left out here and pinned above.
	 *
	 * @dataProvider lint_scenarios
	 *
	 * @param list<array{0: string, 1: list<string>, 2?: bool}> $rules Rule id, lines, enabled.
	 */
	public function test_the_check_agrees_with_the_library_lint( array $rules ): void {
		$stored  = array();
		$plugins = array();

		foreach ( $rules as $rule ) {
			$entry            = $this->rule( $rule[0], $rule[1] );
			$entry['enabled'] = $rule[2] ?? true;
			$stored[]         = $entry;

			$config = array();

			foreach ( Rate_Limit::limits( $entry['settings'] ) as $limit ) {
				$config[] = array(
					'path'   => $limit['pattern'],
					'rate'   => $limit['limit'],
					'sample' => $limit['window'],
				) + ( array() === $limit['key'] ? array() : array( 'key' => $limit['key'] ) );
			}

			$plugins[] = array(
				'plugin'   => \Kanopi\Firewall\Plugins\RateLimit::class,
				'name'     => $rule[0],
				'enable'   => $entry['enabled'],
				'response' => 'block',
				'config'   => $config,
			);
		}

		$library_unpaired    = array();
		$library_unreachable = array();

		foreach ( ( new \Kanopi\Firewall\Diagnostics\ConfigLinter( array( array( 'plugins' => $plugins ) ) ) )->run() as $finding ) {
			$title = (string) $finding->toArray()['title'];

			if ( 1 === preg_match( '/^(.+) is rate limited by identity, but not by address$/', $title, $match ) ) {
				$library_unpaired[] = strtolower( $match[1] );
			}

			if ( 1 === preg_match( '/the entry for (.+) never runs|more than one entry for (.+); only the first/', $title, $match ) ) {
				$library_unreachable[] = strtolower( '' !== $match[1] ? $match[1] : $match[2] );
			}
		}

		$unpaired = array_map( 'strtolower', array_merge( array(), ...array_values( Rate_Limit::unpaired_identity_limits( $stored ) ) ) );

		$unreachable = array();

		foreach ( $stored as $entry ) {
			if ( $entry['enabled'] ) {
				$unreachable = array_merge( $unreachable, array_map( 'strtolower', array_column( Rate_Limit::unreachable_limits( $entry['settings'] ), 'pattern' ) ) );
			}
		}

		sort( $library_unpaired );
		sort( $unpaired );
		sort( $library_unreachable );
		sort( $unreachable );

		$this->assertSame( array_values( array_unique( $library_unpaired ) ), array_values( array_unique( $unpaired ) ), 'Unpaired limits differ from the library lint.' );
		$this->assertSame( $library_unreachable, $unreachable, 'Unreachable lines differ from the library lint.' );
	}

	/**
	 * Configurations both can judge.
	 *
	 * @return array<string, array{0: list<array{0: string, 1: list<string>, 2?: bool}>}>
	 */
	public static function lint_scenarios(): array {
		return array(
			'alone'                        => array( array( array( 'accounts', array( '/login 5 300 post.log' ) ) ) ),
			'paired in two rules'          => array(
				array(
					array( 'accounts', array( '/login 5 300 post.log' ) ),
					array( 'addresses', array( '/login 50 300' ) ),
				),
			),
			'paired in one rule'           => array( array( array( 'both', array( '/login 5 300 post.log', '/login 50 300' ) ) ) ),
			'a wildcard takes the account' => array( array( array( 'shadowed', array( '/log* 50 300', '/login 5 300 post.log' ) ) ) ),
			'case across rules'            => array(
				array(
					array( 'accounts', array( '/login 5 300 post.log' ) ),
					array( 'addresses', array( '/LOGIN 50 300' ) ),
				),
			),
			'case within a rule'           => array( array( array( 'both', array( '/login 5 300 post.log', '/LOGIN 50 300' ) ) ) ),
			'a disabled companion'         => array(
				array(
					array( 'accounts', array( '/login 5 300 post.log' ) ),
					array( 'addresses', array( '/login 50 300' ), false ),
				),
			),
			'a combined key'               => array( array( array( 'combined', array( '/login 5 300 client_ip,post.log' ) ) ) ),
			'a prefix before a longer one' => array( array( array( 'api', array( '/api* 100 60', '/api/v1/* 10 60 header.x-api-key' ) ) ) ),
		);
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
