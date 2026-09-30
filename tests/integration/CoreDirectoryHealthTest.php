<?php
/**
 * Site Health's request path check with WordPress in its own directory.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;

/**
 * With core under `/wp`, only the site's own rules that miss it are flagged (#45).
 *
 * Before kanopi/firewall 2.35.0 every enabled preset was flagged, because the
 * WordPress presets named the root paths. `wordpress.yml` and `search-bots.yml`
 * now match at any depth, so the check reads this site's own enabled rules,
 * asks each whether it matches a core file at the root and misses it under
 * the prefix, and names only an enabled preset's root-anchored rate limit.
 *
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 * @covers \Kanopi\BasicFirewall\Health\Unprefixed_Core_Paths
 */
final class CoreDirectoryHealthTest extends Settings_Snapshot {

	/**
	 * Lay the site out with WordPress in `/wp`.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( is_multisite() ) {
			$this->markTestSkipped( 'A single-site layout: a network takes its paths from the network.' );
		}

		add_filter( 'pre_option_home', array( self::class, 'home' ) );
		add_filter( 'pre_option_siteurl', array( self::class, 'siteurl' ) );
	}

	/**
	 * Put the addresses back before the snapshot restores and recompiles.
	 */
	protected function tearDown(): void {
		remove_filter( 'pre_option_home', array( self::class, 'home' ) );
		remove_filter( 'pre_option_siteurl', array( self::class, 'siteurl' ) );

		parent::tearDown();
	}

	/**
	 * The Site Address.
	 */
	public static function home(): string {
		return 'http://example.org';
	}

	/**
	 * The WordPress Address.
	 */
	public static function siteurl(): string {
		return 'http://example.org/wp';
	}

	/**
	 * Presets that match at any depth, and rules written for it, are healthy.
	 */
	public function test_prefixed_rules_and_the_crawler_preset_are_good(): void {
		$result = $this->check(
			array( 'search-bots' ),
			array(
				$this->url_rule( 'prefixed', 'equals', '/wp/wp-login.php' ),
				$this->url_rule( 'anywhere', 'ends_with', '/xmlrpc.php' ),
				$this->url_rule( 'inside', 'contains', '/wp-admin/' ),
			)
		);

		$this->assertSame( 'good', $result['status'], wp_strip_all_tags( $result['description'] ) );
		$this->assertStringContainsString( '/wp/wp-login.php', $result['description'] );
	}

	/**
	 * A rule that equals or starts with a bare core path is named; one that ends with it is not.
	 */
	public function test_an_own_rule_without_the_prefix_is_named(): void {
		$result = $this->check(
			array( 'search-bots' ),
			array(
				$this->url_rule( 'bare-login', 'equals', '/wp-login.php' ),
				$this->url_rule( 'bare-admin', 'starts_with', '/wp-admin' ),
				$this->url_rule( 'anywhere', 'ends_with', '/xmlrpc.php' ),
			)
		);

		$this->assertSame( 'recommended', $result['status'] );
		$this->assertStringContainsString( 'bare-login', $result['description'] );
		$this->assertStringContainsString( 'bare-admin', $result['description'] );
		$this->assertStringNotContainsString( 'anywhere', $result['description'], 'A rule that matches at any depth was flagged.' );
		$this->assertStringNotContainsString( 'search-bots', $result['description'] );
	}

	/**
	 * A disabled rule is not read.
	 */
	public function test_a_disabled_rule_is_not_named(): void {
		$rule            = $this->url_rule( 'bare-login', 'equals', '/wp-login.php' );
		$rule['enabled'] = false;

		$this->assertSame( 'good', $this->check( array(), array( $rule ) )['status'] );
	}

	/**
	 * An enabled preset's rate limit on a bare core path is still named.
	 *
	 * `rate-limiting.yml` was not changed by 2.35.0, and a rate limit pattern
	 * is anchored, so its `/wp-login.php` limit does not count `/wp/wp-login.php`.
	 */
	public function test_a_preset_rate_limit_without_the_prefix_is_named(): void {
		$result = $this->check( array( 'rate-limiting' ), array() );

		$this->assertSame( 'recommended', $result['status'] );
		$this->assertStringContainsString( '<code>/wp-login.php</code>', $result['description'] );
	}

	/**
	 * Compile the settings and run the check.
	 *
	 * @param list<string>                     $presets Enabled presets.
	 * @param array<int, array<string, mixed>> $rules   Rules.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private function check( array $presets, array $rules ): array {
		$this->given_settings(
			array(
				'presets' => $presets,
				'rules'   => $rules,
			)
		);

		Plugin::instance()->compiled()->rebuild();

		return Site_Health::check( 'request_path' );
	}

	/**
	 * A URL rule with one path condition.
	 *
	 * @param string $id       Rule ID, used as its label.
	 * @param string $operator The comparison.
	 * @param string $value    The path.
	 *
	 * @return array<string, mixed>
	 */
	private function url_rule( string $id, string $operator, string $value ): array {
		return array(
			'id'          => $id,
			'type'        => 'url',
			'label'       => $id,
			'enabled'     => true,
			'response'    => 'block',
			'weight'      => 0,
			'status_code' => 403,
			'expiration'  => 600,
			'record'      => 'no',
			'settings'    => array(
				'match_type' => 'any',
				'conditions' => array(
					array(
						'variable' => 'path',
						'operator' => $operator,
						'value'    => $value,
					),
				),
			),
		);
	}
}
