<?php
/**
 * Tests for which rules miss WordPress's files when core has its own directory.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Health\Unprefixed_Core_Paths;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * With WordPress under `/wp`, the login page reaches the rules as `/wp/wp-login.php`.
 *
 * A rule is flagged only when it would match the file at the root and miss it
 * under the prefix. Presets are flagged only for a rate limit on a bare core
 * path, since kanopi/firewall 2.35.0 made the WordPress presets match at any
 * depth (#45).
 *
 * @covers \Kanopi\BasicFirewall\Health\Unprefixed_Core_Paths
 */
final class UnprefixedCorePathsTest extends TestCase {

	/**
	 * Path conditions, and whether each misses a core file under `/wp`.
	 *
	 * @dataProvider conditions
	 *
	 * @param string $operator  The comparison.
	 * @param string $value     As stored.
	 * @param bool   $flagged   Whether it misses.
	 * @param bool   $sensitive Case sensitive.
	 */
	public function test_a_path_condition( string $operator, string $value, bool $flagged, bool $sensitive = false ): void {
		$condition = array(
			'variable'       => 'path',
			'operator'       => $operator,
			'value'          => $value,
			'case_sensitive' => $sensitive,
		);

		$this->assertSame( $flagged, Unprefixed_Core_Paths::condition_misses( $condition, '/wp' ) );
	}

	/**
	 * Conditions, and whether each is flagged.
	 *
	 * @return array<string, array{0: string, 1: string, 2: bool, 3?: bool}>
	 */
	public static function conditions(): array {
		return array(
			'equals the login page'          => array( 'equals', '/wp-login.php', true ),
			'equals it, in capitals'         => array( 'equals', '/WP-LOGIN.PHP', true ),
			'not equal to it'                => array( 'not_equals', '/wp-login.php', true ),
			'one of'                         => array( 'in', '/xmlrpc.php, /wp-cron.php', true ),
			'starts with the admin'          => array( 'starts_with', '/wp-admin', true ),
			'an anchored pattern'            => array( 'regex', '^/wp-login\.php$', true ),
			'ends with the login page'       => array( 'ends_with', '/wp-login.php', false ),
			'contains the admin'             => array( 'contains', '/wp-admin/', false ),
			'does not contain the admin'     => array( 'not_contains', '/wp-admin/', false ),
			'an unanchored pattern'          => array( 'regex', 'wp-login\.php', false ),
			'already prefixed'               => array( 'equals', '/wp/wp-login.php', false ),
			'starts with the prefix'         => array( 'starts_with', '/wp/wp-admin', false ),
			'something else'                 => array( 'equals', '/contact/', false ),
			'a case-sensitive capital match' => array( 'equals', '/WP-LOGIN.PHP', false, true ),
		);
	}

	/**
	 * Rate limit patterns, and whether each misses a core file under `/wp`.
	 */
	public function test_a_rate_limit_pattern(): void {
		$this->assertTrue( Unprefixed_Core_Paths::limit_misses( '/wp-login.php', '/wp' ), 'An exact pattern is anchored.' );
		$this->assertTrue( Unprefixed_Core_Paths::limit_misses( '/wp-admin/*', '/wp' ) );
		$this->assertTrue( Unprefixed_Core_Paths::limit_misses( '/WP-LOGIN.PHP', '/wp' ), 'Patterns ignore case as of kanopi/firewall 2.35.0.' );
		$this->assertFalse( Unprefixed_Core_Paths::limit_misses( '/wp/wp-login.php', '/wp' ) );
		$this->assertFalse( Unprefixed_Core_Paths::limit_misses( '*/wp-login.php', '/wp' ), 'A leading wildcard matches at any depth.' );
		$this->assertFalse( Unprefixed_Core_Paths::limit_misses( '#/wp-login\.php$#', '/wp' ), 'An unanchored regex matches at any depth.' );
		$this->assertFalse( Unprefixed_Core_Paths::limit_misses( '/contact', '/wp' ) );
	}

	/**
	 * Only enabled rules are read, and each offender is named.
	 */
	public function test_rules_are_read_when_enabled(): void {
		$rules = array(
			array(
				'id'       => 'login',
				'label'    => 'Login block',
				'type'     => 'url',
				'enabled'  => true,
				'settings' => array(
					'conditions' => array(
						array(
							'variable' => 'path',
							'operator' => 'equals',
							'value'    => '/wp-login.php',
						),
						array(
							'variable' => 'path',
							'operator' => 'ends_with',
							'value'    => '/xmlrpc.php',
						),
						array(
							'variable' => 'method',
							'operator' => 'equals',
							'value'    => '/wp-login.php',
						),
					),
				),
			),
			array(
				'id'       => 'limit',
				'label'    => 'Login limit',
				'type'     => 'rate_limit',
				'enabled'  => true,
				'settings' => array( 'paths' => array( '/wp-login.php 5 300', '/contact 5 60' ) ),
			),
			array(
				'id'       => 'off',
				'label'    => 'Disabled',
				'type'     => 'url',
				'enabled'  => false,
				'settings' => array(
					'conditions' => array(
						array(
							'variable' => 'path',
							'operator' => 'starts_with',
							'value'    => '/wp-admin',
						),
					),
				),
			),
		);

		$this->assertSame(
			array(
				array(
					'rule'  => 'login',
					'label' => 'Login block',
					'value' => 'equals /wp-login.php',
				),
				array(
					'rule'  => 'limit',
					'label' => 'Login limit',
					'value' => '/wp-login.php',
				),
			),
			Unprefixed_Core_Paths::in_rules( $rules, '/wp' )
		);

		$this->assertSame( array(), Unprefixed_Core_Paths::in_rules( $rules, '' ), 'Nothing is flagged at the root.' );
	}

	/**
	 * The shipped WordPress presets are not flagged; a root-anchored rate limit in a preset is.
	 */
	public function test_presets_are_flagged_only_for_a_root_anchored_rate_limit(): void {
		$dir = dirname( __DIR__, 2 ) . '/vendor/kanopi/firewall/presets';

		$this->assertSame( array(), Unprefixed_Core_Paths::in_preset_rate_limits( array( Yaml::parseFile( $dir . '/search-bots.yml' ), Yaml::parseFile( $dir . '/wordpress.yml' ), Yaml::parseFile( $dir . '/malicious-requests.yml' ) ), '/wp' ) );

		$flagged = Unprefixed_Core_Paths::in_preset_rate_limits( array( Yaml::parseFile( $dir . '/rate-limiting.yml' ) ), '/wp' );

		$this->assertContains( '/wp-login.php', $flagged );
		$this->assertNotContains( '/login', $flagged, 'A limit on a path that is not a core file is not flagged.' );
	}
}
