<?php
/**
 * The Request Tester leaves no trace, rate limit counters included.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Request_Tester;
use Kanopi\Firewall\Firewall;

/**
 * A test of a request is not a request.
 *
 * The tester overrode the block list's storage and left every rate limit's
 * counters where the rule put them -- so each test of a rate-limited path
 * spent a request of the real client's allowance in the real counter store,
 * and a few tests limited that client for real.
 *
 * @covers \Kanopi\BasicFirewall\Request_Tester
 */
final class RequestTesterIsolationTest extends Honoured_Settings {

	/**
	 * Testing a rate-limited path, however often, counts nothing.
	 */
	public function test_rate_limit_counters_are_not_written(): void {
		$counters = $this->scratch . '/ratelimit.data';

		$this->build(
			array(
				'rules' => array(
					$this->rule(
						'tester-limit',
						'rate_limit',
						array(
							'paths'                => array( '/rl-tester 2 60' ),
							'default_limit'        => 60,
							'default_window'       => 60,
							'limit_unlisted_paths' => false,
							'storage'              => array(
								'backend' => 'file',
								'file'    => $counters,
							),
						)
					),
				),
			)
		);

		$tester = new Request_Tester();

		for ( $i = 0; $i < 5; $i++ ) {
			$result = $tester->test(
				array(
					'path' => '/rl-tester',
					'ip'   => '203.0.113.77',
				)
			);

			$this->assertNull( $result['error'], 'The tester could not run: ' . (string) $result['error'] );
			$this->assertSame( 'allow', $result['verdict'], 'Testing a path counted towards its rate limit, so the tester limited the client it was asked about.' );
		}

		$this->assertTrue( ! file_exists( $counters ) || '' === trim( (string) file_get_contents( $counters ), "[]{} \n" ), 'The tester wrote rate limit counters to the rule\'s own storage.' ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a scratch file.

		// The control: the same rule, evaluated for real, does count -- so
		// the loop above passed because of the isolation, not a dead rule.
		$firewall = Firewall::create( array( Plugin::instance()->paths()->compiled_file() ) );
		$verdicts = array();

		for ( $i = 0; $i < 3; $i++ ) {
			$verdicts[] = $this->outcome( $firewall, self::request( '/rl-tester', '203.0.113.78' ) )['verdict'];
		}

		$this->assertSame( array( 'allow', 'allow', 'block' ), $verdicts, 'The rule under test does not limit anybody, so this test proves nothing.' );
	}

	/**
	 * Every rate limit is found, wherever it sits in the loaded configuration.
	 */
	public function test_every_rate_limit_is_overridden(): void {
		$limit = array(
			'paths'                => array( '/rl-a 5 60' ),
			'default_limit'        => 60,
			'default_window'       => 60,
			'limit_unlisted_paths' => false,
			'storage'              => array(
				'backend' => 'file',
				'file'    => $this->scratch . '/ratelimit.data',
			),
		);

		$this->build(
			array(
				'rules' => array(
					$this->rule( 'first-limit', 'rate_limit', $limit ),
					$this->rule( 'between', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/between' ) ) ) ),
					$this->rule( 'second-limit', 'rate_limit', $limit ),
				),
			)
		);

		$overrides = Request_Tester::rate_limit_overrides( Plugin::instance()->paths()->compiled_file() );

		$this->assertCount( 2, $overrides, 'A rate limit kept its real counters under the tester.' );

		$firewall = Firewall::create( array( Plugin::instance()->paths()->compiled_file() ), $overrides );

		foreach ( array( 'first-limit', 'second-limit' ) as $name ) {
			$this->assertStringEndsWith( 'InMemoryRateLimitStorage', get_class( self::property( $this->plugin_named( $firewall, $name ), 'storage' ) ), "$name still counts in its configured storage under the tester." );
		}
	}
}
