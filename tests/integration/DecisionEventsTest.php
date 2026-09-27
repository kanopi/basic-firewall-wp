<?php
/**
 * Firewall decisions announced as WordPress actions.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Runtime\Decision_Dispatcher;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Symfony\Component\HttpFoundation\Request;

/**
 * Site code can react to a decision without polling the block list or parsing
 * the log.
 *
 * Two properties are worth pinning down, because both are the kind of thing
 * somebody will otherwise assume the other way round:
 *
 * - **A listener cannot change a verdict.** The events carry no setters and an
 *   action's return value is discarded.
 * - **A listener that throws is not an outage.** The request is blocked or
 *   allowed exactly as it would have been.
 *
 * Only `exception` mode is exercised, and that is a property of the library
 * rather than a gap: under CLI it bypasses itself in every other mode, so a test
 * here asserting anything about blocking or log mode would be asserting the
 * bypass. The suite also runs after `plugins_loaded`, so decisions are announced
 * as they are made rather than held -- which is the fallback path's behaviour,
 * and the one a test process can reach.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Decision_Dispatcher
 */
final class DecisionEventsTest extends Settings_Snapshot {

	/**
	 * An address a rule refuses. RFC 5737 documentation space.
	 */
	private const BAD_IP = '203.0.113.66';

	/**
	 * A rule refusing BAD_IP.
	 */
	protected function setUp(): void {
		parent::setUp();

		Decision_Dispatcher::reset();

		$this->given_settings(
			array(
				'enabled' => true,
				'global'  => array( 'mode' => 'exception' ),
				'rules'   => array(
					array(
						'id'          => 'decision_events',
						'label'       => 'Decision events',
						'type'        => 'ip_address',
						'response'    => 'block',
						'enabled'     => true,
						'weight'      => 0,

						/*
						 * Explicit, because the event reports the rule's own code.
						 * The default, 0, means "use the site-wide code" and is
						 * resolved only when the response is sent -- after the
						 * event has been announced carrying the 0.
						 */
						'status_code' => 403,
						'settings'    => array( 'addresses' => array( self::BAD_IP ) ),
					),
				),
			)
		);

		$this->assertTrue( Plugin::instance()->compiled()->rebuild()['written'] );
	}

	/**
	 * Detach every listener a test attached.
	 */
	protected function tearDown(): void {
		foreach ( array( 'allowed', 'blocked', 'challenged', 'recorded', 'marked' ) as $type ) {
			remove_all_actions( Decision_Dispatcher::ACTION . '_' . $type );
		}

		remove_all_actions( Decision_Dispatcher::ACTION );
		Decision_Dispatcher::reset();

		parent::tearDown();
	}

	/**
	 * A listener is told about the block, and which rule made it.
	 */
	public function test_a_listener_sees_the_block_and_the_rule_that_made_it(): void {
		$seen = array();

		add_action(
			Decision_Dispatcher::ACTION . '_blocked',
			static function ( $event ) use ( &$seen ): void {
				$seen[] = $event;
			}
		);

		$this->assertTrue( $this->evaluate( self::BAD_IP ), 'The rule did not refuse the request.' );

		$this->assertCount( 1, $seen, 'The block was not announced.' );
		$this->assertSame( 403, $seen[0]->getStatusCode() );
		$this->assertTrue( $seen[0]->isEnforced(), 'Exception mode enforces, and says so.' );
		$this->assertNotNull( $seen[0]->getPlugin(), 'The rule that decided is carried.' );
	}

	/**
	 * The generic action names the kind of decision.
	 *
	 * Listeners should switch on this rather than type-hint the event class,
	 * which is namespace-scoped in a release build.
	 */
	public function test_the_generic_action_carries_the_type(): void {
		$types = array();

		add_action(
			Decision_Dispatcher::ACTION,
			static function ( $event, string $type ) use ( &$types ): void {
				$types[] = $type;
			},
			10,
			2
		);

		$this->evaluate( self::BAD_IP );
		$this->evaluate( '198.51.100.10' );

		$this->assertContains( 'blocked', $types );
		$this->assertContains( 'allowed', $types, 'An ordinary request was not announced, so metrics could count only one side.' );
	}

	/**
	 * A listener that throws does not change what happens to the request.
	 *
	 * The corollary worth documenting: a listener is not the place for anything
	 * the request depends on, because failing in one is invisible to traffic.
	 */
	public function test_a_throwing_listener_does_not_change_the_outcome(): void {
		add_action(
			Decision_Dispatcher::ACTION,
			static function (): void {
				throw new \RuntimeException( 'a listener that misbehaves' );
			}
		);

		$log = ini_set( 'error_log', '/dev/null' ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- keeps the announced failure out of the test output.

		try {
			$this->assertTrue( $this->evaluate( self::BAD_IP ), 'The block did not happen.' );
			$this->assertFalse( $this->evaluate( '198.51.100.10' ), 'An ordinary request was refused.' );
		} finally {
			ini_set( 'error_log', false === $log ? '' : $log ); // phpcs:ignore WordPress.PHP.IniSet.Risky
		}
	}

	/**
	 * Nothing is announced twice.
	 *
	 * The queue is emptied before anything is announced, and `announce()` is
	 * both hooked to `plugins_loaded` and registered for shutdown.
	 */
	public function test_nothing_is_announced_twice(): void {
		$count = 0;

		add_action(
			Decision_Dispatcher::ACTION . '_blocked',
			static function () use ( &$count ): void {
				++$count;
			}
		);

		$this->evaluate( self::BAD_IP );
		Decision_Dispatcher::announce();
		Decision_Dispatcher::announce();

		$this->assertSame( 1, $count );
		$this->assertSame( array(), Decision_Dispatcher::pending() );
	}

	/**
	 * The early path builds the same dispatcher.
	 *
	 * It is loaded there without the plugin's autoloader, which the release
	 * build does not register before WordPress.
	 */
	public function test_the_early_path_hands_the_library_a_dispatcher(): void {
		require_once dirname( __DIR__, 2 ) . '/bootstrap.php';

		$this->assertInstanceOf(
			Decision_Dispatcher::class,
			basic_firewall_decision_dispatcher( array( 'plugin_path' => dirname( __DIR__, 2 ) ) )
		);
	}

	/**
	 * Evaluate a request from the given address.
	 *
	 * @param string $address Client address.
	 *
	 * @return bool True when the firewall refused it.
	 */
	private function evaluate( string $address ): bool {
		$firewall = Firewall::create(
			array( Plugin::instance()->paths()->compiled_file() ),
			array(
				'[storage][type]'   => Library_Map::STORAGE['memory'],
				'[storage][config]' => array(),
			),
			new Decision_Dispatcher()
		);

		try {
			$firewall->evaluate( Request::create( '/', 'GET', array(), array(), array(), array( 'REMOTE_ADDR' => $address ) ) );
		} catch ( FirewallBlockedException $e ) {
			return true;
		}

		return false;
	}
}
