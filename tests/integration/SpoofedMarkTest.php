<?php
/**
 * A client cannot send a firewall mark of its own.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Runtime\Runner;
use Symfony\Component\HttpFoundation\Request;

/**
 * `X-Firewall-Mark` is the plugin's to set, on both evaluation paths.
 *
 * The plugin mirrors each mark it applies into `$_SERVER['HTTP_X_FIREWALL_MARK']`
 * for code that reads request headers the ordinary way -- which is also where
 * PHP puts an `X-Firewall-Mark` header the client sent. Nothing removed it, so
 * on a request no rule marked, a scanner's own header read exactly like a mark.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Runner
 */
final class SpoofedMarkTest extends Settings_Snapshot {

	/**
	 * What the test process had, put back afterwards.
	 *
	 * @var array{server: mixed, early: mixed, marks: mixed, runner_marks: list<string>}
	 */
	private array $saved;

	/**
	 * Remember the globals these tests replace.
	 */
	protected function setUp(): void {
		parent::setUp();

		require_once dirname( __DIR__, 2 ) . '/bootstrap.php';

		$this->saved = array(
			'server'       => $_SERVER[ Runner::MARK_SERVER_KEY ] ?? null, // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared, never output or used.
			'early'        => $GLOBALS['basic_firewall_early'] ?? null,
			'marks'        => $GLOBALS['basic_firewall_marks'] ?? null,
			'runner_marks' => Runner::marks(),
		);

		$this->set_runner_marks( array() );
	}

	/**
	 * Put them back.
	 */
	protected function tearDown(): void {
		if ( null === $this->saved['server'] ) {
			unset( $_SERVER[ Runner::MARK_SERVER_KEY ] );
		} else {
			$_SERVER[ Runner::MARK_SERVER_KEY ] = $this->saved['server'];
		}

		foreach ( array(
			'early' => 'basic_firewall_early',
			'marks' => 'basic_firewall_marks',
		) as $saved => $name ) {
			if ( null === $this->saved[ $saved ] ) {
				unset( $GLOBALS[ $name ] );
			} else {
				$GLOBALS[ $name ] = $this->saved[ $saved ]; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- restoring the plugin's own globals.
			}
		}

		$this->set_runner_marks( $this->saved['runner_marks'] );

		parent::tearDown();
	}

	/**
	 * The mu-plugin path drops a client's header on a request nothing marked.
	 */
	public function test_the_runner_drops_a_client_sent_mark(): void {
		$_SERVER[ Runner::MARK_SERVER_KEY ] = 'trusted-partner';
		unset( $GLOBALS['basic_firewall_marks'] );

		Plugin::instance()->runner()->evaluate();

		$this->assertArrayNotHasKey( Runner::MARK_SERVER_KEY, $_SERVER, 'A header the client sent is still readable as a firewall mark.' );
		$this->assertFalse( Runner::is_marked( 'trusted-partner' ) );
	}

	/**
	 * A mark the wp-config.php path applied replaces whatever the client sent.
	 */
	public function test_an_early_mark_replaces_a_client_sent_one(): void {
		$_SERVER[ Runner::MARK_SERVER_KEY ] = 'trusted-partner';
		$GLOBALS['basic_firewall_marks']    = array( 'honeypot' );

		Plugin::instance()->runner()->evaluate();

		$this->assertSame( 'honeypot', $_SERVER[ Runner::MARK_SERVER_KEY ] ?? null ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared, never output or used.
		$this->assertSame( array( 'honeypot' ), Runner::marks() );
	}

	/**
	 * A mark the firewall applies is still published.
	 *
	 * The control: without it, a runner that never set the header would pass.
	 */
	public function test_a_real_mark_is_still_published(): void {
		unset( $_SERVER[ Runner::MARK_SERVER_KEY ] );

		$request = Request::create( '/' );
		$request->attributes->set( 'firewall.marks', array( 'honeypot' ) );

		$method = new \ReflectionMethod( Runner::class, 'publish_marks' );
		$method->setAccessible( true );
		$method->invoke( Plugin::instance()->runner(), $request );

		$this->assertSame( 'honeypot', $_SERVER[ Runner::MARK_SERVER_KEY ] ?? null ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared, never output or used.
	}

	/**
	 * The wp-config.php path drops it too, before anything can return early.
	 */
	public function test_the_bootstrap_drops_a_client_sent_mark(): void {
		$_SERVER[ Runner::MARK_SERVER_KEY ] = 'trusted-partner';

		// Switched off, so it returns at its first check -- after the header has gone.
		basic_firewall_evaluate( array( 'enabled' => false ) );

		$this->assertArrayNotHasKey( Runner::MARK_SERVER_KEY, $_SERVER );
	}

	/**
	 * Set the marks the runner holds for this request.
	 *
	 * @param list<string> $marks Marks.
	 */
	private function set_runner_marks( array $marks ): void {
		$property = new \ReflectionProperty( Runner::class, 'marks' );
		$property->setAccessible( true );
		$property->setValue( null, $marks );
	}
}
